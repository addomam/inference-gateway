//! Client routes. Each variant is one frontend contract. Preparing a route
//! asks the selected [`Backend`] for that capability, so a new frontend does
//! not add a provider-kind branch to the proxy.

use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode};
use serde_json::{Map, Value};

use crate::{
    backend::{Backend, Generation, SystemOne},
    catalog::{self, Dialect},
    system_one::Transport,
    translate::{self, Protocol},
};

pub const FAMILY_MISMATCH: &str = "generation, embeddings, System One, OpenAI Decisions, and Clairic APIs cannot be translated; use a provider of the matching kind or explicit provider passthrough";

pub struct RouteError {
    pub status: StatusCode,
    pub message: String,
}

pub struct ResponsePlan {
    pub upstream_protocol: Protocol,
    pub client_protocol: Protocol,
    pub model: String,
    pub client_stream: bool,
    pub include_usage: bool,
    pub upstream_stream: bool,
}
pub struct RoutePolicy<'a> {
    pub access_program: Option<&'a str>,
    pub daybreak: crate::config::DaybreakLevel,
    pub danger_zone_images: bool,
    pub operations: &'a [catalog::Operation],
    pub operations_declared: bool,
    pub modalities: Option<Vec<catalog::Modality>>,
}

pub struct Prepared {
    pub bytes: Bytes,
    pub suffix: String,
    pub rewritten: bool,
    pub warning: Option<&'static str>,
    pub response: Option<ResponsePlan>,
    pub decision: Option<crate::translate::AnswerPlan>,
}

enum Body {
    Json(Value),
    Multipart {
        model: String,
        response_format: Option<String>,
        boundary: String,
    },
    SystemOne {
        value: Value,
        transport: Transport,
    },
}

pub struct Parsed {
    body: Body,
    raw: Vec<u8>,
    images_opt_in: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum AudioKind {
    Speech,
    Transcription,
    Diarization,
}

pub enum Route {
    Generation(Protocol),
    Decisions,
    SystemOne,
    Embeddings,
    Extraction { account: String },
    Audio(AudioKind),
}

impl Route {
    pub fn recognize(method: &Method, path: &str) -> Option<Self> {
        if method != Method::POST {
            return None;
        }
        Some(match path {
            "/v1/messages" => Self::Generation(Protocol::Anthropic),
            "/v1/chat/completions" => Self::Generation(Protocol::Chat),
            "/v1/responses" => Self::Generation(Protocol::Responses),
            "/v1/decisions" => Self::Decisions,
            "/v1/systemone" => Self::SystemOne,
            "/v1/embeddings" => Self::Embeddings,
            "/v1/audio/speech" => Self::Audio(AudioKind::Speech),
            "/v1/audio/transcriptions" => Self::Audio(AudioKind::Transcription),
            "/v1/audio/diarization" => Self::Audio(AudioKind::Diarization),
            _ => return clairic_account(path).map(|account| Self::Extraction { account }),
        })
    }

    pub fn client_dialect(&self) -> Dialect {
        match self {
            Self::Generation(protocol) => Dialect::from_protocol(*protocol),
            Self::Decisions => Dialect::Decisions,
            Self::SystemOne => Dialect::SystemOne,
            Self::Embeddings => Dialect::Embeddings,
            Self::Extraction { .. } => Dialect::Extraction,
            Self::Audio(AudioKind::Speech) => Dialect::Speech,
            Self::Audio(AudioKind::Transcription) => Dialect::Transcription,
            Self::Audio(AudioKind::Diarization) => Dialect::Diarization,
        }
    }

    pub fn request_limit(&self, configured: usize) -> usize {
        match self {
            Self::SystemOne => configured.min(crate::system_one::MAX_BODY),
            _ => configured,
        }
    }

    pub fn parse(
        &self,
        raw: Vec<u8>,
        headers: &HeaderMap,
        limit: usize,
    ) -> Result<Parsed, RouteError> {
        let body = match &self {
            Self::Audio(AudioKind::Transcription | AudioKind::Diarization)
                if headers
                    .get(http::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| value.to_ascii_lowercase().contains("multipart/")) =>
            {
                let (model, response_format, boundary) = multipart_audio(&raw, headers)?;
                Body::Multipart {
                    model,
                    response_format,
                    boundary,
                }
            }
            Self::SystemOne => {
                let (value, transport) =
                    Transport::parse(&raw, headers, limit).map_err(|error| RouteError {
                        status: error.status,
                        message: error.message.to_owned(),
                    })?;
                Body::SystemOne { value, transport }
            }
            _ => Body::Json(crate::json::from_slice(&raw).map_err(|_| RouteError {
                status: StatusCode::BAD_REQUEST,
                message: "invalid JSON request".to_owned(),
            })?),
        };
        let images_opt_in = headers
            .get("typesafe-danger-zone-images")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.eq_ignore_ascii_case("true"));
        Ok(Parsed {
            body,
            raw,
            images_opt_in,
        })
    }

    pub fn model<'a>(&self, parsed: &'a Parsed) -> Option<&'a str> {
        if let Body::Multipart { model, .. } = &parsed.body {
            return Some(model);
        }
        self.value(parsed).get("model").and_then(Value::as_str)
    }

    pub fn prepare(
        &self,
        backend: &dyn Backend,
        parsed: Parsed,
        client_model: &str,
        upstream_model: &str,
        policy: RoutePolicy<'_>,
        limit: usize,
    ) -> Result<Prepared, RouteError> {
        if let Self::Audio(kind) = self {
            return prepare_audio(*kind, backend, parsed, upstream_model, &policy);
        }
        let mut outgoing = self.value(&parsed).clone();
        let changed_model = upstream_model != client_model;
        if catalog::target_dialect(self.client_dialect(), backend.dialects()).is_none() {
            return Err(mismatch());
        }
        if changed_model {
            outgoing["model"] = Value::String(upstream_model.to_owned());
        }
        match self {
            Self::Generation(source) => {
                let Some(generation) = backend.generation() else {
                    return Err(mismatch());
                };
                prepare_generation(
                    generation,
                    *source,
                    outgoing,
                    parsed.raw,
                    changed_model,
                    client_model,
                    policy.access_program,
                    policy.daybreak,
                    policy.modalities.as_deref(),
                )
            }
            Self::Decisions => {
                if let Some(decisions) = backend.decisions() {
                    native(decisions.upstream_path(), outgoing, parsed, changed_model)
                } else if let Some(system_one) = backend.system_one() {
                    let (translated, plan) = crate::translate::decisions_request(&outgoing)
                        .map_err(|error| RouteError {
                            status: StatusCode::BAD_REQUEST,
                            message: format!("unsupported translation: {error}"),
                        })?;
                    Ok(Prepared {
                        bytes: Bytes::from(serde_json::to_vec(&translated).unwrap()),
                        suffix: system_one.upstream_path().to_owned(),
                        rewritten: true,
                        warning: None,
                        response: None,
                        decision: Some(crate::translate::AnswerPlan::Decisions(plan)),
                    })
                } else {
                    Err(mismatch())
                }
            }
            Self::Embeddings => {
                let Some(embeddings) = backend.embeddings() else {
                    return Err(mismatch());
                };
                if let Err(message) = embeddings.reject(&outgoing) {
                    return Err(RouteError {
                        status: StatusCode::BAD_REQUEST,
                        message: message.to_owned(),
                    });
                }
                if catalog::embedding_dimensions(upstream_model) == Some(false)
                    && outgoing
                        .get("dimensions")
                        .is_some_and(|value| !value.is_null())
                {
                    return Err(RouteError {
                        status: StatusCode::BAD_REQUEST,
                        message: format!("{upstream_model} does not apply embeddings dimensions"),
                    });
                }
                if let Err(error) = catalog::validate_embedding_input(
                    upstream_model,
                    &outgoing,
                    policy.modalities.as_deref(),
                ) {
                    return Err(RouteError {
                        status: StatusCode::BAD_REQUEST,
                        message: error,
                    });
                }
                native(embeddings.upstream_path(), outgoing, parsed, changed_model)
            }
            Self::SystemOne => {
                reject_unsupported_system_one(
                    upstream_model,
                    &outgoing,
                    parsed.images_opt_in || policy.danger_zone_images,
                )?;
                if let Some(system_one) = backend.system_one() {
                    prepare_system_one(system_one, outgoing, parsed, changed_model, limit)
                } else if let Some(decisions) = backend.decisions() {
                    let (translated, plan) =
                        crate::translate::from_system_one(&outgoing).map_err(|error| {
                            RouteError {
                                status: StatusCode::BAD_REQUEST,
                                message: format!("unsupported translation: {error}"),
                            }
                        })?;
                    Ok(Prepared {
                        bytes: Bytes::from(serde_json::to_vec(&translated).unwrap()),
                        suffix: decisions.upstream_path().to_owned(),
                        rewritten: true,
                        warning: None,
                        response: None,
                        decision: Some(crate::translate::AnswerPlan::SystemOne(plan)),
                    })
                } else {
                    Err(mismatch())
                }
            }
            Self::Extraction { account } => {
                let Some(extraction) = backend.extraction() else {
                    return Err(mismatch());
                };
                native(
                    &extraction.upstream_path(account),
                    outgoing,
                    parsed,
                    changed_model,
                )
            }
            Self::Audio(_) => unreachable!("audio is prepared before the JSON match"),
        }
    }

    fn value<'a>(&self, parsed: &'a Parsed) -> &'a Value {
        match &parsed.body {
            Body::Json(value) | Body::SystemOne { value, .. } => value,
            Body::Multipart { .. } => {
                unreachable!("multipart audio is prepared before JSON projection")
            }
        }
    }
}
fn prepare_audio(
    kind: AudioKind,
    backend: &dyn Backend,
    parsed: Parsed,
    upstream_model: &str,
    policy: &RoutePolicy<'_>,
) -> Result<Prepared, RouteError> {
    let client = match kind {
        AudioKind::Speech => Dialect::Speech,
        AudioKind::Transcription => Dialect::Transcription,
        AudioKind::Diarization => Dialect::Diarization,
    };
    if kind == AudioKind::Diarization {
        validate_diarization(&parsed)?;
    }
    let format = audio_format(&parsed);
    let operation = match kind {
        AudioKind::Speech => catalog::Operation::Speak,
        AudioKind::Diarization => catalog::Operation::Diarize,
        AudioKind::Transcription if format.as_deref() == Some("diarized_json") => {
            catalog::Operation::Diarize
        }
        AudioKind::Transcription => catalog::Operation::Transcribe,
    };
    if kind == AudioKind::Diarization && policy.operations.contains(&catalog::Operation::Transcribe)
    {
        return Err(RouteError {
            status: StatusCode::BAD_REQUEST,
            message: format!(
                "{upstream_model} declares transcription; use /v1/audio/transcriptions with response_format=diarized_json"
            ),
        });
    }
    if !policy.operations.contains(&operation)
        && (policy.operations_declared
            || !matches!(
                operation,
                catalog::Operation::Transcribe | catalog::Operation::Speak
            ))
    {
        return Err(RouteError {
            status: StatusCode::BAD_REQUEST,
            message: format!(
                "{upstream_model} does not declare {}; infer will not call a second model",
                operation.as_str()
            ),
        });
    }
    if catalog::target_dialect(client, backend.dialects()).is_none() {
        return Err(RouteError {
            status: StatusCode::BAD_REQUEST,
            message: format!(
                "selected provider does not speak {}; no configured provider exposes this route",
                client.as_str()
            ),
        });
    }
    let suffix = match kind {
        AudioKind::Speech => "/v1/audio/speech",
        AudioKind::Transcription => "/v1/audio/transcriptions",
        AudioKind::Diarization => "/v1/audio/diarization",
    };
    let boundary = match &parsed.body {
        Body::Multipart { boundary, .. } => Some(boundary.clone()),
        _ => None,
    };
    let changed = match &parsed.body {
        Body::Json(value) => value.get("model").and_then(Value::as_str) != Some(upstream_model),
        Body::Multipart { model, .. } => model != upstream_model,
        Body::SystemOne { .. } => false,
    };
    let bytes = if !changed {
        Bytes::from(parsed.raw)
    } else if let Body::Json(mut value) = parsed.body {
        if let Some(object) = value.as_object_mut() {
            object.insert("model".into(), Value::String(upstream_model.to_owned()));
        }
        Bytes::from(serde_json::to_vec(&value).unwrap())
    } else if let Some(boundary) = boundary {
        Bytes::from(
            rewrite_multipart_model(&parsed.raw, &boundary, upstream_model).map_err(|message| {
                RouteError {
                    status: StatusCode::BAD_REQUEST,
                    message,
                }
            })?,
        )
    } else {
        Bytes::from(parsed.raw)
    };
    Ok(Prepared {
        bytes,
        suffix: suffix.to_owned(),
        rewritten: changed,
        warning: None,
        response: None,
        decision: None,
    })
}

fn audio_format(parsed: &Parsed) -> Option<String> {
    match &parsed.body {
        Body::Multipart {
            response_format, ..
        } => response_format.clone(),
        Body::Json(value) => value
            .get("response_format")
            .and_then(Value::as_str)
            .map(str::to_owned),
        Body::SystemOne { .. } => None,
    }
}

fn validate_diarization(parsed: &Parsed) -> Result<(), RouteError> {
    let fields = diarization_fields(parsed)?;
    if !fields.iter().any(|field| field == "file") {
        return Err(RouteError {
            status: StatusCode::BAD_REQUEST,
            message: "diarization requires a multipart file".to_owned(),
        });
    }
    if fields.iter().any(|field| field == "include_text") {
        return Err(RouteError {
            status: StatusCode::BAD_REQUEST,
            message: "diarization does not transcribe; omit include_text and call /v1/audio/transcriptions".to_owned(),
        });
    }
    for hint in ["num_speakers", "min_speakers", "max_speakers"] {
        if fields.iter().any(|field| field == hint) {
            return Err(RouteError {
                status: StatusCode::BAD_REQUEST,
                message: format!(
                    "{hint} is not accepted; no diarization provider declares speaker-count hints"
                ),
            });
        }
    }
    if let Some(format) = audio_format(parsed)
        && !matches!(format.as_str(), "json" | "rttm")
    {
        return Err(RouteError {
            status: StatusCode::BAD_REQUEST,
            message: "diarization response_format must be json or rttm".to_owned(),
        });
    }
    Ok(())
}

fn diarization_fields(parsed: &Parsed) -> Result<Vec<String>, RouteError> {
    match &parsed.body {
        Body::Multipart { boundary, .. } => Ok(multipart_names(&parsed.raw, boundary)),
        Body::Json(_) => Err(RouteError {
            status: StatusCode::BAD_REQUEST,
            message: "diarization requires multipart/form-data".to_owned(),
        }),
        Body::SystemOne { .. } => Err(RouteError {
            status: StatusCode::BAD_REQUEST,
            message: "diarization requires multipart/form-data".to_owned(),
        }),
    }
}

fn find_slice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

struct PartRanges {
    headers: std::ops::Range<usize>,
    body: std::ops::Range<usize>,
}

/// Parts split on `CRLF--boundary`. The marker alone is not a delimiter, so
/// audio bytes that contain it stay in the part.
fn multipart_parts(raw: &[u8], boundary: &str) -> Vec<PartRanges> {
    let mut marker = b"--".to_vec();
    marker.extend_from_slice(boundary.as_bytes());
    let mut delimiter = b"\r\n".to_vec();
    delimiter.extend_from_slice(&marker);
    let mut parts = Vec::new();
    let Some(mut at) = find_delimited_marker(raw, 0, &marker) else {
        return parts;
    };
    loop {
        let mut cursor = at + marker.len();
        if raw.get(cursor..cursor + 2) == Some(b"--") {
            break;
        }
        if raw.get(cursor..cursor + 2) == Some(b"\r\n") {
            cursor += 2;
        }
        let Some(split) = find_slice(&raw[cursor..], b"\r\n\r\n") else {
            break;
        };
        let body_start = cursor + split + 4;
        let body_end = find_slice(&raw[body_start..], &delimiter)
            .map(|index| body_start + index)
            .unwrap_or(raw.len());
        parts.push(PartRanges {
            headers: cursor..cursor + split,
            body: body_start..body_end,
        });
        if body_end + delimiter.len() > raw.len() {
            break;
        }
        at = body_end + 2;
        if !raw[at..].starts_with(&marker) {
            break;
        }
    }
    parts
}

fn find_delimited_marker(raw: &[u8], from: usize, marker: &[u8]) -> Option<usize> {
    let mut index = from;
    while let Some(found) = find_slice(&raw[index..], marker) {
        let at = index + found;
        if at == 0 || raw.get(at.saturating_sub(2)..at) == Some(b"\r\n") {
            return Some(at);
        }
        index = at + 1;
    }
    None
}

fn disposition_name(headers: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(headers);
    for line in text.split("\r\n") {
        if !line.to_ascii_lowercase().contains("content-disposition") {
            continue;
        }
        for item in line.split(';') {
            let Some(value) = item.trim().strip_prefix("name=") else {
                continue;
            };
            return Some(value.trim_matches('"').trim().to_owned());
        }
    }
    None
}

fn multipart_names(raw: &[u8], boundary: &str) -> Vec<String> {
    multipart_parts(raw, boundary)
        .into_iter()
        .filter_map(|part| disposition_name(&raw[part.headers.clone()]))
        .collect()
}

fn multipart_audio(
    raw: &[u8],
    headers: &HeaderMap,
) -> Result<(String, Option<String>, String), RouteError> {
    let content_type = headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| RouteError {
            status: StatusCode::BAD_REQUEST,
            message: "transcription requires multipart/form-data or JSON".to_owned(),
        })?;
    let boundary = content_type
        .split(';')
        .filter_map(|part| part.trim().strip_prefix("boundary="))
        .next()
        .map(|value| value.trim_matches('"').to_owned())
        .ok_or_else(|| RouteError {
            status: StatusCode::BAD_REQUEST,
            message: "multipart transcription is missing a boundary".to_owned(),
        })?;
    let model = multipart_field(raw, &boundary, "model").ok_or_else(|| RouteError {
        status: StatusCode::BAD_REQUEST,
        message: "transcription model must be a form field".to_owned(),
    })?;
    Ok((
        model,
        multipart_field(raw, &boundary, "response_format"),
        boundary,
    ))
}

fn multipart_field(raw: &[u8], boundary: &str, name: &str) -> Option<String> {
    multipart_parts(raw, boundary).into_iter().find_map(|part| {
        (disposition_name(&raw[part.headers]).as_deref() == Some(name))
            .then(|| String::from_utf8_lossy(&raw[part.body]).trim().to_owned())
    })
}

fn rewrite_multipart_model(raw: &[u8], boundary: &str, model: &str) -> Result<Vec<u8>, String> {
    let Some(part) = multipart_parts(raw, boundary)
        .into_iter()
        .find(|part| disposition_name(&raw[part.headers.clone()]).as_deref() == Some("model"))
    else {
        return Err("cannot rewrite a multipart model field".to_owned());
    };
    let mut out = Vec::with_capacity(raw.len() + model.len());
    out.extend_from_slice(&raw[..part.body.start]);
    out.extend_from_slice(model.as_bytes());
    out.extend_from_slice(&raw[part.body.end..]);
    Ok(out)
}
#[allow(clippy::too_many_arguments)]
fn prepare_generation(
    generation: &dyn Generation,
    source: Protocol,
    mut outgoing: Value,
    raw: Vec<u8>,
    changed_model: bool,
    client_model: &str,
    access_program: Option<&str>,
    daybreak: crate::config::DaybreakLevel,
    modalities: Option<&[catalog::Modality]>,
) -> Result<Prepared, RouteError> {
    let target = generation.target(source);
    let translated = source != target;
    if let Some(model) = outgoing.get("model").and_then(Value::as_str)
        && let Err(message) =
            catalog::reject_undeclared_generation_media(model, &outgoing, modalities, translated)
    {
        return Err(RouteError {
            status: StatusCode::BAD_REQUEST,
            message,
        });
    }
    let target = generation.target(source);
    let client_stream = outgoing
        .get("stream")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let include_usage = source == Protocol::Chat
        && client_stream
        && outgoing
            .pointer("/stream_options/include_usage")
            .and_then(Value::as_bool)
            .unwrap_or(false);
    if client_stream && source == Protocol::Responses && target != Protocol::Responses {
        return Err(RouteError {
            status: StatusCode::BAD_REQUEST,
            message: "streaming Responses clients require a Responses backend; use Messages/Chat or disable streaming".to_owned(),
        });
    }
    if translated {
        outgoing = translate::request(outgoing, source, target).map_err(|error| RouteError {
            status: StatusCode::BAD_REQUEST,
            message: format!("unsupported translation: {error}"),
        })?;
    }
    let warning = generation.adapt(target, translated, &mut outgoing);
    let injected = apply_access_program(&mut outgoing, target, access_program)?;
    if let Some(program) = outgoing
        .pointer("/access_programs/cyber")
        .and_then(Value::as_str)
        && !daybreak.allows(program)
    {
        return Err(RouteError {
            status: StatusCode::BAD_REQUEST,
            message: format!(
                "provider daybreak ceiling is {}; {program} exceeds it",
                daybreak.as_str()
            ),
        });
    }
    if let Err(error) = catalog::validate_cyber(
        outgoing
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or(client_model),
        &outgoing,
    ) {
        return Err(RouteError {
            status: StatusCode::BAD_REQUEST,
            message: error,
        });
    }
    let rewritten = translated || changed_model || generation.forces_rewrite() || injected;
    let bytes = if rewritten {
        Bytes::from(serde_json::to_vec(&outgoing).unwrap())
    } else {
        Bytes::from(raw)
    };
    Ok(Prepared {
        suffix: generation.upstream_path(target).to_owned(),
        bytes,
        rewritten,
        warning,
        response: Some(ResponsePlan {
            upstream_protocol: target,
            client_protocol: source,
            model: client_model.to_owned(),
            client_stream,
            include_usage,
            upstream_stream: outgoing
                .get("stream")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        }),
        decision: None,
    })
}

fn prepare_system_one(
    system_one: &dyn SystemOne,
    outgoing: Value,
    parsed: Parsed,
    changed_model: bool,
    limit: usize,
) -> Result<Prepared, RouteError> {
    let Body::SystemOne { transport, .. } = parsed.body else {
        unreachable!("system one route parsed a system one body");
    };
    let rewritten = changed_model;
    let bytes = if rewritten {
        Bytes::from(
            transport
                .rewrite(&parsed.raw, &outgoing, limit)
                .map_err(|error| RouteError {
                    status: error.status,
                    message: error.message.to_owned(),
                })?,
        )
    } else {
        Bytes::from(parsed.raw)
    };
    Ok(Prepared {
        suffix: system_one.upstream_path().to_owned(),
        bytes,
        rewritten,
        warning: None,
        response: None,
        decision: None,
    })
}

fn native(
    suffix: &str,
    outgoing: Value,
    parsed: Parsed,
    changed_model: bool,
) -> Result<Prepared, RouteError> {
    let bytes = if changed_model {
        Bytes::from(serde_json::to_vec(&outgoing).unwrap())
    } else {
        Bytes::from(parsed.raw)
    };
    Ok(Prepared {
        suffix: suffix.to_owned(),
        bytes,
        rewritten: changed_model,
        warning: None,
        response: None,
        decision: None,
    })
}

fn apply_access_program(
    body: &mut Value,
    target: Protocol,
    program: Option<&str>,
) -> Result<bool, RouteError> {
    let Some(program) = program else {
        return Ok(false);
    };
    if target != Protocol::Responses {
        return Err(RouteError {
            status: StatusCode::BAD_REQUEST,
            message: "Daybreak is a Responses access program; use /v1/responses".to_owned(),
        });
    }
    let Some(object) = body.as_object_mut() else {
        return Err(RouteError {
            status: StatusCode::BAD_REQUEST,
            message: "request must be a JSON object".to_owned(),
        });
    };
    let programs = object
        .entry("access_programs")
        .or_insert_with(|| Value::Object(Map::new()));
    let Some(programs) = programs.as_object_mut() else {
        return Err(RouteError {
            status: StatusCode::BAD_REQUEST,
            message: "access_programs must be an object".to_owned(),
        });
    };
    match programs.get("cyber") {
        Some(Value::String(existing)) if existing == program => Ok(false),
        Some(Value::String(existing)) => Err(RouteError {
            status: StatusCode::BAD_REQUEST,
            message: format!("access_programs.cyber is {existing}; this model requires {program}"),
        }),
        Some(_) => Err(RouteError {
            status: StatusCode::BAD_REQUEST,
            message: "access_programs.cyber must be a string".to_owned(),
        }),
        None => {
            programs.insert("cyber".into(), Value::String(program.to_owned()));
            Ok(true)
        }
    }
}

fn reject_unsupported_system_one(
    model: &str,
    body: &Value,
    images_opt_in: bool,
) -> Result<(), RouteError> {
    let Some(caps) = catalog::system_one_caps(model) else {
        return Ok(());
    };
    let images = body
        .get("assets")
        .and_then(Value::as_object)
        .is_some_and(|assets| !assets.is_empty());
    let box_questions = body
        .get("questions")
        .and_then(Value::as_object)
        .is_some_and(|questions| {
            questions
                .values()
                .any(|question| question.get("type").and_then(Value::as_str) == Some("box"))
        });
    if images && !caps.images {
        return Err(RouteError {
            status: StatusCode::BAD_REQUEST,
            message: format!("{model} does not accept System One images"),
        });
    }
    if box_questions && !caps.box_questions {
        return Err(RouteError {
            status: StatusCode::BAD_REQUEST,
            message: format!("{model} does not accept System One Box questions"),
        });
    }
    if (images || box_questions) && !images_opt_in {
        return Err(RouteError {
            status: StatusCode::BAD_REQUEST,
            message:
                "System One images and Box questions require TypeSafe-Danger-Zone-Images: true"
                    .to_owned(),
        });
    }
    Ok(())
}

fn mismatch() -> RouteError {
    RouteError {
        status: StatusCode::BAD_REQUEST,
        message: FAMILY_MISMATCH.to_owned(),
    }
}

fn clairic_account(path: &str) -> Option<String> {
    let (account, model) = path
        .strip_prefix("/client/v4/accounts/")?
        .split_once("/ai/run/")?;
    let encoded_model = model.eq_ignore_ascii_case("@cf%2fcloudflare%2fclairic")
        || model.eq_ignore_ascii_case("%40cf%2fcloudflare%2fclairic");
    (!account.is_empty()
        && !account.contains('/')
        && !account_is_dot_segment(account)
        && (model == "@cf/cloudflare/clairic" || encoded_model))
        .then(|| account.to_owned())
}

fn account_is_dot_segment(account: &str) -> bool {
    let decoded = percent_decode_account(account);
    decoded == "." || decoded == ".." || decoded.contains('/') || decoded.contains('\\')
}

fn percent_decode_account(account: &str) -> String {
    let bytes = account.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let (Some(high), Some(low)) =
                (hex_digit(bytes[index + 1]), hex_digit(bytes[index + 2]))
        {
            out.push((high << 4) | low);
            index += 3;
            continue;
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
