//! Compiled model catalog. Discovery may fill gaps later; an unknown id falls
//! back to the selected provider profile instead of being guessed, and that
//! fallback warns so a missing record is visible.
//!
//! A client dialect reaches a model when the model speaks that dialect, or when
//! one shared translator can produce a dialect the model speaks. Decisions can
//! target System One. Embeddings stay on a provider that speaks that contract.
//!
//! These records define local routing and denial policy, not live upstream
//! capability or entitlement discovery. Image, audio, realtime, and speech ids are known so they
//! are not sent to a generation backend; accepting those media routes is separate.

use serde::Deserialize;

use crate::translate::Protocol;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Dialect {
    Chat,
    Responses,
    Messages,
    Decisions,
    SystemOne,
    Extraction,
    Embeddings,
    Transcription,
    Speech,
    Realtime,
    Diarization,
}

impl Dialect {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Chat => "chat",
            Self::Responses => "responses",
            Self::Messages => "messages",
            Self::Decisions => "decisions",
            Self::SystemOne => "system_one",
            Self::Extraction => "extraction",
            Self::Embeddings => "embeddings",
            Self::Transcription => "transcription",
            Self::Speech => "speech",
            Self::Realtime => "realtime",
            Self::Diarization => "diarization",
        }
    }

    pub fn from_protocol(protocol: Protocol) -> Self {
        match protocol {
            Protocol::Chat => Self::Chat,
            Protocol::Responses => Self::Responses,
            Protocol::Anthropic => Self::Messages,
        }
    }
}

impl std::fmt::Display for Dialect {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Openai,
    Anthropic,
    Xai,
    Llama,
    Codex,
    Cloudflare,
    TypeSafe,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CyberProgram {
    Standard,
    DaybreakBlue,
    DaybreakRed,
}

impl CyberProgram {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::DaybreakBlue => "daybreak_blue",
            Self::DaybreakRed => "daybreak_red",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "standard" => Some(Self::Standard),
            "daybreak-blue" | "daybreak_blue" => Some(Self::DaybreakBlue),
            "daybreak-red" | "daybreak_red" => Some(Self::DaybreakRed),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Modality {
    Text,
    Image,
    Audio,
    Video,
}

impl Modality {
    fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Image => "image",
            Self::Audio => "audio",
            Self::Video => "video",
        }
    }
}

/// An operation a model can serve. Absence is a refusal, not a hidden cascade.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Transcribe,
    Diarize,
    Speak,
    Realtime,
}

impl Operation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Transcribe => "transcribe",
            Self::Diarize => "diarize",
            Self::Speak => "speak",
            Self::Realtime => "realtime",
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub struct SystemOneCaps {
    pub images: bool,
    pub box_questions: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct ModelRecord {
    pub families: &'static [Family],
    pub dialects: &'static [Dialect],
    /// `None` means this record does not constrain `access_programs.cyber`.
    pub cyber: Option<&'static [CyberProgram]>,
    /// `None` means this record does not constrain embedding `dimensions`.
    pub embedding_dimensions: Option<bool>,
    /// `None` means this record does not constrain embedding input modalities.
    pub modalities: Option<&'static [Modality]>,
    /// `None` means this record does not constrain System One images or Box questions.
    pub system_one: Option<SystemOneCaps>,
    pub operations: &'static [Operation],
}

#[derive(Clone, Debug)]
pub struct Hit {
    pub record: ModelRecord,
    pub upstream_model: String,
    pub inject_cyber: Option<&'static str>,
}

const OPENAI_AND_CODEX: &[Family] = &[Family::Openai, Family::Codex];
const OPENAI_FAMILY: &[Family] = &[Family::Openai];
const LLAMA_FAMILY: &[Family] = &[Family::Llama];
const CLOUDFLARE: &[Family] = &[Family::Cloudflare];
const RESPONSES_AND_DECISIONS: &[Dialect] = &[Dialect::Responses, Dialect::Decisions];
const CHAT_AND_RESPONSES_DIALECTS: &[Dialect] = &[Dialect::Chat, Dialect::Responses];
const CHAT_ONLY: &[Dialect] = &[Dialect::Chat];
const RESPONSES_ONLY: &[Dialect] = &[Dialect::Responses];
const EMBEDDINGS_ONLY: &[Dialect] = &[Dialect::Embeddings];
const NONE: &[Dialect] = &[];
const EXTRACTION: &[Dialect] = &[Dialect::Extraction];
const BLUE: &[CyberProgram] = &[CyberProgram::Standard, CyberProgram::DaybreakBlue];
const RED: &[CyberProgram] = &[CyberProgram::DaybreakRed];
const TEXT_ONLY: &[Modality] = &[Modality::Text];
const EMBEDDINGGEMMA_MEDIA: &[Modality] = &[
    Modality::Text,
    Modality::Image,
    Modality::Audio,
    Modality::Video,
];
const TYPESAFE: &[Family] = &[Family::TypeSafe];
struct Row {
    id: &'static str,
    dated: bool,
    record: ModelRecord,
}

fn row(
    id: &'static str,
    dated: bool,
    families: &'static [Family],
    dialects: &'static [Dialect],
) -> Row {
    Row {
        id,
        dated,
        record: ModelRecord {
            families,
            dialects,
            cyber: None,
            embedding_dimensions: None,
            modalities: None,
            system_one: None,
            operations: &[],
        },
    }
}

fn cyber(id: &'static str, dialects: &'static [Dialect], programs: &'static [CyberProgram]) -> Row {
    Row {
        id,
        dated: true,
        record: ModelRecord {
            families: OPENAI_FAMILY,
            dialects,
            cyber: Some(programs),
            embedding_dimensions: None,
            modalities: None,
            system_one: None,
            operations: &[],
        },
    }
}

fn embedding(id: &'static str, dimensions: bool) -> Row {
    Row {
        id,
        dated: true,
        record: ModelRecord {
            families: OPENAI_FAMILY,
            dialects: EMBEDDINGS_ONLY,
            cyber: None,
            embedding_dimensions: Some(dimensions),
            modalities: Some(TEXT_ONLY),
            system_one: None,
            operations: &[],
        },
    }
}

fn system_one(id: &'static str, images: bool, box_questions: bool) -> Row {
    Row {
        id,
        dated: false,
        record: ModelRecord {
            families: TYPESAFE,
            dialects: SYSTEM_ONE,
            cyber: None,
            embedding_dimensions: None,
            modalities: None,
            system_one: Some(SystemOneCaps {
                images,
                box_questions,
            }),
            operations: &[],
        },
    }
}

fn audio(id: &'static str, dialect: Dialect, operations: &'static [Operation]) -> Row {
    Row {
        id,
        dated: true,
        record: ModelRecord {
            families: OPENAI_FAMILY,
            dialects: match dialect {
                Dialect::Transcription => TRANSCRIPTION,
                Dialect::Speech => SPEECH,
                Dialect::Realtime => REALTIME,
                _ => NONE,
            },
            cyber: None,
            embedding_dimensions: None,
            modalities: None,
            system_one: None,
            operations,
        },
    }
}

const TEXT_IMAGE_AUDIO: &[Modality] = &[Modality::Text, Modality::Image, Modality::Audio];

fn audio_chat(id: &'static str) -> Row {
    Row {
        id,
        dated: true,
        record: ModelRecord {
            families: OPENAI_FAMILY,
            dialects: CHAT_AND_RESPONSES_DIALECTS,
            cyber: None,
            embedding_dimensions: None,
            modalities: Some(TEXT_IMAGE_AUDIO),
            system_one: None,
            operations: &[],
        },
    }
}

fn audio_chat_records() -> impl Iterator<Item = Row> {
    [
        "gpt-4o-audio-preview",
        "gpt-4o-mini-audio-preview",
        "gpt-audio",
        "gpt-audio-1.5",
        "gpt-audio-mini",
    ]
    .into_iter()
    .map(audio_chat)
}

fn audio_records() -> impl Iterator<Item = Row> {
    const TRANSCRIBE: &[Operation] = &[Operation::Transcribe];
    const DIARIZE: &[Operation] = &[Operation::Transcribe, Operation::Diarize];
    const SPEAK: &[Operation] = &[Operation::Speak];
    const LIVE: &[Operation] = &[Operation::Realtime];
    [
        audio("whisper-1", Dialect::Transcription, TRANSCRIBE),
        audio("gpt-4o-mini-transcribe", Dialect::Transcription, TRANSCRIBE),
        audio("gpt-4o-transcribe", Dialect::Transcription, TRANSCRIBE),
        audio("gpt-transcribe", Dialect::Transcription, TRANSCRIBE),
        audio("gpt-live-transcribe", Dialect::Transcription, TRANSCRIBE),
        audio("gpt-4o-transcribe-diarize", Dialect::Transcription, DIARIZE),
        audio("tts-1", Dialect::Speech, SPEAK),
        audio("tts-1-hd", Dialect::Speech, SPEAK),
        audio("gpt-4o-mini-tts", Dialect::Speech, SPEAK),
        audio("gpt-4o-mini-realtime-preview", Dialect::Realtime, LIVE),
        audio("gpt-4o-realtime-preview", Dialect::Realtime, LIVE),
        audio("gpt-realtime", Dialect::Realtime, LIVE),
        audio("gpt-realtime-1.5", Dialect::Realtime, LIVE),
        audio("gpt-realtime-2", Dialect::Realtime, LIVE),
        audio("gpt-realtime-2.1", Dialect::Realtime, LIVE),
        audio("gpt-realtime-2.1-mini", Dialect::Realtime, LIVE),
        audio("gpt-realtime-mini", Dialect::Realtime, LIVE),
        audio("gpt-realtime-translate", Dialect::Realtime, LIVE),
        audio("gpt-realtime-whisper", Dialect::Realtime, LIVE),
    ]
    .into_iter()
}

/// Public generation ids. Chat and Responses are both listed where either client
/// route should reach OpenAI; older chat-only ids stay on Chat so a Responses
/// client is translated instead of sent to an endpoint the model never had.
const GENERATION: &[&str] = &[
    "gpt-4.1",
    "gpt-4.1-mini",
    "gpt-4.1-nano",
    "gpt-4o",
    "gpt-4o-mini",
    "gpt-5",
    "gpt-5-mini",
    "gpt-5-nano",
    "gpt-5-pro",
    "gpt-5-codex",
    "gpt-5.1",
    "gpt-5.1-codex",
    "gpt-5.1-codex-mini",
    "gpt-5.1-codex-max",
    "gpt-5.2",
    "gpt-5.2-pro",
    "gpt-5.2-codex",
    "gpt-5.3-codex",
    "gpt-5.4",
    "gpt-5.4-mini",
    "gpt-5.4-nano",
    "gpt-5.4-pro",
    "gpt-5.5",
    "gpt-5.5-pro",
    "gpt-5.6-luna",
    "gpt-5.6-sol",
    "gpt-5.6-terra",
    "gpt-oss-120b",
    "gpt-oss-20b",
    "o1",
    "o1-mini",
    "o1-pro",
    "o3",
    "o3-mini",
    "o3-pro",
    "o4-mini",
    "codex-mini-latest",
];

const CHAT: &[&str] = &[
    "chat-latest",
    "chatgpt-4o-latest",
    "gpt-3.5-turbo",
    "gpt-4",
    "gpt-4-turbo",
    "gpt-4-turbo-preview",
    "gpt-4.5-preview",
    "gpt-4o-mini-search-preview",
    "gpt-4o-search-preview",
    "gpt-5-chat-latest",
    "gpt-5.1-chat-latest",
    "gpt-5.2-chat-latest",
    "gpt-5.3-chat-latest",
];

/// Known OpenAI ids that are not generation, embeddings, or decisions. Recording
/// them refuses those routes instead of falling through to the default provider.
const OTHER: &[&str] = &[
    "babbage-002",
    "chatgpt-image-latest",
    "computer-use-preview",
    "davinci-002",
    "gpt-image-1",
    "gpt-image-1-mini",
    "gpt-image-1.5",
    "gpt-image-2",
    "gpt-image-2.5-flare",
    "gpt-image-2.5-sunburst",
    "gpt-live-1",
    "gpt-rosalind-research",
    "omni-moderation-latest",
    "text-moderation-latest",
    "text-moderation-stable",
];

fn records() -> impl Iterator<Item = Row> {
    let luna = std::iter::once(Row {
        id: "gpt-6-luna",
        dated: true,
        record: ModelRecord {
            families: OPENAI_AND_CODEX,
            dialects: RESPONSES_AND_DECISIONS,
            cyber: None,
            embedding_dimensions: None,
            modalities: None,
            system_one: None,
            operations: &[],
        },
    });
    let generation = GENERATION
        .iter()
        .copied()
        .map(|id| row(id, true, OPENAI_FAMILY, CHAT_AND_RESPONSES_DIALECTS));
    let chat = CHAT
        .iter()
        .copied()
        .map(|id| row(id, true, OPENAI_FAMILY, CHAT_ONLY));
    let responses = [
        cyber("gpt-6-sol", CHAT_AND_RESPONSES_DIALECTS, BLUE),
        cyber("gpt-6.1-sol", CHAT_AND_RESPONSES_DIALECTS, BLUE),
        cyber("gpt-6-astra", CHAT_AND_RESPONSES_DIALECTS, BLUE),
        cyber("gpt-5.6-cyber", RESPONSES_ONLY, RED),
        row("o1-preview", true, OPENAI_FAMILY, RESPONSES_ONLY),
        row("o3-deep-research", true, OPENAI_FAMILY, RESPONSES_ONLY),
        row("o4-mini-deep-research", true, OPENAI_FAMILY, RESPONSES_ONLY),
        row("daybreak-blue-latest", false, OPENAI_FAMILY, RESPONSES_ONLY),
        row("daybreak-red-latest", false, OPENAI_FAMILY, RESPONSES_ONLY),
        row(
            "gpt-daybreak-blue-latest",
            false,
            OPENAI_FAMILY,
            RESPONSES_ONLY,
        ),
        row(
            "gpt-daybreak-red-latest",
            false,
            OPENAI_FAMILY,
            RESPONSES_ONLY,
        ),
    ];
    let embeddings = [
        embedding("text-embedding-3-large", true),
        embedding("text-embedding-3-small", true),
        embedding("text-embedding-ada-002", false),
    ];
    let other = OTHER
        .iter()
        .copied()
        .map(|id| row(id, true, OPENAI_FAMILY, NONE));
    let local = std::iter::once(Row {
        id: "ggml-org/embeddinggemma-2-GGUF:Q8_0",
        dated: false,
        record: ModelRecord {
            families: LLAMA_FAMILY,
            dialects: EMBEDDINGS_ONLY,
            cyber: None,
            embedding_dimensions: Some(false),
            modalities: Some(EMBEDDINGGEMMA_MEDIA),
            system_one: None,
            operations: &[],
        },
    });
    let typesafe = [
        system_one("jev-latest", true, true),
        system_one("jev-preview", true, true),
        system_one("jev-1.14", true, true),
        system_one("jev-1.14.0", true, true),
        system_one("jev-1.13", true, false),
        system_one("jev-1.13.0", true, false),
    ];
    let clairic = std::iter::once(row("@cf/cloudflare/clairic", false, CLOUDFLARE, EXTRACTION));
    luna.chain(generation)
        .chain(chat)
        .chain(responses)
        .chain(embeddings)
        .chain(audio_records())
        .chain(audio_chat_records())
        .chain(other)
        .chain(local)
        .chain(typesafe)
        .chain(clairic)
}

pub fn listed() -> Vec<(&'static str, ModelRecord)> {
    records().map(|row| (row.id, row.record)).collect()
}

pub fn lookup(model: &str) -> Option<ModelRecord> {
    find(model).or_else(|| {
        let rest = model.strip_prefix("ft:")?;
        let base = rest.split(':').next()?;
        (!base.is_empty()).then(|| find(base)).flatten()
    })
}

/// Resolve a client model, including a `#daybreak-blue` or `#daybreak-red`
/// suffix. The suffix is not an upstream id: it selects the base model and the
/// Responses `access_programs.cyber` value to set.
pub fn resolve(model: &str) -> Result<Option<Hit>, String> {
    if let Some((base, program)) = model.split_once('#') {
        let Some(record) = lookup(base) else {
            return Err(format!("unknown model {base}"));
        };
        let Some(allowed) = record.cyber else {
            return Err(format!("{base} has no Daybreak access program"));
        };
        let Some(parsed) = CyberProgram::parse(program) else {
            return Err(format!("unknown access program {program}"));
        };
        if !allowed.contains(&parsed) || parsed == CyberProgram::Standard {
            return Err(format!(
                "{base} does not accept access program {}",
                parsed.as_str()
            ));
        }
        return Ok(Some(Hit {
            record,
            upstream_model: base.to_owned(),
            inject_cyber: Some(parsed.as_str()),
        }));
    }
    Ok(lookup(model).map(|record| Hit {
        record,
        upstream_model: model.to_owned(),
        inject_cyber: None,
    }))
}

pub fn validate_cyber(model: &str, body: &serde_json::Value) -> Result<(), String> {
    let Some(record) = lookup(model) else {
        return Ok(());
    };
    let Some(allowed) = record.cyber else {
        return Ok(());
    };
    match body.pointer("/access_programs/cyber") {
        None => Ok(()),
        Some(serde_json::Value::Null) => {
            Err("access_programs.cyber does not accept null".to_owned())
        }
        Some(serde_json::Value::String(value)) => {
            let Some(program) = CyberProgram::parse(value) else {
                return Err(format!("{model} does not accept access program {value}"));
            };
            if allowed.contains(&program) {
                Ok(())
            } else {
                Err(format!("{model} does not accept access program {value}"))
            }
        }
        Some(_) => Err("access_programs.cyber must be a string".to_owned()),
    }
}

pub fn embedding_dimensions(model: &str) -> Option<bool> {
    lookup(model).and_then(|record| record.embedding_dimensions)
}

/// Audio and video input require a same-protocol provider. Known models and
/// explicit alias declarations must allow the requested media.
/// Image input stays allowed when the record does not constrain modalities.
/// An unknown id is not constrained. Declared audio and video are not translated.
pub fn reject_undeclared_generation_media(
    model: &str,
    body: &serde_json::Value,
    declared: Option<&[Modality]>,
    translated: bool,
) -> Result<(), String> {
    let mut parts = Vec::new();
    collect_media(body, &mut parts);
    if parts.is_empty() {
        return Ok(());
    }
    let allowed = declared.or_else(|| lookup(model).and_then(|record| record.modalities));
    let known = lookup(model).is_some() || declared.is_some();
    for modality in parts {
        if translated && matches!(modality, Modality::Audio | Modality::Video) {
            return Err(format!(
                "{model} {} input is not translated; use a provider that already speaks this protocol",
                modality.as_str()
            ));
        }
        if let Some(allowed) = allowed {
            if !allowed.contains(&modality) {
                return Err(format!(
                    "{model} does not declare {} input",
                    modality.as_str()
                ));
            }
            continue;
        }
        if known && matches!(modality, Modality::Audio | Modality::Video) {
            return Err(format!(
                "{model} does not declare {} input",
                modality.as_str()
            ));
        }
    }
    Ok(())
}

fn collect_media(value: &serde_json::Value, found: &mut Vec<Modality>) {
    match value {
        serde_json::Value::Array(items) => {
            for item in items {
                collect_media(item, found);
            }
        }
        serde_json::Value::Object(object) => {
            if let Some(kind) = object.get("type").and_then(serde_json::Value::as_str) {
                let modality = match kind {
                    "image_url" | "input_image" | "image" => Some(Modality::Image),
                    "input_audio" | "audio" => Some(Modality::Audio),
                    "input_video" | "video" => Some(Modality::Video),
                    _ => None,
                };
                if let Some(modality) = modality {
                    found.push(modality);
                }
            }
            for (key, child) in object {
                if key != "type" {
                    collect_media(child, found);
                }
            }
        }
        _ => {}
    }
}

pub fn validate_embedding_input(
    model: &str,
    body: &serde_json::Value,
    declared: Option<&[Modality]>,
) -> Result<(), String> {
    let allowed = match declared {
        Some(declared) => Some(declared),
        None => lookup(model).and_then(|record| record.modalities),
    };
    let Some(allowed) = allowed else {
        return Ok(());
    };
    let Some(input) = body.get("input") else {
        return Err("embeddings request is missing input".to_owned());
    };
    for modality in embedding_modalities(input)? {
        if !allowed.contains(&modality) {
            return Err(format!(
                "{model} embeddings do not accept {} input",
                modality.as_str()
            ));
        }
    }
    Ok(())
}

pub fn system_one_caps(model: &str) -> Option<SystemOneCaps> {
    lookup(model).and_then(|record| record.system_one)
}

fn embedding_modalities(input: &serde_json::Value) -> Result<Vec<Modality>, String> {
    match input {
        serde_json::Value::String(_) => Ok(vec![Modality::Text]),
        serde_json::Value::Array(items) if items.iter().all(serde_json::Value::is_number) => {
            Ok(vec![Modality::Text])
        }
        serde_json::Value::Array(items)
            if items.iter().all(|item| {
                item.is_string()
                    || item
                        .as_array()
                        .is_some_and(|tokens| tokens.iter().all(serde_json::Value::is_number))
            }) =>
        {
            Ok(vec![Modality::Text])
        }
        serde_json::Value::Array(items) => {
            let mut found = Vec::new();
            for item in items {
                let content = item
                    .as_object()
                    .and_then(|object| object.get("content"))
                    .and_then(serde_json::Value::as_array)
                    .ok_or_else(|| {
                        "embedding input object must contain a content array".to_owned()
                    })?;
                for part in content {
                    let kind = part
                        .get("type")
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| "embedding content part is missing type".to_owned())?;
                    let modality = match kind {
                        "text" => Modality::Text,
                        "image_url" => Modality::Image,
                        "input_audio" => Modality::Audio,
                        "input_video" => Modality::Video,
                        other => {
                            return Err(format!("unsupported embedding content type {other}"));
                        }
                    };
                    if !found.contains(&modality) {
                        found.push(modality);
                    }
                }
            }
            if found.is_empty() {
                return Err("embedding content array is empty".to_owned());
            }
            Ok(found)
        }
        _ => Err("embedding input must be text, tokens, or content parts".to_owned()),
    }
}

fn find(model: &str) -> Option<ModelRecord> {
    records().find_map(|row| {
        let dated = row.dated && dated_snapshot(model, row.id);
        (model == row.id || dated).then_some(row.record)
    })
}

fn dated_snapshot(model: &str, id: &str) -> bool {
    let Some(rest) = model
        .strip_prefix(id)
        .and_then(|tail| tail.strip_prefix('-'))
    else {
        return false;
    };
    let bytes = rest.as_bytes();
    bytes.len() >= 10
        && bytes[0..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-'
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[7] == b'-'
        && bytes[8..10].iter().all(u8::is_ascii_digit)
        && (bytes.len() == 10 || bytes[10] == b'-')
}

/// Native dialect first. Generation dialects share `translate`. Decisions and
/// System One translate in both directions for the supported typed subset.
/// Embeddings have no second dialect.
pub fn target_dialect(client: Dialect, native: &[Dialect]) -> Option<Dialect> {
    if native.contains(&client) {
        return Some(client);
    }
    match client {
        Dialect::Chat | Dialect::Responses | Dialect::Messages => {
            [Dialect::Chat, Dialect::Responses, Dialect::Messages]
                .into_iter()
                .find(|dialect| native.contains(dialect))
        }
        Dialect::Decisions if native.contains(&Dialect::SystemOne) => Some(Dialect::SystemOne),
        Dialect::SystemOne if native.contains(&Dialect::Decisions) => Some(Dialect::Decisions),
        _ => None,
    }
}

pub const CHAT_AND_RESPONSES: &[Dialect] = &[Dialect::Chat, Dialect::Responses];
pub const OPENAI: &[Dialect] = &[
    Dialect::Chat,
    Dialect::Responses,
    Dialect::Embeddings,
    Dialect::Transcription,
    Dialect::Speech,
    Dialect::Realtime,
];
const TRANSCRIPTION: &[Dialect] = &[Dialect::Transcription];
const SPEECH: &[Dialect] = &[Dialect::Speech];
const REALTIME: &[Dialect] = &[Dialect::Realtime];
pub const RESPONSES: &[Dialect] = &[Dialect::Responses];
pub const MESSAGES: &[Dialect] = &[Dialect::Messages];
pub const DECISIONS: &[Dialect] = &[Dialect::Decisions];
pub const LLAMA: &[Dialect] = &[
    Dialect::Chat,
    Dialect::Responses,
    Dialect::SystemOne,
    Dialect::Embeddings,
    Dialect::Realtime,
];
pub const SYSTEM_ONE: &[Dialect] = &[Dialect::SystemOne];
pub const CLAIRIC: &[Dialect] = &[Dialect::Extraction];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_inherits_fine_tune_base_and_does_not_cross_decision_dialects() {
        let luna = lookup("ft:gpt-6-luna:acme:job").unwrap();
        assert!(luna.families.contains(&Family::Openai));
        assert!(luna.dialects.contains(&Dialect::Decisions));
        assert_eq!(
            target_dialect(Dialect::Decisions, luna.dialects),
            Some(Dialect::Decisions)
        );
        assert_eq!(
            target_dialect(Dialect::SystemOne, luna.dialects),
            Some(Dialect::Decisions)
        );
        assert_eq!(
            target_dialect(Dialect::Decisions, &[Dialect::SystemOne]),
            Some(Dialect::SystemOne)
        );
        assert_eq!(
            target_dialect(Dialect::Chat, &[Dialect::Responses]),
            Some(Dialect::Responses)
        );
        assert_eq!(target_dialect(Dialect::Embeddings, &[Dialect::Chat]), None);
        assert_eq!(
            target_dialect(Dialect::Embeddings, &[Dialect::Embeddings]),
            Some(Dialect::Embeddings)
        );
    }

    #[test]
    fn dated_snapshots_do_not_swallow_sibling_ids() {
        assert!(lookup("gpt-4o-2024-08-06").is_some());
        assert_eq!(
            lookup("gpt-4o-mini").unwrap().dialects,
            CHAT_AND_RESPONSES_DIALECTS
        );
        assert!(lookup("gpt-4o-mini-2024-07-18").is_some());
        let whisper = lookup("whisper-1").unwrap();
        assert_eq!(whisper.dialects, TRANSCRIPTION);
        assert_eq!(whisper.operations, &[Operation::Transcribe]);
        assert!(
            lookup("gpt-4o-transcribe-diarize")
                .unwrap()
                .operations
                .contains(&Operation::Diarize)
        );
        assert_eq!(
            lookup("text-embedding-ada-002")
                .unwrap()
                .embedding_dimensions,
            Some(false)
        );
        assert_eq!(
            lookup("ggml-org/embeddinggemma-2-GGUF:Q8_0")
                .unwrap()
                .families,
            LLAMA_FAMILY
        );
        let daybreak = resolve("gpt-6-sol-2026-08-01#daybreak-blue")
            .unwrap()
            .unwrap();
        assert_eq!(daybreak.upstream_model, "gpt-6-sol-2026-08-01");
        assert_eq!(daybreak.inject_cyber, Some("daybreak_blue"));
        assert!(resolve("gpt-6-sol#daybreak-red").is_err());
        assert!(resolve("gpt-4o#daybreak-blue").is_err());
    }

    #[test]
    fn embedding_and_system_one_media_follow_the_catalog() {
        let text = serde_json::json!({"input":["hello",[1,2]]});
        assert!(validate_embedding_input("text-embedding-3-small", &text, None).is_ok());
        let image = serde_json::json!({"input":[{"content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,YQ=="}}]}]});
        assert!(validate_embedding_input("text-embedding-3-small", &image, None).is_err());
        assert!(
            validate_embedding_input("ggml-org/embeddinggemma-2-GGUF:Q8_0", &image, None).is_ok()
        );
        assert!(
            validate_embedding_input(
                "ggml-org/embeddinggemma-2-GGUF:Q8_0",
                &image,
                Some(&[Modality::Text]),
            )
            .is_err()
        );
        let caps = system_one_caps("jev-1.13").unwrap();
        assert!(caps.images);
        assert!(!caps.box_questions);
        assert!(system_one_caps("jev-latest").unwrap().box_questions);
        assert!(system_one_caps("meta-llama/Llama-3.1-8B").is_none());
    }
}
