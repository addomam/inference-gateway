//! Machine-readable description of what this process can route. This is not an
//! OpenAPI document. `/v1/models` remains the selected backend's own list.

use serde_json::{Value, json};

use crate::{catalog, config::Config};

pub fn document(config: &Config) -> Value {
    let providers: Vec<_> = config
        .providers
        .iter()
        .map(|(name, provider)| {
            json!({
                "name": name,
                "kind": provider.kind,
                "dialects": provider.kind.dialects().iter().map(|dialect| dialect.as_str()).collect::<Vec<_>>(),
                "family": family_name(provider.kind.family()),
                "daybreak": provider.daybreak.as_str(),
                "danger_zone_images": provider.danger_zone_images,
                "namespace": provider.namespace,
            })
        })
        .collect();
    let mut models = Vec::new();
    for (id, record) in catalog::listed() {
        let Some(provider) = serving_provider(config, &record) else {
            continue;
        };
        if let Some(program) = required_program(id, &record)
            && !provider.1.daybreak.allows(program)
        {
            continue;
        }
        models.push(model_json(id, &record, provider.0, None));
        if let Some(programs) = record.cyber {
            for program in programs {
                if matches!(
                    program,
                    catalog::CyberProgram::DaybreakBlue | catalog::CyberProgram::DaybreakRed
                ) && provider.1.daybreak.allows(program.as_str())
                {
                    let suffix = match program {
                        catalog::CyberProgram::DaybreakBlue => "daybreak-blue",
                        catalog::CyberProgram::DaybreakRed => "daybreak-red",
                        catalog::CyberProgram::Standard => continue,
                    };
                    models.push(model_json(
                        &format!("{id}#{suffix}"),
                        &record,
                        provider.0,
                        Some(program.as_str()),
                    ));
                }
            }
        }
    }
    json!({
        "object": "infer.capabilities",
        "routes": routes(),
        "providers": providers,
        "models": models,
    })
}

fn routes() -> Vec<Value> {
    [
        ("POST", "/v1/messages", "messages"),
        ("POST", "/v1/chat/completions", "chat"),
        ("POST", "/v1/responses", "responses"),
        ("POST", "/v1/decisions", "decisions"),
        ("POST", "/v1/systemone", "system_one"),
        ("POST", "/v1/embeddings", "embeddings"),
        ("POST", "/v1/audio/transcriptions", "transcription"),
        ("POST", "/v1/audio/speech", "speech"),
        ("POST", "/v1/audio/diarization", "diarization"),
        ("POST", "/v1/files", "files"),
        ("GET", "/v1/realtime", "realtime"),
        (
            "POST",
            "/client/v4/accounts/{account}/ai/run/@cf/cloudflare/clairic",
            "extraction",
        ),
        ("GET", "/v1/capabilities", "capabilities"),
    ]
    .into_iter()
    .map(|(method, path, dialect)| json!({"method": method, "path": path, "dialect": dialect}))
    .collect()
}

fn serving_provider<'a>(
    config: &'a Config,
    record: &catalog::ModelRecord,
) -> Option<(&'a str, &'a crate::config::Provider)> {
    let mut matched = config.providers.iter().filter(|(_, provider)| {
        record.dialects.iter().any(|dialect| {
            catalog::target_dialect(*dialect, record.dialects).is_some_and(|target| {
                record.families.contains(&provider.kind.family())
                    && provider.kind.dialects().contains(&target)
            })
        })
    });
    let (name, provider) = matched.next()?;
    matched
        .next()
        .is_none()
        .then_some((name.as_str(), provider))
}

fn required_program(id: &str, record: &catalog::ModelRecord) -> Option<&'static str> {
    if id.contains("daybreak-red") {
        return Some("daybreak_red");
    }
    if id.contains("daybreak-blue") {
        return Some("daybreak_blue");
    }
    record.cyber.and_then(|programs| {
        (programs == [catalog::CyberProgram::DaybreakRed]).then_some("daybreak_red")
    })
}

fn model_json(
    id: &str,
    record: &catalog::ModelRecord,
    provider: &str,
    access_program: Option<&str>,
) -> Value {
    json!({
        "id": id,
        "provider": provider,
        "families": record.families.iter().copied().map(family_name).collect::<Vec<_>>(),
        "dialects": record.dialects.iter().map(|dialect| dialect.as_str()).collect::<Vec<_>>(),
        "daybreak_programs": record.cyber.map(|programs| {
            programs.iter().map(|program| program.as_str()).collect::<Vec<_>>()
        }),
        "access_program": access_program,
        "embedding_dimensions": record.embedding_dimensions,
        "modalities": record.modalities.map(|modalities| {
            modalities.iter().map(|modality| modality_name(*modality)).collect::<Vec<_>>()
        }),
        "system_one": record.system_one.map(|caps| json!({
            "images": caps.images,
            "box_questions": caps.box_questions,
        })),
        "operations": record.operations.iter().map(|operation| operation.as_str()).collect::<Vec<_>>(),
    })
}

fn family_name(family: catalog::Family) -> &'static str {
    match family {
        catalog::Family::Openai => "openai",
        catalog::Family::Anthropic => "anthropic",
        catalog::Family::Xai => "xai",
        catalog::Family::Llama => "llama",
        catalog::Family::Codex => "codex",
        catalog::Family::Cloudflare => "cloudflare",
        catalog::Family::TypeSafe => "typesafe",
    }
}

fn modality_name(modality: catalog::Modality) -> &'static str {
    match modality {
        catalog::Modality::Text => "text",
        catalog::Modality::Image => "image",
        catalog::Modality::Audio => "audio",
        catalog::Modality::Video => "video",
    }
}
