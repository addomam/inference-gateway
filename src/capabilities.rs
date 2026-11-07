//! Machine-readable description of what this process can route. This is not an
//! OpenAPI document. `/v1/models` remains the selected backend's own list.

use std::collections::BTreeMap;

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
        let mut groups: BTreeMap<&str, Vec<catalog::Dialect>> = BTreeMap::new();
        for dialect in client_dialects() {
            let Some((name, provider)) = serving_provider(config, id, *dialect) else {
                continue;
            };
            if let Some(program) = required_program(id, &record)
                && !provider.daybreak.allows(program)
            {
                continue;
            }
            groups.entry(name).or_default().push(*dialect);
        }
        for (name, dialects) in &groups {
            let provider = &config.providers[*name];
            models.push(model_json(id, &record, name, None, dialects));
            let Some(programs) = record.cyber else {
                continue;
            };
            for program in programs {
                let suffix = match program {
                    catalog::CyberProgram::DaybreakBlue => "daybreak-blue",
                    catalog::CyberProgram::DaybreakRed => "daybreak-red",
                    catalog::CyberProgram::Standard => continue,
                };
                if !provider.daybreak.allows(program.as_str()) {
                    continue;
                }
                models.push(model_json(
                    &format!("{id}#{suffix}"),
                    &record,
                    name,
                    Some(program.as_str()),
                    dialects,
                ));
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

fn client_dialects() -> &'static [catalog::Dialect] {
    &[
        catalog::Dialect::Chat,
        catalog::Dialect::Responses,
        catalog::Dialect::Messages,
        catalog::Dialect::Decisions,
        catalog::Dialect::SystemOne,
        catalog::Dialect::Extraction,
        catalog::Dialect::Embeddings,
        catalog::Dialect::Transcription,
        catalog::Dialect::Speech,
        catalog::Dialect::Realtime,
        catalog::Dialect::Diarization,
    ]
}

fn serving_provider<'a>(
    config: &'a Config,
    id: &str,
    dialect: catalog::Dialect,
) -> Option<(&'a str, &'a crate::config::Provider)> {
    let name = config.resolve_model(id, dialect).ok()?.provider;
    let provider = config.providers.get(name)?;
    Some((name, provider))
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
    dialects: &[catalog::Dialect],
) -> Value {
    json!({
        "id": id,
        "provider": provider,
        "families": record.families.iter().copied().map(family_name).collect::<Vec<_>>(),
        "dialects": dialects.iter().map(|dialect| dialect.as_str()).collect::<Vec<_>>(),
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::catalog;
    use crate::config::Config;

    use super::document;

    const DIALECTS: [catalog::Dialect; 11] = [
        catalog::Dialect::Chat,
        catalog::Dialect::Responses,
        catalog::Dialect::Messages,
        catalog::Dialect::Decisions,
        catalog::Dialect::SystemOne,
        catalog::Dialect::Extraction,
        catalog::Dialect::Embeddings,
        catalog::Dialect::Transcription,
        catalog::Dialect::Speech,
        catalog::Dialect::Realtime,
        catalog::Dialect::Diarization,
    ];

    fn example_without_chatgpt() -> Config {
        let mut config: Config = toml::from_str(include_str!("../infer.example.toml")).unwrap();
        config.providers.remove("chatgpt");
        config
    }

    fn dialect_named(name: &str) -> catalog::Dialect {
        DIALECTS
            .into_iter()
            .find(|dialect| dialect.as_str() == name)
            .unwrap_or_else(|| panic!("unknown dialect {name}"))
    }

    fn listed_providers(document: &serde_json::Value, id: &str) -> BTreeMap<String, String> {
        let mut listed = BTreeMap::new();
        for model in document["models"].as_array().unwrap() {
            if model["id"].as_str() != Some(id) {
                continue;
            }
            let provider = model["provider"].as_str().unwrap().to_owned();
            for dialect in model["dialects"].as_array().unwrap() {
                let name = dialect.as_str().unwrap().to_owned();
                let previous = listed.insert(name.clone(), provider.clone());
                assert!(previous.is_none(), "{id} lists {name} under two providers");
            }
        }
        listed
    }

    #[test]
    fn listed_models_match_resolve_model() {
        let config = example_without_chatgpt();
        let document = document(&config);
        for model in document["models"].as_array().unwrap() {
            let id = model["id"].as_str().unwrap();
            let provider = model["provider"].as_str().unwrap();
            for dialect_name in model["dialects"].as_array().unwrap() {
                let name = dialect_name.as_str().unwrap();
                let dialect = dialect_named(name);
                let resolved = config.resolve_model(id, dialect);
                assert!(
                    resolved
                        .as_ref()
                        .is_ok_and(|selection| selection.provider == provider),
                    "{id} is listed for {name} under {provider}, resolve_model returned {resolved:?}"
                );
            }
        }
        let listed = listed_providers(&document, "gpt-6-luna");
        for dialect in DIALECTS {
            let name = dialect.as_str();
            match config.resolve_model("gpt-6-luna", dialect) {
                Ok(selection) => assert_eq!(
                    listed.get(name).map(String::as_str),
                    Some(selection.provider),
                    "gpt-6-luna for {name}, listed {listed:?}"
                ),
                Err(error) => assert!(
                    !listed.contains_key(name),
                    "gpt-6-luna is listed for {name} but resolve_model returned no provider: {error}; listed {listed:?}"
                ),
            }
        }
    }
}
