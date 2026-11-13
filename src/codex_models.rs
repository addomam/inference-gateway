//! ChatGPT Codex model discovery and the Responses body the official CLI sends.
//!
//! Behavior is taken from openai/codex `69231e119bfca0b14453515e97d99688ce1c47c9`:
//! `codex-rs/codex-api/src/endpoint/models.rs` (`GET {base}/models?client_version=`),
//! `codex-rs/codex-api/src/common.rs` (`ResponsesApiRequest`),
//! `codex-rs/core/src/client.rs` (`build_responses_request`, session headers,
//! `x-openai-internal-codex-responses-lite`), and
//! `codex-rs/login/src/auth/default_client.rs` (`default_headers` sets `originator`
//! to `codex_cli_rs` and does not set `version`). `codex exec` overrides the
//! originator to `codex_exec` and the provider map stamps `version` `0.169.0`.
//! Those request and models files match
//! release `rust-v0.169.0` (`d32063f96c2dff1dc96af839b3952abb6acfeda4`).
//! `client_version_to_whole()` is the Cargo package version. That release stamps
//! `0.169.0`. The main workspace version at the pinned commit is `0.0.0`, which
//! is below every bundled `minimal_client_version` (`0.98.0` through `0.155.0`).
//!
//! `CODEX_SUBSCRIPTION_MODELS` is only the fallback list when discovery fails.
//! It is not the account's entitlement. Request flags below are the bundled
//! `models.json` values at the same commit (`use_responses_lite`,
//! `default_reasoning_level`, `default_verbosity`). `gpt-5.6-sol` is Responses
//! Lite: `parallel_tool_calls` is false, `reasoning.context` is `all_turns`, and
//! the lite header is set. There is no top-level `instructions` field. Base
//! instructions are a `developer` input message when the catalog or the caller
//! supplies them.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use serde_json::{Map, Value, json};

use crate::catalog::CODEX_SUBSCRIPTION_MODELS;

pub const CODEX_SOURCE_COMMIT: &str = "69231e119bfca0b14453515e97d99688ce1c47c9";
pub const CODEX_RELEASE_COMMIT: &str = "d32063f96c2dff1dc96af839b3952abb6acfeda4";
pub const CODEX_CLIENT_VERSION: &str = "0.169.0";
const CACHE_TTL: Duration = Duration::from_secs(300);
const REASONING_INCLUDE: &str = "reasoning.encrypted_content";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ModelProfile {
    pub responses_lite: bool,
    pub reasoning_effort: Option<String>,
    pub verbosity: Option<String>,
    pub instructions: Option<String>,
}

#[derive(Clone, Debug)]
struct Discovered {
    slug: String,
    priority: i64,
    profile: ModelProfile,
}

struct Entry {
    fetched_at: Instant,
    models: Vec<Discovered>,
}

#[derive(Default)]
pub(crate) struct Catalog {
    entries: Mutex<HashMap<String, Entry>>,
}

impl Catalog {
    pub(crate) fn store(&self, provider: &str, models: Vec<DiscoveredModel>) {
        let mut models: Vec<Discovered> = models.into_iter().map(Discovered::from).collect();
        models.sort_by(|left, right| {
            left.priority
                .cmp(&right.priority)
                .then_with(|| left.slug.cmp(&right.slug))
        });
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        entries.insert(
            provider.to_owned(),
            Entry {
                fetched_at: Instant::now(),
                models,
            },
        );
    }

    pub(crate) fn fresh_ids(&self, provider: &str) -> Option<Vec<String>> {
        let entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let entry = entries.get(provider)?;
        (entry.fetched_at.elapsed() < CACHE_TTL).then(|| ids(entry))
    }

    pub(crate) fn cached_ids(&self, provider: &str) -> Option<Vec<String>> {
        let entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        entries.get(provider).map(ids)
    }

    pub(crate) fn profile(&self, provider: &str, slug: &str) -> ModelProfile {
        let entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        entries
            .get(provider)
            .and_then(|entry| {
                entry
                    .models
                    .iter()
                    .find(|model| model.slug == slug)
                    .map(|model| model.profile.clone())
            })
            .unwrap_or_else(|| bundled(slug))
    }
}

fn ids(entry: &Entry) -> Vec<String> {
    entry
        .models
        .iter()
        .map(|model| model.slug.clone())
        .collect()
}

#[derive(Clone, Debug)]
pub(crate) struct DiscoveredModel {
    pub slug: String,
    pub priority: i64,
    pub profile: ModelProfile,
}

impl From<DiscoveredModel> for Discovered {
    fn from(model: DiscoveredModel) -> Self {
        Self {
            slug: model.slug,
            priority: model.priority,
            profile: model.profile,
        }
    }
}

pub(crate) fn models_url(base: &str) -> String {
    format!(
        "{}/models?client_version={CODEX_CLIENT_VERSION}",
        base.trim_end_matches('/')
    )
}

pub(crate) fn static_ids() -> Vec<String> {
    CODEX_SUBSCRIPTION_MODELS
        .iter()
        .map(|id| (*id).to_owned())
        .collect()
}

pub(crate) fn openai_list(ids: &[String]) -> Value {
    json!({
        "object": "list",
        "data": ids.iter().map(|id| json!({
            "id": id,
            "object": "model",
            "created": 0,
            "owned_by": "openai"
        })).collect::<Vec<_>>()
    })
}

pub(crate) fn parse_catalog(bytes: &[u8]) -> Result<Vec<DiscoveredModel>, String> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| "models response was not JSON")?;
    let models = value
        .get("models")
        .and_then(Value::as_array)
        .ok_or("models response has no models array")?;
    let mut parsed = Vec::new();
    for model in models {
        let Some(slug) = model.get("slug").and_then(Value::as_str) else {
            continue;
        };
        let slug = slug.trim();
        if slug.is_empty() {
            continue;
        }
        parsed.push(DiscoveredModel {
            slug: slug.to_owned(),
            priority: model.get("priority").and_then(Value::as_i64).unwrap_or(0),
            profile: ModelProfile {
                responses_lite: model
                    .get("use_responses_lite")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                reasoning_effort: model
                    .get("default_reasoning_level")
                    .and_then(Value::as_str)
                    .filter(|effort| !effort.is_empty())
                    .map(str::to_owned),
                verbosity: verbosity(model),
                instructions: instructions(model),
            },
        });
    }
    if parsed.is_empty() {
        return Err("models response did not include a slug".to_owned());
    }
    Ok(parsed)
}

fn verbosity(model: &Value) -> Option<String> {
    if model.get("support_verbosity").and_then(Value::as_bool) == Some(false) {
        return None;
    }
    model
        .get("default_verbosity")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn instructions(model: &Value) -> Option<String> {
    model
        .pointer("/model_messages/instructions_template")
        .or_else(|| model.get("base_instructions"))
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

std::thread_local! {
    static ACTIVE: std::cell::RefCell<Option<ModelProfile>> = const { std::cell::RefCell::new(None) };
}

pub(crate) struct ActiveProfile {
    previous: Option<ModelProfile>,
}

impl ActiveProfile {
    pub(crate) fn install(profile: ModelProfile) -> Self {
        let previous = ACTIVE.with(|slot| slot.replace(Some(profile)));
        Self { previous }
    }
}

impl Drop for ActiveProfile {
    fn drop(&mut self) {
        let previous = self.previous.take();
        ACTIVE.with(|slot| *slot.borrow_mut() = previous);
    }
}

pub(crate) fn shape(object: &mut Map<String, Value>) {
    let slug = object
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let profile = ACTIVE
        .with(|slot| slot.borrow().clone())
        .unwrap_or_else(|| bundled(&slug));
    let supplied = match object.remove("instructions") {
        Some(Value::String(text)) if !text.is_empty() => Some(text),
        _ => None,
    };
    let mut input = normalize_input(object.remove("input").unwrap_or(Value::Null));
    if let Some(text) = supplied {
        input.insert(0, developer_message(&text));
    } else if !has_developer(&input)
        && let Some(text) = profile
            .instructions
            .as_deref()
            .filter(|text| !text.is_empty())
    {
        input.insert(0, developer_message(text));
    }
    if profile.responses_lite {
        if let Some(Value::Array(tools)) = object.remove("tools")
            && !tools.is_empty()
        {
            input.insert(
                0,
                json!({"type":"additional_tools","role":"developer","tools": tools}),
            );
        }
    } else {
        let tools = object
            .remove("tools")
            .unwrap_or_else(|| Value::Array(Vec::new()));
        object.insert("tools".into(), tools);
    }
    object.insert("input".into(), Value::Array(input));
    object
        .entry("tool_choice")
        .or_insert(Value::String("auto".into()));
    if profile.responses_lite {
        object.insert("parallel_tool_calls".into(), Value::Bool(false));
    } else {
        object
            .entry("parallel_tool_calls")
            .or_insert(Value::Bool(true));
    }
    shape_reasoning(object, &profile);
    shape_include(object);
    if let Some(verbosity) = profile.verbosity.as_deref() {
        object
            .entry("text")
            .or_insert(json!({"verbosity": verbosity}));
    }
    object.insert("stream".into(), Value::Bool(true));
    object.insert("store".into(), Value::Bool(false));
}

fn shape_reasoning(object: &mut Map<String, Value>, profile: &ModelProfile) {
    if profile.reasoning_effort.is_none() && !profile.responses_lite {
        return;
    }
    let mut reasoning = match object.remove("reasoning") {
        Some(Value::Object(map)) => map,
        _ => Map::new(),
    };
    if let Some(effort) = &profile.reasoning_effort {
        reasoning
            .entry("effort")
            .or_insert(Value::String(effort.clone()));
    }
    if profile.responses_lite {
        reasoning
            .entry("context")
            .or_insert(Value::String("all_turns".into()));
    }
    if !reasoning.is_empty() {
        object.insert("reasoning".into(), Value::Object(reasoning));
    }
}

fn shape_include(object: &mut Map<String, Value>) {
    let mut include = match object.remove("include") {
        Some(Value::Array(items)) => items,
        _ => Vec::new(),
    };
    if !include
        .iter()
        .any(|item| item.as_str() == Some(REASONING_INCLUDE))
    {
        include.insert(0, Value::String(REASONING_INCLUDE.into()));
    }
    object.insert("include".into(), Value::Array(include));
}

fn normalize_input(value: Value) -> Vec<Value> {
    match value {
        Value::Array(items) => items.into_iter().map(normalize_item).collect(),
        Value::String(text) => vec![message("user", &text)],
        Value::Null => Vec::new(),
        other => vec![normalize_item(other)],
    }
}

fn normalize_item(value: Value) -> Value {
    let Value::Object(mut item) = value else {
        return value;
    };
    let typed_message = item.get("type").and_then(Value::as_str) == Some("message");
    if typed_message || item.contains_key("role") {
        if item.get("role").and_then(Value::as_str) == Some("system") {
            item.insert("role".into(), Value::String("developer".into()));
        }
        item.entry("type")
            .or_insert(Value::String("message".into()));
    }
    Value::Object(item)
}

fn has_developer(input: &[Value]) -> bool {
    input.iter().any(|item| {
        item.get("role").and_then(Value::as_str) == Some("developer")
            && item.get("type").and_then(Value::as_str) != Some("additional_tools")
    })
}

fn developer_message(text: &str) -> Value {
    message("developer", text)
}

fn message(role: &str, text: &str) -> Value {
    json!({
        "type": "message",
        "role": role,
        "content": [{"type": "input_text", "text": text}]
    })
}

fn bundled(slug: &str) -> ModelProfile {
    let Some((lite, effort, verbosity)) = BUNDLED
        .iter()
        .find(|(id, ..)| *id == slug)
        .map(|(_, lite, effort, verbosity)| (*lite, *effort, *verbosity))
    else {
        return ModelProfile {
            responses_lite: false,
            reasoning_effort: None,
            verbosity: None,
            instructions: None,
        };
    };
    ModelProfile {
        responses_lite: lite,
        reasoning_effort: Some(effort.to_owned()),
        verbosity: Some(verbosity.to_owned()),
        instructions: None,
    }
}

/// Bundled `models.json` flags at the pinned commit. Instructions text stays in
/// the account catalog response and is not copied here.
const BUNDLED: &[(&str, bool, &str, &str)] = &[
    ("gpt-6-astra", true, "low", "low"),
    ("gpt-6.1-sol", true, "low", "low"),
    ("gpt-6.1-terra", true, "low", "low"),
    ("gpt-6-sol", true, "medium", "low"),
    ("gpt-6-luna", true, "medium", "low"),
    ("gpt-5.6-sol", true, "low", "low"),
    ("gpt-5.6-terra", true, "medium", "low"),
    ("gpt-5.6-luna", true, "medium", "low"),
    ("gpt-daybreak-blue-latest", true, "low", "low"),
    ("gpt-daybreak-red-latest", true, "medium", "high"),
    ("gpt-5.5", false, "medium", "low"),
    ("codex-auto-review", true, "medium", "low"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn models_url_uses_the_released_client_version() {
        assert_eq!(CODEX_CLIENT_VERSION, "0.169.0");
        assert_eq!(CODEX_SOURCE_COMMIT.len(), 40);
        assert_eq!(CODEX_RELEASE_COMMIT.len(), 40);
        assert_eq!(
            models_url("https://chatgpt.com/backend-api/codex/"),
            "https://chatgpt.com/backend-api/codex/models?client_version=0.169.0"
        );
    }

    #[test]
    fn bundled_gpt_5_6_sol_is_responses_lite() {
        let profile = bundled("gpt-5.6-sol");
        assert!(profile.responses_lite);
        assert_eq!(profile.reasoning_effort.as_deref(), Some("low"));
        assert!(!bundled("gpt-5.5").responses_lite);
        assert!(bundled("gpt-4o-mini").reasoning_effort.is_none());
    }

    #[test]
    fn fixture_catalog_sorts_by_priority_and_hides_instructions_from_the_list() {
        let parsed = parse_catalog(include_bytes!("../tests/fixtures/codex/models.json")).unwrap();
        let catalog = Catalog::default();
        catalog.store("chatgpt", parsed);
        let ids = catalog.fresh_ids("chatgpt").unwrap();
        assert_eq!(ids, ["gpt-5.5", "gpt-5.6-sol"]);
        let listed = openai_list(&ids);
        assert!(!listed.to_string().contains("fixture-base-instructions"));
        let lite = catalog.profile("chatgpt", "gpt-5.6-sol");
        assert!(lite.responses_lite);
        assert_eq!(
            lite.instructions.as_deref(),
            Some("fixture-base-instructions")
        );
        assert!(!catalog.profile("chatgpt", "gpt-5.5").responses_lite);
    }
}
