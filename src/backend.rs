//! Provider capabilities. The proxy asks a backend whether it implements a
//! client contract; it does not match on [`Kind`] to decide that.
//!
//! A new contract adds a trait and a default `None` accessor here. Only
//! backends that speak it override the accessor. Generation already has more
//! than one dialect: Anthropic, Chat, and Responses translate inside the
//! generation route, and each backend only declares the dialect it can serve.

use http::{HeaderMap, HeaderValue};
use serde_json::Value;

use crate::{catalog::Dialect, config::Kind, translate::Protocol};

pub trait Generation: Send + Sync {
    fn target(&self, source: Protocol) -> Protocol;
    fn adapt(&self, target: Protocol, translated: bool, body: &mut Value) -> Option<&'static str> {
        let _ = (target, translated, body);
        None
    }
    fn upstream_path(&self, target: Protocol) -> &'static str {
        match target {
            Protocol::Anthropic => "/v1/messages",
            Protocol::Chat => "/v1/chat/completions",
            Protocol::Responses => "/v1/responses",
        }
    }
    fn forces_rewrite(&self) -> bool {
        false
    }
    /// The upstream answers with a Responses SSE body even when the client did not
    /// ask for a stream. Codex does this because `ResponsesApiRequest.stream` is true.
    fn expects_sse(&self) -> bool {
        false
    }
}

pub trait Decisions: Send + Sync {
    fn upstream_path(&self) -> &'static str {
        "/v1/decisions"
    }
}

pub trait SystemOne: Send + Sync {
    fn upstream_path(&self) -> &'static str {
        "/v1/systemone"
    }
}

pub trait Embeddings: Send + Sync {
    fn upstream_path(&self) -> &'static str {
        "/v1/embeddings"
    }

    /// Reject a client field this backend would ignore. A silent ignore is a
    /// different vector, not a compatible embedding response.
    fn reject(&self, body: &Value) -> Result<(), &'static str> {
        let _ = body;
        Ok(())
    }
}

pub trait Extraction: Send + Sync {
    fn upstream_path(&self, account: &str) -> String;
}

pub trait Backend: Send + Sync {
    fn generation(&self) -> Option<&dyn Generation> {
        None
    }
    fn decisions(&self) -> Option<&dyn Decisions> {
        None
    }
    fn system_one(&self) -> Option<&dyn SystemOne> {
        None
    }
    fn extraction(&self) -> Option<&dyn Extraction> {
        None
    }
    fn embeddings(&self) -> Option<&dyn Embeddings> {
        None
    }
    fn dialects(&self) -> &'static [Dialect];
    fn anthropic_credentials(&self) -> bool {
        false
    }
    fn prepare_headers(&self, headers: &mut HeaderMap, rewritten: bool);
}

pub fn get(kind: Kind) -> &'static dyn Backend {
    match kind {
        Kind::Anthropic => &Anthropic,
        Kind::Openai => &Openai,
        Kind::Grok => &ChatResponses,
        Kind::Llama => &Llama,
        Kind::Codex => &Codex,
        Kind::OpenaiDecisions => &OpenaiDecisions,
        Kind::SystemOne => &SystemOneBackend,
        Kind::Clairic => &Clairic,
    }
}

pub(crate) fn strip_body_digests(headers: &mut HeaderMap) {
    for name in ["content-digest", "repr-digest", "digest", "content-md5"] {
        headers.remove(name);
    }
}

fn standard_headers(headers: &mut HeaderMap, rewritten: bool) {
    if !rewritten {
        return;
    }
    rewritten_content_type(headers);
    headers.remove("content-encoding");
    strip_body_digests(headers);
    headers.remove("anthropic-beta");
    headers.remove("anthropic-version");
}

fn rewritten_content_type(headers: &mut HeaderMap) {
    let multipart = headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.to_ascii_lowercase().contains("multipart/"));
    if !multipart {
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
    }
}

struct ChatResponses;

impl Generation for ChatResponses {
    fn target(&self, source: Protocol) -> Protocol {
        Kind::Grok.protocol(source).expect("chat/responses backend")
    }
}

impl Backend for ChatResponses {
    fn generation(&self) -> Option<&dyn Generation> {
        Some(self)
    }
    fn dialects(&self) -> &'static [Dialect] {
        crate::catalog::CHAT_AND_RESPONSES
    }
    fn prepare_headers(&self, headers: &mut HeaderMap, rewritten: bool) {
        standard_headers(headers, rewritten);
    }
}

struct Llama;

impl Generation for Llama {
    fn target(&self, source: Protocol) -> Protocol {
        Kind::Llama
            .protocol(source)
            .expect("llama generation backend")
    }
}

impl SystemOne for Llama {}

impl Embeddings for Llama {
    fn reject(&self, body: &Value) -> Result<(), &'static str> {
        match body.get("dimensions") {
            None | Some(Value::Null) => Ok(()),
            Some(_) => Err(
                "llama.cpp does not apply embeddings dimensions and would return the model width; remove dimensions or use an OpenAI embeddings provider",
            ),
        }
    }
}

impl Backend for Llama {
    fn generation(&self) -> Option<&dyn Generation> {
        Some(self)
    }
    fn system_one(&self) -> Option<&dyn SystemOne> {
        Some(self)
    }
    fn embeddings(&self) -> Option<&dyn Embeddings> {
        Some(self)
    }
    fn dialects(&self) -> &'static [Dialect] {
        crate::catalog::LLAMA
    }
    fn prepare_headers(&self, headers: &mut HeaderMap, rewritten: bool) {
        standard_headers(headers, rewritten);
    }
}

struct Openai;

impl Generation for Openai {
    fn target(&self, source: Protocol) -> Protocol {
        Kind::Openai
            .protocol(source)
            .expect("openai generation backend")
    }
    fn adapt(&self, target: Protocol, translated: bool, body: &mut Value) -> Option<&'static str> {
        if translated
            && target == Protocol::Chat
            && let Some(cap) = body.as_object_mut().unwrap().remove("max_tokens")
        {
            body["max_completion_tokens"] = cap;
        }
        None
    }
}

impl Embeddings for Openai {}

impl Backend for Openai {
    fn generation(&self) -> Option<&dyn Generation> {
        Some(self)
    }
    fn embeddings(&self) -> Option<&dyn Embeddings> {
        Some(self)
    }
    fn dialects(&self) -> &'static [Dialect] {
        crate::catalog::OPENAI
    }
    fn prepare_headers(&self, headers: &mut HeaderMap, rewritten: bool) {
        standard_headers(headers, rewritten);
    }
}

struct Anthropic;

impl Generation for Anthropic {
    fn target(&self, source: Protocol) -> Protocol {
        Kind::Anthropic
            .protocol(source)
            .expect("anthropic generation backend")
    }
}

impl Backend for Anthropic {
    fn generation(&self) -> Option<&dyn Generation> {
        Some(self)
    }
    fn dialects(&self) -> &'static [Dialect] {
        crate::catalog::MESSAGES
    }
    fn anthropic_credentials(&self) -> bool {
        true
    }
    fn prepare_headers(&self, headers: &mut HeaderMap, rewritten: bool) {
        if !headers.contains_key("anthropic-version") {
            headers.insert("anthropic-version", HeaderValue::from_static("2023-06-01"));
        }
        if rewritten {
            rewritten_content_type(headers);
            headers.remove("content-encoding");
            strip_body_digests(headers);
        }
    }
}

struct Codex;

impl Generation for Codex {
    fn target(&self, source: Protocol) -> Protocol {
        Kind::Codex
            .protocol(source)
            .expect("codex generation backend")
    }
    fn adapt(
        &self,
        _target: Protocol,
        _translated: bool,
        body: &mut Value,
    ) -> Option<&'static str> {
        let object = body.as_object_mut()?;
        // Caps and sampling are not fields of `ResponsesApiRequest`. The rest of
        // the body is shaped to that struct in `codex_models::shape`.
        let dropped_cap = object.remove("max_output_tokens").is_some()
            || object.remove("max_tokens").is_some()
            || object.remove("max_completion_tokens").is_some();
        let dropped_sampling =
            object.remove("temperature").is_some() || object.remove("top_p").is_some();
        if object.get("instructions").is_some_and(Value::is_null) {
            object.remove("instructions");
        }
        crate::codex_models::shape(object);
        match (dropped_cap, dropped_sampling) {
            (true, true) => Some(
                "Codex subscription endpoint rejects max_output_tokens, temperature, and top_p; those fields were omitted",
            ),
            (true, false) => Some("Codex subscription endpoint does not enforce max_output_tokens"),
            (false, true) => Some(
                "Codex subscription endpoint rejects temperature and top_p; those fields were omitted",
            ),
            (false, false) => None,
        }
    }
    fn upstream_path(&self, _target: Protocol) -> &'static str {
        "/responses"
    }
    fn forces_rewrite(&self) -> bool {
        true
    }
    fn expects_sse(&self) -> bool {
        true
    }
}

impl Backend for Codex {
    fn generation(&self) -> Option<&dyn Generation> {
        Some(self)
    }
    fn dialects(&self) -> &'static [Dialect] {
        crate::catalog::RESPONSES
    }
    fn prepare_headers(&self, headers: &mut HeaderMap, rewritten: bool) {
        standard_headers(headers, rewritten);
        apply_codex_identity(headers);
        if rewritten {
            headers.insert(
                http::header::ACCEPT,
                HeaderValue::from_static("text/event-stream"),
            );
            // A new root thread uses one id for the session, the thread, and
            // `x-client-request-id` (`build_session_headers` plus the thread id).
            let session = uuid::Uuid::new_v4().to_string();
            insert_if_absent(headers, "session-id", &session);
            insert_if_absent(headers, "thread-id", &session);
            insert_if_absent(headers, "x-client-request-id", &session);
        }
    }
}

/// `codex exec` sets this originator. `default_headers` alone still says
/// `codex_cli_rs`; the exec binary overrides it before any request.
const CODEX_ORIGINATOR: &str = "codex_exec";
/// Product token only. OS, architecture, terminal, and the parenthetical
/// suffix come from the machine that ran the CLI and are not invented here.
const CODEX_USER_AGENT: &str = "codex_exec/0.169.0";

pub(crate) fn apply_codex_identity(headers: &mut HeaderMap) {
    headers.insert("originator", HeaderValue::from_static(CODEX_ORIGINATOR));
    headers.insert(
        "version",
        HeaderValue::from_static(crate::codex_models::CODEX_CLIENT_VERSION),
    );
    headers.insert("user-agent", HeaderValue::from_static(CODEX_USER_AGENT));
    headers.remove("openai-beta");
}

/// Fill the session trio the way a new `codex exec` thread does: one id for
/// `session-id`, `thread-id`, and `x-client-request-id` when the caller omitted them.
pub(crate) fn codex_outbound_headers(incoming: &HeaderMap) -> HeaderMap {
    let mut headers = incoming.clone();
    let session = incoming
        .get("session-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            incoming
                .get("thread-id")
                .and_then(|value| value.to_str().ok())
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    for name in ["session-id", "thread-id", "x-client-request-id"] {
        insert_if_absent(&mut headers, name, &session);
    }
    headers
}

/// The CLI's `prompt_cache_key` is the session id. A caller-supplied key stays.
pub(crate) fn ensure_codex_cache_key(bytes: bytes::Bytes, headers: &HeaderMap) -> bytes::Bytes {
    let Some(session) = headers
        .get("session-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
    else {
        return bytes;
    };
    let Ok(mut value) = crate::json::from_slice(&bytes) else {
        return bytes;
    };
    let Some(object) = value.as_object_mut() else {
        return bytes;
    };
    if object.contains_key("prompt_cache_key") {
        return bytes;
    }
    object.insert(
        "prompt_cache_key".to_owned(),
        Value::String(session.to_owned()),
    );
    match serde_json::to_vec(&value) {
        Ok(encoded) => bytes::Bytes::from(encoded),
        Err(_) => bytes,
    }
}

/// Headers `codex exec` derives from the request: routing hint, window id, and
/// turn metadata when the caller already put that metadata on the body.
pub(crate) fn stamp_codex_headers(headers: &mut HeaderMap, body: &[u8]) {
    let Ok(value) = crate::json::from_slice(body) else {
        return;
    };
    let Some(object) = value.as_object() else {
        return;
    };
    if let Some(model) = object
        .get("model")
        .and_then(Value::as_str)
        .filter(|model| !model.is_empty())
    {
        let hint = match object
            .get("service_tier")
            .and_then(Value::as_str)
            .filter(|tier| !tier.is_empty())
        {
            Some(tier) => format!("model={model};tier={tier}"),
            None => format!("model={model}"),
        };
        insert_header(headers, "x-codex-routing-hint", &hint);
    }
    // exec's window number is 0. A caller-supplied client_metadata window id wins.
    let supplied = value
        .pointer("/client_metadata/x-codex-window-id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    let derived = headers
        .get("session-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(|session| format!("{session}:0"));
    if let Some(window) = supplied.or(derived.as_deref()) {
        insert_header(headers, "x-codex-window-id", window);
    }
    if let Some(metadata) = value
        .pointer("/client_metadata/x-codex-turn-metadata")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    {
        insert_header(headers, "x-codex-turn-metadata", metadata);
    }
}

fn insert_header(headers: &mut HeaderMap, name: &'static str, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        headers.insert(name, value);
    }
}

fn insert_if_absent(headers: &mut HeaderMap, name: &'static str, value: &str) {
    if headers.contains_key(name) {
        return;
    }
    if let Ok(value) = HeaderValue::from_str(value) {
        headers.insert(name, value);
    }
}

/// Prefix for `derive_conversation_group_id` in grok 1.0.77. UUIDv5 of the
/// session id under the OID namespace. The committed chat-turn capture matches.
const GROK_CONVERSATION_GROUP_PREFIX: &str = "xai:grok-build:conversation-group:";
/// Detector window `x-grok-doom-loop-check` on the recorded streaming Responses turn.
const GROK_DOOM_LOOP_WINDOW: &str = "1024";
/// Exact-repetition minimum `x-grok-exact-repetition-check` on that same turn.
const GROK_EXACT_REPETITION_TOKENS: &str = "64";

/// Headers the official grok CLI derives on the way to cli-chat-proxy.
///
/// A caller-supplied value is kept. The conversation group id is UUIDv5 of
/// `x-grok-session-id`. The doom-loop defaults are added only on a streaming
/// Responses call that already carries grok-build client identity, which is
/// where 1.0.77 sent `1024` and `64`. Chat completions and a buffered
/// Responses call do not gain those two headers.
pub(crate) fn stamp_grok_headers(headers: &mut HeaderMap, path: &str) {
    if let Some(session) = header_text(headers, "x-grok-session-id") {
        let group = grok_conversation_group_id(session);
        insert_if_absent(headers, "x-grok-conv-group-id", &group);
    }
    if grok_responses_stream(path, headers) && grok_build_request(headers) {
        insert_if_absent(headers, "x-grok-doom-loop-check", GROK_DOOM_LOOP_WINDOW);
        insert_if_absent(
            headers,
            "x-grok-exact-repetition-check",
            GROK_EXACT_REPETITION_TOKENS,
        );
    }
}

fn grok_conversation_group_id(session_id: &str) -> String {
    uuid::Uuid::new_v5(
        &uuid::Uuid::NAMESPACE_OID,
        format!("{GROK_CONVERSATION_GROUP_PREFIX}{session_id}").as_bytes(),
    )
    .to_string()
}

fn grok_responses_stream(path: &str, headers: &HeaderMap) -> bool {
    let path = path.split('?').next().unwrap_or(path);
    path.trim_end_matches('/').ends_with("/responses") && accepts_event_stream(headers)
}

fn accepts_event_stream(headers: &HeaderMap) -> bool {
    headers
        .get(http::header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(',').any(|part| {
                part.split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .eq_ignore_ascii_case("text/event-stream")
            })
        })
}

fn grok_build_request(headers: &HeaderMap) -> bool {
    [
        "x-grok-client-identifier",
        "x-grok-client-version",
        "x-grok-client-mode",
        "x-authenticateresponse",
    ]
    .into_iter()
    .any(|name| header_text(headers, name).is_some())
}

fn header_text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
}

struct OpenaiDecisions;

impl Decisions for OpenaiDecisions {}

impl Backend for OpenaiDecisions {
    fn decisions(&self) -> Option<&dyn Decisions> {
        Some(self)
    }
    fn dialects(&self) -> &'static [Dialect] {
        crate::catalog::DECISIONS
    }
    fn prepare_headers(&self, headers: &mut HeaderMap, rewritten: bool) {
        standard_headers(headers, rewritten);
    }
}

struct SystemOneBackend;

impl SystemOne for SystemOneBackend {}

impl Backend for SystemOneBackend {
    fn system_one(&self) -> Option<&dyn SystemOne> {
        Some(self)
    }
    fn dialects(&self) -> &'static [Dialect] {
        crate::catalog::SYSTEM_ONE
    }
    fn prepare_headers(&self, headers: &mut HeaderMap, rewritten: bool) {
        if !rewritten {
            return;
        }
        if !headers.contains_key("content-type") {
            headers.insert("content-type", HeaderValue::from_static("application/json"));
        }
        headers.remove("content-encoding");
        strip_body_digests(headers);
        headers.remove("anthropic-beta");
        headers.remove("anthropic-version");
    }
}

struct Clairic;

impl Extraction for Clairic {
    fn upstream_path(&self, account: &str) -> String {
        format!("/client/v4/accounts/{account}/ai/run/@cf/cloudflare/clairic")
    }
}

impl Backend for Clairic {
    fn extraction(&self) -> Option<&dyn Extraction> {
        Some(self)
    }
    fn dialects(&self) -> &'static [Dialect] {
        crate::catalog::CLAIRIC
    }
    fn prepare_headers(&self, headers: &mut HeaderMap, rewritten: bool) {
        standard_headers(headers, rewritten);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn codex_chat_translation_drops_rejected_fields_and_keeps_the_model() {
        let generation = get(Kind::Codex).generation().unwrap();
        for model in ["gpt-4o-mini", "gpt-5-codex", "gpt-5.1-codex"] {
            let mut body = crate::translate::request(
                json!({
                    "model": model,
                    "messages": [{"role": "user", "content": "ping"}],
                    "max_tokens": 1,
                    "temperature": 0
                }),
                Protocol::Chat,
                Protocol::Responses,
            )
            .unwrap();
            let warning = generation.adapt(Protocol::Responses, true, &mut body);
            assert!(warning.is_some(), "{model}");
            assert_eq!(body["model"], model);
            assert_eq!(body["stream"], true);
            assert_eq!(body["store"], false);
            assert_eq!(body["tool_choice"], "auto");
            assert_eq!(body["parallel_tool_calls"], true);
            assert_eq!(body["include"][0], "reasoning.encrypted_content");
            assert!(body.get("max_output_tokens").is_none(), "{body}");
            assert!(body.get("max_tokens").is_none(), "{body}");
            assert!(body.get("temperature").is_none(), "{body}");
            assert!(body.get("top_p").is_none(), "{body}");
            assert!(body.get("instructions").is_none(), "{body}");
            assert!(body.get("reasoning").is_none(), "{body}");
            let input = body["input"].as_array().unwrap();
            assert_eq!(input[0]["type"], "message");
            assert_eq!(input[0]["role"], "user");
            assert_eq!(input[0]["content"][0]["text"], "ping");
        }
    }

    #[test]
    fn codex_responses_lite_model_matches_the_cli_request() {
        let generation = get(Kind::Codex).generation().unwrap();
        let mut body = crate::translate::request(
            json!({
                "model": "gpt-5.6-sol",
                "messages": [
                    {"role": "system", "content": "be brief"},
                    {"role": "user", "content": "ping"}
                ],
                "max_tokens": 1
            }),
            Protocol::Chat,
            Protocol::Responses,
        )
        .unwrap();
        generation.adapt(Protocol::Responses, true, &mut body);
        assert!(body.get("instructions").is_none(), "{body}");
        assert_eq!(body["input"][0]["type"], "message");
        assert_eq!(body["input"][0]["role"], "developer");
        assert_eq!(body["input"][0]["content"][0]["text"], "be brief");
        assert_eq!(body["input"][1]["role"], "user");
        assert_eq!(body["parallel_tool_calls"], false);
        assert_eq!(body["reasoning"]["effort"], "low");
        assert_eq!(body["reasoning"]["context"], "all_turns");
        assert_eq!(body["text"]["verbosity"], "low");
        assert!(body.get("tools").is_none(), "{body}");
        let mut headers = http::HeaderMap::new();
        get(Kind::Codex).prepare_headers(&mut headers, true);
        assert_eq!(headers["originator"], "codex_exec");
        assert_eq!(
            headers["version"],
            crate::codex_models::CODEX_CLIENT_VERSION
        );
        assert_eq!(headers["user-agent"], "codex_exec/0.169.0");
        assert!(
            headers["user-agent"]
                .to_str()
                .unwrap()
                .ends_with(crate::codex_models::CODEX_CLIENT_VERSION)
        );
        assert_eq!(headers["accept"], "text/event-stream");
        assert!(headers.get("openai-beta").is_none());
        assert_eq!(headers["session-id"], headers["thread-id"]);
        assert_eq!(headers["x-client-request-id"], headers["thread-id"]);
    }

    #[test]
    fn codex_stamp_derives_routing_window_and_keeps_caller_metadata() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "session-id",
            http::HeaderValue::from_static("00000000-0000-4000-8000-000000000001"),
        );
        let body = br#"{"model":"gpt-6.1-sol","service_tier":"priority","client_metadata":{"x-codex-window-id":"00000000-0000-4000-8000-000000000001:0","x-codex-turn-metadata":"{\"model\":\"gpt-6.1-sol\"}"}}"#;
        stamp_codex_headers(&mut headers, body);
        assert_eq!(
            headers["x-codex-routing-hint"],
            "model=gpt-6.1-sol;tier=priority"
        );
        assert_eq!(
            headers["x-codex-window-id"],
            "00000000-0000-4000-8000-000000000001:0"
        );
        assert_eq!(
            headers["x-codex-turn-metadata"],
            "{\"model\":\"gpt-6.1-sol\"}"
        );
        let mut plain = http::HeaderMap::new();
        plain.insert(
            "session-id",
            http::HeaderValue::from_static("00000000-0000-4000-8000-000000000001"),
        );
        stamp_codex_headers(&mut plain, br#"{"model":"gpt-5.5"}"#);
        assert_eq!(plain["x-codex-routing-hint"], "model=gpt-5.5");
        assert_eq!(
            plain["x-codex-window-id"],
            "00000000-0000-4000-8000-000000000001:0"
        );
        assert!(plain.get("x-codex-turn-metadata").is_none());
    }

    #[test]
    fn codex_cache_key_uses_the_session_when_the_caller_omits_it() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "session-id",
            http::HeaderValue::from_static("00000000-0000-4000-8000-000000000001"),
        );
        let bytes = ensure_codex_cache_key(
            bytes::Bytes::from_static(br#"{"model":"gpt-5.5"}"#),
            &headers,
        );
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            value["prompt_cache_key"],
            "00000000-0000-4000-8000-000000000001"
        );
        let kept = ensure_codex_cache_key(
            bytes::Bytes::from_static(br#"{"model":"gpt-5.5","prompt_cache_key":"keep"}"#),
            &headers,
        );
        let value: Value = serde_json::from_slice(&kept).unwrap();
        assert_eq!(value["prompt_cache_key"], "keep");
    }

    #[test]
    fn grok_stamp_derives_the_recorded_group_and_keeps_caller_values() {
        let session = "01a1dc95-42fe-7082-92c0-f10036e5a6a9";
        let mut headers = http::HeaderMap::new();
        headers.insert("x-grok-session-id", http::HeaderValue::from_static(session));
        headers.insert(
            "x-grok-client-identifier",
            http::HeaderValue::from_static("grok-shell"),
        );
        headers.insert(
            http::header::ACCEPT,
            http::HeaderValue::from_static("text/event-stream"),
        );
        stamp_grok_headers(&mut headers, "/v1/responses");
        assert_eq!(
            headers["x-grok-conv-group-id"],
            "247d90df-b575-5cd7-b714-44e0ed9d09f3"
        );
        assert_eq!(headers["x-grok-doom-loop-check"], "1024");
        assert_eq!(headers["x-grok-exact-repetition-check"], "64");

        headers.insert(
            "x-grok-conv-group-id",
            http::HeaderValue::from_static("11111111-1111-4111-8111-111111111111"),
        );
        headers.insert(
            "x-grok-doom-loop-check",
            http::HeaderValue::from_static("2048"),
        );
        stamp_grok_headers(&mut headers, "/v1/responses");
        assert_eq!(
            headers["x-grok-conv-group-id"],
            "11111111-1111-4111-8111-111111111111"
        );
        assert_eq!(headers["x-grok-doom-loop-check"], "2048");

        let mut chat = http::HeaderMap::new();
        chat.insert("x-grok-session-id", http::HeaderValue::from_static(session));
        chat.insert(
            "x-grok-client-identifier",
            http::HeaderValue::from_static("grok-shell"),
        );
        chat.insert(
            http::header::ACCEPT,
            http::HeaderValue::from_static("text/event-stream"),
        );
        stamp_grok_headers(&mut chat, "/v1/chat/completions");
        assert_eq!(
            chat["x-grok-conv-group-id"],
            "247d90df-b575-5cd7-b714-44e0ed9d09f3"
        );
        assert!(chat.get("x-grok-doom-loop-check").is_none());
        assert!(chat.get("x-grok-exact-repetition-check").is_none());

        let mut buffered = http::HeaderMap::new();
        buffered.insert("x-grok-session-id", http::HeaderValue::from_static(session));
        buffered.insert(
            "x-authenticateresponse",
            http::HeaderValue::from_static("authenticate-response"),
        );
        buffered.insert(
            http::header::ACCEPT,
            http::HeaderValue::from_static("application/json"),
        );
        stamp_grok_headers(&mut buffered, "/v1/responses");
        assert!(buffered.get("x-grok-doom-loop-check").is_none());

        let mut plain = http::HeaderMap::new();
        plain.insert(
            http::header::ACCEPT,
            http::HeaderValue::from_static("text/event-stream"),
        );
        stamp_grok_headers(&mut plain, "/v1/responses");
        assert!(plain.get("x-grok-conv-group-id").is_none());
        assert!(plain.get("x-grok-doom-loop-check").is_none());
    }

    #[test]
    fn each_kind_speaks_only_its_profile_dialects() {
        let all = [
            Dialect::Chat,
            Dialect::Responses,
            Dialect::Messages,
            Dialect::Decisions,
            Dialect::SystemOne,
            Dialect::Extraction,
            Dialect::Embeddings,
        ];
        for kind in [
            Kind::Anthropic,
            Kind::Openai,
            Kind::Grok,
            Kind::Llama,
            Kind::Codex,
            Kind::OpenaiDecisions,
            Kind::SystemOne,
            Kind::Clairic,
        ] {
            let backend = get(kind);
            assert_eq!(backend.dialects(), kind.dialects());
            for dialect in all {
                assert_eq!(
                    backend.dialects().contains(&dialect),
                    kind.dialects().contains(&dialect),
                    "{kind:?} {dialect}"
                );
            }
        }
    }
}
