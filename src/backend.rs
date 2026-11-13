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
        headers.insert(
            "user-agent",
            HeaderValue::from_static(concat!("infer/", env!("CARGO_PKG_VERSION"))),
        );
        // `default_headers` sends this originator. It does not send `version`
        // or `OpenAI-Beta`; those were gateway inventions.
        headers.insert("originator", HeaderValue::from_static("codex_cli_rs"));
        headers.remove("version");
        headers.remove("openai-beta");
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

fn insert_if_absent(headers: &mut HeaderMap, name: &'static str, value: &str) {
    if headers.contains_key(name) {
        return;
    }
    if let Ok(value) = HeaderValue::from_str(value) {
        headers.insert(name, value);
    }
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
        assert_eq!(headers["originator"], "codex_cli_rs");
        assert_eq!(headers["accept"], "text/event-stream");
        assert!(headers.get("version").is_none());
        assert!(headers.get("openai-beta").is_none());
        assert_eq!(headers["session-id"], headers["thread-id"]);
        assert_eq!(headers["x-client-request-id"], headers["thread-id"]);
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
