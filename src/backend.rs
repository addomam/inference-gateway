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
        let warning = object
            .remove("max_output_tokens")
            .map(|_| "Codex subscription endpoint does not enforce max_output_tokens");
        object.insert("stream".into(), Value::Bool(true));
        object.insert("store".into(), Value::Bool(false));
        object
            .entry("instructions")
            .or_insert(Value::String(String::new()));
        warning
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
            "openai-beta",
            HeaderValue::from_static("responses=experimental"),
        );
        headers.insert(
            "user-agent",
            HeaderValue::from_static(concat!("infer/", env!("CARGO_PKG_VERSION"))),
        );
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
