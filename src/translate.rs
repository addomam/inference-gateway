//! Strict native protocol conversion. Transport and native passthrough live elsewhere.
mod decisions;
mod request;
mod stream;

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};

pub use decisions::{
    DecisionPlan, SystemOnePlan, from_system_one, request as decisions_request,
    response as decisions_response, to_system_one,
};

pub enum AnswerPlan {
    Decisions(DecisionPlan),
    SystemOne(SystemOnePlan),
}
pub use stream::StreamTranslator;
pub(crate) use stream::collect_response_sse;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Anthropic,
    Chat,
    Responses,
}

/// Convert a complete request. Equal protocols preserve the original value.
/// Unrepresentable semantic content is rejected. Cross-protocol Anthropic cache
/// hints and typed tool errors use the compatibility approximations documented
/// in the README; native and equal-protocol requests bypass those conversions.
pub fn request(body: Value, from: Protocol, to: Protocol) -> Result<Value> {
    if from == to {
        return Ok(body);
    }
    request::convert(body, from, to)
}

#[derive(Default, Debug, Clone)]
pub(super) struct Usage {
    pub input: u64,
    pub output: u64,
    pub cached: u64,
    pub cache_write: u64,
    pub reasoning: u64,
    uncached: u64,
}
impl Usage {
    fn parse(v: &Value, protocol: Protocol) -> Result<Self> {
        let number = |name: &str| -> Result<u64> { Ok(Self::counter(v, name)?.unwrap_or(0)) };
        Ok(match protocol {
            Protocol::Anthropic => {
                let mut usage = Self::default();
                usage.merge_anthropic(v)?;
                usage
            }
            Protocol::Chat => Self {
                input: number("prompt_tokens")?,
                output: number("completion_tokens")?,
                cached: Self::nested_counter(v, "prompt_tokens_details", "cached_tokens")?
                    .unwrap_or(0),
                reasoning: Self::nested_counter(
                    v,
                    "completion_tokens_details",
                    "reasoning_tokens",
                )?
                .unwrap_or(0),
                ..Self::default()
            },
            Protocol::Responses => Self {
                input: number("input_tokens")?,
                output: number("output_tokens")?,
                cached: Self::nested_counter(v, "input_tokens_details", "cached_tokens")?
                    .unwrap_or(0),
                reasoning: Self::nested_counter(v, "output_tokens_details", "reasoning_tokens")?
                    .unwrap_or(0),
                ..Self::default()
            },
        })
    }
    fn counter(v: &Value, name: &str) -> Result<Option<u64>> {
        match v.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(n) => n
                .as_u64()
                .map(Some)
                .with_context(|| format!("usage.{name} must be a nonnegative integer")),
        }
    }
    fn nested_counter(v: &Value, details: &str, name: &str) -> Result<Option<u64>> {
        let values = match v.get(details) {
            None | Some(Value::Null) => return Ok(None),
            Some(Value::Object(values)) => values,
            Some(_) => bail!("usage.{details} must be an object"),
        };
        match values.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(value) => value
                .as_u64()
                .map(Some)
                .with_context(|| format!("usage.{details}.{name} must be a nonnegative integer")),
        }
    }
    fn merge_anthropic(&mut self, v: &Value) -> Result<()> {
        if let Some(input) = Self::counter(v, "input_tokens")? {
            self.uncached = input;
        }
        if let Some(cached) = Self::counter(v, "cache_read_input_tokens")? {
            self.cached = cached;
        }
        if let Some(write) = Self::counter(v, "cache_creation_input_tokens")? {
            self.cache_write = write;
        }
        if let Some(output) = Self::counter(v, "output_tokens")? {
            self.output = output;
        }
        self.input = self
            .uncached
            .saturating_add(self.cached)
            .saturating_add(self.cache_write);
        Ok(())
    }
    fn json(&self, to: Protocol) -> Value {
        match to {
            Protocol::Anthropic => {
                json!({"input_tokens":self.input.saturating_sub(self.cached).saturating_sub(self.cache_write),"output_tokens":self.output,"cache_read_input_tokens":self.cached,"cache_creation_input_tokens":self.cache_write})
            }
            Protocol::Chat => {
                json!({"prompt_tokens":self.input,"completion_tokens":self.output,"total_tokens":self.input.saturating_add(self.output),"prompt_tokens_details":{"cached_tokens":self.cached},"completion_tokens_details":{"reasoning_tokens":self.reasoning}})
            }
            Protocol::Responses => {
                json!({"input_tokens":self.input,"output_tokens":self.output,"total_tokens":self.input.saturating_add(self.output),"input_tokens_details":{"cached_tokens":self.cached},"output_tokens_details":{"reasoning_tokens":self.reasoning}})
            }
        }
    }
}

pub(super) fn obj(value: Value, context: &str) -> Result<Map<String, Value>> {
    match value {
        Value::Object(m) => Ok(m),
        _ => bail!("{context} must be an object"),
    }
}
pub(super) fn string(m: &mut Map<String, Value>, key: &str) -> Result<String> {
    match m.remove(key) {
        Some(Value::String(s)) => Ok(s),
        _ => bail!("{key} must be a string"),
    }
}
pub(super) fn array(m: &mut Map<String, Value>, key: &str) -> Result<Vec<Value>> {
    match m.remove(key) {
        Some(Value::Array(a)) => Ok(a),
        _ => bail!("{key} must be an array"),
    }
}
pub(super) fn strict(m: &Map<String, Value>, context: &str) -> Result<()> {
    if let Some(key) = m.keys().next() {
        bail!(
            "cannot translate {context}.{key}; use the native protocol endpoint or remove this feature"
        );
    }
    Ok(())
}
pub(super) fn ignore(m: &mut Map<String, Value>, keys: &[&str]) {
    for key in keys {
        m.remove(*key);
    }
}
pub(super) fn arguments(s: &str) -> Result<Value> {
    let value = crate::json::from_slice(s.as_bytes())
        .context("tool arguments must be valid JSON; incomplete tool calls cannot be translated")?;
    if !value.is_object() {
        bail!("tool arguments must be a JSON object");
    }
    Ok(value)
}
pub(super) fn only_keys(value: &Value, allowed: &[&str], context: &str) -> Result<()> {
    for key in value
        .as_object()
        .with_context(|| format!("{context} must be an object"))?
        .keys()
    {
        if !allowed.contains(&key.as_str()) {
            bail!("cannot translate {context}.{key}; use the native protocol endpoint");
        }
    }
    Ok(())
}
pub(super) fn stop(reason: &str, from: Protocol, to: Protocol) -> Result<&'static str> {
    let canonical = match (from, reason) {
        (Protocol::Anthropic, "end_turn" | "stop_sequence")
        | (Protocol::Chat, "stop")
        | (Protocol::Responses, "completed") => "stop",
        (Protocol::Anthropic, "tool_use") | (Protocol::Chat, "tool_calls") => "tool",
        (Protocol::Anthropic, "max_tokens")
        | (Protocol::Chat, "length")
        | (Protocol::Responses, "max_output_tokens") => "length",
        (Protocol::Anthropic, "refusal")
        | (Protocol::Chat, "content_filter")
        | (Protocol::Responses, "content_filter") => "filter",
        _ => bail!(
            "cannot translate {from:?} stop reason {reason:?}; use the native protocol endpoint"
        ),
    };
    Ok(match (to, canonical) {
        (Protocol::Anthropic, "tool") => "tool_use",
        (Protocol::Anthropic, "length") => "max_tokens",
        (Protocol::Anthropic, "filter") => "refusal",
        (Protocol::Anthropic, _) => "end_turn",
        (Protocol::Chat, "tool") => "tool_calls",
        (Protocol::Chat, "length") => "length",
        (Protocol::Chat, "filter") => "content_filter",
        (Protocol::Chat, _) => "stop",
        (Protocol::Responses, "length") => "max_output_tokens",
        (Protocol::Responses, "filter") => "content_filter",
        (Protocol::Responses, _) => "completed",
    })
}

pub(super) fn anthropic_refusal_reason(reason: &str, has_refusal: bool) -> Result<&str> {
    if !has_refusal {
        return Ok(reason);
    }
    match reason {
        "end_turn" => Ok("refusal"),
        "refusal" => Ok(reason),
        _ => bail!(
            "Anthropic cannot preserve refusal with incompatible stop reason {reason}; use the native protocol endpoint"
        ),
    }
}

/// Convert a complete native response, including mixed text/tool output and usage.
pub fn response(body: Value, from: Protocol, to: Protocol, model: &str) -> Result<Value> {
    if from == to {
        return Ok(body);
    }
    if body.get("error").is_some_and(|v| !v.is_null()) {
        bail!("upstream returned an error response: {}", body["error"]);
    }
    let usage = Usage::parse(&body["usage"], from)?;
    let id = body
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("translated")
        .to_owned();
    let mut blocks = Vec::new();
    let mut reason;
    let mut stop_sequence = Value::Null;
    match from {
        Protocol::Anthropic => {
            reason = stop(
                body["stop_reason"]
                    .as_str()
                    .context("Anthropic response is missing stop_reason")?,
                from,
                to,
            )?
            .to_owned();
            stop_sequence = body.get("stop_sequence").cloned().unwrap_or(Value::Null);
            for block in body["content"]
                .as_array()
                .context("Anthropic response content must be an array")?
            {
                match block["type"].as_str() {
                    Some("text") => {
                        if block.get("citations").is_some_and(|v| {
                            !v.is_null() && v.as_array().is_none_or(|a| !a.is_empty())
                        }) {
                            bail!(
                                "citations cannot be translated losslessly; use native Anthropic"
                            );
                        }
                        blocks.push(json!({"type":"text","text":block["text"].as_str().context("text block missing text")?}));
                    }
                    Some("tool_use") => {
                        if !block["input"].is_object() {
                            bail!("tool input must be an object");
                        }
                        blocks.push(json!({"type":"tool_use","id":block["id"].as_str().context("tool_use.id missing")?,"name":block["name"].as_str().context("tool_use.name missing")?,"input":block["input"]}));
                    }
                    _ => bail!(
                        "unsupported Anthropic response block {}; thinking and server tools require native protocol",
                        block["type"]
                    ),
                }
            }
        }
        Protocol::Chat => {
            let choices = body["choices"]
                .as_array()
                .context("Chat response choices must be an array")?;
            if choices.len() != 1 {
                bail!("translation requires exactly one Chat response choice (set n=1)");
            }
            let choice = &choices[0];
            reason = stop(
                choice["finish_reason"]
                    .as_str()
                    .context("Chat response missing finish_reason")?,
                from,
                to,
            )?
            .to_owned();
            let message = &choice["message"];
            only_keys(
                message,
                &[
                    "role",
                    "content",
                    "tool_calls",
                    "refusal",
                    "audio",
                    "reasoning_content",
                    "annotations",
                ],
                "Chat output message",
            )?;
            if message["role"] != "assistant" {
                bail!("Chat output message role must be assistant");
            }
            if message.get("audio").is_some_and(|v| !v.is_null())
                || message
                    .get("reasoning_content")
                    .is_some_and(|v| !v.is_null() && v != "")
            {
                bail!("audio/reasoning Chat output cannot be translated; use native Chat");
            }
            if let Some(content) = message.get("content").filter(|v| !v.is_null()) {
                if let Some(s) = content.as_str() {
                    blocks.push(json!({"type":"text","text":s}));
                } else {
                    bail!("non-text Chat output content cannot be translated");
                }
            }
            if let Some(refusal) = message.get("refusal").filter(|v| !v.is_null()) {
                let text = refusal.as_str().context("refusal must be text")?;
                if !text.is_empty() {
                    blocks.push(json!({"type":"refusal","text":text}));
                }
            }
            if let Some(calls) = message.get("tool_calls").filter(|v| !v.is_null()) {
                for call in calls.as_array().context("tool_calls must be an array")? {
                    only_keys(call, &["id", "type", "function"], "Chat output tool call")?;
                    only_keys(
                        &call["function"],
                        &["name", "arguments"],
                        "Chat output function",
                    )?;
                    if call["type"] != "function" {
                        bail!("only function tools can be translated");
                    }
                    blocks.push(json!({"type":"tool_use","id":call["id"].as_str().context("tool call missing id")?,"name":call["function"]["name"].as_str().context("tool call missing name")?,"input":arguments(call["function"]["arguments"].as_str().context("tool arguments missing")?)?}));
                }
            }
            if choice.get("logprobs").is_some_and(|v| !v.is_null())
                || message
                    .get("annotations")
                    .is_some_and(|v| !v.is_null() && v.as_array().is_none_or(|a| !a.is_empty()))
            {
                bail!("Chat logprobs/annotations cannot be translated losslessly");
            }
        }
        Protocol::Responses => {
            let status = body["status"]
                .as_str()
                .context("Responses response missing status")?;
            reason = match status {
                "completed" => stop("completed", from, to)?,
                "incomplete" => stop(
                    body["incomplete_details"]["reason"]
                        .as_str()
                        .context("incomplete response missing reason")?,
                    from,
                    to,
                )?,
                _ => bail!(
                    "Responses response did not complete: status={status}, error={}",
                    body["error"]
                ),
            }
            .to_owned();
            for item in body["output"]
                .as_array()
                .context("Responses output must be an array")?
            {
                match item["type"].as_str() {
                    Some("message") => {
                        validate_phase(item)?;
                        if item["role"]!="assistant" {bail!("Responses output message role must be assistant");}
                        for part in item["content"].as_array().context("output message content must be an array")? {
                            match part["type"].as_str() {
                                Some("output_text") => {
                                    if part.get("annotations").is_some_and(|v| v.as_array().is_none_or(|a| !a.is_empty())) || part.get("logprobs").is_some_and(|v| !v.is_null() && v.as_array().is_none_or(|a| !a.is_empty())) { bail!("Responses annotations/logprobs require native Responses"); }
                                    blocks.push(json!({"type":"text","text":part["text"].as_str().context("output_text missing text")?}));
                                }
                                Some("refusal") => blocks.push(json!({"type":"refusal","text":part["refusal"].as_str().context("refusal missing text")?})),
                                _ => bail!("unsupported Responses output content {}", part["type"]),
                            }
                        }
                    }
                    Some("function_call") => blocks.push(json!({"type":"tool_use","id":item["call_id"].as_str().context("function_call missing call_id")?,"name":item["name"].as_str().context("function_call missing name")?,"input":arguments(item["arguments"].as_str().context("function_call missing arguments")?)?})),
                    Some("reasoning") => validate_reasoning(item)?,
                    _ => bail!("unsupported Responses output item {}; built-in tools require native Responses", item["type"]),
                }
            }
            if status == "completed" && blocks.iter().any(|b| b["type"] == "tool_use") {
                reason = if to == Protocol::Anthropic {
                    "tool_use"
                } else {
                    "tool_calls"
                }
                .into();
            }
        }
    }
    if from == Protocol::Anthropic && body["stop_reason"] == "refusal" {
        for block in &mut blocks {
            if block["type"] == "text" {
                block["type"] = json!("refusal");
            }
        }
    }
    if to == Protocol::Chat {
        let mut saw_tool = false;
        let mut saw_text = false;
        let mut saw_refusal = false;
        let mut content_kind = None;
        for block in &blocks {
            let kind = block["type"].as_str().unwrap();
            if kind == "tool_use" {
                saw_tool = true;
                continue;
            }
            if saw_tool {
                bail!(
                    "Chat responses cannot preserve text after a tool call; use native Anthropic/Responses for interleaved output"
                );
            }
            let seen = if kind == "text" {
                &mut saw_text
            } else {
                &mut saw_refusal
            };
            if content_kind.is_some_and(|previous| previous != kind) && *seen {
                bail!(
                    "Chat responses cannot preserve interleaved text/refusal blocks; use native Anthropic/Responses"
                );
            }
            *seen = true;
            content_kind = Some(kind);
        }
    }
    match to {
        Protocol::Anthropic => {
            if from != Protocol::Anthropic {
                stop_sequence = Value::Null;
            }
            let has_refusal = blocks.iter().any(|block| block["type"] == "refusal");
            reason = anthropic_refusal_reason(&reason, has_refusal)?.to_owned();
            for block in &mut blocks {
                if block["type"] == "refusal" {
                    block["type"] = json!("text");
                }
            }
            Ok(
                json!({"id":id,"type":"message","role":"assistant","model":model,"content":blocks,"stop_reason":reason,"stop_sequence":stop_sequence,"usage":usage.json(to)}),
            )
        }
        Protocol::Chat => {
            let mut text = String::new();
            let mut calls = Vec::new();
            let mut refusal = String::new();
            for block in blocks {
                if block["type"] == "text" {
                    text.push_str(block["text"].as_str().unwrap());
                } else if block["type"] == "refusal" {
                    refusal.push_str(block["text"].as_str().unwrap());
                } else {
                    calls.push(json!({"id":block["id"],"type":"function","function":{"name":block["name"],"arguments":serde_json::to_string(&block["input"])?}}));
                }
            }
            let mut message = json!({"role":"assistant","content":if text.is_empty() && !calls.is_empty() { Value::Null } else { Value::String(text) }});
            if !calls.is_empty() {
                message["tool_calls"] = Value::Array(calls);
            }
            if !refusal.is_empty() {
                message["refusal"] = json!(refusal);
            }
            Ok(
                json!({"id":id,"object":"chat.completion","created":0,"model":model,"choices":[{"index":0,"message":message,"finish_reason":reason,"logprobs":null}],"usage":usage.json(to)}),
            )
        }
        Protocol::Responses => {
            let mut output = Vec::new();
            for (index, block) in blocks.into_iter().enumerate() {
                if block["type"] == "text" {
                    output.push(json!({"id":format!("{id}_msg_{index}"),"type":"message","status":"completed","role":"assistant","content":[{"type":"output_text","text":block["text"],"annotations":[]}]}));
                } else if block["type"] == "refusal" {
                    output.push(json!({"id":format!("{id}_msg_{index}"),"type":"message","status":"completed","role":"assistant","content":[{"type":"refusal","refusal":block["text"]}]}));
                } else {
                    output.push(json!({"id":format!("{id}_call_{index}"),"type":"function_call","status":"completed","call_id":block["id"],"name":block["name"],"arguments":serde_json::to_string(&block["input"])?}));
                }
            }
            let incomplete = reason == "max_output_tokens" || reason == "content_filter";
            Ok(
                json!({"id":id,"object":"response","created_at":0,"status":if incomplete {"incomplete"} else {"completed"},"model":model,"output":output,"usage":usage.json(to),"error":null,"incomplete_details":if incomplete {json!({"reason":reason})} else {Value::Null}}),
            )
        }
    }
}

pub(super) fn validate_phase(item: &Value) -> Result<()> {
    if item.get("phase").is_some_and(|phase| !phase.is_null()) {
        bail!(
            "Responses assistant phase cannot be preserved across protocols; use native Responses"
        );
    }
    Ok(())
}

pub(super) fn validate_reasoning(item: &Value) -> Result<()> {
    if item
        .get("encrypted_content")
        .is_some_and(|v| !v.is_null() && v != "")
        || item
            .get("summary")
            .is_some_and(|v| v.as_array().is_none_or(|a| !a.is_empty()))
        || item
            .get("content")
            .is_some_and(|v| !v.is_null() && v.as_array().is_none_or(|a| !a.is_empty()))
    {
        bail!(
            "Responses reasoning content cannot be represented losslessly in this protocol; disable reasoning summaries/encrypted reasoning or use native Responses"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_argument_numbers_remain_exact_in_responses_and_histories() {
        for number in [
            "18446744073709551617",
            "-9223372036854775809",
            "0.12345678901234567890123456789",
        ] {
            let args = format!(r#"{{"record_id":{number}}}"#);
            let chat = json!({"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","content":null,"tool_calls":[{"id":"call_a","type":"function","function":{"name":"lookup","arguments":args}}]}}],"usage":{}});
            let anthropic = response(chat, Protocol::Chat, Protocol::Anthropic, "x").unwrap();
            assert_eq!(
                anthropic["content"][0]["input"]["record_id"].to_string(),
                number
            );

            let responses = json!({"id":"r","status":"completed","output":[{"type":"function_call","call_id":"call_a","name":"lookup","arguments":args}],"usage":{}});
            let anthropic =
                response(responses, Protocol::Responses, Protocol::Anthropic, "x").unwrap();
            assert_eq!(
                anthropic["content"][0]["input"]["record_id"].to_string(),
                number
            );

            let history = json!({"model":"x","messages":[{"role":"assistant","tool_calls":[{"id":"call_a","type":"function","function":{"name":"lookup","arguments":args}}]},{"role":"tool","tool_call_id":"call_a","content":"found"}]});
            let translated = request(history, Protocol::Chat, Protocol::Responses).unwrap();
            assert_eq!(translated["input"][0]["arguments"].as_str().unwrap(), args);
        }
    }

    #[test]
    fn literal_json_marker_objects_survive_tool_argument_conversion() {
        let args = r#"{"value":{"$serde_json::private::Number":"123"},"raw":{"$serde_json::private::RawValue":"[1,2]"},"record_id":123456789012345678901234567890}"#;
        let chat = json!({"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","tool_calls":[{"id":"call_a","type":"function","function":{"name":"lookup","arguments":args}}]}}],"usage":{}});
        let responses = json!({"status":"completed","output":[{"type":"function_call","call_id":"call_a","name":"lookup","arguments":args}],"usage":{}});
        for (input, from) in [(chat, Protocol::Chat), (responses, Protocol::Responses)] {
            let translated = response(input, from, Protocol::Anthropic, "x").unwrap();
            let input = &translated["content"][0]["input"];
            assert_eq!(
                input["value"],
                json!({"$serde_json::private::Number":"123"})
            );
            assert_eq!(
                input["raw"],
                json!({"$serde_json::private::RawValue":"[1,2]"})
            );
            assert_eq!(
                input["record_id"].to_string(),
                "123456789012345678901234567890"
            );
        }
    }

    #[test]
    fn buffered_responses_reject_unrepresentable_assistant_phases() {
        for phase in [
            json!("commentary"),
            json!("final_answer"),
            json!(""),
            json!(false),
            json!(1),
            json!({}),
        ] {
            let input = json!({"id":"r","status":"completed","output":[{"type":"message","role":"assistant","phase":phase,"content":[{"type":"output_text","text":"working","annotations":[]}]}],"usage":{}});
            for to in [Protocol::Anthropic, Protocol::Chat] {
                assert!(response(input.clone(), Protocol::Responses, to, "x").is_err());
            }
            assert_eq!(
                response(input.clone(), Protocol::Responses, Protocol::Responses, "x").unwrap(),
                input
            );
        }
        let input = json!({"id":"r","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"done","annotations":[]}]}],"usage":{}});
        for to in [Protocol::Anthropic, Protocol::Chat] {
            let absent = response(input.clone(), Protocol::Responses, to, "x").unwrap();
            let mut nullable = input.clone();
            nullable["output"][0]["phase"] = Value::Null;
            assert_eq!(
                response(nullable, Protocol::Responses, to, "x").unwrap(),
                absent
            );
        }
    }

    #[test]
    fn empty_chat_refusals_do_not_change_successful_completion() {
        let input = json!({"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"hello"}}],"usage":{}});
        for to in [Protocol::Anthropic, Protocol::Responses] {
            let expected = response(input.clone(), Protocol::Chat, to, "x").unwrap();
            for refusal in [Value::Null, json!("")] {
                let mut variant = input.clone();
                variant["choices"][0]["message"]["refusal"] = refusal;
                assert_eq!(
                    response(variant, Protocol::Chat, to, "x").unwrap(),
                    expected
                );
            }
            let mut refused = input.clone();
            refused["choices"][0]["message"]["refusal"] = json!("cannot comply");
            let out = response(refused, Protocol::Chat, to, "x").unwrap();
            if to == Protocol::Anthropic {
                assert_eq!(out["stop_reason"], "refusal");
                assert_eq!(out["content"][1]["text"], "cannot comply");
            } else {
                assert_eq!(out["output"][1]["content"][0]["refusal"], "cannot comply");
            }
            for refusal in [json!(false), json!(0), json!([]), json!({})] {
                let mut invalid = input.clone();
                invalid["choices"][0]["message"]["refusal"] = refusal;
                assert!(response(invalid, Protocol::Chat, to, "x").is_err());
            }
        }
    }
    #[test]
    fn chat_response_null_tool_calls_preserves_text_and_completion() {
        let input = json!({"id":"r","choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"hello"}}],"usage":{}});
        for to in [Protocol::Anthropic, Protocol::Responses] {
            let expected = response(input.clone(), Protocol::Chat, to, "x").unwrap();
            let mut nullable = input.clone();
            nullable["choices"][0]["message"]["tool_calls"] = Value::Null;
            let out = response(nullable, Protocol::Chat, to, "x").unwrap();
            assert_eq!(out, expected);
            if to == Protocol::Anthropic {
                assert_eq!(out["content"], json!([{"type":"text","text":"hello"}]));
                assert_eq!(out["stop_reason"], "end_turn");
            } else {
                assert_eq!(out["output"][0]["content"][0]["text"], "hello");
                assert_eq!(out["status"], "completed");
            }
        }
    }

    #[test]
    fn chat_response_rejects_non_array_tool_calls() {
        for calls in [json!("invalid"), json!({}), json!(true), json!(1)] {
            for to in [Protocol::Anthropic, Protocol::Responses] {
                let input = json!({"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"hello","tool_calls":calls}}],"usage":{}});
                let error = response(input, Protocol::Chat, to, "x").unwrap_err();
                assert!(error.to_string().contains("tool_calls must be an array"));
            }
        }
    }

    #[test]
    fn responses_mixed_text_and_tool_usage() {
        let input = json!({"id":"r","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"checking","annotations":[]}]},{"type":"function_call","call_id":"call_a","name":"read","arguments":"{\"path\":\"a\"}"}],"usage":{"input_tokens":20,"output_tokens":7,"input_tokens_details":{"cached_tokens":4}}});
        let out = response(input, Protocol::Responses, Protocol::Anthropic, "alias").unwrap();
        assert_eq!(out["content"][0]["text"], "checking");
        assert_eq!(out["content"][1]["input"]["path"], "a");
        assert_eq!(out["stop_reason"], "tool_use");
        assert_eq!(out["usage"]["input_tokens"], 16);
        assert_eq!(out["usage"]["cache_read_input_tokens"], 4);
        assert_eq!(out["model"], "alias");
    }

    #[test]
    fn responses_to_chat_rejects_resumed_text_or_refusal_blocks() {
        let content = [
            json!({"type":"output_text","text":"A","annotations":[]}),
            json!({"type":"refusal","refusal":"B"}),
            json!({"type":"output_text","text":"C","annotations":[]}),
        ];
        let input = json!({"id":"r","status":"completed","output":[{"type":"message","role":"assistant","content":content}],"usage":{}});
        let error = response(input.clone(), Protocol::Responses, Protocol::Chat, "x").unwrap_err();
        assert!(error.to_string().contains("interleaved text/refusal"));

        let anthropic =
            response(input.clone(), Protocol::Responses, Protocol::Anthropic, "x").unwrap();
        assert_eq!(
            anthropic["content"],
            json!([
                {"type":"text","text":"A"},
                {"type":"text","text":"B"},
                {"type":"text","text":"C"}
            ])
        );
        assert_eq!(
            response(input.clone(), Protocol::Responses, Protocol::Responses, "x").unwrap(),
            input
        );

        for content in [
            json!([
                {"type":"output_text","text":"A","annotations":[]},
                {"type":"refusal","refusal":"B"}
            ]),
            json!([
                {"type":"refusal","refusal":"A"},
                {"type":"output_text","text":"B","annotations":[]}
            ]),
        ] {
            let representable = json!({"id":"r","status":"completed","output":[{"type":"message","role":"assistant","content":content}],"usage":{}});
            response(representable, Protocol::Responses, Protocol::Chat, "x").unwrap();
        }
    }

    #[test]
    fn anthropic_refusal_rejects_competing_terminal_reasons() {
        let chat = |reason| json!({"id":"c","choices":[{"finish_reason":reason,"message":{"role":"assistant","content":null,"refusal":"denied"}}],"usage":{}});
        for reason in ["length", "tool_calls"] {
            let error =
                response(chat(reason), Protocol::Chat, Protocol::Anthropic, "x").unwrap_err();
            assert!(error.to_string().contains("refusal"));
            assert!(error.to_string().contains("stop reason"));
        }

        let responses = |status, reason: Option<&str>| {
            let mut value = json!({"id":"r","status":status,"error":null,"output":[{"type":"message","role":"assistant","content":[{"type":"refusal","refusal":"denied"}]}],"usage":{}});
            if let Some(reason) = reason {
                value["incomplete_details"] = json!({"reason":reason});
            }
            value
        };
        let incomplete = responses("incomplete", Some("max_output_tokens"));
        let error = response(
            incomplete.clone(),
            Protocol::Responses,
            Protocol::Anthropic,
            "x",
        )
        .unwrap_err();
        assert!(error.to_string().contains("refusal"));
        assert_eq!(
            response(
                incomplete.clone(),
                Protocol::Responses,
                Protocol::Responses,
                "x"
            )
            .unwrap(),
            incomplete
        );

        for (input, from) in [
            (chat("stop"), Protocol::Chat),
            (chat("content_filter"), Protocol::Chat),
            (responses("completed", None), Protocol::Responses),
            (
                responses("incomplete", Some("content_filter")),
                Protocol::Responses,
            ),
        ] {
            let translated = response(input, from, Protocol::Anthropic, "x").unwrap();
            assert_eq!(translated["content"][0]["text"], "denied");
            assert_eq!(translated["stop_reason"], "refusal");
        }
    }

    #[test]
    fn nested_usage_details_require_nonnegative_integer_counters() {
        let cases = [
            (
                Protocol::Chat,
                Protocol::Anthropic,
                json!({"id":"c","choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":3,"completion_tokens":2}}),
                "prompt_tokens_details",
                "cached_tokens",
            ),
            (
                Protocol::Chat,
                Protocol::Anthropic,
                json!({"id":"c","choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":3,"completion_tokens":2}}),
                "completion_tokens_details",
                "reasoning_tokens",
            ),
            (
                Protocol::Responses,
                Protocol::Chat,
                json!({"id":"r","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"ok","annotations":[]}]}],"usage":{"input_tokens":3,"output_tokens":2}}),
                "input_tokens_details",
                "cached_tokens",
            ),
            (
                Protocol::Responses,
                Protocol::Chat,
                json!({"id":"r","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"ok","annotations":[]}]}],"usage":{"input_tokens":3,"output_tokens":2}}),
                "output_tokens_details",
                "reasoning_tokens",
            ),
        ];
        for (from, to, input, details, counter) in cases {
            for value in [
                Value::Null,
                json!({}),
                json!({counter:null}),
                json!({counter:7}),
            ] {
                let mut valid = input.clone();
                valid["usage"][details] = value;
                response(valid, from, to, "x").unwrap();
            }
            for invalid in [json!(-1), json!(1.5), json!("7"), json!(true), json!([])] {
                let mut malformed = input.clone();
                malformed["usage"][details] = invalid;
                assert!(
                    response(malformed, from, to, "x").is_err(),
                    "{from:?} {details} container"
                );
            }
            for invalid in [
                json!(-1),
                json!(1.5),
                json!("7"),
                json!(true),
                json!([]),
                json!({}),
            ] {
                let mut malformed = input.clone();
                malformed["usage"][details] = json!({counter:invalid});
                assert!(
                    response(malformed, from, to, "x").is_err(),
                    "{from:?} {details}.{counter}"
                );
            }
        }
    }
    #[test]
    fn buffered_anthropic_refusal_remains_classified_for_chat() {
        let input = json!({
            "id":"m",
            "stop_reason":"refusal",
            "content":[{"type":"text","text":"denied"}],
            "usage":{"input_tokens":1,"output_tokens":1}
        });
        let output = response(input.clone(), Protocol::Anthropic, Protocol::Chat, "x").unwrap();
        assert_eq!(output["choices"][0]["message"]["content"], "");
        assert_eq!(output["choices"][0]["message"]["refusal"], "denied");
        assert_eq!(output["choices"][0]["finish_reason"], "content_filter");
        assert_eq!(
            response(input.clone(), Protocol::Anthropic, Protocol::Anthropic, "x").unwrap(),
            input
        );
    }
    #[test]
    fn refusal_and_truncated_json_are_explicit() {
        let input = json!({"id":"r","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"refusal","refusal":"cannot comply"}]}],"usage":{}});
        let out = response(input, Protocol::Responses, Protocol::Chat, "x").unwrap();
        assert_eq!(out["choices"][0]["message"]["refusal"], "cannot comply");
        let input = json!({"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","content":null,"tool_calls":[{"id":"a","type":"function","function":{"name":"f","arguments":"{"}}]}}],"usage":{}});
        assert!(response(input, Protocol::Chat, Protocol::Anthropic, "x").is_err());
    }
}
