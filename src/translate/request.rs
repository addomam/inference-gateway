use super::{Protocol, arguments, array, ignore, obj, strict, string};
use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};

#[derive(Debug)]
enum Part {
    Text(String),
    Image {
        url: String,
        detail: Option<String>,
    },
    Call {
        id: String,
        name: String,
        input: Value,
    },
    Result {
        id: String,
        content: Vec<Part>,
        error: bool,
    },
}
struct Message {
    role: String,
    parts: Vec<Part>,
}
struct Tool {
    name: String,
    description: Option<Value>,
    schema: Value,
    strict: Option<Value>,
}

pub(super) fn convert(body: Value, from: Protocol, to: Protocol) -> Result<Value> {
    let mut body = obj(body, "request")?;
    if from == Protocol::Chat {
        // Normalize only known nullable request options, never message/tool contents
        // or unknown keys whose semantics cannot safely be dropped.
        for key in [
            "audio",
            "frequency_penalty",
            "logit_bias",
            "logprobs",
            "max_completion_tokens",
            "max_tokens",
            "modalities",
            "moderation",
            "n",
            "prediction",
            "presence_penalty",
            "prompt_cache_key",
            "prompt_cache_retention",
            "reasoning_effort",
            "response_format",
            "safety_identifier",
            "seed",
            "service_tier",
            "stop",
            "store",
            "stream",
            "stream_options",
            "temperature",
            "top_logprobs",
            "top_p",
            "verbosity",
        ] {
            if body.get(key).is_some_and(Value::is_null) {
                body.remove(key);
            }
        }
    }
    let model = string(&mut body, "model")?;
    let mut messages = Vec::new();
    let mut extras = Map::new();
    let mut reasoning = None;
    let tools;
    let choice;
    let mut parallel = body.remove("parallel_tool_calls");
    match from {
        Protocol::Anthropic => {
            if let Some(system) = body.remove("system") {
                messages.push(Message {
                    role: "system".into(),
                    parts: anthropic_parts(system, "system")?,
                });
            }
            for m in array(&mut body, "messages")? {
                let mut m = obj(m, "message")?;
                let role = string(&mut m, "role")?;
                if !matches!(role.as_str(), "user" | "assistant" | "system") {
                    bail!("Anthropic message role must be user, assistant, or system");
                }
                let content = m.remove("content").context("message missing content")?;
                messages.push(Message {
                    parts: anthropic_parts(content, &role)?,
                    role,
                });
                strict(&m, "message")?;
            }
            if messages
                .iter()
                .rev()
                .find(|message| message.role != "system")
                .is_some_and(|message| message.role == "assistant")
            {
                bail!(
                    "Anthropic assistant prefill has no equivalent in {to:?}; use native Anthropic"
                );
            }
            tools = parse_tools(body.remove("tools"), from)?;
            choice = parse_choice(body.remove("tool_choice"), from, &mut parallel)?;
            move_option(&mut body, &mut extras, "max_tokens", "max_tokens");
            move_option(&mut body, &mut extras, "stop_sequences", "stop");
            if let Some(v) = body.remove("top_k") {
                bail!(
                    "top_k={v} has no equivalent outside Anthropic; remove top_k or use native Anthropic"
                );
            }
            let mut adaptive_responses = false;
            if let Some(thinking) = body.remove("thinking") {
                let mut thinking = obj(thinking, "thinking")?;
                match string(&mut thinking, "type")?.as_str() {
                    "disabled" => {}
                    "adaptive" if to == Protocol::Responses => {
                        adaptive_responses = true;
                    }
                    "enabled" => bail!(
                        "Anthropic thinking.budget_tokens cannot be enforced by this provider; disable thinking (Claude Code MAX_THINKING_TOKENS=0) or use native Anthropic. Adaptive thinking toward Responses requires output_config.effort of low, medium, or high"
                    ),
                    _ => bail!(
                        "thinking mode cannot be translated to {to:?}; disable thinking or use native Anthropic"
                    ),
                }
                strict(&thinking, "thinking")?;
            }
            if let Some(output) = body.remove("output_config") {
                let mut output = obj(output, "output_config")?;
                if let Some(effort) = output.remove("effort") {
                    if to != Protocol::Responses
                        || !matches!(effort.as_str(), Some("low" | "medium" | "high"))
                    {
                        bail!(
                            "output_config.effort cannot be represented by this target; supported Responses efforts: low, medium, high"
                        );
                    }
                    reasoning = Some(json!({"effort":effort}));
                }
                strict(&output, "output_config")?;
            }
            if adaptive_responses && reasoning.is_none() {
                bail!(
                    "adaptive thinking toward Responses requires output_config.effort of low, medium, or high"
                );
            }
        }
        Protocol::Chat => {
            for m in array(&mut body, "messages")? {
                messages.push(chat_message(m)?);
            }
            tools = parse_tools(body.remove("tools"), from)?;
            choice = parse_choice(body.remove("tool_choice"), from, &mut parallel)?;
            let old_cap = body.remove("max_tokens");
            let new_cap = body.remove("max_completion_tokens");
            if old_cap.is_some() && new_cap.is_some() {
                bail!("specify only one of max_tokens and max_completion_tokens");
            }
            if let Some(v) = new_cap.or(old_cap) {
                extras.insert("max_tokens".into(), v);
            }
            move_option(&mut body, &mut extras, "stop", "stop");
            for (key, default) in [
                ("n", json!(1)),
                ("frequency_penalty", json!(0)),
                ("presence_penalty", json!(0)),
                ("logprobs", json!(false)),
                ("store", json!(false)),
            ] {
                if let Some(v) = body.remove(key) {
                    let equal = v == default
                        || (v
                            .as_f64()
                            .zip(default.as_f64())
                            .is_some_and(|(a, b)| a == b));
                    if !equal {
                        bail!("Chat {key}={v} cannot be translated; use the native endpoint");
                    }
                }
            }
            if let Some(format) = body.remove("response_format")
                && format != json!({"type":"text"})
            {
                bail!(
                    "Chat response_format requires the native endpoint; structured output constraints cannot be dropped"
                );
            }
            if let Some(options) = body.remove("stream_options") {
                let mut options = obj(options, "stream_options")?;
                if let Some(include) = options.remove("include_usage")
                    && !include.is_boolean()
                {
                    bail!("stream_options.include_usage must be boolean");
                }
                strict(&options, "stream_options")?;
            }
        }
        Protocol::Responses => {
            if body.get("stream").is_some_and(Value::is_null) {
                body.remove("stream");
            }
            if let Some(instructions) = body.remove("instructions").filter(|v| !v.is_null()) {
                messages.push(Message {
                    role: "system".into(),
                    parts: vec![Part::Text(
                        instructions
                            .as_str()
                            .context("instructions must be a string")?
                            .into(),
                    )],
                });
            }
            match body
                .remove("input")
                .context("Responses request missing input")?
            {
                Value::String(s) => messages.push(Message {
                    role: "user".into(),
                    parts: vec![Part::Text(s)],
                }),
                Value::Array(items) => {
                    for item in items {
                        messages.push(response_item(item)?);
                    }
                }
                _ => bail!("Responses input must be a string or array"),
            }
            tools = parse_tools(body.remove("tools"), from)?;
            choice = parse_choice(body.remove("tool_choice"), from, &mut parallel)?;
            move_option(&mut body, &mut extras, "max_output_tokens", "max_tokens");
            if body.remove("store") != Some(Value::Bool(false)) {
                bail!(
                    "Responses storage cannot be preserved by the translated provider; set store=false explicitly or use native Responses"
                );
            }
            if let Some(v) = body.remove("reasoning") {
                let mut r = obj(v, "reasoning")?;
                if let Some(effort) = r.remove("effort")
                    && !effort.is_null()
                    && effort != "none"
                {
                    if to == Protocol::Anthropic
                        && matches!(effort.as_str(), Some("low" | "medium" | "high"))
                    {
                        reasoning = Some(json!({"effort":effort}));
                    } else {
                        bail!(
                            "Responses reasoning effort cannot be represented by this provider; disable reasoning or use native Responses"
                        );
                    }
                }
                strict(&r, "reasoning")?;
            }
            if let Some(v) = body.remove("text")
                && v != json!({"format":{"type":"text"}})
            {
                bail!("Responses text configuration cannot be translated losslessly");
            }
        }
    }
    for key in ["temperature", "top_p", "stream"] {
        move_option(&mut body, &mut extras, key, key);
    }
    strict(&body, "request")?;
    if messages.is_empty() {
        bail!("request must contain at least one message");
    }
    let mut out = Map::new();
    out.insert("model".into(), Value::String(model));
    if from != Protocol::Responses && to == Protocol::Responses {
        // Responses stores generated objects by default. Chat and Anthropic
        // requests have no matching persistence contract, so translated calls
        // must remain stateless.
        out.insert("store".into(), Value::Bool(false));
    }
    for key in ["temperature", "top_p", "stream"] {
        if let Some(v) = extras.remove(key) {
            out.insert(key.into(), v);
        }
    }
    if let Some(v) = extras.remove("max_tokens") {
        if v.as_u64().is_none_or(|n| n == 0) {
            bail!("output token cap must be a positive integer");
        }
        out.insert(
            if to == Protocol::Responses {
                "max_output_tokens"
            } else {
                "max_tokens"
            }
            .into(),
            v,
        );
    } else if to == Protocol::Anthropic {
        bail!("Anthropic requires max_tokens; supply an explicit output cap in the source request");
    }
    if let Some(mut stop) = extras.remove("stop")
        && !stop.is_null()
        && !(to == Protocol::Responses && stop.as_array().is_some_and(Vec::is_empty))
    {
        if to == Protocol::Responses {
            bail!(
                "Responses has no stop-sequence equivalent; remove stop/stop_sequences or use native Chat/Anthropic"
            );
        }
        if let Value::String(s) = stop {
            stop = json!([s]);
        }
        if stop
            .as_array()
            .is_none_or(|a| a.iter().any(|v| !v.is_string()))
        {
            bail!("stop sequences must be strings");
        }
        out.insert(
            if to == Protocol::Anthropic {
                "stop_sequences"
            } else {
                "stop"
            }
            .into(),
            stop,
        );
    }
    if let Some(reasoning) = reasoning {
        if to == Protocol::Responses {
            out.insert("reasoning".into(), reasoning);
        } else {
            out.insert("thinking".into(), json!({"type":"adaptive"}));
            out.insert("output_config".into(), reasoning);
        }
    }
    if let Some(tools) = tools {
        let mut encoded = Vec::new();
        for t in tools {
            let mut spec = Map::new();
            spec.insert("name".into(), Value::String(t.name));
            if let Some(d) = t.description {
                spec.insert("description".into(), d);
            }
            spec.insert(
                if to == Protocol::Anthropic {
                    "input_schema"
                } else {
                    "parameters"
                }
                .into(),
                t.schema,
            );
            if let Some(s) = t.strict {
                if to == Protocol::Anthropic && s != false && !s.is_null() {
                    bail!(
                        "strict function schemas require native Chat/Responses; Anthropic strict validation is not equivalent"
                    );
                }
                if to != Protocol::Anthropic {
                    spec.insert("strict".into(), s);
                }
            }
            if to == Protocol::Responses && !spec.contains_key("strict") {
                // Responses otherwise normalizes optional fields into strict schemas.
                spec.insert("strict".into(), json!(false));
            }
            encoded.push(match to {
                Protocol::Chat => json!({"type":"function","function":spec}),
                Protocol::Responses => {
                    spec.insert("type".into(), json!("function"));
                    Value::Object(spec)
                }
                Protocol::Anthropic => Value::Object(spec),
            });
        }
        out.insert("tools".into(), Value::Array(encoded));
    }
    if let Some(choice) = choice {
        let kind = choice["type"].as_str().unwrap();
        let encoded = match to {
            Protocol::Anthropic => match kind {
                "required" => json!({"type":"any"}),
                "tool" => json!({"type":"tool","name":choice["name"]}),
                k => json!({"type":k}),
            },
            Protocol::Chat => {
                if kind == "tool" {
                    json!({"type":"function","function":{"name":choice["name"]}})
                } else {
                    json!(kind)
                }
            }
            Protocol::Responses => {
                if kind == "tool" {
                    json!({"type":"function","name":choice["name"]})
                } else {
                    json!(kind)
                }
            }
        };
        out.insert("tool_choice".into(), encoded);
    }
    if let Some(p) = parallel {
        if !p.is_boolean() {
            bail!("parallel_tool_calls must be boolean");
        }
        if to == Protocol::Anthropic {
            let choice = out
                .entry("tool_choice")
                .or_insert_with(|| json!({"type":"auto"}));
            choice["disable_parallel_tool_use"] = json!(!p.as_bool().unwrap());
        } else {
            out.insert("parallel_tool_calls".into(), p);
        }
    }
    encode_messages(messages, to, &mut out)?;
    Ok(Value::Object(out))
}
fn move_option(
    source: &mut Map<String, Value>,
    target: &mut Map<String, Value>,
    from: &str,
    to: &str,
) {
    if let Some(v) = source.remove(from) {
        target.insert(to.into(), v);
    }
}
fn parse_tools(value: Option<Value>, from: Protocol) -> Result<Option<Vec<Tool>>> {
    let Some(value) = value.filter(|v| !v.is_null()) else {
        return Ok(None);
    };
    let mut tools = Vec::new();
    let Value::Array(values) = value else {
        bail!("tools must be an array");
    };
    for t in values {
        let mut t = obj(t, "tool")?;
        ignore(&mut t, &["cache_control"]);
        if from == Protocol::Chat {
            if string(&mut t, "type")? != "function" {
                bail!("only custom function tools are translatable");
            }
            let function = t.remove("function").context("tool missing function")?;
            strict(&t, "tool")?;
            t = obj(function, "tool.function")?;
        } else if from == Protocol::Responses && string(&mut t, "type")? != "function" {
            bail!("Responses built-in tools cannot be translated");
        }
        if from == Protocol::Anthropic
            && t.remove("type")
                .filter(|v| !v.is_null())
                .is_some_and(|v| v.as_str() != Some("custom"))
        {
            bail!(
                "only custom Anthropic tools are translatable; server/computer tools require native Anthropic"
            );
        }
        let name = string(&mut t, "name")?;
        let description = t
            .remove("description")
            .filter(|value| from != Protocol::Responses || !value.is_null());
        if description.as_ref().is_some_and(|v| !v.is_string()) {
            bail!("tool description must be a string");
        }
        let schema = t
            .remove(if from == Protocol::Anthropic {
                "input_schema"
            } else {
                "parameters"
            })
            .unwrap_or_else(|| json!({"type":"object","properties":{}}));
        if !schema.is_object() {
            bail!("tool schema must be an object");
        }
        let strict_schema = t.remove("strict").filter(|v| !v.is_null());
        if strict_schema.as_ref().is_some_and(|v| !v.is_boolean()) {
            bail!("tool strict must be boolean");
        }
        if from == Protocol::Responses && strict_schema.is_none() {
            bail!(
                "Responses tools with implicit schema normalization require native Responses; set strict explicitly for translation"
            );
        }
        strict(&t, "tool")?;
        tools.push(Tool {
            name,
            description,
            schema,
            strict: strict_schema,
        });
    }
    Ok(Some(tools))
}
fn parse_choice(
    value: Option<Value>,
    from: Protocol,
    parallel: &mut Option<Value>,
) -> Result<Option<Value>> {
    let Some(value) = value.filter(|v| !v.is_null()) else {
        return Ok(None);
    };
    if let Value::String(kind) = value {
        if !matches!(kind.as_str(), "auto" | "none" | "required") {
            bail!("unsupported tool_choice {kind}");
        }
        return Ok(Some(json!({"type":kind})));
    }
    let mut v = obj(value, "tool_choice")?;
    let kind = string(&mut v, "type")?;
    if let Some(disable) = v.remove("disable_parallel_tool_use") {
        if from != Protocol::Anthropic || !disable.is_boolean() {
            bail!("invalid disable_parallel_tool_use");
        }
        if parallel.is_some() {
            bail!("conflicting parallel tool configuration");
        }
        *parallel = Some(json!(!disable.as_bool().unwrap()));
    }
    let out = match kind.as_str() {
        "tool" if from == Protocol::Anthropic => {
            json!({"type":"tool","name":string(&mut v,"name")?})
        }
        "function" if from == Protocol::Chat => {
            let mut f = obj(
                v.remove("function")
                    .context("tool_choice missing function")?,
                "tool_choice.function",
            )?;
            let name = string(&mut f, "name")?;
            strict(&f, "tool_choice.function")?;
            json!({"type":"tool","name":name})
        }
        "function" if from == Protocol::Responses => {
            json!({"type":"tool","name":string(&mut v,"name")?})
        }
        "any" if from == Protocol::Anthropic => json!({"type":"required"}),
        "auto" | "none" => json!({"type":kind}),
        _ => bail!("unsupported tool_choice type {kind}"),
    };
    strict(&v, "tool_choice")?;
    Ok(Some(out))
}
fn anthropic_parts(value: Value, role: &str) -> Result<Vec<Part>> {
    if let Value::String(s) = value {
        return Ok(vec![Part::Text(s)]);
    }
    let Value::Array(values) = value else {
        bail!("Anthropic content must be string or array");
    };
    let mut parts = Vec::new();
    for value in values {
        let mut v = obj(value, "content block")?;
        ignore(&mut v, &["cache_control"]);
        let kind = string(&mut v, "type")?;
        parts.push(match kind.as_str() {
            "text" => {
                if let Some(citations) = v.remove("citations")
                    && !citations.is_null()
                    && citations.as_array().is_none_or(|values| !values.is_empty())
                {
                    bail!("Anthropic citations require native Anthropic");
                }
                Part::Text(string(&mut v, "text")?)
            }
            "image" if role == "user" || role == "tool" => {
                let mut source = obj(v.remove("source").context("image missing source")?, "image.source")?;
                let source_type = string(&mut source, "type")?;
                let url = match source_type.as_str() {
                    "url" => string(&mut source, "url")?,
                    "base64" => format!("data:{};base64,{}", string(&mut source,"media_type")?, string(&mut source,"data")?),
                    _ => bail!("unsupported image source {source_type}"),
                };
                strict(&source, "image.source")?;
                Part::Image { url, detail: None }
            }
            "tool_use" if role == "assistant" => {
                let input = v.remove("input").context("tool_use missing input")?;
                if !input.is_object() { bail!("tool_use.input must be an object"); }
                Part::Call { id: string(&mut v,"id")?, name: string(&mut v,"name")?, input }
            }
            "tool_result" if role == "user" => {
                let error = match v.remove("is_error") { None => false, Some(Value::Bool(b)) => b, _ => bail!("tool_result.is_error must be boolean") };
                let content = anthropic_parts(v.remove("content").unwrap_or_else(|| json!("")), "tool")?;
                Part::Result { id: string(&mut v,"tool_use_id")?, content, error }
            }
            _ => bail!("unsupported Anthropic {role} content block {kind}; thinking, documents and server tools require native Anthropic"),
        });
        strict(&v, "content block")?;
    }
    Ok(parts)
}
fn chat_parts(value: Value, role: &str) -> Result<Vec<Part>> {
    match value {
        Value::Null => Ok(Vec::new()),
        Value::String(s) => Ok(vec![Part::Text(s)]),
        Value::Array(a) => a
            .into_iter()
            .map(|v| {
                let mut v = obj(v, "Chat content part")?;
                let kind = string(&mut v, "type")?;
                let part = match kind.as_str() {
                    "text" => Part::Text(string(&mut v, "text")?),
                    "image_url" if role == "user" => {
                        let mut source = obj(
                            v.remove("image_url").context("image_url missing")?,
                            "image_url",
                        )?;
                        let url = string(&mut source, "url")?;
                        let detail = match source.remove("detail") {
                            None | Some(Value::Null) => None,
                            Some(Value::String(s))
                                if matches!(s.as_str(), "auto" | "low" | "high" | "original") =>
                            {
                                Some(s)
                            }
                            _ => bail!("unsupported image detail"),
                        };
                        strict(&source, "image_url")?;
                        Part::Image { url, detail }
                    }
                    _ => bail!("unsupported Chat content type {kind}"),
                };
                strict(&v, "Chat content part")?;
                Ok(part)
            })
            .collect(),
        _ => bail!("Chat content must be string, array or null"),
    }
}
fn chat_message(value: Value) -> Result<Message> {
    let mut m = obj(value, "Chat message")?;
    let role = string(&mut m, "role")?;
    if !matches!(
        role.as_str(),
        "user" | "assistant" | "system" | "developer" | "tool"
    ) {
        bail!("unsupported Chat role {role}");
    }
    let mut parts = chat_parts(m.remove("content").unwrap_or(Value::Null), &role)?;
    if role == "tool" {
        let id = string(&mut m, "tool_call_id")?;
        parts = vec![Part::Result {
            id,
            content: parts,
            error: false,
        }];
    }
    if let Some(calls) = m.remove("tool_calls").filter(|v| !v.is_null()) {
        if role != "assistant" {
            bail!("tool_calls require assistant role");
        }
        let Value::Array(calls) = calls else {
            bail!("tool_calls must be an array");
        };
        for call in calls {
            let mut call = obj(call, "tool call")?;
            if string(&mut call, "type")? != "function" {
                bail!("only function calls are translatable");
            }
            let id = string(&mut call, "id")?;
            let mut f = obj(
                call.remove("function")
                    .context("tool call missing function")?,
                "tool call function",
            )?;
            let name = string(&mut f, "name")?;
            let input = arguments(&string(&mut f, "arguments")?)?;
            strict(&f, "tool function")?;
            strict(&call, "tool call")?;
            parts.push(Part::Call { id, name, input });
        }
    }
    if let Some(refusal) = m.remove("refusal").filter(|v| !v.is_null() && v != "") {
        bail!(
            "Chat refusal history cannot be translated without losing refusal semantics ({refusal}); use native Chat"
        );
    }
    strict(&m, "Chat message")?;
    Ok(Message { role, parts })
}
fn response_parts(value: Value, role: &str) -> Result<Vec<Part>> {
    if let Value::String(s) = value {
        return Ok(vec![Part::Text(s)]);
    }
    let Value::Array(values) = value else {
        bail!("Responses content must be string or array");
    };
    let mut out = Vec::new();
    for v in values {
        let mut v = obj(v, "Responses content")?;
        let kind = string(&mut v, "type")?;
        let part = match kind.as_str() {
            "input_text" | "output_text" => {
                if let Some(annotations) = v.remove("annotations")
                    && annotations.as_array().is_none_or(|a| !a.is_empty())
                {
                    bail!("Responses annotations require native Responses");
                }
                if kind == "output_text"
                    && let Some(logprobs) = v.remove("logprobs")
                    && !logprobs.is_null()
                    && logprobs.as_array().is_none_or(|values| !values.is_empty())
                {
                    bail!("Responses logprobs require native Responses");
                }
                Part::Text(string(&mut v, "text")?)
            }
            "input_image" if role == "user" || role == "tool" => {
                let url = string(&mut v, "image_url")?;
                let detail = match v.remove("detail") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(s)) => Some(s),
                    _ => bail!("image detail must be string"),
                };
                Part::Image { url, detail }
            }
            _ => bail!(
                "unsupported Responses content {kind}; files/audio/refusal require native Responses"
            ),
        };
        strict(&v, "Responses content")?;
        out.push(part);
    }
    Ok(out)
}
fn response_item(value: Value) -> Result<Message> {
    super::validate_phase(&value)?;
    let mut v = obj(value, "Responses input item")?;
    let kind = v.remove("type").unwrap_or_else(|| json!("message"));
    // Item IDs/status are server bookkeeping; assistant phase, however, affects semantics.
    ignore(&mut v, &["id", "status"]);
    let message = match kind.as_str() {
        Some("message") => {
            v.remove("phase");
            let role = string(&mut v, "role")?;
            if !matches!(role.as_str(), "system" | "developer" | "user" | "assistant") {
                bail!("unsupported Responses role {role}");
            }
            let parts = response_parts(
                v.remove("content").context("message content missing")?,
                &role,
            )?;
            Message { role, parts }
        }
        Some("function_call") => Message {
            role: "assistant".into(),
            parts: vec![Part::Call {
                id: string(&mut v, "call_id")?,
                name: string(&mut v, "name")?,
                input: arguments(&string(&mut v, "arguments")?)?,
            }],
        },
        Some("function_call_output") => Message {
            role: "tool".into(),
            parts: vec![Part::Result {
                id: string(&mut v, "call_id")?,
                content: response_parts(
                    v.remove("output").context("function output missing")?,
                    "tool",
                )?,
                error: false,
            }],
        },
        _ => bail!(
            "unsupported Responses input item {kind}; reasoning/server tools require native Responses"
        ),
    };
    strict(&v, "Responses input item")?;
    Ok(message)
}
fn plain_parts(parts: Vec<Part>, to: Protocol, role: &str) -> Result<Vec<Value>> {
    parts
        .into_iter()
        .map(|part| plain_part(part, to, role))
        .collect()
}
fn plain_part(part: Part, to: Protocol, role: &str) -> Result<Value> {
    Ok(match part {
        Part::Text(text) => match to {
            Protocol::Anthropic | Protocol::Chat => json!({"type":"text","text":text}),
            Protocol::Responses => {
                json!({"type":if role == "assistant" {"output_text"} else {"input_text"},"text":text})
            }
        },
        Part::Image { url, detail } => match to {
            Protocol::Anthropic => {
                if detail.as_ref().is_some_and(|d| d != "auto") {
                    bail!(
                        "explicit image detail cannot be enforced by Anthropic; remove image detail or use native Chat/Responses"
                    );
                }
                if let Some(data) = url.strip_prefix("data:") {
                    let (media, data) = data
                        .split_once(";base64,")
                        .context("Anthropic image data URLs must use base64 encoding")?;
                    json!({"type":"image","source":{"type":"base64","media_type":media,"data":data}})
                } else {
                    json!({"type":"image","source":{"type":"url","url":url}})
                }
            }
            Protocol::Chat => {
                json!({"type":"image_url","image_url":{"url":url,"detail":detail.unwrap_or_else(|| "auto".into())}})
            }
            Protocol::Responses => {
                json!({"type":"input_image","image_url":url,"detail":detail.unwrap_or_else(|| "auto".into())})
            }
        },
        _ => bail!("nested tools cannot be translated in this content position"),
    })
}
fn tool_output(content: Vec<Part>, error: bool, to: Protocol) -> Result<Value> {
    if to == Protocol::Chat || content.iter().all(|p| matches!(p, Part::Text(_))) {
        let mut text = if error {
            "[Tool error]\n".to_owned()
        } else {
            String::new()
        };
        for part in content {
            match part {
                Part::Text(s) => text.push_str(&s),
                _ => bail!(
                    "Chat tool results only support text; image tool results require Responses or native Anthropic"
                ),
            }
        }
        Ok(Value::String(text))
    } else {
        let mut content = plain_parts(content, to, "tool")?;
        if error {
            content.insert(0, json!({"type":"input_text","text":"[Tool error]"}));
        }
        Ok(Value::Array(content))
    }
}
fn encode_messages(
    messages: Vec<Message>,
    to: Protocol,
    out: &mut Map<String, Value>,
) -> Result<()> {
    let mut encoded: Vec<Value> = Vec::new();
    let mut system: Vec<Value> = Vec::new();
    for message in messages {
        let role = message.role;
        if to == Protocol::Anthropic && role == "developer" {
            bail!(
                "developer-role hierarchy has no lossless Anthropic equivalent; use system role or native Chat/Responses"
            );
        }
        if to == Protocol::Anthropic && role == "system" {
            if !encoded.is_empty() {
                bail!(
                    "Anthropic cannot represent system instructions inserted between conversation turns"
                );
            }
            system.extend(plain_parts(message.parts, to, &role)?);
            continue;
        }
        let mut pending = Vec::new();
        // Flush at tool boundaries so mixed text/results retain their ordering.
        for part in message.parts {
            match part {
                Part::Result { id, content, error } => {
                    flush(&mut pending, &role, to, &mut encoded)?;
                    let item = match to {
                        Protocol::Anthropic => {
                            json!({"role":"user","content":[{"type":"tool_result","tool_use_id":id,"content":plain_parts(content,to,"tool")?,"is_error":error}]})
                        }
                        Protocol::Chat => {
                            json!({"role":"tool","tool_call_id":id,"content":tool_output(content,error,to)?})
                        }
                        Protocol::Responses => {
                            json!({"type":"function_call_output","call_id":id,"output":tool_output(content,error,to)?})
                        }
                    };
                    append_message(&mut encoded, item, to);
                }
                Part::Call { id, name, input } => {
                    if role != "assistant" {
                        bail!("tool calls require assistant role");
                    }
                    if to == Protocol::Responses {
                        flush(&mut pending, &role, to, &mut encoded)?;
                        encoded.push(json!({"type":"function_call","call_id":id,"name":name,"arguments":serde_json::to_string(&input)?}));
                    } else {
                        pending.push(Part::Call { id, name, input });
                    }
                }
                p => {
                    if to == Protocol::Chat
                        && pending
                            .last()
                            .is_some_and(|p| matches!(p, Part::Call { .. }))
                    {
                        bail!(
                            "Chat cannot preserve assistant content after a tool call and before its result; use native Messages/Responses"
                        );
                    }
                    pending.push(p);
                }
            }
        }
        flush(&mut pending, &role, to, &mut encoded)?;
    }
    if to == Protocol::Chat {
        let mut pending: Vec<&str> = Vec::new();
        for message in &encoded {
            if message["role"] == "tool" {
                let id = message["tool_call_id"]
                    .as_str()
                    .context("tool result missing call ID")?;
                let index = pending
                    .iter()
                    .position(|candidate| *candidate == id)
                    .context("Chat history contains an unmatched tool result")?;
                pending.swap_remove(index);
            } else {
                if !pending.is_empty() {
                    bail!(
                        "Chat cannot represent a message between tool calls and their results; use native Messages/Responses"
                    );
                }
                if let Some(calls) = message["tool_calls"].as_array() {
                    for call in calls {
                        pending.push(call["id"].as_str().context("tool call missing ID")?);
                    }
                }
            }
        }
        if !pending.is_empty() {
            bail!("Chat history requires every tool call to have a result before generation");
        }
    }
    if to == Protocol::Anthropic
        && encoded
            .last()
            .is_some_and(|message| message["role"] == "assistant")
    {
        bail!(
            "terminal assistant history would become an Anthropic assistant prefill; end with a user/tool-result turn or use the native source protocol"
        );
    }
    if to == Protocol::Anthropic && !system.is_empty() {
        out.insert("system".into(), Value::Array(system));
    }
    out.insert(
        if to == Protocol::Responses {
            "input"
        } else {
            "messages"
        }
        .into(),
        Value::Array(encoded),
    );
    Ok(())
}
fn append_message(encoded: &mut Vec<Value>, mut item: Value, to: Protocol) {
    if to == Protocol::Anthropic
        && let Some(last) = encoded.last_mut()
        && last["role"] == item["role"]
    {
        let Value::Array(content) = item["content"].take() else {
            unreachable!("encoded content is always an array");
        };
        last["content"].as_array_mut().unwrap().extend(content);
        return;
    }
    encoded.push(item);
}
fn flush(parts: &mut Vec<Part>, role: &str, to: Protocol, encoded: &mut Vec<Value>) -> Result<()> {
    if parts.is_empty() {
        return Ok(());
    }
    let mut content = Vec::new();
    let mut calls = Vec::new();
    for part in std::mem::take(parts) {
        match part {
            Part::Call { id, name, input } => {
                if to == Protocol::Anthropic {
                    content.push(json!({"type":"tool_use","id":id,"name":name,"input":input}));
                } else {
                    calls.push(json!({"id":id,"type":"function","function":{"name":name,"arguments":serde_json::to_string(&input)?}}));
                }
            }
            p => content.push(plain_part(p, to, role)?),
        }
    }
    if to == Protocol::Chat && !calls.is_empty() {
        // Text before tool calls belongs to the same assistant turn.
        let content = if content.is_empty() {
            Value::Null
        } else {
            Value::Array(content)
        };
        if let Some(last) = encoded.last_mut()
            && last["role"] == role
        {
            if last.get("tool_calls").is_some() && !content.is_null() {
                bail!(
                    "Chat cannot preserve text between parallel tool calls; use native Messages/Responses"
                );
            }
            if let Value::Array(content) = content {
                last["content"]
                    .as_array_mut()
                    .context("assistant content must be an array")?
                    .extend(content);
            }
            if let Some(previous) = last.get_mut("tool_calls").and_then(Value::as_array_mut) {
                previous.extend(calls);
            } else {
                last["tool_calls"] = Value::Array(calls);
            }
            return Ok(());
        }
        encoded.push(json!({"role":role,"content":content,"tool_calls":calls}));
    } else {
        append_message(encoded, json!({"role":role,"content":content}), to);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::request;
    use super::*;

    #[test]
    fn translated_response_storage_is_explicit_and_stateless() {
        for to in [Protocol::Anthropic, Protocol::Chat] {
            for store in [None, Some(Value::Null), Some(json!(true))] {
                let mut input = json!({"model":"x","max_output_tokens":16,"input":"Hello"});
                if let Some(store) = store {
                    input["store"] = store;
                }
                let error = request(input, Protocol::Responses, to).unwrap_err();
                assert!(error.to_string().contains("set store=false explicitly"));
            }
            let input = json!({"model":"x","max_output_tokens":16,"store":false,"input":"Hello"});
            assert!(request(input, Protocol::Responses, to).is_ok());
        }

        for from in [Protocol::Anthropic, Protocol::Chat] {
            let input = match from {
                Protocol::Anthropic => {
                    json!({"model":"x","max_tokens":16,"messages":[{"role":"user","content":"Hello"}]})
                }
                Protocol::Chat => {
                    json!({"model":"x","messages":[{"role":"user","content":"Hello"}]})
                }
                Protocol::Responses => unreachable!(),
            };
            let out = request(input, from, Protocol::Responses).unwrap();
            assert_eq!(out["store"], false);
        }

        for store in [
            None,
            Some(Value::Null),
            Some(json!(false)),
            Some(json!(true)),
        ] {
            let mut input = json!({"model":"x","input":"Hello"});
            if let Some(store) = store {
                input["store"] = store;
            }
            assert_eq!(
                request(input.clone(), Protocol::Responses, Protocol::Responses).unwrap(),
                input
            );
        }
    }

    #[test]
    fn empty_stop_lists_do_not_constrain_responses_requests() {
        for (from, key) in [
            (Protocol::Anthropic, "stop_sequences"),
            (Protocol::Chat, "stop"),
        ] {
            let input = json!({"model":"x","max_tokens":16,"messages":[
                {"role":"user","content":"Hello"}
            ],key:[]});
            let out = request(input, from, Protocol::Responses).unwrap();
            assert_eq!(
                out["input"],
                json!([
                    {"role":"user","content":[{"type":"input_text","text":"Hello"}]}
                ])
            );
            assert_eq!(out["max_output_tokens"], 16);
            assert!(out.get("stop").is_none());
            assert!(out.get("stop_sequences").is_none());
        }
    }

    #[test]
    fn responses_stop_lists_still_reject_constraints_and_invalid_shapes() {
        for (from, key) in [
            (Protocol::Anthropic, "stop_sequences"),
            (Protocol::Chat, "stop"),
        ] {
            for stop in [
                json!(["END"]),
                json!("END"),
                json!([null]),
                json!({}),
                json!(false),
            ] {
                let input = json!({"model":"x","max_tokens":16,"messages":[
                    {"role":"user","content":"Hello"}
                ],key:stop});
                assert!(request(input, from, Protocol::Responses).is_err());
            }
        }
    }

    #[test]
    fn responses_nullable_tool_descriptions_preserve_tool_contract() {
        for to in [Protocol::Anthropic, Protocol::Chat] {
            for description in [None, Some(Value::Null), Some(json!("Look up a value"))] {
                let mut input = json!({"model":"x","max_output_tokens":16,"store":false,"input":"Hello",
                    "tools":[{"type":"function","name":"lookup","strict":false,
                        "parameters":{"type":"object","properties":{"query":{"type":"string"}}}}]});
                if let Some(description) = &description {
                    input["tools"][0]["description"] = description.clone();
                }
                let out = request(input, Protocol::Responses, to).unwrap();
                let tool = if to == Protocol::Chat {
                    &out["tools"][0]["function"]
                } else {
                    &out["tools"][0]
                };
                assert_eq!(tool["name"], "lookup");
                let schema = if to == Protocol::Chat {
                    "parameters"
                } else {
                    "input_schema"
                };
                assert_eq!(
                    tool[schema],
                    json!({"type":"object","properties":{"query":{"type":"string"}}})
                );
                if let Some(description) = description.filter(Value::is_string) {
                    assert_eq!(tool["description"], description);
                } else {
                    assert!(tool.get("description").is_none());
                }
            }
        }
    }

    #[test]
    fn responses_nullable_tool_descriptions_do_not_hide_invalid_tools() {
        for to in [Protocol::Anthropic, Protocol::Chat] {
            for description in [json!(false), json!(0), json!([]), json!({})] {
                let input = json!({"model":"x","max_output_tokens":16,"store":false,"input":"Hello",
                    "tools":[{"type":"function","name":"lookup","strict":false,
                        "parameters":{"type":"object"},"description":description}]});
                assert!(request(input, Protocol::Responses, to).is_err());
            }
            let input = json!({"model":"x","max_output_tokens":16,"store":false,"input":"Hello",
                "tools":[{"type":"function","name":"lookup","strict":false,
                    "parameters":{"type":"object"},"description":null,"unknown":null}]});
            assert!(request(input, Protocol::Responses, to).is_err());
        }
    }

    #[test]
    fn chat_null_stream_is_absent_without_changing_explicit_stream_modes() {
        for to in [Protocol::Anthropic, Protocol::Responses] {
            for stream in [
                None,
                Some(Value::Null),
                Some(json!(false)),
                Some(json!(true)),
            ] {
                let mut input = json!({"model":"x","max_tokens":16,"messages":[
                    {"role":"user","content":"Hello"}
                ]});
                if let Some(stream) = &stream {
                    input["stream"] = stream.clone();
                }
                let out = request(input, Protocol::Chat, to).unwrap();
                if let Some(stream) = stream.filter(Value::is_boolean) {
                    assert_eq!(out["stream"], stream);
                } else {
                    assert!(out.get("stream").is_none());
                }
                let key = if to == Protocol::Anthropic {
                    "messages"
                } else {
                    "input"
                };
                assert_eq!(out[key][0]["content"][0]["text"], "Hello");
            }
        }
    }

    #[test]
    fn anthropic_history_empty_citations_preserve_conversation() {
        for to in [Protocol::Chat, Protocol::Responses] {
            for citations in [None, Some(Value::Null), Some(json!([]))] {
                let mut input = json!({"model":"x","max_tokens":16,"messages":[
                    {"role":"user","content":"Hello"},
                    {"role":"assistant","content":[{"type":"text","text":"Previous answer"}]},
                    {"role":"user","content":"Continue"}
                ]});
                if let Some(citations) = citations {
                    input["messages"][1]["content"][0]["citations"] = citations;
                }
                let out = request(input, Protocol::Anthropic, to).unwrap();
                let (key, user_text, assistant_text) = if to == Protocol::Chat {
                    ("messages", "text", "text")
                } else {
                    ("input", "input_text", "output_text")
                };
                assert_eq!(
                    out[key],
                    json!([
                        {"role":"user","content":[{"type":user_text,"text":"Hello"}]},
                        {"role":"assistant","content":[{"type":assistant_text,"text":"Previous answer"}]},
                        {"role":"user","content":[{"type":user_text,"text":"Continue"}]}
                    ])
                );
            }
        }
    }

    #[test]
    fn anthropic_history_empty_citations_do_not_hide_unsupported_or_malformed_values() {
        for citations in [
            json!([{"type":"char_location","cited_text":"source"}]),
            json!([null]),
            json!({}),
            json!(""),
            json!(false),
            json!(0),
        ] {
            for to in [Protocol::Chat, Protocol::Responses] {
                let input = json!({"model":"x","max_tokens":16,"messages":[
                    {"role":"assistant","content":[
                        {"type":"text","text":"Previous answer","citations":citations}
                    ]},
                    {"role":"user","content":"Continue"}
                ]});
                assert!(request(input, Protocol::Anthropic, to).is_err());
            }
        }
        for to in [Protocol::Chat, Protocol::Responses] {
            let input = json!({"model":"x","max_tokens":16,"messages":[
                {"role":"user","content":[
                    {"type":"text","text":"Hello","citations":[],"unknown_field":null}
                ]}
            ]});
            assert!(request(input, Protocol::Anthropic, to).is_err());
        }
    }

    #[test]
    fn chat_history_empty_refusal_preserves_conversation() {
        for to in [Protocol::Anthropic, Protocol::Responses] {
            for refusal in [None, Some(Value::Null), Some(json!(""))] {
                let mut input = json!({"model":"x","max_tokens":16,"messages":[
                    {"role":"user","content":"Hello"},
                    {"role":"assistant","content":"Previous answer"},
                    {"role":"user","content":"Continue"}
                ]});
                if let Some(refusal) = refusal {
                    input["messages"][1]["refusal"] = refusal;
                }
                let out = request(input, Protocol::Chat, to).unwrap();
                let (key, user_text, assistant_text) = if to == Protocol::Anthropic {
                    ("messages", "text", "text")
                } else {
                    ("input", "input_text", "output_text")
                };
                assert_eq!(
                    out[key],
                    json!([
                        {"role":"user","content":[{"type":user_text,"text":"Hello"}]},
                        {"role":"assistant","content":[{"type":assistant_text,"text":"Previous answer"}]},
                        {"role":"user","content":[{"type":user_text,"text":"Continue"}]}
                    ])
                );
            }
        }
    }

    #[test]
    fn chat_history_empty_refusal_does_not_hide_unsupported_or_malformed_values() {
        for refusal in [
            json!("Cannot comply"),
            json!(false),
            json!(0),
            json!([]),
            json!({}),
        ] {
            for to in [Protocol::Anthropic, Protocol::Responses] {
                let input = json!({"model":"x","max_tokens":16,"messages":[
                    {"role":"assistant","content":"Previous answer","refusal":refusal},
                    {"role":"user","content":"Continue"}
                ]});
                assert!(request(input, Protocol::Chat, to).is_err());
            }
        }
    }

    #[test]
    fn responses_history_null_phase_preserves_conversation() {
        for to in [Protocol::Anthropic, Protocol::Chat] {
            for phase in [None, Some(Value::Null)] {
                let mut input = json!({"model":"x","max_output_tokens":16,"store":false,"input":[
                    {"role":"user","content":"Hello"},
                    {"type":"message","id":"msg_previous","status":"completed","role":"assistant",
                     "content":[{"type":"output_text","text":"Previous answer","annotations":[]}]},
                    {"role":"user","content":"Continue"}
                ]});
                if let Some(phase) = phase {
                    input["input"][1]["phase"] = phase;
                }
                let out = request(input, Protocol::Responses, to).unwrap();
                assert_eq!(
                    out["messages"],
                    json!([
                        {"role":"user","content":[{"type":"text","text":"Hello"}]},
                        {"role":"assistant","content":[{"type":"text","text":"Previous answer"}]},
                        {"role":"user","content":[{"type":"text","text":"Continue"}]}
                    ])
                );
            }
        }
    }

    #[test]
    fn responses_history_null_phase_does_not_hide_non_null_values() {
        for phase in [
            json!("commentary"),
            json!("final_answer"),
            json!(""),
            json!(false),
            json!(0),
            json!([]),
            json!({}),
        ] {
            for to in [Protocol::Anthropic, Protocol::Chat] {
                let input = json!({"model":"x","max_output_tokens":16,"store":false,"input":[
                    {"role":"assistant","phase":phase,"content":"Previous answer"},
                    {"role":"user","content":"Continue"}
                ]});
                assert!(request(input, Protocol::Responses, to).is_err());
            }
        }
    }

    #[test]
    fn responses_history_empty_logprobs_preserves_conversation() {
        for to in [Protocol::Anthropic, Protocol::Chat] {
            for logprobs in [None, Some(Value::Null), Some(json!([]))] {
                let mut input = json!({"model":"x","max_output_tokens":16,"store":false,"input":[
                    {"role":"user","content":"Hello"},
                    {"role":"assistant","content":[
                        {"type":"output_text","text":"Previous answer","annotations":[]}
                    ]},
                    {"role":"user","content":"Continue"}
                ]});
                if let Some(logprobs) = logprobs {
                    input["input"][1]["content"][0]["logprobs"] = logprobs;
                }
                let out = request(input, Protocol::Responses, to).unwrap();
                assert_eq!(
                    out["messages"],
                    json!([
                        {"role":"user","content":[{"type":"text","text":"Hello"}]},
                        {"role":"assistant","content":[{"type":"text","text":"Previous answer"}]},
                        {"role":"user","content":[{"type":"text","text":"Continue"}]}
                    ])
                );
            }
        }
    }

    #[test]
    fn responses_history_empty_logprobs_does_not_hide_unsupported_or_malformed_values() {
        for logprobs in [
            json!([{"token":"answer","logprob":-0.5,"bytes":[97],"top_logprobs":[]}]),
            json!(""),
            json!(false),
            json!(0),
            json!({}),
        ] {
            for to in [Protocol::Anthropic, Protocol::Chat] {
                let input = json!({"model":"x","max_output_tokens":16,"store":false,"input":[
                    {"role":"assistant","content":[
                        {"type":"output_text","text":"Previous answer","annotations":[],"logprobs":logprobs}
                    ]},
                    {"role":"user","content":"Continue"}
                ]});
                assert!(request(input, Protocol::Responses, to).is_err());
            }
        }
    }

    #[test]
    fn chat_nullable_caps_do_not_conflict_or_override_explicit_caps() {
        for to in [Protocol::Anthropic, Protocol::Responses] {
            let output_key = if to == Protocol::Anthropic {
                "max_tokens"
            } else {
                "max_output_tokens"
            };
            for (old, new) in [(json!(17), Value::Null), (Value::Null, json!(17))] {
                let input = json!({
                    "model":"x",
                    "messages":[{"role":"user","content":"hello"}],
                    "max_tokens":old,
                    "max_completion_tokens":new
                });
                let out = request(input, Protocol::Chat, to).unwrap();
                assert_eq!(out[output_key], 17);
            }
            let input = json!({
                "model":"x",
                "messages":[{"role":"user","content":"hello"}],
                "max_tokens":17,
                "max_completion_tokens":18
            });
            assert!(request(input, Protocol::Chat, to).is_err());
        }
    }

    #[test]
    fn chat_null_caps_are_absent_but_anthropic_still_requires_a_positive_cap() {
        for caps in [
            json!({"max_tokens":null}),
            json!({"max_completion_tokens":null}),
            json!({"max_tokens":null,"max_completion_tokens":null}),
        ] {
            let mut input = json!({"model":"x","messages":[{"role":"user","content":"hello"}]});
            input
                .as_object_mut()
                .unwrap()
                .extend(caps.as_object().unwrap().clone());
            let out = request(input.clone(), Protocol::Chat, Protocol::Responses).unwrap();
            assert!(out.get("max_output_tokens").is_none());
            assert!(request(input, Protocol::Chat, Protocol::Anthropic).is_err());
        }
    }

    #[test]
    fn chat_nullable_options_preserve_messages_tools_and_sampling_absence() {
        let input = json!({
            "model":"x",
            "max_tokens":17,
            "stream":true,
            "messages":[
                {"role":"system","content":"rules"},
                {"role":"assistant","content":"checking","tool_calls":null},
                {"role":"user","content":"hello"}
            ],
            "tools":[{"type":"function","function":{
                "name":"lookup",
                "parameters":{
                    "type":"object",
                    "properties":{"value":{"type":["string","null"],"default":null}}
                }
            }}]
        });
        for to in [Protocol::Anthropic, Protocol::Responses] {
            let expected = request(input.clone(), Protocol::Chat, to).unwrap();
            let mut nullable = input.clone();
            for key in [
                "audio",
                "frequency_penalty",
                "logit_bias",
                "logprobs",
                "max_completion_tokens",
                "modalities",
                "moderation",
                "n",
                "prediction",
                "presence_penalty",
                "prompt_cache_key",
                "prompt_cache_retention",
                "reasoning_effort",
                "response_format",
                "safety_identifier",
                "seed",
                "service_tier",
                "stop",
                "store",
                "stream_options",
                "temperature",
                "top_logprobs",
                "top_p",
                "verbosity",
            ] {
                nullable[key] = Value::Null;
            }
            let out = request(nullable, Protocol::Chat, to).unwrap();
            assert_eq!(out, expected);
            assert!(out.get("temperature").is_none());
            assert!(out.get("top_p").is_none());
            let schema_key = if to == Protocol::Anthropic {
                "input_schema"
            } else {
                "parameters"
            };
            assert_eq!(
                out["tools"][0][schema_key],
                input["tools"][0]["function"]["parameters"]
            );
        }
    }

    #[test]
    fn chat_stream_options_accept_boolean_include_usage() {
        for include_usage in [false, true] {
            for to in [Protocol::Anthropic, Protocol::Responses] {
                let input = json!({
                    "model":"x",
                    "max_completion_tokens":17,
                    "stream":true,
                    "stream_options":{"include_usage":include_usage},
                    "response_format":{"type":"text"},
                    "temperature":0.5,
                    "top_p":0.8,
                    "messages":[{"role":"user","content":"hello"}]
                });
                let out = request(input, Protocol::Chat, to).unwrap();
                assert_eq!(out["stream"], true);
                assert_eq!(out["temperature"], 0.5);
                assert_eq!(out["top_p"], 0.8);
                assert!(out.get("stream_options").is_none());
            }
        }
    }

    #[test]
    fn chat_non_null_unsupported_options_remain_rejected() {
        for (key, value) in [
            ("audio", json!({"format":"wav","voice":"alloy"})),
            ("logit_bias", json!({"123":1})),
            ("modalities", json!(["text"])),
            ("moderation", json!({})),
            ("prediction", json!({"type":"content","content":"answer"})),
            ("prompt_cache_key", json!("cache-key")),
            ("prompt_cache_retention", json!("24h")),
            ("reasoning_effort", json!("low")),
            ("safety_identifier", json!("user-id")),
            ("seed", json!(42)),
            ("service_tier", json!("default")),
            ("top_logprobs", json!(0)),
            ("verbosity", json!("low")),
            ("n", json!(2)),
            ("frequency_penalty", json!(0.5)),
            ("presence_penalty", json!(0.5)),
            ("logprobs", json!(true)),
            ("store", json!(true)),
            ("response_format", json!({"type":"json_object"})),
        ] {
            for to in [Protocol::Anthropic, Protocol::Responses] {
                let mut input = json!({
                    "model":"x",
                    "max_tokens":17,
                    "messages":[{"role":"user","content":"hello"}]
                });
                input[key] = value.clone();
                assert!(
                    request(input, Protocol::Chat, to).is_err(),
                    "{key}={value} must not be ignored"
                );
            }
        }
    }

    #[test]
    fn chat_null_normalization_does_not_hide_invalid_or_unknown_fields() {
        for (key, value) in [
            ("model", Value::Null),
            ("messages", Value::Null),
            ("unknown_option", Value::Null),
            ("parallel_tool_calls", Value::Null),
            ("max_tokens", json!(0)),
            ("max_tokens", json!(-1)),
            ("max_tokens", json!(1.5)),
            ("max_tokens", json!("17")),
            ("max_completion_tokens", json!(0)),
            ("max_completion_tokens", json!(-1)),
            ("max_completion_tokens", json!(1.5)),
            ("max_completion_tokens", json!("17")),
            ("tools", json!({})),
            ("tool_choice", json!({"type":"function","function":null})),
            ("response_format", json!("text")),
            ("stream_options", json!(false)),
            ("stream_options", json!({"include_usage":null})),
            ("stream_options", json!({"include_usage":"true"})),
            ("stream_options", json!({"unknown_option":null})),
            ("stop", json!([null])),
        ] {
            for to in [Protocol::Anthropic, Protocol::Responses] {
                let mut input = json!({
                    "model":"x",
                    "max_tokens":17,
                    "messages":[{"role":"user","content":"hello"}]
                });
                if key == "max_completion_tokens" {
                    input.as_object_mut().unwrap().remove("max_tokens");
                }
                input[key] = value.clone();
                assert!(
                    request(input, Protocol::Chat, to).is_err(),
                    "{key}={value} must remain invalid"
                );
            }
        }
        for to in [Protocol::Anthropic, Protocol::Responses] {
            for input in [
                json!({"model":"x","max_tokens":17,"messages":[
                    {"role":"user","content":"hello","unknown_option":null}
                ]}),
                json!({"model":"x","max_tokens":17,"messages":[
                    {"role":"user","content":"hello"}
                ],"tools":[{"type":"function","function":{
                    "name":"lookup","parameters":{"type":"object"},"unknown_option":null
                }}]}),
            ] {
                assert!(request(input, Protocol::Chat, to).is_err());
            }
        }
    }

    #[test]
    fn chat_history_null_tool_calls_preserves_text() {
        for role in ["assistant", "user", "system"] {
            let input = json!({"model":"x","max_tokens":10,"messages":[{"role":role,"content":"hello"},{"role":"user","content":"next"}]});
            for to in [Protocol::Anthropic, Protocol::Responses] {
                let expected = request(input.clone(), Protocol::Chat, to).unwrap();
                let mut nullable = input.clone();
                nullable["messages"][0]["tool_calls"] = Value::Null;
                let out = request(nullable, Protocol::Chat, to).unwrap();
                assert_eq!(out, expected);
                if role == "assistant" {
                    if to == Protocol::Anthropic {
                        assert_eq!(out["messages"][0]["content"][0]["text"], "hello");
                    } else {
                        assert_eq!(out["input"][0]["content"][0]["text"], "hello");
                    }
                }
            }
        }
    }

    #[test]
    fn chat_history_rejects_non_array_tool_calls() {
        for calls in [json!("invalid"), json!({}), json!(true), json!(1)] {
            for to in [Protocol::Anthropic, Protocol::Responses] {
                let input = json!({"model":"x","max_tokens":10,"messages":[{"role":"assistant","content":"hello","tool_calls":calls}]});
                let error = request(input, Protocol::Chat, to).unwrap_err();
                assert!(error.to_string().contains("tool_calls must be an array"));
            }
        }
    }

    #[test]
    fn anthropic_custom_and_null_tool_types_match_absent_type() {
        let schema = json!({"type":"object","properties":{"query":{"type":"string"}},"required":["query"],"additionalProperties":false});
        for strict in [
            None,
            Some(Value::Null),
            Some(json!(false)),
            Some(json!(true)),
        ] {
            let mut input = json!({"model":"x","max_tokens":10,"messages":[{"role":"user","content":"hello"}],"tools":[{"name":"lookup","description":"Look up a query","input_schema":schema}]});
            if let Some(strict) = strict {
                input["tools"][0]["strict"] = strict;
            }
            for to in [Protocol::Chat, Protocol::Responses] {
                let expected = request(input.clone(), Protocol::Anthropic, to).unwrap();
                let tool = if to == Protocol::Chat {
                    &expected["tools"][0]["function"]
                } else {
                    &expected["tools"][0]
                };
                assert_eq!(tool["name"], "lookup");
                assert_eq!(tool["description"], "Look up a query");
                assert_eq!(tool["parameters"], schema);
                let expected_strict = input["tools"][0]["strict"]
                    .as_bool()
                    .map(|value| json!(value));
                if to == Protocol::Responses {
                    assert_eq!(tool["strict"], expected_strict.unwrap_or(json!(false)));
                } else {
                    assert_eq!(tool.get("strict"), expected_strict.as_ref());
                }
                for kind in [Value::Null, json!("custom")] {
                    let mut explicit = input.clone();
                    explicit["tools"][0]["type"] = kind;
                    assert_eq!(
                        request(explicit, Protocol::Anthropic, to).unwrap(),
                        expected
                    );
                }
            }
        }
    }

    #[test]
    fn anthropic_rejects_native_and_malformed_tool_types() {
        for kind in [
            json!("web_search_20250305"),
            json!("computer_20250124"),
            json!("bash_20250124"),
            json!("function"),
            json!(""),
            json!(false),
            json!(1),
            json!({}),
            json!([]),
        ] {
            for to in [Protocol::Chat, Protocol::Responses] {
                let input = json!({"model":"x","max_tokens":10,"messages":[{"role":"user","content":"hello"}],"tools":[{"type":kind,"name":"lookup","input_schema":{"type":"object"}}]});
                let error = request(input, Protocol::Anthropic, to).unwrap_err();
                assert!(error.to_string().contains("only custom Anthropic tools"));
            }
        }
    }

    #[test]
    fn claude_mixed_tools_and_result_to_responses() {
        let input = json!({"model":"codex","max_tokens":512,"system":[{"type":"text","text":"system","cache_control":{"type":"ephemeral"}}],"messages":[{"role":"assistant","content":[{"type":"text","text":"looking"},{"type":"tool_use","id":"call_1","name":"read","input":{"path":"x"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"call_1","is_error":true,"content":"missing"},{"type":"text","text":"try again"}]}],"tools":[{"name":"read","input_schema":{"type":"object"},"cache_control":{"type":"ephemeral"}}]});
        let out = request(input, Protocol::Anthropic, Protocol::Responses).unwrap();
        assert_eq!(out["input"][2]["type"], "function_call");
        assert_eq!(out["input"][3]["output"], "[Tool error]\nmissing");
        assert_eq!(out["input"][4]["content"][0]["text"], "try again");
        assert_eq!(out["tools"][0]["type"], "function");
    }
    #[test]
    fn rejects_budget_and_unknown_semantics() {
        let input = json!({"model":"x","max_tokens":1,"messages":[{"role":"user","content":"hi"}],"thinking":{"type":"enabled","budget_tokens":1000}});
        assert!(request(input, Protocol::Anthropic, Protocol::Responses).is_err());
        let input = json!({"model":"x","messages":[{"role":"user","content":"hi"}],"seed":42});
        assert!(request(input, Protocol::Chat, Protocol::Responses).is_err());
    }
    #[test]
    fn adaptive_thinking_maps_supported_effort() {
        for effort in ["low", "medium", "high"] {
            let input = json!({"model":"x","max_tokens":10,"messages":[{"role":"user","content":"hi"}],"thinking":{"type":"adaptive"},"output_config":{"effort":effort}});
            assert_eq!(
                request(input, Protocol::Anthropic, Protocol::Responses).unwrap()["reasoning"]["effort"],
                effort
            );
        }
    }
    #[test]
    fn adaptive_thinking_without_explicit_effort_is_rejected() {
        let base = json!({"model":"x","max_tokens":10,"messages":[{"role":"user","content":"hi"}]});
        let mut bare = base.clone();
        bare["thinking"] = json!({"type":"adaptive"});
        let error = request(bare, Protocol::Anthropic, Protocol::Responses)
            .unwrap_err()
            .to_string();
        assert!(error.contains("output_config.effort"), "{error}");
        assert!(error.contains("low, medium, or high"), "{error}");

        let mut empty = base.clone();
        empty["thinking"] = json!({"type":"adaptive"});
        empty["output_config"] = json!({});
        let error = request(empty, Protocol::Anthropic, Protocol::Responses)
            .unwrap_err()
            .to_string();
        assert!(error.contains("output_config.effort"), "{error}");

        for effort in [Value::Null, json!("max"), json!("minimal")] {
            let mut input = base.clone();
            input["thinking"] = json!({"type":"adaptive"});
            input["output_config"] = json!({"effort":effort});
            let error = request(input, Protocol::Anthropic, Protocol::Responses)
                .unwrap_err()
                .to_string();
            assert!(error.contains("output_config.effort"), "{effort}: {error}");
        }

        let mut chat = base.clone();
        chat["thinking"] = json!({"type":"adaptive"});
        chat["output_config"] = json!({"effort":"high"});
        assert!(request(chat, Protocol::Anthropic, Protocol::Chat).is_err());

        let mut enabled = base.clone();
        enabled["thinking"] = json!({"type":"enabled","budget_tokens":1000});
        let error = request(enabled, Protocol::Anthropic, Protocol::Responses)
            .unwrap_err()
            .to_string();
        assert!(error.contains("output_config.effort"), "{error}");
        assert!(error.contains("low, medium, or high"), "{error}");

        let mut disabled = base;
        disabled["thinking"] = json!({"type":"disabled"});
        let out = request(disabled, Protocol::Anthropic, Protocol::Responses).unwrap();
        assert!(out.get("reasoning").is_none());
    }
    #[test]
    fn cross_protocol_rejects_top_level_metadata_and_user() {
        let cases = [
            (
                Protocol::Chat,
                Protocol::Responses,
                json!({"model":"x","messages":[{"role":"user","content":"hi"}]}),
            ),
            (
                Protocol::Anthropic,
                Protocol::Chat,
                json!({"model":"x","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}),
            ),
            (
                Protocol::Anthropic,
                Protocol::Responses,
                json!({"model":"x","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}),
            ),
            (
                Protocol::Responses,
                Protocol::Chat,
                json!({"model":"x","input":"hi","store":false}),
            ),
            (
                Protocol::Responses,
                Protocol::Anthropic,
                json!({"model":"x","max_output_tokens":10,"input":"hi","store":false}),
            ),
        ];
        for (from, to, base) in cases {
            for (field, value) in [("metadata", json!({"k":"v"})), ("user", json!("person"))] {
                let mut input = base.clone();
                input[field] = value;
                let error = request(input, from, to).unwrap_err().to_string();
                assert!(
                    error.contains(&format!("cannot translate request.{field}")),
                    "{from:?}->{to:?} {field}: {error}"
                );
            }
        }
    }
    #[test]
    fn same_protocol_preserves_user_and_metadata() {
        for protocol in [Protocol::Anthropic, Protocol::Chat, Protocol::Responses] {
            let input = json!({"model":"x","user":"person","metadata":{"k":"v"},"messages":[{"role":"user","content":"hi"}]});
            let input = if protocol == Protocol::Responses {
                json!({"model":"x","user":"person","metadata":{"k":"v"},"input":"hi"})
            } else {
                input
            };
            assert_eq!(request(input.clone(), protocol, protocol).unwrap(), input);
        }
    }
    #[test]
    fn chat_history_tools_to_anthropic() {
        let input = json!({"model":"x","max_tokens":10,"messages":[{"role":"system","content":"sys"},{"role":"assistant","content":"checking","tool_calls":[{"id":"a","type":"function","function":{"name":"read","arguments":"{}"}}]},{"role":"tool","tool_call_id":"a","content":"ok"},{"role":"user","content":"next"}]});
        let out = request(input, Protocol::Chat, Protocol::Anthropic).unwrap();
        assert_eq!(out["messages"][0]["content"][1]["type"], "tool_use");
        assert_eq!(out["messages"][1]["content"][0]["type"], "tool_result");
        assert_eq!(out["messages"][1]["content"][1]["text"], "next");
    }
    #[test]
    fn responses_images_and_tools_to_anthropic() {
        let input = json!({"model":"x","max_output_tokens":10,"store":false,"input":[{"role":"user","content":[{"type":"input_image","image_url":"data:image/png;base64,YQ==","detail":"auto"}]},{"type":"function_call","call_id":"a","name":"f","arguments":"{}"},{"type":"function_call_output","call_id":"a","output":"ok"}]});
        let out = request(input, Protocol::Responses, Protocol::Anthropic).unwrap();
        assert_eq!(
            out["messages"][0]["content"][0]["source"]["media_type"],
            "image/png"
        );
        assert_eq!(out["messages"][2]["content"][0]["tool_use_id"], "a");
    }
    #[test]
    fn translation_regression_preserves_non_strict_tool_contract() {
        let schema = json!({"type":"object","properties":{"optional":{"type":"string"}}});
        let cases = [
            (
                Protocol::Anthropic,
                json!({"model":"x","max_tokens":10,"messages":[{"role":"user","content":"hi"}],"tools":[{"name":"lookup","input_schema":schema}]}),
            ),
            (
                Protocol::Chat,
                json!({"model":"x","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"lookup","parameters":schema}}]}),
            ),
            (
                Protocol::Chat,
                json!({"model":"x","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"lookup","parameters":schema,"strict":null}}]}),
            ),
        ];
        for (from, input) in cases {
            let out = request(input, from, Protocol::Responses).unwrap();
            assert_eq!(out["tools"][0]["strict"], false);
            assert_eq!(out["tools"][0]["parameters"], schema);
        }
    }

    #[test]
    fn translation_regression_rejects_text_between_tools_and_results() {
        let input = json!({"model":"x","max_tokens":10,"messages":[
            {"role":"assistant","content":[{"type":"tool_use","id":"a","name":"read","input":{}},{"type":"text","text":"interleaved"}]},
            {"role":"user","content":[{"type":"tool_result","tool_use_id":"a","content":"ok"}]}
        ]});
        assert!(request(input, Protocol::Anthropic, Protocol::Chat).is_err());
        let input = json!({"model":"x","store":false,"input":[
            {"type":"function_call","call_id":"a","name":"read","arguments":"{}"},
            {"role":"assistant","content":[{"type":"output_text","text":"interleaved"}]},
            {"type":"function_call_output","call_id":"a","output":"ok"}
        ]});
        assert!(request(input, Protocol::Responses, Protocol::Chat).is_err());
    }

    #[test]
    fn translation_regression_preserves_claude_code_dynamic_system_order() {
        let input = json!({"model":"x","max_tokens":10,"system":"base rules","messages":[
            {"role":"user","content":"hello"},
            {"role":"system","content":[{"type":"text","text":"dynamic context","cache_control":{"type":"ephemeral"}}]}
        ]});
        for to in [Protocol::Chat, Protocol::Responses] {
            let out = request(input.clone(), Protocol::Anthropic, to).unwrap();
            let key = if to == Protocol::Responses {
                "input"
            } else {
                "messages"
            };
            assert_eq!(out[key][0]["role"], "system");
            assert_eq!(out[key][1]["role"], "user");
            assert_eq!(out[key][2]["role"], "system");
            assert_eq!(out[key][2]["content"][0]["text"], "dynamic context");
        }
    }

    #[test]
    fn anthropic_completed_tool_round_is_not_assistant_prefill() {
        let input = json!({"model":"x","max_tokens":16,"messages":[
            {"role":"assistant","content":[{"type":"tool_use","id":"a","name":"read","input":{}}]},
            {"role":"user","content":[{"type":"tool_result","tool_use_id":"a","content":"ok"}]},
            {"role":"system","content":"dynamic context"}
        ]});
        let chat = request(input.clone(), Protocol::Anthropic, Protocol::Chat).unwrap();
        assert_eq!(chat["messages"][0]["tool_calls"][0]["id"], "a");
        assert_eq!(chat["messages"][1]["tool_call_id"], "a");
        assert_eq!(chat["messages"][1]["content"], "ok");
        assert_eq!(chat["messages"][2]["role"], "system");
        let responses = request(input, Protocol::Anthropic, Protocol::Responses).unwrap();
        assert_eq!(responses["input"][0]["type"], "function_call");
        assert_eq!(responses["input"][0]["call_id"], "a");
        assert_eq!(responses["input"][1]["type"], "function_call_output");
        assert_eq!(responses["input"][1]["call_id"], "a");
        assert_eq!(responses["input"][1]["output"], "ok");
        assert_eq!(responses["input"][2]["role"], "system");
    }

    #[test]
    fn terminal_assistant_history_is_not_translated_into_anthropic_prefill() {
        for (from, key, cap) in [
            (Protocol::Chat, "messages", "max_tokens"),
            (Protocol::Responses, "input", "max_output_tokens"),
        ] {
            let mut input = json!({"model":"x"});
            input[cap] = json!(16);
            if from == Protocol::Responses {
                input["store"] = Value::Bool(false);
            }
            input[key] = json!([
                {"role":"user","content":"Say hello"},
                {"role":"assistant","content":"Hello"},
            ]);
            assert!(request(input.clone(), from, Protocol::Anthropic).is_err());
            assert_eq!(request(input.clone(), from, from).unwrap(), input);

            input[key]
                .as_array_mut()
                .unwrap()
                .push(json!({"role":"user","content":"Explain"}));
            let translated = request(input, from, Protocol::Anthropic).unwrap();
            assert_eq!(translated["messages"][1]["content"][0]["text"], "Hello");
            assert_eq!(translated["messages"][2]["role"], "user");
            assert_eq!(translated["messages"][2]["content"][0]["text"], "Explain");
        }
    }

    #[test]
    fn anthropic_assistant_prefill_is_rejected_for_cross_protocol_requests() {
        for content in [
            json!("The answer is ("),
            json!([{"type":"text","text":"The answer is ("}]),
        ] {
            for trailing_system in [false, true] {
                let mut input = json!({"model":"x","max_tokens":16,"messages":[
                    {"role":"user","content":"Question"},
                    {"role":"assistant","content":content}
                ]});
                if trailing_system {
                    input["messages"].as_array_mut().unwrap().extend([
                        json!({"role":"system","content":"dynamic context"}),
                        json!({"role":"system","content":[{"type":"text","text":"more context"}]}),
                    ]);
                }
                for to in [Protocol::Chat, Protocol::Responses] {
                    let error = request(input.clone(), Protocol::Anthropic, to).unwrap_err();
                    assert!(error.to_string().contains("assistant prefill"), "{error}");
                }
                assert_eq!(
                    request(input.clone(), Protocol::Anthropic, Protocol::Anthropic).unwrap(),
                    input
                );
            }
        }
    }

    #[test]
    fn anthropic_completed_assistant_history_keeps_dynamic_system_order() {
        let input = json!({"model":"x","max_tokens":16,"messages":[
            {"role":"user","content":"Question"},
            {"role":"assistant","content":"The answer is (42)."},
            {"role":"system","content":"dynamic context"},
            {"role":"user","content":"Explain"},
            {"role":"system","content":"more context"}
        ]});
        for to in [Protocol::Chat, Protocol::Responses] {
            let out = request(input.clone(), Protocol::Anthropic, to).unwrap();
            let key = if to == Protocol::Responses {
                "input"
            } else {
                "messages"
            };
            let messages = out[key].as_array().unwrap();
            assert_eq!(messages.len(), 5);
            for (message, (role, text)) in messages.iter().zip([
                ("user", "Question"),
                ("assistant", "The answer is (42)."),
                ("system", "dynamic context"),
                ("user", "Explain"),
                ("system", "more context"),
            ]) {
                assert_eq!(message["role"], role);
                assert_eq!(message["content"][0]["text"], text);
            }
        }
    }

    #[test]
    fn responses_implicit_schema_normalization_is_not_silently_removed() {
        let mut input = json!({"model":"x","store":false,"input":"hi","tools":[{"type":"function","name":"lookup","parameters":{"type":"object","properties":{"optional":{"type":"string"}}}}]});
        assert!(request(input.clone(), Protocol::Responses, Protocol::Chat).is_err());
        input["tools"][0]["strict"] = json!(false);
        let out = request(input.clone(), Protocol::Responses, Protocol::Chat).unwrap();
        assert_eq!(out["tools"][0]["function"]["strict"], false);
        assert_eq!(
            out["tools"][0]["function"]["parameters"],
            input["tools"][0]["parameters"]
        );
    }

    #[test]
    fn parallel_responses_tool_round_remains_a_valid_chat_turn() {
        let input = json!({"model":"x","store":false,"input":[
            {"role":"assistant","content":[{"type":"output_text","text":"checking"}]},
            {"type":"function_call","call_id":"a","name":"read","arguments":"{}"},
            {"type":"function_call","call_id":"b","name":"read","arguments":"{}"},
            {"type":"function_call_output","call_id":"b","output":"B"},
            {"type":"function_call_output","call_id":"a","output":"A"}
        ]});
        let out = request(input, Protocol::Responses, Protocol::Chat).unwrap();
        assert_eq!(out["messages"][0]["content"][0]["text"], "checking");
        assert_eq!(out["messages"][0]["tool_calls"][0]["id"], "a");
        assert_eq!(out["messages"][0]["tool_calls"][1]["id"], "b");
        assert_eq!(out["messages"][1]["tool_call_id"], "b");
        assert_eq!(out["messages"][2]["tool_call_id"], "a");
    }
}
