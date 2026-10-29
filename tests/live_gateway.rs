mod support;

use anyhow::{Context, Result, anyhow};
use serde_json::{Value, json};
use std::{future::Future, path::Path, pin::Pin};

#[derive(serde::Serialize)]
struct CaseReport {
    case: &'static str,
    status: &'static str,
    classification: &'static str,
    request_count: u8,
    evidence: Value,
    description: Option<&'static str>,
}

#[derive(serde::Serialize)]
struct LiveReport<'a> {
    schema: &'static str,
    profile: &'static str,
    model: &'a str,
    cases: Vec<CaseReport>,
}

type CaseFuture<'a> = Pin<Box<dyn Future<Output = Result<Value>> + 'a>>;

#[derive(Debug)]
struct ObservedFailure {
    code: &'static str,
    classification: &'static str,
    evidence: Value,
}

impl std::fmt::Display for ObservedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code)
    }
}

impl std::error::Error for ObservedFailure {}

async fn run_cases<'a>(
    profile: &'static str,
    model: &str,
    cases: Vec<(&'static str, CaseFuture<'a>)>,
) -> Result<()> {
    let selected = std::env::var("INFER_VALIDATION_CASE").ok();
    if let Some(selected) = &selected
        && !cases.iter().any(|(name, _)| *name == selected)
    {
        return Err(anyhow!(
            "INFER_VALIDATION_CASE does not match a case in this profile"
        ));
    }
    let mut report = LiveReport {
        schema: "infer.live-validation.v1",
        profile,
        model,
        cases: Vec::with_capacity(cases.len()),
    };
    let mut failures = Vec::new();
    for (name, case) in cases {
        if selected.as_ref().is_some_and(|selected| selected != name) {
            continue;
        }
        match case.await {
            Ok(evidence) => {
                let request_count = evidence
                    .get("request_count")
                    .and_then(Value::as_u64)
                    .unwrap_or(1) as u8;
                report.cases.push(CaseReport {
                    case: name,
                    status: "passed",
                    classification: "confirmed_behavior",
                    request_count,
                    evidence,
                    description: None,
                });
            }
            Err(error) => {
                let rendered = error.to_string();
                let (request_count, cause) = rendered
                    .strip_prefix("calls:")
                    .and_then(|v| v.split_once(':'))
                    .and_then(|(n, cause)| n.parse::<u8>().ok().map(|n| (n, cause)))
                    .unwrap_or((1, rendered.as_str()));
                let status = cause
                    .strip_prefix("http_status:")
                    .and_then(|s| s.parse::<u16>().ok());
                let observation = error.downcast_ref::<ObservedFailure>();
                let classification = observation
                    .map(|value| value.classification)
                    .unwrap_or_else(|| {
                        if cause.starts_with("model_noncompliance:") {
                            "model_output_noncompliance"
                        } else if matches!(status, Some(401 | 403)) {
                            "authentication_or_entitlement"
                        } else {
                            "unclassified_observation"
                        }
                    });
                let evidence = observation.map(|value| value.evidence.clone()).unwrap_or_else(|| json!({"http_status":status,"failure_code":cause.strip_prefix("model_noncompliance:").unwrap_or("tool_or_transport_observation"),"provider_body_redacted":true}));
                report.cases.push(CaseReport {
                    case: name, status: "failed", classification, request_count, evidence,
                    description: Some("Not automatically a gateway defect. Reports retain structural evidence only; credentials and provider content are excluded."),
                });
                failures.push(name);
            }
        }
    }
    write_report(profile, &report)?;
    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow!(
            "{profile} live validation failures: {}; see INFER_VALIDATION_REPORT_DIR if configured",
            failures.join(", ")
        ))
    }
}

fn write_report(profile: &str, report: &LiveReport<'_>) -> Result<()> {
    let Some(dir) = std::env::var_os("INFER_VALIDATION_REPORT_DIR") else {
        return Ok(());
    };
    std::fs::create_dir_all(&dir).context("create validation report directory")?;
    let bytes = serde_json::to_vec_pretty(report).context("serialize sanitized report")?;
    let suffix = if std::env::var_os("INFER_VALIDATION_CASE").is_some() {
        format!("-{}", report.cases[0].case)
    } else {
        String::new()
    };
    std::fs::write(
        Path::new(&dir).join(format!("{profile}{suffix}-validation.json")),
        bytes,
    )
    .context("write sanitized validation report")
}

fn required(name: &str) -> Result<String> {
    std::env::var(name).map_err(|_| {
        anyhow!("live validation requires {name}; set it before running this ignored test")
    })
}

fn event_kind<'a>(event: &'a support::Event, value: &'a Value) -> &'a str {
    event
        .event
        .as_deref()
        .or_else(|| value.get("type").and_then(Value::as_str))
        .unwrap_or("")
}

fn usage_evidence(response: &[u8]) -> Value {
    let values = match serde_json::from_slice::<Value>(response) {
        Ok(value) => vec![value],
        Err(_) => support::sse_events(response)
            .unwrap_or_default()
            .iter()
            .filter_map(|event| serde_json::from_str::<Value>(&event.data).ok())
            .collect(),
    };
    let mut counts = serde_json::Map::new();
    for value in &values {
        for pointer in ["/usage", "/message/usage", "/response/usage"] {
            if let Some(usage) = value.pointer(pointer) {
                for key in [
                    "prompt_tokens",
                    "completion_tokens",
                    "total_tokens",
                    "input_tokens",
                    "output_tokens",
                ] {
                    if let Some(count) = usage.get(key).and_then(Value::as_u64) {
                        counts.insert(key.to_owned(), json!(count));
                    }
                }
            }
        }
    }
    Value::Object(counts)
}

async fn settled_trace(gateway: &support::Gateway, id: &str) -> Result<Value> {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let trace = gateway.trace(id).await?;
            if trace["complete"] == true || trace["error"].is_string() {
                return Ok(trace);
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .context("trace completion deadline")?
}

fn upstream_media_type(trace: &Value) -> &'static str {
    match trace
        .pointer("/response_headers/upstream/content-type/0")
        .and_then(Value::as_str)
        .map(|value| value.split(';').next().unwrap_or("").trim())
    {
        Some("text/event-stream") => "text/event-stream",
        Some("application/json") => "application/json",
        Some("text/plain") => "text/plain",
        None => "missing",
        _ => "other",
    }
}

async fn observation(
    gateway: &support::Gateway,
    id: &str,
    code: &'static str,
    status: u16,
    bytes: &[u8],
) -> anyhow::Error {
    let trace = settled_trace(gateway, id).await.ok();
    let error = trace
        .as_ref()
        .and_then(|trace| trace["error"].as_str())
        .unwrap_or("");
    let boundary = error.contains("phase") && error.contains("cannot");
    let classification = if boundary {
        "documented_translation_boundary"
    } else if matches!(status, 401 | 403) {
        "authentication_or_entitlement"
    } else {
        "unclassified_observation"
    };
    let events = support::sse_events(bytes).unwrap_or_default();
    let mut kinds = std::collections::BTreeSet::new();
    let mut phases = std::collections::BTreeSet::new();
    for event in &events {
        if let Ok(value) = serde_json::from_str::<Value>(&event.data) {
            let kind = event_kind(event, &value);
            if !kind.is_empty()
                && kind.len() <= 80
                && kind
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || b"._".contains(&byte))
            {
                kinds.insert(kind.to_owned());
            }
            if let Some(output) = value.pointer("/response/output").and_then(Value::as_array) {
                for item in output {
                    if let Some(phase) = item.get("phase").filter(|value| !value.is_null()) {
                        phases.insert(match phase.as_str() {
                            Some("commentary") => "commentary",
                            Some("final_answer") => "final_answer",
                            _ => "non_null",
                        });
                    }
                }
            }
        }
    }
    ObservedFailure {
        code,
        classification,
        evidence: json!({
            "failure_code":code,"http_status":status,"response_bytes":bytes.len(),
            "trace_complete":trace.as_ref().map(|value| value["complete"] == true),
            "trace_error_present":trace.as_ref().map(|value| value["error"].is_string()),
            "documented_phase_boundary":boundary,"event_kinds":kinds,"response_phases":phases,
            "gateway_error_category": if error.contains("requires an SSE") { "non_sse_upstream" }
                else if error.contains("expected value") { "invalid_upstream_json" }
                else if boundary { "phase_boundary" }
                else if error.contains("upstream request failed") { "upstream_transport" }
                else { "other" },
            "upstream_media_type":trace.as_ref().map(upstream_media_type),
            "provider_body_redacted":true
        }),
    }
    .into()
}

async fn receive(
    gateway: &support::Gateway,
    path: &str,
    body: &Value,
) -> Result<(String, Vec<u8>)> {
    let mut response = gateway.post(path, body).await?;
    let status = response.status().as_u16();
    let id = response
        .headers()
        .get("x-infer-trace-id")
        .and_then(|value| value.to_str().ok())
        .context("missing trace id")?
        .to_owned();
    let mut bytes = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => bytes.extend_from_slice(&chunk),
            Ok(None) => break,
            Err(_) => {
                return Err(
                    observation(gateway, &id, "incomplete_response_body", status, &bytes).await,
                );
            }
        }
    }
    if !(200..300).contains(&status) {
        return Err(observation(gateway, &id, "http_rejection", status, &bytes).await);
    }
    Ok((id, bytes))
}

fn protocol_name(path: &str) -> &'static str {
    if path.ends_with("/messages") || path == "/v1/messages" {
        "anthropic_messages"
    } else if path.ends_with("/responses") || path == "/v1/responses" {
        "openai_responses"
    } else {
        "openai_chat"
    }
}

async fn trace_evidence(
    gateway: &support::Gateway,
    profile: &str,
    id: &str,
    path: &str,
    expected_request: &Value,
    expected_response: &[u8],
    streaming: Option<(&[support::Event], bool)>,
) -> Result<Value> {
    let trace = settled_trace(gateway, id).await?;

    if trace.get("complete").and_then(Value::as_bool) != Some(true)
        || !trace.get("error").map(Value::is_null).unwrap_or(false)
    {
        return Err(anyhow!("trace state assertion"));
    }
    let request = gateway.body(id, "request").await?;
    if request != serde_json::to_vec(expected_request)? {
        return Err(anyhow!("request trace byte integrity assertion"));
    }
    let parsed: Value = serde_json::from_slice(&request)?;
    if parsed.get("messages").is_none() && parsed.get("input").is_none() {
        return Err(anyhow!("trace request shape assertion"));
    }
    let recorded_response = gateway.body(id, "response").await?;
    if recorded_response != expected_response {
        return Err(anyhow!("response trace byte integrity assertion"));
    }
    let export = gateway.export().await?;
    if !export.iter().any(|row| row.to_string().contains(id)) {
        return Err(anyhow!("export assertion"));
    }
    let target = if profile == "codex" {
        "openai_responses"
    } else {
        "openai_chat"
    };
    let mut evidence = json!({"http_status":200,"source_format":protocol_name(path),"target_format":target,"usage_counts":usage_evidence(expected_response),"trace_complete":true,"error_free":true,"request_body_bytes":request.len(),"response_body_bytes":recorded_response.len(),"request_response_bytes_exact":true,"export_contains_trace":true});
    evidence["upstream_media_type"] = json!(upstream_media_type(&trace));
    if let Some((events, terminal)) = streaming {
        evidence["sse_event_count"] = json!(events.len());
        evidence["valid_terminal"] = json!(terminal);
    }
    Ok(evidence)
}

async fn checked_json(
    gateway: &support::Gateway,
    profile: &str,
    path: &str,
    body: Value,
) -> Result<Value> {
    let (id, bytes) = receive(gateway, path, &body).await?;
    let value: Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => return Err(observation(gateway, &id, "response_not_json", 200, &bytes).await),
    };
    let (text, terminal) = match protocol_name(path) {
        "anthropic_messages" => (
            value["content"]
                .as_array()
                .map(|parts| {
                    parts
                        .iter()
                        .filter_map(|part| part["text"].as_str())
                        .collect::<String>()
                })
                .unwrap_or_default(),
            value["role"] == "assistant" && value["stop_reason"] == "end_turn",
        ),
        "openai_responses" => (
            value["output"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item["content"].as_array())
                        .flatten()
                        .filter_map(|part| part["text"].as_str())
                        .collect::<String>()
                })
                .unwrap_or_default(),
            value["status"] == "completed" && value.get("error").is_none_or(Value::is_null),
        ),
        _ => (
            value["choices"][0]["message"]["content"]
                .as_str()
                .unwrap_or("")
                .to_owned(),
            value["choices"][0]["message"]["role"] == "assistant"
                && value["choices"][0]["finish_reason"] == "stop",
        ),
    };
    if text.trim().is_empty() || !terminal {
        return Err(observation(gateway, &id, "buffered_semantics_or_terminal", 200, &bytes).await);
    }
    trace_evidence(gateway, profile, &id, path, &body, &bytes, None).await
}

async fn checked_stream(
    gateway: &support::Gateway,
    profile: &str,
    path: &str,
    body: Value,
) -> Result<Value> {
    let (id, bytes) = receive(gateway, path, &body).await?;
    let events = support::sse_events(&bytes)?;
    let mut text = String::new();
    let mut stops = 0;
    let mut terminals = 0;
    for event in &events {
        if event.data == "[DONE]" {
            if protocol_name(path) == "openai_chat" {
                terminals += 1;
            }
            continue;
        }
        let value: Value = serde_json::from_str(&event.data)?;
        match protocol_name(path) {
            "anthropic_messages" => match event_kind(event, &value) {
                "content_block_delta" => {
                    if let Some(fragment) = value["delta"]["text"].as_str() {
                        text.push_str(fragment);
                    }
                }
                "message_delta" if value["delta"]["stop_reason"] == "end_turn" => stops += 1,
                "message_stop" => terminals += 1,
                _ => {}
            },
            "openai_responses" => match event_kind(event, &value) {
                "response.output_text.delta" => {
                    if let Some(fragment) = value["delta"].as_str() {
                        text.push_str(fragment);
                    }
                }
                "response.completed"
                    if value["response"]["status"] == "completed"
                        && value["response"].get("error").is_none_or(Value::is_null) =>
                {
                    stops += 1;
                    terminals += 1;
                }
                _ => {}
            },
            _ => {
                if let Some(fragment) = value["choices"][0]["delta"]["content"].as_str() {
                    text.push_str(fragment);
                }
                if value["choices"][0]["finish_reason"] == "stop" {
                    stops += 1;
                }
            }
        }
    }
    if text.trim().is_empty() || stops != 1 || terminals != 1 {
        return Err(observation(gateway, &id, "stream_semantics_or_terminal", 200, &bytes).await);
    }
    trace_evidence(
        gateway,
        profile,
        &id,
        path,
        &body,
        &bytes,
        Some((&events, true)),
    )
    .await
}

fn request_case<'a>(
    gateway: &'a support::Gateway,
    profile: &'static str,
    path: &'static str,
    body: Value,
    stream: bool,
) -> CaseFuture<'a> {
    Box::pin(async move {
        if stream {
            checked_stream(gateway, profile, path, body).await
        } else {
            checked_json(gateway, profile, path, body).await
        }
    })
}

async fn llama_tool_case(gateway: &support::Gateway) -> Result<Value> {
    let first = json!({
        "model":"validation",
        "messages":[{"role":"user","content":"Use lookup_weather for Paris; make the function call before replying."}],
        "tools":[{"type":"function","function":{"name":"lookup_weather","description":"Look up a location","parameters":{"type":"object","properties":{"location":{"type":"string"}},"required":["location"],"additionalProperties":false}}}],
        "tool_choice":{"type":"function","function":{"name":"lookup_weather"}},
        "max_tokens":96
    });
    let response = gateway
        .post("/v1/chat/completions", &first)
        .await
        .map_err(|_| anyhow!("calls:1:gateway_observation"))?;
    if !response.status().is_success() {
        return Err(anyhow!(
            "calls:1:http_status:{}",
            response.status().as_u16()
        ));
    }
    let id = response
        .headers()
        .get("x-infer-trace-id")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| anyhow!("calls:1:gateway_observation"))?
        .to_owned();
    let bytes = response
        .bytes()
        .await
        .map_err(|_| anyhow!("calls:1:gateway_observation"))?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow!("calls:1:model_noncompliance:invalid_json"))?;
    let message = value
        .pointer("/choices/0/message")
        .ok_or_else(|| anyhow!("calls:1:model_noncompliance:no_assistant_message"))?;
    if message
        .pointer("/tool_calls/0/function/name")
        .and_then(Value::as_str)
        != Some("lookup_weather")
        || message
            .pointer("/tool_calls")
            .and_then(Value::as_array)
            .map(Vec::len)
            != Some(1)
        || value
            .pointer("/choices/0/finish_reason")
            .and_then(Value::as_str)
            != Some("tool_calls")
    {
        return Err(anyhow!(
            "calls:1:model_noncompliance:missing_named_tool_or_tool_terminal"
        ));
    }
    let call = &message["tool_calls"][0];
    let call_id = call
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("calls:1:model_noncompliance:missing_tool_id"))?;
    let arguments = call
        .pointer("/function/arguments")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("calls:1:model_noncompliance:invalid_arguments_type"))?;
    let args: Value = serde_json::from_str(arguments)
        .map_err(|_| anyhow!("calls:1:model_noncompliance:invalid_arguments_json"))?;
    if args.get("location").and_then(Value::as_str) != Some("Paris") {
        return Err(anyhow!(
            "calls:1:model_noncompliance:invalid_location_argument"
        ));
    }
    let first_trace = trace_evidence(
        gateway,
        "llama",
        &id,
        "/v1/chat/completions",
        &first,
        &bytes,
        None,
    )
    .await
    .map_err(|_| anyhow!("calls:1:gateway_trace_observation"))?;

    let tool_result = json!({"lookup_received":args});
    let followup = json!({
        "model":"validation",
        "messages":[
            {"role":"user","content":"Use lookup_weather for Paris; make the function call before replying."},
            {"role":"assistant","content":null,"tool_calls":[{"id":call_id,"type":"function","function":{"name":"lookup_weather","arguments":arguments}}]},
            {"role":"tool","tool_call_id":call_id,"name":"lookup_weather","content":tool_result.to_string()},
            {"role":"user","content":"State the location returned by the lookup in one short sentence."}
        ],
        "max_tokens":24
    });
    let response = gateway
        .post("/v1/chat/completions", &followup)
        .await
        .map_err(|_| anyhow!("calls:2:gateway_observation"))?;
    if !response.status().is_success() {
        return Err(anyhow!(
            "calls:2:http_status:{}",
            response.status().as_u16()
        ));
    }
    let id = response
        .headers()
        .get("x-infer-trace-id")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| anyhow!("calls:2:gateway_observation"))?
        .to_owned();
    let bytes = response
        .bytes()
        .await
        .map_err(|_| anyhow!("calls:2:gateway_observation"))?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow!("calls:2:model_noncompliance:invalid_followup_json"))?;
    let content = value
        .pointer("/choices/0/message/content")
        .and_then(Value::as_str)
        .unwrap_or("");
    if content.trim().is_empty()
        || !content.to_lowercase().contains("paris")
        || value
            .pointer("/choices/0/finish_reason")
            .and_then(Value::as_str)
            != Some("stop")
    {
        return Err(anyhow!(
            "calls:2:model_noncompliance:followup_not_ordinary_completion"
        ));
    }
    let second_trace = trace_evidence(
        gateway,
        "llama",
        &id,
        "/v1/chat/completions",
        &followup,
        &bytes,
        None,
    )
    .await
    .map_err(|_| anyhow!("calls:2:gateway_trace_observation"))?;
    Ok(
        json!({"request_count":2,"tool_call_id_present":true,"tool_name":"lookup_weather","arguments_valid_for_schema":true,"terminal_reason":"tool_calls","followup_terminal_reason":"stop","followup_text_nonempty":true,"first_trace":first_trace,"followup_trace":second_trace}),
    )
}

fn find_function_call(value: &Value) -> Option<&Value> {
    if value.get("type").and_then(Value::as_str) == Some("function_call") {
        return Some(value);
    }
    match value {
        Value::Array(values) => values.iter().find_map(find_function_call),
        Value::Object(values) => values.values().find_map(find_function_call),
        _ => None,
    }
}

async fn codex_tool_case(gateway: &support::Gateway, model: &str) -> Result<Value> {
    let body = json!({
        "model":model,
        "input":[{"role":"user","content":[{"type":"input_text","text":"Use lookup_weather for Paris; make the function call before replying."}]}],
        "stream":true,
        "store":false,
        "reasoning":{"effort":"low"},
        "instructions":"",
        "tools":[{"type":"function","name":"lookup_weather","description":"Look up a location","parameters":{"type":"object","properties":{"location":{"type":"string"}},"required":["location"],"additionalProperties":false},"strict":true}],
        "tool_choice":{"type":"function","name":"lookup_weather"}
    });
    let response = gateway.post("/providers/backend/responses", &body).await?;
    if !response.status().is_success() {
        return Err(anyhow!("http_status:{}", response.status().as_u16()));
    }
    let id = response
        .headers()
        .get("x-infer-trace-id")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| anyhow!("gateway_observation"))?
        .to_owned();
    let bytes = response.bytes().await?;
    let events = support::sse_events(&bytes)?;
    let terminal = events
        .iter()
        .any(|event| event.event.as_deref() == Some("response.completed"));
    let call = events
        .iter()
        .rev()
        .filter_map(|event| serde_json::from_str::<Value>(&event.data).ok())
        .find_map(|value| find_function_call(&value).cloned());
    let call = call.ok_or_else(|| anyhow!("model_noncompliance:no_function_call"))?;
    call.get("call_id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("model_noncompliance:missing_call_id"))?;
    let name = call.get("name").and_then(Value::as_str).unwrap_or("");
    let args_text = call.get("arguments").and_then(Value::as_str).unwrap_or("");
    let args: Value = serde_json::from_str(args_text)
        .map_err(|_| anyhow!("model_noncompliance:invalid_arguments_json"))?;
    if !terminal
        || name != "lookup_weather"
        || args.get("location").and_then(Value::as_str) != Some("Paris")
    {
        return Err(anyhow!("model_noncompliance:tool_semantics_or_terminal"));
    }
    let trace = trace_evidence(
        gateway,
        "codex",
        &id,
        "/providers/backend/responses",
        &body,
        &bytes,
        Some((&events, terminal)),
    )
    .await?;
    Ok(
        json!({"request_count":1,"tool_call_id_present":true,"tool_name":name,"arguments_valid_for_schema":true,"terminal_event":"response.completed","trace":trace}),
    )
}

#[tokio::test]
#[ignore = "explicit live gateway validation; may make billable requests"]
async fn live_llama_validation() -> Result<()> {
    let upstream = required("INFER_LIVE_LLAMA_URL")?;
    let model = required("INFER_LIVE_LLAMA_MODEL")?;
    let gateway = support::Gateway::start("llama", &upstream, &model, None).await?;
    let prompt = "Reply with OK only";
    let chat = |alias: &str, stream| json!({"model":alias,"messages":[{"role":"user","content":prompt}],"stream":stream,"max_tokens":24});
    let anthropic = |stream| json!({"model":"validation","messages":[{"role":"user","content":prompt}],"max_tokens":24,"stream":stream});
    let tool_case: CaseFuture<'_> = Box::pin(llama_tool_case(&gateway));
    let cases = vec![
        (
            "native_chat_buffered",
            request_case(
                &gateway,
                "llama",
                "/providers/backend/v1/chat/completions",
                chat(&model, false),
                false,
            ),
        ),
        (
            "native_chat_stream",
            request_case(
                &gateway,
                "llama",
                "/providers/backend/v1/chat/completions",
                chat(&model, true),
                true,
            ),
        ),
        (
            "routed_chat_buffered",
            request_case(
                &gateway,
                "llama",
                "/v1/chat/completions",
                chat("validation", false),
                false,
            ),
        ),
        (
            "routed_chat_stream",
            request_case(
                &gateway,
                "llama",
                "/v1/chat/completions",
                chat("validation", true),
                true,
            ),
        ),
        (
            "anthropic_buffered",
            request_case(&gateway, "llama", "/v1/messages", anthropic(false), false),
        ),
        (
            "anthropic_stream",
            request_case(&gateway, "llama", "/v1/messages", anthropic(true), true),
        ),
        ("forced_tool_and_followup_history", tool_case),
    ];
    run_cases("llama", &model, cases).await
}

#[tokio::test]
#[ignore = "explicit live gateway validation; may make billable requests"]
async fn live_codex_validation() -> Result<()> {
    let auth_path = required("INFER_LIVE_CODEX_AUTH_FILE")?;
    let auth_file = Path::new(&auth_path);
    if !auth_file.is_file() {
        return Err(anyhow!(
            "INFER_LIVE_CODEX_AUTH_FILE must name an existing regular credential file"
        ));
    }
    let model = required("INFER_LIVE_CODEX_MODEL")?;
    let upstream = std::env::var("INFER_LIVE_CODEX_BASE_URL")
        .unwrap_or_else(|_| "https://chatgpt.com/backend-api/codex".to_owned());
    let upstream = upstream
        .trim_end_matches('/')
        .trim_end_matches("/backend-api/codex");
    let gateway = support::Gateway::start("codex", upstream, &model, Some(auth_file)).await?;
    let prompt = "Reply with OK only";
    let responses = |alias: &str, stream: bool, native: bool| {
        let mut body = json!({"model":alias,"input":[{"role":"user","content":[{"type":"input_text","text":prompt}]}],"instructions":"","stream":stream,"store":false,"reasoning":{"effort":"low"}});
        if !native {
            body["max_output_tokens"] = json!(48);
        }
        body
    };
    let chat = |stream| json!({"model":"validation","messages":[{"role":"user","content":prompt}],"stream":stream,"max_completion_tokens":48});
    let anthropic = |stream| json!({"model":"validation","messages":[{"role":"user","content":prompt}],"stream":stream,"max_tokens":48});
    let tool_case: CaseFuture<'_> = Box::pin(codex_tool_case(&gateway, &model));
    let cases = vec![
        (
            "native_responses_sse",
            request_case(
                &gateway,
                "codex",
                "/providers/backend/responses",
                responses(&model, true, true),
                true,
            ),
        ),
        (
            "routed_chat_buffered",
            request_case(
                &gateway,
                "codex",
                "/v1/chat/completions",
                chat(false),
                false,
            ),
        ),
        (
            "routed_chat_stream",
            request_case(&gateway, "codex", "/v1/chat/completions", chat(true), true),
        ),
        (
            "anthropic_buffered",
            request_case(&gateway, "codex", "/v1/messages", anthropic(false), false),
        ),
        (
            "anthropic_stream",
            request_case(&gateway, "codex", "/v1/messages", anthropic(true), true),
        ),
        (
            "responses_buffered_reconstruction",
            request_case(
                &gateway,
                "codex",
                "/v1/responses",
                responses("validation", false, false),
                false,
            ),
        ),
        (
            "responses_routed_sse",
            request_case(
                &gateway,
                "codex",
                "/v1/responses",
                responses("validation", true, false),
                true,
            ),
        ),
        ("native_forced_function_tool", tool_case),
    ];
    run_cases("codex", &model, cases).await
}
