#[allow(dead_code)]
mod support;

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result, bail};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::StatusCode,
    response::Response,
};
use infer::traffic::codex::{self, CODEX};
use infer::traffic::grok_build::{self, GROK_BUILD};
use infer::traffic::{self, ActualRequest, Harness, assert_clean};
use serde_json::{Map, Value, json};
use support::Gateway;
use tokio::sync::Mutex as AsyncMutex;

const CODEX_ORIGINATED_USER_AGENT: &str =
    "codex_exec/0.169.0 (Linux Unknown; x86_64) unknown (codex_exec; 0.169.0)";
const GROK_ORIGINATED_USER_AGENT: &str = "grok-shell/1.0.77 (linux; x86_64)";
const RECORDED_GROK_TRACE_ID: &str = "ec2dbe8943832cb3ce012bca4a4988f3";

struct Reply {
    status: u16,
    headers: Map<String, Value>,
    body: Vec<u8>,
}

struct MockState {
    replies: AsyncMutex<VecDeque<Reply>>,
    captured: Mutex<Vec<ActualRequest>>,
}

struct Mock {
    base: String,
    state: Arc<MockState>,
    task: tokio::task::JoinHandle<()>,
}

impl Mock {
    async fn start(replies: Vec<Reply>) -> Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let base = format!("http://{}", listener.local_addr()?);
        let state = Arc::new(MockState {
            replies: AsyncMutex::new(replies.into()),
            captured: Mutex::new(Vec::new()),
        });
        let app = Router::new()
            .fallback(received)
            .with_state(Arc::clone(&state));
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(Self { base, state, task })
    }

    fn captured(&self) -> Vec<ActualRequest> {
        self.state
            .captured
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn received(State(state): State<Arc<MockState>>, request: Request) -> Response {
    let method = request.method().as_str().to_owned();
    let path = request.uri().path().to_owned();
    let query = request.uri().query().unwrap_or("").to_owned();
    let mut headers = Map::new();
    for (name, value) in request.headers() {
        let text = value.to_str().unwrap_or("<non-utf8>");
        headers.insert(name.as_str().to_ascii_lowercase(), json!(text));
    }
    let body = to_bytes(request.into_body(), 32 * 1024 * 1024)
        .await
        .unwrap_or_default()
        .to_vec();
    state
        .captured
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .push(ActualRequest {
            method,
            path,
            query,
            headers,
            body,
        });
    let Some(reply) = state.replies.lock().await.pop_front() else {
        return Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from("no replay left"))
            .unwrap_or_default();
    };
    let mut response = Response::new(Body::from(reply.body));
    *response.status_mut() = StatusCode::from_u16(reply.status).unwrap_or(StatusCode::BAD_GATEWAY);
    for (name, value) in reply.headers {
        let Some(text) = value.as_str() else {
            continue;
        };
        if let (Ok(name), Ok(value)) = (
            axum::http::HeaderName::try_from(name),
            axum::http::HeaderValue::try_from(text),
        ) {
            response.headers_mut().insert(name, value);
        }
    }
    response
}

#[tokio::test]
async fn codex_upstream_matches_the_cli_fixture() -> Result<()> {
    assert_clean(&codex::fixture_dir())?;
    let fixtures = traffic::fixtures_in(&codex::fixture_dir())?;
    assert!(
        fixtures.len() >= 2,
        "Codex needs a non-streaming turn and a streaming turn"
    );
    for (path, fixture) in fixtures {
        if fixture.harness != CODEX.id() {
            bail!("{} is not a Codex fixture", path.display());
        }
        if fixture.provenance == traffic::Provenance::SourceDerived {
            assert!(
                fixture
                    .source
                    .note
                    .to_ascii_lowercase()
                    .contains("not a packet capture")
                    || fixture
                        .source
                        .note
                        .to_ascii_lowercase()
                        .contains("source-derived"),
                "{} must say it is source-derived",
                path.display()
            );
        }
        let replies = fixture
            .exchanges
            .iter()
            .filter(|exchange| exchange.compare)
            .map(|exchange| {
                Ok(Reply {
                    status: exchange.response.status,
                    headers: exchange.response.headers.clone(),
                    body: exchange.response.bytes()?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let expected: Vec<_> = fixture
            .exchanges
            .iter()
            .filter(|exchange| exchange.compare)
            .map(|exchange| &exchange.request)
            .collect();
        let mock = Mock::start(replies).await?;
        let auth_root = tempfile::tempdir()?;
        let auth = auth_root.path().join("auth.json");
        std::fs::write(
            &auth,
            serde_json::to_vec(&json!({
                "tokens": {"access_token": "opaque-ready-token", "account_id": "account-test"}
            }))?,
        )?;
        let gateway = Gateway::start("codex", &mock.base, "gpt-5.5", Some(&auth)).await?;
        let mut request = gateway
            .client
            .post(format!("{}{}", gateway.base, fixture.client.path));
        request = request.header("x-infer-key", &gateway.proxy_token);
        for (name, value) in &fixture.client.headers {
            let Some(text) = value.as_str() else {
                bail!("{} client header {name} is not a string", fixture.scenario);
            };
            request = request.header(name, text);
        }
        let response = send_fixture(&gateway.client, request.json(&fixture.client.body))
            .await
            .with_context(|| format!("send {}", fixture.scenario))?;
        let status = response.status();
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let bytes = response.bytes().await.context("read gateway response")?;
        let text = String::from_utf8_lossy(&bytes);
        if !status.is_success() {
            bail!("{} gateway returned {status}: {text}", fixture.scenario);
        }
        let streamed = fixture.client.body.get("stream") == Some(&json!(true));
        if streamed {
            if !content_type
                .to_ascii_lowercase()
                .contains("text/event-stream")
            {
                bail!(
                    "{} streamed response content-type is {content_type}",
                    fixture.scenario
                );
            }
        } else if !content_type
            .to_ascii_lowercase()
            .contains("application/json")
        {
            bail!(
                "{} buffered response content-type is {content_type}",
                fixture.scenario
            );
        }
        // The client observes the replayed completion, whatever the prompt was.
        // Take the final output_text from the compared exchange's
        // response.output_text.done, or from response.completed when that
        // event is the one that carries it.
        let expected_text = replayed_output_text(&fixture).with_context(|| {
            format!(
                "{} compared exchange has no output_text to observe",
                fixture.scenario
            )
        })?;
        if !text.contains(&expected_text) {
            bail!(
                "{} client response did not contain the replayed text {expected_text:?}: {text}",
                fixture.scenario
            );
        }
        let actual = mock.captured();
        if actual.len() != expected.len() {
            let paths: Vec<_> = actual.iter().map(|call| call.path.clone()).collect();
            bail!(
                "{} made {} upstream call(s) {paths:?}, fixture expects {}",
                fixture.scenario,
                actual.len(),
                expected.len()
            );
        }
        for (index, (expected, actual)) in expected.iter().zip(actual.iter()).enumerate() {
            traffic::align(&CODEX, expected, actual).with_context(|| {
                format!(
                    "{} exchange {index} drifted from the Codex fixture",
                    fixture.scenario
                )
            })?;
            assert_eq!(
                actual.headers.get("user-agent").and_then(Value::as_str),
                Some(CODEX_ORIGINATED_USER_AGENT),
                "{} exchange {index} user-agent",
                fixture.scenario
            );
            let traceparent = actual
                .headers
                .get("traceparent")
                .and_then(Value::as_str)
                .with_context(|| format!("{} exchange {index} traceparent", fixture.scenario))?;
            assert_fresh_traceparent(traceparent)
                .with_context(|| format!("{} exchange {index} traceparent", fixture.scenario))?;
            assert!(
                actual.headers.get("x-codex-beta-features").is_none(),
                "{} exchange {index} invented x-codex-beta-features",
                fixture.scenario
            );
        }
        let _ = gateway;
    }
    Ok(())
}

/// Final assistant text a client can read from the compared replay.
///
/// Streaming captures carry it on `response.output_text.done`. A completed
/// JSON response, or an SSE stream whose done event omitted `text`, carries
/// the same string on the last `output_text` part of `response.completed`.
fn replayed_output_text(fixture: &traffic::Fixture) -> Result<String> {
    let mut text = None;
    for exchange in fixture.exchanges.iter().filter(|exchange| exchange.compare) {
        let bytes = exchange.response.bytes()?;
        if let Some(found) = output_text_from_replay(&bytes)
            && !found.is_empty()
        {
            text = Some(found);
        }
    }
    text.with_context(|| format!("{} replay has no output_text", fixture.scenario))
}

fn output_text_from_replay(bytes: &[u8]) -> Option<String> {
    if let Ok(events) = support::sse_events(bytes) {
        let mut done = None;
        let mut completed = None;
        for event in events {
            let Ok(value) = serde_json::from_str::<Value>(&event.data) else {
                continue;
            };
            let kind = event
                .event
                .as_deref()
                .or_else(|| value.get("type").and_then(Value::as_str))
                .unwrap_or("");
            if kind == "response.output_text.done" {
                if let Some(text) = value.get("text").and_then(Value::as_str) {
                    done = Some(text.to_owned());
                }
            } else if kind == "response.completed" {
                completed = message_output_text(value.get("response").unwrap_or(&value));
            }
        }
        if done.is_some() || completed.is_some() {
            return done.or(completed);
        }
    }
    serde_json::from_slice::<Value>(bytes)
        .ok()
        .as_ref()
        .and_then(message_output_text)
}

fn message_output_text(value: &Value) -> Option<String> {
    let mut last = None;
    let output = value.get("output")?.as_array()?;
    for item in output {
        let Some(parts) = item.get("content").and_then(Value::as_array) else {
            continue;
        };
        for part in parts {
            if part.get("type").and_then(Value::as_str) == Some("output_text")
                && let Some(text) = part.get("text").and_then(Value::as_str)
            {
                last = Some(text.to_owned());
            }
        }
    }
    last
}

#[tokio::test]
async fn grok_provider_forwards_a_chat_completion() -> Result<()> {
    let body = json!({
        "model": "grok-4",
        "messages": [{"role": "user", "content": "Hello"}]
    });
    let reply = json!({
        "id": "chatcmpl-fixture",
        "choices": [{"message": {"role": "assistant", "content": "Hi"}}]
    });
    let mock = Mock::start(vec![Reply {
        status: 200,
        headers: json!({"content-type": "application/json"})
            .as_object()
            .cloned()
            .context("content-type header")?,
        body: serde_json::to_vec(&reply)?,
    }])
    .await?;
    let gateway = Gateway::start("grok", &mock.base, "grok-4", None).await?;
    let response = gateway
        .client
        .post(format!("{}/v1/chat/completions", gateway.base))
        .header("x-infer-key", &gateway.proxy_token)
        .json(&body)
        .send()
        .await
        .context("send grok chat completion")?;
    let status = response.status();
    let text = response
        .text()
        .await
        .context("read grok gateway response")?;
    if !status.is_success() {
        bail!("grok gateway returned {status}: {text}");
    }
    if !text.contains("Hi") {
        bail!("grok gateway response did not contain the mock text: {text}");
    }
    let actual = mock.captured();
    if actual.len() != 1 {
        let paths: Vec<_> = actual.iter().map(|call| call.path.clone()).collect();
        bail!(
            "grok provider made {} upstream call(s) {paths:?}",
            actual.len()
        );
    }
    if actual[0].method != "POST" || actual[0].path != "/v1/chat/completions" {
        bail!("grok provider sent {} {}", actual[0].method, actual[0].path);
    }
    let sent: Value = serde_json::from_slice(&actual[0].body).context("upstream body")?;
    if sent["model"] != "grok-4" || sent["messages"][0]["content"] != "Hello" {
        bail!("grok provider rewrote the chat body: {sent}");
    }
    let user_agent = actual[0]
        .headers
        .get("user-agent")
        .and_then(Value::as_str)
        .unwrap_or("");
    if user_agent == GROK_ORIGINATED_USER_AGENT || user_agent.contains("macos") {
        bail!("plain grok chat originated a grok-build user-agent: {user_agent}");
    }
    let traceparent = actual[0]
        .headers
        .get("traceparent")
        .and_then(Value::as_str)
        .context("plain grok chat traceparent")?;
    assert_fresh_traceparent(traceparent)?;
    let _ = gateway;
    Ok(())
}

#[tokio::test]
async fn grok_build_upstream_matches_the_cli_fixture() -> Result<()> {
    let dir = grok_build::fixture_dir();
    if !dir.is_dir() {
        bail!("grok-build fixtures directory {} is missing", dir.display());
    }
    let fixtures = traffic::fixtures_in(&dir)?;
    if fixtures.is_empty() {
        bail!(
            "grok-build fixtures directory {} has no JSON fixtures. The recorded chat-turn must be replayed, not skipped.",
            dir.display()
        );
    }
    if !fixtures
        .iter()
        .any(|(_, fixture)| fixture.provenance == traffic::Provenance::Recorded)
    {
        bail!("grok-build replay needs a recorded fixture");
    }
    assert_clean(&dir)?;
    for (path, fixture) in fixtures {
        if fixture.harness != GROK_BUILD.id() {
            bail!("{} is not a grok-build fixture", path.display());
        }
        if fixture.provenance == traffic::Provenance::SourceDerived {
            let note = fixture.source.note.to_ascii_lowercase();
            if !note.contains("not a packet capture") && !note.contains("source-derived") {
                bail!("{} must say it is source-derived", path.display());
            }
        }
        let replies = fixture
            .exchanges
            .iter()
            .filter(|exchange| exchange.compare)
            .map(|exchange| {
                Ok(Reply {
                    status: exchange.response.status,
                    headers: exchange.response.headers.clone(),
                    body: exchange.response.bytes()?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let expected: Vec<_> = fixture
            .exchanges
            .iter()
            .filter(|exchange| exchange.compare)
            .map(|exchange| &exchange.request)
            .collect();
        let mock = Mock::start(replies).await?;
        let gateway = Gateway::start("grok", &mock.base, "grok-4", None).await?;
        let mut request = gateway
            .client
            .post(format!("{}{}", gateway.base, fixture.client.path));
        request = request.header("x-infer-key", &gateway.proxy_token);
        for (name, value) in &fixture.client.headers {
            let Some(text) = value.as_str() else {
                bail!("{} client header {name} is not a string", fixture.scenario);
            };
            request = request.header(name, text);
        }
        let response = send_fixture(&gateway.client, request.json(&fixture.client.body))
            .await
            .with_context(|| format!("send {}", fixture.scenario))?;
        let status = response.status();
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let bytes = response.bytes().await.context("read gateway response")?;
        let text = String::from_utf8_lossy(&bytes);
        if !status.is_success() {
            bail!("{} gateway returned {status}: {text}", fixture.scenario);
        }
        let streamed = fixture.client.body.get("stream") == Some(&json!(true));
        if streamed {
            if !content_type
                .to_ascii_lowercase()
                .contains("text/event-stream")
            {
                bail!(
                    "{} streamed response content-type is {content_type}",
                    fixture.scenario
                );
            }
        } else if !content_type
            .to_ascii_lowercase()
            .contains("application/json")
        {
            bail!(
                "{} buffered response content-type is {content_type}",
                fixture.scenario
            );
        }
        let expected_text = replayed_output_text(&fixture)
            .ok()
            .or_else(|| chat_visible_text(&fixture).ok().flatten());
        let Some(expected_text) = expected_text.filter(|text| !text.is_empty()) else {
            bail!(
                "{} compared exchange has no output_text or chat message to observe",
                fixture.scenario
            );
        };
        if !text.contains(&expected_text) {
            bail!(
                "{} client response did not contain the replayed text {expected_text:?}: {text}",
                fixture.scenario
            );
        }
        let actual = mock.captured();
        if actual.len() != expected.len() {
            let paths: Vec<_> = actual.iter().map(|call| call.path.clone()).collect();
            bail!(
                "{} made {} upstream call(s) {paths:?}, fixture expects {}",
                fixture.scenario,
                actual.len(),
                expected.len()
            );
        }
        for (index, (expected, actual)) in expected.iter().zip(actual.iter()).enumerate() {
            traffic::align(&GROK_BUILD, expected, actual).with_context(|| {
                format!(
                    "{} exchange {index} drifted from the grok-build fixture",
                    fixture.scenario
                )
            })?;
            assert_eq!(
                actual.headers.get("user-agent").and_then(Value::as_str),
                Some(GROK_ORIGINATED_USER_AGENT),
                "{} exchange {index} user-agent",
                fixture.scenario
            );
            let traceparent = actual
                .headers
                .get("traceparent")
                .and_then(Value::as_str)
                .with_context(|| format!("{} exchange {index} traceparent", fixture.scenario))?;
            assert_fresh_traceparent(traceparent)
                .with_context(|| format!("{} exchange {index} traceparent", fixture.scenario))?;
            assert!(
                actual.headers.get("x-compaction-at").is_none(),
                "{} exchange {index} invented x-compaction-at",
                fixture.scenario
            );
            assert!(
                actual.headers.get("x-compactions-remaining").is_none(),
                "{} exchange {index} invented x-compactions-remaining",
                fixture.scenario
            );
        }
        let _ = gateway;
    }
    Ok(())
}

fn chat_visible_text(fixture: &traffic::Fixture) -> Result<Option<String>> {
    let mut text = None;
    for exchange in fixture.exchanges.iter().filter(|exchange| exchange.compare) {
        let bytes = exchange.response.bytes()?;
        if let Some(found) = chat_text_from_replay(&bytes)
            && !found.is_empty()
        {
            text = Some(found);
        }
    }
    Ok(text)
}

fn chat_text_from_replay(bytes: &[u8]) -> Option<String> {
    if let Ok(events) = support::sse_events(bytes) {
        let mut deltas = String::new();
        let mut message = None;
        for event in events {
            let Ok(value) = serde_json::from_str::<Value>(&event.data) else {
                continue;
            };
            if let Some(text) = chat_choice_text(&value, "message") {
                message = Some(text);
            }
            if let Some(text) = chat_choice_text(&value, "delta") {
                deltas.push_str(&text);
            }
        }
        if let Some(text) = message.filter(|text| !text.is_empty()) {
            return Some(text);
        }
        if !deltas.is_empty() {
            return Some(deltas);
        }
    }
    serde_json::from_slice::<Value>(bytes)
        .ok()
        .as_ref()
        .and_then(|value| chat_choice_text(value, "message"))
}

fn chat_choice_text(value: &Value, key: &str) -> Option<String> {
    let choices = value.get("choices")?.as_array()?;
    let mut last = None;
    for choice in choices {
        let Some(text) = choice
            .get(key)
            .and_then(|item| item.get("content"))
            .and_then(Value::as_str)
        else {
            continue;
        };
        last = Some(text.to_owned());
    }
    last
}

/// The test client is reqwest, which supplies its own User-Agent. Fixture
/// clients omit that header, so drop the library default before sending.
async fn send_fixture(
    client: &reqwest::Client,
    builder: reqwest::RequestBuilder,
) -> Result<reqwest::Response> {
    let mut request = builder.build().context("build request")?;
    request.headers_mut().remove(reqwest::header::USER_AGENT);
    client.execute(request).await.context("send request")
}

fn assert_fresh_traceparent(value: &str) -> Result<()> {
    let mut parts = value.split('-');
    let version = parts.next();
    let trace = parts.next().unwrap_or("");
    let parent = parts.next().unwrap_or("");
    let flags = parts.next();
    if version != Some("00")
        || flags != Some("01")
        || parts.next().is_some()
        || trace.len() != 32
        || parent.len() != 16
        || !trace.chars().all(|ch| ch.is_ascii_hexdigit())
        || !parent.chars().all(|ch| ch.is_ascii_hexdigit())
        || trace.chars().all(|ch| ch == '0')
        || parent.chars().all(|ch| ch == '0')
    {
        bail!("traceparent {value} is not a sampled W3C id");
    }
    if trace == RECORDED_GROK_TRACE_ID
        || parent == "13d799ca13cbe621"
        || parent == "dea86bc10009a204"
    {
        bail!("traceparent {value} reuses a fixture id");
    }
    Ok(())
}

fn completed_sse() -> Vec<u8> {
    concat!(
        "event: response.completed\n",
        "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"r\",\"status\":\"completed\",\"output\":[{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"pong\"}]}],\"usage\":{}}}\n\n"
    )
    .into()
}

async fn sse_reply() -> Result<Reply> {
    Ok(Reply {
        status: 200,
        headers: json!({"content-type": "text/event-stream"})
            .as_object()
            .cloned()
            .context("sse content-type")?,
        body: completed_sse(),
    })
}

async fn post_json(
    client: &reqwest::Client,
    url: &str,
    proxy_token: &str,
    body: &Value,
    headers: &[(&str, &str)],
    omit_user_agent: bool,
) -> Result<()> {
    let mut request = client.post(url).header("x-infer-key", proxy_token);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let mut built = request.json(body).build().context("build request")?;
    if omit_user_agent {
        built.headers_mut().remove(reqwest::header::USER_AGENT);
    }
    let response = client.execute(built).await.context("send request")?;
    let status = response.status();
    let text = response.text().await.context("read response")?;
    if !status.is_success() {
        bail!("gateway returned {status}: {text}");
    }
    Ok(())
}

#[tokio::test]
async fn caller_markers_are_forwarded_and_omitted_ones_stay_absent() -> Result<()> {
    let mock = Mock::start(vec![
        sse_reply().await?,
        sse_reply().await?,
        sse_reply().await?,
    ])
    .await?;
    let auth_root = tempfile::tempdir()?;
    let auth = auth_root.path().join("auth.json");
    std::fs::write(
        &auth,
        serde_json::to_vec(&json!({
            "tokens": {"access_token": "opaque-ready-token", "account_id": "account-test"}
        }))?,
    )?;
    let gateway = Gateway::start("codex", &mock.base, "gpt-5.5", Some(&auth)).await?;
    let codex_url = format!("{}/v1/responses", gateway.base);
    let plain = json!({"model": "gpt-5.5", "input": "ping"});
    post_json(
        &gateway.client,
        &codex_url,
        &gateway.proxy_token,
        &plain,
        &[],
        true,
    )
    .await?;
    post_json(
        &gateway.client,
        &codex_url,
        &gateway.proxy_token,
        &plain,
        &[],
        true,
    )
    .await?;
    post_json(
        &gateway.client,
        &codex_url,
        &gateway.proxy_token,
        &json!({
            "model": "gpt-5.5",
            "input": "ping",
            "client_metadata": {"keep": "yes"}
        }),
        &[
            ("user-agent", "Caller/1.2 (Test)"),
            (
                "traceparent",
                "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-00",
            ),
            ("x-codex-beta-features", "remote_compaction_v2"),
        ],
        false,
    )
    .await?;
    let actual = mock.captured();
    if actual.len() != 3 {
        bail!("codex marker probe made {} upstream call(s)", actual.len());
    }
    let mut generated = Vec::new();
    for call in &actual[..2] {
        assert_eq!(
            call.headers.get("user-agent").and_then(Value::as_str),
            Some(CODEX_ORIGINATED_USER_AGENT)
        );
        let traceparent = call
            .headers
            .get("traceparent")
            .and_then(Value::as_str)
            .context("generated traceparent")?;
        assert_fresh_traceparent(traceparent)?;
        generated.push(traceparent.to_owned());
        if call.headers.get("x-codex-beta-features").is_some() {
            bail!("omitted x-codex-beta-features was invented");
        }
        let body: Value = serde_json::from_slice(&call.body).context("codex body")?;
        if body.get("client_metadata").is_some() {
            bail!("omitted client_metadata was invented: {body}");
        }
    }
    if generated[0] == generated[1] {
        bail!("two requests reused traceparent {}", generated[0]);
    }
    let forwarded = &actual[2];
    assert_eq!(
        forwarded.headers.get("user-agent").and_then(Value::as_str),
        Some("Caller/1.2 (Test)")
    );
    assert_eq!(
        forwarded.headers.get("traceparent").and_then(Value::as_str),
        Some("00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-00")
    );
    assert_eq!(
        forwarded
            .headers
            .get("x-codex-beta-features")
            .and_then(Value::as_str),
        Some("remote_compaction_v2")
    );
    let body: Value = serde_json::from_slice(&forwarded.body).context("forwarded body")?;
    if body["client_metadata"]["keep"] != "yes" {
        bail!("caller client_metadata was dropped: {body}");
    }
    let _ = gateway;

    let grok_mock = Mock::start(vec![sse_reply().await?, sse_reply().await?]).await?;
    let grok = Gateway::start("grok", &grok_mock.base, "grok-4", None).await?;
    let grok_url = format!("{}/v1/responses", grok.base);
    let grok_body = json!({"model": "grok-4", "input": "ping", "stream": true});
    post_json(
        &grok.client,
        &grok_url,
        &grok.proxy_token,
        &grok_body,
        &[
            ("x-grok-client-identifier", "grok-shell"),
            ("accept", "text/event-stream"),
        ],
        true,
    )
    .await?;
    post_json(
        &grok.client,
        &grok_url,
        &grok.proxy_token,
        &grok_body,
        &[
            ("x-grok-client-identifier", "grok-shell"),
            ("accept", "text/event-stream"),
            ("user-agent", "Caller/1.2 (Test)"),
            (
                "traceparent",
                "00-cccccccccccccccccccccccccccccccc-dddddddddddddddd-01",
            ),
            ("x-compaction-at", "204800"),
            ("x-compactions-remaining", "1"),
        ],
        false,
    )
    .await?;
    let grok_actual = grok_mock.captured();
    if grok_actual.len() != 2 {
        bail!(
            "grok marker probe made {} upstream call(s)",
            grok_actual.len()
        );
    }
    assert_eq!(
        grok_actual[0]
            .headers
            .get("user-agent")
            .and_then(Value::as_str),
        Some(GROK_ORIGINATED_USER_AGENT)
    );
    let grok_trace = grok_actual[0]
        .headers
        .get("traceparent")
        .and_then(Value::as_str)
        .context("grok generated traceparent")?;
    assert_fresh_traceparent(grok_trace)?;
    if grok_actual[0].headers.get("x-compaction-at").is_some()
        || grok_actual[0]
            .headers
            .get("x-compactions-remaining")
            .is_some()
    {
        bail!(
            "omitted compaction headers were invented: {:?}",
            grok_actual[0].headers
        );
    }
    let grok_body: Value = serde_json::from_slice(&grok_actual[0].body).context("grok body")?;
    if grok_body.get("client_metadata").is_some() {
        bail!("grok invented client_metadata: {grok_body}");
    }
    assert_eq!(
        grok_actual[1]
            .headers
            .get("user-agent")
            .and_then(Value::as_str),
        Some("Caller/1.2 (Test)")
    );
    assert_eq!(
        grok_actual[1]
            .headers
            .get("traceparent")
            .and_then(Value::as_str),
        Some("00-cccccccccccccccccccccccccccccccc-dddddddddddddddd-01")
    );
    assert_eq!(
        grok_actual[1]
            .headers
            .get("x-compaction-at")
            .and_then(Value::as_str),
        Some("204800")
    );
    assert_eq!(
        grok_actual[1]
            .headers
            .get("x-compactions-remaining")
            .and_then(Value::as_str),
        Some("1")
    );
    let _ = grok;
    Ok(())
}

#[tokio::test]
async fn empty_fixture_directory_is_not_a_pass() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let error = assert_clean(dir.path()).unwrap_err();
    assert!(error.to_string().contains("no fixtures"), "{error}");
    Ok(())
}
