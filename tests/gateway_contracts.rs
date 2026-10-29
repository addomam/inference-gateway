mod support;

use std::{
    collections::VecDeque,
    ffi::CString,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::Response,
    routing::get,
};
use serde_json::{Value, json};
use support::{Gateway, sse_events};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, Notify, mpsc};
use uuid::Uuid;

const WAIT: Duration = Duration::from_secs(5);
#[derive(Debug)]
struct RawResponse {
    status: u16,
    trace_id: String,
    bytes: Vec<u8>,
}

async fn interrupted_upload(
    gateway: &Gateway,
    path: &str,
    prefix: &[u8],
    declared_length: usize,
) -> Result<RawResponse> {
    if declared_length <= prefix.len() {
        bail!("declared interrupted upload length must exceed its prefix");
    }
    let address: SocketAddr = gateway
        .base
        .strip_prefix("http://")
        .context("gateway base is not HTTP")?
        .parse()
        .context("parse gateway address")?;
    let mut socket = tokio::net::TcpStream::connect(address)
        .await
        .context("connect interrupted upload")?;
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {address}\r\nx-infer-key: {}\r\nContent-Type: application/json\r\nContent-Length: {declared_length}\r\nConnection: close\r\n\r\n",
        gateway.proxy_token
    );
    socket.write_all(request.as_bytes()).await?;
    socket.write_all(prefix).await?;
    socket.shutdown().await?;
    let mut bytes = Vec::new();
    tokio::time::timeout(WAIT, socket.read_to_end(&mut bytes))
        .await
        .map_err(|_| anyhow!("interrupted upload response timed out"))??;
    let text = String::from_utf8_lossy(&bytes);
    let head = text
        .split_once("\r\n\r\n")
        .map_or(text.as_ref(), |(head, _)| head);
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_ascii_whitespace().nth(1))
        .context("interrupted upload response has no status")?
        .parse()
        .context("parse interrupted upload status")?;
    let trace_id = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("x-infer-trace-id")
                .then(|| value.trim().to_owned())
        })
        .context("interrupted upload response has no trace id")?;
    Ok(RawResponse {
        status,
        trace_id,
        bytes,
    })
}

#[derive(Clone)]
struct Gates {
    prefix_sent: Arc<Notify>,
    release: Arc<Notify>,
}

struct Reply {
    status: StatusCode,
    content_type: Option<&'static str>,
    chunks: Vec<Vec<u8>>,
    headers: Vec<(&'static str, &'static str)>,
    gates: Option<Gates>,
}

#[derive(Debug)]
struct Captured {
    path: String,
    uri: String,
    body: Vec<u8>,
    headers: HeaderMap,
}

#[derive(Clone)]
struct FixtureState {
    replies: Arc<Mutex<VecDeque<Reply>>>,
    captured: mpsc::Sender<Captured>,
    strict_boolean_stream: bool,
}

struct Fixture {
    base: String,
    captured: mpsc::Receiver<Captured>,
    task: tokio::task::JoinHandle<()>,
}

impl Fixture {
    async fn start(replies: Vec<Reply>) -> Result<Self> {
        Self::start_with_stream_validation(replies, false).await
    }

    async fn start_strict_stream(replies: Vec<Reply>) -> Result<Self> {
        Self::start_with_stream_validation(replies, true).await
    }

    async fn start_with_stream_validation(
        replies: Vec<Reply>,
        strict_boolean_stream: bool,
    ) -> Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (captured_tx, captured) = mpsc::channel(32);
        let state = FixtureState {
            replies: Arc::new(Mutex::new(replies.into())),
            captured: captured_tx,
            strict_boolean_stream,
        };
        let app = Router::new()
            .route("/v1/realtime", get(realtime_echo))
            .fallback(upstream)
            .with_state(state);
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(Self {
            base: format!("http://{address}"),
            captured,
            task,
        })
    }

    async fn received(&mut self) -> Result<Captured> {
        tokio::time::timeout(WAIT, self.captured.recv())
            .await
            .map_err(|_| anyhow!("fixture did not receive request"))?
            .context("fixture request channel closed")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn realtime_echo(upgrade: axum::extract::ws::WebSocketUpgrade) -> Response {
    upgrade.on_upgrade(|mut socket| async move {
        if let Some(Ok(message)) = socket.recv().await {
            let _ = socket.send(message).await;
        }
    })
}
async fn upstream(State(state): State<FixtureState>, request: Request) -> Response {
    let headers = request.headers().clone();
    let path = request.uri().path().to_owned();
    let uri = request.uri().to_string();
    let body = to_bytes(request.into_body(), 32 * 1024 * 1024)
        .await
        .unwrap_or_default()
        .to_vec();
    let invalid_stream = state.strict_boolean_stream
        && serde_json::from_slice::<Value>(&body)
            .ok()
            .and_then(|value| value.get("stream").cloned())
            .is_some_and(|stream| !stream.is_boolean());
    let _ = state
        .captured
        .send(Captured {
            path,
            uri,
            body,
            headers,
        })
        .await;
    if invalid_stream {
        let mut response = Response::new(Body::from(
            br#"{"error":{"message":"stream must be boolean"}}"#.as_slice(),
        ));
        *response.status_mut() = StatusCode::UNPROCESSABLE_ENTITY;
        response
            .headers_mut()
            .insert("content-type", HeaderValue::from_static("application/json"));
        return response;
    }
    let reply = state
        .replies
        .lock()
        .await
        .pop_front()
        .expect("fixture reply");
    let body = if let Some(gates) = reply.gates {
        let mut chunks = reply.chunks.into_iter();
        let first = chunks.next().unwrap_or_default();
        Body::from_stream(async_stream::stream! {
            gates.prefix_sent.notify_one();
            yield Ok::<_, std::io::Error>(bytes::Bytes::from(first));
            gates.release.notified().await;
            for chunk in chunks {
                yield Ok::<_, std::io::Error>(bytes::Bytes::from(chunk));
            }
        })
    } else {
        Body::from(reply.chunks.concat())
    };
    let mut response = Response::new(body);
    *response.status_mut() = reply.status;
    if let Some(content_type) = reply.content_type {
        response
            .headers_mut()
            .insert("content-type", HeaderValue::from_static(content_type));
    }
    for (name, value) in reply.headers {
        response
            .headers_mut()
            .append(name, HeaderValue::from_static(value));
    }
    response
}

fn json_reply(value: Value) -> Reply {
    Reply {
        status: StatusCode::OK,
        content_type: Some("application/json"),
        headers: vec![],
        chunks: vec![serde_json::to_vec(&value).unwrap()],
        gates: None,
    }
}

#[tokio::test]
async fn cloudflare_legacy_keys_reach_upstream_but_never_trace_metadata_or_export() -> Result<()> {
    let reply = Reply {
        status: StatusCode::OK,
        content_type: Some("application/json"),
        chunks: vec![serde_json::to_vec(&json!({"success": true}))?],
        headers: vec![
            ("x-auth-email", "response-primary@example.invalid"),
            ("x-auth-email", "response-secondary@example.invalid"),
        ],
        gates: None,
    };
    let mut fixture = Fixture::start(vec![reply]).await?;
    let gateway = Gateway::start("openai", &fixture.base, "upstream", None).await?;
    let response = gateway
        .client
        .post(format!(
            "{}/providers/backend/client/v4/accounts/example/ai/run/@cf/cloudflare/clairic",
            gateway.base
        ))
        .header("x-infer-key", &gateway.proxy_token)
        .header("X-Auth-Key", "dummy-cloudflare-primary")
        .header("x-auth-key", "dummy-cloudflare-secondary")
        .header("X-Auth-Email", "request-primary@example.invalid")
        .header("x-auth-email", "request-secondary@example.invalid")
        .body("{}")
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let id = response.headers()["x-infer-trace-id"].to_str()?.to_owned();
    let email_response: Vec<_> = response
        .headers()
        .get_all("x-auth-email")
        .iter()
        .map(|value| value.to_str().map(str::to_owned))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    assert_eq!(response.json::<Value>().await?, json!({"success": true}));
    assert_eq!(email_response.len(), 2);
    assert_eq!(email_response[0], "response-primary@example.invalid");
    assert_eq!(email_response[1], "response-secondary@example.invalid");
    let received = fixture.received().await?;
    let keys: Vec<_> = received.headers.get_all("x-auth-key").iter().collect();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0], "dummy-cloudflare-primary");
    assert_eq!(keys[1], "dummy-cloudflare-secondary");
    let emails: Vec<_> = received.headers.get_all("x-auth-email").iter().collect();
    assert_eq!(emails.len(), 2);
    assert_eq!(emails[0], "request-primary@example.invalid");
    assert_eq!(emails[1], "request-secondary@example.invalid");
    let trace = gateway.trace(&id).await?;
    assert_eq!(trace["request_headers"]["x-auth-key"], "[REDACTED]");
    assert_eq!(trace["upstream_headers"]["x-auth-key"], "[REDACTED]");
    assert_eq!(trace["request_headers"]["x-auth-email"], "[REDACTED]");
    assert_eq!(trace["upstream_headers"]["x-auth-email"], "[REDACTED]");
    assert_eq!(
        trace["response_headers"]["upstream"]["x-auth-email"],
        "[REDACTED]"
    );
    assert_eq!(
        trace["response_headers"]["client"]["x-auth-email"],
        "[REDACTED]"
    );
    let exported = gateway.export().await?;
    let row = exported
        .iter()
        .find(|row| row["metadata"]["id"] == id)
        .context("native Cloudflare trace missing from export")?;
    let metadata = serde_json::to_string(&row["metadata"])?;
    assert!(!metadata.contains("dummy-cloudflare-primary"));
    assert!(!metadata.contains("dummy-cloudflare-secondary"));
    assert!(!metadata.contains("request-primary@example.invalid"));
    assert!(!metadata.contains("request-secondary@example.invalid"));
    assert!(!metadata.contains("response-primary@example.invalid"));
    assert!(!metadata.contains("response-secondary@example.invalid"));
    Ok(())
}

#[tokio::test]
async fn connection_nominated_passthrough_credentials_stay_filtered() -> Result<()> {
    let mut fixture = Fixture::start(vec![
        json_reply(json!({"ok": true})),
        json_reply(json!({"ok": true})),
    ])
    .await?;
    let gateway =
        Gateway::start_with_provider_auth("openai", &fixture.base, "upstream", "passthrough", None)
            .await?;

    let first = gateway
        .client
        .post(format!(
            "{}/providers/backend/v1/native-nominated",
            gateway.base
        ))
        .header("x-infer-key", &gateway.proxy_token)
        .header("Connection", "Authorization, X-Api-Key")
        .header("connection", "X-Other")
        .header("Authorization", "Bearer caller-provider-secret")
        .header("Authorization", format!("Bearer {}", gateway.proxy_token))
        .header("x-api-key", "caller-api-key-secret")
        .header("x-api-key", &gateway.proxy_token)
        .body("native")
        .send()
        .await?;
    assert_eq!(first.status(), StatusCode::OK);
    first.bytes().await?;
    let nominated = fixture.received().await?;
    assert!(
        nominated
            .headers
            .get_all("authorization")
            .iter()
            .next()
            .is_none()
    );
    assert!(
        nominated
            .headers
            .get_all("x-api-key")
            .iter()
            .next()
            .is_none()
    );
    assert!(nominated.headers.get_all("x-other").iter().next().is_none());

    let second = gateway
        .client
        .post(format!(
            "{}/providers/backend/v1/native-passthrough",
            gateway.base
        ))
        .header("x-infer-key", &gateway.proxy_token)
        .header("Connection", "X-Other")
        .header("connection", "X-Another")
        .header("Authorization", "Bearer caller-provider-secret")
        .header("Authorization", format!("Bearer {}", gateway.proxy_token))
        .header("x-api-key", "caller-api-key-secret")
        .header("x-api-key", &gateway.proxy_token)
        .body("native")
        .send()
        .await?;
    assert_eq!(second.status(), StatusCode::OK);
    second.bytes().await?;
    let passthrough = fixture.received().await?;
    let authorization: Vec<_> = passthrough
        .headers
        .get_all("authorization")
        .iter()
        .collect();
    assert_eq!(authorization, ["Bearer caller-provider-secret"]);
    let api_keys: Vec<_> = passthrough.headers.get_all("x-api-key").iter().collect();
    assert_eq!(api_keys, ["caller-api-key-secret"]);
    assert!(
        passthrough
            .headers
            .get_all("x-other")
            .iter()
            .next()
            .is_none()
    );
    assert!(
        passthrough
            .headers
            .get_all("x-another")
            .iter()
            .next()
            .is_none()
    );

    let mut configured_fixture = Fixture::start(vec![json_reply(json!({"ok": true}))]).await?;
    let configured_gateway = Gateway::start_with_provider_auth(
        "openai",
        &configured_fixture.base,
        "upstream",
        "bearer",
        Some("configured-provider-secret"),
    )
    .await?;
    let configured = configured_gateway
        .client
        .post(format!(
            "{}/providers/backend/v1/native-configured",
            configured_gateway.base
        ))
        .header("x-infer-key", &configured_gateway.proxy_token)
        .header("Connection", "Authorization")
        .header("Authorization", "Bearer caller-provider-secret")
        .body("native")
        .send()
        .await?;
    assert_eq!(configured.status(), StatusCode::OK);
    configured.bytes().await?;
    let configured_headers = configured_fixture.received().await?.headers;
    let configured_authorization: Vec<_> =
        configured_headers.get_all("authorization").iter().collect();
    assert_eq!(
        configured_authorization,
        ["Bearer configured-provider-secret"]
    );
    Ok(())
}

#[tokio::test]
async fn raw_gateway_token_is_not_forwarded_as_authorization() -> Result<()> {
    let mut fixture = Fixture::start(vec![json_reply(json!({"ok": true}))]).await?;
    let gateway =
        Gateway::start_with_provider_auth("openai", &fixture.base, "upstream", "passthrough", None)
            .await?;
    let response = gateway
        .client
        .post(format!("{}/providers/backend/v1/native", gateway.base))
        .header("x-infer-key", &gateway.proxy_token)
        .header("authorization", &gateway.proxy_token)
        .body("native")
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    response.bytes().await?;
    let captured = fixture.received().await?;
    assert!(captured.headers.get("authorization").is_none());
    Ok(())
}

#[tokio::test]
async fn google_api_key_headers_are_forwarded_but_redacted_at_every_trace_boundary() -> Result<()> {
    let reply = Reply {
        status: StatusCode::OK,
        content_type: Some("application/json"),
        chunks: vec![br#"{"ok":true}"#.to_vec()],
        headers: vec![
            ("x-goog-api-key", "dummy-response-primary"),
            ("x-goog-api-key", "dummy-response-secondary"),
        ],
        gates: None,
    };
    let mut fixture = Fixture::start(vec![reply]).await?;
    let gateway = Gateway::start("openai", &fixture.base, "upstream", None).await?;
    let response = gateway
        .client
        .post(format!("{}/providers/backend/v1/native", gateway.base))
        .header("x-infer-key", &gateway.proxy_token)
        .header("x-goog-api-key", "dummy-request-primary")
        .header("x-goog-api-key", "dummy-request-secondary")
        .body("opaque native body")
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let id = response.headers()["x-infer-trace-id"].to_str()?.to_owned();
    let response_keys: Vec<_> = response
        .headers()
        .get_all("x-goog-api-key")
        .iter()
        .collect();
    assert_eq!(response_keys.len(), 2);
    assert_eq!(response_keys[0], "dummy-response-primary");
    assert_eq!(response_keys[1], "dummy-response-secondary");
    let response_body = response.bytes().await?;
    assert_eq!(response_body.as_ref(), br#"{"ok":true}"#);
    let received = fixture.received().await?;
    let request_keys: Vec<_> = received.headers.get_all("x-goog-api-key").iter().collect();
    assert_eq!(request_keys.len(), 2);
    assert_eq!(request_keys[0], "dummy-request-primary");
    assert_eq!(request_keys[1], "dummy-request-secondary");

    let trace = gateway.trace(&id).await?;
    assert_eq!(trace["request_headers"]["x-goog-api-key"], "[REDACTED]");
    assert_eq!(trace["upstream_headers"]["x-goog-api-key"], "[REDACTED]");
    assert_eq!(
        trace["response_headers"]["upstream"]["x-goog-api-key"],
        "[REDACTED]"
    );
    assert_eq!(
        trace["response_headers"]["client"]["x-goog-api-key"],
        "[REDACTED]"
    );
    let exported = gateway.export().await?;
    let row = exported
        .iter()
        .find(|row| row["metadata"]["id"] == id)
        .context("native Google API-key trace missing from export")?;
    let metadata = serde_json::to_string(&row["metadata"])?;
    for secret in [
        "dummy-request-primary",
        "dummy-request-secondary",
        "dummy-response-primary",
        "dummy-response-secondary",
    ] {
        assert!(!metadata.contains(secret));
    }
    Ok(())
}

fn sse_reply(bytes: Vec<u8>) -> Reply {
    Reply {
        status: StatusCode::OK,
        content_type: Some("text/event-stream"),
        headers: vec![],
        chunks: vec![bytes],
        gates: None,
    }
}

fn frame(event: &str, value: Value) -> Vec<u8> {
    format!("event: {event}\r\ndata: {value}\r\n\r\n").into_bytes()
}

fn chat_frame(delta: Value, finish_reason: Value) -> Vec<u8> {
    format!(
        "data: {}\n\n",
        json!({"choices":[{"index":0,"delta":delta,"finish_reason":finish_reason}]})
    )
    .into_bytes()
}

fn anthropic_frame(event: &str, value: Value) -> Vec<u8> {
    frame(event, value)
}

fn responses_text_stream(logprobs: Option<Value>) -> Vec<u8> {
    let message = json!({"type":"message","role":"assistant","content":[
        {"type":"output_text","text":"hello","annotations":[],"logprobs":null}
    ]});
    let mut delta = json!({"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"hello"});
    if let Some(logprobs) = logprobs {
        delta["logprobs"] = logprobs;
    }
    [
        frame("response.created", json!({"type":"response.created","response":{"id":"r"}})),
        frame("response.output_item.added", json!({"type":"response.output_item.added","output_index":0,"item":{"type":"message","role":"assistant","content":[]}})),
        frame("response.content_part.added", json!({"type":"response.content_part.added","output_index":0,"content_index":0,"part":{"type":"output_text","text":"","annotations":[]}})),
        frame("response.output_text.delta", delta),
        frame("response.output_text.done", json!({"type":"response.output_text.done","output_index":0,"content_index":0,"text":"hello"})),
        frame("response.content_part.done", json!({"type":"response.content_part.done","output_index":0,"content_index":0,"part":message["content"][0]})),
        frame("response.output_item.done", json!({"type":"response.output_item.done","output_index":0,"item":message})),
        frame("response.completed", json!({"type":"response.completed","response":{"id":"r","status":"completed","error":null,"output":[message],"usage":{"input_tokens":2,"output_tokens":1}}})),
    ]
    .concat()
}

fn responses_ordered_stream() -> Vec<u8> {
    let message = json!({"type":"message","role":"assistant","content":[
        {"type":"output_text","text":"first","annotations":[]},
        {"type":"output_text","text":"tail","annotations":[]}
    ]});
    let tool = json!({"type":"function_call","call_id":"call_later","name":"later","arguments":"{\"y\":2}"});
    [
        frame("response.output_item.added", json!({"type":"response.output_item.added","output_index":0,"item":{"type":"message","role":"assistant","content":[]}})),
        frame("response.output_item.added", json!({"type":"response.output_item.added","output_index":1,"item":{"type":"function_call","call_id":"call_later","name":"later","arguments":""}})),
        frame("response.function_call_arguments.delta", json!({"type":"response.function_call_arguments.delta","output_index":1,"delta":"{\"y\":2}"})),
        frame("response.output_text.delta", json!({"type":"response.output_text.delta","output_index":0,"content_index":1,"delta":"tail"})),
        frame("response.content_part.added", json!({"type":"response.content_part.added","output_index":0,"content_index":0,"part":{"type":"output_text","text":""}})),
        frame("response.output_text.delta", json!({"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"first"})),
        frame("response.content_part.done", json!({"type":"response.content_part.done","output_index":0,"content_index":1,"part":message["content"][1]})),
        frame("response.content_part.done", json!({"type":"response.content_part.done","output_index":0,"content_index":0,"part":message["content"][0]})),
        frame("response.output_item.done", json!({"type":"response.output_item.done","output_index":1,"item":tool})),
        frame("response.output_item.done", json!({"type":"response.output_item.done","output_index":0,"item":message})),
        frame("response.completed", json!({"type":"response.completed","response":{"status":"completed","error":null,"output":[message,tool],"usage":{}}})),
    ]
    .concat()
}

fn valid_codex_auth(root: &Path) -> Result<PathBuf> {
    let path = root.join("auth.json");
    std::fs::write(
        &path,
        serde_json::to_vec(&json!({
            "tokens":{"access_token":"opaque-ready-token","account_id":"account-test"}
        }))?,
    )?;
    Ok(path)
}

fn trace_id(response: &reqwest::Response) -> Result<String> {
    Ok(response
        .headers()
        .get("x-infer-trace-id")
        .context("missing trace id")?
        .to_str()?
        .to_owned())
}

async fn completed_trace(gateway: &Gateway, id: &str) -> Result<Value> {
    tokio::time::timeout(WAIT, async {
        loop {
            let trace = gateway.trace(id).await?;
            if trace["complete"] == true {
                return Ok(trace);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| anyhow!("trace did not complete"))?
}

async fn collect(mut response: reqwest::Response) -> (Vec<u8>, Option<anyhow::Error>) {
    let mut output = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => output.extend_from_slice(&chunk),
            Ok(None) => return (output, None),
            Err(error) => return (output, Some(error.into())),
        }
    }
}

fn chat_request(stream: bool) -> Value {
    json!({"model":"validation","messages":[{"role":"user","content":"hello"}],"stream":stream,"max_tokens":32})
}

fn anthropic_request(stream: bool) -> Value {
    json!({"model":"validation","max_tokens":32,"messages":[{"role":"user","content":"hello"}],"stream":stream})
}

#[tokio::test]
async fn clairic_sdk_path_alias_preserves_native_contract_and_trace_bodies() -> Result<()> {
    let response_wire = r#"{"result":{"model":"clairic","answers":{"missing_po":{"type":"text","value":null,"guess":"INV-2291","span":[8,16],"p_null":1.0,"confidence":0.9995},"contacts":{"type":"list","value":[],"spans":[],"confidence":0.9999},"payment_days":{"type":"estimate","value":30,"mean":29.535,"median":30,"p10":21,"p90":38,"p_below":0.0000059,"p_above":0.000012,"quantiles":[0,1,2]},"cashflow":{"type":"forecast","value":[100,120],"steps":[{"value":100,"mean":99.5,"median":100,"p10":90,"p90":110},{"value":120,"mean":121,"median":120,"p10":105,"p90":135}]}},"truncated":true,"state_text":"請求書 INV-2291 — café","usage":{"state_tokens":61,"image_tokens":7,"schema_tokens":472,"input_tokens":655,"output_tokens":0,"passes":3}},"success":true,"errors":[],"messages":[]}"#.as_bytes();
    let mut fixture = Fixture::start(vec![Reply {
        status: StatusCode::OK,
        content_type: Some("application/json"),
        headers: vec![("cf-ray", "fixture-ray"), ("x-ratelimit-remaining", "9")],
        chunks: vec![response_wire.to_vec()],
        gates: None,
    }])
    .await?;
    let deployment = format!("{}/deployment", fixture.base);
    let gateway = Gateway::start("clairic", &deployment, "@cf/cloudflare/clairic", None).await?;
    let request_wire = r#"{
  "model":"validation",
  "state":"請求書 INV-2291 — café",
  "fields":{
    "title":{"type":"text"},
    "amount":{"type":"number","integer":false,"decimals":2,"unit":"USD"},
    "issued":{"type":"date"},
    "at":{"type":"time"},
    "created":{"type":"datetime"},
    "age":{"type":"duration","unit":"days","integer":true},
    "contacts":{"type":"list","items":"text"},
    "payment_days":{"type":"estimate","min":0,"max":120,"step":1,"scale":"linear","null_threshold":0.8},
    "cashflow":{"type":"forecast","min":0,"max":1000,"step":5,"horizon":2,"interval":"month"}
  },
  "reference_date":"2026-10-22",
  "options":{"include_quantiles":true,"return_state_text":true},
  "images":["data:image/png;base64,iVBORw0KGgo=",{"content_type":"image/webp","base64":"UklGRg=="}],
  "provider_extension":{"keep":true}
}"#.as_bytes();
    let response = gateway
        .client
        .post(format!(
            "{}/client/v4/accounts/account-01/ai/run/@cf%2Fcloudflare%2Fclairic?beta=true&tag=a%2Fb",
            gateway.base
        ))
        .header("x-infer-key", &gateway.proxy_token)
        .header("content-type", "application/json")
        .header("content-digest", "sha-256=:stale-after-rewrite:")
        .body(request_wire)
        .send()
        .await?;
    let id = trace_id(&response)?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cf-ray"], "fixture-ray");
    assert_eq!(response.headers()["x-ratelimit-remaining"], "9");
    assert_eq!(response.bytes().await?.as_ref(), response_wire);

    let captured = fixture.received().await?;
    assert_eq!(
        captured.uri,
        "/deployment/client/v4/accounts/account-01/ai/run/@cf/cloudflare/clairic?beta=true&tag=a%2Fb"
    );
    assert!(!captured.headers.contains_key("content-digest"));
    let mut expected: Value = serde_json::from_slice(request_wire)?;
    expected["model"] = json!("@cf/cloudflare/clairic");
    assert_eq!(serde_json::from_slice::<Value>(&captured.body)?, expected);

    let trace = completed_trace(&gateway, &id).await?;
    assert_eq!(trace["provider"], "backend");
    assert_eq!(
        trace["upstream_url"],
        format!(
            "{}/client/v4/accounts/account-01/ai/run/@cf/cloudflare/clairic?beta=true&tag=a%2Fb",
            deployment
        )
    );
    assert_eq!(gateway.body(&id, "request").await?, request_wire);
    assert_eq!(gateway.body(&id, "upstream_request").await?, captured.body);
    assert_eq!(gateway.body(&id, "response").await?, response_wire);
    assert_eq!(gateway.body(&id, "upstream_response").await?, response_wire);
    Ok(())
}

#[tokio::test]
async fn clairic_default_route_preserves_wire_and_cloudflare_error() -> Result<()> {
    let error_wire = br#"{"result":null,"success":false,"errors":[{"code":10000,"message":"Workers AI rate limit exceeded"}],"messages":[{"code":10001,"message":"retry later"}]}"#;
    let mut fixture = Fixture::start(vec![Reply {
        status: StatusCode::TOO_MANY_REQUESTS,
        content_type: Some("application/json"),
        headers: vec![("retry-after", "23"), ("cf-ray", "fixture-error-ray")],
        chunks: vec![error_wire.to_vec()],
        gates: None,
    }])
    .await?;
    let gateway = Gateway::start("clairic", &fixture.base, "unused", None).await?;
    let request_wire =
        br#"{ "model":"clairic", "state":"unchanged", "fields":{"name":{"type":"text"}}, "extension":true }"#;
    let response = gateway
        .client
        .post(format!(
            "{}/client/v4/accounts/account-02/ai/run/@cf/cloudflare/clairic",
            gateway.base
        ))
        .header("x-infer-key", &gateway.proxy_token)
        .header("content-type", "application/json")
        .header("content-digest", "sha-256=:unchanged:")
        .body(request_wire.as_slice())
        .send()
        .await?;
    let id = trace_id(&response)?;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers()["retry-after"], "23");
    assert_eq!(response.headers()["cf-ray"], "fixture-error-ray");
    assert_eq!(response.bytes().await?.as_ref(), error_wire);

    let captured = fixture.received().await?;
    assert_eq!(
        captured.path,
        "/client/v4/accounts/account-02/ai/run/@cf/cloudflare/clairic"
    );
    assert_eq!(captured.body, request_wire);
    assert_eq!(captured.headers["content-digest"], "sha-256=:unchanged:");
    let trace = completed_trace(&gateway, &id).await?;
    assert_eq!(trace["status"], 429);
    assert!(trace["error"].is_string());
    assert_eq!(gateway.body(&id, "request").await?, request_wire);
    assert_eq!(gateway.body(&id, "response").await?, error_wire);
    Ok(())
}

#[tokio::test]
async fn clairic_explicit_provider_path_stays_schema_free() -> Result<()> {
    let response_wire = b"native response bytes";
    let mut fixture = Fixture::start(vec![Reply {
        status: StatusCode::ACCEPTED,
        content_type: Some("application/octet-stream"),
        headers: vec![("x-provider-extension", "native")],
        chunks: vec![response_wire.to_vec()],
        gates: None,
    }])
    .await?;
    let gateway = Gateway::start("clairic", &fixture.base, "unused", None).await?;
    let request_wire = b"not JSON and no model";
    let response = gateway
        .client
        .post(format!(
            "{}/providers/backend/client/v4/accounts/native/ai/run/@cf/cloudflare/clairic?mode=raw",
            gateway.base
        ))
        .header("x-infer-key", &gateway.proxy_token)
        .header("content-type", "application/octet-stream")
        .body(request_wire.as_slice())
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(response.headers()["x-provider-extension"], "native");
    assert_eq!(response.bytes().await?.as_ref(), response_wire);
    let captured = fixture.received().await?;
    assert_eq!(
        captured.uri,
        "/client/v4/accounts/native/ai/run/@cf/cloudflare/clairic?mode=raw"
    );
    assert_eq!(captured.body, request_wire);
    Ok(())
}

#[tokio::test]
async fn clairic_rejects_cross_family_routes_before_dispatch() -> Result<()> {
    let mut fixture = Fixture::start(vec![]).await?;
    let canonical = "/client/v4/accounts/account-03/ai/run/@cf/cloudflare/clairic";
    for (kind, paths) in [
        (
            "clairic",
            vec![
                "/v1/messages",
                "/v1/chat/completions",
                "/v1/responses",
                "/v1/decisions",
                "/v1/systemone",
            ],
        ),
        ("openai", vec![canonical]),
        ("openai_decisions", vec![canonical]),
        ("system_one", vec![canonical]),
    ] {
        let gateway = Gateway::start(kind, &fixture.base, "@cf/cloudflare/clairic", None).await?;
        for path in paths {
            for model in ["validation", "@cf/cloudflare/clairic"] {
                let response = gateway
                    .post(
                        path,
                        &json!({"model":model,"state":"evidence","fields":{"name":{"type":"text"}}}),
                    )
                    .await?;
                let id = trace_id(&response)?;
                assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{kind}: {path}");
                let body: Value = response.json().await?;
                assert!(
                    body["error"]["message"]
                        .as_str()
                        .unwrap()
                        .contains("cannot be translated"),
                    "{body}"
                );
                assert_eq!(completed_trace(&gateway, &id).await?["status"], 400);
                assert!(fixture.captured.try_recv().is_err());
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn system_one_rejects_cross_family_routes_before_dispatch() -> Result<()> {
    let mut fixture = Fixture::start(vec![]).await?;
    for (kind, paths) in [
        (
            "system_one",
            vec!["/v1/messages", "/v1/chat/completions", "/v1/responses"],
        ),
        ("openai", vec!["/v1/systemone"]),
    ] {
        let gateway = Gateway::start(kind, &fixture.base, "jev-latest", None).await?;
        for path in paths {
            // Test both alias resolution and the default-provider path.
            for model in ["validation", "jev-preview"] {
                let response = gateway
                    .post(
                        path,
                        &json!({"model": model, "state": "hello", "questions": {}}),
                    )
                    .await?;
                let id = trace_id(&response)?;
                assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{kind}: {path}");
                let body: Value = response.json().await?;
                assert!(
                    body["error"]["message"]
                        .as_str()
                        .unwrap()
                        .contains("cannot be translated"),
                    "{body}"
                );
                assert_eq!(completed_trace(&gateway, &id).await?["status"], 400);
                assert!(fixture.captured.try_recv().is_err());
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn openai_decisions_alias_preserves_native_typed_contract_and_trace_bodies() -> Result<()> {
    let response_wire = br#"{"model":"gpt-6-luna-2026-10-01","answers":[{"type":"predicate","name":null,"probability":0.875},{"type":"choice","name":"typed","choice":true,"confidence":0.61,"probabilities":[{"value":true,"probability":0.61},{"value":"true","probability":0.39}]},{"type":"score","name":"priority","score":1.25,"confidence":0.72,"probabilities":[{"label":"low","value":0,"probability":0.1},{"label":"medium","value":1,"probability":0.55},{"label":"high","value":2,"probability":0.35}]},{"type":"refusal","name":"restricted"}],"usage":{"input_tokens":100,"output_tokens":12,"total_tokens":112,"input_tokens_details":{"cached_tokens":80,"cache_write_tokens":20},"output_tokens_details":{"reasoning_tokens":7}},"provider_extension":{"retained":true}}"#;
    let mut fixture = Fixture::start(vec![Reply {
        status: StatusCode::OK,
        content_type: Some("application/json"),
        headers: vec![("x-openai-request-id", "req_decisions_fixture")],
        chunks: vec![response_wire.to_vec()],
        gates: None,
    }])
    .await?;
    let gateway = Gateway::start("openai_decisions", &fixture.base, "gpt-6-luna", None).await?;
    let request_wire = br#"{
  "model": "validation",
  "input": [{"role":"user","content":[{"type":"input_text","text":"Inspect"},{"type":"input_image","image_url":"https://images.example.test/item.png","detail":"original","prompt_cache_breakpoint":{"mode":"explicit"}},{"type":"input_json","data":{"precise":123456789012345678901234567890.123456789}}]}],
  "questions": [{"type":"predicate","instructions":"Condition?"},{"type":"choice","name":"typed","instructions":"Choose","choices":[{"value":true},{"value":"true"},{"value":false,"description":"false boolean"}]},{"type":"score","name":"priority","instructions":"Rate","levels":[{"label":"low","description":"wait"},{"label":"high","description":"act"}]},{"type":"future_question","extension":true}],
  "prompt_cache_key":"tenant-a",
  "prompt_cache_options":{"mode":"explicit","ttl":"30m"},
  "safety_identifier":"safe-user",
  "native_extension":{"keep":"yes"}
}"#;
    let response = gateway
        .client
        .post(format!("{}/v1/decisions", gateway.base))
        .header("x-infer-key", &gateway.proxy_token)
        .header("content-type", "application/json")
        .header("content-digest", "sha-256=:stale-after-rewrite:")
        .body(request_wire.as_slice())
        .send()
        .await?;
    let id = trace_id(&response)?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["x-openai-request-id"],
        "req_decisions_fixture"
    );
    assert_eq!(response.bytes().await?.as_ref(), response_wire);

    let captured = fixture.received().await?;
    assert_eq!(captured.path, "/v1/decisions");
    assert!(!captured.headers.contains_key("content-digest"));
    let mut expected: Value = serde_json::from_slice(request_wire)?;
    expected["model"] = json!("gpt-6-luna");
    let upstream: Value = serde_json::from_slice(&captured.body)?;
    assert_eq!(upstream, expected);
    assert_eq!(upstream["questions"][1]["choices"][0]["value"], true);
    assert_eq!(upstream["questions"][1]["choices"][1]["value"], "true");
    assert!(
        String::from_utf8_lossy(&captured.body)
            .contains("123456789012345678901234567890.123456789")
    );

    let trace = completed_trace(&gateway, &id).await?;
    assert_eq!(trace["provider"], "backend");
    assert_eq!(gateway.body(&id, "request").await?, request_wire);
    assert_eq!(gateway.body(&id, "upstream_request").await?, captured.body);
    assert_eq!(gateway.body(&id, "response").await?, response_wire);
    assert_eq!(gateway.body(&id, "upstream_response").await?, response_wire);
    Ok(())
}

#[tokio::test]
async fn openai_decisions_default_route_preserves_wire_and_provider_error() -> Result<()> {
    let error_wire =
        br#"{"error":{"type":"rate_limit_error","message":"decision capacity exhausted"}}"#;
    let mut fixture = Fixture::start(vec![Reply {
        status: StatusCode::TOO_MANY_REQUESTS,
        content_type: Some("application/json"),
        headers: vec![
            ("retry-after", "17"),
            ("x-provider-extension", "decision-error"),
        ],
        chunks: vec![error_wire.to_vec()],
        gates: None,
    }])
    .await?;
    let gateway = Gateway::start("openai_decisions", &fixture.base, "gpt-6-luna", None).await?;
    let request_wire =
        br#"{ "native_extension":true, "questions":[{"type":"future"}], "model":"gpt-6-luna", "input":"evidence" }"#;
    let response = gateway
        .client
        .post(format!("{}/v1/decisions", gateway.base))
        .header("x-infer-key", &gateway.proxy_token)
        .header("content-type", "application/json")
        .header("content-digest", "sha-256=:unchanged:")
        .header("x-client-extension", "keep")
        .body(request_wire.as_slice())
        .send()
        .await?;
    let id = trace_id(&response)?;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers()["retry-after"], "17");
    assert_eq!(response.headers()["x-provider-extension"], "decision-error");
    assert_eq!(response.bytes().await?.as_ref(), error_wire);

    let captured = fixture.received().await?;
    assert_eq!(captured.path, "/v1/decisions");
    assert_eq!(captured.body, request_wire);
    assert_eq!(captured.headers["content-digest"], "sha-256=:unchanged:");
    assert_eq!(captured.headers["x-client-extension"], "keep");
    let trace = completed_trace(&gateway, &id).await?;
    assert_eq!(trace["status"], 429);
    assert!(trace["error"].is_string());
    assert_eq!(gateway.body(&id, "request").await?, request_wire);
    assert_eq!(gateway.body(&id, "response").await?, error_wire);
    Ok(())
}

#[tokio::test]
async fn openai_decisions_rejects_cross_family_routes_before_dispatch() -> Result<()> {
    let mut fixture = Fixture::start(vec![]).await?;
    for (kind, path) in [
        ("openai_decisions", "/v1/messages"),
        ("openai_decisions", "/v1/chat/completions"),
        ("openai_decisions", "/v1/responses"),
        ("openai", "/v1/decisions"),
        ("openai_decisions", "/v1/embeddings"),
        ("system_one", "/v1/embeddings"),
        ("anthropic", "/v1/embeddings"),
        ("grok", "/v1/embeddings"),
    ] {
        let gateway = Gateway::start(kind, &fixture.base, "gpt-6-luna", None).await?;
        for model in ["validation", "gpt-6-luna"] {
            let response = gateway
                .post(
                    path,
                    &json!({"model":model,"input":"evidence","questions":[]}),
                )
                .await?;
            let id = trace_id(&response)?;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{kind}: {path}");
            let body: Value = response.json().await?;
            assert!(
                body["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("cannot be translated"),
                "{body}"
            );
            assert_eq!(completed_trace(&gateway, &id).await?["status"], 400);
            assert!(fixture.captured.try_recv().is_err());
        }
    }

    let auth_root = tempfile::tempdir()?;
    let auth = valid_codex_auth(auth_root.path())?;
    let gateway = Gateway::start("codex", &fixture.base, "gpt-6-luna", Some(&auth)).await?;
    let response = gateway
        .post(
            "/v1/embeddings",
            &json!({"model":"validation","input":"evidence"}),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(fixture.captured.try_recv().is_err());
    Ok(())
}

#[tokio::test]
async fn embeddings_route_preserves_openai_body_and_rejects_llama_dimensions() -> Result<()> {
    let mut fixture = Fixture::start(vec![
        json_reply(json!({
            "object":"list",
            "data":[{"object":"embedding","index":0,"embedding":[0.1,0.2]}],
            "model":"text-embedding-3-small",
            "usage":{"prompt_tokens":2,"total_tokens":2}
        })),
        json_reply(json!({
            "object":"list",
            "data":[{"object":"embedding","index":0,"embedding":[0.3]}],
            "model":"nomic-embed",
            "usage":{"prompt_tokens":1,"total_tokens":1}
        })),
    ])
    .await?;
    let openai = Gateway::start("openai", &fixture.base, "text-embedding-3-small", None).await?;
    let request = json!({
        "model":"validation",
        "input":[[1,2],[3]],
        "encoding_format":"base64",
        "dimensions":256,
        "user":"person"
    });
    let response = openai.post("/v1/embeddings", &request).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await?;
    assert_eq!(body["data"][0]["embedding"], json!([0.1, 0.2]));
    let captured = fixture.received().await?;
    assert_eq!(captured.path, "/v1/embeddings");
    let upstream: Value = serde_json::from_slice(&captured.body)?;
    assert_eq!(upstream["model"], "text-embedding-3-small");
    assert_eq!(upstream["input"], json!([[1, 2], [3]]));
    assert_eq!(upstream["dimensions"], 256);
    assert_eq!(upstream["user"], "person");

    let llama = Gateway::start("llama", &fixture.base, "nomic-embed", None).await?;
    let rejected = llama
        .post(
            "/v1/embeddings",
            &json!({"model":"validation","input":"hello","dimensions":64}),
        )
        .await?;
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    let error: Value = rejected.json().await?;
    assert!(
        error["error"]["message"]
            .as_str()
            .unwrap()
            .contains("dimensions"),
        "{error}"
    );
    assert!(fixture.captured.try_recv().is_err());

    let response = llama
        .post(
            "/v1/embeddings",
            &json!({"model":"validation","input":["hello","world"],"encoding_format":"float","user":"person"}),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let captured = fixture.received().await?;
    assert_eq!(captured.path, "/v1/embeddings");
    let upstream: Value = serde_json::from_slice(&captured.body)?;
    assert_eq!(upstream["model"], "nomic-embed");
    assert_eq!(upstream["input"], json!(["hello", "world"]));
    assert_eq!(upstream["encoding_format"], "float");
    assert_eq!(upstream["user"], "person");
    assert!(upstream.get("dimensions").is_none());
    Ok(())
}

#[tokio::test]
async fn catalog_routes_daybreak_and_refuses_unsupported_models() -> Result<()> {
    let mut fixture = Fixture::start(vec![json_reply(json!({
        "id":"resp",
        "model":"gpt-6-sol",
        "output":[],
        "usage":{"input_tokens":1,"output_tokens":1}
    }))])
    .await?;
    let gateway = Gateway::start_with_provider_lines(
        "openai",
        &fixture.base,
        "unused",
        "daybreak = \"blue\"\n",
    )
    .await?;
    let rejected = gateway
        .post(
            "/v1/chat/completions",
            &json!({"model":"whisper-1","messages":[{"role":"user","content":"hi"}]}),
        )
        .await?;
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    let error: Value = rejected.json().await?;
    assert!(
        error["error"]["message"]
            .as_str()
            .unwrap()
            .contains("does not speak"),
        "{error}"
    );
    assert!(fixture.captured.try_recv().is_err());

    let rejected = gateway
        .post(
            "/v1/embeddings",
            &json!({"model":"text-embedding-ada-002","input":"hello","dimensions":8}),
        )
        .await?;
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    assert!(fixture.captured.try_recv().is_err());

    let response = gateway
        .post(
            "/v1/responses",
            &json!({"model":"gpt-6-sol#daybreak-blue","input":"Explain the patch."}),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let captured = fixture.received().await?;
    assert_eq!(captured.path, "/v1/responses");
    let upstream: Value = serde_json::from_slice(&captured.body)?;
    assert_eq!(upstream["model"], "gpt-6-sol");
    assert_eq!(upstream["access_programs"]["cyber"], "daybreak_blue");
    assert_eq!(upstream["input"], "Explain the patch.");

    let rejected = gateway
        .post(
            "/v1/responses",
            &json!({"model":"gpt-6-sol","input":"x","access_programs":{"cyber":"daybreak_red"}}),
        )
        .await?;
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    assert!(fixture.captured.try_recv().is_err());
    Ok(())
}

#[tokio::test]
async fn capabilities_hides_daybreak_models_until_the_ceiling_allows_them() -> Result<()> {
    let fixture = Fixture::start(vec![]).await?;
    let standard = Gateway::start("openai", &fixture.base, "unused", None).await?;
    let hidden = standard
        .client
        .get(format!("{}/v1/capabilities", standard.base))
        .header("x-infer-key", &standard.proxy_token)
        .send()
        .await?;
    assert_eq!(hidden.status(), StatusCode::OK);
    let hidden: Value = hidden.json().await?;
    let ids: Vec<_> = hidden["models"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|model| model["id"].as_str())
        .collect();
    assert!(ids.contains(&"gpt-6-sol"));
    assert!(!ids.iter().any(|id| id.contains("daybreak")));
    assert_eq!(hidden["providers"][0]["daybreak"], "standard");

    let blue = Gateway::start_with_provider_lines(
        "openai",
        &fixture.base,
        "unused",
        "daybreak = \"blue\"\n",
    )
    .await?;
    let shown = blue
        .client
        .get(format!("{}/v1/capabilities", blue.base))
        .header("x-infer-key", &blue.proxy_token)
        .send()
        .await?;
    let shown: Value = shown.json().await?;
    let ids: Vec<_> = shown["models"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|model| model["id"].as_str())
        .collect();
    assert!(ids.contains(&"gpt-6-sol#daybreak-blue"));
    assert!(
        !ids.iter()
            .any(|id| id.contains("daybreak-red") || *id == "gpt-5.6-cyber")
    );
    Ok(())
}

#[tokio::test]
async fn account_products_are_refused_and_audio_follows_declared_operations() -> Result<()> {
    let mut fixture = Fixture::start(vec![
        json_reply(json!({"text":"hello"})),
        json_reply(json!({"text":"speakers"})),
    ])
    .await?;
    let gateway = Gateway::start("openai", &fixture.base, "unused", None).await?;
    for path in [
        "/v1/batches",
        "/v1/assistants",
        "/v1/fine_tuning/jobs",
        "/v1/evals",
    ] {
        let refused = gateway.post(path, &json!({})).await?;
        assert_eq!(refused.status(), StatusCode::NOT_IMPLEMENTED, "{path}");
        let error: Value = refused.json().await?;
        assert!(
            error["error"]["message"]
                .as_str()
                .unwrap()
                .contains("account products"),
            "{path} {error}"
        );
    }
    assert!(fixture.captured.try_recv().is_err());

    let speech = gateway
        .post(
            "/v1/audio/speech",
            &json!({"model":"tts-1","input":"hello","voice":"alloy"}),
        )
        .await?;
    assert_eq!(speech.status(), StatusCode::OK);
    let captured = fixture.received().await?;
    assert_eq!(captured.path, "/v1/audio/speech");

    let diarize = gateway
        .client
        .post(format!("{}/v1/audio/transcriptions", gateway.base))
        .header("x-infer-key", &gateway.proxy_token)
        .header(
            "content-type",
            "multipart/form-data; boundary=bound",
        )
        .body("--bound\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nwhisper-1\r\n--bound\r\nContent-Disposition: form-data; name=\"response_format\"\r\n\r\ndiarized_json\r\n--bound\r\nContent-Disposition: form-data; name=\"file\"; filename=\"talk.mp3\"\r\nContent-Type: audio/mpeg\r\n\r\nnot-audio\r\n--bound--\r\n")
        .send()
        .await?;
    assert_eq!(diarize.status(), StatusCode::BAD_REQUEST);
    let error: Value = diarize.json().await?;
    assert!(
        error["error"]["message"]
            .as_str()
            .unwrap()
            .contains("does not declare diarize"),
        "{error}"
    );

    let speakers = gateway
        .client
        .post(format!("{}/v1/audio/transcriptions", gateway.base))
        .header("x-infer-key", &gateway.proxy_token)
        .header("content-type", "multipart/form-data; boundary=bound")
        .body("--bound\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\ngpt-4o-transcribe-diarize\r\n--bound\r\nContent-Disposition: form-data; name=\"response_format\"\r\n\r\ndiarized_json\r\n--bound\r\nContent-Disposition: form-data; name=\"file\"; filename=\"talk.mp3\"\r\nContent-Type: audio/mpeg\r\n\r\nnot-audio\r\n--bound--\r\n")
        .send()
        .await?;
    assert_eq!(speakers.status(), StatusCode::OK);
    let captured = fixture.received().await?;
    assert_eq!(captured.path, "/v1/audio/transcriptions");
    assert!(
        captured
            .body
            .windows(25)
            .any(|window| window == b"gpt-4o-transcribe-diarize")
    );
    Ok(())
}

#[tokio::test]
async fn diarization_is_routed_and_refused_until_a_provider_speaks_it() -> Result<()> {
    let mut fixture = Fixture::start(vec![]).await?;
    let gateway = Gateway::start("openai", &fixture.base, "unused", None).await?;
    let body = "--bound\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nwhisper-1\r\n--bound\r\nContent-Disposition: form-data; name=\"file\"; filename=\"talk.mp3\"\r\nContent-Type: audio/mpeg\r\n\r\nnot-audio\r\n--bound--\r\n";
    let refused = gateway
        .client
        .post(format!("{}/v1/audio/diarization", gateway.base))
        .header("x-infer-key", &gateway.proxy_token)
        .header("content-type", "multipart/form-data; boundary=bound")
        .body(body)
        .send()
        .await?;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    let error: Value = refused.json().await?;
    assert!(
        error["error"]["message"]
            .as_str()
            .unwrap()
            .contains("does not speak diarization"),
        "{error}"
    );
    let combined = "--bound\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\ngpt-4o-transcribe-diarize\r\n--bound\r\nContent-Disposition: form-data; name=\"file\"; filename=\"talk.mp3\"\r\nContent-Type: audio/mpeg\r\n\r\nnot-audio\r\n--bound--\r\n";
    let refused = gateway
        .client
        .post(format!("{}/v1/audio/diarization", gateway.base))
        .header("x-infer-key", &gateway.proxy_token)
        .header("content-type", "multipart/form-data; boundary=bound")
        .body(combined)
        .send()
        .await?;
    let error: Value = refused.json().await?;
    assert!(
        error["error"]["message"]
            .as_str()
            .unwrap()
            .contains("does not speak diarization"),
        "{error}"
    );
    assert!(fixture.captured.try_recv().is_err());
    let listed = gateway
        .client
        .get(format!("{}/v1/capabilities", gateway.base))
        .header("x-infer-key", &gateway.proxy_token)
        .send()
        .await?;
    let listed: Value = listed.json().await?;
    assert!(
        listed["routes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|route| { route["path"] == "/v1/audio/diarization" })
    );
    Ok(())
}

#[tokio::test]
async fn transcription_rewrites_alias_without_splitting_binary_audio() -> Result<()> {
    let mut fixture = Fixture::start(vec![json_reply(json!({"text":"heard"}))]).await?;
    let gateway = Gateway::start("openai", &fixture.base, "whisper-1", None).await?;
    let audio = b"\xff\xfe--bound--name=\"model\"\r\n\r\nEVIL\r\n--";
    let mut body = b"--bound\r\nContent-Disposition: form-data; name=\"file\"; filename=\"talk.mp3\"\r\nContent-Type: audio/mpeg\r\n\r\n".to_vec();
    body.extend_from_slice(audio);
    body.extend_from_slice(b"\r\n--bound\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nvalidation\r\n--bound--\r\n");
    let response = gateway
        .client
        .post(format!("{}/v1/audio/transcriptions", gateway.base))
        .header("x-infer-key", &gateway.proxy_token)
        .header("content-type", "multipart/form-data; boundary=bound")
        .body(body)
        .send()
        .await?;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "{}",
        response.text().await?
    );
    let captured = fixture.received().await?;
    assert_eq!(captured.path, "/v1/audio/transcriptions");
    assert!(
        captured
            .body
            .windows(audio.len())
            .any(|window| window == audio),
        "binary audio was rewritten or truncated"
    );
    let content_type = captured
        .headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.to_ascii_lowercase().contains("multipart/"),
        "rewritten audio was labeled {content_type}"
    );
    let model = captured
        .body
        .windows(b"\r\n\r\nvalidation\r\n".len())
        .any(|window| window == b"\r\n\r\nvalidation\r\n");
    assert!(!model, "alias was forwarded instead of the upstream model");
    assert!(
        captured
            .body
            .windows(b"\r\n\r\nwhisper-1\r\n".len())
            .any(|window| window == b"\r\n\r\nwhisper-1\r\n")
    );
    Ok(())
}

#[tokio::test]
async fn files_are_stored_locally_and_not_forwarded() -> Result<()> {
    let mut fixture = Fixture::start(vec![]).await?;
    let gateway = Gateway::start("openai", &fixture.base, "unused", None).await?;
    let body = "--bound\r\nContent-Disposition: form-data; name=\"purpose\"\r\n\r\nuser_data\r\n--bound\r\nContent-Disposition: form-data; name=\"file\"; filename=\"note.txt\"\r\nContent-Type: text/plain\r\n\r\nhello\r\n--bound--\r\n";
    let created = gateway
        .client
        .post(format!("{}/v1/files", gateway.base))
        .header("x-infer-key", &gateway.proxy_token)
        .header("content-type", "multipart/form-data; boundary=bound")
        .body(body)
        .send()
        .await?;
    assert_eq!(created.status(), StatusCode::OK);
    let created: Value = created.json().await?;
    let id = created["id"].as_str().unwrap();
    assert!(id.starts_with("file-"));
    assert!(created["provider_file_id"].is_null());
    assert!(fixture.captured.try_recv().is_err());
    let content = gateway
        .client
        .get(format!("{}/v1/files/{id}/content", gateway.base))
        .header("x-infer-key", &gateway.proxy_token)
        .send()
        .await?;
    assert_eq!(content.status(), StatusCode::OK);
    assert_eq!(content.text().await?, "hello");
    let removed = gateway
        .client
        .delete(format!("{}/v1/files/{id}", gateway.base))
        .header("x-infer-key", &gateway.proxy_token)
        .send()
        .await?;
    assert_eq!(removed.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn file_upload_keeps_bytes_that_look_like_a_boundary() -> Result<()> {
    let fixture = Fixture::start(vec![]).await?;
    let gateway = Gateway::start("openai", &fixture.base, "unused", None).await?;
    let payload = b"hello\r\n--not-the-boundary\r\nworld";
    let mut body = b"--bound\r\nContent-Disposition: form-data; name=\"purpose\"\r\n\r\nvision\r\n--bound\r\nContent-Disposition: form-data; name=\"file\"; filename=\"bin.dat\"\r\nContent-Type: application/octet-stream\r\n\r\n".to_vec();
    body.extend_from_slice(payload);
    body.extend_from_slice(b"\r\n--bound--\r\n");
    let created = gateway
        .client
        .post(format!("{}/v1/files", gateway.base))
        .header("x-infer-key", &gateway.proxy_token)
        .header("content-type", "multipart/form-data; boundary=bound")
        .body(body)
        .send()
        .await?;
    assert_eq!(created.status(), StatusCode::OK);
    let created: Value = created.json().await?;
    let id = created["id"].as_str().unwrap();
    let content = gateway
        .client
        .get(format!("{}/v1/files/{id}/content", gateway.base))
        .header("x-infer-key", &gateway.proxy_token)
        .send()
        .await?;
    assert_eq!(&content.bytes().await?[..], payload);
    Ok(())
}

#[tokio::test]
async fn routed_requests_upload_infer_files_and_swap_the_provider_id() -> Result<()> {
    let mut fixture = Fixture::start(vec![
        json_reply(json!({"id":"file-upstream","object":"file"})),
        json_reply(
            json!({"id":"chat","choices":[{"message":{"role":"assistant","content":"ok"}}]}),
        ),
        json_reply(
            json!({"id":"chat","choices":[{"message":{"role":"assistant","content":"again"}}]}),
        ),
    ])
    .await?;
    let gateway = Gateway::start("openai", &fixture.base, "unused", None).await?;
    let created = gateway
        .client
        .post(format!("{}/v1/files", gateway.base))
        .header("x-infer-key", &gateway.proxy_token)
        .header("content-type", "multipart/form-data; boundary=bound")
        .body("--bound\r\nContent-Disposition: form-data; name=\"purpose\"\r\n\r\nuser_data\r\n--bound\r\nContent-Disposition: form-data; name=\"file\"; filename=\"note.txt\"\r\nContent-Type: text/plain\r\n\r\nhello\r\n--bound--\r\n")
        .send()
        .await?;
    assert_eq!(created.status(), StatusCode::OK);
    let created: Value = created.json().await?;
    let id = created["id"].as_str().unwrap();
    let response = gateway
        .post(
            "/v1/chat/completions",
            &json!({"model":"gpt-4o","messages":[{"role":"user","content":[{"type":"text","text":id},{"type":"file","file":{"file_id":id}}]}]}),
        )
        .await?;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "{:?}",
        response.text().await
    );
    let upload = fixture.received().await?;
    assert_eq!(upload.path, "/v1/files");
    assert!(upload.body.windows(5).any(|window| window == b"hello"));
    let chat = fixture.received().await?;
    assert_eq!(chat.path, "/v1/chat/completions");
    let body: Value = serde_json::from_slice(&chat.body)?;
    assert_eq!(body["messages"][0]["content"][0]["text"], id);
    assert_eq!(
        body["messages"][0]["content"][1]["file"]["file_id"],
        "file-upstream"
    );
    let again = gateway
        .post(
            "/v1/chat/completions",
            &json!({"model":"gpt-4o","messages":[{"role":"user","content":[{"type":"file","file":{"file_id":id}}]}]}),
        )
        .await?;
    assert_eq!(again.status(), StatusCode::OK);
    let chat = fixture.received().await?;
    assert_eq!(chat.path, "/v1/chat/completions");
    Ok(())
}

#[tokio::test]
async fn deleted_infer_file_is_not_served_from_the_provider_cache() -> Result<()> {
    let fixture = Fixture::start(vec![
        json_reply(json!({"id":"file-upstream","object":"file"})),
        json_reply(
            json!({"id":"chat","choices":[{"message":{"role":"assistant","content":"ok"}}]}),
        ),
    ])
    .await?;
    let gateway = Gateway::start("openai", &fixture.base, "unused", None).await?;
    let created = gateway
        .client
        .post(format!("{}/v1/files", gateway.base))
        .header("x-infer-key", &gateway.proxy_token)
        .header("content-type", "multipart/form-data; boundary=bound")
        .body("--bound\r\nContent-Disposition: form-data; name=\"purpose\"\r\n\r\nuser_data\r\n--bound\r\nContent-Disposition: form-data; name=\"file\"; filename=\"note.txt\"\r\nContent-Type: text/plain\r\n\r\nhello\r\n--bound--\r\n")
        .send()
        .await?;
    let created: Value = created.json().await?;
    let id = created["id"].as_str().unwrap();
    let response = gateway
        .post(
            "/v1/chat/completions",
            &json!({"model":"gpt-4o","messages":[{"role":"user","content":[{"type":"file","file":{"file_id":id}}]}]}),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let removed = gateway
        .client
        .delete(format!("{}/v1/files/{id}", gateway.base))
        .header("x-infer-key", &gateway.proxy_token)
        .send()
        .await?;
    assert_eq!(removed.status(), StatusCode::OK);
    let again = gateway
        .post(
            "/v1/chat/completions",
            &json!({"model":"gpt-4o","messages":[{"role":"user","content":[{"type":"file","file":{"file_id":id}}]}]}),
        )
        .await?;
    assert_eq!(again.status(), StatusCode::BAD_REQUEST);
    let error: Value = again.json().await?;
    assert!(
        error["error"]["message"]
            .as_str()
            .unwrap()
            .contains("unknown infer file id"),
        "{error}"
    );
    Ok(())
}

#[tokio::test]
async fn declared_audio_passes_on_the_same_protocol_and_not_across_it() -> Result<()> {
    let mut fixture = Fixture::start(vec![json_reply(json!({"id":"chat","choices":[]}))]).await?;
    let gateway = Gateway::start("openai", &fixture.base, "unused", None).await?;
    let passed = gateway
        .post(
            "/v1/chat/completions",
            &json!({"model":"gpt-4o-audio-preview","messages":[{"role":"user","content":[{"type":"input_audio","input_audio":{"data":"YQ==","format":"wav"}}]}]}),
        )
        .await?;
    assert_eq!(passed.status(), StatusCode::OK);
    let captured = fixture.received().await?;
    let body: Value = serde_json::from_slice(&captured.body)?;
    assert_eq!(body["messages"][0]["content"][0]["type"], "input_audio");
    let translated = gateway
        .post(
            "/v1/messages",
            &json!({"model":"gpt-4o-audio-preview","max_tokens":8,"messages":[{"role":"user","content":[{"type":"input_audio","input_audio":{"data":"YQ==","format":"wav"}}]}]}),
        )
        .await?;
    assert_eq!(translated.status(), StatusCode::BAD_REQUEST);
    let error: Value = translated.json().await?;
    assert!(
        error["error"]["message"]
            .as_str()
            .unwrap()
            .contains("not translated"),
        "{error}"
    );
    assert!(fixture.captured.try_recv().is_err());
    Ok(())
}

#[tokio::test]
async fn realtime_websocket_proxies_frames_only_for_a_declared_model() -> Result<()> {
    use futures_util::{SinkExt, StreamExt};
    let fixture = Fixture::start(vec![]).await?;
    let gateway = Gateway::start("openai", &fixture.base, "unused", None).await?;
    let refused = realtime_request(&gateway, "gpt-4o").await;
    assert!(refused.is_err());
    let (mut socket, _) = realtime_request(&gateway, "gpt-realtime").await?;
    socket
        .send(tokio_tungstenite::tungstenite::Message::Text("ping".into()))
        .await?;
    let echoed = socket
        .next()
        .await
        .context("realtime proxy returned no frame")??;
    assert_eq!(echoed.to_text()?, "ping");
    Ok(())
}

async fn realtime_request(
    gateway: &Gateway,
    model: &str,
) -> Result<(
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    tokio_tungstenite::tungstenite::handshake::client::Response,
)> {
    let uri = format!(
        "{}/v1/realtime?model={model}",
        gateway.base.replace("http://", "ws://")
    );
    let request = tokio_tungstenite::tungstenite::http::Request::builder()
        .uri(uri)
        .header("x-infer-key", &gateway.proxy_token)
        .header("host", "127.0.0.1")
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .body(())
        .unwrap();
    Ok(tokio_tungstenite::connect_async(request).await?)
}
#[tokio::test]
async fn catalog_gates_embedding_and_system_one_media() -> Result<()> {
    let mut fixture = Fixture::start(vec![
        json_reply(json!({"object":"list","data":[{"embedding":[0.1],"index":0}],"model":"gemma"})),
        json_reply(json!({"model":"jev-latest","answers":{"mug":{"type":"box","box":{"top":0.1,"bottom":0.2,"left":0.3,"right":0.4},"confidence":0.9}}})),
    ])
    .await?;
    let openai = Gateway::start("openai", &fixture.base, "unused", None).await?;
    let rejected = openai
        .post(
            "/v1/embeddings",
            &json!({"model":"text-embedding-3-small","input":[{"content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,YQ=="}}]}]}),
        )
        .await?;
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    assert!(fixture.captured.try_recv().is_err());

    let llama = Gateway::start("llama", &fixture.base, "unused", None).await?;
    let response = llama
        .post(
            "/v1/embeddings",
            &json!({"model":"ggml-org/embeddinggemma-2-GGUF:Q8_0","input":[{"content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,YQ=="}}]}]}),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let captured = fixture.received().await?;
    assert_eq!(captured.path, "/v1/embeddings");
    let upstream: Value = serde_json::from_slice(&captured.body)?;
    assert_eq!(upstream["input"][0]["content"][0]["type"], "image_url");

    let typesafe = Gateway::start("system_one", &fixture.base, "unused", None).await?;
    let rejected = typesafe
        .client
        .post(format!("{}/v1/systemone", typesafe.base))
        .header("x-infer-key", &typesafe.proxy_token)
        .header("TypeSafe-Danger-Zone-Images", "true")
        .json(&json!({"model":"jev-1.13","state":"x","questions":{"mug":{"type":"box","instructions":"mug"}}}))
        .send()
        .await?;
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    assert!(fixture.captured.try_recv().is_err());

    let response = typesafe
        .client
        .post(format!("{}/v1/systemone", typesafe.base))
        .header("x-infer-key", &typesafe.proxy_token)
        .header("TypeSafe-Danger-Zone-Images", "true")
        .json(&json!({
            "model":"jev-latest",
            "state":{"photo":"img"},
            "assets":{"img":{"type":"image","format":"jpg","data_base64":"YQ=="}},
            "questions":{"mug":{"type":"box","instructions":"the mug in `photo`"}}
        }))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let captured = fixture.received().await?;
    assert_eq!(captured.path, "/v1/systemone");
    assert_eq!(captured.headers["typesafe-danger-zone-images"], "true");
    Ok(())
}

#[tokio::test]
async fn system_one_to_decisions_translates_request_and_response() -> Result<()> {
    let mut fixture = Fixture::start(vec![json_reply(json!({
        "model":"gpt-6-luna",
        "answers":[{"name":"damaged","type":"predicate","probability":0.25}],
        "usage":{"input_tokens":3,"output_tokens":1}
    }))])
    .await?;
    let gateway = Gateway::start("openai_decisions", &fixture.base, "gpt-6-luna", None).await?;
    let response = gateway
        .post(
            "/v1/systemone",
            &json!({"model":"validation","state":"Inspect","questions":{"damaged":{"type":"noul","instructions":"Damaged?"}}}),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await?;
    assert_eq!(body["answers"]["damaged"]["noul"], 0.25);
    let captured = fixture.received().await?;
    assert_eq!(captured.path, "/v1/decisions");
    let upstream: Value = serde_json::from_slice(&captured.body)?;
    assert_eq!(upstream["model"], "gpt-6-luna");
    assert_eq!(upstream["input"], "Inspect");
    assert_eq!(upstream["questions"][0]["type"], "predicate");
    Ok(())
}

#[tokio::test]
async fn decisions_to_local_system_one_translates_request_and_response() -> Result<()> {
    let mut fixture = Fixture::start(vec![json_reply(json!({
        "model":"ggml-org/Kev-0.8B-GGUF:Q8_0",
        "answers":{"damaged":{"type":"noul","noul":0.91}},
        "usage":{"input_tokens":21,"output_tokens":0}
    }))])
    .await?;
    let gateway =
        Gateway::start("llama", &fixture.base, "ggml-org/Kev-0.8B-GGUF:Q8_0", None).await?;
    let response = gateway
        .post(
            "/v1/decisions",
            &json!({
                "model":"validation",
                "input":"Inspect this item",
                "questions":[{"type":"predicate","name":"damaged","instructions":"Is it damaged?"}]
            }),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await?;
    assert_eq!(body["answers"][0]["type"], "predicate");
    assert_eq!(body["answers"][0]["name"], "damaged");
    assert_eq!(body["answers"][0]["probability"], 0.91);
    let captured = fixture.received().await?;
    assert_eq!(captured.path, "/v1/systemone");
    let upstream: Value = serde_json::from_slice(&captured.body)?;
    assert_eq!(upstream["model"], "ggml-org/Kev-0.8B-GGUF:Q8_0");
    assert_eq!(upstream["state"], "Inspect this item");
    assert_eq!(upstream["questions"]["damaged"]["type"], "noul");
    Ok(())
}

#[tokio::test]
async fn openai_decisions_explicit_provider_path_stays_schema_free() -> Result<()> {
    let mut fixture = Fixture::start(vec![json_reply(json!({"native":true}))]).await?;
    let gateway = Gateway::start("openai_decisions", &fixture.base, "gpt-6-luna", None).await?;
    let wire = b"not JSON and no model";
    let response = gateway
        .client
        .post(format!(
            "{}/providers/backend/v1/decisions?native=1",
            gateway.base
        ))
        .header("x-infer-key", &gateway.proxy_token)
        .header("content-type", "application/octet-stream")
        .body(wire.as_slice())
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let captured = fixture.received().await?;
    assert_eq!(captured.path, "/v1/decisions");
    assert_eq!(captured.body, wire);
    Ok(())
}

#[tokio::test]
async fn c01_responses_null_stream_matches_omission_for_anthropic_backend() -> Result<()> {
    let success = || {
        json_reply(json!({
            "id":"msg_fixture",
            "type":"message",
            "role":"assistant",
            "model":"upstream",
            "content":[{"type":"text","text":"fixture answer"}],
            "stop_reason":"end_turn",
            "stop_sequence":null,
            "usage":{"input_tokens":3,"output_tokens":2}
        }))
    };
    let mut fixture = Fixture::start_strict_stream(vec![success(), success(), success()]).await?;
    let gateway = Gateway::start("anthropic", &fixture.base, "upstream", None).await?;
    let common = json!({"model":"validation","input":"hello","max_output_tokens":32,"store":false});

    for stream in [Some(Value::Null), None, Some(json!(false))] {
        let mut request = common.clone();
        if let Some(stream) = stream {
            request["stream"] = stream;
        }
        let response = gateway.post("/v1/responses", &request).await?;
        let id = trace_id(&response)?;
        assert_eq!(response.status(), StatusCode::OK);
        let value: Value = response.json().await?;
        assert_eq!(value["output"][0]["content"][0]["text"], "fixture answer");
        assert_eq!(completed_trace(&gateway, &id).await?["error"], Value::Null);

        let received = fixture.received().await?;
        assert_eq!(received.path, "/v1/messages");
        let upstream: Value = serde_json::from_slice(&received.body)?;
        if request["stream"] == false {
            assert_eq!(upstream["stream"], false);
        } else {
            assert!(upstream.get("stream").is_none());
        }
    }

    let mut streamed = common;
    streamed["stream"] = json!(true);
    let response = gateway.post("/v1/responses", &streamed).await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(fixture.captured.try_recv().is_err());

    let native = br#"{"model":"upstream","max_tokens":32,"messages":[],"stream":null}"#;
    let response = gateway
        .client
        .post(format!("{}/providers/backend/v1/messages", gateway.base))
        .header("x-infer-key", &gateway.proxy_token)
        .header("content-type", "application/json")
        .body(native.as_slice())
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        response.bytes().await?.as_ref(),
        br#"{"error":{"message":"stream must be boolean"}}"#
    );
    let received = fixture.received().await?;
    assert_eq!(received.path, "/v1/messages");
    assert_eq!(received.body, native);
    Ok(())
}
#[tokio::test]
async fn n01_interrupted_routed_and_native_uploads_preserve_only_prefix_and_incomplete_trace()
-> Result<()> {
    let mut fixture = Fixture::start(vec![json_reply(json!({"ok":true}))]).await?;
    let gateway = Gateway::start("llama", &fixture.base, "upstream", None).await?;
    for (path, prefix) in [
        (
            "/v1/chat/completions",
            br#"{"model":"validation","messages":["#.as_slice(),
        ),
        (
            "/providers/backend/v1/chat/completions",
            br#"{"native":"prefix""#.as_slice(),
        ),
    ] {
        let response = interrupted_upload(&gateway, path, prefix, prefix.len() + 128).await?;
        assert_eq!(
            response.status,
            400,
            "{}",
            String::from_utf8_lossy(&response.bytes)
        );
        let trace = gateway.trace(&response.trace_id).await?;
        assert_eq!(trace["complete"], false);
        assert_eq!(gateway.body(&response.trace_id, "request").await?, prefix);
        assert_eq!(gateway.body(&response.trace_id, "response").await?, b"");
        let exported = gateway.export().await?;
        let row = exported
            .iter()
            .find(|row| row["metadata"]["id"] == response.trace_id)
            .context("interrupted trace missing from export")?;
        assert_eq!(row["metadata"]["complete"], false);
        assert_eq!(row["bodies"]["response"]["size"], 0);
    }
    let native = fixture.received().await?;
    assert_eq!(native.path, "/v1/chat/completions");
    Ok(())
}

#[tokio::test]
async fn n02_n13_codex_check_distinguishes_credentials_and_rejects_fifo_without_blocking()
-> Result<()> {
    let root = tempfile::tempdir()?;
    let ready = root.path().join("ready.json");
    let refreshable = root.path().join("refreshable.json");
    std::fs::write(
        &ready,
        br#"{"tokens":{"access_token":"opaque","account_id":"acct"}}"#,
    )?;
    std::fs::write(
        &refreshable,
        br#"{"tokens":{"refresh_token":"refreshable-token"}}"#,
    )?;
    assert!(run_codex_command(&root, &ready, "check").await?);
    assert!(run_codex_command(&root, &refreshable, "check").await?);

    for (name, bytes) in [
        ("malformed.json", b"{".as_slice()),
        ("missing.json", br#"{"other":true}"#.as_slice()),
        (
            "unusable.json",
            br#"{"tokens":{"access_token":""}}"#.as_slice(),
        ),
    ] {
        let path = root.path().join(name);
        std::fs::write(&path, bytes)?;
        assert!(
            !run_codex_command(&root, &path, "check").await?,
            "accepted {name}"
        );
    }

    #[cfg(unix)]
    {
        let fifo = root.path().join("auth.fifo");
        let path = CString::new(fifo.as_os_str().as_encoded_bytes())?;
        let result = unsafe { libc::mkfifo(path.as_ptr(), 0o600) };
        if result != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        assert!(!run_codex_command(&root, &fifo, "check").await?);
        assert!(!run_codex_command(&root, &fifo, "serve").await?);

        let alias = root.path().join("current-auth.json");
        std::os::unix::fs::symlink(&ready, &alias)?;
        let mut fixture = Fixture::start(Vec::new()).await?;
        let gateway = Gateway::start("codex", &fixture.base, "upstream", Some(&alias)).await?;
        std::fs::remove_file(&alias)?;
        std::os::unix::fs::symlink(&fifo, &alias)?;
        let response = gateway
            .post(
                "/providers/backend/responses",
                &json!({"model":"upstream","stream":true,"store":false}),
            )
            .await?;
        let id = trace_id(&response)?;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let _ = response.bytes().await?;
        assert!(completed_trace(&gateway, &id).await?["error"].is_string());
        assert!(fixture.captured.try_recv().is_err());
    }
    Ok(())
}

async fn run_codex_command(root: &TempDir, auth_file: &Path, command: &str) -> Result<bool> {
    let config = root
        .path()
        .join(format!("{command}-{}.toml", Uuid::new_v4()));
    let inference = std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?;
    let mut control = std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?;
    while control == inference {
        control = std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?;
    }
    let proxy_env = format!("INFER_CHECK_PROXY_{}", Uuid::new_v4().simple());
    let control_env = format!("INFER_CHECK_CONTROL_{}", Uuid::new_v4().simple());
    std::fs::write(
        &config,
        format!(
            "listen = \"{inference}\"\ncontrol_listen = \"{control}\"\nproxy_token_env = \"{proxy_env}\"\ncontrol_token_env = \"{control_env}\"\ntrace_dir = {:?}\ndefault_provider = \"backend\"\n[providers.backend]\nkind = \"codex\"\nbase_url = \"http://127.0.0.1:3/backend-api/codex\"\n[providers.backend.auth]\nmode = \"codex\"\nauth_file = {:?}\n",
            root.path().join("check-traces"),
            auth_file
        ),
    )?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_infer"))
        .arg("--config")
        .arg(config)
        .arg(command)
        .env(&proxy_env, format!("proxy-{}", Uuid::new_v4()))
        .env(&control_env, format!("control-{}", Uuid::new_v4()))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let status = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(status) = child.try_wait()? {
                return Ok::<_, std::io::Error>(status.success());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    match status {
        Ok(status) => Ok(status?),
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(anyhow!(
                "Codex {command} blocked or accepted auth_file instead of rejecting it"
            ))
        }
    }
}

#[tokio::test]
async fn c02_dotted_opaque_codex_tokens_work_with_explicit_or_claimed_accounts() -> Result<()> {
    const ID_TOKEN: &str = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9hY2NvdW50X2lkIjoiY2xhaW1lZC1hY2NvdW50In19.signature";
    let root = tempfile::tempdir()?;
    let cases = [
        (
            "file-account.json",
            "opaque.access-token",
            Some("file-account"),
            None,
            None,
            "file-account",
        ),
        (
            "configured-account.json",
            "opaque.access.token",
            None,
            Some("configured-account"),
            None,
            "configured-account",
        ),
        (
            "claimed-account.json",
            "opaque.access.token",
            None,
            None,
            Some(ID_TOKEN),
            "claimed-account",
        ),
    ];
    for (name, access, file_account, configured_account, id_token, expected_account) in cases {
        let path = root.path().join(name);
        let mut tokens = json!({"access_token":access});
        if let Some(account) = file_account {
            tokens["account_id"] = json!(account);
        }
        if let Some(id_token) = id_token {
            tokens["id_token"] = json!(id_token);
        }
        std::fs::write(&path, serde_json::to_vec(&json!({"tokens":tokens}))?)?;

        if configured_account.is_none() {
            assert!(run_codex_command(&root, &path, "check").await?, "{name}");
        }
        let mut fixture = Fixture::start(vec![sse_reply(responses_text_stream(None))]).await?;
        let gateway = Gateway::start_with_account(
            "codex",
            &fixture.base,
            "upstream",
            Some(&path),
            configured_account,
        )
        .await?;
        let response = gateway
            .post(
                "/v1/responses",
                &json!({"model":"validation","input":"hello","max_output_tokens":32,"stream":false}),
            )
            .await?;
        let id = trace_id(&response)?;
        assert_eq!(response.status(), StatusCode::OK);
        let value: Value = response.json().await?;
        assert_eq!(value["output"][0]["content"][0]["text"], "hello");
        let trace = completed_trace(&gateway, &id).await?;
        assert_eq!(trace["error"], Value::Null);
        assert_eq!(trace["upstream_headers"]["authorization"], "[REDACTED]");
        assert_eq!(
            trace["upstream_headers"]["chatgpt-account-id"],
            "[REDACTED]"
        );

        let received = fixture.received().await?;
        assert_eq!(received.path, "/backend-api/codex/responses");
        assert_eq!(
            received.headers["authorization"],
            format!("Bearer {access}")
        );
        assert_eq!(received.headers["chatgpt-account-id"], expected_account);
        let upstream: Value = serde_json::from_slice(&received.body)?;
        assert_eq!(upstream["stream"], true);
    }

    for (name, document) in [
        (
            "missing-account.json",
            json!({"tokens":{"access_token":"opaque.access.token"}}),
        ),
        (
            "recognizable-malformed.json",
            json!({"tokens":{"access_token":"eyJhbGciOiJub25lIn0.not-base64.signature","account_id":"acct"}}),
        ),
        (
            "recognizable-invalid-exp.json",
            json!({"tokens":{"access_token":"eyJhbGciOiJub25lIn0.eyJleHAiOiJsYXRlciJ9.signature","account_id":"acct"}}),
        ),
    ] {
        let path = root.path().join(name);
        std::fs::write(&path, serde_json::to_vec(&document)?)?;
        assert!(
            !run_codex_command(&root, &path, "check").await?,
            "accepted {name}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn n03_streamed_responses_logprobs_normalize_absent_values_and_reject_unsupported_values()
-> Result<()> {
    let auth_root = tempfile::tempdir()?;
    let auth = valid_codex_auth(auth_root.path())?;
    for path in ["/v1/chat/completions", "/v1/messages"] {
        for logprobs in [None, Some(Value::Null), Some(json!([]))] {
            let fixture = Fixture::start(vec![sse_reply(responses_text_stream(logprobs))]).await?;
            let gateway = Gateway::start("codex", &fixture.base, "upstream", Some(&auth)).await?;
            let body = if path.ends_with("messages") {
                anthropic_request(true)
            } else {
                chat_request(true)
            };
            let response = gateway.post(path, &body).await?;
            let id = trace_id(&response)?;
            let (bytes, error) = collect(response).await;
            assert!(error.is_none());
            assert!(String::from_utf8_lossy(&bytes).contains("hello"));
            let events = sse_events(&bytes)?;
            assert!(
                events.iter().any(|event| event.data == "[DONE]")
                    || events
                        .iter()
                        .any(|event| event.event.as_deref() == Some("message_stop"))
            );
            assert_eq!(completed_trace(&gateway, &id).await?["error"], Value::Null);
        }
        for logprobs in [json!([{"token":"hello"}]), json!({}), json!(false)] {
            let fixture =
                Fixture::start(vec![sse_reply(responses_text_stream(Some(logprobs)))]).await?;
            let gateway = Gateway::start("codex", &fixture.base, "upstream", Some(&auth)).await?;
            let body = if path.ends_with("messages") {
                anthropic_request(true)
            } else {
                chat_request(true)
            };
            let response = gateway.post(path, &body).await?;
            let id = trace_id(&response)?;
            let (bytes, error) = collect(response).await;
            assert!(error.is_some());
            assert!(
                !sse_events(&bytes)?
                    .iter()
                    .any(|event| event.data == "[DONE]"
                        || event.event.as_deref() == Some("message_stop"))
            );
            assert!(completed_trace(&gateway, &id).await?["error"].is_string());
        }
    }
    Ok(())
}

#[tokio::test]
async fn n04_n11_responses_streams_emit_canonical_text_tools_and_anthropic_tool_terminal()
-> Result<()> {
    let auth_root = tempfile::tempdir()?;
    let auth = valid_codex_auth(auth_root.path())?;
    for path in ["/v1/chat/completions", "/v1/messages"] {
        let mut fixture = Fixture::start(vec![sse_reply(responses_ordered_stream())]).await?;
        let gateway = Gateway::start("codex", &fixture.base, "upstream", Some(&auth)).await?;
        let body = if path.ends_with("messages") {
            anthropic_request(true)
        } else {
            chat_request(true)
        };
        let response = gateway.post(path, &body).await?;
        let id = trace_id(&response)?;
        let (bytes, error) = collect(response).await;
        assert!(error.is_none());
        let values: Vec<Value> = sse_events(&bytes)?
            .into_iter()
            .filter(|event| event.data != "[DONE]")
            .map(|event| serde_json::from_str(&event.data))
            .collect::<std::result::Result<_, _>>()?;
        if path.ends_with("messages") {
            let starts: Vec<_> = values
                .iter()
                .filter(|value| value["type"] == "content_block_start")
                .map(|value| value["content_block"]["type"].as_str().unwrap())
                .collect();
            assert_eq!(starts, ["text", "text", "tool_use"]);
            assert_eq!(
                values
                    .iter()
                    .find(|value| value["type"] == "message_delta")
                    .unwrap()["delta"]["stop_reason"],
                "tool_use"
            );
            let tool = values
                .iter()
                .find(|value| value["content_block"]["type"] == "tool_use")
                .unwrap();
            assert_eq!(tool["content_block"]["id"], "call_later");
            assert_eq!(tool["content_block"]["name"], "later");
            let arguments: String = values
                .iter()
                .filter_map(|value| value["delta"]["partial_json"].as_str())
                .collect();
            assert_eq!(serde_json::from_str::<Value>(&arguments)?, json!({"y":2}));
        } else {
            let mut text = String::new();
            let mut tool_seen = false;
            for value in &values {
                if let Some(fragment) = value["choices"][0]["delta"]["content"].as_str() {
                    assert!(!tool_seen);
                    text.push_str(fragment);
                }
                tool_seen |= value["choices"][0]["delta"]["tool_calls"].is_array();
            }
            assert_eq!(text, "firsttail");
            assert!(tool_seen);
            let calls: Vec<&Value> = values
                .iter()
                .filter_map(|value| value["choices"][0]["delta"]["tool_calls"].as_array())
                .flatten()
                .collect();
            assert_eq!(
                calls.iter().find_map(|call| call["id"].as_str()),
                Some("call_later")
            );
            assert_eq!(
                calls
                    .iter()
                    .find_map(|call| call["function"]["name"].as_str()),
                Some("later")
            );
            let arguments: String = calls
                .iter()
                .filter_map(|call| call["function"]["arguments"].as_str())
                .collect();
            assert_eq!(serde_json::from_str::<Value>(&arguments)?, json!({"y":2}));
            assert!(
                values
                    .iter()
                    .any(|value| value["choices"][0]["finish_reason"] == "tool_calls")
            );
        }
        assert_eq!(completed_trace(&gateway, &id).await?["error"], Value::Null);
        let received = fixture.received().await?;
        assert_eq!(received.path, "/backend-api/codex/responses");
    }
    Ok(())
}

#[tokio::test]
async fn n05_chat_usage_chunk_obeys_true_false_and_omitted_for_both_backends() -> Result<()> {
    let anthropic = [
        anthropic_frame("message_start", json!({"type":"message_start","message":{"id":"m","content":[],"usage":{"input_tokens":5,"output_tokens":0}}})),
        anthropic_frame("content_block_start", json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}})),
        anthropic_frame("content_block_delta", json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello"}})),
        anthropic_frame("content_block_stop", json!({"type":"content_block_stop","index":0})),
        anthropic_frame("message_delta", json!({"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":2}})),
        anthropic_frame("message_stop", json!({"type":"message_stop"})),
    ].concat();
    let auth_root = tempfile::tempdir()?;
    let auth = valid_codex_auth(auth_root.path())?;
    for backend in ["anthropic", "codex"] {
        for preference in [None, Some(false), Some(true)] {
            let stream = if backend == "anthropic" {
                anthropic.clone()
            } else {
                responses_text_stream(None)
            };
            let fixture = Fixture::start(vec![sse_reply(stream)]).await?;
            let gateway = Gateway::start(
                backend,
                &fixture.base,
                "upstream",
                (backend == "codex").then_some(auth.as_path()),
            )
            .await?;
            let mut request = chat_request(true);
            if let Some(include_usage) = preference {
                request["stream_options"] = json!({"include_usage":include_usage});
            }
            let response = gateway.post("/v1/chat/completions", &request).await?;
            let (bytes, error) = collect(response).await;
            assert!(error.is_none());
            let usage = sse_events(&bytes)?
                .into_iter()
                .filter(|event| event.data != "[DONE]")
                .map(|event| serde_json::from_str::<Value>(&event.data))
                .collect::<std::result::Result<Vec<_>, _>>()?
                .into_iter()
                .filter(|value| {
                    value["choices"].as_array().is_some_and(Vec::is_empty)
                        && value.get("usage").is_some()
                })
                .count();
            assert_eq!(
                usage,
                usize::from(preference == Some(true)),
                "{backend} {preference:?}"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn n06_responses_terminals_reject_contradictions_and_accept_valid_incomplete() -> Result<()> {
    let auth_root = tempfile::tempdir()?;
    let auth = valid_codex_auth(auth_root.path())?;
    let invalid = [
        (
            "response.completed",
            json!({"status":"failed","error":null,"output":[],"usage":{}}),
        ),
        (
            "response.completed",
            json!({"status":"completed","error":{"message":"failed"},"output":[],"usage":{}}),
        ),
        (
            "response.incomplete",
            json!({"status":"completed","error":null,"output":[],"usage":{},"incomplete_details":{"reason":"max_output_tokens"}}),
        ),
        (
            "response.incomplete",
            json!({"status":"incomplete","error":{"message":"failed"},"output":[],"usage":{},"incomplete_details":{"reason":"max_output_tokens"}}),
        ),
    ];
    for path in ["/v1/chat/completions", "/v1/messages"] {
        for (event, snapshot) in &invalid {
            let fixture = Fixture::start(vec![sse_reply(frame(
                event,
                json!({"type":event,"response":snapshot}),
            ))])
            .await?;
            let gateway = Gateway::start("codex", &fixture.base, "upstream", Some(&auth)).await?;
            let body = if path.ends_with("messages") {
                anthropic_request(true)
            } else {
                chat_request(true)
            };
            let response = gateway.post(path, &body).await?;
            let id = trace_id(&response)?;
            let (bytes, error) = collect(response).await;
            assert!(error.is_some());
            assert!(
                !sse_events(&bytes)?
                    .iter()
                    .any(|event| event.data == "[DONE]"
                        || event.event.as_deref() == Some("message_stop"))
            );
            assert!(completed_trace(&gateway, &id).await?["error"].is_string());
        }
        let valid = json!({"status":"incomplete","error":null,"output":[],"usage":{},"incomplete_details":{"reason":"max_output_tokens"}});
        let fixture = Fixture::start(vec![sse_reply(frame(
            "response.incomplete",
            json!({"type":"response.incomplete","response":valid}),
        ))])
        .await?;
        let gateway = Gateway::start("codex", &fixture.base, "upstream", Some(&auth)).await?;
        let body = if path.ends_with("messages") {
            anthropic_request(true)
        } else {
            chat_request(true)
        };
        let response = gateway.post(path, &body).await?;
        let id = trace_id(&response)?;
        let (bytes, error) = collect(response).await;
        assert!(error.is_none());
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains(if path.ends_with("messages") {
            "max_tokens"
        } else {
            "length"
        }));
        assert_eq!(completed_trace(&gateway, &id).await?["error"], Value::Null);
    }
    Ok(())
}

#[tokio::test]
async fn n07_buffered_responses_text_refusal_text_interleaving_fails_explicitly() -> Result<()> {
    let auth_root = tempfile::tempdir()?;
    let auth = valid_codex_auth(auth_root.path())?;
    let response = json!({"id":"r","status":"completed","error":null,"output":[{"type":"message","role":"assistant","content":[
        {"type":"output_text","text":"A","annotations":[]},{"type":"refusal","refusal":"B"},{"type":"output_text","text":"C","annotations":[]}
    ]}],"usage":{}});
    let fixture = Fixture::start(vec![sse_reply(frame(
        "response.completed",
        json!({"type":"response.completed","response":response}),
    ))])
    .await?;
    let gateway = Gateway::start("codex", &fixture.base, "upstream", Some(&auth)).await?;
    let response = gateway
        .post("/v1/chat/completions", &chat_request(false))
        .await?;
    let id = trace_id(&response)?;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let body: Value = response.json().await?;
    assert!(body["error"].is_object());
    assert!(completed_trace(&gateway, &id).await?["error"].is_string());
    Ok(())
}

#[tokio::test]
async fn n08_nested_usage_rejects_malformed_accepts_null_and_valid_and_preserves_native()
-> Result<()> {
    let base_chat = json!({"id":"c","choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":3,"completion_tokens":2}});
    for detail in [
        Value::Null,
        json!({"cached_tokens":null}),
        json!({"cached_tokens":7}),
    ] {
        let mut value = base_chat.clone();
        value["usage"]["prompt_tokens_details"] = detail;
        let fixture = Fixture::start(vec![json_reply(value)]).await?;
        let gateway = Gateway::start("llama", &fixture.base, "upstream", None).await?;
        assert_eq!(
            gateway
                .post("/v1/messages", &anthropic_request(false))
                .await?
                .status(),
            StatusCode::OK
        );
    }
    for malformed in [json!("bad"), json!({"cached_tokens":-1})] {
        let mut value = base_chat.clone();
        value["usage"]["prompt_tokens_details"] = malformed;
        let fixture = Fixture::start(vec![json_reply(value)]).await?;
        let gateway = Gateway::start("llama", &fixture.base, "upstream", None).await?;
        assert_eq!(
            gateway
                .post("/v1/messages", &anthropic_request(false))
                .await?
                .status(),
            StatusCode::BAD_GATEWAY
        );
    }

    let auth_root = tempfile::tempdir()?;
    let auth = valid_codex_auth(auth_root.path())?;
    let base_responses = json!({
        "id":"r","status":"completed","error":null,
        "output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"ok","annotations":[]}]}],
        "usage":{"input_tokens":3,"output_tokens":2}
    });
    for detail in [
        Value::Null,
        json!({"reasoning_tokens":null}),
        json!({"reasoning_tokens":7}),
    ] {
        let mut value = base_responses.clone();
        value["usage"]["output_tokens_details"] = detail;
        let fixture = Fixture::start(vec![json_reply(value)]).await?;
        let gateway = Gateway::start("codex", &fixture.base, "upstream", Some(&auth)).await?;
        assert_eq!(
            gateway
                .post("/v1/chat/completions", &chat_request(false))
                .await?
                .status(),
            StatusCode::OK
        );
    }
    for malformed in [json!([]), json!({"reasoning_tokens":"7"})] {
        let mut value = base_responses.clone();
        value["usage"]["output_tokens_details"] = malformed;
        let fixture = Fixture::start(vec![json_reply(value)]).await?;
        let gateway = Gateway::start("codex", &fixture.base, "upstream", Some(&auth)).await?;
        assert_eq!(
            gateway
                .post("/v1/chat/completions", &chat_request(false))
                .await?
                .status(),
            StatusCode::BAD_GATEWAY
        );
    }
    let mut native = base_chat;
    native["usage"]["prompt_tokens_details"] = json!("malformed-native");
    let wire = serde_json::to_vec(&native)?;
    let fixture = Fixture::start(vec![Reply {
        status: StatusCode::OK,
        content_type: Some("application/json"),
        chunks: vec![wire.clone()],
        headers: vec![],
        gates: None,
    }])
    .await?;
    let gateway = Gateway::start("llama", &fixture.base, "upstream", None).await?;
    let response = gateway
        .post(
            "/providers/backend/v1/chat/completions",
            &json!({"native":true}),
        )
        .await?;
    assert_eq!(response.bytes().await?.as_ref(), wire.as_slice());
    Ok(())
}

#[tokio::test]
async fn n09_refusal_terminal_conflicts_fail_while_compatible_refusal_remains_classified()
-> Result<()> {
    for reason in ["length", "tool_calls"] {
        let chat = json!({"choices":[{"finish_reason":reason,"message":{"role":"assistant","content":null,"refusal":"denied"}}],"usage":{}});
        let fixture = Fixture::start(vec![json_reply(chat)]).await?;
        let gateway = Gateway::start("llama", &fixture.base, "upstream", None).await?;
        assert_eq!(
            gateway
                .post("/v1/messages", &anthropic_request(false))
                .await?
                .status(),
            StatusCode::BAD_GATEWAY
        );
    }
    let compatible = json!({"choices":[{"finish_reason":"content_filter","message":{"role":"assistant","content":null,"refusal":"denied"}}],"usage":{}});
    let fixture = Fixture::start(vec![json_reply(compatible)]).await?;
    let gateway = Gateway::start("llama", &fixture.base, "upstream", None).await?;
    let value: Value = gateway
        .post("/v1/messages", &anthropic_request(false))
        .await?
        .json()
        .await?;
    assert_eq!(value["stop_reason"], "refusal");
    assert_eq!(value["content"][0]["text"], "denied");

    let auth_root = tempfile::tempdir()?;
    let auth = valid_codex_auth(auth_root.path())?;
    let refusal = json!({"type":"message","role":"assistant","content":[{"type":"refusal","refusal":"denied"}]});
    let conflicting = json!({
        "id":"r","status":"incomplete","error":null,"output":[refusal.clone()],"usage":{},
        "incomplete_details":{"reason":"max_output_tokens"}
    });
    for stream in [false, true] {
        let reply = if stream {
            sse_reply(frame(
                "response.incomplete",
                json!({"type":"response.incomplete","response":conflicting.clone()}),
            ))
        } else {
            json_reply(conflicting.clone())
        };
        let fixture = Fixture::start(vec![reply]).await?;
        let gateway = Gateway::start("codex", &fixture.base, "upstream", Some(&auth)).await?;
        let response = gateway
            .post("/v1/messages", &anthropic_request(stream))
            .await?;
        if stream {
            let id = trace_id(&response)?;
            let (bytes, error) = collect(response).await;
            assert!(error.is_some());
            assert!(
                !sse_events(&bytes)?
                    .iter()
                    .any(|event| event.event.as_deref() == Some("message_stop"))
            );
            assert!(completed_trace(&gateway, &id).await?["error"].is_string());
        } else {
            assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        }
    }
    let compatible = json!({
        "id":"r","status":"completed","error":null,"output":[refusal],"usage":{}
    });
    let fixture = Fixture::start(vec![json_reply(compatible)]).await?;
    let gateway = Gateway::start("codex", &fixture.base, "upstream", Some(&auth)).await?;
    let value: Value = gateway
        .post("/v1/messages", &anthropic_request(false))
        .await?
        .json()
        .await?;
    assert_eq!(value["stop_reason"], "refusal");
    Ok(())
}

#[tokio::test]
async fn n10_chat_tools_follow_indices_and_reject_gaps_and_aggregate_budget() -> Result<()> {
    let reversed = [
        chat_frame(json!({"tool_calls":[{"index":1,"id":"one","function":{"name":"second","arguments":"{\"n\":1}"}}]}), Value::Null),
        chat_frame(json!({"tool_calls":[{"index":0,"id":"zero","function":{"name":"first","arguments":"{\"n\":0}"}}]}), Value::Null),
        chat_frame(json!({}), json!("tool_calls")),
        b"data: [DONE]\n\n".to_vec(),
    ].concat();
    let fixture = Fixture::start(vec![sse_reply(reversed.clone())]).await?;
    let gateway = Gateway::start("llama", &fixture.base, "upstream", None).await?;
    let response = gateway
        .post("/v1/messages", &anthropic_request(true))
        .await?;
    let (bytes, error) = collect(response).await;
    assert!(error.is_none());
    let starts: Vec<Value> = sse_events(&bytes)?
        .into_iter()
        .filter_map(|event| serde_json::from_str::<Value>(&event.data).ok())
        .filter(|value| value["type"] == "content_block_start")
        .collect();
    assert_eq!(starts[0]["content_block"]["id"], "zero");
    assert_eq!(starts[1]["content_block"]["id"], "one");

    let gap = [chat_frame(json!({"tool_calls":[{"index":1,"id":"one","function":{"name":"second","arguments":"{}"}}]}), Value::Null), chat_frame(json!({}), json!("tool_calls")), b"data: [DONE]\n\n".to_vec()].concat();
    let fixture = Fixture::start(vec![sse_reply(gap)]).await?;
    let gateway = Gateway::start("llama", &fixture.base, "upstream", None).await?;
    let response = gateway
        .post("/v1/messages", &anthropic_request(true))
        .await?;
    let id = trace_id(&response)?;
    let (_, error) = collect(response).await;
    assert!(error.is_some());
    assert!(completed_trace(&gateway, &id).await?["error"].is_string());

    let megabyte = "x".repeat(1024 * 1024);
    let mut budget = chat_frame(
        json!({"tool_calls":[{"index":1,"id":"one","function":{"name":"second","arguments":""}}]}),
        Value::Null,
    );
    for _ in 0..8 {
        budget.extend(chat_frame(
            json!({"tool_calls":[{"index":1,"function":{"arguments":megabyte}}]}),
            Value::Null,
        ));
    }
    let fixture = Fixture::start(vec![sse_reply(budget)]).await?;
    let gateway = Gateway::start("llama", &fixture.base, "upstream", None).await?;
    let response = gateway
        .post("/v1/messages", &anthropic_request(true))
        .await?;
    let id = trace_id(&response)?;
    let (_, error) = collect(response).await;
    assert!(error.is_some());
    assert!(completed_trace(&gateway, &id).await?["error"].is_string());

    let fixture = Fixture::start(vec![sse_reply(reversed.clone())]).await?;
    let gateway = Gateway::start("llama", &fixture.base, "upstream", None).await?;
    let response = gateway
        .post(
            "/providers/backend/v1/chat/completions",
            &json!({"stream":true}),
        )
        .await?;
    assert_eq!(response.bytes().await?.as_ref(), reversed.as_slice());
    Ok(())
}

#[tokio::test]
async fn n12_late_anthropic_refusal_fails_closed_without_delaying_normal_first_delta() -> Result<()>
{
    for (reason, expect_success) in [("refusal", false), ("end_turn", true)] {
        let gates = Gates {
            prefix_sent: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
        };
        let prefix = [
            anthropic_frame("message_start", json!({"type":"message_start","message":{"id":"m","content":[],"usage":{"input_tokens":1,"output_tokens":0}}})),
            anthropic_frame("content_block_start", json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}})),
            anthropic_frame("content_block_delta", json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"visible-first"}})),
            anthropic_frame("content_block_stop", json!({"type":"content_block_stop","index":0})),
        ].concat();
        let terminal = [
            anthropic_frame("message_delta", json!({"type":"message_delta","delta":{"stop_reason":reason,"stop_sequence":null},"usage":{"output_tokens":1}})),
            anthropic_frame("message_stop", json!({"type":"message_stop"})),
        ].concat();
        let fixture = Fixture::start(vec![Reply {
            status: StatusCode::OK,
            content_type: Some("text/event-stream"),
            chunks: vec![prefix, terminal],
            headers: vec![],
            gates: Some(gates.clone()),
        }])
        .await?;
        let gateway = Gateway::start("anthropic", &fixture.base, "upstream", None).await?;
        let mut response = gateway
            .post("/v1/chat/completions", &chat_request(true))
            .await?;
        let id = trace_id(&response)?;
        let mut before_terminal = Vec::new();
        tokio::time::timeout(WAIT, async {
            loop {
                let chunk = response
                    .chunk()
                    .await?
                    .context("translated stream ended before first text delta")?;
                before_terminal.extend_from_slice(&chunk);
                if String::from_utf8_lossy(&before_terminal).contains("visible-first") {
                    return Ok::<_, anyhow::Error>(());
                }
            }
        })
        .await
        .map_err(|_| anyhow!("normal first delta was withheld behind terminal release"))??;
        tokio::time::timeout(WAIT, gates.prefix_sent.notified()).await?;
        gates.release.notify_one();
        let (rest, error) = collect(response).await;
        let events = sse_events(&[before_terminal, rest].concat())?;
        if expect_success {
            assert!(error.is_none());
            assert!(events.iter().any(|event| event.data == "[DONE]"));
            assert_eq!(completed_trace(&gateway, &id).await?["error"], Value::Null);
        } else {
            assert!(error.is_some());
            assert!(!events.iter().any(|event| event.data == "[DONE]"));
            assert!(completed_trace(&gateway, &id).await?["error"].is_string());
        }
    }
    Ok(())
}

#[test]
fn support_sse_parser_handles_bom_crlf_multiline_and_done() -> Result<()> {
    let events = sse_events(
        b"\xef\xbb\xbfevent: sample\r\ndata: first\r\ndata: second\r\n\r\ndata: [DONE]\r\n\r\n",
    )?;
    assert_eq!(events[0].event.as_deref(), Some("sample"));
    assert_eq!(events[0].data, "first\nsecond");
    assert_eq!(events[1].data, "[DONE]");
    assert!(
        sse_events(b"data: [DONE]\n")?.is_empty(),
        "an unterminated frame is not a success event"
    );
    Ok(())
}

#[tokio::test]
async fn v01_codex_nonstream_responses_never_leak_sse_as_successful_json() -> Result<()> {
    let auth_root = tempfile::tempdir()?;
    let auth = valid_codex_auth(auth_root.path())?;
    let wire = responses_text_stream(None);
    let mut violations = Vec::new();
    for media_type in [None, Some("application/json"), Some("text/event-stream")] {
        let replies = (0..5)
            .map(|_| Reply {
                status: StatusCode::OK,
                content_type: media_type,
                chunks: vec![wire.clone()],
                headers: vec![],
                gates: None,
            })
            .collect();
        let fixture = Fixture::start(replies).await?;
        let gateway = Gateway::start("codex", &fixture.base, "upstream", Some(&auth)).await?;
        let native = gateway
            .post(
                "/providers/backend/responses",
                &json!({
                    "model":"upstream","input":"hello","stream":true,"store":false
                }),
            )
            .await?;
        assert_eq!(native.status(), StatusCode::OK);
        assert_eq!(native.bytes().await?.as_ref(), wire.as_slice());
        let streamed = gateway
            .post(
                "/v1/responses",
                &json!({
                    "model":"validation","input":"hello","stream":true
                }),
            )
            .await?;
        assert_eq!(streamed.status(), StatusCode::OK);
        assert_eq!(streamed.bytes().await?.as_ref(), wire.as_slice());

        for (mode, stream) in [
            ("false", Some(json!(false))),
            ("null", Some(Value::Null)),
            ("omitted", None),
        ] {
            let mut body = json!({"model":"validation","input":"hello"});
            if let Some(stream) = stream {
                body["stream"] = stream;
            }
            let response = gateway.post("/v1/responses", &body).await?;
            let id = trace_id(&response)?;
            let status = response.status();
            let bytes = response.bytes().await?;
            let trace = completed_trace(&gateway, &id).await?;
            match status {
                StatusCode::OK => match serde_json::from_slice::<Value>(&bytes) {
                    Ok(value) => {
                        assert_eq!(value["status"], "completed");
                        assert_eq!(value["output"][0]["content"][0]["text"], "hello");
                        assert_eq!(trace["error"], Value::Null);
                    }
                    Err(_) => violations.push((media_type, mode)),
                },
                StatusCode::BAD_GATEWAY if media_type != Some("text/event-stream") => {
                    let error: Value = serde_json::from_slice(&bytes)?;
                    assert!(error["error"].is_object());
                    assert!(trace["error"].is_string());
                }
                _ => panic!(
                    "unexpected routed status {status} for upstream media type {media_type:?}"
                ),
            }
        }
    }
    assert!(
        violations.is_empty(),
        "non-streaming Responses returned HTTP 200 with SSE instead of JSON for upstream media types {violations:?}; reconstruct or fail explicitly"
    );
    Ok(())
}
