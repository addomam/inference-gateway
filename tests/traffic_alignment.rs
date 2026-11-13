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
use infer::traffic::{self, ActualRequest, Harness, assert_clean};
use serde_json::{Map, Value, json};
use support::Gateway;
use tokio::sync::Mutex as AsyncMutex;

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
        let response = request
            .json(&fixture.client.body)
            .send()
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
        // The recorded completion is "Hello!"; the source-derived fixtures use
        // lowercase. The check is the replayed word, not its capitalization.
        if !text.to_ascii_lowercase().contains("hello") {
            bail!(
                "{} client response did not contain the replayed text: {text}",
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
        }
        let _ = gateway;
    }
    Ok(())
}

#[tokio::test]
async fn empty_fixture_directory_is_not_a_pass() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let error = assert_clean(dir.path()).unwrap_err();
    assert!(error.to_string().contains("no fixtures"), "{error}");
    Ok(())
}
