//! Recording reverse proxy.
//!
//! The official CLI is pointed at this process with its own base URL. The proxy
//! forwards to the real origin, streams the response back, and keeps the request
//! and the full response body. It is not used by the replay test.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result};
use async_stream::stream;
use axum::{
    body::{Body, to_bytes},
    extract::{Request, State},
    response::Response,
};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

const BODY_LIMIT: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapturedExchange {
    pub method: String,
    pub path: String,
    pub query: String,
    pub request_headers: Map<String, Value>,
    pub request_body: Value,
    pub status: u16,
    pub response_headers: Map<String, Value>,
    pub response_body: Value,
}

pub struct RecordingProxy {
    pub base: String,
    captures: Arc<Mutex<Vec<CapturedExchange>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for RecordingProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl RecordingProxy {
    pub async fn start(upstream_origin: &str, timeout: Duration) -> Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .context("bind recording proxy")?;
        let address = listener.local_addr().context("recording proxy address")?;
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .context("recording proxy client")?;
        let captures = Arc::new(Mutex::new(Vec::new()));
        let state = ProxyState {
            origin: upstream_origin.trim_end_matches('/').to_owned(),
            client,
            captures: Arc::clone(&captures),
        };
        let task = tokio::spawn(async move {
            let app = axum::Router::new().fallback(record).with_state(state);
            let _ = axum::serve(listener, app).await;
        });
        Ok(Self {
            base: format!("http://{address}"),
            captures,
            task,
        })
    }

    pub fn exchanges(&self) -> Vec<CapturedExchange> {
        self.captures
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }
}

#[derive(Clone)]
struct ProxyState {
    origin: String,
    client: reqwest::Client,
    captures: Arc<Mutex<Vec<CapturedExchange>>>,
}

async fn record(State(state): State<ProxyState>, request: Request) -> Response {
    let method = request.method().as_str().to_owned();
    let path = request.uri().path().to_owned();
    let query = request.uri().query().unwrap_or("").to_owned();
    let request_headers = headers_json(request.headers());
    let Ok(bytes) = to_bytes(request.into_body(), BODY_LIMIT).await else {
        return Response::builder()
            .status(400)
            .body(Body::from("request body exceeds 32 MiB"))
            .unwrap_or_default();
    };
    let request_body = body_value(&bytes);
    let url = if query.is_empty() {
        format!("{}{path}", state.origin)
    } else {
        format!("{}{path}?{query}", state.origin)
    };
    let upstream_method =
        reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET);
    let mut builder = state.client.request(upstream_method, &url);
    for (name, value) in &request_headers {
        if forward_request_header(name) {
            builder = builder.header(name, value.as_str().unwrap_or_default());
        }
    }
    // The stored response is the uncompressed SSE. The CLI's own Accept-Encoding
    // is still in the capture; it is not forwarded, so the origin does not gzip it.
    builder = builder.header("accept-encoding", "identity");
    let upstream = match builder.body(bytes.to_vec()).send().await {
        Ok(response) => response,
        Err(error) => {
            let message = error.to_string();
            push(
                &state.captures,
                CapturedExchange {
                    method,
                    path,
                    query,
                    request_headers,
                    request_body,
                    status: 0,
                    response_headers: Map::new(),
                    response_body: Value::String(message.clone()),
                },
            );
            return Response::builder()
                .status(502)
                .body(Body::from(message))
                .unwrap_or_default();
        }
    };
    let status = upstream.status().as_u16();
    let response_headers = headers_json(upstream.headers());
    let recorded_headers = response_headers.clone();
    let (sender, receiver) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(8);
    let captures = Arc::clone(&state.captures);
    tokio::spawn(async move {
        let mut stream = upstream.bytes_stream();
        let mut body = Vec::new();
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(chunk) => {
                    body.extend_from_slice(&chunk);
                    if sender.send(Ok(chunk)).await.is_err() {
                        break;
                    }
                }
                Err(error) => {
                    let _ = sender
                        .send(Err(std::io::Error::other(error.to_string())))
                        .await;
                    break;
                }
            }
        }
        push(
            &captures,
            CapturedExchange {
                method,
                path,
                query,
                request_headers,
                request_body,
                status,
                response_headers: recorded_headers,
                response_body: body_value(&body),
            },
        );
    });
    let body = Body::from_stream(stream! {
        let mut receiver = receiver;
        while let Some(item) = receiver.recv().await {
            yield item.map_err(|error| -> Box<dyn std::error::Error + Send + Sync> {
                Box::new(error)
            });
        }
    });
    let mut response = Response::new(body);
    *response.status_mut() =
        axum::http::StatusCode::from_u16(status).unwrap_or(axum::http::StatusCode::BAD_GATEWAY);
    for (name, value) in response_headers {
        if forward_response_header(&name)
            && let Ok(header_name) = axum::http::HeaderName::try_from(name)
            && let Ok(header_value) =
                axum::http::HeaderValue::try_from(value.as_str().unwrap_or_default())
        {
            response.headers_mut().insert(header_name, header_value);
        }
    }
    response
}

fn push(captures: &Mutex<Vec<CapturedExchange>>, exchange: CapturedExchange) {
    captures
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .push(exchange);
}

fn headers_json(headers: &axum::http::HeaderMap) -> Map<String, Value> {
    let mut out = Map::new();
    for (name, value) in headers {
        let text = value.to_str().unwrap_or("<non-utf8>").to_owned();
        let key = name.as_str().to_ascii_lowercase();
        match out.get_mut(&key) {
            Some(Value::String(existing)) => {
                existing.push_str(", ");
                existing.push_str(&text);
            }
            _ => {
                out.insert(key, Value::String(text));
            }
        }
    }
    out
}

fn body_value(bytes: &[u8]) -> Value {
    if let Ok(value) = serde_json::from_slice::<Value>(bytes) {
        return value;
    }
    match String::from_utf8(bytes.to_vec()) {
        Ok(text) => Value::String(text),
        Err(error) => {
            use base64::Engine;
            json!({
                "base64": base64::engine::general_purpose::STANDARD.encode(error.as_bytes())
            })
        }
    }
}

fn forward_request_header(name: &str) -> bool {
    !matches!(
        name,
        "host"
            | "content-length"
            | "connection"
            | "transfer-encoding"
            | "accept-encoding"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "upgrade"
    )
}

fn forward_response_header(name: &str) -> bool {
    !matches!(
        name,
        "content-length"
            | "connection"
            | "transfer-encoding"
            | "content-encoding"
            | "keep-alive"
            | "trailer"
            | "upgrade"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn proxy_records_method_path_query_headers_body_and_the_stream() {
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let app = axum::Router::new().fallback(|request: Request| async move {
                let _ = to_bytes(request.into_body(), BODY_LIMIT).await;
                let stream = stream! {
                    yield Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"hello"));
                    yield Ok::<_, std::io::Error>(bytes::Bytes::from_static(b" stream"));
                };
                Response::builder()
                    .header("content-type", "text/event-stream")
                    .body(Body::from_stream(stream))
                    .unwrap()
            });
            let _ = axum::serve(upstream, app).await;
        });
        let proxy = RecordingProxy::start(&format!("http://{address}"), Duration::from_secs(5))
            .await
            .unwrap();
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let response = client
            .post(format!("{}/backend-api/codex/responses?turn=1", proxy.base))
            .header("originator", "codex_cli_rs")
            .header("authorization", "Bearer super-secret-token")
            .body(r#"{"model":"gpt-5.5"}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.text().await.unwrap(), "hello stream");
        let exchanges = proxy.exchanges();
        assert_eq!(exchanges.len(), 1);
        let exchange = &exchanges[0];
        assert_eq!(exchange.method, "POST");
        assert_eq!(exchange.path, "/backend-api/codex/responses");
        assert_eq!(exchange.query, "turn=1");
        assert_eq!(exchange.request_headers["originator"], "codex_cli_rs");
        assert_eq!(
            exchange.request_headers["authorization"],
            "Bearer super-secret-token"
        );
        assert_eq!(exchange.request_body["model"], "gpt-5.5");
        assert_eq!(exchange.status, 200);
        assert_eq!(exchange.response_body.as_str(), Some("hello stream"));
        let _ = proxy;
    }
}
