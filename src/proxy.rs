use std::{
    collections::{BTreeMap, HashSet},
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, bail};
use axum::{
    Router,
    body::{Body, HttpBody, to_bytes},
    extract::{Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use serde::Deserialize;
use serde_json::{Value, json};
use subtle::ConstantTimeEq;
use tokio::{io::AsyncReadExt, sync::Mutex};

use crate::{
    auth::{ProviderAuth, validate_runtime_credentials},
    config::{Config, Provider},
    sensitive_headers::is_sensitive_header,
    trace::{
        EventConflict, InvalidSessionEvent, SessionEvent, TraceStart, TraceStore, TraceWriter,
    },
    translate::{self, Protocol, StreamTranslator},
};

type Writer = Arc<Mutex<Option<TraceWriter>>>;

struct UploadState {
    complete: AtomicBool,
    body_failed: AtomicBool,
}

// Fix the fallible stream item type without allocating a boxed stream.
fn io_bytes<S: Stream<Item = io::Result<Bytes>>>(stream: S) -> S {
    stream
}

#[derive(Clone)]
struct App {
    config: Arc<Config>,
    client: reqwest::Client,
    auth: Arc<BTreeMap<String, ProviderAuth>>,
    traces: TraceStore,
    proxy_token: Arc<String>,
}

fn secret(name: &str) -> Result<String> {
    let value =
        std::env::var(name).with_context(|| format!("missing environment variable {name}"))?;
    validate_gateway_secret(&value).with_context(|| format!("invalid gateway token in {name}"))?;
    Ok(value)
}

fn validate_gateway_secret(value: &str) -> Result<()> {
    if value.len() < 16 || !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        bail!("gateway tokens require at least 16 visible ASCII characters without whitespace");
    }
    Ok(())
}

pub fn validate_runtime(config: &Config) -> Result<()> {
    config.validate()?;
    let proxy = secret(&config.proxy_token_env)?;
    let control = secret(&config.control_token_env)?;
    if proxy == control {
        bail!("inference and control access tokens must differ");
    }
    for provider in config.providers.values() {
        ProviderAuth::new(provider.auth.clone())?;
        if matches!(provider.auth.mode.as_str(), "api_key" | "bearer") {
            let name = provider
                .auth
                .token_env
                .as_deref()
                .context("missing token_env")?;
            let token = std::env::var(name)
                .with_context(|| format!("missing credential environment variable {name}"))?;
            if token.is_empty()
                || token.bytes().any(|byte| byte.is_ascii_whitespace())
                || HeaderValue::from_str(&token).is_err()
            {
                bail!("credential environment variable {name} is empty or not a valid token");
            }
        }
        if provider.auth.mode == "codex" {
            validate_runtime_credentials(&provider.auth)
                .context("invalid Codex auth_file; run codex login with file credential storage")?;
        }
    }
    Ok(())
}

pub async fn serve(config: Config) -> Result<()> {
    validate_runtime(&config)?;
    let proxy_token = Arc::new(secret(&config.proxy_token_env)?);
    let control_token = Arc::new(secret(&config.control_token_env)?);
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(config.connect_timeout_seconds))
        .read_timeout(Duration::from_secs(config.read_timeout_seconds))
        .pool_idle_timeout(Duration::from_secs(90))
        .tcp_nodelay(true)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()?;
    let auth = config
        .providers
        .iter()
        .map(|(name, p)| Ok((name.clone(), ProviderAuth::new(p.auth.clone())?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let traces = TraceStore::open(&config.trace_dir).await?;
    let app = App {
        config: Arc::new(config),
        client,
        auth: Arc::new(auth),
        traces,
        proxy_token: proxy_token.clone(),
    };
    let inference = Router::new()
        .route("/v1/capabilities", get(capabilities))
        .route("/v1/realtime", get(realtime))
        .route("/v1/files", post(create_file).get(list_files))
        .route("/v1/files/{id}/content", get(file_content))
        .route("/v1/files/{id}", get(get_file).delete(delete_file))
        .route("/session-events", post(ingest_session_event))
        .fallback(inference)
        .layer(middleware::from_fn_with_state(proxy_token, authenticate))
        .with_state(app.clone());
    let control = Router::new()
        .route("/health", get(health))
        .route("/providers", get(providers))
        .route("/traces", get(list_traces))
        .route("/traces/{id}", get(get_trace))
        .route("/traces/{id}/body/{kind}", get(trace_body))
        .route("/export", get(export))
        .route("/artifacts/{digest}", get(imported_artifact))
        .route("/sessions", get(list_sessions))
        .route("/sessions/{id}/events", get(session_events))
        .route("/sessions/{id}/traces", get(session_traces))
        .route("/sessions/{id}/export", get(export_session_events))
        .layer(middleware::from_fn(control_no_cache))
        .layer(middleware::from_fn_with_state(control_token, authenticate))
        .with_state(app.clone());
    let listener = tokio::net::TcpListener::bind(app.config.listen)
        .await
        .context("binding inference listener")?;
    let control_listener = tokio::net::TcpListener::bind(app.config.control_listen)
        .await
        .context("binding control listener")?;
    tracing::info!(inference = %listener.local_addr()?, control = %control_listener.local_addr()?, "gateway listening");
    let (stop, _) = tokio::sync::watch::channel(false);
    let mut a_stop = stop.subscribe();
    let mut b_stop = stop.subscribe();
    let mut a = tokio::spawn(async move {
        axum::serve(listener, inference)
            .with_graceful_shutdown(async move {
                let _ = a_stop.changed().await;
            })
            .await
    });
    let mut b = tokio::spawn(async move {
        axum::serve(control_listener, control)
            .with_graceful_shutdown(async move {
                let _ = b_stop.changed().await;
            })
            .await
    });
    tokio::select! {
        result = &mut a => { stop.send_replace(true); result??; bail!("inference listener exited unexpectedly"); }
        result = &mut b => { stop.send_replace(true); result??; bail!("control listener exited unexpectedly"); }
        _ = shutdown_signal() => { stop.send_replace(true); }
    }
    match tokio::time::timeout(Duration::from_secs(30), async {
        a.await??;
        b.await??;
        Ok::<_, anyhow::Error>(())
    })
    .await
    {
        Ok(result) => result,
        Err(_) => {
            tracing::warn!("shutdown drain timed out; active traces remain incomplete");
            Ok(())
        }
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler");
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn matches_secret(value: &[u8], key: &str) -> bool {
    bool::from(value.ct_eq(key.as_bytes()))
}

fn bearer(value: &HeaderValue) -> Option<&[u8]> {
    let mut parts = value.to_str().ok()?.split_ascii_whitespace();
    if !parts.next()?.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    Some(token.as_bytes())
}

fn connection_nominated_headers(headers: &HeaderMap) -> HashSet<String> {
    headers
        .get_all("connection")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|name| name.trim().to_ascii_lowercase())
        .filter(|name| !name.is_empty())
        .collect()
}

fn provider_credentials(incoming: &HeaderMap, proxy_token: &str) -> HeaderMap {
    let mut credentials = HeaderMap::new();
    let nominated = connection_nominated_headers(incoming);
    for name in ["authorization", "x-api-key"] {
        if nominated.contains(name) {
            continue;
        }
        for value in incoming.get_all(name) {
            let token = if name == "authorization" {
                bearer(value).or(Some(value.as_bytes().trim_ascii()))
            } else {
                Some(value.as_bytes().trim_ascii())
            };
            if !token.is_some_and(|token| matches_secret(token, proxy_token)) {
                credentials.append(name, value.clone());
            }
        }
    }
    credentials
}

async fn authenticate(State(key): State<Arc<String>>, request: Request, next: Next) -> Response {
    let headers = request.headers();
    let credential = headers
        .get("x-infer-key")
        .map(|h| h.as_bytes())
        .or_else(|| headers.get("authorization").and_then(bearer))
        .or_else(|| headers.get("x-api-key").map(|h| h.as_bytes()));
    if !credential.is_some_and(|value| matches_secret(value, &key)) {
        return error_response(StatusCode::UNAUTHORIZED, "invalid gateway credential", None);
    }
    next.run(request).await
}

async fn control_no_cache(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
}

fn account_product(path: &str) -> bool {
    const FAMILIES: &[&str] = &[
        "/v1/assistants",
        "/v1/threads",
        "/v1/batches",
        "/v1/fine_tuning",
        "/v1/fine-tunes",
        "/v1/vector_stores",
        "/v1/evals",
    ];
    FAMILIES
        .iter()
        .any(|family| path == *family || path.starts_with(&format!("{family}/")))
}
fn error_response(status: StatusCode, message: &str, id: Option<&str>) -> Response {
    let mut response = (
        status,
        axum::Json(json!({"type":"error","error":{"type":"proxy_error","message":message}})),
    )
        .into_response();
    if let Some(id) = id {
        response
            .headers_mut()
            .insert("x-infer-trace-id", HeaderValue::from_str(id).unwrap());
    }
    response
}

fn headers_json(headers: &HeaderMap) -> Value {
    let mut result = serde_json::Map::new();
    for name in headers.keys() {
        let key = name.as_str();
        let sensitive = is_sensitive_header(key);
        let values: Vec<_> = headers
            .get_all(name)
            .iter()
            .map(|v| {
                if sensitive {
                    Value::String("[REDACTED]".into())
                } else {
                    Value::String(String::from_utf8_lossy(v.as_bytes()).into_owned())
                }
            })
            .collect();
        result.insert(key.into(), json!(values));
    }
    Value::Object(result)
}

fn filtered_headers(headers: &HeaderMap, request: bool) -> HeaderMap {
    let nominated = connection_nominated_headers(headers);
    let mut out = HeaderMap::new();
    for (name, value) in headers {
        let key = name.as_str();
        if matches!(
            key,
            "connection"
                | "keep-alive"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "te"
                | "trailer"
                | "transfer-encoding"
                | "upgrade"
                | "content-length"
        ) || nominated.contains(key)
            || (request
                && (matches!(
                    key,
                    "host"
                        | "authorization"
                        | "x-api-key"
                        | "x-infer-key"
                        | "cookie"
                        | "forwarded"
                        | "accept-encoding"
                ) || key.starts_with("x-forwarded-")))
        {
            continue;
        }
        out.append(name, value.clone());
    }
    out
}

fn remove_body_digests(headers: &mut HeaderMap) {
    crate::backend::strip_body_digests(headers);
}

async fn finish(writer: &Writer, status: u16, headers: Value, error: Option<String>) -> Result<()> {
    if let Some(writer) = writer.lock().await.take() {
        writer.finish(status, headers, error).await?;
    }
    Ok(())
}

async fn reject(writer: &Writer, id: &str, status: StatusCode, message: &str) -> Response {
    let bytes = serde_json::to_vec(
        &json!({"type":"error","error":{"type":"proxy_error","message":message}}),
    )
    .unwrap();
    let result = async {
        if let Some(w) = writer.lock().await.as_mut() {
            w.response(&bytes).await?;
        }
        finish(
            writer,
            status.as_u16(),
            json!({"content-type":["application/json"]}),
            Some(message.into()),
        )
        .await
    }
    .await;
    if let Err(error) = result {
        tracing::error!(trace_id=id, %error, "failed to persist rejected trace");
    }
    error_response(status, message, Some(id))
}

async fn inference(State(app): State<App>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let path = parts.uri.path();
    let raw = path
        .strip_prefix("/providers/")
        .and_then(|s| s.split_once('/'));
    if raw.is_none() && (path == "/v1/uploads" || path.starts_with("/v1/uploads/")) {
        return error_response(
            StatusCode::NOT_IMPLEMENTED,
            "segmented uploads are not routed; use POST /v1/files",
            None,
        );
    }
    if raw.is_none() && (path == "/v1/files" || path.starts_with("/v1/files/")) {
        return error_response(StatusCode::NOT_FOUND, "unknown files route", None);
    }
    if raw.is_none() && account_product(path) {
        return error_response(
            StatusCode::NOT_IMPLEMENTED,
            "infer does not route OpenAI account products (assistants, threads, batches, fine-tunes, vector stores, evals); they have no migration path",
            None,
        );
    }
    let (provider_name, suffix, auto) = match raw {
        Some((name, suffix)) => (name.to_owned(), format!("/{suffix}"), false),
        None => (app.config.default_provider.clone(), path.to_owned(), true),
    };
    let Some(provider) = app.config.providers.get(&provider_name) else {
        return error_response(StatusCode::NOT_FOUND, "unknown provider", None);
    };
    let id = uuid::Uuid::new_v4().to_string();
    let meta = TraceStart {
        id: id.clone(),
        provider: if auto {
            "auto".into()
        } else {
            provider_name.clone()
        },
        method: parts.method.to_string(),
        path: parts.uri.to_string(),
        request_headers: headers_json(&parts.headers),
        upstream_url: String::new(),
        upstream_headers: json!({}),
    };
    let writer = match app.traces.start(meta).await {
        Ok(writer) => Arc::new(Mutex::new(Some(writer))),
        Err(error) => {
            tracing::error!(%error, "trace store unavailable");
            return error_response(
                StatusCode::INSUFFICIENT_STORAGE,
                "trace store unavailable",
                None,
            );
        }
    };
    if parts.headers.contains_key("upgrade") || parts.method == Method::CONNECT {
        let message = if path.starts_with("/v1/realtime") {
            "realtime requires one model that declares speech-to-speech; infer does not stitch a voice pipeline"
        } else {
            "HTTP upgrades and CONNECT are not supported"
        };
        return reject(&writer, &id, StatusCode::NOT_IMPLEMENTED, message).await;
    }
    let route = if auto {
        crate::route::Route::recognize(&parts.method, path)
    } else {
        None
    };
    if let Some(route) = route {
        let mut stream = body.into_data_stream();
        let mut data = Vec::new();
        let request_limit = route.request_limit(app.config.max_request_bytes);
        while let Some(chunk) = stream.next().await {
            let chunk = match chunk {
                Ok(c) => c,
                Err(_) => {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "request body interrupted",
                        Some(&id),
                    );
                }
            };
            if let Some(w) = writer.lock().await.as_mut()
                && w.request(&chunk).await.is_err()
            {
                return error_response(
                    StatusCode::INSUFFICIENT_STORAGE,
                    "trace write failed",
                    Some(&id),
                );
            }
            if chunk.len() > request_limit.saturating_sub(data.len()) {
                return reject(&writer, &id, StatusCode::PAYLOAD_TOO_LARGE, "routed request exceeds max_request_bytes; use explicit provider passthrough for large native requests").await;
            }
            data.extend_from_slice(&chunk);
        }
        let parsed = match route.parse(data, &parts.headers, request_limit) {
            Ok(parsed) => parsed,
            Err(error) => return reject(&writer, &id, error.status, &error.message).await,
        };
        let Some(model) = route.model(&parsed) else {
            return reject(
                &writer,
                &id,
                StatusCode::BAD_REQUEST,
                "model must be a string",
            )
            .await;
        };
        let client_model = model.to_owned();
        let selection = match app
            .config
            .resolve_model(&client_model, route.client_dialect())
        {
            Ok(selection) => selection,
            Err(error) => {
                return reject(&writer, &id, StatusCode::BAD_REQUEST, &error.to_string()).await;
            }
        };
        let name = selection.provider;
        let provider = &app.config.providers[name];
        let backend = crate::backend::get(provider.kind);
        let prepared = match route.prepare(
            backend,
            parsed,
            &client_model,
            &selection.upstream_model,
            crate::route::RoutePolicy {
                access_program: selection.access_program,
                daybreak: provider.daybreak,
                danger_zone_images: provider.danger_zone_images,
                operations: &selection.operations,
                operations_declared: selection.operations_declared,
                modalities: selection.modalities.clone(),
            },
            request_limit,
        ) {
            Ok(prepared) => prepared,
            Err(error) => return reject(&writer, &id, error.status, &error.message).await,
        };
        let prepared = match swap_infer_files(&app, name, provider, &parts.headers, prepared).await
        {
            Ok(prepared) => prepared,
            Err(error) => return reject(&writer, &id, error.status, &error.message).await,
        };
        if prepared.rewritten
            && let Some(w) = writer.lock().await.as_mut()
            && w.upstream_request(&prepared.bytes).await.is_err()
        {
            return error_response(
                StatusCode::INSUFFICIENT_STORAGE,
                "trace write failed",
                Some(&id),
            );
        }
        let url = match upstream_url(provider, &prepared.suffix, &parts.uri) {
            Ok(url) => url,
            Err(error) => {
                return reject(&writer, &id, StatusCode::BAD_REQUEST, &error.to_string()).await;
            }
        };
        let outgoing_length = prepared.bytes.len() as u64;
        let upstream = send(
            &app,
            name,
            provider,
            &parts.method,
            url,
            &parts.headers,
            reqwest::Body::from(prepared.bytes),
            Some(outgoing_length),
            prepared.rewritten,
            &writer,
        )
        .await;
        let upstream = match upstream {
            Ok(response) => response,
            Err(error) => {
                return reject(
                    &writer,
                    &id,
                    StatusCode::BAD_GATEWAY,
                    &format!("upstream request failed: {error}"),
                )
                .await;
            }
        };
        return respond(
            &app,
            upstream,
            writer,
            id,
            prepared.response.map(|plan| ResponseRoute {
                upstream_protocol: plan.upstream_protocol,
                client_protocol: plan.client_protocol,
                model: plan.model,
                client_stream: plan.client_stream,
                include_usage: plan.include_usage,
                upstream_stream: plan.upstream_stream,
            }),
            prepared.rewritten,
            prepared.warning,
            prepared.decision,
            None,
            parts.method == Method::HEAD,
        )
        .await;
    }
    let url = match upstream_url(provider, &suffix, &parts.uri) {
        Ok(url) => url,
        Err(error) => {
            return reject(&writer, &id, StatusCode::BAD_REQUEST, &error.to_string()).await;
        }
    };
    let length = body.size_hint().exact();
    let shared = writer.clone();
    let upload_state = Arc::new(UploadState {
        complete: AtomicBool::new(body.is_end_stream() || length == Some(0)),
        body_failed: AtomicBool::new(false),
    });
    let stream_state = upload_state.clone();
    let request_stream = io_bytes(async_stream::try_stream! {
        let mut input = body.into_data_stream();
        let mut remaining = length;
        while let Some(chunk) = input.next().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(error) => {
                    stream_state.body_failed.store(true, Ordering::Release);
                    Err::<Bytes, io::Error>(io::Error::other(error))?
                }
            };
            let mut lock = shared.lock().await;
            let w = lock.as_mut().ok_or_else(|| io::Error::other("trace finalized before upload ended"))?;
            w.request(&chunk).await.map_err(io::Error::other)?;
            if let Some(bytes_left) = &mut remaining {
                let Some(next) = bytes_left.checked_sub(chunk.len() as u64) else {
                    stream_state.body_failed.store(true, Ordering::Release);
                    Err::<(), io::Error>(io::Error::other("request body exceeds its declared length"))?;
                    unreachable!();
                };
                *bytes_left = next;
                if next == 0 {
                    stream_state.complete.store(true, Ordering::Release);
                }
            }
            drop(lock);
            yield chunk;
        }
        if remaining.is_some_and(|bytes_left| bytes_left != 0) {
            stream_state.body_failed.store(true, Ordering::Release);
            Err::<(), io::Error>(io::Error::new(io::ErrorKind::UnexpectedEof, "request body ended before its declared length"))?;
        }
        stream_state.complete.store(true, Ordering::Release);
    });
    let upstream = send(
        &app,
        &provider_name,
        provider,
        &parts.method,
        url,
        &parts.headers,
        reqwest::Body::wrap_stream(request_stream),
        length,
        false,
        &writer,
    )
    .await;
    if upload_state.body_failed.load(Ordering::Acquire) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "request body interrupted",
            Some(&id),
        );
    }
    match upstream {
        Ok(response) => {
            respond(
                &app,
                response,
                writer,
                id,
                None,
                false,
                None,
                None,
                Some(upload_state),
                parts.method == Method::HEAD,
            )
            .await
        }
        Err(error) => {
            reject(
                &writer,
                &id,
                StatusCode::BAD_GATEWAY,
                &format!("upstream request failed: {error}"),
            )
            .await
        }
    }
}

fn upstream_url(provider: &Provider, suffix: &str, uri: &Uri) -> Result<reqwest::Url> {
    let base = reqwest::Url::parse(&provider.base_url).context("invalid provider base URL")?;
    let suffix_path = suffix.split('?').next().unwrap_or(suffix);
    if suffix_path
        .strip_prefix("/client/v4/accounts/")
        .and_then(|path| path.split_once("/ai/run/"))
        .is_some_and(|(account, _)| path_has_dot_segment(account))
    {
        bail!("request path escapes the configured provider URL prefix");
    }
    let mut target = format!("{}{}", base.as_str().trim_end_matches('/'), suffix);
    if let Some(query) = uri.query() {
        target.push('?');
        target.push_str(query);
    }
    let url = reqwest::Url::parse(&target).context("invalid upstream URL")?;
    let prefix = base.path().trim_end_matches('/');
    if url.origin() != base.origin()
        || !(prefix.is_empty()
            || url.path() == prefix
            || url
                .path()
                .strip_prefix(prefix)
                .is_some_and(|tail| tail.starts_with('/')))
    {
        bail!("request path escapes the configured provider URL prefix");
    }
    Ok(url)
}

async fn swap_infer_files(
    app: &App,
    name: &str,
    provider: &Provider,
    incoming: &HeaderMap,
    mut prepared: crate::route::Prepared,
) -> Result<crate::route::Prepared, crate::route::RouteError> {
    let Ok(mut value) = crate::json::from_slice(&prepared.bytes) else {
        return Ok(prepared);
    };
    let mut ids = Vec::new();
    collect_infer_file_ids(&value, &mut ids);
    ids.sort();
    ids.dedup();
    if ids.is_empty() {
        return Ok(prepared);
    }
    if !matches!(
        provider.kind,
        crate::config::Kind::Openai | crate::config::Kind::Grok | crate::config::Kind::Anthropic
    ) {
        return Err(crate::route::RouteError {
            status: StatusCode::BAD_REQUEST,
            message: format!(
                "provider {:?} cannot accept an uploaded file id",
                provider.kind
            ),
        });
    }
    let mut mapped = std::collections::HashMap::new();
    for id in ids {
        let provider_id = ensure_provider_file(app, name, provider, incoming, &id)
            .await
            .map_err(|error| {
                let message = error.to_string();
                let status = if message.starts_with("unknown infer file id") {
                    StatusCode::BAD_REQUEST
                } else {
                    StatusCode::BAD_GATEWAY
                };
                crate::route::RouteError { status, message }
            })?;
        mapped.insert(id, provider_id);
    }
    replace_infer_file_ids(&mut value, &mapped);
    prepared.bytes = Bytes::from(serde_json::to_vec(&value).unwrap());
    prepared.rewritten = true;
    Ok(prepared)
}

fn collect_infer_file_ids(value: &Value, ids: &mut Vec<String>) {
    let Value::Object(object) = value else {
        if let Value::Array(items) = value {
            for item in items {
                collect_infer_file_ids(item, ids);
            }
        }
        return;
    };
    for (key, child) in object {
        if matches!(key.as_str(), "file_id" | "file")
            && let Some(text) = child.as_str()
            && crate::trace::is_infer_file_id(text)
        {
            ids.push(text.to_owned());
        }
        collect_infer_file_ids(child, ids);
    }
}

fn replace_infer_file_ids(value: &mut Value, mapped: &std::collections::HashMap<String, String>) {
    match value {
        Value::Array(items) => {
            for item in items {
                replace_infer_file_ids(item, mapped);
            }
        }
        Value::Object(object) => {
            for (key, child) in object.iter_mut() {
                if matches!(key.as_str(), "file_id" | "file")
                    && let Some(text) = child.as_str()
                    && let Some(provider_id) = mapped.get(text)
                {
                    *child = Value::String(provider_id.clone());
                }
                replace_infer_file_ids(child, mapped);
            }
        }
        _ => {}
    }
}

async fn ensure_provider_file(
    app: &App,
    name: &str,
    provider: &Provider,
    incoming: &HeaderMap,
    infer_id: &str,
) -> Result<String> {
    if let Some(existing) = app.traces.provider_file(infer_id, name).await?
        && app.traces.file(infer_id).await?.is_some()
    {
        return Ok(existing);
    }
    let Some(record) = app.traces.file(infer_id).await? else {
        bail!("unknown infer file id {infer_id}");
    };
    let Some(mut file) = app.traces.file_body(infer_id).await? else {
        bail!("stored file {infer_id} is missing its bytes");
    };
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut bytes)?;
    let uploaded = upload_provider_file(app, name, provider, incoming, &record, &bytes).await?;
    app.traces
        .remember_provider_file(infer_id, name, &uploaded)
        .await?;
    Ok(uploaded)
}

async fn upload_provider_file(
    app: &App,
    name: &str,
    provider: &Provider,
    incoming: &HeaderMap,
    record: &crate::trace::OwnedFile,
    bytes: &[u8],
) -> Result<String> {
    let url = upstream_url(provider, "/v1/files", &Uri::from_static("/v1/files"))?;
    let boundary = format!("infer{}", uuid::Uuid::new_v4().simple());
    let filename = record.filename.replace(['"', '\r', '\n', '\\'], "_");
    let mut body = Vec::new();
    if provider.kind != crate::config::Kind::Anthropic {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"purpose\"\r\n\r\n{}\r\n",
                record.purpose
            )
            .as_bytes(),
        );
    }
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(bytes);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let credentials = provider_credentials(incoming, &app.proxy_token);
    let mut headers = app.auth[name]
        .headers(
            &app.client,
            crate::backend::get(provider.kind).anthropic_credentials(),
            &credentials,
        )
        .await?;
    headers.insert(
        "content-type",
        HeaderValue::from_str(&format!("multipart/form-data; boundary={boundary}"))?,
    );
    headers.insert("accept-encoding", HeaderValue::from_static("identity"));
    if provider.kind == crate::config::Kind::Anthropic {
        headers.insert("anthropic-version", HeaderValue::from_static("2023-06-01"));
        headers.insert(
            "anthropic-beta",
            HeaderValue::from_static("files-api-2025-04-14"),
        );
    }
    let response = app
        .client
        .post(url)
        .headers(headers)
        .body(body)
        .send()
        .await
        .context("provider file upload failed")?;
    let status = response.status();
    let payload = response
        .bytes()
        .await
        .context("reading provider file upload")?;
    if !status.is_success() {
        bail!("provider file upload returned HTTP {}", status.as_u16());
    }
    let value: Value =
        serde_json::from_slice(&payload).context("provider file upload was not JSON")?;
    value
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
        .context("provider file upload did not return an id")
}

#[allow(clippy::too_many_arguments)]
async fn send(
    app: &App,
    name: &str,
    provider: &Provider,
    method: &Method,
    url: reqwest::Url,
    incoming: &HeaderMap,
    body: reqwest::Body,
    length: Option<u64>,
    rewritten: bool,
    writer: &Writer,
) -> Result<reqwest::Response> {
    let mut headers = filtered_headers(incoming, true);
    if let Some(length) = length {
        headers.insert("content-length", HeaderValue::from(length));
    } else {
        // Hyper otherwise treats unknown-length GET/HEAD streams as bodyless.
        // This is freshly generated framing, never forwarded hop-by-hop input.
        headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
    }
    // Filter every value: HeaderMap::get alone misses repeated credential headers.
    let credentials = provider_credentials(incoming, &app.proxy_token);
    headers.extend(
        app.auth[name]
            .headers(
                &app.client,
                crate::backend::get(provider.kind).anthropic_credentials(),
                &credentials,
            )
            .await?,
    );
    headers.insert("accept-encoding", HeaderValue::from_static("identity"));
    if provider.danger_zone_images && !headers.contains_key("typesafe-danger-zone-images") {
        headers.insert(
            "typesafe-danger-zone-images",
            HeaderValue::from_static("true"),
        );
    }
    crate::backend::get(provider.kind).prepare_headers(&mut headers, rewritten);
    if let Some(w) = writer.lock().await.as_mut() {
        w.route(name, url.as_str(), headers_json(&headers)).await?;
    }
    app.client
        .request(method.clone(), url)
        .headers(headers)
        .body(body)
        .send()
        .await
        .context("provider transport error")
}

struct ResponseRoute {
    upstream_protocol: Protocol,
    client_protocol: Protocol,
    model: String,
    client_stream: bool,
    include_usage: bool,
    upstream_stream: bool,
}

#[allow(clippy::too_many_arguments)]
async fn respond(
    app: &App,
    upstream: reqwest::Response,
    writer: Writer,
    id: String,
    route: Option<ResponseRoute>,
    rewritten: bool,
    warning: Option<&'static str>,
    decision: Option<crate::translate::AnswerPlan>,
    upload_state: Option<Arc<UploadState>>,
    head: bool,
) -> Response {
    let status = upstream.status();
    let mut headers = filtered_headers(upstream.headers(), false);
    let upstream_headers = headers_json(upstream.headers());
    headers.insert("x-infer-trace-id", HeaderValue::from_str(&id).unwrap());
    headers.insert("x-accel-buffering", HeaderValue::from_static("no"));
    if let Some(warning) = warning {
        headers.insert("x-infer-warning", HeaderValue::from_static(warning));
    }
    if head
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED
        || status.is_informational()
    {
        // These responses cannot carry a body, so Hyper will never poll a lazy
        // response stream. Commit before returning, including early-upload state.
        if (head || status == StatusCode::NOT_MODIFIED)
            && let Some(length) = upstream.headers().get("content-length")
        {
            headers.insert("content-length", length.clone());
        }
        let error = exchange_error(status, upload_state.as_deref(), false);
        if let Err(error) = finish(
            &writer,
            status.as_u16(),
            json!({"client":headers_json(&headers),"upstream":upstream_headers}),
            error,
        )
        .await
        {
            tracing::error!(trace_id=%id, %error, "trace commit failed");
            return error_response(
                StatusCode::INSUFFICIENT_STORAGE,
                "trace commit failed",
                Some(&id),
            );
        }
        // Hyper drops an explicit 304 representation length when an already-ended
        // body is supplied. An empty stream preserves that header without ever
        // yielding response bytes; finalization above is still eager.
        let body = if status == StatusCode::NOT_MODIFIED && headers.contains_key("content-length") {
            Body::from_stream(futures_util::stream::empty::<io::Result<Bytes>>())
        } else {
            Body::empty()
        };
        let mut response = Response::new(body);
        *response.status_mut() = status;
        *response.headers_mut() = headers;
        return response;
    }
    let is_sse = upstream
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(';')
                .next()
                .unwrap_or_default()
                .trim_matches([' ', '\t'])
                .eq_ignore_ascii_case("text/event-stream")
        });
    let conversion = route
        .as_ref()
        .filter(|route| route.upstream_protocol != route.client_protocol);
    // Forced upstream streaming still needs collection when its media type is wrong.
    if let Some(plan) = decision
        && status.is_success()
    {
        if is_sse {
            return reject(
                &writer,
                &id,
                StatusCode::BAD_GATEWAY,
                "Decisions translation does not accept an SSE upstream",
            )
            .await;
        }
        let mut stream = upstream.bytes_stream();
        let mut data = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(_) => {
                    return reject(
                        &writer,
                        &id,
                        StatusCode::BAD_GATEWAY,
                        "upstream response interrupted",
                    )
                    .await;
                }
            };
            if let Some(writer) = writer.lock().await.as_mut()
                && writer.upstream_response(&chunk).await.is_err()
            {
                return error_response(
                    StatusCode::INSUFFICIENT_STORAGE,
                    "trace write failed",
                    Some(&id),
                );
            }
            if chunk.len()
                > app
                    .config
                    .max_buffered_response_bytes
                    .saturating_sub(data.len())
            {
                return reject(
                    &writer,
                    &id,
                    StatusCode::BAD_GATEWAY,
                    "upstream response exceeds max_buffered_response_bytes",
                )
                .await;
            }
            data.extend_from_slice(&chunk);
        }
        let translated = match crate::json::from_slice(&data)
            .map_err(|error| error.to_string())
            .and_then(|value| {
                match &plan {
                    crate::translate::AnswerPlan::Decisions(plan) => {
                        crate::translate::decisions_response(value, plan)
                    }
                    crate::translate::AnswerPlan::SystemOne(plan) => {
                        crate::translate::to_system_one(value, plan)
                    }
                }
                .map_err(|error| error.to_string())
            }) {
            Ok(value) => value,
            Err(error) => {
                return reject(
                    &writer,
                    &id,
                    StatusCode::BAD_GATEWAY,
                    &format!("invalid upstream response: {error}"),
                )
                .await;
            }
        };
        let bytes = serde_json::to_vec(&translated).unwrap();
        if let Some(writer) = writer.lock().await.as_mut()
            && writer.response(&bytes).await.is_err()
        {
            return error_response(
                StatusCode::INSUFFICIENT_STORAGE,
                "trace write failed",
                Some(&id),
            );
        }
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        headers.remove("content-encoding");
        remove_body_digests(&mut headers);
        if let Err(error) = finish(
            &writer,
            status.as_u16(),
            json!({"client":headers_json(&headers),"upstream":upstream_headers}),
            None,
        )
        .await
        {
            tracing::error!(trace_id=%id, %error, "trace commit failed");
            return error_response(
                StatusCode::INSUFFICIENT_STORAGE,
                "trace commit failed",
                Some(&id),
            );
        }
        let mut response = Response::new(Body::from(bytes));
        *response.status_mut() = status;
        *response.headers_mut() = headers;
        return response;
    }
    let need_collect = status.is_success()
        && route.as_ref().is_some_and(|route| {
            !route.client_stream && (route.upstream_stream || is_sse || conversion.is_some())
        });
    if need_collect {
        let mut stream = upstream.bytes_stream();
        let mut data = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = match chunk {
                Ok(c) => c,
                Err(_) => {
                    return reject(
                        &writer,
                        &id,
                        StatusCode::BAD_GATEWAY,
                        "upstream response interrupted",
                    )
                    .await;
                }
            };
            if let Some(w) = writer.lock().await.as_mut()
                && w.upstream_response(&chunk).await.is_err()
            {
                return error_response(
                    StatusCode::INSUFFICIENT_STORAGE,
                    "trace write failed",
                    Some(&id),
                );
            }
            if chunk.len()
                > app
                    .config
                    .max_buffered_response_bytes
                    .saturating_sub(data.len())
            {
                return reject(
                    &writer,
                    &id,
                    StatusCode::BAD_GATEWAY,
                    "upstream response exceeds max_buffered_response_bytes; enable streaming",
                )
                .await;
            }
            data.extend_from_slice(&chunk);
        }
        let result: Result<Value> = (|| {
            let route = route.as_ref().unwrap();
            let value = if is_sse {
                translate::collect_response_sse(&data, route.client_protocol)?
            } else {
                crate::json::from_slice(&data)?
            };
            translate::response(
                value,
                route.upstream_protocol,
                route.client_protocol,
                &route.model,
            )
        })();
        let value = match result {
            Ok(v) => v,
            Err(error) => {
                return reject(
                    &writer,
                    &id,
                    StatusCode::BAD_GATEWAY,
                    &format!("invalid upstream response: {error}"),
                )
                .await;
            }
        };
        let bytes = serde_json::to_vec(&value).unwrap();
        if let Some(w) = writer.lock().await.as_mut()
            && w.response(&bytes).await.is_err()
        {
            return error_response(
                StatusCode::INSUFFICIENT_STORAGE,
                "trace write failed",
                Some(&id),
            );
        }
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        headers.remove("content-encoding");
        remove_body_digests(&mut headers);
        if let Err(error) = finish(
            &writer,
            status.as_u16(),
            json!({"client":headers_json(&headers),"upstream":upstream_headers}),
            None,
        )
        .await
        {
            tracing::error!(trace_id=%id, %error, "trace commit failed");
            return error_response(
                StatusCode::INSUFFICIENT_STORAGE,
                "trace commit failed",
                Some(&id),
            );
        }
        let mut response = Response::new(Body::from(bytes));
        *response.status_mut() = status;
        *response.headers_mut() = headers;
        return response;
    }
    let mut translator = if status.is_success() && is_sse {
        conversion.map(|route| {
            StreamTranslator::new(
                route.upstream_protocol,
                route.client_protocol,
                route.model.clone(),
                route.include_usage,
            )
        })
    } else {
        None
    };
    if status.is_success() && conversion.is_some() && !is_sse {
        return reject(
            &writer,
            &id,
            StatusCode::BAD_GATEWAY,
            "streaming translation requires an SSE upstream response",
        )
        .await;
    }
    if translator.is_some() {
        headers.insert(
            "content-type",
            HeaderValue::from_static("text/event-stream"),
        );
        headers.remove("content-encoding");
        remove_body_digests(&mut headers);
    }
    let output_headers = json!({"client":headers_json(&headers),"upstream":upstream_headers});
    enum Output {
        Native(Bytes),
        Translated(Vec<Bytes>),
    }
    let stream = io_bytes(async_stream::try_stream! {
        let mut upstream = upstream.bytes_stream();
        while let Some(chunk) = upstream.next().await {
            let result: Result<Output> = async {
                let chunk = chunk.context("upstream response interrupted")?;
                if (rewritten || translator.is_some())
                    && let Some(w) = writer.lock().await.as_mut() { w.upstream_response(&chunk).await?; }
                if let Some(t) = &mut translator {
                    let chunks = t.push(&chunk)?;
                    for chunk in &chunks {
                        if let Some(w) = writer.lock().await.as_mut() { w.response(chunk).await?; }
                    }
                    Ok(Output::Translated(chunks))
                } else {
                    if let Some(w) = writer.lock().await.as_mut() { w.response(&chunk).await?; }
                    Ok(Output::Native(chunk))
                }
            }.await;
            match result {
                Ok(Output::Native(chunk)) => yield chunk,
                Ok(Output::Translated(chunks)) => { for chunk in chunks { yield chunk; } }
                Err(error) => {
                    let _ = finish(&writer, status.as_u16(), output_headers.clone(), Some(error.to_string())).await;
                    Err::<(), io::Error>(io::Error::other(error))?;
                }
            }
        }
        if let Some(t) = &mut translator {
            match t.finish() {
                Ok(chunks) => {
                    for chunk in chunks {
                        if let Some(w) = writer.lock().await.as_mut() { w.response(&chunk).await.map_err(io::Error::other)?; }
                        yield chunk;
                    }
                }
                Err(error) => {
                    let _ = finish(&writer, status.as_u16(), output_headers.clone(), Some(error.to_string())).await;
                    Err::<(), io::Error>(io::Error::other(error))?;
                }
            }
        }
        let error = exchange_error(
            status,
            upload_state.as_deref(),
            translator.as_ref().is_some_and(StreamTranslator::upstream_failed),
        );
        finish(&writer, status.as_u16(), output_headers, error).await.map_err(io::Error::other)?;
    });
    let mut response = Response::new(Body::from_stream::<_>(stream));
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}

fn exchange_error(
    status: StatusCode,
    upload_state: Option<&UploadState>,
    semantic_error: bool,
) -> Option<String> {
    if upload_state.is_some_and(|state| !state.complete.load(Ordering::Acquire)) {
        Some("upstream responded before the complete request upload was recorded".into())
    } else if semantic_error {
        Some("upstream emitted a semantic SSE error".into())
    } else if status.is_success() {
        None
    } else {
        Some(format!("upstream HTTP {status}"))
    }
}

async fn create_file(State(app): State<App>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let bytes = match to_bytes(body, app.config.max_request_bytes).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "file exceeds max_request_bytes",
                None,
            );
        }
    };
    let (filename, purpose, file) = match parse_file_upload(&parts.headers, &bytes) {
        Ok(parsed) => parsed,
        Err(message) => return error_response(StatusCode::BAD_REQUEST, message, None),
    };
    match app.traces.put_file(file, filename, purpose).await {
        Ok(stored) => axum::Json(stored.json()).into_response(),
        Err(error) => error_response(StatusCode::BAD_REQUEST, &error.to_string(), None),
    }
}

async fn list_files(State(app): State<App>) -> Response {
    match app.traces.list_files(100).await {
        Ok(files) => axum::Json(json!({
            "object": "list",
            "data": files.iter().map(crate::trace::OwnedFile::json).collect::<Vec<_>>(),
        }))
        .into_response(),
        Err(error) => error_response(StatusCode::BAD_REQUEST, &error.to_string(), None),
    }
}

async fn get_file(State(app): State<App>, Path(id): Path<String>) -> Response {
    match app.traces.file(&id).await {
        Ok(Some(file)) => axum::Json(file.json()).into_response(),
        Ok(None) => error_response(StatusCode::NOT_FOUND, "file not found", None),
        Err(error) => error_response(StatusCode::BAD_REQUEST, &error.to_string(), None),
    }
}

async fn delete_file(State(app): State<App>, Path(id): Path<String>) -> Response {
    match app.traces.delete_file(&id).await {
        Ok(true) => {
            axum::Json(json!({"id": id, "object": "file", "deleted": true})).into_response()
        }
        Ok(false) => error_response(StatusCode::NOT_FOUND, "file not found", None),
        Err(error) => error_response(StatusCode::BAD_REQUEST, &error.to_string(), None),
    }
}

async fn file_content(State(app): State<App>, Path(id): Path<String>) -> Response {
    match app.traces.file_body(&id).await {
        Ok(Some(mut file)) => {
            let stream = io_bytes(async_stream::try_stream! {
                let mut buffer = vec![0u8; 65536];
                loop {
                    let read = std::io::Read::read(&mut file, &mut buffer)?;
                    if read == 0 {
                        break;
                    }
                    yield Bytes::copy_from_slice(&buffer[..read]);
                }
            });
            let mut response = Response::new(Body::from_stream::<_>(stream));
            response.headers_mut().insert(
                "content-type",
                HeaderValue::from_static("application/octet-stream"),
            );
            response
        }
        Ok(None) => error_response(StatusCode::NOT_FOUND, "file not found", None),
        Err(error) => error_response(StatusCode::BAD_REQUEST, &error.to_string(), None),
    }
}

fn parse_file_upload(
    headers: &HeaderMap,
    raw: &[u8],
) -> Result<(String, String, Vec<u8>), &'static str> {
    let content_type = headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .ok_or("file upload requires multipart/form-data")?;
    let boundary = content_type
        .split(';')
        .filter_map(|part| part.trim().strip_prefix("boundary="))
        .next()
        .map(|value| value.trim_matches('"'))
        .ok_or("multipart file upload is missing a boundary")?;
    let marker = format!("--{boundary}").into_bytes();
    let mut filename = None;
    let mut purpose = None;
    let mut file = None;
    let mut rest = raw;
    while let Some(start) = rest
        .windows(marker.len())
        .position(|window| window == marker)
    {
        let after = &rest[start + marker.len()..];
        if after.starts_with(b"--") {
            break;
        }
        let after = after.strip_prefix(b"\r\n").unwrap_or(after);
        let Some(split) = after.windows(4).position(|window| window == b"\r\n\r\n") else {
            break;
        };
        let header_text = String::from_utf8_lossy(&after[..split]);
        let body_and_rest = &after[split + 4..];
        let mut delimiter = b"\r\n".to_vec();
        delimiter.extend_from_slice(&marker);
        let end = body_and_rest
            .windows(delimiter.len())
            .position(|window| window == delimiter.as_slice())
            .unwrap_or(body_and_rest.len());
        let body = &body_and_rest[..end];
        let mut name = None;
        let mut part_filename = None;
        for item in header_text.split(';') {
            let item = item.trim();
            if let Some(value) = item.strip_prefix("name=") {
                name = Some(value.trim_matches('"'));
            } else if let Some(value) = item.strip_prefix("filename=") {
                part_filename = Some(value.trim_matches('"').to_owned());
            }
        }
        match name {
            Some("purpose") => purpose = Some(String::from_utf8_lossy(body).trim().to_owned()),
            Some("file") => {
                filename = part_filename;
                file = Some(body.to_vec());
            }
            _ => {}
        }
        rest = &body_and_rest[end..];
    }
    let purpose = purpose.ok_or("file purpose is required")?;
    if !matches!(purpose.as_str(), "user_data" | "vision") {
        return Err("purpose must be user_data or vision");
    }
    let file = file.ok_or("file part is required")?;
    if file.is_empty() {
        return Err("file is empty");
    }
    let filename = filename.unwrap_or_else(|| "file".to_owned());
    let filename = filename.rsplit(['/', '\\']).next().unwrap_or("file");
    if filename.is_empty() || filename == "." || filename == ".." || filename.len() > 255 {
        return Err("file name is invalid");
    }
    Ok((filename.to_owned(), purpose, file))
}

async fn health(State(app): State<App>) -> Response {
    match app.traces.list(1, None).await {
        Ok(_) => axum::Json(json!({"status":"ok"})).into_response(),
        Err(_) => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "trace index unavailable",
            None,
        ),
    }
}

#[derive(Deserialize)]
struct RealtimeQuery {
    model: String,
}

async fn realtime(
    State(app): State<App>,
    Query(query): Query<RealtimeQuery>,
    headers: HeaderMap,
    upgrade: axum::extract::ws::WebSocketUpgrade,
) -> Response {
    let selection = match app
        .config
        .resolve_model(&query.model, crate::catalog::Dialect::Realtime)
    {
        Ok(selection) => selection,
        Err(_) => {
            return error_response(
                StatusCode::NOT_IMPLEMENTED,
                "realtime requires one model that declares speech-to-speech; infer does not stitch a voice pipeline",
                None,
            );
        }
    };
    let provider = &app.config.providers[selection.provider];
    let declared = selection
        .operations
        .contains(&crate::catalog::Operation::Realtime);
    if !declared
        || !provider
            .kind
            .dialects()
            .contains(&crate::catalog::Dialect::Realtime)
    {
        return error_response(
            StatusCode::NOT_IMPLEMENTED,
            "realtime requires one model that declares speech-to-speech; infer does not stitch a voice pipeline",
            None,
        );
    }
    let url = match realtime_url(provider, &selection.upstream_model) {
        Ok(url) => url,
        Err(error) => return error_response(StatusCode::BAD_REQUEST, &error.to_string(), None),
    };
    let credentials = provider_credentials(&headers, &app.proxy_token);
    let auth = match app.auth[selection.provider]
        .headers(
            &app.client,
            crate::backend::get(provider.kind).anthropic_credentials(),
            &credentials,
        )
        .await
    {
        Ok(headers) => headers,
        Err(error) => {
            return error_response(StatusCode::BAD_GATEWAY, &error.to_string(), None);
        }
    };
    let request = match realtime_request(&url, &headers, &auth) {
        Ok(request) => request,
        Err(error) => return error_response(StatusCode::BAD_GATEWAY, &error.to_string(), None),
    };
    let upstream = match tokio_tungstenite::connect_async(request).await {
        Ok((socket, _)) => socket,
        Err(_) => {
            return error_response(
                StatusCode::BAD_GATEWAY,
                "realtime upstream websocket failed",
                None,
            );
        }
    };
    upgrade
        .on_upgrade(move |client| proxy_realtime(client, upstream))
        .into_response()
}

fn realtime_url(provider: &Provider, model: &str) -> Result<reqwest::Url> {
    let mut url = reqwest::Url::parse(&provider.base_url).context("invalid provider base URL")?;
    let scheme = match url.scheme() {
        "https" | "wss" => "wss",
        "http" | "ws" => "ws",
        other => bail!("unsupported realtime scheme {other}"),
    };
    url.set_scheme(scheme)
        .map_err(|_| anyhow::anyhow!("cannot set realtime scheme"))?;
    let prefix = url.path().trim_end_matches('/').to_owned();
    url.set_path(&format!("{prefix}/v1/realtime"));
    url.query_pairs_mut().clear().append_pair("model", model);
    Ok(url)
}

fn path_has_dot_segment(path: &str) -> bool {
    path.split('/').any(|segment| {
        let decoded = percent_decode_segment(segment);
        decoded == "." || decoded == ".." || decoded.contains('/') || decoded.contains('\\')
    })
}

fn percent_decode_segment(segment: &str) -> String {
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
        {
            out.push((high << 4) | low);
            index += 3;
            continue;
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn realtime_request(
    url: &reqwest::Url,
    incoming: &HeaderMap,
    auth: &HeaderMap,
) -> Result<tokio_tungstenite::tungstenite::handshake::client::Request> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut request = url.as_str().into_client_request()?;
    for (name, value) in filtered_headers(incoming, true) {
        let Some(name) = name else {
            continue;
        };
        if request.headers().contains_key(&name) {
            continue;
        }
        request.headers_mut().append(name, value);
    }
    for (name, value) in auth.iter() {
        request.headers_mut().insert(name, value.clone());
    }
    Ok(request)
}

async fn proxy_realtime(
    client: axum::extract::ws::WebSocket,
    upstream: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) {
    use axum::extract::ws::Message as ClientMessage;
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message as UpstreamMessage;
    let (mut client_write, mut client_read) = client.split();
    let (mut upstream_write, mut upstream_read) = upstream.split();
    // Each direction must keep reading while the other send waits. A single
    // select arm that awaits send fills both TCP windows and stops polling.
    let client_to_up = async {
        while let Some(Ok(message)) = client_read.next().await {
            let Some(message) = client_to_upstream(message) else {
                continue;
            };
            if upstream_write.send(message).await.is_err() {
                break;
            }
        }
        let _ = upstream_write.send(UpstreamMessage::Close(None)).await;
    };
    let up_to_client = async {
        while let Some(Ok(message)) = upstream_read.next().await {
            let Some(message) = upstream_to_client(message) else {
                continue;
            };
            if client_write.send(message).await.is_err() {
                break;
            }
        }
        let _ = client_write.send(ClientMessage::Close(None)).await;
    };
    tokio::join!(client_to_up, up_to_client);
}

fn client_to_upstream(
    message: axum::extract::ws::Message,
) -> Option<tokio_tungstenite::tungstenite::Message> {
    use axum::extract::ws::Message as ClientMessage;
    use tokio_tungstenite::tungstenite::Message as UpstreamMessage;
    Some(match message {
        ClientMessage::Text(text) => UpstreamMessage::Text(text.to_string().into()),
        ClientMessage::Binary(bytes) => UpstreamMessage::Binary(bytes.to_vec().into()),
        ClientMessage::Ping(_) | ClientMessage::Pong(_) => return None,
        ClientMessage::Close(_) => UpstreamMessage::Close(None),
    })
}

fn upstream_to_client(
    message: tokio_tungstenite::tungstenite::Message,
) -> Option<axum::extract::ws::Message> {
    use axum::extract::ws::Message as ClientMessage;
    use tokio_tungstenite::tungstenite::Message as UpstreamMessage;
    Some(match message {
        UpstreamMessage::Text(text) => ClientMessage::Text(text.to_string().into()),
        UpstreamMessage::Binary(bytes) => ClientMessage::Binary(bytes.to_vec().into()),
        UpstreamMessage::Ping(_) | UpstreamMessage::Pong(_) | UpstreamMessage::Frame(_) => {
            return None;
        }
        UpstreamMessage::Close(_) => ClientMessage::Close(None),
    })
}
async fn capabilities(State(app): State<App>) -> Response {
    axum::Json(crate::capabilities::document(&app.config)).into_response()
}

async fn providers(State(app): State<App>) -> Response {
    let providers: Vec<_> = app
        .config
        .providers
        .iter()
        .map(|(name, p)| json!({"name":name,"kind":p.kind,"auth_mode":p.auth.mode}))
        .collect();
    axum::Json(json!({"providers":providers,"models":app.config.models.iter().map(|(alias,r)|json!({"alias":alias,"provider":r.provider,"model":r.model})).collect::<Vec<_>>()})).into_response()
}

#[derive(Deserialize)]
struct Page {
    #[serde(default = "page_limit")]
    limit: usize,
    before: Option<String>,
}
fn page_limit() -> usize {
    50
}

async fn list_traces(State(app): State<App>, Query(page): Query<Page>) -> Response {
    if !(1..=100).contains(&page.limit) {
        return error_response(StatusCode::BAD_REQUEST, "limit must be 1..=100", None);
    }
    match app.traces.list(page.limit, page.before).await {
        Ok(v) => axum::Json(v).into_response(),
        Err(e) => error_response(StatusCode::BAD_REQUEST, &e.to_string(), None),
    }
}
async fn get_trace(State(app): State<App>, Path(id): Path<String>) -> Response {
    match app.traces.get(&id).await {
        Ok(Some(v)) => axum::Json(v).into_response(),
        Ok(None) => error_response(StatusCode::NOT_FOUND, "trace not found", None),
        Err(_) => error_response(
            StatusCode::BAD_REQUEST,
            "invalid trace id or unreadable trace",
            None,
        ),
    }
}
async fn trace_body(State(app): State<App>, Path((id, kind)): Path<(String, String)>) -> Response {
    match app.traces.body(&id, &kind).await {
        Ok(Some(mut file)) => {
            let stream = io_bytes(async_stream::try_stream! {
                let mut buffer = vec![0u8; 65536];
                loop { let n = file.read(&mut buffer).await?; if n == 0 { break; } yield Bytes::copy_from_slice(&buffer[..n]); }
            });
            let mut response = Response::new(Body::from_stream::<_>(stream));
            response.headers_mut().insert(
                "content-type",
                HeaderValue::from_static("application/octet-stream"),
            );
            response
                .headers_mut()
                .insert("cache-control", HeaderValue::from_static("no-store"));
            response
        }
        Ok(None) => error_response(StatusCode::NOT_FOUND, "trace body not found", None),
        Err(_) => error_response(
            StatusCode::BAD_REQUEST,
            "invalid trace id/body kind or unreadable body",
            None,
        ),
    }
}
async fn imported_artifact(State(app): State<App>, Path(digest): Path<String>) -> Response {
    match app.traces.artifact(&digest).await {
        Ok(Some(mut file)) => {
            let stream = io_bytes(async_stream::try_stream! {
                let mut buffer = vec![0u8; 65536];
                loop {
                    let read = file.read(&mut buffer).await?;
                    if read == 0 {
                        break;
                    }
                    yield Bytes::copy_from_slice(&buffer[..read]);
                }
            });
            let mut response = Response::new(Body::from_stream::<_>(stream));
            response.headers_mut().insert(
                "content-type",
                HeaderValue::from_static("application/octet-stream"),
            );
            response
                .headers_mut()
                .insert("cache-control", HeaderValue::from_static("no-store"));
            response
        }
        Ok(None) => error_response(StatusCode::NOT_FOUND, "artifact not found", None),
        Err(_) => error_response(
            StatusCode::BAD_REQUEST,
            "invalid artifact digest or unreadable artifact",
            None,
        ),
    }
}

async fn export(State(app): State<App>, Query(page): Query<Page>) -> Response {
    if !(1..=100).contains(&page.limit) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "export limit must be 1..=100",
            None,
        );
    }
    match app.traces.export(page.limit, page.before).await {
        Ok(rows) => {
            let body: String = rows
                .iter()
                .map(|row| format!("{}\n", serde_json::to_string(row).unwrap()))
                .collect();
            let mut response = body.into_response();
            response.headers_mut().insert(
                "content-type",
                HeaderValue::from_static("application/x-ndjson"),
            );
            response
                .headers_mut()
                .insert("cache-control", HeaderValue::from_static("no-store"));
            response
        }
        Err(error) => error_response(StatusCode::BAD_REQUEST, &error.to_string(), None),
    }
}

async fn ingest_session_event(State(app): State<App>, request: Request) -> Response {
    let bytes = match to_bytes(request.into_body(), app.config.max_request_bytes).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "session event body exceeds the request limit or could not be read",
                None,
            );
        }
    };
    let event = match SessionEvent::decode(&bytes) {
        Ok(event) => event,
        Err(error) => return error_response(StatusCode::BAD_REQUEST, &error.to_string(), None),
    };
    match app.traces.put_event(event).await {
        Ok(receipt) => {
            let mut response = (StatusCode::CREATED, axum::Json(receipt)).into_response();
            response
                .headers_mut()
                .insert("cache-control", HeaderValue::from_static("no-store"));
            response
        }
        Err(error) if error.downcast_ref::<EventConflict>().is_some() => error_response(
            StatusCode::CONFLICT,
            "event id already has different data",
            None,
        ),
        Err(error) if error.downcast_ref::<InvalidSessionEvent>().is_some() => {
            error_response(StatusCode::BAD_REQUEST, &error.to_string(), None)
        }
        Err(error) => {
            tracing::error!(%error, "session event storage failed");
            error_response(
                StatusCode::INSUFFICIENT_STORAGE,
                "session event storage unavailable",
                None,
            )
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionPage {
    #[serde(default = "page_limit")]
    limit: usize,
    before: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EventPage {
    #[serde(default = "page_limit")]
    limit: usize,
    #[serde(default)]
    after: u64,
}

async fn list_sessions(State(app): State<App>, Query(page): Query<SessionPage>) -> Response {
    match app.traces.list_sessions(page.limit, page.before).await {
        Ok(value) => axum::Json(value).into_response(),
        Err(error) => error_response(StatusCode::BAD_REQUEST, &error.to_string(), None),
    }
}

async fn session_events(
    State(app): State<App>,
    Path(id): Path<String>,
    Query(page): Query<EventPage>,
) -> Response {
    match app.traces.session_events(&id, page.limit, page.after).await {
        Ok(value) => axum::Json(value).into_response(),
        Err(error) => error_response(StatusCode::BAD_REQUEST, &error.to_string(), None),
    }
}

async fn session_traces(
    State(app): State<App>,
    Path(id): Path<String>,
    Query(page): Query<Page>,
) -> Response {
    match app
        .traces
        .session_traces(&id, page.limit, page.before)
        .await
    {
        Ok(value) => axum::Json(value).into_response(),
        Err(error) => error_response(StatusCode::BAD_REQUEST, &error.to_string(), None),
    }
}

async fn export_session_events(
    State(app): State<App>,
    Path(id): Path<String>,
    Query(page): Query<EventPage>,
) -> Response {
    match app.traces.session_events(&id, page.limit, page.after).await {
        Ok(value) => {
            let mut body = String::new();
            for row in value["events"]
                .as_array()
                .expect("event page contains rows")
            {
                body.push_str(&serde_json::to_string(row).expect("JSON event serializes"));
                body.push('\n');
            }
            let mut response = body.into_response();
            response.headers_mut().insert(
                "content-type",
                HeaderValue::from_static("application/x-ndjson"),
            );
            if let Some(next) = value["next_after"].as_u64() {
                response.headers_mut().insert(
                    "x-infer-next-after",
                    HeaderValue::from_str(&next.to_string()).expect("numeric cursor"),
                );
            }
            response
        }
        Err(error) => error_response(StatusCode::BAD_REQUEST, &error.to_string(), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Kind;

    #[test]
    fn dot_segments_cannot_leave_an_account_path() {
        let provider = crate::config::Provider {
            kind: Kind::Clairic,
            base_url: "https://api.cloudflare.com/deployment".into(),
            auth: crate::auth::AuthConfig::default(),
            namespace: None,
            danger_zone_images: false,
            daybreak: crate::config::DaybreakLevel::Standard,
        };
        let uri = Uri::from_static("/");
        for suffix in [
            "/client/v4/accounts/../ai/run/@cf/cloudflare/clairic",
            "/client/v4/accounts/%2e%2e/ai/run/@cf/cloudflare/clairic",
            "/client/v4/accounts/%2E%2E/ai/run/@cf/cloudflare/clairic",
        ] {
            let error = upstream_url(&provider, suffix, &uri)
                .unwrap_err()
                .to_string();
            assert!(error.contains("escapes"), "{suffix}: {error}");
        }
        let kept = upstream_url(
            &provider,
            "/client/v4/accounts/account-01/ai/run/@cf/cloudflare/clairic",
            &uri,
        )
        .unwrap();
        assert!(kept.path().contains("/accounts/account-01/"));
        assert!(
            crate::route::Route::recognize(
                &Method::POST,
                "/client/v4/accounts/../ai/run/@cf/cloudflare/clairic"
            )
            .is_none()
        );
        assert!(
            crate::route::Route::recognize(
                &Method::POST,
                "/client/v4/accounts/%2E%2E/ai/run/@cf/cloudflare/clairic"
            )
            .is_none()
        );
        assert!(
            crate::route::Route::recognize(
                &Method::POST,
                "/client/v4/accounts/account-01/ai/run/@cf/cloudflare/clairic"
            )
            .is_some()
        );
    }

    struct HttpFixture {
        gateway: String,
        upstream: String,
        app: App,
        requests: tokio::sync::mpsc::UnboundedReceiver<(Method, String, Bytes)>,
        servers: Vec<tokio::task::JoinHandle<()>>,
        _directory: tempfile::TempDir,
    }

    impl Drop for HttpFixture {
        fn drop(&mut self) {
            for server in &self.servers {
                server.abort();
            }
        }
    }

    async fn http_fixture(prefix: &str, unavailable_auth: bool) -> HttpFixture {
        let directory = tempfile::tempdir().unwrap();
        let (tx, requests) = tokio::sync::mpsc::unbounded_channel();
        let failure_database = directory.path().join("traces/index.sqlite3");
        let backend =
            Router::new().fallback(move |request: Request| {
                let tx = tx.clone();
                let failure_database = failure_database.clone();
                async move {
                    let (parts, body) = request.into_parts();
                    let path = parts.uri.path();
                    if path.ends_with("/early") {
                        // A forwarded chunk has already completed its trace append.
                        // Reply while the rest of this upload is still pending.
                        let bytes = body.into_data_stream().next().await.unwrap().unwrap();
                        tx.send((parts.method, parts.uri.to_string(), bytes))
                            .unwrap();
                        return StatusCode::NO_CONTENT.into_response();
                    }
                    if path.ends_with("/commit-failure") {
                        tokio::task::spawn_blocking(move || {
                            let connection = rusqlite::Connection::open(failure_database).unwrap();
                            connection.execute_batch(
                            "CREATE TRIGGER fail_completion BEFORE UPDATE OF complete ON traces
                             WHEN NEW.complete = 1 BEGIN
                             SELECT RAISE(FAIL, 'injected completion storage failure'); END;"
                        ).unwrap();
                        })
                        .await
                        .unwrap();
                        return StatusCode::NO_CONTENT.into_response();
                    }
                    let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
                    tx.send((parts.method.clone(), parts.uri.to_string(), bytes.clone()))
                        .unwrap();
                    let mut response = Response::new(Body::from(bytes));
                    response
                        .headers_mut()
                        .insert("x-backend", HeaderValue::from_static("observed"));
                    if path.ends_with("/v1/messages") {
                        *response.body_mut() = Body::from(
                            json!({
                                "id":"anthropic-response",
                                "type":"message",
                                "role":"assistant",
                                "model":"mock",
                                "content":[{"type":"text","text":"Accepted"}],
                                "stop_reason":"end_turn",
                                "stop_sequence":null,
                                "usage":{"input_tokens":1,"output_tokens":1}
                            })
                            .to_string(),
                        );
                        response
                            .headers_mut()
                            .insert("content-type", HeaderValue::from_static("application/json"));
                    } else if parts.method == Method::HEAD {
                        response
                            .headers_mut()
                            .insert("content-length", HeaderValue::from_static("123"));
                    } else if path.ends_with("/no-content") {
                        *response.status_mut() = StatusCode::NO_CONTENT;
                        *response.body_mut() = Body::empty();
                    } else if path.ends_with("/not-modified") {
                        *response.status_mut() = StatusCode::NOT_MODIFIED;
                        // An already-ended body makes Hyper remove this legal
                        // representation length before the gateway can receive it.
                        *response.body_mut() =
                            Body::from_stream(futures_util::stream::empty::<io::Result<Bytes>>());
                        response
                            .headers_mut()
                            .insert("content-length", HeaderValue::from_static("456"));
                    } else if path.ends_with("/not-modified-no-length") {
                        *response.status_mut() = StatusCode::NOT_MODIFIED;
                        *response.body_mut() = Body::empty();
                    }
                    response
                }
            });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = format!("http://{}", listener.local_addr().unwrap());
        let backend_server = tokio::spawn(async move {
            axum::serve(listener, backend).await.unwrap();
        });
        let mut auth = crate::auth::AuthConfig::default();
        if unavailable_auth {
            auth.mode = "codex".into();
            auth.auth_file = Some(directory.path().join("missing-auth.json"));
        }
        let provider = Provider {
            kind: Kind::Openai,
            base_url: format!("{upstream}{prefix}"),
            auth: auth.clone(),
            namespace: None,
            danger_zone_images: false,
            daybreak: crate::config::DaybreakLevel::Standard,
        };
        let config = Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            control_listen: "127.0.0.1:1".parse().unwrap(),
            proxy_token_env: String::new(),
            control_token_env: String::new(),
            trace_dir: directory.path().join("traces"),
            default_provider: "native".into(),
            max_request_bytes: 1,
            max_buffered_response_bytes: 1024,
            connect_timeout_seconds: 2,
            read_timeout_seconds: 2,
            providers: BTreeMap::from([("native".into(), provider)]),
            models: BTreeMap::new(),
        };
        let app = App {
            traces: TraceStore::open(&config.trace_dir).await.unwrap(),
            config: Arc::new(config),
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
            auth: Arc::new(BTreeMap::from([(
                "native".into(),
                ProviderAuth::new(auth).unwrap(),
            )])),
            proxy_token: Arc::new("test-gateway-token".into()),
        };
        let router = Router::new().fallback(inference).with_state(app.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gateway = format!("http://{}", listener.local_addr().unwrap());
        let gateway_server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        HttpFixture {
            gateway,
            upstream,
            app,
            requests,
            servers: vec![backend_server, gateway_server],
            _directory: directory,
        }
    }

    async fn recorded_body(app: &App, id: &str, kind: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        app.traces
            .body(id, kind)
            .await
            .unwrap()
            .unwrap()
            .read_to_end(&mut bytes)
            .await
            .unwrap();
        bytes
    }

    async fn assert_interrupted_upload_is_not_finalized(path: &str, prefix: &'static [u8]) {
        let fixture = http_fixture("", false).await;
        let mut app = fixture.app.clone();
        let config = Arc::make_mut(&mut app.config);
        config.max_request_bytes = 4096;
        config.models.insert(
            "alias".into(),
            crate::config::ModelRoute {
                provider: "native".into(),
                model: "upstream-model".into(),
                operations: Vec::new(),
                modalities: Vec::new(),
            },
        );
        let body = futures_util::stream::iter([
            Ok::<_, io::Error>(Bytes::from_static(prefix)),
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "injected truncated upload",
            )),
        ]);
        let response = inference(
            State(app),
            Request::builder()
                .method(Method::POST)
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from_stream(body))
                .unwrap(),
        )
        .await;
        assert!(
            matches!(
                response.status(),
                StatusCode::BAD_REQUEST | StatusCode::BAD_GATEWAY
            ),
            "{}",
            response.status()
        );
        let id = response.headers()["x-infer-trace-id"]
            .to_str()
            .unwrap()
            .to_owned();
        let trace = fixture.app.traces.get(&id).await.unwrap().unwrap();
        assert_eq!(trace["complete"], false, "{trace}");
        assert!(trace["status"].is_null(), "{trace}");
        assert!(trace["error"].is_null(), "{trace}");
        assert_eq!(recorded_body(&fixture.app, &id, "request").await, prefix);
        assert!(
            recorded_body(&fixture.app, &id, "response")
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn interrupted_routed_upload_preserves_prefix_without_finalizing_trace() {
        assert_interrupted_upload_is_not_finalized(
            "/v1/chat/completions",
            b"{\"model\":\"alias\",\"messages\":[",
        )
        .await;
    }

    #[tokio::test]
    async fn interrupted_native_upload_preserves_prefix_without_finalizing_trace() {
        assert_interrupted_upload_is_not_finalized(
            "/providers/native/v1/chat/completions",
            b"{\"prefix\":\"native-",
        )
        .await;
    }

    async fn raw_get(fixture: &HttpFixture, path: &str) -> (u16, String) {
        use tokio::io::AsyncWriteExt;
        let address = fixture.gateway.strip_prefix("http://").unwrap();
        let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
        socket
            .write_all(
                format!("GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let mut bytes = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), socket.read_to_end(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        let response = String::from_utf8(bytes).unwrap();
        let status = response
            .split_ascii_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let id = response
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("x-infer-trace-id")
                    .then(|| value.trim().to_owned())
            })
            .unwrap();
        (status, id)
    }

    #[tokio::test]
    async fn translated_caps_satisfy_openai_and_legacy_provider_contracts() {
        for (kind, cap_key) in [
            (Kind::Openai, "max_completion_tokens"),
            (Kind::Grok, "max_tokens"),
            (Kind::Llama, "max_tokens"),
        ] {
            let mut fixture = http_fixture("", false).await;
            let backend = Router::new().route(
                "/v1/chat/completions",
                axum::routing::post(move |axum::Json(body): axum::Json<Value>| async move {
                    let other_cap = if cap_key == "max_tokens" {
                        "max_completion_tokens"
                    } else {
                        "max_tokens"
                    };
                    if body[cap_key] != 128 || body.get(other_cap).is_some() {
                        return (StatusCode::BAD_REQUEST, axum::Json(json!({
                            "error":{"message":"unsupported token cap"}
                        })));
                    }
                    (StatusCode::OK, axum::Json(json!({
                        "id":"cap-response",
                        "choices":[{"index":0,"message":{"role":"assistant","content":"Accepted"},
                            "finish_reason":"stop"}]
                    })))
                }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut app = fixture.app.clone();
            let config = Arc::make_mut(&mut app.config);
            config.max_request_bytes = 4096;
            let provider = config.providers.get_mut("native").unwrap();
            provider.kind = kind;
            provider.base_url = format!("http://{}", listener.local_addr().unwrap());
            fixture.servers.push(tokio::spawn(async move {
                axum::serve(listener, backend).await.unwrap();
            }));
            let response = inference(
                State(app),
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/messages")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "model":"model","max_tokens":128,
                            "messages":[{"role":"user","content":"Hello"}]
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK, "{kind:?}");
            let bytes = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let body = crate::json::from_slice(&bytes).unwrap();
            assert_eq!(body["content"], json!([{"type":"text","text":"Accepted"}]));
            assert_eq!(body["stop_reason"], "end_turn");
        }
    }

    #[tokio::test]
    async fn responses_to_anthropic_requires_explicit_store_false_before_upstream() {
        let mut fixture = http_fixture("", false).await;
        let mut app = fixture.app.clone();
        let config = Arc::make_mut(&mut app.config);
        config.max_request_bytes = 4096;
        config.providers.get_mut("native").unwrap().kind = Kind::Anthropic;

        for store in [None, Some(Value::Null), Some(json!(true))] {
            let mut body = json!({
                "model":"model",
                "max_output_tokens":16,
                "input":"Hello"
            });
            if let Some(store) = store {
                body["store"] = store;
            }
            let response = inference(
                State(app.clone()),
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/responses")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert!(fixture.requests.try_recv().is_err());
        }

        let response = inference(
            State(app),
            Request::builder()
                .method(Method::POST)
                .uri("/v1/responses")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "model":"model",
                        "max_output_tokens":16,
                        "store":false,
                        "input":"Hello"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let (_, uri, bytes) = fixture.requests.recv().await.unwrap();
        assert_eq!(uri, "/v1/messages");
        let translated: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(translated.get("store"), None);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let translated_response: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            translated_response["output"][0]["content"][0]["text"],
            "Accepted"
        );
    }

    #[tokio::test]
    async fn namespaced_model_selects_provider_and_strips_prefix() {
        let mut fixture = http_fixture("", false).await;
        let mut app = fixture.app.clone();
        {
            let config = Arc::make_mut(&mut app.config);
            config.max_request_bytes = 4096;
            let base_url = config.providers["native"].base_url.clone();
            config.providers.insert(
                "grok".into(),
                Provider {
                    kind: Kind::Grok,
                    base_url,
                    auth: crate::auth::AuthConfig::default(),
                    namespace: Some("xai".into()),
                    danger_zone_images: false,
                    daybreak: crate::config::DaybreakLevel::Standard,
                },
            );
        }
        Arc::make_mut(&mut app.auth).insert(
            "grok".into(),
            ProviderAuth::new(crate::auth::AuthConfig::default()).unwrap(),
        );

        let response = inference(
            State(app.clone()),
            Request::builder()
                .method(Method::POST)
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "model":"xai/grok-4.7",
                        "messages":[{"role":"user","content":"Hello"}]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let id = response.headers()["x-infer-trace-id"]
            .to_str()
            .unwrap()
            .to_owned();
        let (_, _, bytes) = fixture.requests.recv().await.unwrap();
        let upstream: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(upstream["model"], "grok-4.7");
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let trace = fixture.app.traces.get(&id).await.unwrap().unwrap();
        assert_eq!(trace["provider"], "grok");

        let response = inference(
            State(app),
            Request::builder()
                .method(Method::POST)
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "model":"org/local-model",
                        "messages":[{"role":"user","content":"Hello"}]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let id = response.headers()["x-infer-trace-id"]
            .to_str()
            .unwrap()
            .to_owned();
        let (_, _, bytes) = fixture.requests.recv().await.unwrap();
        let upstream: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(upstream["model"], "org/local-model");
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let trace = fixture.app.traces.get(&id).await.unwrap().unwrap();
        assert_eq!(trace["provider"], "native");
    }

    #[tokio::test]
    async fn native_get_and_post_uploads_reach_backend_and_finish_lossless_traces() {
        let mut fixture = http_fixture("/scoped/", false).await;
        for (method, payload, chunked) in [
            (Method::GET, &b"native GET payload!"[..], false),
            (Method::GET, &b""[..], false),
            (Method::GET, &b"chunked GET payload"[..], true),
            (Method::POST, &b"ordinary POST body"[..], false),
        ] {
            let mut request = fixture.app.client.request(
                method.clone(),
                format!(
                    "{}/providers/native/echo?item=a%2Fb&item=c",
                    fixture.gateway
                ),
            );
            if chunked {
                let data = Bytes::copy_from_slice(payload);
                request = request.header("transfer-encoding", "chunked").body(
                    reqwest::Body::wrap_stream(futures_util::stream::iter([
                        Ok::<_, io::Error>(data.slice(..7)),
                        Ok(data.slice(7..)),
                    ])),
                );
            } else {
                request = request.body(Bytes::copy_from_slice(payload));
            }
            let response = request.send().await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let id = response.headers()["x-infer-trace-id"]
                .to_str()
                .unwrap()
                .to_owned();
            assert_eq!(response.bytes().await.unwrap().as_ref(), payload);
            let (observed_method, uri, bytes) = fixture.requests.recv().await.unwrap();
            assert_eq!(observed_method, method);
            assert_eq!(uri, "/scoped/echo?item=a%2Fb&item=c");
            assert_eq!(bytes.as_ref(), payload);
            let trace = fixture.app.traces.get(&id).await.unwrap().unwrap();
            assert_eq!(trace["complete"], true);
            assert_eq!(trace["status"], 200);
            assert!(trace["error"].is_null(), "{trace}");
            assert_eq!(trace["upstream_url"], format!("{}{uri}", fixture.upstream));
            assert_eq!(recorded_body(&fixture.app, &id, "request").await, payload);
            assert_eq!(recorded_body(&fixture.app, &id, "response").await, payload);
        }
    }

    #[tokio::test]
    async fn bodyless_http_responses_finish_before_returning_and_preserve_metadata() {
        let mut fixture = http_fixture("/scoped", false).await;
        for (method, path, status, length, payload, chunked) in [
            (
                Method::HEAD,
                "representation",
                200,
                Some("123"),
                &b""[..],
                false,
            ),
            (Method::GET, "no-content", 204, None, &b""[..], false),
            (
                Method::GET,
                "not-modified",
                304,
                Some("456"),
                &b""[..],
                false,
            ),
            (
                Method::GET,
                "not-modified-no-length",
                304,
                None,
                &b""[..],
                false,
            ),
            (
                Method::POST,
                "no-content",
                204,
                None,
                &b"complete fixed upload"[..],
                false,
            ),
            (
                Method::POST,
                "no-content",
                204,
                None,
                &b"complete chunked upload"[..],
                true,
            ),
        ] {
            let mut request = fixture.app.client.request(
                method.clone(),
                format!("{}/providers/native/{path}", fixture.gateway),
            );
            if chunked {
                request = request.body(reqwest::Body::wrap_stream(futures_util::stream::iter([
                    Ok::<_, io::Error>(Bytes::copy_from_slice(&payload[..7])),
                    Ok(Bytes::copy_from_slice(&payload[7..])),
                ])));
            } else {
                request = request.body(Bytes::copy_from_slice(payload));
            }
            let response = request.send().await.unwrap();
            assert_eq!(response.status().as_u16(), status);
            if let Some(length) = length {
                assert_eq!(response.headers().get("content-length").unwrap(), length);
            } else {
                assert!(!response.headers().contains_key("content-length"));
            }
            let id = response.headers()["x-infer-trace-id"]
                .to_str()
                .unwrap()
                .to_owned();
            let (observed_method, uri, bytes) = fixture.requests.recv().await.unwrap();
            assert_eq!(observed_method, method);
            assert_eq!(uri, format!("/scoped/{path}"));
            assert_eq!(bytes.as_ref(), payload);
            // The trace must already be final when only the response headers
            // have been consumed; these responses have no body to drive polling.
            let trace = fixture.app.traces.get(&id).await.unwrap().unwrap();
            assert_eq!(trace["complete"], true, "{trace}");
            assert_eq!(trace["status"], status);
            assert_eq!(
                trace["response_headers"]["upstream"]["x-backend"][0],
                "observed"
            );
            assert_eq!(
                trace["response_headers"]["client"]["x-backend"][0],
                "observed"
            );
            if let Some(length) = length {
                assert_eq!(
                    trace["response_headers"]["upstream"]["content-length"][0],
                    length
                );
                assert_eq!(
                    trace["response_headers"]["client"]["content-length"][0],
                    length
                );
            }
            if status != 304 {
                assert!(trace["error"].is_null(), "{trace}");
            }
            assert!(
                recorded_body(&fixture.app, &id, "response")
                    .await
                    .is_empty()
            );
            assert_eq!(recorded_body(&fixture.app, &id, "request").await, payload);
            assert!(response.bytes().await.unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn bodyless_response_commit_failure_fails_closed() {
        let fixture = http_fixture("/scoped", false).await;
        let response = fixture
            .app
            .client
            .get(format!(
                "{}/providers/native/commit-failure",
                fixture.gateway
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INSUFFICIENT_STORAGE);
        let id = response.headers()["x-infer-trace-id"]
            .to_str()
            .unwrap()
            .to_owned();
        let trace = fixture.app.traces.get(&id).await.unwrap().unwrap();
        assert_eq!(trace["complete"], false);
        assert!(trace["status"].is_null(), "{trace}");
    }

    #[tokio::test]
    async fn early_bodyless_response_records_incomplete_upload_instead_of_success() {
        let mut fixture = http_fixture("/scoped", false).await;
        let body = futures_util::stream::once(async {
            Ok::<_, io::Error>(Bytes::from_static(b"partial"))
        })
        .chain(futures_util::stream::pending());
        let response = fixture
            .app
            .client
            .post(format!("{}/providers/native/early", fixture.gateway))
            .body(reqwest::Body::wrap_stream(body))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let id = response.headers()["x-infer-trace-id"]
            .to_str()
            .unwrap()
            .to_owned();
        let trace = fixture.app.traces.get(&id).await.unwrap().unwrap();
        assert_eq!(trace["complete"], true);
        assert_eq!(trace["status"], 204);
        assert_eq!(
            trace["error"],
            "upstream responded before the complete request upload was recorded"
        );
        let (method, uri, bytes) = fixture.requests.recv().await.unwrap();
        assert_eq!(method, Method::POST);
        assert_eq!(uri, "/scoped/early");
        assert_eq!(bytes.as_ref(), b"partial");
        assert_eq!(
            recorded_body(&fixture.app, &id, "request").await,
            b"partial"
        );
        assert!(
            recorded_body(&fixture.app, &id, "response")
                .await
                .is_empty()
        );
    }

    #[test]
    fn cancelled_upload_append_makes_early_bodyless_response_fail_closed() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        runtime.block_on(async {
            let fixture = http_fixture("/scoped", false).await;
            let upstream = fixture
                .app
                .client
                .get(format!("{}/scoped/no-content", fixture.upstream))
                .send()
                .await
                .unwrap();
            assert_eq!(upstream.status(), StatusCode::NO_CONTENT);
            let id = uuid::Uuid::new_v4().to_string();
            let mut writer = fixture
                .app
                .traces
                .start(TraceStart {
                    id: id.clone(),
                    provider: "native".into(),
                    method: "POST".into(),
                    path: "/providers/native/early".into(),
                    request_headers: json!({}),
                    upstream_url: format!("{}/scoped/early", fixture.upstream),
                    upstream_headers: json!({}),
                })
                .await
                .unwrap();

            // Hold the only filesystem worker so the append must suspend after
            // poisoning the writer. Dropping that future models Hyper cancelling
            // the upload on an early response, without racing filesystem timing.
            let (release, blocked) = std::sync::mpsc::channel::<()>();
            let (started, ready) = tokio::sync::oneshot::channel();
            let blocker = tokio::task::spawn_blocking(move || {
                started.send(()).unwrap();
                let _ = blocked.recv();
            });
            ready.await.unwrap();
            {
                let append = writer.request(b"partial");
                tokio::pin!(append);
                assert!(futures_util::poll!(append).is_pending());
            }
            drop(release);
            blocker.await.unwrap();

            let response = respond(
                &fixture.app,
                upstream,
                Arc::new(Mutex::new(Some(writer))),
                id.clone(),
                None,
                false,
                None,
                None,
                Some(Arc::new(UploadState {
                    complete: AtomicBool::new(false),
                    body_failed: AtomicBool::new(false),
                })),
                false,
            )
            .await;
            assert_eq!(response.status(), StatusCode::INSUFFICIENT_STORAGE);
            assert_eq!(response.headers()["x-infer-trace-id"], id.as_str());
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let error: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(error["error"]["message"], "trace commit failed");
            let trace = fixture.app.traces.get(&id).await.unwrap().unwrap();
            assert_eq!(trace["complete"], false, "{trace}");
            // Refusing the commit leaves no published completion status/error;
            // the consumer receives the 507 diagnostic instead of a false 204.
            assert!(trace["status"].is_null(), "{trace}");
            assert!(trace["error"].is_null(), "{trace}");
            assert!(trace["completed_at"].is_null(), "{trace}");
        });
    }

    #[tokio::test]
    async fn prefix_escapes_are_recorded_bad_requests_before_auth_or_backend_contact() {
        let mut fixture = http_fixture("/scope/", true).await;
        for path in [
            "/providers/native/%2e%2e/admin",
            "/providers/native/.%2e/admin",
            "/providers/native/%2E./admin",
            "/providers/native/%2e%2e/scope-other/admin",
            "/providers/native/%2e%2e\\admin",
        ] {
            let (status, id) = raw_get(&fixture, path).await;
            assert_eq!(status, 400, "{path}");
            let trace = fixture.app.traces.get(&id).await.unwrap().unwrap();
            assert_eq!(trace["complete"], true);
            assert_eq!(trace["status"], 400);
            assert_eq!(trace["upstream_url"], "");
            assert!(fixture.requests.try_recv().is_err());
        }
    }

    #[tokio::test]
    async fn normalized_paths_within_prefix_record_exact_backend_url() {
        let mut fixture = http_fixture("/scope/", false).await;
        let (status, id) = raw_get(
            &fixture,
            "/providers/native/child/%2e%2e/echo?keep=a%2Fb&repeat=1&repeat=2",
        )
        .await;
        assert_eq!(status, 200);
        let (_, uri, _) = fixture.requests.recv().await.unwrap();
        assert_eq!(uri, "/scope/echo?keep=a%2Fb&repeat=1&repeat=2");
        let trace = fixture.app.traces.get(&id).await.unwrap().unwrap();
        assert_eq!(trace["complete"], true);
        assert_eq!(trace["upstream_url"], format!("{}{uri}", fixture.upstream));
    }

    async fn media_type_response(
        app: &App,
        content_type: &str,
        body: &str,
        protocols: Option<(Protocol, Protocol, String, bool)>,
    ) -> Response {
        let upstream = reqwest::Response::from(
            axum::http::Response::builder()
                .header("content-type", content_type)
                .body(body.to_owned())
                .unwrap(),
        );
        respond(
            app,
            upstream,
            Arc::new(Mutex::new(None)),
            uuid::Uuid::new_v4().to_string(),
            protocols.map(|(from, to, model, stream)| ResponseRoute {
                upstream_protocol: from,
                client_protocol: to,
                model,
                client_stream: stream,
                include_usage: true,
                upstream_stream: stream,
            }),
            false,
            None,
            None,
            None,
            false,
        )
        .await
    }

    #[tokio::test]
    async fn sse_media_types_translate_streaming_chat_case_insensitively() {
        let fixture = http_fixture("", false).await;
        let body = concat!(
            "data: {\"id\":\"chat-1\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"hello\"},\"finish_reason\":null}]}\n\n",
            "data: {\"id\":\"chat-1\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
            "data: [DONE]\n\n",
        );
        for content_type in [
            "Text/Event-Stream",
            "text/event-stream; charset=utf-8",
            "\t TeXt/EvEnT-StReAm \t; charset=utf-8",
        ] {
            let response = media_type_response(
                &fixture.app,
                content_type,
                body,
                Some((Protocol::Chat, Protocol::Anthropic, "model".into(), true)),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK, "{content_type}");
            assert_eq!(response.headers()["content-type"], "text/event-stream");
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let text = std::str::from_utf8(&bytes).unwrap();
            let events: Vec<Value> = text
                .lines()
                .filter_map(|line| line.strip_prefix("data: "))
                .map(|data| serde_json::from_str(data).unwrap())
                .collect();
            assert!(
                events.iter().any(|event| {
                    event["type"] == "content_block_delta" && event["delta"]["text"] == "hello"
                }),
                "{text}"
            );
            assert!(
                events.iter().any(|event| event["type"] == "message_stop"),
                "{text}"
            );
        }
    }

    #[tokio::test]
    async fn sse_media_types_reconstruct_buffered_responses_case_insensitively() {
        let fixture = http_fixture("", false).await;
        let body = concat!(
            "event: response.completed\n",
            "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"r\",\"status\":\"completed\",\"output\":[{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"hello\"}]}],\"usage\":{}}}\n\n",
        );
        for content_type in [
            "Text/Event-Stream",
            "text/event-stream; charset=utf-8",
            " \tTEXT/EVENT-STREAM\t ; charset=utf-8",
        ] {
            let response = media_type_response(
                &fixture.app,
                content_type,
                body,
                Some((Protocol::Responses, Protocol::Chat, "model".into(), false)),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK, "{content_type}");
            assert_eq!(response.headers()["content-type"], "application/json");
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let value: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(value["choices"][0]["message"]["content"], "hello");
            assert_eq!(value["choices"][0]["finish_reason"], "stop");
        }
    }

    #[tokio::test]
    async fn sse_media_type_lookalikes_are_rejected_for_translation() {
        let fixture = http_fixture("", false).await;
        let body = "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"r\",\"status\":\"completed\",\"output\":[],\"usage\":{}}}\n\n";
        for content_type in [
            "text/event-streaming",
            "text/event-stream+json",
            "application/text/event-stream",
        ] {
            for stream in [true, false] {
                let response = media_type_response(
                    &fixture.app,
                    content_type,
                    body,
                    Some((Protocol::Responses, Protocol::Chat, "model".into(), stream)),
                )
                .await;
                assert_eq!(response.status(), StatusCode::BAD_GATEWAY, "{content_type}");
                let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap();
                let error: Value = serde_json::from_slice(&bytes).unwrap();
                let message = error["error"]["message"].as_str().unwrap();
                if stream {
                    assert_eq!(
                        message,
                        "streaming translation requires an SSE upstream response"
                    );
                } else {
                    assert!(
                        message.starts_with("invalid upstream response:"),
                        "{message}"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn sse_media_type_classification_preserves_native_passthrough() {
        let fixture = http_fixture("", false).await;
        let body = "data: opaque native event\n\n";
        for content_type in ["Text/Event-Stream; charset=utf-8", "text/event-streaming"] {
            let response = media_type_response(&fixture.app, content_type, body, None).await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()["content-type"], content_type);
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(bytes.as_ref(), body.as_bytes());
        }
    }

    #[test]
    fn translation_regression_collected_sse_rejects_unterminated_terminal() {
        let data = b"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"r\",\"status\":\"completed\",\"output\":[],\"usage\":{}}}";
        assert!(translate::collect_response_sse(data, Protocol::Responses).is_err());
    }

    #[test]
    fn translation_regression_collected_sse_accepts_native_line_endings() {
        for ending in ["\n", "\r\n", "\r"] {
            let data = format!(
                "event: response.completed{ending}data: {{\"type\":\"response.completed\",\"response\":{{\"id\":\"r\",\"status\":\"completed\",\"output\":[],\"usage\":{{}}}}}}{ending}{ending}"
            );
            assert_eq!(
                translate::collect_response_sse(data.as_bytes(), Protocol::Responses).unwrap()["id"],
                "r"
            );
        }
    }

    #[test]
    fn credential_regression_removes_gateway_keys_from_every_header_value() {
        let key = "private-gateway-key";
        for scheme in ["Bearer", "bearer", "BEARER", "Bearer  "] {
            let mut headers = HeaderMap::new();
            headers.append(
                "authorization",
                HeaderValue::from_static("Bearer provider-key"),
            );
            headers.append(
                "authorization",
                HeaderValue::from_str(&format!("{scheme} {key}")).unwrap(),
            );
            headers.append("x-api-key", HeaderValue::from_static("provider-api-key"));
            headers.append("x-api-key", HeaderValue::from_str(key).unwrap());
            let clean = provider_credentials(&headers, key);
            assert_eq!(clean.get_all("authorization").iter().count(), 1);
            assert_eq!(clean.get_all("x-api-key").iter().count(), 1);
            assert!(!clean.values().any(|value| {
                value
                    .as_bytes()
                    .windows(key.len())
                    .any(|bytes| bytes == key.as_bytes())
            }));
        }
    }

    #[test]
    fn gateway_tokens_cannot_bypass_bearer_sanitization_with_whitespace() {
        for invalid in [
            "private gateway key",
            "private\tgateway-key",
            "short",
            "private-gateway-é",
        ] {
            assert!(validate_gateway_secret(invalid).is_err());
        }
        let key = "private-gateway-key";
        validate_gateway_secret(key).unwrap();
        let value = HeaderValue::from_str(&format!("Bearer {key}")).unwrap();
        assert_eq!(bearer(&value), Some(key.as_bytes()));
        let mut headers = HeaderMap::new();
        headers.insert("authorization", value);
        assert!(provider_credentials(&headers, key).is_empty());
    }
}
