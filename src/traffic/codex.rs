//! Codex CLI harness.
//!
//! Request shape is taken from openai/codex `69231e119bfca0b14453515e97d99688ce1c47c9`
//! (`ResponsesApiRequest` in `codex-rs/codex-api/src/common.rs`, `build_responses_request`
//! and session headers in `codex-rs/core/src/client.rs`, `default_headers` in
//! `codex-rs/login/src/auth/default_client.rs`). That tree matches release
//! `rust-v0.169.0` (`d32063f96c2dff1dc96af839b3952abb6acfeda4`) for those files.
//! The release binary is the official `codex-package-*` archive, checked against
//! the published `codex-package_SHA256SUMS`.

use std::path::Path;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use super::{
    ClientCall, Exchange, Fixture, ObservedRequest, ObservedResponse, Provenance, SourceNote,
    encoding,
    harness::Harness,
    record::CapturedExchange,
    scrub::{scrub_text, scrub_value},
};
use serde_json::{Map, Value, json};

pub const RELEASE: &str = "rust-v0.169.0";
pub const SOURCE_COMMIT: &str = "69231e119bfca0b14453515e97d99688ce1c47c9";
pub const RELEASE_COMMIT: &str = "d32063f96c2dff1dc96af839b3952abb6acfeda4";
pub const PACKAGE_SUMS_NAME: &str = "codex-package_SHA256SUMS";

/// `codex-package_SHA256SUMS` from the rust-v0.169.0 release, retrieved 2026-11-13.
pub const PACKAGE_SHA256SUMS: &str = "\
50284209ed4cad6627a3fdff67336a6bf98874099766209920c46a53f489ee08  codex-app-server-package-aarch64-apple-darwin.tar.gz
8a232260df7a12c5e83e0b4b7659e1c8d9259b41942517bc0068d8ab55c36461  codex-package-aarch64-apple-darwin.tar.gz
988d225f8c7af824ebc2946f55fd8b8a1417a6832c460fcfc5fa3af158722ad1  codex-app-server-package-aarch64-pc-windows-msvc.tar.gz
75318180f853d1846f6542f3f6409bfeae4553b91cac6aaaa08c64ee16e7a534  codex-package-aarch64-pc-windows-msvc.tar.gz
ec781053d9f5d36057d12304640e8bf166a52b5e7684cdfd34842bd90b1adca4  codex-app-server-package-aarch64-unknown-linux-musl.tar.gz
c8d0b4ab2a97c595b70b10412d36d0d5464dcef1e1d3246b073d48017cdf5a4f  codex-package-aarch64-unknown-linux-musl.tar.gz
05da7e8c5f6e286977595c737ee0ee81de93525e6c2b0a0279af8bf83b6e6832  codex-provisioned-package-aarch64-apple-darwin.tar.gz
c69993dc7b978665315a3f1f358f3f4aa106dadedb715db46597b86b9b160e54  codex-provisioned-package-x86_64-apple-darwin.tar.gz
2661c50242e496abc41dbe00d836958c4c3cef9a8f13f4cf1d0189d980aba252  codex-app-server-package-x86_64-apple-darwin.tar.gz
0a3c392235b4712409495ced02bbe0662ce7a038232766d1c1c34af74e905c2f  codex-package-x86_64-apple-darwin.tar.gz
37ad913838d7755929802aa7137dc25560a6c246578d014273a450669491b5df  codex-app-server-package-x86_64-pc-windows-msvc.tar.gz
456db280d16f4393cd99a398f11b4a14a3ede68b6bd31610ce41fb10d6b65737  codex-package-x86_64-pc-windows-msvc.tar.gz
91c08d7d795342f934ba90ae105427be54effcd9844ae63e2ec0cca2484ba452  codex-app-server-package-x86_64-unknown-linux-musl.tar.gz
3b8ed091149cc63a59046b9f094bcfa21cdb4dda15ede441ce369bcee4a71ba0  codex-package-x86_64-unknown-linux-musl.tar.gz";

pub static CODEX: Codex = Codex;

pub struct Codex;

impl Harness for Codex {
    fn id(&self) -> &'static str {
        "codex"
    }

    fn api_base_path(&self) -> &'static str {
        "/backend-api/codex"
    }

    fn compared_headers(&self) -> &'static [&'static str] {
        &[
            "accept",
            "content-type",
            "originator",
            "session-id",
            "thread-id",
            "version",
            "x-client-request-id",
            "x-codex-routing-hint",
            // Present when the caller sent client_metadata. Absence is compared.
            "x-codex-turn-metadata",
            "x-codex-window-id",
            // Present only for Responses Lite models. Absence is also compared.
            "x-openai-internal-codex-responses-lite",
        ]
    }

    fn forbidden_headers(&self) -> &'static [&'static str] {
        // `default_headers` does not send `OpenAI-Beta: responses=experimental`.
        // The websocket transport sets a different beta value; the HTTP capture
        // disables websockets, and infer must not invent this header.
        &["openai-beta"]
    }
}

pub fn fixture_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/traffic/codex/fixtures")
}

pub fn package_filename() -> Result<&'static str> {
    Ok(match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "codex-package-x86_64-unknown-linux-musl.tar.gz",
        ("linux", "aarch64") => "codex-package-aarch64-unknown-linux-musl.tar.gz",
        ("macos", "x86_64") => "codex-package-x86_64-apple-darwin.tar.gz",
        ("macos", "aarch64") => "codex-package-aarch64-apple-darwin.tar.gz",
        ("windows", "x86_64") => "codex-package-x86_64-pc-windows-msvc.tar.gz",
        ("windows", "aarch64") => "codex-package-aarch64-pc-windows-msvc.tar.gz",
        (os, arch) => bail!("no official Codex package is pinned for {os}/{arch}"),
    })
}

pub fn verify_sums_manifest(downloaded: &str) -> Result<()> {
    if canonical(downloaded) != canonical(PACKAGE_SHA256SUMS) {
        bail!(
            "published {PACKAGE_SUMS_NAME} does not match the pin in src/traffic/codex.rs; refusing to run"
        );
    }
    Ok(())
}

pub fn pinned_digest(filename: &str) -> Result<&'static str> {
    PACKAGE_SHA256SUMS
        .lines()
        .find_map(|line| {
            let mut parts = line.split_whitespace();
            let digest = parts.next()?;
            let name = parts.next()?;
            (name == filename).then_some(digest)
        })
        .with_context(|| format!("no pinned digest for {filename}"))
}

pub fn verify_artifact(filename: &str, bytes: &[u8]) -> Result<()> {
    let expected = pinned_digest(filename)?;
    let actual = hex(&Sha256::digest(bytes));
    if !actual.eq_ignore_ascii_case(expected) {
        bail!("SHA-256 mismatch for {filename}: got {actual}, pinned {expected}");
    }
    Ok(())
}

/// Arguments for one official `codex exec` turn pointed at the recording proxy.
///
/// `openai_base_url` cannot retarget the built-in provider's inference host
/// together with `supports_websockets`: `model_providers.openai` only accepts a
/// catalog URL. A provider id `traffic` with display name `OpenAI` keeps
/// `is_openai()` true (that check is the display name) and
/// `supports_codex_backend_routes()` true because the base ends in
/// `/backend-api/codex`. Websockets are off so the capture is the HTTP
/// `POST /responses` call; the body is still `build_responses_request`.
/// `http_headers.version` is the release version `create_openai_provider` stamps.
pub fn exec_args(proxy_origin: &str, model: &str, prompt: &str) -> Vec<String> {
    let base = format!("{}/backend-api/codex", proxy_origin.trim_end_matches('/'));
    vec![
        "exec".into(),
        "--skip-git-repo-check".into(),
        "--dangerously-bypass-approvals-and-sandbox".into(),
        "--model".into(),
        model.into(),
        "-c".into(),
        "model_provider=\"traffic\"".into(),
        "-c".into(),
        "model_providers.traffic.name=\"OpenAI\"".into(),
        "-c".into(),
        format!("model_providers.traffic.base_url={base:?}"),
        "-c".into(),
        "model_providers.traffic.wire_api=\"responses\"".into(),
        "-c".into(),
        "model_providers.traffic.requires_openai_auth=true".into(),
        "-c".into(),
        "model_providers.traffic.supports_websockets=false".into(),
        "-c".into(),
        format!(
            "model_providers.traffic.http_headers.version={:?}",
            "0.169.0"
        ),
        prompt.into(),
    ]
}

pub fn fixture_from_capture(scenario: &str, exchanges: &[CapturedExchange]) -> Result<Fixture> {
    // The fixture is the gateway turn. Model, auth, and telemetry calls are not
    // POST /responses, so they are omitted. The recorder prints both counts.
    // Extra POST /responses turns stay, and only the first is compared.
    let turns: Vec<&CapturedExchange> = exchanges
        .iter()
        .filter(|exchange| {
            exchange.method.eq_ignore_ascii_case("POST")
                && (exchange.path == "/backend-api/codex/responses"
                    || exchange.path.ends_with("/responses"))
        })
        .collect();
    if turns.is_empty() {
        bail!("recording has no POST /responses call");
    }
    let mut fixture_exchanges = Vec::new();
    for (index, turn) in turns.iter().enumerate() {
        let request_coding = encoding::recorded_coding(turn.request_content_encoding.as_deref())
            .or_else(|| encoding::header_coding(&turn.request_headers));
        // Decode before scrub. Otherwise a compressed base64 body becomes `<blob>`
        // and the fixture has no JSON to compare.
        let request_body = encoding::materialize(&turn.request_body, request_coding.as_deref())?;
        let body = scrub_value(request_body);
        if !body.is_object() {
            bail!("POST /responses body was not a JSON object");
        }
        let mut headers = scrubbed_headers(&turn.request_headers);
        headers.remove("content-encoding");
        let response_coding = encoding::recorded_coding(turn.response_content_encoding.as_deref())
            .or_else(|| encoding::header_coding(&turn.response_headers));
        let response_value =
            encoding::materialize(&turn.response_body, response_coding.as_deref())?;
        let mut response_headers = scrubbed_headers(&turn.response_headers);
        response_headers.remove("content-encoding");
        let response_body = scrub_text(&response_text(&response_value)?);
        fixture_exchanges.push(Exchange {
            // One gateway call corresponds to one of these. Extra turns stay in
            // the file so they can be split into their own scenarios.
            compare: index == 0,
            request: ObservedRequest {
                method: "POST".into(),
                path: "/responses".into(),
                query: turn.query.clone(),
                headers,
                content_encoding: request_coding,
                body,
            },
            response: {
                let mut response = ObservedResponse {
                    status: turn.status,
                    headers: response_headers,
                    content_encoding: response_coding,
                    body: Some(response_body),
                    body_base64: None,
                };
                response.label_sse_media_type();
                response
            },
        });
    }
    let first = &fixture_exchanges[0];
    let mut client_headers = Map::new();
    for name in ["session-id", "thread-id", "x-client-request-id"] {
        if let Some(value) = first.request.headers.get(name) {
            client_headers.insert(name.to_owned(), value.clone());
        }
    }
    Ok(Fixture {
        harness: "codex".into(),
        scenario: scenario.into(),
        provenance: Provenance::Recorded,
        source: SourceNote {
            repository: "openai/codex".into(),
            commit: SOURCE_COMMIT.into(),
            release: RELEASE.into(),
            release_commit: RELEASE_COMMIT.into(),
            note: "Scrubbed capture from the official rust-v0.169.0 CLI through the local recording proxy. Raw bytes stayed in traffic-recordings/.".into(),
        },
        client: ClientCall {
            method: "POST".into(),
            path: "/v1/responses".into(),
            headers: client_headers,
            body: first.request.body.clone(),
        },
        exchanges: fixture_exchanges,
    })
}

fn scrubbed_headers(headers: &Map<String, Value>) -> Map<String, Value> {
    scrub_value(json!({"headers": headers}))
        .get("headers")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
}

fn response_text(value: &Value) -> Result<String> {
    match value {
        Value::String(text) => Ok(text.clone()),
        Value::Object(_) | Value::Array(_) => Ok(value.to_string()),
        other => bail!("recording response body is {other}"),
    }
}

fn canonical(text: &str) -> String {
    text.replace("\r\n", "\n").trim().to_owned()
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0xf) as usize] as char);
    }
    out
}

pub fn release_archive_url(filename: &str) -> String {
    format!("https://github.com/openai/codex/releases/download/{RELEASE}/{filename}")
}

pub fn sums_url() -> String {
    release_archive_url(PACKAGE_SUMS_NAME)
}

pub fn binary_name() -> &'static str {
    if cfg!(windows) { "codex.exe" } else { "codex" }
}

pub fn find_binary(root: &Path) -> Result<std::path::PathBuf> {
    let name = binary_name();
    let mut found = Vec::new();
    find_named(root, name, &mut found)?;
    found.sort_by_key(|path| path.components().count());
    found
        .into_iter()
        .next()
        .with_context(|| format!("archive has no {name} binary"))
}

fn find_named(dir: &Path, name: &str, found: &mut Vec<std::path::PathBuf>) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            find_named(&path, name, found)?;
        } else if path.file_name().and_then(|value| value.to_str()) == Some(name) {
            found.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traffic::scrub::{assert_clean, findings};

    #[test]
    fn committed_fixtures_have_no_token_material() {
        assert_clean(&fixture_dir()).unwrap();
    }

    #[test]
    fn pinned_manifest_matches_the_linux_package_digest() {
        verify_sums_manifest(PACKAGE_SHA256SUMS).unwrap();
        assert!(verify_sums_manifest(&format!("{PACKAGE_SHA256SUMS}\nextra")).is_err());
        assert_eq!(
            pinned_digest("codex-package-x86_64-unknown-linux-musl.tar.gz").unwrap(),
            "3b8ed091149cc63a59046b9f094bcfa21cdb4dda15ede441ce369bcee4a71ba0"
        );
        assert!(
            verify_artifact("codex-package-x86_64-unknown-linux-musl.tar.gz", b"nope").is_err()
        );
    }

    #[test]
    fn exec_args_point_the_official_cli_at_the_proxy_over_http() {
        let args = exec_args("http://127.0.0.1:9", "gpt-5.5", "Say hello in one word.");
        let joined = args.join(" ");
        assert!(
            joined.contains(
                "model_providers.traffic.base_url=\"http://127.0.0.1:9/backend-api/codex\""
            )
        );
        assert!(joined.contains("supports_websockets=false"));
        assert!(joined.contains("name=\"OpenAI\""));
        assert!(joined.contains("http_headers.version=\"0.169.0\""));
        assert!(joined.contains("requires_openai_auth=true"));
        assert_eq!(
            args.last().map(String::as_str),
            Some("Say hello in one word.")
        );
    }

    #[test]
    fn scrubbed_capture_drops_authorization_and_keeps_the_responses_path() {
        let capture = CapturedExchange {
            method: "POST".into(),
            path: "/backend-api/codex/responses".into(),
            query: String::new(),
            request_headers: serde_json::json!({
                "authorization": "Bearer super-secret-token",
                "originator": "codex_cli_rs",
                "session-id": "00000000-0000-4000-8000-000000000001",
                "thread-id": "00000000-0000-4000-8000-000000000001",
                "x-client-request-id": "00000000-0000-4000-8000-000000000001"
            })
            .as_object()
            .unwrap()
            .clone(),
            request_body: serde_json::json!({"model": "gpt-5.5", "stream": true}),
            request_content_encoding: None,
            status: 200,
            response_headers: serde_json::json!({"content-type": "text/event-stream"})
                .as_object()
                .unwrap()
                .clone(),
            response_body: serde_json::json!("event: response.completed\ndata: {}\n\n"),
            response_content_encoding: None,
        };
        let fixture = fixture_from_capture("chat-turn", &[capture]).unwrap();
        let text = serde_json::to_string(&fixture).unwrap();
        assert!(findings(&text).is_empty(), "{text}");
        assert_eq!(fixture.provenance, Provenance::Recorded);
        assert_eq!(fixture.client.path, "/v1/responses");
        assert_eq!(fixture.exchanges[0].request.path, "/responses");
        assert!(fixture.exchanges[0].compare);
        assert_eq!(fixture.client.body["model"], "gpt-5.5");
        assert_eq!(
            fixture.client.headers["session-id"],
            "00000000-0000-4000-8000-000000000001"
        );
    }

    #[test]
    fn sse_response_without_a_media_type_is_labeled() {
        let capture = CapturedExchange {
            method: "POST".into(),
            path: "/backend-api/codex/responses".into(),
            query: String::new(),
            request_headers: serde_json::json!({"originator": "codex_exec"})
                .as_object()
                .unwrap()
                .clone(),
            request_body: serde_json::json!({"model": "gpt-6.1-sol", "stream": true}),
            request_content_encoding: None,
            status: 200,
            response_headers: serde_json::Map::new(),
            response_body: serde_json::json!(
                "event: response.output_text.delta\ndata: {\"delta\":\"hello\"}\n\n"
            ),
            response_content_encoding: None,
        };
        let fixture = fixture_from_capture("chat-turn", &[capture]).unwrap();
        assert_eq!(
            fixture.exchanges[0].response.headers["content-type"],
            "text/event-stream"
        );
        let json_body = CapturedExchange {
            method: "POST".into(),
            path: "/responses".into(),
            query: String::new(),
            request_headers: serde_json::Map::new(),
            request_body: serde_json::json!({"model": "gpt-6.1-sol"}),
            request_content_encoding: None,
            status: 200,
            response_headers: serde_json::Map::new(),
            response_body: serde_json::json!(r#"{"output":"hello"}"#),
            response_content_encoding: None,
        };
        let fixture = fixture_from_capture("chat-turn", &[json_body]).unwrap();
        assert!(
            fixture.exchanges[0]
                .response
                .headers
                .get("content-type")
                .is_none()
        );
    }

    #[test]
    fn load_fixture_labels_sse_without_rewriting_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("turn.json");
        let raw = serde_json::json!({
            "harness": "codex",
            "scenario": "chat-turn",
            "provenance": "recorded",
            "source": {
                "repository": "openai/codex",
                "commit": SOURCE_COMMIT,
                "release": RELEASE,
                "release_commit": RELEASE_COMMIT,
                "note": "unit"
            },
            "client": {
                "method": "POST",
                "path": "/v1/responses",
                "headers": {},
                "body": {"stream": true}
            },
            "exchanges": [{
                "request": {
                    "method": "POST",
                    "path": "/responses",
                    "headers": {},
                    "body": {"stream": true}
                },
                "response": {
                    "status": 200,
                    "headers": {},
                    "body": "event: response.output_text.delta\ndata: {\"delta\":\"hello\"}\n\n"
                }
            }]
        });
        std::fs::write(&path, serde_json::to_vec(&raw).unwrap()).unwrap();
        let fixture = crate::traffic::load_fixture(&path).unwrap();
        assert_eq!(
            fixture.exchanges[0].response.headers["content-type"],
            "text/event-stream"
        );
        let on_disk: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert!(
            on_disk["exchanges"][0]["response"]["headers"]
                .get("content-type")
                .is_none()
        );
    }

    #[test]
    fn fixture_omits_calls_that_are_not_post_responses() {
        let responses = captured(
            "POST",
            "/backend-api/codex/responses",
            serde_json::json!({"originator": "codex_cli_rs"}),
            serde_json::json!({"model": "gpt-5.5", "stream": true}),
            None,
        );
        let models = captured(
            "GET",
            "/backend-api/codex/models",
            serde_json::json!({}),
            serde_json::json!(null),
            None,
        );
        let files = captured(
            "POST",
            "/backend-api/codex/files",
            serde_json::json!({}),
            serde_json::json!({"purpose": "user_data"}),
            None,
        );
        let fixture = fixture_from_capture("chat-turn", &[models, responses, files]).unwrap();
        assert_eq!(fixture.exchanges.len(), 1);
        assert_eq!(fixture.exchanges[0].request.path, "/responses");
        assert_eq!(fixture.exchanges[0].request.body["model"], "gpt-5.5");
    }

    #[test]
    fn scrub_decodes_a_stored_zstd_blob_and_rejects_one_it_cannot() {
        use base64::Engine;
        let json = r#"{"model":"gpt-6.1-sol","stream":true}"#;
        let compressed = zstd::encode_all(json.as_bytes(), 1).unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(compressed);
        let capture = captured(
            "POST",
            "/backend-api/codex/responses",
            serde_json::json!({
                "content-encoding": "zstd",
                "content-type": "application/json",
                "originator": "codex_cli_rs"
            }),
            serde_json::json!({"base64": encoded}),
            None,
        );
        let fixture = fixture_from_capture("chat-turn", &[capture]).unwrap();
        assert_eq!(fixture.exchanges[0].request.body["model"], "gpt-6.1-sol");
        assert_eq!(fixture.client.body["model"], "gpt-6.1-sol");
        assert_eq!(
            fixture.exchanges[0].request.content_encoding.as_deref(),
            Some("zstd")
        );
        assert!(
            fixture.exchanges[0]
                .request
                .headers
                .get("content-encoding")
                .is_none()
        );
        let text = serde_json::to_string(&fixture).unwrap();
        assert!(findings(&text).is_empty(), "{text}");

        let garbage = base64::engine::general_purpose::STANDARD.encode(b"this is not a zstd frame");
        let bad = captured(
            "POST",
            "/responses",
            serde_json::json!({"content-encoding": "zstd"}),
            serde_json::json!({"base64": garbage}),
            Some("zstd"),
        );
        let error = fixture_from_capture("chat-turn", &[bad]).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("<blob>"), "{message}");
        assert!(message.contains("could not be decoded"), "{message}");

        let bare = captured(
            "POST",
            "/responses",
            serde_json::json!({}),
            serde_json::json!({"base64": "A".repeat(90)}),
            None,
        );
        let error = fixture_from_capture("chat-turn", &[bare]).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("no content-encoding"), "{message}");
        assert!(message.contains("<blob>"), "{message}");
    }

    #[tokio::test]
    async fn zstd_request_survives_scrub_and_replay_comparison() {
        use std::{
            sync::{Arc, Mutex},
            time::Duration,
        };

        use super::super::record::RecordingProxy;
        use super::super::{ActualRequest, align};
        use axum::{
            body::{Body, to_bytes},
            extract::Request,
            response::Response,
        };

        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_upstream = Arc::clone(&seen);
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = upstream.local_addr().unwrap();
        let sse = "event: response.output_text.delta\ndata: {\"delta\":\"hello\"}\n\n";
        let sse_zstd = zstd::encode_all(sse.as_bytes(), 1).unwrap();
        tokio::spawn(async move {
            let app = axum::Router::new().fallback(move |request: Request| {
                let seen_upstream = Arc::clone(&seen_upstream);
                let sse_zstd = sse_zstd.clone();
                async move {
                    let path = request.uri().path().to_owned();
                    let encoding = request
                        .headers()
                        .get("content-encoding")
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or("")
                        .to_owned();
                    let bytes = to_bytes(request.into_body(), 32 * 1024 * 1024)
                        .await
                        .unwrap_or_default()
                        .to_vec();
                    seen_upstream
                        .lock()
                        .unwrap()
                        .push((path.clone(), encoding, bytes));
                    if path.ends_with("/responses") {
                        Response::builder()
                            .header("content-type", "text/event-stream")
                            .header("content-encoding", "zstd")
                            .body(Body::from(sse_zstd))
                            .unwrap()
                    } else {
                        Response::builder()
                            .status(200)
                            .body(Body::from("models"))
                            .unwrap()
                    }
                }
            });
            let _ = axum::serve(upstream, app).await;
        });
        let proxy = RecordingProxy::start(&format!("http://{address}"), Duration::from_secs(5))
            .await
            .unwrap();
        let plain = serde_json::json!({
            "model": "gpt-6.1-sol",
            "input": "Say hello in one word.",
            "attachment": "A".repeat(80),
            "note": "Bearer super-secret-token"
        });
        let compressed =
            zstd::encode_all(serde_json::to_vec(&plain).unwrap().as_slice(), 3).unwrap();
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let response = client
            .post(format!("{}/backend-api/codex/responses", proxy.base))
            .header("content-encoding", "zstd")
            .header("content-type", "application/json")
            .header("accept", "text/event-stream")
            .header("originator", "codex_cli_rs")
            .header("authorization", "Bearer super-secret-token")
            .body(compressed.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert!(response.headers().get("content-encoding").is_none());
        let text = response.text().await.unwrap();
        assert!(text.contains("hello"), "{text}");
        let models = client
            .get(format!("{}/backend-api/codex/models", proxy.base))
            .send()
            .await
            .unwrap();
        assert_eq!(models.status(), 200);
        let _ = models.bytes().await.unwrap();

        let upstream_calls = seen.lock().unwrap().clone();
        let post = upstream_calls
            .iter()
            .find(|(path, _, _)| path.ends_with("/responses"))
            .expect("upstream POST");
        assert_eq!(post.1, "zstd");
        assert_eq!(post.2, compressed);

        let exchanges = proxy.exchanges();
        assert_eq!(exchanges.len(), 2);
        assert_eq!(exchanges[0].request_body["model"], "gpt-6.1-sol");
        assert_eq!(
            exchanges[0].request_content_encoding.as_deref(),
            Some("zstd")
        );
        assert_eq!(exchanges[0].response_body.as_str(), Some(sse));
        assert_eq!(
            exchanges[0].response_content_encoding.as_deref(),
            Some("zstd")
        );

        let fixture = fixture_from_capture("chat-turn", &exchanges).unwrap();
        assert_eq!(fixture.exchanges.len(), 1);
        let request = &fixture.exchanges[0].request;
        assert_eq!(request.body["model"], "gpt-6.1-sol");
        assert_eq!(request.body["input"], "Say hello in one word.");
        assert_eq!(request.body["attachment"], "<blob>");
        assert_eq!(request.body["note"], "<redacted>");
        assert_eq!(request.content_encoding.as_deref(), Some("zstd"));
        assert!(request.headers.get("content-encoding").is_none());
        assert!(request.headers.get("authorization").is_none());
        assert_eq!(fixture.client.body, request.body);
        assert_eq!(
            fixture.exchanges[0].response.content_encoding.as_deref(),
            Some("zstd")
        );
        assert!(
            fixture.exchanges[0]
                .response
                .body
                .as_deref()
                .unwrap()
                .contains("hello")
        );
        let fixture_text = serde_json::to_string(&fixture).unwrap();
        assert!(
            findings(&fixture_text).is_empty(),
            "{fixture_text} {:?}",
            findings(&fixture_text)
        );
        assert!(!fixture_text.contains(&"A".repeat(80)));

        let scrubbed = serde_json::to_vec(&request.body).unwrap();
        let mut headers = request.headers.clone();
        headers.insert("content-encoding".into(), serde_json::json!("zstd"));
        let compressed_scrubbed = zstd::encode_all(scrubbed.as_slice(), 3).unwrap();
        align(
            &CODEX,
            request,
            &ActualRequest {
                method: "POST".into(),
                path: "/backend-api/codex/responses".into(),
                query: String::new(),
                headers: headers.clone(),
                body: compressed_scrubbed,
            },
        )
        .unwrap();
        headers.remove("content-encoding");
        align(
            &CODEX,
            request,
            &ActualRequest {
                method: "POST".into(),
                path: "/backend-api/codex/responses".into(),
                query: String::new(),
                headers: headers.clone(),
                body: scrubbed.clone(),
            },
        )
        .unwrap();
        headers.insert("content-encoding".into(), serde_json::json!("gzip"));
        let error = align(
            &CODEX,
            request,
            &ActualRequest {
                method: "POST".into(),
                path: "/backend-api/codex/responses".into(),
                query: String::new(),
                headers,
                body: scrubbed,
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("content-encoding"), "{error}");
        let mut wrong = request.body.clone();
        wrong["model"] = serde_json::json!("other");
        let error = align(
            &CODEX,
            request,
            &ActualRequest {
                method: "POST".into(),
                path: "/backend-api/codex/responses".into(),
                query: String::new(),
                headers: request.headers.clone(),
                body: serde_json::to_vec(&wrong).unwrap(),
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("model"), "{error}");
        let _ = proxy;
    }

    fn captured(
        method: &str,
        path: &str,
        headers: serde_json::Value,
        body: serde_json::Value,
        encoding: Option<&str>,
    ) -> CapturedExchange {
        CapturedExchange {
            method: method.into(),
            path: path.into(),
            query: String::new(),
            request_headers: headers.as_object().cloned().unwrap_or_default(),
            request_body: body,
            request_content_encoding: encoding.map(str::to_owned),
            status: 200,
            response_headers: serde_json::json!({"content-type": "text/event-stream"})
                .as_object()
                .unwrap()
                .clone(),
            response_body: serde_json::json!("event: response.completed\ndata: {}\n\n"),
            response_content_encoding: None,
        }
    }
}
