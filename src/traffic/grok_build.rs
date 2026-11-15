//! Grok Build CLI harness.
//!
//! The pinned binary is the official `grok` 1.0.77 artifact from `https://x.ai/cli/`.
//! `grok --version` on that binary prints `grok 1.0.77 (50ca579fa996)`. x.ai does not
//! publish a checksum manifest or a full git SHA for the build. The digests below are
//! SHA-256 of those artifacts, retrieved 2026-11-14. They match the Homebrew cask
//! `grok-build` 1.0.77 for the four macOS and Linux files that cask lists.
//!
//! Headless invocation is `grok -p` / `--single` (official `--help` on 1.0.77).
//! The base URL is not a flag on that command. `grok agent` has
//! `--cli-chat-proxy-base-url` and `--xai-api-base-url`; the same overrides are the
//! environment variables `GROK_CLI_CHAT_PROXY_BASE_URL` and `GROK_XAI_API_BASE_URL`.
//! A logged-in grok.com session on 1.0.77 honors `GROK_CLI_CHAT_PROXY_BASE_URL`.
//! The committed `chat-turn` capture was made by pointing that variable at the
//! local recorder: the generation request arrived with `Host: 127.0.0.1`, and the
//! recorder forwarded it to `https://cli-chat-proxy.grok.com`. With `XAI_API_KEY`
//! and no session, `GROK_XAI_API_BASE_URL` is the override that receives
//! `GET /v1/api-key`. `XAI_API_BASE_URL` was not consulted. Session inference uses
//! the cli-chat-proxy (`EndpointsConfig::proxy_url` in the public xai-org/grok-build
//! tree). That tree's `SOURCE_REV` is not `50ca579fa996`; the binary stamp is what
//! this pin follows.
//!
//! `is_cli_chat_proxy_url` treats `127.0.0.1` as the chat proxy, so a recording
//! proxy on loopback still receives the first-party proxy headers.

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::{
    ClientCall, Exchange, Fixture, ObservedRequest, ObservedResponse, Provenance, SourceNote,
    encoding,
    harness::Harness,
    record::CapturedExchange,
    scrub::{scrub_text, scrub_value},
};

pub const RELEASE: &str = "1.0.77";
/// Stamp printed by `grok --version`. Not a verified full git commit.
pub const VERSION_STAMP: &str = "50ca579fa996";

/// SHA-256 of the official `https://x.ai/cli/grok-1.0.77-*` artifacts, 2026-11-14.
pub const PACKAGE_SHA256SUMS: &str = "\
b30eee14a656124ef3c9da8577b5e783ef2cffabeb2b679c5c49633e77eed574  grok-1.0.77-linux-aarch64
b702950aa5827d855e493278ab6215a4e0f5bceb5bba6c6243a9f55cdd143b0a  grok-1.0.77-linux-x86_64
197c66a63e5ac46e07450b0ca21d141ce665050a412180f185dadfae1c7a5b2a  grok-1.0.77-macos-aarch64
7728f79ea713ae67a4fa4736dcf808f6b386d9642202aea1df695073fa56675a  grok-1.0.77-macos-x86_64
ab4e5fddcd9f189fb379405a8fbfda43edf38dbbe893d302c0df697d180a6034  grok-1.0.77-windows-aarch64.exe
6b757512d240a6439535ca75aad039e581d00f17ba8e937112fd0dbaadf1bc81  grok-1.0.77-windows-x86_64.exe";

pub static GROK_BUILD: GrokBuild = GrokBuild;

pub struct GrokBuild;

impl Harness for GrokBuild {
    fn id(&self) -> &'static str {
        "grok-build"
    }

    fn api_base_path(&self) -> &'static str {
        // Both official bases end in `/v1`: `https://cli-chat-proxy.grok.com/v1`
        // and `https://api.x.ai/v1`. The sampler appends `chat/completions` or
        // `responses`. infer's grok provider base is the origin without `/v1`
        // and the upstream path starts with `/v1`, so comparisons use the suffix.
        "/v1"
    }

    fn compared_headers(&self) -> &'static [&'static str] {
        &[
            "accept",
            "content-type",
            // Present on cli-chat-proxy calls, including a loopback override.
            // The 1.0.77 session capture sent `authenticate-response`.
            // Absent on the public API. Absence is compared.
            "x-authenticateresponse",
            "x-grok-agent-id",
            "x-grok-client-identifier",
            "x-grok-client-mode",
            "x-grok-client-version",
            // UUIDv5 of `x-grok-session-id`. infer fills it when the caller omits it.
            "x-grok-conv-group-id",
            "x-grok-conv-id",
            // Optional. Absent on the committed turn. Absence is compared.
            "x-grok-deployment-id",
            // Streaming Responses only. The committed turn sent the CLI defaults.
            // Chat completions and a buffered Responses call omit them.
            "x-grok-doom-loop-check",
            "x-grok-exact-repetition-check",
            "x-grok-model-override",
            "x-grok-req-id",
            "x-grok-session-id",
            // Optional. Absent on the first attempt. Absence is compared.
            "x-grok-transient-retry",
            "x-grok-turn-idx",
        ]
    }

    fn forbidden_headers(&self) -> &'static [&'static str] {
        // The 1.0.77 capture has no header infer must refuse to send.
        // `X-XAI-Token-Auth` is a chat-proxy marker the CLI does send, but scrub
        // drops any header whose name contains "token", so the fixture cannot
        // require it. Credential headers are replaced by the provider credential
        // and are not part of this list.
        &[]
    }
}

/// Which official origin the recorder forwards to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Upstream {
    /// Logged-in OIDC or external session. `GROK_CLI_CHAT_PROXY_BASE_URL`.
    ChatProxy,
    /// `XAI_API_KEY` or an `auth_mode = api_key` entry. `GROK_XAI_API_BASE_URL`.
    PublicApi,
}

impl Upstream {
    pub fn origin(self) -> &'static str {
        match self {
            Self::ChatProxy => "https://cli-chat-proxy.grok.com",
            Self::PublicApi => "https://api.x.ai",
        }
    }

    pub fn base_env(self) -> &'static str {
        match self {
            Self::ChatProxy => "GROK_CLI_CHAT_PROXY_BASE_URL",
            Self::PublicApi => "GROK_XAI_API_BASE_URL",
        }
    }

    /// Env overrides for the other origin. Cleared so one recording stays on one host.
    pub fn suppressed_env(self) -> &'static [&'static str] {
        match self {
            Self::ChatProxy => &["GROK_XAI_API_BASE_URL", "XAI_API_BASE_URL"],
            Self::PublicApi => &["GROK_CLI_CHAT_PROXY_BASE_URL"],
        }
    }

    pub fn base_url(self, proxy_origin: &str) -> String {
        match self {
            Self::ChatProxy | Self::PublicApi => {
                format!("{}/v1", proxy_origin.trim_end_matches('/'))
            }
        }
    }
}

/// What `auth.json` says, ignoring the secret itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthClass {
    /// OIDC or external session. The CLI prefers this over an API key.
    Session,
    /// Plain API key stored by `grok login`.
    ApiKey,
    /// Legacy `web_login` / `grok` token. grok 1.0.77 skips it.
    LegacyOnly,
    None,
}

pub fn classify_auth(value: &Value) -> AuthClass {
    let Some(map) = value.as_object() else {
        return AuthClass::None;
    };
    let mut session = false;
    let mut api_key = false;
    let mut legacy = false;
    for auth in map.values() {
        let mode = auth
            .get("auth_mode")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_ascii_lowercase();
        match mode.as_str() {
            "oidc" | "external" => session = true,
            "api_key" => api_key = true,
            "web_login" | "grok" => legacy = true,
            _ => {}
        }
    }
    if session {
        AuthClass::Session
    } else if api_key {
        AuthClass::ApiKey
    } else if legacy {
        AuthClass::LegacyOnly
    } else {
        AuthClass::None
    }
}

pub fn select_upstream(class: AuthClass, env_api_key: bool) -> Result<Upstream> {
    match class {
        AuthClass::Session => Ok(Upstream::ChatProxy),
        AuthClass::ApiKey => Ok(Upstream::PublicApi),
        AuthClass::None | AuthClass::LegacyOnly if env_api_key => Ok(Upstream::PublicApi),
        AuthClass::LegacyOnly => bail!(
            "grok auth.json only has a legacy WebLogin token, which grok {RELEASE} ignores. Run `grok login`, or set XAI_API_KEY."
        ),
        AuthClass::None => bail!(
            "grok is not signed in. Run `grok login`, or set XAI_API_KEY from console.x.ai. A session is used first when both exist."
        ),
    }
}

pub fn fixture_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/traffic/grok-build/fixtures")
}

pub fn package_filename() -> Result<&'static str> {
    Ok(match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "grok-1.0.77-linux-x86_64",
        ("linux", "aarch64") => "grok-1.0.77-linux-aarch64",
        ("macos", "x86_64") => "grok-1.0.77-macos-x86_64",
        ("macos", "aarch64") => "grok-1.0.77-macos-aarch64",
        ("windows", "x86_64") => "grok-1.0.77-windows-x86_64.exe",
        ("windows", "aarch64") => "grok-1.0.77-windows-aarch64.exe",
        (os, arch) => bail!("no official grok binary is pinned for {os}/{arch}"),
    })
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

pub fn release_url(filename: &str) -> String {
    format!("https://x.ai/cli/{filename}")
}

/// Arguments for one official `grok -p` turn.
///
/// `--always-approve` lets a headless run finish a tool call without a TUI
/// prompt. It does not remove tools or change the prompt. The upstream base
/// is an environment variable, not a flag on this command.
pub fn exec_args(cwd: &str, model: &str, prompt: &str) -> Vec<String> {
    vec![
        "--cwd".into(),
        cwd.into(),
        "--always-approve".into(),
        "--model".into(),
        model.into(),
        "-p".into(),
        prompt.into(),
    ]
}

/// Identity headers. Scrub rewrites an email value but keeps the header name.
/// These are not auth tokens and are not part of the comparison.
const IDENTITY_HEADERS: &[&str] = &["x-email", "x-userid", "x-user-id", "x-grok-user-id"];

pub fn fixture_from_capture(scenario: &str, exchanges: &[CapturedExchange]) -> Result<Fixture> {
    let turns: Vec<&CapturedExchange> = exchanges
        .iter()
        .filter(|exchange| {
            exchange.method.eq_ignore_ascii_case("POST")
                && generation_path(&exchange.path).is_some()
        })
        .collect();
    if turns.is_empty() {
        let paths: Vec<String> = exchanges
            .iter()
            .map(|exchange| format!("{} {}", exchange.method, exchange.path))
            .collect();
        bail!(
            "recording has no POST /v1/chat/completions or POST /v1/responses call; saw {paths:?}"
        );
    }
    let mut fixture_exchanges = Vec::new();
    for (index, turn) in turns.iter().enumerate() {
        let path = generation_path(&turn.path).expect("filtered to a generation path");
        let request_coding = encoding::recorded_coding(turn.request_content_encoding.as_deref())
            .or_else(|| encoding::header_coding(&turn.request_headers));
        let request_body = encoding::materialize(&turn.request_body, request_coding.as_deref())?;
        let body = scrub_value(request_body);
        if !body.is_object() {
            bail!("{path} body was not a JSON object");
        }
        let mut headers = scrubbed_headers(&turn.request_headers);
        headers.remove("content-encoding");
        drop_identity_headers(&mut headers);
        let response_coding = encoding::recorded_coding(turn.response_content_encoding.as_deref())
            .or_else(|| encoding::header_coding(&turn.response_headers));
        let response_value =
            encoding::materialize(&turn.response_body, response_coding.as_deref())?;
        let mut response_headers = scrubbed_headers(&turn.response_headers);
        response_headers.remove("content-encoding");
        drop_identity_headers(&mut response_headers);
        let response_body = scrub_text(&response_text(&response_value)?);
        fixture_exchanges.push(Exchange {
            compare: index == 0,
            request: ObservedRequest {
                method: "POST".into(),
                path: path.into(),
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
    for name in GROK_BUILD.compared_headers() {
        if let Some(value) = first.request.headers.get(*name) {
            client_headers.insert((*name).to_owned(), value.clone());
        }
    }
    Ok(Fixture {
        harness: GROK_BUILD.id().into(),
        scenario: scenario.into(),
        provenance: Provenance::Recorded,
        source: SourceNote {
            repository: "xai-org/grok-build".into(),
            commit: VERSION_STAMP.into(),
            release: RELEASE.into(),
            release_commit: VERSION_STAMP.into(),
            note: "Scrubbed capture from the official grok 1.0.77 (50ca579fa996) CLI through the local recording proxy. Raw bytes stayed in traffic-recordings/. The parenthetical stamp is what grok --version prints; it is not a full git commit.".into(),
        },
        client: ClientCall {
            method: "POST".into(),
            path: format!("/v1{}", first.request.path),
            headers: client_headers,
            body: first.request.body.clone(),
        },
        exchanges: fixture_exchanges,
    })
}

fn generation_path(path: &str) -> Option<&'static str> {
    let path = path.split('?').next().unwrap_or(path);
    if path.ends_with("/chat/completions") {
        Some("/chat/completions")
    } else if path.ends_with("/responses") {
        Some("/responses")
    } else {
        None
    }
}

fn drop_identity_headers(headers: &mut Map<String, Value>) {
    headers.retain(|name, _| {
        let lowered = name.to_ascii_lowercase();
        !IDENTITY_HEADERS.contains(&lowered.as_str())
    });
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

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0xf) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traffic::scrub::findings;

    #[test]
    fn compared_headers_follow_the_recorded_turn() {
        let compared = GROK_BUILD.compared_headers();
        for name in [
            "accept",
            "content-type",
            "x-authenticateresponse",
            "x-grok-agent-id",
            "x-grok-client-identifier",
            "x-grok-client-mode",
            "x-grok-client-version",
            "x-grok-conv-group-id",
            "x-grok-conv-id",
            "x-grok-deployment-id",
            "x-grok-doom-loop-check",
            "x-grok-exact-repetition-check",
            "x-grok-model-override",
            "x-grok-req-id",
            "x-grok-session-id",
            "x-grok-transient-retry",
            "x-grok-turn-idx",
        ] {
            assert!(compared.contains(&name), "{name}");
        }
        // Compaction budgets, a per-request traceparent, and the user-agent are
        // forwarded or pinned outside this comparison. See the README. Framing
        // stays out too.
        for name in [
            "traceparent",
            "user-agent",
            "x-compaction-at",
            "x-compactions-remaining",
            "host",
            "content-length",
            "accept-encoding",
            "authorization",
            "x-api-key",
        ] {
            assert!(!compared.contains(&name), "{name}");
        }
        assert!(GROK_BUILD.forbidden_headers().is_empty());
    }

    #[test]
    fn pinned_digests_match_the_official_linux_binary() {
        assert_eq!(
            pinned_digest("grok-1.0.77-linux-x86_64").unwrap(),
            "b702950aa5827d855e493278ab6215a4e0f5bceb5bba6c6243a9f55cdd143b0a"
        );
        assert_eq!(
            pinned_digest("grok-1.0.77-macos-aarch64").unwrap(),
            "197c66a63e5ac46e07450b0ca21d141ce665050a412180f185dadfae1c7a5b2a"
        );
        assert_eq!(
            pinned_digest("grok-1.0.77-windows-x86_64.exe").unwrap(),
            "6b757512d240a6439535ca75aad039e581d00f17ba8e937112fd0dbaadf1bc81"
        );
        assert!(verify_artifact("grok-1.0.77-linux-x86_64", b"nope").is_err());
        assert!(pinned_digest("grok-1.0.77-linux-unknown").is_err());
        let url = release_url("grok-1.0.77-linux-x86_64");
        assert_eq!(url, "https://x.ai/cli/grok-1.0.77-linux-x86_64");
        assert!(url.chars().all(|ch| !ch.is_ascii_uppercase()));
    }

    #[test]
    fn exec_args_are_the_headless_single_turn() {
        let args = exec_args("/tmp/work", "grok-4", "Say hello in one word.");
        assert_eq!(
            args,
            vec![
                "--cwd",
                "/tmp/work",
                "--always-approve",
                "--model",
                "grok-4",
                "-p",
                "Say hello in one word.",
            ]
        );
        let joined = args.join(" ");
        assert!(!joined.contains("base-url"));
        assert!(!joined.contains("cli-chat-proxy"));
    }

    #[test]
    fn session_auth_selects_the_chat_proxy_and_an_api_key_selects_the_public_api() {
        let session = json!({
            "https://auth.x.ai": {
                "key": "session-secret-value",
                "auth_mode": "oidc"
            }
        });
        assert_eq!(classify_auth(&session), AuthClass::Session);
        let upstream = select_upstream(AuthClass::Session, true).unwrap();
        assert_eq!(upstream, Upstream::ChatProxy);
        assert_eq!(upstream.origin(), "https://cli-chat-proxy.grok.com");
        assert_eq!(upstream.base_env(), "GROK_CLI_CHAT_PROXY_BASE_URL");
        assert_eq!(
            upstream.base_url("http://127.0.0.1:9"),
            "http://127.0.0.1:9/v1"
        );
        assert_eq!(
            classify_auth(&json!({"xai::api_key": {"auth_mode": "api_key", "key": "xai-secret"}})),
            AuthClass::ApiKey
        );
        assert_eq!(
            select_upstream(AuthClass::ApiKey, false).unwrap(),
            Upstream::PublicApi
        );
        assert_eq!(
            select_upstream(AuthClass::None, true).unwrap().origin(),
            "https://api.x.ai"
        );
        assert_eq!(
            classify_auth(&json!({"old": {"auth_mode": "grok", "key": "legacy"}})),
            AuthClass::LegacyOnly
        );
        assert!(select_upstream(AuthClass::None, false).is_err());
        assert!(select_upstream(AuthClass::LegacyOnly, false).is_err());
        let text = format!("{session}");
        assert!(text.contains("session-secret-value"));
        assert!(!format!("{upstream:?}").contains("session-secret-value"));
    }

    #[test]
    fn scrubbed_capture_drops_xai_auth_and_keeps_the_chat_path() {
        let capture = CapturedExchange {
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            query: String::new(),
            request_headers: json!({
                "authorization": "Bearer xai-super-secret-token",
                "x-api-key": "xai-another-secret-key",
                "X-XAI-Token-Auth": "xai-grok-cli",
                "x-email": "person@x.ai",
                "x-grok-user-id": "user-123",
                "content-type": "application/json",
                "x-grok-client-version": RELEASE,
                "x-grok-session-id": "00000000-0000-4000-8000-000000000001",
                "x-authenticateresponse": "authenticate-response"
            })
            .as_object()
            .unwrap()
            .clone(),
            request_body: json!({
                "model": "grok-4",
                "stream": true,
                "messages": [{"role": "user", "content": "Say hello in one word."}]
            }),
            request_content_encoding: None,
            status: 200,
            response_headers: json!({"content-type": "text/event-stream"})
                .as_object()
                .unwrap()
                .clone(),
            response_body: json!("data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\n\n"),
            response_content_encoding: None,
        };
        let models = CapturedExchange {
            method: "GET".into(),
            path: "/v1/models".into(),
            query: String::new(),
            request_headers: Map::new(),
            request_body: Value::Null,
            request_content_encoding: None,
            status: 200,
            response_headers: Map::new(),
            response_body: json!("{\"data\":[]}"),
            response_content_encoding: None,
        };
        let fixture = fixture_from_capture("chat-turn", &[models, capture]).unwrap();
        let text = serde_json::to_string(&fixture).unwrap();
        assert!(findings(&text).is_empty(), "{text} {:?}", findings(&text));
        assert!(!text.contains("xai-super-secret-token"));
        assert!(!text.contains("xai-another-secret-key"));
        assert!(!text.contains("xai-grok-cli"));
        assert!(!text.contains("person@x.ai"));
        assert!(!text.contains("user-123"));
        assert!(!text.to_ascii_lowercase().contains("authorization"));
        assert!(!text.to_ascii_lowercase().contains("x-xai-token-auth"));
        assert!(!text.contains("x-grok-user-id"));
        assert_eq!(fixture.provenance, Provenance::Recorded);
        assert_eq!(fixture.harness, "grok-build");
        assert_eq!(fixture.client.path, "/v1/chat/completions");
        assert_eq!(fixture.exchanges[0].request.path, "/chat/completions");
        assert!(fixture.exchanges[0].compare);
        assert_eq!(fixture.client.body["model"], "grok-4");
        assert_eq!(fixture.client.headers["x-grok-client-version"], RELEASE);
        assert_eq!(
            fixture.client.headers["x-grok-session-id"],
            "00000000-0000-4000-8000-000000000001"
        );
        assert!(fixture.client.headers.get("x-email").is_none());
    }

    #[test]
    fn fixture_keeps_a_responses_turn_and_drops_the_api_key_probe() {
        let probe = captured("GET", "/v1/api-key");
        let responses = captured("POST", "/v1/responses");
        let fixture = fixture_from_capture("chat-turn", &[probe, responses]).unwrap();
        assert_eq!(fixture.exchanges.len(), 1);
        assert_eq!(fixture.exchanges[0].request.path, "/responses");
        assert_eq!(fixture.client.path, "/v1/responses");
    }

    fn captured(method: &str, path: &str) -> CapturedExchange {
        CapturedExchange {
            method: method.into(),
            path: path.into(),
            query: String::new(),
            request_headers: json!({"content-type": "application/json"})
                .as_object()
                .cloned()
                .unwrap_or_default(),
            request_body: json!({"model": "grok-4", "stream": true}),
            request_content_encoding: None,
            status: 200,
            response_headers: json!({"content-type": "text/event-stream"})
                .as_object()
                .unwrap()
                .clone(),
            response_body: json!("data: {}\n\n"),
            response_content_encoding: None,
        }
    }
}
