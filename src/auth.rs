//! Provider credentials are resolved at request time; secrets never enter configuration or errors.

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use http::{HeaderMap, HeaderValue, header::AUTHORIZATION};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{BufWriter, Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, LazyLock, Mutex as RegistryMutex, Weak},
    time::Duration,
};
use tokio::sync::{Mutex, OwnedMutexGuard};

// Upstream references for the Codex refresh protocol implemented here:
// https://github.com/openai/codex/blob/main/codex-rs/login/src/auth/manager.rs
// https://github.com/openai/codex/blob/main/codex-rs/login/src/oauth/client.rs
const CODEX_TOKEN_ENDPOINT: &str = "https://auth.openai.com/oauth/token";
const CODEX_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
const REFRESH_WINDOW_SECONDS: i64 = 5 * 60;
const REFRESH_INTERVAL_SECONDS: i64 = 8 * 24 * 60 * 60;
const MAX_AUTH_BYTES: u64 = 4 * 1024 * 1024;
const MAX_REFRESH_BYTES: usize = 1024 * 1024;
const LOGIN_HELP: &str = "Sign in again with `codex login` using file credential storage, then configure auth_file to that auth.json.";

static REFRESH_LOCKS: LazyLock<
    RegistryMutex<HashMap<PathBuf, Weak<Mutex<CredentialFileIdentity>>>>,
> = LazyLock::new(|| RegistryMutex::new(HashMap::new()));

struct CredentialFileIdentity {
    resolved_path: PathBuf,
}

impl Drop for CredentialFileIdentity {
    fn drop(&mut self) {
        let mut registry = REFRESH_LOCKS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Another caller may already have replaced our expired Weak. Remove only dead
        // registrations, never the newer live lock for the same path.
        if registry
            .get(&self.resolved_path)
            .is_some_and(|entry| entry.strong_count() == 0)
        {
            registry.remove(&self.resolved_path);
        }
    }
}

type CredentialFileGuard = OwnedMutexGuard<CredentialFileIdentity>;

fn shared_refresh_lock(resolved_path: PathBuf) -> Arc<Mutex<CredentialFileIdentity>> {
    let mut registry = REFRESH_LOCKS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(lock) = registry.get(&resolved_path).and_then(Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(Mutex::new(CredentialFileIdentity {
        resolved_path: resolved_path.clone(),
    }));
    registry.insert(resolved_path, Arc::downgrade(&lock));
    lock
}

#[derive(Deserialize, Clone, Debug)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    pub mode: String,
    pub token_env: Option<String>,
    pub auth_file: Option<PathBuf>,
    pub account_id: Option<String>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            mode: "none".into(),
            token_env: None,
            auth_file: None,
            account_id: None,
        }
    }
}

#[derive(Clone)]
pub struct ProviderAuth {
    config: Arc<AuthConfig>,
    // Private to prevent configuration from redirecting subscription credentials to another host.
    refresh_endpoint: Arc<str>,
}

impl ProviderAuth {
    pub fn new(config: AuthConfig) -> Result<Self> {
        match config.mode.as_str() {
            "none" | "passthrough" => {}
            "api_key" | "bearer" => {
                let name = config.token_env.as_deref().ok_or_else(|| {
                    anyhow!("API key/bearer authentication requires token_env naming an environment variable")
                })?;
                if name.is_empty() || name.contains('=') || name.contains('\0') {
                    bail!(
                        "token_env must be a nonempty environment variable name without '=' or NUL"
                    );
                }
            }
            "codex" => {
                if config
                    .auth_file
                    .as_ref()
                    .is_none_or(|path| path.as_os_str().is_empty())
                {
                    bail!("Codex authentication requires an explicit auth_file path. {LOGIN_HELP}");
                }
            }
            _ => bail!(
                "Unknown authentication mode; expected none, api_key, bearer, passthrough, or codex"
            ),
        }
        if let Some(account_id) = &config.account_id {
            validate_secret(account_id, "ChatGPT account ID", false)?;
        }
        Ok(Self {
            config: Arc::new(config),
            refresh_endpoint: CODEX_TOKEN_ENDPOINT.into(),
        })
    }

    /// The supplied HTTP client must disable redirects: refresh POST bodies contain credentials.
    pub async fn headers(
        &self,
        client: &reqwest::Client,
        anthropic: bool,
        incoming: &HeaderMap,
    ) -> Result<HeaderMap> {
        match self.config.mode.as_str() {
            "none" => Ok(HeaderMap::new()),
            "passthrough" => {
                let mut headers = HeaderMap::with_capacity(2);
                for name in ["authorization", "x-api-key"] {
                    for value in incoming.get_all(name).iter() {
                        let text = value.to_str().map_err(|_| {
                            anyhow!("Incoming authentication header must contain visible ASCII characters")
                        })?;
                        validate_secret(text, "Incoming authentication header", true)?;
                        let mut value = value.clone();
                        value.set_sensitive(true);
                        headers.append(name, value);
                    }
                }
                Ok(headers)
            }
            "api_key" | "bearer" => {
                let name = self
                    .config
                    .token_env
                    .as_deref()
                    .expect("validated token_env");
                let token = std::env::var(name).map_err(|_| {
                    anyhow!("Credential environment variable {name} is missing or is not valid Unicode; set it before sending requests")
                })?;
                token_headers(&token, self.config.mode == "api_key" && anthropic)
                    .with_context(|| format!("Invalid credential in environment variable {name}"))
            }
            "codex" => self.codex_headers(client).await,
            _ => unreachable!("authentication mode is validated on construction"),
        }
    }

    async fn codex_headers(&self, client: &reqwest::Client) -> Result<HeaderMap> {
        let path = self.config.auth_file.as_ref().expect("validated auth_file");
        let (guard, snapshot) = lock_snapshot(path.clone()).await?;
        if !snapshot.needs_refresh(chrono::Utc::now().timestamp())? {
            return snapshot.headers(self.config.account_id.as_deref());
        }

        // Refresh tokens can rotate on use. Once started, finish refresh and durable persistence
        // even if the inference request disconnects; the task retains the shared lock.
        let auth = self.clone();
        let client = client.clone();
        tokio::spawn(async move { auth.refresh_and_resolve(&client, guard, snapshot).await })
        .await
        .map_err(|_| anyhow!("Codex credential refresh task failed; inspect auth_file and sign in again if necessary"))?
    }

    async fn refresh_and_resolve(
        &self,
        client: &reqwest::Client,
        mut guard: CredentialFileGuard,
        mut snapshot: AuthSnapshot,
    ) -> Result<HeaderMap> {
        let configured_path = self.config.auth_file.as_ref().expect("validated auth_file");
        for _ in 0..3 {
            if !snapshot.needs_refresh(chrono::Utc::now().timestamp())? {
                return snapshot.headers(self.config.account_id.as_deref());
            }
            let refresh_token = snapshot.token("refresh_token")?
                .filter(|token| !token.is_empty())
                .ok_or_else(|| anyhow!("Codex access token needs refreshing but auth_file has no refresh_token. {LOGIN_HELP}"))?;
            validate_secret(refresh_token, "Codex refresh token", false)?;
            let refreshed = request_refresh(client, &self.refresh_endpoint, refresh_token).await;

            let refreshed = match refreshed {
                Ok(refreshed) => {
                    // A configured symlink may now point elsewhere, but the original refresh
                    // token was consumed. Preserve its rotation unless that file itself changed.
                    let latest = load_snapshot(snapshot.resolved_path.clone()).await?;
                    if !snapshot.same_file_contents(&latest) {
                        let latest = load_snapshot(configured_path.clone()).await?;
                        (guard, snapshot) =
                            relock_if_retargeted(configured_path.clone(), guard, latest).await?;
                        continue;
                    }
                    refreshed
                }
                Err(error) => {
                    // A failed refresh must not mask a newer configured login or symlink target.
                    let latest = load_snapshot(configured_path.clone()).await?;
                    if snapshot.same_file_contents(&latest) {
                        return Err(error);
                    }
                    (guard, snapshot) =
                        relock_if_retargeted(configured_path.clone(), guard, latest).await?;
                    continue;
                }
            };
            snapshot.apply_refresh(refreshed)?;
            let persisted = tokio::task::spawn_blocking(move || {
                persist_if_unchanged(&snapshot, &snapshot.document)
            })
            .await
            .map_err(|_| {
                anyhow!(
                    "Codex auth_file persistence task failed; inspect auth_file before retrying"
                )
            })??;
            // Finish persistence under the captured target's lock before resolving the alias:
            // even a dangling or repeatedly retargeted alias cannot discard a consumed rotation.
            let latest = load_snapshot(configured_path.clone()).await?;
            if matches!(persisted, PersistOutcome::Written)
                && latest.resolved_path == guard.resolved_path
            {
                return latest.headers(self.config.account_id.as_deref());
            }
            (guard, snapshot) =
                relock_if_retargeted(configured_path.clone(), guard, latest).await?;
        }
        bail!(
            "Codex auth_file changed repeatedly during refresh; let the other credential writer finish, then retry"
        )
    }
}

fn validate_secret(text: &str, description: &str, allow_spaces: bool) -> Result<()> {
    if text.is_empty()
        || text.trim() != text
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || (allow_spaces && byte == b' '))
    {
        bail!(
            "{description} must be nonempty visible ASCII without control characters or surrounding whitespace"
        );
    }
    Ok(())
}

fn secret_header(text: &str, description: &str, allow_spaces: bool) -> Result<HeaderValue> {
    validate_secret(text, description, allow_spaces)?;
    let mut header = HeaderValue::from_str(text)
        .map_err(|_| anyhow!("{description} cannot be encoded as an HTTP header"))?;
    header.set_sensitive(true);
    Ok(header)
}

fn token_headers(token: &str, use_api_key: bool) -> Result<HeaderMap> {
    let mut headers = HeaderMap::with_capacity(1);
    if use_api_key {
        headers.insert(
            "x-api-key",
            secret_header(token, "Provider credential", false)?,
        );
    } else {
        validate_secret(token, "Provider credential", false)?;
        let mut bearer = String::with_capacity(7 + token.len());
        bearer.push_str("Bearer ");
        bearer.push_str(token);
        let mut value = HeaderValue::from_maybe_shared(bytes::Bytes::from(bearer))
            .map_err(|_| anyhow!("Bearer credential cannot be encoded as an HTTP header"))?;
        value.set_sensitive(true);
        headers.insert(AUTHORIZATION, value);
    }
    Ok(headers)
}

struct AuthSnapshot {
    resolved_path: PathBuf,
    bytes: Vec<u8>,
    document: Value,
}

impl AuthSnapshot {
    fn same_file_contents(&self, other: &Self) -> bool {
        self.resolved_path == other.resolved_path && self.bytes == other.bytes
    }

    fn tokens(&self) -> Result<&serde_json::Map<String, Value>> {
        self.document
            .get("tokens")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                anyhow!("Codex auth_file has no subscription tokens object. {LOGIN_HELP}")
            })
    }

    fn token(&self, name: &str) -> Result<Option<&str>> {
        match self.tokens()?.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(value)) => Ok(Some(value)),
            _ => bail!("Codex auth_file token field {name} must be a string. {LOGIN_HELP}"),
        }
    }

    fn needs_refresh(&self, now: i64) -> Result<bool> {
        let Some(access) = self
            .token("access_token")?
            .filter(|token| !token.is_empty())
        else {
            return Ok(true);
        };
        validate_secret(access, "Codex access token", false)?;
        if let Some(exp) = jwt_claims(access)?.and_then(|claims| claims.get("exp").cloned()) {
            let expires = exp.as_i64().ok_or_else(|| {
                anyhow!("Codex access token has an invalid JWT expiration. {LOGIN_HELP}")
            })?;
            if expires <= now.saturating_add(REFRESH_WINDOW_SECONDS) {
                return Ok(true);
            }
        }
        // Refresh old logins periodically too, including tokens without an exp claim.
        let last_refresh = self
            .document
            .get("last_refresh")
            .and_then(Value::as_str)
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok());
        Ok(last_refresh
            .is_some_and(|last| now.saturating_sub(last.timestamp()) >= REFRESH_INTERVAL_SECONDS))
    }

    fn headers(&self, account_override: Option<&str>) -> Result<HeaderMap> {
        let token = self
            .token("access_token")?
            .filter(|token| !token.is_empty())
            .ok_or_else(|| anyhow!("Codex auth_file has no access_token. {LOGIN_HELP}"))?;
        let mut headers = token_headers(token, false)?;
        let mut claimed_account = None;
        let account = if let Some(account) = account_override {
            account
        } else if let Some(account) = self
            .token("account_id")?
            .filter(|account| !account.is_empty())
        {
            account
        } else {
            // Recognize the Codex account hint in this namespaced ID/access JWT claim.
            for candidate in [Some(token), self.token("id_token")?].into_iter().flatten() {
                if let Some(account) = jwt_claims(candidate)?.and_then(|claims| {
                    claims
                        .get("https://api.openai.com/auth")?
                        .get("chatgpt_account_id")?
                        .as_str()
                        .map(str::to_owned)
                }) {
                    claimed_account = Some(account);
                    break;
                }
            }
            claimed_account.as_deref().ok_or_else(|| anyhow!(
                "Codex auth_file has no account ID; configure account_id or sign in again with `codex login`"
            ))?
        };
        headers.insert(
            "chatgpt-account-id",
            secret_header(account, "ChatGPT account ID", false)?,
        );
        Ok(headers)
    }

    fn apply_refresh(&mut self, refreshed: RefreshResponse) -> Result<()> {
        validate_secret(
            &refreshed.access_token,
            "Refreshed Codex access token",
            false,
        )?;
        if let Some(exp) =
            jwt_claims(&refreshed.access_token)?.and_then(|claims| claims.get("exp").cloned())
            && exp
                .as_i64()
                .is_none_or(|exp| exp <= chrono::Utc::now().timestamp())
        {
            bail!("Codex refresh returned an expired or invalid access token. {LOGIN_HELP}");
        }
        if let Some(token_type) = refreshed.token_type
            && !token_type.eq_ignore_ascii_case("bearer")
        {
            bail!("Codex refresh returned an unsupported token type. {LOGIN_HELP}");
        }
        let tokens = self
            .document
            .get_mut("tokens")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| anyhow!("Codex auth_file has no tokens object. {LOGIN_HELP}"))?;
        tokens.insert("access_token".into(), Value::String(refreshed.access_token));
        for (name, token) in [
            ("refresh_token", refreshed.refresh_token),
            ("id_token", refreshed.id_token),
        ] {
            if let Some(token) = token {
                validate_secret(&token, "Refreshed Codex token", false)?;
                tokens.insert(name.into(), Value::String(token));
            }
        }
        self.document
            .as_object_mut()
            .expect("validated auth object")
            .insert(
                "last_refresh".into(),
                Value::String(
                    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                ),
            );
        Ok(())
    }
}

// JWT claims are unverified scheduling/routing hints, not proof of entitlement. Only upstream
// validates credentials. Opaque bearer values remain usable when an account ID is supplied.
fn jwt_claims(token: &str) -> Result<Option<Value>> {
    let Some((protected, _)) = token.split_once('.') else {
        return Ok(None);
    };
    let decode = |segment| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(segment)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(segment))
    };
    let Ok(decoded_header) = decode(protected) else {
        return Ok(None);
    };
    let Ok(header) = crate::json::from_slice(&decoded_header) else {
        return Ok(None);
    };
    let Some(algorithm) = header.as_object().and_then(|header| header.get("alg")) else {
        return Ok(None);
    };
    if algorithm.as_str().is_none_or(str::is_empty) {
        bail!("Codex token has an invalid JWT header. {LOGIN_HELP}");
    }

    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature)) = (parts.next(), parts.next(), parts.next())
    else {
        bail!("Codex token has a malformed JWT envelope. {LOGIN_HELP}");
    };
    if header.is_empty() || payload.is_empty() || signature.is_empty() || parts.next().is_some() {
        bail!("Codex token has a malformed JWT envelope. {LOGIN_HELP}");
    }
    let decoded = decode(payload)
        .map_err(|_| anyhow!("Codex token has a malformed JWT payload. {LOGIN_HELP}"))?;
    let claims = crate::json::from_slice(&decoded)
        .map_err(|_| anyhow!("Codex token has invalid JWT claims. {LOGIN_HELP}"))?;
    if !claims.is_object() {
        bail!("Codex token JWT claims must be an object. {LOGIN_HELP}");
    }
    Ok(Some(claims))
}

// Resolve on every use, not at construction: a login can replace the file or retarget a symlink.
// Canonical paths survive our atomic rename, unlike inode-based identities. Only registry lookup
// is process-wide; unrelated credential files never share an async refresh lock.
async fn lock_snapshot(path: PathBuf) -> Result<(CredentialFileGuard, AuthSnapshot)> {
    for _ in 0..3 {
        let configured_path = path.clone();
        let lock = tokio::task::spawn_blocking(move || {
            resolve_auth_path(&configured_path).map(shared_refresh_lock)
        })
        .await
        .map_err(|_| anyhow!("Codex auth_file reader task failed"))??;
        let guard = lock.lock_owned().await;
        let snapshot = load_snapshot(path.clone()).await?;
        if snapshot.resolved_path == guard.resolved_path {
            return Ok((guard, snapshot));
        }
        // The configured symlink changed while we waited. Drop this lock before resolving
        // again so a new target is never refreshed under the previous target's lock.
    }
    bail!(
        "Codex auth_file changed repeatedly while resolving credentials; let the other credential writer finish, then retry"
    )
}

async fn relock_if_retargeted(
    configured_path: PathBuf,
    guard: CredentialFileGuard,
    snapshot: AuthSnapshot,
) -> Result<(CredentialFileGuard, AuthSnapshot)> {
    if guard.resolved_path == snapshot.resolved_path {
        return Ok((guard, snapshot));
    }
    drop(guard);
    lock_snapshot(configured_path).await
}

async fn load_snapshot(path: PathBuf) -> Result<AuthSnapshot> {
    tokio::task::spawn_blocking(move || read_snapshot(&path))
        .await
        .map_err(|_| anyhow!("Codex auth_file reader task failed"))?
}

fn resolve_auth_path(path: &Path) -> Result<PathBuf> {
    std::fs::canonicalize(path).with_context(|| {
        format!(
            "Cannot locate Codex auth_file {}. {LOGIN_HELP}",
            path.display()
        )
    })
}

pub(crate) fn validate_runtime_credentials(config: &AuthConfig) -> Result<()> {
    let path = config.auth_file.as_deref().context("missing auth_file")?;
    let snapshot = read_snapshot(path)?;
    if snapshot.needs_refresh(chrono::Utc::now().timestamp())? {
        let refresh_token = snapshot
            .token("refresh_token")?
            .filter(|token| !token.is_empty())
            .ok_or_else(|| {
                anyhow!(
                    "Codex access token needs refreshing but auth_file has no refresh_token. {LOGIN_HELP}"
                )
            })?;
        validate_secret(refresh_token, "Codex refresh token", false)?;
    } else {
        snapshot.headers(config.account_id.as_deref())?;
    }
    Ok(())
}

fn open_snapshot_file(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    options.open(path)
}

fn read_snapshot(path: &Path) -> Result<AuthSnapshot> {
    let resolved_path = resolve_auth_path(path)?;
    if !std::fs::metadata(&resolved_path)
        .context("Cannot inspect Codex auth_file")?
        .is_file()
    {
        bail!("Codex auth_file must be a regular file");
    }
    let file = open_snapshot_file(&resolved_path)
        .context("Cannot open Codex auth_file; check its permissions")?;
    if !file
        .metadata()
        .context("Cannot inspect Codex auth_file")?
        .is_file()
    {
        bail!("Codex auth_file must be a regular file");
    }
    let mut bytes = Vec::new();
    file.take(MAX_AUTH_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("Cannot read Codex auth_file; check its permissions")?;
    if bytes.len() as u64 > MAX_AUTH_BYTES {
        bail!("Codex auth_file exceeds the 4 MiB credential-file limit");
    }
    let document = crate::json::from_slice(&bytes).map_err(|error| {
        anyhow!(
            "Codex auth_file is not valid JSON (line {}, column {}). {LOGIN_HELP}",
            error.line(),
            error.column()
        )
    })?;
    if !document.is_object() {
        bail!("Codex auth_file must contain a JSON object. {LOGIN_HELP}");
    }
    Ok(AuthSnapshot {
        resolved_path,
        bytes,
        document,
    })
}

#[derive(Deserialize)]
struct RefreshResponse {
    access_token: String,
    refresh_token: Option<String>,
    id_token: Option<String>,
    token_type: Option<String>,
}

async fn request_refresh(
    client: &reqwest::Client,
    endpoint: &str,
    refresh_token: &str,
) -> Result<RefreshResponse> {
    let mut response = client
        .post(endpoint)
        .timeout(Duration::from_secs(30))
        .json(&serde_json::json!({
            "grant_type": "refresh_token",
            "client_id": CODEX_CLIENT_ID,
            "refresh_token": refresh_token,
            "refresh_reason": "proactive_expiry",
        }))
        .send()
        .await
        .map_err(|_| {
            anyhow!(
                "Cannot reach Codex token refresh service; check network/TLS connectivity and retry"
            )
        })?;
    if !response.status().is_success() {
        let status = response.status();
        // Do not include the remote body, URL, or transport diagnostics: they may echo tokens.
        if status.is_client_error() {
            bail!(
                "Codex token refresh was rejected (HTTP {}). {LOGIN_HELP}",
                status.as_u16()
            );
        }
        bail!(
            "Codex token refresh service returned HTTP {}; retry when the service is available",
            status.as_u16()
        );
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| {
        anyhow!("Cannot read Codex token refresh response; check network connectivity")
    })? {
        if chunk.len() > MAX_REFRESH_BYTES.saturating_sub(bytes.len()) {
            bail!("Codex token refresh response exceeds the 1 MiB safety limit");
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| {
        anyhow!("Codex token refresh returned an invalid token response. {LOGIN_HELP}")
    })
}

enum PersistOutcome {
    Written,
    Changed,
}

struct PendingAuthFile(PathBuf);

impl Drop for PendingAuthFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn persist_if_unchanged(original: &AuthSnapshot, document: &Value) -> Result<PersistOutcome> {
    let parent = original
        .resolved_path
        .parent()
        .ok_or_else(|| anyhow!("Codex auth_file has no parent directory"))?;
    let temporary =
        PendingAuthFile(parent.join(format!(".infer-auth-{}.tmp", uuid::Uuid::new_v4())));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary.0)
        .context("Cannot create private temporary Codex auth_file; check directory permissions")?;
    {
        let mut output = BufWriter::new(&mut file);
        serde_json::to_writer_pretty(&mut output, document)
            .map_err(|_| anyhow!("Cannot serialize refreshed Codex auth_file"))?;
        output
            .write_all(b"\n")
            .context("Cannot write refreshed Codex auth_file")?;
        output
            .flush()
            .context("Cannot flush refreshed Codex auth_file")?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .context("Cannot set refreshed Codex auth_file permissions to 0600")?;
    }
    file.sync_all()
        .context("Cannot durably sync refreshed Codex auth_file; credentials were not replaced")?;

    // Recheck the captured target *after* syncing the replacement, immediately before rename.
    // A symlink-only retarget must not strand its consumed refresh token; an external replacement
    // of the original target still wins. Independent writers must cooperate to eliminate the
    // final filesystem compare/rename race entirely.
    let latest = read_snapshot(&original.resolved_path)?;
    if !original.same_file_contents(&latest) {
        return Ok(PersistOutcome::Changed);
    }
    std::fs::rename(&temporary.0, &original.resolved_path)
        .context("Cannot atomically replace Codex auth_file; check directory permissions")?;
    File::open(parent).and_then(|directory| directory.sync_all())
        .context("Refreshed Codex auth_file was replaced but its directory could not be synced; inspect storage durability before retrying")?;
    Ok(PersistOutcome::Written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::{sync::Notify, task::JoinHandle};

    fn jwt(exp: i64, account: Option<&str>) -> String {
        let mut claims = serde_json::json!({"exp": exp});
        if let Some(account) = account {
            claims["https://api.openai.com/auth"] =
                serde_json::json!({"chatgpt_account_id": account});
        }
        format!(
            "eyJhbGciOiJub25lIn0.{}.signature",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&claims).unwrap())
        )
    }

    fn credentials(access: &str) -> Value {
        serde_json::json!({
            "auth_mode": "chatgpt",
            "OPENAI_API_KEY": null,
            "custom": {"preserve": [1, 2, 3]},
            "tokens": {
                "access_token": access,
                "refresh_token": "original-refresh-secret",
                "id_token": "original-id-secret",
                "account_id": "account-one",
                "custom_token_metadata": {"keep": true}
            }
        })
    }

    fn write_credentials(path: &Path, document: &Value) {
        std::fs::write(path, serde_json::to_vec(document).unwrap()).unwrap();
    }

    fn auth(path: &Path) -> ProviderAuth {
        ProviderAuth::new(AuthConfig {
            mode: "codex".into(),
            auth_file: Some(path.to_owned()),
            ..AuthConfig::default()
        })
        .unwrap()
    }

    fn client() -> reqwest::Client {
        reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
    }

    #[derive(Clone)]
    struct RefreshState {
        calls: Arc<AtomicUsize>,
        requests: Arc<Mutex<Vec<Value>>>,
        response: Value,
        status: StatusCode,
        pause: Option<Arc<(Notify, Notify)>>,
    }

    struct RefreshFixture {
        endpoint: Arc<str>,
        state: RefreshState,
        task: JoinHandle<()>,
    }

    impl Drop for RefreshFixture {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn fixture(response: Value, status: StatusCode, paused: bool) -> RefreshFixture {
        async fn refresh(
            State(state): State<RefreshState>,
            Json(body): Json<Value>,
        ) -> (StatusCode, Json<Value>) {
            state.calls.fetch_add(1, Ordering::SeqCst);
            state.requests.lock().await.push(body);
            if let Some(pause) = &state.pause {
                pause.0.notify_one();
                pause.1.notified().await;
            }
            (state.status, Json(state.response))
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/oauth/token", listener.local_addr().unwrap()).into();
        let state = RefreshState {
            calls: Arc::new(AtomicUsize::new(0)),
            requests: Arc::new(Mutex::new(Vec::new())),
            response,
            status,
            pause: paused.then(|| Arc::new((Notify::new(), Notify::new()))),
        };
        let app = Router::new()
            .route("/oauth/token", post(refresh))
            .with_state(state.clone());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        RefreshFixture {
            endpoint,
            state,
            task,
        }
    }

    #[test]
    fn invalid_authentication_configuration_is_rejected() {
        for mode in ["api_key", "bearer", "codex", "unknown"] {
            assert!(
                ProviderAuth::new(AuthConfig {
                    mode: mode.into(),
                    ..AuthConfig::default()
                })
                .is_err()
            );
        }
        assert!(
            ProviderAuth::new(AuthConfig {
                mode: "bearer".into(),
                token_env: Some("INVALID=NAME".into()),
                ..AuthConfig::default()
            })
            .is_err()
        );
        assert!(
            ProviderAuth::new(AuthConfig {
                account_id: Some("account\r\ninjected: true".into()),
                ..AuthConfig::default()
            })
            .is_err()
        );
    }

    #[test]
    fn runtime_validation_rejects_unusable_codex_credential_files() {
        let directory = tempfile::tempdir().unwrap();
        let cases = [
            ("empty.json", b"{}".as_slice()),
            ("malformed.json", b"{invalid".as_slice()),
            (
                "typed.json",
                br#"{"tokens":{"access_token":123,"refresh_token":"valid-refresh"}}"#.as_slice(),
            ),
        ];
        for (name, bytes) in cases {
            let path = directory.path().join(name);
            std::fs::write(&path, bytes).unwrap();
            assert!(
                validate_runtime_credentials(&AuthConfig {
                    mode: "codex".into(),
                    auth_file: Some(path),
                    ..AuthConfig::default()
                })
                .is_err(),
                "{name}"
            );
        }
        assert!(
            validate_runtime_credentials(&AuthConfig {
                mode: "codex".into(),
                auth_file: Some(directory.path().to_owned()),
                ..AuthConfig::default()
            })
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn runtime_validation_rejects_fifo_credentials_promptly() {
        use std::{
            ffi::CString,
            os::unix::{ffi::OsStrExt, fs::OpenOptionsExt},
            sync::mpsc::{self, RecvTimeoutError},
            thread,
        };

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("auth.fifo");
        let fifo_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: fifo_path is a live, NUL-terminated path for the duration of the call.
        assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) }, 0);
        let validator_path = path.clone();
        let (done, result) = mpsc::channel();
        let validator = thread::spawn(move || {
            let checked = validate_runtime_credentials(&AuthConfig {
                mode: "codex".into(),
                auth_file: Some(validator_path),
                ..AuthConfig::default()
            });
            done.send(checked).unwrap();
        });
        let mut required_writer = false;
        let error = loop {
            match result.recv_timeout(Duration::from_millis(10)) {
                Ok(checked) => break checked.unwrap_err(),
                Err(RecvTimeoutError::Disconnected) => panic!("credential validator disconnected"),
                Err(RecvTimeoutError::Timeout) => {
                    // Release a regressed blocking reader without relying on a latency
                    // threshold or leaving it stranded when the test fails.
                    match OpenOptions::new()
                        .write(true)
                        .custom_flags(libc::O_NONBLOCK)
                        .open(&path)
                    {
                        Ok(writer) => {
                            required_writer = true;
                            drop(writer);
                        }
                        Err(error) if error.raw_os_error() == Some(libc::ENXIO) => {}
                        Err(error) => panic!("cannot probe FIFO reader: {error}"),
                    }
                }
            }
        };
        validator.join().unwrap();

        assert!(error.to_string().contains("must be a regular file"));
        assert!(
            !required_writer,
            "FIFO rejection required a connected writer"
        );
    }

    #[test]
    fn runtime_validation_accepts_ready_and_refreshable_codex_logins_without_writes() {
        let directory = tempfile::tempdir().unwrap();
        let ready_path = directory.path().join("ready.json");
        write_credentials(&ready_path, &credentials("opaque-access"));

        let refreshable_path = directory.path().join("refreshable.json");
        let mut refreshable = credentials(&jwt(1, None));
        refreshable["tokens"]["account_id"] = Value::Number(1.into());
        refreshable["tokens"]["id_token"] = Value::Array(Vec::new());
        write_credentials(&refreshable_path, &refreshable);

        for path in [ready_path, refreshable_path] {
            let before = std::fs::read(&path).unwrap();
            validate_runtime_credentials(&AuthConfig {
                mode: "codex".into(),
                auth_file: Some(path.clone()),
                ..AuthConfig::default()
            })
            .unwrap();
            assert_eq!(std::fs::read(path).unwrap(), before);
        }
    }

    #[test]
    fn runtime_validation_requires_a_valid_refresh_token_when_refresh_is_needed() {
        let directory = tempfile::tempdir().unwrap();
        for (name, refresh_token) in [
            ("missing", Value::Null),
            ("typed", Value::Number(1.into())),
            ("unsafe", Value::String("bad refresh".into())),
        ] {
            let path = directory.path().join(format!("{name}.json"));
            let mut document = credentials(&jwt(1, None));
            document["tokens"]["refresh_token"] = refresh_token;
            write_credentials(&path, &document);
            assert!(
                validate_runtime_credentials(&AuthConfig {
                    mode: "codex".into(),
                    auth_file: Some(path),
                    ..AuthConfig::default()
                })
                .is_err(),
                "{name}"
            );
        }
    }

    #[test]
    fn api_key_and_bearer_headers_are_distinct_and_sensitive() {
        let anthropic = token_headers("api-key-fixture", true).unwrap();
        assert_eq!(anthropic["x-api-key"], "api-key-fixture");
        assert!(anthropic["x-api-key"].is_sensitive());
        assert!(!anthropic.contains_key(AUTHORIZATION));
        let bearer = token_headers("bearer-fixture", false).unwrap();
        assert_eq!(bearer[AUTHORIZATION], "Bearer bearer-fixture");
        assert!(bearer[AUTHORIZATION].is_sensitive());
        assert!(!bearer.contains_key("x-api-key"));
        for invalid in [
            "",
            " leading",
            "trailing ",
            "line\r\ninjection",
            "tab\tvalue",
            "two tokens",
            "非ASCII",
        ] {
            let error = token_headers(invalid, false).unwrap_err().to_string();
            assert!(!error.contains(invalid) || invalid.is_empty());
        }
    }

    #[tokio::test]
    async fn none_and_passthrough_do_not_leak_other_incoming_headers() {
        let mut incoming = HeaderMap::new();
        incoming.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer client-token"),
        );
        incoming.insert("x-api-key", HeaderValue::from_static("client-key"));
        incoming.insert("cookie", HeaderValue::from_static("session=private"));
        incoming.insert(
            "chatgpt-account-id",
            HeaderValue::from_static("untrusted-account"),
        );
        let none = ProviderAuth::new(AuthConfig::default()).unwrap();
        assert!(
            none.headers(&client(), true, &incoming)
                .await
                .unwrap()
                .is_empty()
        );
        let passthrough = ProviderAuth::new(AuthConfig {
            mode: "passthrough".into(),
            ..AuthConfig::default()
        })
        .unwrap();
        let headers = passthrough
            .headers(&client(), true, &incoming)
            .await
            .unwrap();
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[AUTHORIZATION], "Bearer client-token");
        assert_eq!(headers["x-api-key"], "client-key");
        assert!(headers.values().all(HeaderValue::is_sensitive));
        incoming.insert(
            AUTHORIZATION,
            HeaderValue::from_bytes(b"Bearer tab\tsecret").unwrap(),
        );
        assert!(
            passthrough
                .headers(&client(), false, &incoming)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn missing_environment_is_rejected_without_mutating_environment() {
        let name = format!("INFER_TEST_MISSING_{}", uuid::Uuid::new_v4().simple());
        let auth = ProviderAuth::new(AuthConfig {
            mode: "bearer".into(),
            token_env: Some(name.clone()),
            ..AuthConfig::default()
        })
        .unwrap();
        assert!(
            auth.headers(&client(), false, &HeaderMap::new())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn codex_reloads_external_rotation_and_respects_account_override() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("auth.json");
        let first = jwt(4_102_444_800, None);
        write_credentials(&path, &credentials(&first));
        let mut auth = auth(&path);
        Arc::make_mut(&mut auth.config).account_id = Some("explicit-account".into());
        let headers = auth
            .headers(&client(), false, &HeaderMap::new())
            .await
            .unwrap();
        assert_eq!(headers[AUTHORIZATION], format!("Bearer {first}"));
        assert_eq!(headers["chatgpt-account-id"], "explicit-account");
        assert!(headers["chatgpt-account-id"].is_sensitive());
        let second = jwt(4_102_444_801, None);
        write_credentials(&path, &credentials(&second));
        let headers = auth
            .clone()
            .headers(&client(), false, &HeaderMap::new())
            .await
            .unwrap();
        assert_eq!(headers[AUTHORIZATION], format!("Bearer {second}"));
    }

    #[tokio::test]
    async fn refresh_is_singleflight_durable_and_preserves_unknown_fields() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("auth.json");
        write_credentials(&path, &credentials(&jwt(1, None)));
        let access = jwt(4_102_444_800, None);
        let server = fixture(serde_json::json!({
            "access_token": access, "refresh_token": "rotated-refresh-secret", "id_token": "rotated-id-secret", "token_type": "Bearer"
        }), StatusCode::OK, false).await;
        let mut auth = auth(&path);
        auth.refresh_endpoint = server.endpoint.clone();
        let client = client();
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let auth = auth.clone();
            let client = client.clone();
            tasks.push(tokio::spawn(async move {
                auth.headers(&client, false, &HeaderMap::new())
                    .await
                    .unwrap()
            }));
        }
        for task in tasks {
            let headers = task.await.unwrap();
            assert_eq!(headers[AUTHORIZATION], format!("Bearer {access}"));
            assert_eq!(headers["chatgpt-account-id"], "account-one");
        }
        assert_eq!(server.state.calls.load(Ordering::SeqCst), 1);
        let requests = server.state.requests.lock().await;
        assert_eq!(requests[0]["grant_type"], "refresh_token");
        assert_eq!(requests[0]["client_id"], CODEX_CLIENT_ID);
        assert_eq!(requests[0]["refresh_token"], "original-refresh-secret");
        let saved: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(saved["custom"], serde_json::json!({"preserve": [1, 2, 3]}));
        assert_eq!(
            saved["tokens"]["custom_token_metadata"],
            serde_json::json!({"keep": true})
        );
        assert_eq!(saved["tokens"]["access_token"], access);
        assert_eq!(saved["tokens"]["refresh_token"], "rotated-refresh-secret");
        assert_eq!(saved["tokens"]["id_token"], "rotated-id-secret");
        assert!(
            chrono::DateTime::parse_from_rfc3339(saved["last_refresh"].as_str().unwrap()).is_ok()
        );
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[tokio::test]
    async fn refresh_accepts_dotted_opaque_access_with_file_account() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("auth.json");
        write_credentials(&path, &credentials(&jwt(1, None)));
        let access = "opaque.rotated.token";
        let server = fixture(
            serde_json::json!({
                "access_token": access,
                "refresh_token": "rotated-refresh-secret",
                "token_type": "Bearer"
            }),
            StatusCode::OK,
            false,
        )
        .await;
        let mut auth = auth(&path);
        auth.refresh_endpoint = server.endpoint.clone();

        let headers = auth
            .headers(&client(), false, &HeaderMap::new())
            .await
            .unwrap();
        assert_eq!(headers[AUTHORIZATION], format!("Bearer {access}"));
        assert_eq!(headers["chatgpt-account-id"], "account-one");
        assert_eq!(server.state.calls.load(Ordering::SeqCst), 1);
        let saved: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(saved["tokens"]["access_token"], access);
    }

    async fn assert_separately_constructed_providers_share_refresh(first: &Path, second: &Path) {
        let access = jwt(4_102_444_800, None);
        let server = fixture(
            serde_json::json!({
                "access_token": access,
                "refresh_token": "shared-rotated-refresh-secret",
                "id_token": "shared-rotated-id-secret"
            }),
            StatusCode::OK,
            true,
        )
        .await;
        let mut first_auth = auth(first);
        let mut second_auth = auth(second);
        first_auth.refresh_endpoint = server.endpoint.clone();
        second_auth.refresh_endpoint = server.endpoint.clone();
        let client = client();
        let first_client = client.clone();
        let first_request = tokio::spawn(async move {
            first_auth
                .headers(&first_client, false, &HeaderMap::new())
                .await
                .unwrap()
        });
        let pause = server.state.pause.as_ref().unwrap();
        pause.0.notified().await;
        let incoming = HeaderMap::new();
        let second_request = second_auth.headers(&client, false, &incoming);
        tokio::pin!(second_request);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), second_request.as_mut())
                .await
                .is_err(),
            "the second provider must wait for the in-flight rotation"
        );
        pause.1.notify_one();
        let first_headers = first_request.await.unwrap();
        let second_headers = tokio::time::timeout(Duration::from_secs(2), second_request)
            .await
            .expect("the shared refresh must release both providers")
            .unwrap();
        for headers in [first_headers, second_headers] {
            assert_eq!(headers[AUTHORIZATION], format!("Bearer {access}"));
            assert_eq!(headers["chatgpt-account-id"], "account-one");
        }
        assert_eq!(server.state.calls.load(Ordering::SeqCst), 1);
        let saved: Value = serde_json::from_slice(&std::fs::read(first).unwrap()).unwrap();
        assert_eq!(saved["tokens"]["access_token"], access);
        assert_eq!(
            saved["tokens"]["refresh_token"],
            "shared-rotated-refresh-secret"
        );
        assert_eq!(saved["tokens"]["id_token"], "shared-rotated-id-secret");
        assert_eq!(
            std::fs::read(first).unwrap(),
            std::fs::read(second).unwrap()
        );
    }

    #[tokio::test]
    async fn separately_constructed_providers_refresh_one_credential_file_once() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("auth.json");
        write_credentials(&path, &credentials(&jwt(1, None)));
        assert_separately_constructed_providers_share_refresh(&path, &path).await;
    }

    #[tokio::test]
    async fn relative_and_absolute_credential_paths_share_refresh() {
        let current_directory = std::env::current_dir().unwrap();
        let directory = tempfile::tempdir_in(&current_directory).unwrap();
        let absolute = directory.path().join("auth.json");
        let relative = absolute.strip_prefix(&current_directory).unwrap();
        write_credentials(&absolute, &credentials(&jwt(1, None)));
        assert_separately_constructed_providers_share_refresh(relative, &absolute).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_and_target_credential_paths_share_refresh() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("actual-auth.json");
        let link = directory.path().join("auth.json");
        write_credentials(&target, &credentials(&jwt(1, None)));
        symlink("actual-auth.json", &link).unwrap();
        assert_separately_constructed_providers_share_refresh(&link, &target).await;
        assert!(
            std::fs::symlink_metadata(link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[tokio::test]
    async fn different_credential_files_refresh_without_waiting_for_each_other() {
        let directory = tempfile::tempdir().unwrap();
        let first_path = directory.path().join("first-auth.json");
        let second_path = directory.path().join("second-auth.json");
        write_credentials(&first_path, &credentials(&jwt(1, None)));
        write_credentials(&second_path, &credentials(&jwt(1, None)));
        let first_access = jwt(4_102_444_800, None);
        let second_access = jwt(4_102_444_801, None);
        let first_server = fixture(
            serde_json::json!({"access_token": first_access, "refresh_token": "first-rotation"}),
            StatusCode::OK,
            true,
        )
        .await;
        let second_server = fixture(
            serde_json::json!({"access_token": second_access, "refresh_token": "second-rotation"}),
            StatusCode::OK,
            false,
        )
        .await;
        let mut first_auth = auth(&first_path);
        let mut second_auth = auth(&second_path);
        first_auth.refresh_endpoint = first_server.endpoint.clone();
        second_auth.refresh_endpoint = second_server.endpoint.clone();
        let first_request = tokio::spawn(async move {
            first_auth
                .headers(&client(), false, &HeaderMap::new())
                .await
                .unwrap()
        });
        let pause = first_server.state.pause.as_ref().unwrap();
        pause.0.notified().await;
        let second_headers = tokio::time::timeout(
            Duration::from_secs(2),
            second_auth.headers(&client(), false, &HeaderMap::new()),
        )
        .await
        .expect("an unrelated credential file must not wait for the first OAuth service")
        .unwrap();
        assert_eq!(
            second_headers[AUTHORIZATION],
            format!("Bearer {second_access}")
        );
        pause.1.notify_one();
        assert_eq!(
            first_request.await.unwrap()[AUTHORIZATION],
            format!("Bearer {first_access}")
        );
        assert_eq!(first_server.state.calls.load(Ordering::SeqCst), 1);
        assert_eq!(second_server.state.calls.load(Ordering::SeqCst), 1);
        for (path, rotated) in [
            (&first_path, "first-rotation"),
            (&second_path, "second-rotation"),
        ] {
            let saved: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
            assert_eq!(saved["tokens"]["refresh_token"], rotated);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn retargeted_symlink_relocks_for_active_and_waiting_refreshes() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let first_path = directory.path().join("first-auth.json");
        let second_path = directory.path().join("second-auth.json");
        let link = directory.path().join("auth.json");
        write_credentials(&first_path, &credentials(&jwt(1, None)));
        write_credentials(&second_path, &credentials(&jwt(1, None)));
        symlink("first-auth.json", &link).unwrap();
        let first_access = jwt(4_102_444_800, None);
        let second_access = jwt(4_102_444_801, None);
        let first_server = fixture(
            serde_json::json!({"access_token": first_access, "refresh_token": "first-rotation"}),
            StatusCode::OK,
            true,
        )
        .await;
        let second_server = fixture(
            serde_json::json!({"access_token": second_access, "refresh_token": "target-rotation"}),
            StatusCode::OK,
            true,
        )
        .await;
        let mut first_auth = auth(&link);
        let mut waiting_auth = auth(&link);
        let mut second_auth = auth(&second_path);
        let mut original_auth = auth(&first_path);
        first_auth.refresh_endpoint = first_server.endpoint.clone();
        waiting_auth.refresh_endpoint = first_server.endpoint.clone();
        second_auth.refresh_endpoint = second_server.endpoint.clone();
        original_auth.refresh_endpoint = first_server.endpoint.clone();
        let mut first_request = tokio::spawn(async move {
            first_auth
                .headers(&client(), false, &HeaderMap::new())
                .await
                .unwrap()
        });
        let second_request = tokio::spawn(async move {
            second_auth
                .headers(&client(), false, &HeaderMap::new())
                .await
                .unwrap()
        });
        let first_pause = first_server.state.pause.as_ref().unwrap();
        let second_pause = second_server.state.pause.as_ref().unwrap();
        first_pause.0.notified().await;
        second_pause.0.notified().await;
        // Both waiters must keep running after A releases its fair mutex, even while
        // this task awaits the independent A provider and B's refresh remains paused.
        let mut waiting_request = tokio::spawn(async move {
            waiting_auth
                .headers(&client(), false, &HeaderMap::new())
                .await
                .unwrap()
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut waiting_request)
                .await
                .is_err()
        );
        let mut original_request = tokio::spawn(async move {
            original_auth
                .headers(&client(), false, &HeaderMap::new())
                .await
                .unwrap()
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut original_request)
                .await
                .is_err(),
            "an independent original-target provider must share the active refresh lock"
        );
        let replacement = directory.path().join("replacement-link");
        symlink("second-auth.json", &replacement).unwrap();
        std::fs::rename(replacement, &link).unwrap();
        first_pause.1.notify_one();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut first_request)
                .await
                .is_err(),
            "the active refresh must wait for the new target's in-flight rotation"
        );
        let original_headers = tokio::time::timeout(Duration::from_secs(2), original_request)
            .await
            .expect("relocking the alias must release the original target before waiting")
            .unwrap();
        assert_eq!(
            original_headers[AUTHORIZATION],
            format!("Bearer {first_access}")
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut waiting_request)
                .await
                .is_err(),
            "a waiting provider must resolve the new symlink target after acquiring its lock"
        );
        second_pause.1.notify_one();
        let active_headers = tokio::time::timeout(Duration::from_secs(2), first_request)
            .await
            .unwrap()
            .unwrap();
        let target_headers = second_request.await.unwrap();
        let waiting_headers = tokio::time::timeout(Duration::from_secs(2), waiting_request)
            .await
            .unwrap()
            .unwrap();
        for headers in [active_headers, target_headers, waiting_headers] {
            assert_eq!(headers[AUTHORIZATION], format!("Bearer {second_access}"));
        }
        assert_eq!(first_server.state.calls.load(Ordering::SeqCst), 1);
        assert_eq!(second_server.state.calls.load(Ordering::SeqCst), 1);
        let first_saved: Value =
            serde_json::from_slice(&std::fs::read(&first_path).unwrap()).unwrap();
        assert_eq!(first_saved["tokens"]["access_token"], first_access);
        assert_eq!(first_saved["tokens"]["refresh_token"], "first-rotation");
        for server in [&first_server, &second_server] {
            let requests = server.state.requests.lock().await;
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0]["refresh_token"], "original-refresh-secret");
        }
        let saved: Value = serde_json::from_slice(&std::fs::read(&link).unwrap()).unwrap();
        assert_eq!(saved["tokens"]["access_token"], second_access);
        assert_eq!(saved["tokens"]["refresh_token"], "target-rotation");
        assert!(
            std::fs::symlink_metadata(link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn successful_rotation_survives_retargeting_to_missing_targets() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("actual-auth.json");
        let link = directory.path().join("auth.json");
        write_credentials(&target, &credentials(&jwt(1, None)));
        symlink("actual-auth.json", &link).unwrap();
        let access = jwt(4_102_444_800, None);
        let server = fixture(
            serde_json::json!({"access_token": access, "refresh_token": "retargeted-rotation"}),
            StatusCode::OK,
            true,
        )
        .await;
        let mut alias_auth = auth(&link);
        alias_auth.refresh_endpoint = server.endpoint.clone();
        let request = tokio::spawn(async move {
            alias_auth
                .headers(&client(), false, &HeaderMap::new())
                .await
        });
        let pause = server.state.pause.as_ref().unwrap();
        pause.0.notified().await;
        for name in ["first-missing-auth.json", "second-missing-auth.json"] {
            let replacement = directory.path().join("replacement-link");
            symlink(name, &replacement).unwrap();
            std::fs::rename(replacement, &link).unwrap();
        }
        pause.1.notify_one();
        let error = tokio::time::timeout(Duration::from_secs(2), request)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err()
            .to_string();
        assert!(error.contains("Cannot locate Codex auth_file"));
        let saved: Value = serde_json::from_slice(&std::fs::read(&target).unwrap()).unwrap();
        assert_eq!(saved["tokens"]["access_token"], access);
        assert_eq!(saved["tokens"]["refresh_token"], "retargeted-rotation");
        let mut original_auth = auth(&target);
        original_auth.refresh_endpoint = server.endpoint.clone();
        let headers = tokio::time::timeout(
            Duration::from_secs(2),
            original_auth.headers(&client(), false, &HeaderMap::new()),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(headers[AUTHORIZATION], format!("Bearer {access}"));
        assert_eq!(server.state.calls.load(Ordering::SeqCst), 1);
        assert!(!directory.path().join("first-missing-auth.json").exists());
        assert!(!directory.path().join("second-missing-auth.json").exists());
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn retargeting_preserves_external_original_replacement_even_when_refresh_fails() {
        use std::os::unix::fs::symlink;
        for status in [StatusCode::OK, StatusCode::UNAUTHORIZED] {
            let directory = tempfile::tempdir().unwrap();
            let original_path = directory.path().join("original-auth.json");
            let current_path = directory.path().join("current-auth.json");
            let link = directory.path().join("auth.json");
            write_credentials(&original_path, &credentials(&jwt(1, None)));
            let current_access = jwt(4_102_444_801, None);
            write_credentials(&current_path, &credentials(&current_access));
            symlink("original-auth.json", &link).unwrap();
            let server = fixture(
                serde_json::json!({
                    "access_token": jwt(4_102_444_800, None),
                    "refresh_token": "superseded-rotation"
                }),
                status,
                true,
            )
            .await;
            let mut alias_auth = auth(&link);
            alias_auth.refresh_endpoint = server.endpoint.clone();
            let request = tokio::spawn(async move {
                alias_auth
                    .headers(&client(), false, &HeaderMap::new())
                    .await
                    .unwrap()
            });
            let pause = server.state.pause.as_ref().unwrap();
            pause.0.notified().await;
            let external_access = jwt(4_102_444_802, None);
            let mut external = credentials(&external_access);
            external["tokens"]["refresh_token"] = Value::String("external-rotation".into());
            let replacement = directory.path().join("external-auth.json");
            write_credentials(&replacement, &external);
            std::fs::rename(replacement, &original_path).unwrap();
            let replacement = directory.path().join("replacement-link");
            symlink("current-auth.json", &replacement).unwrap();
            std::fs::rename(replacement, &link).unwrap();
            let original_bytes = std::fs::read(&original_path).unwrap();
            let current_bytes = std::fs::read(&current_path).unwrap();
            pause.1.notify_one();
            let headers = tokio::time::timeout(Duration::from_secs(2), request)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(headers[AUTHORIZATION], format!("Bearer {current_access}"));
            let mut original_auth = auth(&original_path);
            original_auth.refresh_endpoint = server.endpoint.clone();
            let original_headers = original_auth
                .headers(&client(), false, &HeaderMap::new())
                .await
                .unwrap();
            assert_eq!(
                original_headers[AUTHORIZATION],
                format!("Bearer {external_access}")
            );
            assert_eq!(std::fs::read(&original_path).unwrap(), original_bytes);
            assert_eq!(std::fs::read(&current_path).unwrap(), current_bytes);
            assert_eq!(server.state.calls.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test]
    async fn external_rotation_during_refresh_wins_even_when_refresh_fails() {
        for status in [StatusCode::OK, StatusCode::UNAUTHORIZED] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("auth.json");
            write_credentials(&path, &credentials(&jwt(1, None)));
            let server = fixture(
                serde_json::json!({"access_token": jwt(4_102_444_800, None)}),
                status,
                true,
            )
            .await;
            let mut auth = auth(&path);
            auth.refresh_endpoint = server.endpoint.clone();
            let request = tokio::spawn(async move {
                auth.headers(&client(), false, &HeaderMap::new())
                    .await
                    .unwrap()
            });
            let pause = server.state.pause.as_ref().unwrap();
            pause.0.notified().await;
            let external_access = jwt(4_102_444_802, None);
            let mut external = credentials(&external_access);
            external["tokens"]["refresh_token"] = Value::String("external-refresh-secret".into());
            external["external-change"] = Value::Bool(true);
            let replacement = directory.path().join("external-auth.json");
            write_credentials(&replacement, &external);
            std::fs::rename(&replacement, &path).unwrap();
            let external_bytes = std::fs::read(&path).unwrap();
            pause.1.notify_one();
            let headers = request.await.unwrap();
            assert_eq!(headers[AUTHORIZATION], format!("Bearer {external_access}"));
            assert_eq!(std::fs::read(&path).unwrap(), external_bytes);
            assert_eq!(server.state.calls.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test]
    async fn cancelled_request_does_not_abandon_rotating_refresh() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("auth.json");
        write_credentials(&path, &credentials(&jwt(1, None)));
        let access = jwt(4_102_444_800, None);
        let server = fixture(
            serde_json::json!({"access_token": access, "refresh_token": "after-cancellation"}),
            StatusCode::OK,
            true,
        )
        .await;
        let mut request_auth = auth(&path);
        let mut waiting_auth = auth(&path);
        request_auth.refresh_endpoint = server.endpoint.clone();
        waiting_auth.refresh_endpoint = server.endpoint.clone();
        let request = tokio::spawn(async move {
            request_auth
                .headers(&client(), false, &HeaderMap::new())
                .await
        });
        let pause = server.state.pause.as_ref().unwrap();
        pause.0.notified().await;
        request.abort();
        let _ = request.await;
        pause.1.notify_one();
        let headers = tokio::time::timeout(
            Duration::from_secs(2),
            waiting_auth.headers(&client(), false, &HeaderMap::new()),
        )
        .await
        .expect("a separately constructed provider must observe the detached refresh")
        .unwrap();
        assert_eq!(headers[AUTHORIZATION], format!("Bearer {access}"));
        let saved: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(saved["tokens"]["refresh_token"], "after-cancellation");
        assert_eq!(server.state.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn refresh_errors_do_not_expose_remote_or_local_secrets_or_modify_file() {
        for (status, body) in [
            (
                StatusCode::UNAUTHORIZED,
                serde_json::json!({"error": "remote-secret original-refresh-secret"}),
            ),
            (
                StatusCode::OK,
                serde_json::json!({"access_token": "bad\r\nremote-secret"}),
            ),
            (
                StatusCode::OK,
                serde_json::json!({"access_token": 123, "error": "remote-secret"}),
            ),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("auth.json");
            write_credentials(&path, &credentials(&jwt(1, None)));
            let original = std::fs::read(&path).unwrap();
            let server = fixture(body, status, false).await;
            let mut auth = auth(&path);
            auth.refresh_endpoint = server.endpoint.clone();
            let error = format!(
                "{:#}",
                auth.headers(&client(), false, &HeaderMap::new())
                    .await
                    .unwrap_err()
            );
            assert!(!error.contains("remote-secret"));
            assert!(!error.contains("original-refresh-secret"));
            assert_eq!(std::fs::read(&path).unwrap(), original);
        }
    }

    #[tokio::test]
    async fn refresh_preserves_optional_tokens_and_account_can_come_from_claims() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("auth.json");
        let mut document = credentials(&jwt(1, None));
        document["tokens"]
            .as_object_mut()
            .unwrap()
            .remove("account_id");
        write_credentials(&path, &document);
        let access = jwt(4_102_444_800, Some("claimed-account"));
        let server = fixture(
            serde_json::json!({"access_token": access}),
            StatusCode::OK,
            false,
        )
        .await;
        let mut auth = auth(&path);
        auth.refresh_endpoint = server.endpoint.clone();
        let headers = auth
            .headers(&client(), false, &HeaderMap::new())
            .await
            .unwrap();
        assert_eq!(headers["chatgpt-account-id"], "claimed-account");
        let saved: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(saved["tokens"]["refresh_token"], "original-refresh-secret");
        assert_eq!(saved["tokens"]["id_token"], "original-id-secret");
    }

    #[test]
    fn expiry_margin_and_periodic_refresh_have_exact_boundaries() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("auth.json");
        for (exp, expected) in [(1299, true), (1300, true), (1301, false)] {
            write_credentials(&path, &credentials(&jwt(exp, None)));
            assert_eq!(
                read_snapshot(&path).unwrap().needs_refresh(1000).unwrap(),
                expected
            );
        }
        let mut document = credentials("opaque-access-fixture");
        document["last_refresh"] = Value::String("2020-01-01T00:00:00Z".into());
        write_credentials(&path, &document);
        let snapshot = read_snapshot(&path).unwrap();
        let last = chrono::DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z")
            .unwrap()
            .timestamp();
        assert!(
            !snapshot
                .needs_refresh(last + REFRESH_INTERVAL_SECONDS - 1)
                .unwrap()
        );
        assert!(
            snapshot
                .needs_refresh(last + REFRESH_INTERVAL_SECONDS)
                .unwrap()
        );
    }

    #[tokio::test]
    async fn rotated_credentials_are_saved_even_if_account_configuration_is_missing() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("auth.json");
        let mut document = credentials(&jwt(1, None));
        document["tokens"]
            .as_object_mut()
            .unwrap()
            .remove("account_id");
        write_credentials(&path, &document);
        let access = jwt(4_102_444_800, None);
        let server = fixture(
            serde_json::json!({
                "access_token": access, "refresh_token": "must-not-lose-rotation"
            }),
            StatusCode::OK,
            false,
        )
        .await;
        let mut auth = auth(&path);
        auth.refresh_endpoint = server.endpoint.clone();
        assert!(
            auth.headers(&client(), false, &HeaderMap::new())
                .await
                .is_err()
        );
        let saved: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(saved["tokens"]["access_token"], access);
        assert_eq!(saved["tokens"]["refresh_token"], "must-not-lose-rotation");
        assert_eq!(server.state.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn missing_refresh_token_requires_login_without_network_or_secret_disclosure() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("auth.json");
        let mut document = credentials(&jwt(1, None));
        document["tokens"]
            .as_object_mut()
            .unwrap()
            .remove("refresh_token");
        write_credentials(&path, &document);
        let original = std::fs::read(&path).unwrap();
        assert!(
            auth(&path)
                .headers(&client(), false, &HeaderMap::new())
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }

    #[test]
    fn persistence_rechecks_external_file_and_cleans_temporary_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("auth.json");
        write_credentials(&path, &credentials(&jwt(1, None)));
        let snapshot = read_snapshot(&path).unwrap();
        let external = credentials(&jwt(4_102_444_800, None));
        write_credentials(&path, &external);
        let result = persist_if_unchanged(&snapshot, &credentials("stale-replacement")).unwrap();
        assert!(matches!(result, PersistOutcome::Changed));
        let saved: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(saved, external);
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn persistence_preserves_configured_symlink_and_replaces_target_privately() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("actual-auth.json");
        let link = directory.path().join("auth.json");
        write_credentials(&target, &credentials(&jwt(1, None)));
        symlink(&target, &link).unwrap();
        let snapshot = read_snapshot(&link).unwrap();
        let replacement = credentials(&jwt(4_102_444_800, None));
        assert!(matches!(
            persist_if_unchanged(&snapshot, &replacement).unwrap(),
            PersistOutcome::Written
        ));
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        let saved: Value = serde_json::from_slice(&std::fs::read(&target).unwrap()).unwrap();
        assert_eq!(saved, replacement);
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[tokio::test]
    async fn missing_auth_file_is_a_clear_runtime_error_without_network_fallback() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("missing-auth.json");
        let server = fixture(
            serde_json::json!({"access_token": jwt(4_102_444_800, None)}),
            StatusCode::OK,
            false,
        )
        .await;
        let mut auth = auth(&path);
        auth.refresh_endpoint = server.endpoint.clone();
        let error = format!(
            "{:#}",
            auth.headers(&client(), false, &HeaderMap::new())
                .await
                .unwrap_err()
        );
        assert!(error.contains("auth_file"));
        assert!(error.contains("codex login"));
        assert_eq!(server.state.calls.load(Ordering::SeqCst), 0);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn malformed_auth_file_errors_are_secret_safe() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("auth.json");
        std::fs::write(&path, b"{\"tokens\": secret-local-value}").unwrap();
        let error = format!(
            "{:#}",
            auth(&path)
                .headers(&client(), false, &HeaderMap::new())
                .await
                .unwrap_err()
        );
        assert!(!error.contains("secret-local-value"));
    }
}
