use std::{
    fs::File,
    net::{SocketAddr, TcpListener},
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;
use tempfile::TempDir;
use uuid::Uuid;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const START_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Gateway {
    pub base: String,
    pub control: String,
    pub client: reqwest::Client,
    child: Child,
    _tempdir: TempDir,
    pub(super) proxy_token: String,
    control_token: String,
}

impl Gateway {
    pub async fn start(
        kind: &str,
        upstream: &str,
        upstream_model: &str,
        auth_file: Option<&Path>,
    ) -> Result<Gateway> {
        Self::start_with_account(kind, upstream, upstream_model, auth_file, None).await
    }

    pub async fn start_with_account(
        kind: &str,
        upstream: &str,
        upstream_model: &str,
        auth_file: Option<&Path>,
        account_id: Option<&str>,
    ) -> Result<Gateway> {
        Self::start_internal(
            kind,
            upstream,
            upstream_model,
            auth_file,
            account_id,
            None,
            "",
        )
        .await
    }

    #[allow(dead_code)]
    pub async fn start_with_provider_lines(
        kind: &str,
        upstream: &str,
        upstream_model: &str,
        lines: &str,
    ) -> Result<Gateway> {
        Self::start_internal(kind, upstream, upstream_model, None, None, None, lines).await
    }

    #[allow(dead_code)]
    pub async fn start_with_provider_auth(
        kind: &str,
        upstream: &str,
        upstream_model: &str,
        mode: &str,
        credential: Option<&str>,
    ) -> Result<Gateway> {
        Self::start_internal(
            kind,
            upstream,
            upstream_model,
            None,
            None,
            Some((mode, credential)),
            "",
        )
        .await
    }

    async fn start_internal(
        kind: &str,
        upstream: &str,
        upstream_model: &str,
        auth_file: Option<&Path>,
        account_id: Option<&str>,
        auth_override: Option<(&str, Option<&str>)>,
        provider_extra: &str,
    ) -> Result<Gateway> {
        let tempdir = tempfile::tempdir().context("create private gateway test directory")?;
        let inference = unused_loopback()?;
        let mut control = unused_loopback()?;
        while control == inference {
            control = unused_loopback()?;
        }
        let proxy_token = format!("test-proxy-{}", Uuid::new_v4());
        let control_token = format!("test-control-{}", Uuid::new_v4());
        let proxy_env = format!("INFER_TEST_PROXY_{}", Uuid::new_v4().simple());
        let control_env = format!("INFER_TEST_CONTROL_{}", Uuid::new_v4().simple());
        let base_url = if kind == "codex" {
            format!("{}/backend-api/codex", upstream.trim_end_matches('/'))
        } else {
            upstream.trim_end_matches('/').to_owned()
        };
        let mut provider_env = None;
        let auth = if let Some((mode, credential)) = auth_override {
            match mode {
                "passthrough" if credential.is_none() => {
                    "[providers.backend.auth]\nmode = \"passthrough\"\n".to_owned()
                }
                "bearer" | "api_key" => {
                    let credential =
                        credential.context("configured test auth requires a credential")?;
                    let name = format!("INFER_TEST_UPSTREAM_{}", Uuid::new_v4().simple());
                    provider_env = Some((name.clone(), credential.to_owned()));
                    format!("[providers.backend.auth]\nmode = {mode:?}\ntoken_env = {name:?}\n")
                }
                _ => bail!("unsupported provider auth test mode {mode}"),
            }
        } else {
            match (kind, auth_file, account_id) {
                ("codex", Some(path), account_id) => format!(
                    "[providers.backend.auth]\nmode = \"codex\"\nauth_file = {:?}\n{}",
                    path,
                    account_id
                        .map_or_else(String::new, |account| format!("account_id = {account:?}\n"))
                ),
                ("codex", None, _) => bail!("Codex gateway fixture requires auth_file"),
                (_, Some(_), _) => bail!("auth_file is only valid for Codex gateway fixtures"),
                (_, None, Some(_)) => bail!("account_id is only valid for Codex gateway fixtures"),
                _ => "[providers.backend.auth]\nmode = \"none\"\n".to_owned(),
            }
        };
        let config = format!(
            "listen = \"{inference}\"\n\
             control_listen = \"{control}\"\n\
             proxy_token_env = \"{proxy_env}\"\n\
             control_token_env = \"{control_env}\"\n\
             trace_dir = {:?}\n\
             default_provider = \"backend\"\n\
             connect_timeout_seconds = 10\n\
             read_timeout_seconds = 60\n\
             [providers.backend]\n\
             kind = \"{kind}\"\n\
             base_url = \"{base_url}\"\n\
             {provider_extra}\
             {auth}\
             [models.validation]\n\
             provider = \"backend\"\n\
             model = \"{upstream_model}\"\n",
            tempdir.path().join("traces")
        );
        let config_path = tempdir.path().join("infer.toml");
        std::fs::write(&config_path, config).context("write gateway test config")?;

        let stdout = private_file(&tempdir.path().join("stdout.log"))?;
        let stderr = private_file(&tempdir.path().join("stderr.log"))?;
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .no_proxy()
            .build()
            .context("build gateway test client")?;
        let mut command = Command::new(env!("CARGO_BIN_EXE_infer"));
        command
            .arg("--config")
            .arg(&config_path)
            .arg("serve")
            .env(&proxy_env, &proxy_token)
            .env(&control_env, &control_token)
            .env("RUST_LOG", "infer=warn")
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        if let Some((name, value)) = provider_env {
            command.env(name, value);
        }
        let child = command.spawn().context("spawn infer gateway")?;

        let mut gateway = Gateway {
            base: format!("http://{inference}"),
            control: format!("http://{control}"),
            client,
            child,
            _tempdir: tempdir,
            proxy_token,
            control_token,
        };
        let ready = async {
            loop {
                if let Some(status) = gateway.child.try_wait().context("inspect gateway child")? {
                    bail!("gateway exited before readiness: {status}");
                }
                match gateway
                    .client
                    .get(format!("{}/health", gateway.control))
                    .bearer_auth(&gateway.control_token)
                    .send()
                    .await
                {
                    Ok(response) if response.status().is_success() => return Ok(()),
                    _ => tokio::time::sleep(Duration::from_millis(10)).await,
                }
            }
        };
        tokio::time::timeout(START_TIMEOUT, ready)
            .await
            .map_err(|_| anyhow!("gateway readiness timed out"))??;

        Ok(gateway)
    }

    pub async fn post(&self, path: &str, body: &Value) -> Result<reqwest::Response> {
        self.client
            .post(format!("{}{}", self.base, path))
            .header("x-infer-key", &self.proxy_token)
            .json(body)
            .send()
            .await
            .context("POST through gateway")
    }

    pub async fn trace(&self, id: &str) -> Result<Value> {
        let response = self
            .client
            .get(format!("{}/traces/{id}", self.control))
            .bearer_auth(&self.control_token)
            .send()
            .await
            .context("fetch trace")?
            .error_for_status()
            .context("trace endpoint status")?;
        response.json().await.context("decode trace")
    }

    pub async fn body(&self, id: &str, kind: &str) -> Result<Vec<u8>> {
        let response = self
            .client
            .get(format!("{}/traces/{id}/body/{kind}", self.control))
            .bearer_auth(&self.control_token)
            .send()
            .await
            .context("fetch trace body")?
            .error_for_status()
            .context("trace body endpoint status")?;
        Ok(response.bytes().await.context("read trace body")?.to_vec())
    }

    pub async fn export(&self) -> Result<Vec<Value>> {
        let text = self
            .client
            .get(format!("{}/export?limit=100", self.control))
            .bearer_auth(&self.control_token)
            .send()
            .await
            .context("export traces")?
            .error_for_status()
            .context("trace export endpoint status")?
            .text()
            .await
            .context("read trace export")?;
        text.lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).context("decode trace export row"))
            .collect()
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        match self.child.try_wait() {
            Ok(Some(_)) => {}
            _ => {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Event {
    pub event: Option<String>,
    pub data: String,
}

pub fn sse_events(bytes: &[u8]) -> Result<Vec<Event>> {
    let mut input = std::str::from_utf8(bytes).context("SSE is not UTF-8")?;
    input = input.strip_prefix('\u{feff}').unwrap_or(input);
    let normalized = input.replace("\r\n", "\n").replace('\r', "\n");
    let mut events = Vec::new();
    let mut event = None;
    let mut data = Vec::new();
    for line in normalized.split_terminator('\n') {
        if line.is_empty() {
            dispatch_event(&mut events, &mut event, &mut data);
            continue;
        }
        if line.starts_with(':') {
            continue;
        }
        let (field, value) = line.split_once(':').unwrap_or((line, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "event" => event = Some(value.to_owned()),
            "data" => data.push(value.to_owned()),
            _ => {}
        }
    }
    Ok(events)
}

fn dispatch_event(events: &mut Vec<Event>, event: &mut Option<String>, data: &mut Vec<String>) {
    if !data.is_empty() {
        events.push(Event {
            event: event.take(),
            data: data.join("\n"),
        });
        data.clear();
    } else {
        *event = None;
    }
}

fn unused_loopback() -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").context("reserve loopback port")?;
    listener.local_addr().context("read reserved loopback port")
}

fn private_file(path: &Path) -> Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true).read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).context("create private gateway log")
}
