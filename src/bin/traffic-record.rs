//! Manual traffic recorder. Never invoked by tests or CI.
//!
//! Downloads the pinned official CLI, checks it against the digest in
//! `src/traffic/`, and runs that binary through a local recording proxy.
//! Raw captures stay in `traffic-recordings/` (gitignored). The scrubbed
//! fixture is written next to the raw capture for review; it is not copied
//! into `tests/traffic` automatically. `--harness` defaults to `codex`.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use infer::traffic::codex::{
    self, PACKAGE_SUMS_NAME, RELEASE, find_binary, fixture_from_capture, package_filename,
    release_archive_url, sums_url, verify_artifact, verify_sums_manifest,
};
use infer::traffic::grok_build::{self, AuthClass, Upstream};
use infer::traffic::{CapturedExchange, Harness, RecordingProxy, assert_clean};
use serde_json::Value;

#[derive(Parser)]
#[command(
    name = "traffic-record",
    about = "Record official Codex or Grok Build CLI traffic"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run one official CLI turn through the recording proxy.
    Record {
        /// `codex` (default) or `grok-build`.
        #[arg(long, default_value = "codex")]
        harness: String,
        /// Fixture scenario name, for example chat-turn.
        #[arg(long)]
        scenario: String,
        /// Model slug the CLI should request. Codex defaults to gpt-5.5.
        /// grok-build requires a model that `grok models` lists for the selected auth.
        #[arg(long)]
        model: Option<String>,
        /// User prompt for the headless turn.
        #[arg(long, default_value = "Say hello in one word.")]
        prompt: String,
    },
    /// Rewrite a raw capture into a scrubbed fixture JSON file.
    Scrub {
        /// `codex` (default) or `grok-build`.
        #[arg(long, default_value = "codex")]
        harness: String,
        #[arg(long)]
        raw: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value = "chat-turn")]
        scenario: String,
    },
    /// Fail if a fixture directory contains token-shaped material.
    Check {
        #[arg(long)]
        fixtures: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Commands::Record {
            harness,
            scenario,
            model,
            prompt,
        } => record(&harness, scenario, model, prompt).await,
        Commands::Scrub {
            harness,
            raw,
            out,
            scenario,
        } => scrub_file(&harness, &raw, &out, &scenario),
        Commands::Check { fixtures } => assert_clean(&fixtures),
    }
}

async fn record(
    harness: &str,
    scenario: String,
    model: Option<String>,
    prompt: String,
) -> Result<()> {
    if scenario.contains('/') || scenario.contains("..") {
        bail!("scenario name must be a single path segment");
    }
    match harness {
        "codex" => {
            let model = model.unwrap_or_else(|| "gpt-5.5".to_owned());
            record_codex(scenario, model, prompt).await
        }
        "grok-build" => {
            let Some(model) = model else {
                bail!(
                    "--model is required for grok-build. Use a model that `grok models` lists for the auth this command selects."
                );
            };
            record_grok(scenario, model, prompt).await
        }
        other => bail!("unknown harness {other}; expected codex or grok-build"),
    }
}

async fn record_codex(scenario: String, model: String, prompt: String) -> Result<()> {
    let binary = ensure_cli().await?;
    let proxy = RecordingProxy::start("https://chatgpt.com", Duration::from_secs(900)).await?;
    let work = tempfile::tempdir().context("create record work directory")?;
    let init = Command::new("git")
        .arg("init")
        .arg(work.path())
        .status()
        .context("git init for codex exec")?;
    if !init.success() {
        bail!("git init failed; codex exec wants a work directory");
    }
    let mut command = Command::new(&binary);
    command
        .current_dir(work.path())
        .args(codex::exec_args(&proxy.base, &model, &prompt));
    let output = command.output().context("run official codex")?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // The CLI child uses a temp cwd. Captures stay under the crate root.
    let dir = recordings_dir()
        .join(codex::CODEX.id())
        .join(&scenario)
        .join(stamp.to_string());
    fs::create_dir_all(&dir)?;
    let dir = fs::canonicalize(&dir).context("canonicalize traffic recording")?;
    fs::write(dir.join("cli.stdout"), &output.stdout)?;
    fs::write(dir.join("cli.stderr"), &output.stderr)?;
    let exchanges = proxy.exchanges();
    fs::write(dir.join("raw.json"), serde_json::to_vec_pretty(&exchanges)?)?;
    if !output.status.success() {
        bail!(
            "codex exec exited {}. Raw capture, if any, is in {}. stderr was not copied into the repository.",
            output.status,
            dir.display()
        );
    }
    let fixture = fixture_from_capture(&scenario, &exchanges)?;
    let fixture_path = dir.join("fixture.json");
    fs::write(&fixture_path, serde_json::to_vec_pretty(&fixture)?)?;
    println!(
        "recorded {} exchange(s) with the official {RELEASE} CLI",
        exchanges.len()
    );
    println!(
        "fixture kept {} POST /responses exchange(s); calls that are not POST /responses are omitted",
        fixture.exchanges.len()
    );
    println!("raw capture: {}", dir.join("raw.json").display());
    println!("scrubbed fixture: {}", fixture_path.display());
    println!(
        "Review it, then copy the fixture you want to keep into tests/traffic/codex/fixtures/{scenario}.json"
    );
    println!("Set provenance stays \"recorded\". Do not commit traffic-recordings/.");
    Ok(())
}

fn scrub_file(harness: &str, raw: &Path, out: &Path, scenario: &str) -> Result<()> {
    let exchanges: Vec<CapturedExchange> =
        serde_json::from_slice(&fs::read(raw).with_context(|| format!("read {}", raw.display()))?)?;
    let fixture = match harness {
        "codex" => fixture_from_capture(scenario, &exchanges)?,
        "grok-build" => grok_build::fixture_from_capture(scenario, &exchanges)?,
        other => bail!("unknown harness {other}; expected codex or grok-build"),
    };
    if let Some(parent) = out.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(out, serde_json::to_vec_pretty(&fixture)?)?;
    println!("wrote {}", out.display());
    Ok(())
}

async fn record_grok(scenario: String, model: String, prompt: String) -> Result<()> {
    let upstream = grok_upstream()?;
    let binary = ensure_grok().await?;
    let proxy = RecordingProxy::start(upstream.origin(), Duration::from_secs(900)).await?;
    let work = tempfile::tempdir().context("create record work directory")?;
    let init = Command::new("git")
        .arg("init")
        .arg(work.path())
        .status()
        .context("git init for grok")?;
    if !init.success() {
        bail!("git init failed; the grok recording uses an empty work directory");
    }
    let cwd = fs::canonicalize(work.path()).context("canonicalize grok work directory")?;
    let cwd = cwd.to_str().context("grok work directory is not UTF-8")?;
    println!(
        "recording grok {} ({}) via {}={} forwarded to {}",
        grok_build::RELEASE,
        grok_build::VERSION_STAMP,
        upstream.base_env(),
        upstream.base_url(&proxy.base),
        upstream.origin()
    );
    let mut command = Command::new(&binary);
    command
        .current_dir(work.path())
        .env(upstream.base_env(), upstream.base_url(&proxy.base))
        .args(grok_build::exec_args(cwd, &model, &prompt));
    for name in upstream.suppressed_env() {
        command.env_remove(name);
    }
    let output = command.output().context("run official grok")?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let dir = recordings_dir()
        .join(grok_build::GROK_BUILD.id())
        .join(&scenario)
        .join(stamp.to_string());
    fs::create_dir_all(&dir)?;
    let dir = fs::canonicalize(&dir).context("canonicalize traffic recording")?;
    fs::write(dir.join("cli.stdout"), &output.stdout)?;
    fs::write(dir.join("cli.stderr"), &output.stderr)?;
    let exchanges = proxy.exchanges();
    fs::write(dir.join("raw.json"), serde_json::to_vec_pretty(&exchanges)?)?;
    if !output.status.success() {
        bail!(
            "grok exited {}. Raw capture, if any, is in {}. stderr was not copied into the repository.",
            output.status,
            dir.display()
        );
    }
    let fixture = grok_build::fixture_from_capture(&scenario, &exchanges)?;
    let fixture_path = dir.join("fixture.json");
    fs::write(&fixture_path, serde_json::to_vec_pretty(&fixture)?)?;
    println!(
        "recorded {} exchange(s) with the official grok {} CLI",
        exchanges.len(),
        grok_build::RELEASE
    );
    println!(
        "fixture kept {} generation exchange(s); calls that are not POST /v1/chat/completions or POST /v1/responses are omitted",
        fixture.exchanges.len()
    );
    println!("raw capture: {}", dir.join("raw.json").display());
    println!("scrubbed fixture: {}", fixture_path.display());
    println!(
        "Review it, then copy the fixture you want to keep into tests/traffic/grok-build/fixtures/{scenario}.json"
    );
    println!("Set provenance stays \"recorded\". Do not commit traffic-recordings/.");
    Ok(())
}

/// Session auth wins, matching grok's own precedence. The file is parsed only
/// for `auth_mode`. Its token is not printed and is not passed on the command line.
fn grok_upstream() -> Result<Upstream> {
    let class = match grok_auth_file() {
        Some(path) => {
            let bytes = fs::read(&path)
                .with_context(|| format!("read grok auth file {}", path.display()))?;
            let value: Value = serde_json::from_slice(&bytes).with_context(|| {
                format!("{} is not JSON. The file was not printed.", path.display())
            })?;
            grok_build::classify_auth(&value)
        }
        None => AuthClass::None,
    };
    let env_api_key = ["XAI_API_KEY", "GROK_CODE_XAI_API_KEY"]
        .into_iter()
        .any(|name| {
            std::env::var(name)
                .ok()
                .is_some_and(|value| !value.is_empty())
        });
    let upstream = grok_build::select_upstream(class, env_api_key)?;
    match upstream {
        Upstream::ChatProxy => println!(
            "grok session auth is active. Inference is recorded at https://cli-chat-proxy.grok.com. XAI_API_KEY is not the upstream while a session exists."
        ),
        Upstream::PublicApi => println!(
            "no grok session is active. API-key inference is recorded at https://api.x.ai. Set XAI_API_KEY, or store an api_key entry with `grok login`."
        ),
    }
    Ok(upstream)
}

fn grok_auth_file() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("GROK_AUTH_PATH") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
    }
    let root = std::env::var_os("GROK_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            let home = std::env::var_os("HOME")
                .or_else(|| std::env::var_os("USERPROFILE"))
                .map(PathBuf::from)?;
            Some(home.join(".grok"))
        })?;
    let path = root.join("auth.json");
    path.is_file().then_some(path)
}

async fn ensure_grok() -> Result<PathBuf> {
    let filename = grok_build::package_filename()?;
    let cache = grok_cli_cache_dir();
    fs::create_dir_all(&cache)?;
    let cache = fs::canonicalize(&cache).context("canonicalize grok CLI cache")?;
    let binary = cache.join(filename);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(600))
        .no_proxy()
        .build()?;
    if !binary.exists() {
        let bytes = client
            .get(grok_build::release_url(filename))
            .send()
            .await
            .with_context(|| format!("download {filename}"))?
            .error_for_status()
            .context("grok release status")?
            .bytes()
            .await?;
        grok_build::verify_artifact(filename, &bytes)?;
        fs::write(&binary, &bytes)?;
    } else {
        grok_build::verify_artifact(filename, &fs::read(&binary)?)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&binary)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&binary, permissions)?;
    }
    let binary = fs::canonicalize(&binary).context("canonicalize official grok")?;
    let version = Command::new(&binary)
        .arg("--version")
        .output()
        .context("run grok --version")?;
    let printed = String::from_utf8_lossy(&version.stdout);
    let errors = String::from_utf8_lossy(&version.stderr);
    let combined = format!("{printed}{errors}");
    if !version.status.success()
        || !combined.contains(grok_build::RELEASE)
        || !combined.contains(grok_build::VERSION_STAMP)
    {
        bail!(
            "official binary {} did not report grok {} ({}). stdout={printed} stderr={errors}",
            binary.display(),
            grok_build::RELEASE,
            grok_build::VERSION_STAMP
        );
    }
    println!(
        "using {} (grok {} {})",
        binary.display(),
        grok_build::RELEASE,
        grok_build::VERSION_STAMP
    );
    Ok(binary)
}

async fn ensure_cli() -> Result<PathBuf> {
    let filename = package_filename()?;
    let cache = cli_cache_dir();
    fs::create_dir_all(&cache)?;
    // `record` spawns this binary with `current_dir` set to a temp work dir.
    // Canonicalize so every caller receives a path that does not depend on that cwd.
    let cache = fs::canonicalize(&cache).context("canonicalize Codex CLI cache")?;
    let archive = cache.join(filename);
    let sums_path = cache.join(PACKAGE_SUMS_NAME);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(600))
        .no_proxy()
        .build()?;
    let sums = client
        .get(sums_url())
        .send()
        .await
        .context("download official checksum manifest")?
        .error_for_status()
        .context("checksum manifest status")?
        .text()
        .await?;
    verify_sums_manifest(&sums)?;
    fs::write(&sums_path, &sums)?;
    if !archive.exists() {
        let bytes = client
            .get(release_archive_url(filename))
            .send()
            .await
            .with_context(|| format!("download {filename}"))?
            .error_for_status()
            .context("release artifact status")?
            .bytes()
            .await?;
        verify_artifact(filename, &bytes)?;
        fs::write(&archive, &bytes)?;
    } else {
        verify_artifact(filename, &fs::read(&archive)?)?;
    }
    let extracted = cache.join(filename.trim_end_matches(".tar.gz"));
    if !extracted.exists() {
        fs::create_dir_all(&extracted)?;
        let status = Command::new("tar")
            .arg("-xzf")
            .arg(&archive)
            .arg("-C")
            .arg(&extracted)
            .status()
            .context("extract official archive with tar")?;
        if !status.success() {
            bail!("tar exited {status}");
        }
    }
    let binary =
        fs::canonicalize(find_binary(&extracted)?).context("canonicalize official codex")?;
    let version = Command::new(&binary)
        .arg("--version")
        .output()
        .context("run codex --version")?;
    let printed = String::from_utf8_lossy(&version.stdout);
    let errors = String::from_utf8_lossy(&version.stderr);
    if !version.status.success() || !printed.contains("0.169.0") && !errors.contains("0.169.0") {
        bail!(
            "official binary {} did not report {RELEASE}. stdout={printed} stderr={errors}",
            binary.display()
        );
    }
    println!("using {} ({RELEASE})", binary.display());
    Ok(binary)
}

/// `traffic-recordings/` next to this crate, not the process cwd and not a child cwd.
fn recordings_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("traffic-recordings")
}

/// Cache directory for the official package. Absolute, from [`recordings_dir`].
fn cli_cache_dir() -> PathBuf {
    recordings_dir().join("cache")
}

fn grok_cli_cache_dir() -> PathBuf {
    cli_cache_dir().join("grok-build")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_cache_dir_is_absolute() {
        let cache = cli_cache_dir();
        assert!(cache.is_absolute(), "{}", cache.display());
    }
}
