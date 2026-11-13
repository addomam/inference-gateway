//! Manual Codex traffic recorder. Never invoked by tests or CI.
//!
//! Downloads the official rust-v0.169.0 package, checks it against the pinned
//! SHA-256 manifest, and runs that binary through a local recording proxy.
//! Raw captures stay in `traffic-recordings/` (gitignored). The scrubbed
//! fixture is written next to the raw capture for review; it is not copied
//! into `tests/traffic` automatically.

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
use infer::traffic::{CapturedExchange, Harness, RecordingProxy, assert_clean};

#[derive(Parser)]
#[command(name = "traffic-record", about = "Record official Codex CLI traffic")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run one Codex exec turn against chatgpt.com through the recording proxy.
    Record {
        /// Fixture scenario name, for example chat-turn.
        #[arg(long)]
        scenario: String,
        /// Model slug the CLI should request.
        #[arg(long, default_value = "gpt-5.5")]
        model: String,
        /// User prompt for `codex exec`.
        #[arg(long, default_value = "Say hello in one word.")]
        prompt: String,
    },
    /// Rewrite a raw capture into a scrubbed fixture JSON file.
    Scrub {
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
            scenario,
            model,
            prompt,
        } => record(scenario, model, prompt).await,
        Commands::Scrub { raw, out, scenario } => scrub_file(&raw, &out, &scenario),
        Commands::Check { fixtures } => assert_clean(&fixtures),
    }
}

async fn record(scenario: String, model: String, prompt: String) -> Result<()> {
    if scenario.contains('/') || scenario.contains("..") {
        bail!("scenario name must be a single path segment");
    }
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
    let dir = PathBuf::from("traffic-recordings")
        .join(codex::CODEX.id())
        .join(&scenario)
        .join(stamp.to_string());
    fs::create_dir_all(&dir)?;
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
    println!("raw capture: {}", dir.join("raw.json").display());
    println!("scrubbed fixture: {}", fixture_path.display());
    println!(
        "Review it, then copy the fixture you want to keep into tests/traffic/codex/fixtures/{scenario}.json"
    );
    println!("Set provenance stays \"recorded\". Do not commit traffic-recordings/.");
    Ok(())
}

fn scrub_file(raw: &Path, out: &Path, scenario: &str) -> Result<()> {
    let exchanges: Vec<CapturedExchange> =
        serde_json::from_slice(&fs::read(raw).with_context(|| format!("read {}", raw.display()))?)?;
    let fixture = fixture_from_capture(scenario, &exchanges)?;
    if let Some(parent) = out.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(out, serde_json::to_vec_pretty(&fixture)?)?;
    println!("wrote {}", out.display());
    Ok(())
}

async fn ensure_cli() -> Result<PathBuf> {
    let filename = package_filename()?;
    let cache = PathBuf::from("traffic-recordings").join("cache");
    fs::create_dir_all(&cache)?;
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
    let binary = find_binary(&extracted)?;
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
