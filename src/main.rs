use anyhow::{Context, ensure};
use clap::{Args, Parser, Subcommand};
use infer::{
    config::Config,
    import::{
        self as local_import, DEFAULT_MAX_ARTIFACT_BYTES, DEFAULT_MAX_RECORD_BYTES,
        DEFAULT_MAX_SOURCES, DiscoveryOptions, DiscoveryScope, Harness, ImportOptions,
    },
    provider_export::{
        self, DEFAULT_MAX_COMPRESSION_RATIO, DEFAULT_MAX_CONVERSATIONS, DEFAULT_MAX_JSON_DEPTH,
        DEFAULT_MAX_MEMBER_BYTES, DEFAULT_MAX_MEMBERS, DEFAULT_MAX_TOTAL_BYTES, ProviderSelection,
    },
    proxy,
    trace::{MAX_SESSION_EVENT_BYTES, SessionEvent, TraceStore},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    str::FromStr,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
#[derive(Parser)]
#[command(
    version,
    about = "Streaming inference proxy with durable training traces"
)]
struct Cli {
    #[arg(short, long, default_value = "infer.toml", global = true)]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Validate configuration and credential availability without binding sockets.
    Check,
    /// Run inference and control HTTP listeners (the default).
    Serve,
    /// Import an OMP event spool; identical events already stored are skipped.
    ImportEvents {
        /// JSONL spool file written by the infer OMP extension.
        file: PathBuf,
    },
    /// Discover or import native local omp, Claude Code, Codex, and Grok Build traces.
    LocalTraces {
        #[command(subcommand)]
        command: LocalTraceCommand,
    },
    /// Import native ChatGPT, Claude, or Grok account export data.
    ProviderExports {
        #[command(subcommand)]
        command: ProviderExportCommand,
    },
}

#[derive(Subcommand)]
enum LocalTraceCommand {
    /// Report supported sources without importing records.
    Discover(LocalTraceSelection),
    /// Import selected native histories into trace_dir.
    Import(LocalTraceImport),
}

#[derive(Subcommand)]
enum ProviderExportCommand {
    /// Validate and import provider JSON or ZIP exports into trace_dir.
    Import(ProviderExportImport),
}

#[derive(Clone, Args)]
struct LocalTraceSelection {
    /// Harness to include; repeat for several. Default: all four.
    #[arg(long = "harness")]
    harnesses: Vec<String>,
    /// Override a discovery root as HARNESS=PATH; repeatable.
    #[arg(long = "root", value_name = "HARNESS=PATH")]
    roots: Vec<String>,
    /// Select one exact source as HARNESS=PATH; repeatable.
    #[arg(long = "source", value_name = "HARNESS=PATH")]
    sources: Vec<String>,
    /// Discovery scope: all, managed, or registered (OMP registry sources).
    #[arg(long, default_value = "all")]
    scope: String,
    /// Maximum discovered source files/directories.
    #[arg(long, default_value_t = DEFAULT_MAX_SOURCES)]
    max_sources: usize,
}

#[derive(Args)]
struct LocalTraceImport {
    #[command(flatten)]
    selection: LocalTraceSelection,
    /// Validate and count records without writing trace_dir.
    #[arg(long)]
    dry_run: bool,
    /// Maximum bytes in one JSONL/SQLite record.
    #[arg(long, default_value_t = DEFAULT_MAX_RECORD_BYTES)]
    max_record_bytes: usize,
    /// Maximum bytes in one opaque artifact.
    #[arg(long, default_value_t = DEFAULT_MAX_ARTIFACT_BYTES)]
    max_artifact_bytes: usize,
}

#[derive(Args)]
struct ProviderExportImport {
    /// Provider format or evidence-based automatic recognition.
    #[arg(long, default_value = "auto")]
    provider: String,
    /// Export JSON or ZIP path; repeat to process independent sources.
    #[arg(long, required = true)]
    source: Vec<PathBuf>,
    /// Explicit stable account/workspace scope used only for identity partitioning.
    #[arg(long)]
    account_scope: String,
    /// Validate and count records without creating trace_dir.
    #[arg(long)]
    dry_run: bool,
    /// Maximum ZIP member count.
    #[arg(long, default_value_t = DEFAULT_MAX_MEMBERS)]
    max_members: usize,
    /// Maximum decoded bytes in one ZIP member.
    #[arg(long, default_value_t = DEFAULT_MAX_MEMBER_BYTES)]
    max_member_bytes: u64,
    /// Maximum source JSON bytes or aggregate decoded ZIP bytes.
    #[arg(long, default_value_t = DEFAULT_MAX_TOTAL_BYTES)]
    max_total_bytes: u64,
    /// Maximum decoded-to-compressed ratio for one ZIP member.
    #[arg(long, default_value_t = DEFAULT_MAX_COMPRESSION_RATIO)]
    max_compression_ratio: u64,
    /// Maximum validated conversations in one source.
    #[arg(long, default_value_t = DEFAULT_MAX_CONVERSATIONS)]
    max_conversations: usize,
    /// Maximum JSON object/array nesting depth.
    #[arg(long, default_value_t = DEFAULT_MAX_JSON_DEPTH)]
    max_json_depth: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "infer=info".into()),
        )
        .init();
    let cli = Cli::parse();
    let config = Config::load(&cli.config).await?;
    match cli.command.unwrap_or(Command::Serve) {
        Command::Check => {
            proxy::validate_runtime(&config)?;
            println!("configuration valid");
            Ok(())
        }
        Command::Serve => proxy::serve(config).await,
        Command::ImportEvents { file } => {
            let file = tokio::fs::File::open(file)
                .await
                .context("opening session event spool")?;
            let mut reader = BufReader::new(file);
            let store = TraceStore::open(&config.trace_dir).await?;
            let mut line = Vec::new();
            let mut count = 0u64;
            loop {
                line.clear();
                // Bound each read even if a damaged spool has no newline.
                let read = (&mut reader)
                    .take(MAX_SESSION_EVENT_BYTES as u64 + 2)
                    .read_until(b'\n', &mut line)
                    .await?;
                if read == 0 {
                    break;
                }
                let record = line
                    .strip_suffix(b"\r\n")
                    .or_else(|| line.strip_suffix(b"\n"))
                    .unwrap_or(&line);
                ensure!(
                    record.len() <= MAX_SESSION_EVENT_BYTES,
                    "event on line {} exceeds 16 MiB",
                    count + 1
                );
                let event = SessionEvent::decode(&line)
                    .with_context(|| format!("decoding event on line {}", count + 1))?;
                store
                    .put_event(event)
                    .await
                    .with_context(|| format!("importing event on line {}", count + 1))?;
                count += 1;
            }
            println!("processed {count} events (identical existing events retained)");
            Ok(())
        }
        Command::LocalTraces { command } => match command {
            LocalTraceCommand::Discover(selection) => {
                let options = selection_options(&selection)?;
                let report = tokio::task::spawn_blocking(move || local_import::discover(&options))
                    .await
                    .context("local trace discovery worker failed")??;
                println!("{}", serde_json::to_string_pretty(&report)?);
                Ok(())
            }
            LocalTraceCommand::Import(arguments) => {
                let discovery_options = selection_options(&arguments.selection)?;
                let discovery =
                    tokio::task::spawn_blocking(move || local_import::discover(&discovery_options))
                        .await
                        .context("local trace discovery worker failed")??;
                let options = ImportOptions {
                    max_record_bytes: arguments.max_record_bytes,
                    max_artifact_bytes: arguments.max_artifact_bytes,
                    dry_run: arguments.dry_run,
                };
                let report = if arguments.dry_run {
                    local_import::dry_run_sources(&discovery, &options).await?
                } else {
                    let store = TraceStore::open(&config.trace_dir).await?;
                    local_import::import_sources(&store, &discovery, &options).await?
                };
                println!("{}", serde_json::to_string_pretty(&report)?);
                ensure!(
                    report.failures.is_empty(),
                    "{} source(s) failed; accepted earlier snapshots remain replay-safe",
                    report.failures.len()
                );
                Ok(())
            }
        },
        Command::ProviderExports { command } => match command {
            ProviderExportCommand::Import(arguments) => {
                let options = provider_export::ImportOptions {
                    dry_run: arguments.dry_run,
                    max_members: arguments.max_members,
                    max_member_bytes: arguments.max_member_bytes,
                    max_total_bytes: arguments.max_total_bytes,
                    max_compression_ratio: arguments.max_compression_ratio,
                    max_conversations: arguments.max_conversations,
                    max_json_depth: arguments.max_json_depth,
                };
                let selection = ProviderSelection::from_str(&arguments.provider)?;
                let store = if arguments.dry_run {
                    None
                } else {
                    Some(TraceStore::open(&config.trace_dir).await?)
                };
                let report = provider_export::import_sources(
                    store.as_ref(),
                    &arguments.source,
                    selection,
                    &arguments.account_scope,
                    &options,
                )
                .await?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                ensure!(
                    report.failures.is_empty(),
                    "{} source(s) failed; accepted earlier snapshots remain replay-safe",
                    report.failures.len()
                );
                Ok(())
            }
        },
    }
}

fn selection_options(selection: &LocalTraceSelection) -> anyhow::Result<DiscoveryOptions> {
    let harnesses = if selection.harnesses.is_empty()
        || selection.harnesses.iter().any(|value| value == "all")
    {
        Harness::ALL.into_iter().collect()
    } else {
        selection
            .harnesses
            .iter()
            .map(|value| Harness::from_str(value))
            .collect::<anyhow::Result<BTreeSet<_>>>()?
    };
    let mut roots = BTreeMap::new();
    for value in &selection.roots {
        let (harness, path) = harness_path(value)?;
        roots.entry(harness).or_insert_with(Vec::new).push(path);
    }
    let sources = selection
        .sources
        .iter()
        .map(|value| harness_path(value))
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(DiscoveryOptions {
        harnesses,
        roots,
        sources,
        scope: DiscoveryScope::from_str(&selection.scope)?,
        max_sources: selection.max_sources,
    })
}

fn harness_path(value: &str) -> anyhow::Result<(Harness, PathBuf)> {
    let (harness, path) = value.split_once('=').context("expected HARNESS=PATH")?;
    ensure!(!path.is_empty(), "source/root path must not be empty");
    Ok((Harness::from_str(harness)?, PathBuf::from(path)))
}
