//! Read-only discovery and lossless import of native local harness histories.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs::{self, File},
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{SecondsFormat, TimeZone, Utc};
use rusqlite::{Connection, OpenFlags, types::ValueRef};
use serde::Serialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::trace::{ImportAcquisition, ImportRaw, ImportSnapshot, TraceStore};

pub const DEFAULT_MAX_RECORD_BYTES: usize = 256 * 1024 * 1024;
pub const DEFAULT_MAX_ARTIFACT_BYTES: usize = 1024 * 1024 * 1024;
pub const DEFAULT_MAX_SOURCES: usize = 100_000;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Harness {
    Omp,
    ClaudeCode,
    Codex,
    GrokBuild,
}

impl Harness {
    pub const ALL: [Self; 4] = [Self::Omp, Self::ClaudeCode, Self::Codex, Self::GrokBuild];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Omp => "omp",
            Self::ClaudeCode => "claude_code",
            Self::Codex => "codex",
            Self::GrokBuild => "grok_build",
        }
    }
}

impl FromStr for Harness {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "omp" => Ok(Self::Omp),
            "claude" | "claude_code" | "claude-code" => Ok(Self::ClaudeCode),
            "codex" => Ok(Self::Codex),
            "grok" | "grok_build" | "grok-build" => Ok(Self::GrokBuild),
            _ => bail!("unknown harness {value}; expected omp, claude_code, codex, or grok_build"),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DiscoveryScope {
    #[default]
    All,
    Managed,
    Registered,
}

impl FromStr for DiscoveryScope {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "all" => Ok(Self::All),
            "managed" => Ok(Self::Managed),
            "registered" => Ok(Self::Registered),
            _ => bail!("unknown scope {value}; expected all, managed, or registered"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Jsonl,
    ZstdJsonl,
    CodexStateDb,
    CodexHistoryDb,
    GrokSession,
}

#[derive(Clone, Debug, Serialize)]
pub struct DiscoveredSource {
    pub harness: Harness,
    pub kind: SourceKind,
    pub path: PathBuf,
    pub source_namespace: String,
    pub size: Option<u64>,
    pub origin: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct DiscoveryReport {
    pub sources: Vec<DiscoveredSource>,
    pub skipped_symlinks: u64,
    pub missing_roots: Vec<PathBuf>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct DiscoveryOptions {
    pub harnesses: BTreeSet<Harness>,
    pub roots: BTreeMap<Harness, Vec<PathBuf>>,
    pub sources: Vec<(Harness, PathBuf)>,
    pub scope: DiscoveryScope,
    pub max_sources: usize,
}

impl Default for DiscoveryOptions {
    fn default() -> Self {
        Self {
            harnesses: Harness::ALL.into_iter().collect(),
            roots: BTreeMap::new(),
            sources: Vec::new(),
            scope: DiscoveryScope::All,
            max_sources: DEFAULT_MAX_SOURCES,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ImportOptions {
    pub max_record_bytes: usize,
    pub max_artifact_bytes: usize,
    pub dry_run: bool,
}

impl Default for ImportOptions {
    fn default() -> Self {
        Self {
            max_record_bytes: DEFAULT_MAX_RECORD_BYTES,
            max_artifact_bytes: DEFAULT_MAX_ARTIFACT_BYTES,
            dry_run: false,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ImportReport {
    pub sources: u64,
    pub records_seen: u64,
    pub imported: u64,
    pub already_present: u64,
    pub malformed_records: u64,
    pub deferred_incomplete_tails: u64,
    pub artifacts: u64,
    pub failures: Vec<ImportFailure>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ImportFailure {
    pub harness: Harness,
    pub path: PathBuf,
    pub error: String,
}

struct SourceCollector {
    report: DiscoveryReport,
    seen: BTreeSet<(Harness, PathBuf)>,
    max_sources: usize,
}

pub fn discover(options: &DiscoveryOptions) -> Result<DiscoveryReport> {
    ensure!(options.max_sources > 0, "max_sources must be positive");
    let mut collector = SourceCollector {
        report: DiscoveryReport::default(),
        seen: BTreeSet::new(),
        max_sources: options.max_sources,
    };
    for harness in &options.harnesses {
        let roots = options
            .roots
            .get(harness)
            .cloned()
            .unwrap_or_else(|| default_roots(*harness));
        for root in roots {
            if !root.exists() {
                collector.report.missing_roots.push(root);
                continue;
            }
            scan_root(*harness, &root, options.scope, &mut collector)?;
        }
    }
    // An explicit selection adds sources without changing the namespace of a
    // source already owned by a selected root or OMP registry.
    for &(harness, ref path) in &options.sources {
        if !options.harnesses.contains(&harness) {
            continue;
        }
        add_explicit_source(harness, path, &mut collector)?;
    }
    let mut report = collector.report;
    report.sources.sort_by(|a, b| {
        (a.harness, &a.path, a.kind as u8).cmp(&(b.harness, &b.path, b.kind as u8))
    });
    ensure!(
        report.sources.len() <= options.max_sources,
        "discovery exceeded {} sources",
        options.max_sources
    );
    Ok(report)
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn default_roots(harness: Harness) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let home = home_dir();
    match harness {
        Harness::Omp => {
            if let Some(config) = std::env::var_os("PI_CONFIG_DIR") {
                roots.push(PathBuf::from(config));
            }
            if let Some(agent) = std::env::var_os("PI_CODING_AGENT_DIR") {
                roots.push(PathBuf::from(agent));
            }
            if let Some(home) = home {
                roots.push(home.join(".omp"));
                if let Some(data) = std::env::var_os("XDG_DATA_HOME") {
                    roots.push(PathBuf::from(data).join("omp"));
                }
                if let Some(state) = std::env::var_os("XDG_STATE_HOME") {
                    roots.push(PathBuf::from(state).join("omp"));
                }
            }
        }
        Harness::ClaudeCode => {
            if let Some(root) = std::env::var_os("CLAUDE_CONFIG_DIR") {
                roots.push(PathBuf::from(root));
            } else if let Some(home) = home {
                roots.push(home.join(".claude"));
            }
        }
        Harness::Codex => {
            let codex_home = std::env::var_os("CODEX_HOME")
                .map(PathBuf::from)
                .or_else(|| home.as_ref().map(|home| home.join(".codex")));
            if let Some(root) = &codex_home {
                roots.push(root.clone());
            }
            if let Some(root) = std::env::var_os("CODEX_SQLITE_HOME") {
                roots.push(PathBuf::from(root));
            } else if let Some(root) = codex_home.as_deref().and_then(configured_codex_sqlite_home)
            {
                roots.push(root);
            }
        }
        Harness::GrokBuild => {
            if let Some(root) = std::env::var_os("GROK_HOME") {
                roots.push(PathBuf::from(root));
            } else if let Some(home) = home {
                roots.push(home.join(".grok"));
            }
        }
    }
    roots.sort();
    roots.dedup();
    roots
}

fn configured_codex_sqlite_home(codex_home: &Path) -> Option<PathBuf> {
    let config = codex_home.join("config.toml");
    let metadata = fs::symlink_metadata(&config).ok()?;
    if !metadata.file_type().is_file() || metadata.len() > 1024 * 1024 {
        return None;
    }
    let value = fs::read_to_string(config)
        .ok()?
        .parse::<toml::Value>()
        .ok()?;
    let configured = PathBuf::from(value.get("sqlite_home")?.as_str()?);
    Some(if configured.is_absolute() {
        configured
    } else {
        codex_home.join(configured)
    })
}

fn add_explicit_source(
    harness: Harness,
    path: &Path,
    collector: &mut SourceCollector,
) -> Result<()> {
    let metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "inspect explicit {} source {}",
            harness.as_str(),
            path.display()
        )
    })?;
    ensure!(
        !metadata.file_type().is_symlink(),
        "explicit source must not be a symlink"
    );
    let canonical = path.canonicalize().context("resolve explicit source")?;
    let kind = classify_source(harness, &canonical, &metadata)?;
    let namespace_root = canonical.parent().unwrap_or(&canonical).to_owned();
    push_source(
        harness,
        kind,
        canonical,
        &namespace_root,
        "explicit",
        collector,
    )
}

fn scan_root(
    harness: Harness,
    root: &Path,
    scope: DiscoveryScope,
    collector: &mut SourceCollector,
) -> Result<()> {
    let max_sources = collector.max_sources;
    let metadata = fs::symlink_metadata(root)?;
    if metadata.file_type().is_symlink() {
        collector.report.skipped_symlinks += 1;
        return Ok(());
    }
    let canonical_root = root.canonicalize().context("resolve discovery root")?;
    let mut queue = VecDeque::from([(canonical_root.clone(), 0usize)]);
    if scope != DiscoveryScope::Registered {
        while let Some((directory, depth)) = queue.pop_front() {
            ensure!(
                depth <= 16,
                "discovery nesting exceeds 16 levels at {}",
                directory.display()
            );
            for entry in fs::read_dir(&directory)
                .with_context(|| format!("read discovery directory {}", directory.display()))?
            {
                let entry = entry?;
                let path = entry.path();
                let metadata = fs::symlink_metadata(&path)?;
                if metadata.file_type().is_symlink() {
                    collector.report.skipped_symlinks += 1;
                    continue;
                }
                if metadata.is_dir() {
                    if harness == Harness::GrokBuild
                        && (path.join("summary.json").is_file()
                            || path.join("updates.jsonl").is_file())
                    {
                        push_source(
                            harness,
                            SourceKind::GrokSession,
                            path,
                            &canonical_root,
                            "root",
                            collector,
                        )?;
                    } else {
                        queue.push_back((path, depth + 1));
                    }
                    continue;
                }
                if !metadata.is_file() {
                    continue;
                }
                if let Some(kind) = classify_file(harness, &path)
                    && eligible_discovered_file(harness, &canonical_root, &path)?
                {
                    push_source(harness, kind, path, &canonical_root, "root", collector)?;
                }
                ensure!(
                    collector.report.sources.len() <= max_sources,
                    "discovery exceeded {max_sources} sources"
                );
            }
        }
    }
    if harness == Harness::Omp && scope != DiscoveryScope::Managed {
        discover_omp_registry(&canonical_root, collector)?;
    }
    if harness == Harness::Codex && scope == DiscoveryScope::All {
        discover_codex_rollout_paths(&canonical_root, collector)?;
    }
    Ok(())
}

fn eligible_discovered_file(harness: Harness, root: &Path, path: &Path) -> Result<bool> {
    let contains = |name: &str| {
        root.file_name().and_then(|value| value.to_str()) == Some(name)
            || path
                .strip_prefix(root)
                .ok()
                .is_some_and(|relative| relative.components().any(|part| part.as_os_str() == name))
    };
    Ok(match harness {
        Harness::Omp => contains("sessions") && omp_has_session_header(path)?,
        Harness::ClaudeCode => {
            contains("projects")
                || std::env::var_os("CLAUDE_CODE_PROJECT_DIR_NAME").is_some_and(|configured| {
                    let configured = PathBuf::from(configured);
                    root.ends_with(&configured)
                        || path
                            .strip_prefix(root)
                            .is_ok_and(|relative| relative.starts_with(&configured))
                })
        }
        Harness::Codex => {
            let supported_location = path.extension().and_then(|value| value.to_str())
                == Some("sqlite")
                || contains("sessions")
                || contains("archived_sessions");
            let compressed_has_plain_sibling = path
                .to_str()
                .is_some_and(|path| path.ends_with(".jsonl.zst"))
                && is_regular_file(&path.with_extension(""));
            supported_location && !compressed_has_plain_sibling
        }
        Harness::GrokBuild => false,
    })
}

fn omp_has_session_header(path: &Path) -> Result<bool> {
    let mut reader = BufReader::new(open_regular_file(path)?);
    let mut line = Vec::new();
    for _ in 0..3 {
        line.clear();
        if read_bounded_line(&mut reader, &mut line, 1024 * 1024)? == 0 {
            break;
        }
        trim_newline(&mut line);
        if let Ok(value) = crate::json::from_slice(&line)
            && value.get("type").and_then(Value::as_str) == Some("session")
            && value.get("id").and_then(Value::as_str).is_some()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn classify_source(harness: Harness, path: &Path, metadata: &fs::Metadata) -> Result<SourceKind> {
    if metadata.is_dir() && harness == Harness::GrokBuild {
        return Ok(SourceKind::GrokSession);
    }
    let kind =
        classify_file(harness, path).context("explicit path is not a supported source type")?;
    if harness == Harness::Omp {
        ensure!(
            omp_has_session_header(path)?,
            "OMP source has no native session header"
        );
    }
    Ok(kind)
}

fn classify_file(harness: Harness, path: &Path) -> Option<SourceKind> {
    let name = path.file_name()?.to_str()?;
    match harness {
        Harness::Omp | Harness::ClaudeCode => name.ends_with(".jsonl").then_some(SourceKind::Jsonl),
        Harness::Codex if name.starts_with("state_") && name.ends_with(".sqlite") => {
            Some(SourceKind::CodexStateDb)
        }
        Harness::Codex if name.starts_with("thread_history_") && name.ends_with(".sqlite") => {
            Some(SourceKind::CodexHistoryDb)
        }
        Harness::Codex if name.ends_with(".jsonl.zst") => Some(SourceKind::ZstdJsonl),
        Harness::Codex if name.ends_with(".jsonl") => Some(SourceKind::Jsonl),
        _ => None,
    }
}

fn push_source(
    harness: Harness,
    kind: SourceKind,
    path: PathBuf,
    namespace_root: &Path,
    origin: &str,
    collector: &mut SourceCollector,
) -> Result<()> {
    let metadata = fs::symlink_metadata(&path)?;
    ensure!(!metadata.file_type().is_symlink(), "source is a symlink");
    let canonical = path.canonicalize().context("resolve discovered source")?;
    if collector.seen.contains(&(harness, canonical.clone())) {
        return Ok(());
    }
    ensure!(
        collector.report.sources.len() < collector.max_sources,
        "discovery exceeded {} sources",
        collector.max_sources
    );
    collector.seen.insert((harness, canonical.clone()));
    let source_namespace = format!(
        "{}:{}",
        harness.as_str(),
        hex_digest(namespace_root.as_os_str().as_encoded_bytes())
    );
    collector.report.sources.push(DiscoveredSource {
        harness,
        kind,
        path: canonical,
        source_namespace,
        size: metadata.is_file().then_some(metadata.len()),
        origin: origin.to_owned(),
    });
    Ok(())
}

fn discover_omp_registry(root: &Path, collector: &mut SourceCollector) -> Result<()> {
    let mut queue = VecDeque::from([(root.to_owned(), 0usize)]);
    while let Some((directory, depth)) = queue.pop_front() {
        ensure!(depth <= 16, "OMP registry nesting exceeds 16 levels");
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                if path.file_name().and_then(|name| name.to_str()) == Some("custom-session-files") {
                    for marker in fs::read_dir(&path)? {
                        let marker = marker?.path();
                        let metadata = fs::symlink_metadata(&marker)?;
                        if !metadata.is_file() || metadata.len() > 4096 {
                            continue;
                        }
                        let registered = fs::read_to_string(&marker)?;
                        let registered = PathBuf::from(registered.trim());
                        let regular = is_regular_file(&registered);
                        if registered.is_absolute()
                            && regular
                            && omp_has_session_header(&registered)?
                        {
                            push_source(
                                Harness::Omp,
                                SourceKind::Jsonl,
                                registered,
                                root,
                                "omp_registry",
                                collector,
                            )?;
                        } else if registered.exists() {
                            collector.report.warnings.push(format!(
                                "OMP registry entry is not a supported transcript: {}",
                                registered.display()
                            ));
                        }
                    }
                } else {
                    queue.push_back((path, depth + 1));
                }
            }
        }
    }
    Ok(())
}

fn discover_codex_rollout_paths(root: &Path, collector: &mut SourceCollector) -> Result<()> {
    for source in collector.report.sources.clone() {
        if source.harness != Harness::Codex || source.kind != SourceKind::CodexStateDb {
            continue;
        }
        let connection = open_sqlite_read_only(&source.path)?;
        if !table_exists(&connection, "threads")? {
            continue;
        }
        let mut statement = connection
            .prepare("SELECT rollout_path FROM threads WHERE rollout_path IS NOT NULL")?;
        let paths = statement.query_map([], |row| row.get::<_, String>(0))?;
        for path in paths {
            let path = PathBuf::from(path?);
            if !path.is_file() {
                continue;
            }
            if fs::symlink_metadata(&path)?.file_type().is_symlink() {
                collector
                    .report
                    .warnings
                    .push("Codex DB rollout symlink was not followed".to_owned());
                continue;
            }
            let canonical = path
                .canonicalize()
                .context("resolve Codex DB rollout path")?;
            if canonical.starts_with(root)
                || source
                    .path
                    .parent()
                    .is_some_and(|parent| canonical.starts_with(parent))
            {
                if let Some(kind) = classify_file(Harness::Codex, &canonical) {
                    push_source(
                        Harness::Codex,
                        kind,
                        canonical,
                        root,
                        "codex_state_db",
                        collector,
                    )?;
                }
            } else {
                collector.report.warnings.push(
                    "Codex DB rollout path outside selected roots was not followed".to_owned(),
                );
            }
        }
    }
    Ok(())
}

pub async fn import_sources(
    store: &TraceStore,
    discovery: &DiscoveryReport,
    options: &ImportOptions,
) -> Result<ImportReport> {
    process_sources(Some(store), discovery, options).await
}

pub async fn dry_run_sources(
    discovery: &DiscoveryReport,
    options: &ImportOptions,
) -> Result<ImportReport> {
    ensure!(options.dry_run, "dry-run options must enable dry_run");
    process_sources(None, discovery, options).await
}

async fn process_sources(
    store: Option<&TraceStore>,
    discovery: &DiscoveryReport,
    options: &ImportOptions,
) -> Result<ImportReport> {
    ensure!(
        options.max_record_bytes > 0,
        "max_record_bytes must be positive"
    );
    ensure!(
        options.max_artifact_bytes > 0,
        "max_artifact_bytes must be positive"
    );
    let mut report = ImportReport::default();
    for source in &discovery.sources {
        report.sources += 1;
        let result = match source.kind {
            SourceKind::Jsonl | SourceKind::ZstdJsonl => {
                import_jsonl(store, source, options, &mut report).await
            }
            SourceKind::CodexStateDb | SourceKind::CodexHistoryDb => {
                import_codex_sqlite(store, source, options, &mut report).await
            }
            SourceKind::GrokSession => {
                import_grok_session(store, source, options, &mut report).await
            }
        };
        if let Err(error) = result {
            report.failures.push(ImportFailure {
                harness: source.harness,
                path: source.path.clone(),
                error: format!("{error:#}"),
            });
        }
    }
    Ok(report)
}

async fn import_jsonl(
    store: Option<&TraceStore>,
    source: &DiscoveredSource,
    options: &ImportOptions,
    report: &mut ImportReport,
) -> Result<()> {
    let (session_id, high_water) = inspect_jsonl_owner(source, options.max_record_bytes)?;
    let file = open_regular_file(&source.path)?;
    let reader: Box<dyn BufRead> = if source.kind == SourceKind::ZstdJsonl {
        Box::new(BufReader::new(zstd::stream::read::Decoder::new(file)?))
    } else {
        Box::new(BufReader::new(file.take(high_water)))
    };
    // Archival compression changes filenames, not the native rollout stream.
    let stream_name = (source.harness == Harness::Codex).then_some("rollout");
    import_line_reader(
        store,
        source,
        options,
        report,
        &session_id,
        stream_name,
        reader,
    )
    .await?;
    if source.kind == SourceKind::Jsonl {
        let after = fs::metadata(&source.path)?.len();
        ensure!(
            after >= high_water,
            "source was truncated during import; accepted prefix remains durable"
        );
    }
    if source.harness == Harness::Omp {
        import_omp_companions(store, source, options, report, &session_id).await?;
        import_omp_blobs(store, source, options, report, &session_id).await?;
    }
    Ok(())
}

fn inspect_jsonl_owner(
    source: &DiscoveredSource,
    max_record_bytes: usize,
) -> Result<(String, u64)> {
    let metadata = fs::metadata(&source.path)?;
    let high_water = metadata.len();
    let file = open_regular_file(&source.path)?;
    let mut reader: Box<dyn BufRead> = if source.kind == SourceKind::ZstdJsonl {
        Box::new(BufReader::new(zstd::stream::read::Decoder::new(file)?))
    } else {
        Box::new(BufReader::new(file.take(high_water)))
    };
    let mut line = Vec::new();
    let mut fallback = None;
    for _ in 0..256 {
        line.clear();
        let read = read_bounded_line(&mut reader, &mut line, max_record_bytes)?;
        if read == 0 {
            break;
        }
        trim_newline(&mut line);
        let Ok(value) = crate::json::from_slice(&line) else {
            continue;
        };
        fallback.get_or_insert_with(|| fallback_session_id(source, &value));
        if let Some(id) = native_session_id(source.harness, &value) {
            return Ok((id, high_water));
        }
    }
    Ok((
        fallback.unwrap_or_else(|| fallback_path_identity(&source.path)),
        high_water,
    ))
}

async fn import_line_reader(
    store: Option<&TraceStore>,
    source: &DiscoveredSource,
    options: &ImportOptions,
    report: &mut ImportReport,
    session_id: &str,
    stream_name: Option<&str>,
    mut reader: Box<dyn BufRead>,
) -> Result<()> {
    let mut line = Vec::new();
    let mut index = 0u64;
    loop {
        line.clear();
        let read = read_bounded_line(&mut reader, &mut line, options.max_record_bytes)?;
        if read == 0 {
            break;
        }
        index += 1;
        let terminated = trim_newline(&mut line);
        let parsed = crate::json::from_slice(&line);
        if !terminated && parsed.is_err() {
            report.deferred_incomplete_tails += 1;
            break;
        }
        let (native, parse_status) = match parsed {
            Ok(value) => (Some(value), "valid_json"),
            Err(_) => {
                report.malformed_records += 1;
                (None, "malformed_completed_record")
            }
        };
        let position = format!("line:{index}");
        let native_record_id = native
            .as_ref()
            .and_then(|value| native_record_id(source.harness, value))
            .unwrap_or_else(|| position.clone());
        let occurred_at = native
            .as_ref()
            .and_then(|value| native_timestamp(source.harness, value));
        let format = match source.kind {
            SourceKind::ZstdJsonl => "jsonl.zst",
            _ => "jsonl",
        };
        let raw = std::mem::take(&mut line);
        import_snapshot(
            store,
            source,
            options,
            report,
            SnapshotParts {
                session_id: session_id.to_owned(),
                stream: stream_name
                    .or_else(|| source.path.file_name().and_then(|name| name.to_str()))
                    .unwrap_or("jsonl")
                    .to_owned(),
                record_id: native_record_id,
                format: format.to_owned(),
                position,
                occurred_at,
                parse_status: parse_status.to_owned(),
                native,
                raw: ImportRaw::Bytes(raw),
                path: source.path.clone(),
                artifact_only: false,
            },
        )
        .await?;
    }
    Ok(())
}

struct SnapshotParts {
    session_id: String,
    stream: String,
    record_id: String,
    format: String,
    position: String,
    occurred_at: Option<String>,
    parse_status: String,
    native: Option<Value>,
    raw: ImportRaw,
    path: PathBuf,
    artifact_only: bool,
}

async fn import_snapshot(
    store: Option<&TraceStore>,
    source: &DiscoveredSource,
    options: &ImportOptions,
    report: &mut ImportReport,
    parts: SnapshotParts,
) -> Result<()> {
    report.records_seen += 1;
    let raw_len = match &parts.raw {
        ImportRaw::Bytes(bytes) => u64::try_from(bytes.len())?,
        ImportRaw::File { path, .. } => {
            let metadata = fs::symlink_metadata(path)?;
            ensure!(
                metadata.file_type().is_file(),
                "artifact must be a regular file, not a symlink"
            );
            metadata.len()
        }
    };
    ensure!(
        raw_len <= options.max_artifact_bytes as u64,
        "artifact exceeds configured {} byte limit",
        options.max_artifact_bytes
    );
    if options.dry_run {
        return Ok(());
    }
    let store = store.context("trace store is required unless dry_run is enabled")?;
    let receipt = store
        .put_import_snapshot(ImportSnapshot {
            adapter: source.harness.as_str().to_owned(),
            event_source: format!("local_{}", source.harness.as_str()),
            payload_schema: "infer.local_trace.v1".to_owned(),
            source_namespace: source.source_namespace.clone(),
            native_session_id: parts.session_id,
            stream: parts.stream,
            native_record_id: parts.record_id,
            format: parts.format,
            position: parts.position.clone(),
            occurred_at: parts.occurred_at,
            parse_status: parts.parse_status,
            native: parts.native,
            raw: parts.raw,
            acquisition: ImportAcquisition {
                source_path: parts.path.to_string_lossy().into_owned(),
                source_digest: None,
                member_path: None,
                position: Some(parts.position),
            },
        })
        .await?;
    if receipt["imported"].as_bool() == Some(true) {
        report.imported += 1;
        if parts.artifact_only {
            report.artifacts += 1;
        }
    } else {
        report.already_present += 1;
    }
    Ok(())
}

async fn import_grok_session(
    store: Option<&TraceStore>,
    source: &DiscoveredSource,
    options: &ImportOptions,
    report: &mut ImportReport,
) -> Result<()> {
    let session_id = grok_session_id(&source.path, options.max_record_bytes)?;
    let updates = source.path.join("updates.jsonl");
    if is_regular_file(&updates) {
        let child = source_for_path(source, updates, SourceKind::Jsonl)?;
        let high_water = fs::metadata(&child.path)?.len();
        let reader = Box::new(BufReader::new(
            open_regular_file(&child.path)?.take(high_water),
        ));
        import_line_reader(
            store,
            &child,
            options,
            report,
            &session_id,
            Some("updates.jsonl"),
            reader,
        )
        .await?;
    }
    for path in walk_regular_files(&source.path, 16)? {
        if path == source.path.join("updates.jsonl") {
            continue;
        }
        let relative = path
            .strip_prefix(&source.path)
            .context("Grok artifact escaped session")?;
        if is_credential_name(relative) {
            continue;
        }
        if path.extension().and_then(|value| value.to_str()) == Some("jsonl") {
            let child = source_for_path(source, path.clone(), SourceKind::Jsonl)?;
            let high_water = fs::metadata(&path)?.len();
            let reader = Box::new(BufReader::new(open_regular_file(&path)?.take(high_water)));
            import_line_reader(
                store,
                &child,
                options,
                report,
                &session_id,
                Some(&relative.to_string_lossy()),
                reader,
            )
            .await?;
        } else {
            import_companion_file(store, source, options, report, &session_id, &path, relative)
                .await?;
        }
    }
    Ok(())
}

fn grok_session_id(path: &Path, max_record_bytes: usize) -> Result<String> {
    let summary = path.join("summary.json");
    if is_regular_file(&summary) {
        let owner_limit = max_record_bytes.min(1024 * 1024);
        if fs::metadata(&summary)?.len() <= owner_limit as u64 {
            let bytes = read_bounded_file(&summary, owner_limit)?;
            if let Ok(value) = crate::json::from_slice(&bytes)
                && let Some(id) = value.pointer("/info/id").and_then(Value::as_str)
            {
                return Ok(id.to_owned());
            }
        }
    }
    let updates = path.join("updates.jsonl");
    if is_regular_file(&updates) {
        let source = DiscoveredSource {
            harness: Harness::GrokBuild,
            kind: SourceKind::Jsonl,
            path: updates,
            source_namespace: String::new(),
            size: None,
            origin: String::new(),
        };
        return inspect_jsonl_owner(&source, max_record_bytes).map(|result| result.0);
    }
    Ok(fallback_path_identity(path))
}

async fn import_omp_companions(
    store: Option<&TraceStore>,
    source: &DiscoveredSource,
    options: &ImportOptions,
    report: &mut ImportReport,
    session_id: &str,
) -> Result<()> {
    let Some(stem) = source.path.file_stem() else {
        return Ok(());
    };
    let directory = source.path.with_file_name(stem);
    if !is_real_directory(&directory) {
        return Ok(());
    }
    for path in walk_regular_files(&directory, 16)? {
        if path.extension().and_then(|value| value.to_str()) == Some("jsonl") {
            continue;
        }
        let relative = path.strip_prefix(&directory)?;
        import_companion_file(store, source, options, report, session_id, &path, relative).await?;
    }
    Ok(())
}

async fn import_omp_blobs(
    store: Option<&TraceStore>,
    source: &DiscoveredSource,
    options: &ImportOptions,
    report: &mut ImportReport,
    session_id: &str,
) -> Result<()> {
    let mut references = BTreeSet::new();
    let high_water = fs::metadata(&source.path)?.len();
    let mut reader = BufReader::new(open_regular_file(&source.path)?.take(high_water));
    let mut line = Vec::new();
    loop {
        line.clear();
        if read_bounded_line(&mut reader, &mut line, options.max_record_bytes)? == 0 {
            break;
        }
        trim_newline(&mut line);
        if let Ok(value) = crate::json::from_slice(&line) {
            collect_omp_blob_references(&value, &mut references);
        }
    }
    let agent_root = source
        .path
        .ancestors()
        .find(|path| path.file_name().and_then(|name| name.to_str()) == Some("sessions"))
        .and_then(Path::parent);
    for digest in references {
        let found = agent_root.and_then(|root| {
            [
                root.join("blobs").join(&digest),
                root.join("blobs/sha256").join(&digest),
            ]
            .into_iter()
            .find(|path| {
                fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_file())
            })
        });
        if let Some(path) = found {
            ensure!(
                hash_regular_file(&path, options.max_artifact_bytes)? == digest,
                "OMP blob bytes do not match referenced SHA-256 digest"
            );
            let relative = PathBuf::from(format!("blobs/sha256/{digest}"));
            import_companion_file(store, source, options, report, session_id, &path, &relative)
                .await?;
        } else {
            let reference = format!("blob:sha256:{digest}");
            import_snapshot(
                store,
                source,
                options,
                report,
                SnapshotParts {
                    session_id: session_id.to_owned(),
                    stream: "blob_references".to_owned(),
                    record_id: reference.clone(),
                    format: "omp_blob_reference".to_owned(),
                    position: "referenced".to_owned(),
                    occurred_at: None,
                    parse_status: "missing_reference".to_owned(),
                    native: Some(json!({"reference": reference, "status": "missing"})),
                    raw: ImportRaw::Bytes(reference.into_bytes()),
                    path: source.path.clone(),
                    artifact_only: true,
                },
            )
            .await?;
        }
    }
    Ok(())
}

fn collect_omp_blob_references(value: &Value, references: &mut BTreeSet<String>) {
    match value {
        Value::String(value) => {
            if let Some(digest) = value.strip_prefix("blob:sha256:")
                && digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                references.insert(digest.to_owned());
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_omp_blob_references(value, references);
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                collect_omp_blob_references(value, references);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

async fn import_companion_file(
    store: Option<&TraceStore>,
    source: &DiscoveredSource,
    options: &ImportOptions,
    report: &mut ImportReport,
    session_id: &str,
    path: &Path,
    relative: &Path,
) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_file(),
        "companion artifact must be a regular file, not a symlink"
    );
    ensure!(
        metadata.len() <= options.max_artifact_bytes as u64,
        "artifact exceeds configured {} byte limit",
        options.max_artifact_bytes
    );
    let is_json = path.extension().and_then(|value| value.to_str()) == Some("json");
    let inline_json = is_json && metadata.len() <= options.max_record_bytes as u64;
    let inline_raw = inline_json
        .then(|| {
            read_bounded_file(
                path,
                options.max_record_bytes.min(options.max_artifact_bytes),
            )
        })
        .transpose()?;
    let native = inline_raw
        .as_deref()
        .and_then(|bytes| crate::json::from_slice(bytes).ok());
    let parse_status = match (is_json, inline_json, native.is_some()) {
        (true, true, true) => "valid_json",
        (true, true, false) => "malformed_json_artifact",
        (true, false, _) => "json_artifact_only",
        (false, _, _) => "opaque_bytes",
    };
    let record_id = format!("artifact:{}", relative.to_string_lossy());
    import_snapshot(
        store,
        source,
        options,
        report,
        SnapshotParts {
            session_id: session_id.to_owned(),
            stream: relative.to_string_lossy().into_owned(),
            record_id,
            format: "companion_artifact".to_owned(),
            position: "file".to_owned(),
            occurred_at: None,
            parse_status: parse_status.to_owned(),
            native,
            raw: inline_raw.map_or_else(
                || ImportRaw::File {
                    path: path.to_owned(),
                    max_bytes: options.max_artifact_bytes as u64,
                },
                ImportRaw::Bytes,
            ),
            path: path.to_owned(),
            artifact_only: true,
        },
    )
    .await
}

// Together the session and record keys cover each table's native primary key.
// Keep projection streams distinct from the corresponding rollout records.
struct CodexSqliteTable {
    name: &'static str,
    session_key: &'static str,
    record_keys: &'static [&'static str],
}

const CODEX_STATE_TABLES: &[CodexSqliteTable] = &[CodexSqliteTable {
    name: "threads",
    session_key: "id",
    record_keys: &["id"],
}];

const CODEX_HISTORY_TABLES: &[CodexSqliteTable] = &[
    CodexSqliteTable {
        name: "thread_items",
        session_key: "thread_id",
        record_keys: &["turn_id", "item_id"],
    },
    CodexSqliteTable {
        name: "thread_turns",
        session_key: "thread_id",
        record_keys: &["turn_id"],
    },
    CodexSqliteTable {
        name: "thread_history_projection_state",
        session_key: "thread_id",
        record_keys: &["thread_id"],
    },
    CodexSqliteTable {
        name: "thread_realtime_items",
        session_key: "thread_id",
        record_keys: &["item_id"],
    },
];

async fn import_codex_sqlite(
    store: Option<&TraceStore>,
    source: &DiscoveredSource,
    options: &ImportOptions,
    report: &mut ImportReport,
) -> Result<()> {
    let tables = match source.kind {
        SourceKind::CodexStateDb => CODEX_STATE_TABLES,
        SourceKind::CodexHistoryDb => CODEX_HISTORY_TABLES,
        _ => unreachable!(),
    };
    for table in tables {
        let connection = open_sqlite_read_only(&source.path)?;
        if !table_exists(&connection, table.name)? {
            continue;
        }
        let columns = table_columns(&connection, table.name)?;
        let mut statement = connection.prepare(&format!(
            "SELECT rowid, * FROM {} ORDER BY rowid",
            table.name
        ))?;
        let mut query = statement.query([])?;
        while let Some(row) = query.next()? {
            let rowid: i64 = row.get(0)?;
            let (native, raw) = sqlite_record(row, table.name, &columns, options.max_record_bytes)
                .with_context(|| format!("read {} rowid {rowid}", table.name))?;
            let session_id = sqlite_identity(native.get(table.session_key))
                .map(std::borrow::Cow::into_owned)
                .unwrap_or_else(|| "codex-sqlite-index".to_owned());
            let record_id = sqlite_record_id(table, rowid, &native);
            import_snapshot(
                store,
                source,
                options,
                report,
                SnapshotParts {
                    session_id,
                    stream: format!("sqlite:{}", table.name),
                    record_id,
                    format: "sqlite_projection".to_owned(),
                    position: format!("rowid:{rowid}"),
                    occurred_at: sqlite_timestamp(table.name, &native),
                    parse_status: "sqlite_row".to_owned(),
                    native: Some(native),
                    raw: ImportRaw::Bytes(raw),
                    path: source.path.clone(),
                    artifact_only: false,
                },
            )
            .await?;
        }
    }
    Ok(())
}

fn open_sqlite_read_only(path: &Path) -> Result<Connection> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_file(),
        "SQLite source must be a regular file"
    );
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .context("open Codex SQLite source read-only")
}

fn table_exists(connection: &Connection, table: &str) -> Result<bool> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
        [table],
        |row| row.get(0),
    )?)
}

fn table_columns(connection: &Connection, table: &str) -> Result<Vec<String>> {
    ensure!(
        table
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
        "invalid table name"
    );
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    Ok(statement
        .query_map([], |row| row.get(1))?
        .collect::<rusqlite::Result<_>>()?)
}

fn sqlite_record(
    row: &rusqlite::Row<'_>,
    table: &str,
    columns: &[String],
    limit: usize,
) -> Result<(Value, Vec<u8>)> {
    // Inspect borrowed cells before copying blobs/text or parsing embedded JSON.
    // Their combined size is a lower bound on the serialized native projection.
    let mut bytes = table.len();
    for (index, name) in columns.iter().enumerate() {
        for size in [
            name.len(),
            match row.get_ref(index + 1)? {
                ValueRef::Text(value) | ValueRef::Blob(value) => value.len(),
                _ => 0,
            },
        ] {
            ensure!(
                size <= limit.saturating_sub(bytes),
                "native record exceeds configured {limit} byte limit"
            );
            bytes += size;
        }
    }
    let mut object = Map::new();
    object.insert("_table".to_owned(), Value::String(table.to_owned()));
    for (index, name) in columns.iter().enumerate() {
        object.insert(name.clone(), sqlite_value(row.get_ref(index + 1)?));
    }
    let native = Value::Object(object);
    let mut raw = RecordWriter {
        bytes: Vec::new(),
        limit,
    };
    // Escaping, base64 and parsed JSON can expand a cell's original bytes.
    serde_json::to_writer(&mut raw, &native)?;
    Ok((native, raw.bytes))
}

struct RecordWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for RecordWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other(format!(
                "native record exceeds configured {} byte limit",
                self.limit
            )));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn sqlite_value(value: ValueRef<'_>) -> Value {
    match value {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(value) => Value::from(value),
        ValueRef::Real(value) if value.is_finite() => Value::from(value),
        ValueRef::Real(value) => json!({
            "encoding": "sqlite_real_non_finite",
            "value": if value.is_nan() {
                "NaN"
            } else if value.is_sign_negative() {
                "-Infinity"
            } else {
                "Infinity"
            },
        }),
        ValueRef::Text(value) => {
            let Ok(text) = std::str::from_utf8(value) else {
                return json!({
                    "encoding": "base64",
                    "sqlite_type": "text",
                    "value": STANDARD.encode(value),
                });
            };
            match crate::json::from_slice(value) {
                Ok(parsed) => json!({"encoding": "utf8", "value": text, "json": parsed}),
                Err(_) => json!({"encoding": "utf8", "value": text}),
            }
        }
        ValueRef::Blob(value) => json!({"encoding": "base64", "value": STANDARD.encode(value)}),
    }
}

fn sqlite_record_id(table: &CodexSqliteTable, rowid: i64, native: &Value) -> String {
    let values: Option<Vec<std::borrow::Cow<'_, str>>> = table
        .record_keys
        .iter()
        .map(|key| sqlite_identity(native.get(key)))
        .collect();
    if let Some(values) = values {
        let value = if values.len() == 1 {
            values.into_iter().next().unwrap().into_owned()
        } else {
            // JSON encoding keeps composite IDs unambiguous even if a key
            // contains delimiters used elsewhere in the record ID.
            json!(values).to_string()
        };
        return format!("{}:{}:{value}", table.name, table.record_keys.join(","));
    }
    format!("{}:rowid:{rowid}", table.name)
}

fn sqlite_identity(value: Option<&Value>) -> Option<std::borrow::Cow<'_, str>> {
    const PREFIX: &str = "~sqlite:";
    let value = value?;
    let text = value.get("value")?.as_str()?;
    match value.get("encoding")?.as_str()? {
        "utf8" if !text.starts_with(PREFIX) => Some(std::borrow::Cow::Borrowed(text)),
        // Reserve the namespace for tagged native bytes, including UTF-8 text
        // that could otherwise impersonate an encoded TEXT or BLOB identity.
        "utf8" => Some(std::borrow::Cow::Owned(format!(
            "{PREFIX}utf8:{}",
            STANDARD.encode(text)
        ))),
        "base64" => {
            let kind = if value.get("sqlite_type").and_then(Value::as_str) == Some("text") {
                "text"
            } else {
                "blob"
            };
            Some(std::borrow::Cow::Owned(format!("{PREFIX}{kind}:{text}")))
        }
        _ => None,
    }
}

fn sqlite_timestamp(table: &str, native: &Value) -> Option<String> {
    for key in [
        "created_at_ms",
        "started_at_ms",
        "completed_at_ms",
        "updated_at_ms",
    ] {
        if let Some(value) = native.get(key).and_then(sqlite_integer)
            && let Some(timestamp) = epoch_millis(value)
        {
            return Some(timestamp);
        }
    }
    // The original threads schema stores seconds; later versions add explicit
    // millisecond columns. Do not guess units for other tables' integer fields.
    if table == "threads" {
        for key in ["created_at", "updated_at"] {
            if let Some(value) = native.get(key).and_then(sqlite_integer)
                && let Some(timestamp) = epoch_seconds(value)
            {
                return Some(timestamp);
            }
        }
    }
    for key in ["created_at", "started_at", "completed_at"] {
        if let Some(value) = sqlite_text(native.get(key))
            && chrono::DateTime::parse_from_rfc3339(value).is_ok()
        {
            return Some(value.to_owned());
        }
    }
    None
}

fn sqlite_text(value: Option<&Value>) -> Option<&str> {
    let value = value?;
    (value.get("encoding")?.as_str()? == "utf8")
        .then(|| value.get("value").and_then(Value::as_str))
        .flatten()
}

fn sqlite_integer(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.get("value").and_then(Value::as_i64))
}

fn native_session_id(harness: Harness, value: &Value) -> Option<String> {
    let id = match harness {
        Harness::Omp => (value.get("type")?.as_str()? == "session")
            .then(|| value.get("id").and_then(Value::as_str))
            .flatten(),
        Harness::ClaudeCode => value.get("sessionId").and_then(Value::as_str),
        Harness::Codex => {
            let is_meta = value.get("type").and_then(Value::as_str) == Some("session_meta");
            is_meta
                .then(|| {
                    value
                        .pointer("/payload/id")
                        .or_else(|| value.pointer("/payload/session_id"))
                        .and_then(Value::as_str)
                })
                .flatten()
        }
        Harness::GrokBuild => value.pointer("/params/sessionId").and_then(Value::as_str),
    };
    id.map(str::to_owned)
}

fn fallback_session_id(source: &DiscoveredSource, value: &Value) -> String {
    match source.harness {
        Harness::Omp => value.get("id").and_then(Value::as_str),
        Harness::ClaudeCode => value.get("sessionId").and_then(Value::as_str),
        Harness::Codex => value.pointer("/payload/session_id").and_then(Value::as_str),
        Harness::GrokBuild => value.pointer("/params/sessionId").and_then(Value::as_str),
    }
    .map(str::to_owned)
    .unwrap_or_else(|| fallback_path_identity(&source.path))
}

fn native_record_id(harness: Harness, value: &Value) -> Option<String> {
    match harness {
        Harness::Omp => value
            .get("id")
            .or_else(|| value.get("entryId"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        Harness::ClaudeCode => value
            .get("uuid")
            .or_else(|| value.get("messageId"))
            .or_else(|| value.get("leafUuid"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        Harness::Codex => value.get("ordinal").map(Value::to_string).or_else(|| {
            value
                .pointer("/payload/id")
                .and_then(Value::as_str)
                .map(str::to_owned)
        }),
        Harness::GrokBuild => value
            .pointer("/params/_meta/eventId")
            .and_then(Value::as_str)
            .map(str::to_owned),
    }
}

fn native_timestamp(harness: Harness, value: &Value) -> Option<String> {
    match harness {
        Harness::Omp => rfc3339(value.get("timestamp").or_else(|| value.get("updatedAt"))),
        Harness::ClaudeCode | Harness::Codex => rfc3339(value.get("timestamp")),
        Harness::GrokBuild => value
            .get("timestamp")
            .and_then(Value::as_i64)
            .and_then(epoch_seconds),
    }
}

fn rfc3339(value: Option<&Value>) -> Option<String> {
    let value = value?.as_str()?;
    chrono::DateTime::parse_from_rfc3339(value).ok()?;
    Some(value.to_owned())
}

fn epoch_seconds(value: i64) -> Option<String> {
    Utc.timestamp_opt(value, 0)
        .single()
        .map(|time| time.to_rfc3339_opts(SecondsFormat::Secs, true))
}

fn epoch_millis(value: i64) -> Option<String> {
    Utc.timestamp_millis_opt(value)
        .single()
        .map(|time| time.to_rfc3339_opts(SecondsFormat::Millis, true))
}

fn read_bounded_line(reader: &mut dyn BufRead, line: &mut Vec<u8>, limit: usize) -> Result<usize> {
    let read = reader
        .take((limit as u64).saturating_add(2))
        .read_until(b'\n', line)?;
    let record = line
        .strip_suffix(b"\r\n")
        .or_else(|| line.strip_suffix(b"\n"))
        .unwrap_or(line);
    ensure!(
        record.len() <= limit,
        "native record exceeds configured {limit} byte limit"
    );
    Ok(read)
}

fn trim_newline(line: &mut Vec<u8>) -> bool {
    if line.last() != Some(&b'\n') {
        return false;
    }
    line.pop();
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    true
}

fn open_regular_file(path: &Path) -> Result<File> {
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.file_type().is_file(),
        "source must be a regular file, not a symlink"
    );
    let file = File::open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let after = file.metadata()?;
        ensure!(
            before.dev() == after.dev() && before.ino() == after.ino(),
            "source changed while opening"
        );
    }
    Ok(file)
}

fn hash_regular_file(path: &Path, limit: usize) -> Result<String> {
    let mut file = open_regular_file(path)?;
    ensure!(
        file.metadata()?.len() <= limit as u64,
        "artifact exceeds configured {limit} byte limit"
    );
    let mut remaining = limit;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let chunk_len = buffer.len().min(remaining.saturating_add(1));
        let read = file.read(&mut buffer[..chunk_len])?;
        ensure!(
            read <= remaining,
            "artifact grew beyond configured {limit} byte limit"
        );
        remaining -= read;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn read_bounded_file(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let file = open_regular_file(path)?;
    let size = usize::try_from(file.metadata()?.len())
        .context("source file size exceeds platform range")?;
    ensure!(
        size <= limit,
        "artifact exceeds configured {limit} byte limit"
    );
    let mut bytes = Vec::with_capacity(size);
    file.take((limit as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= limit,
        "artifact grew beyond configured {limit} byte limit"
    );
    Ok(bytes)
}

fn is_regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_file())
}

fn is_real_directory(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_dir())
}

fn walk_regular_files(root: &Path, max_depth: usize) -> Result<Vec<PathBuf>> {
    if !is_real_directory(root) {
        bail!("artifact directory must be a real directory, not a symlink");
    }
    let mut queue = VecDeque::from([(root.to_owned(), 0usize)]);
    let mut files = Vec::new();
    while let Some((directory, depth)) = queue.pop_front() {
        ensure!(
            depth <= max_depth,
            "artifact nesting exceeds {max_depth} levels"
        );
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                queue.push_back((path, depth + 1));
            } else if metadata.is_file() {
                files.push(path);
                ensure!(
                    files.len() <= DEFAULT_MAX_SOURCES,
                    "session contains more than {DEFAULT_MAX_SOURCES} artifacts"
                );
            }
        }
    }
    files.sort();
    Ok(files)
}

fn source_for_path(
    source: &DiscoveredSource,
    path: PathBuf,
    kind: SourceKind,
) -> Result<DiscoveredSource> {
    let metadata = fs::metadata(&path)?;
    Ok(DiscoveredSource {
        harness: source.harness,
        kind,
        path,
        source_namespace: source.source_namespace.clone(),
        size: Some(metadata.len()),
        origin: source.origin.clone(),
    })
}

fn fallback_path_identity(path: &Path) -> String {
    format!("path:{}", hex_digest(path.as_os_str().as_encoded_bytes()))
}

fn hex_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn is_credential_name(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            matches!(name, "auth.json" | "mcp_credentials.json") || name.contains("credential")
        })
}
