//! Lossless inference bodies and session events in one private durable SQLite index.
//!
//! Native traffic writes `request` and `response`; translated traffic additionally
//! writes `upstream_request` and `upstream_response`. Dropping a writer never marks
//! it complete. Bodies are not truncated. Inspection is paginated by insertion
//! order, with a canonical trace UUID as the `before` cursor.
//! Session events are append-only, deduplicated by canonical event UUID/content,
//! and correlated to inference traces without requiring the trace to exist locally.
//! Event payloads are sensitive: unlike trace headers, they are never redacted.

use std::{
    fs::{self, File as StdFile, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::{fs::File, io::AsyncWriteExt};
use uuid::Uuid;

use crate::sensitive_headers::is_sensitive_header;

/// Export rejects the whole operation if all selected raw bodies exceed this cap.
/// This is an aggregate limit, not a per-file truncation threshold.
pub const MAX_EXPORT_BODY_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_TRACE_ROWS: usize = 100;
pub const MAX_SESSION_EVENT_BYTES: usize = 16 * 1024 * 1024;
const MAX_METADATA_BYTES: usize = 256 * 1024;
const BODY_KINDS: [&str; 4] = [
    "request",
    "response",
    "upstream_request",
    "upstream_response",
];
const BODY_FILES: [&str; 4] = [
    "request.body",
    "response.body",
    "upstream_request.body",
    "upstream_response.body",
];

/// A lossless native session hook event. Payloads are sensitive and are not redacted.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionEvent {
    pub id: String,
    pub session_id: String,
    pub source: String,
    pub kind: String,
    pub occurred_at: String,
    pub trace_id: Option<String>,
    #[serde(deserialize_with = "deserialize_event_payload")]
    pub payload: Value,
}

/// Exact bytes retained for an imported observation or source artifact.
#[derive(Debug)]
pub enum ImportRaw {
    Bytes(Vec<u8>),
    File { path: PathBuf, max_bytes: u64 },
}

/// Acquisition-specific provenance kept outside the immutable event payload.
#[derive(Debug)]
pub struct ImportAcquisition {
    pub source_path: String,
    pub source_digest: Option<String>,
    pub member_path: Option<String>,
    pub position: Option<String>,
}

/// One immutable native-record observation produced by an import adapter.
/// `raw` is always retained as a content-addressed artifact; `native` is an
/// optional parsed projection for convenient inspection.
#[derive(Debug)]
pub struct ImportSnapshot {
    pub adapter: String,
    pub event_source: String,
    pub payload_schema: String,
    pub source_namespace: String,
    pub native_session_id: String,
    pub stream: String,
    pub native_record_id: String,
    pub format: String,
    pub position: String,
    pub occurred_at: Option<String>,
    pub parse_status: String,
    pub native: Option<Value>,
    pub raw: ImportRaw,
    pub acquisition: ImportAcquisition,
}

fn deserialize_event_payload<'de, D>(deserializer: D) -> std::result::Result<Value, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = <&serde_json::value::RawValue>::deserialize(deserializer)?;
    crate::json::from_slice(raw.get().as_bytes()).map_err(serde::de::Error::custom)
}

impl SessionEvent {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).context("decode session event")
    }

    /// Validate identifiers, time, and the complete reserialized event size.
    pub fn validate(&self) -> Result<()> {
        self.validate_fields()
            .map_err(|error| InvalidSessionEvent(error.to_string()))?;
        serde_json::to_writer(EventSizeCounter(0), self)
            .map_err(|error| InvalidSessionEvent(error.to_string()))?;
        Ok(())
    }

    fn validate_fields(&self) -> Result<()> {
        let id = validate_id(&self.id).context("invalid session event id")?;
        ensure!(
            id.get_version_num() == 4 && id.get_variant() == uuid::Variant::RFC4122,
            "session event id must be a UUID v4"
        );
        validate_identifier(&self.session_id, 128, "session id")?;
        validate_identifier(&self.source, 64, "event source")?;
        validate_identifier(&self.kind, 128, "event kind")?;
        chrono::DateTime::parse_from_rfc3339(&self.occurred_at)
            .context("event occurred_at must be RFC3339")?;
        if let Some(trace_id) = &self.trace_id {
            validate_id(trace_id)?;
        }
        Ok(())
    }
}

struct EventSizeCounter(usize);

impl io::Write for EventSizeCounter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_SESSION_EVENT_BYTES - self.0 {
            return Err(io::Error::other(format!(
                "session event exceeds {MAX_SESSION_EVENT_BYTES} bytes"
            )));
        }
        self.0 += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Reusing an event UUID with different canonical content is a conflict.
#[derive(Debug)]
pub struct EventConflict {
    pub id: String,
}

impl std::fmt::Display for EventConflict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "session event {} already has different content",
            self.id
        )
    }
}

impl std::error::Error for EventConflict {}

/// Invalid wire fields or an oversized serialized event, never a storage failure.
#[derive(Debug)]
pub struct InvalidSessionEvent(String);

impl std::fmt::Display for InvalidSessionEvent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for InvalidSessionEvent {}

#[derive(Clone)]
pub struct TraceStore {
    inner: Arc<StoreInner>,
}

struct StoreInner {
    root: PathBuf,
    connection: Mutex<Option<Connection>>,
}

impl Drop for StoreInner {
    fn drop(&mut self) {
        let connection = match self.connection.get_mut() {
            Ok(slot) => slot.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        if let Some(connection) = connection {
            // Closing the last WAL connection can checkpoint and fsync. It is
            // metadata persistence too, so never perform it on a Tokio worker.
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn_blocking(move || drop(connection));
            } else {
                std::thread::spawn(move || drop(connection));
            }
        }
    }
}

pub struct TraceStart {
    pub id: String,
    pub provider: String,
    pub method: String,
    pub path: String,
    pub request_headers: Value,
    pub upstream_url: String,
    pub upstream_headers: Value,
}

/// A failed or cancelled append/route operation poisons this writer. The caller
/// must fail closed; it cannot subsequently publish a successful completion.
pub struct TraceWriter {
    store: TraceStore,
    id: String,
    files: [Option<File>; 4],
    failed: bool,
}

struct IndexedTrace {
    id: String,
    metadata: String,
    complete: bool,
    status: Option<u16>,
    response_headers: Option<String>,
    error: Option<String>,
    completed_at: Option<String>,
}

impl TraceStore {
    pub async fn open(path: &Path) -> Result<Self> {
        let root = path.to_owned();
        let inner = tokio::task::spawn_blocking(move || -> Result<StoreInner> {
            create_private_directory(&root, true)?;
            let root = root.canonicalize().context("resolve trace directory")?;
            create_private_directory(&root.join("artifacts"), true)?;
            create_private_directory(&root.join("artifacts").join("sha256"), true)?;
            let database = root.join("index.sqlite3");
            create_private_database(&database)?;
            // SQLite sidecars inherit the database's 0600 mode. Tighten existing
            // sidecars too, and reject symlinks before SQLite accesses them.
            protect_sidecars(&root)?;
            let connection = Connection::open_with_flags(
                &database,
                OpenFlags::SQLITE_OPEN_READ_WRITE
                    | OpenFlags::SQLITE_OPEN_NO_MUTEX
                    | OpenFlags::SQLITE_OPEN_NOFOLLOW,
            )
            .context("open trace index")?;
            connection.busy_timeout(Duration::from_secs(5))?;
            let journal: String =
                connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
            ensure!(
                journal.eq_ignore_ascii_case("wal"),
                "trace index requires WAL journaling"
            );
            connection.pragma_update(None, "synchronous", "FULL")?;
            let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
            ensure!(
                version <= 4,
                "unsupported trace index schema version {version}"
            );
            connection
                .execute_batch(
                    "BEGIN IMMEDIATE;
                 CREATE TABLE IF NOT EXISTS traces (
                     sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                     id TEXT NOT NULL UNIQUE,
                     metadata TEXT NOT NULL,
                     complete INTEGER NOT NULL DEFAULT 0 CHECK (complete IN (0, 1)),
                     status INTEGER,
                     response_headers TEXT,
                     error TEXT,
                     completed_at TEXT
                 );
                 CREATE TABLE IF NOT EXISTS session_events (
                     sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                     id TEXT NOT NULL UNIQUE,
                     session_id TEXT NOT NULL,
                     source TEXT NOT NULL,
                     kind TEXT NOT NULL,
                     occurred_at TEXT NOT NULL,
                     trace_id TEXT,
                     received_at TEXT NOT NULL,
                     event_json TEXT NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS session_events_session_sequence
                     ON session_events (session_id, sequence);
                 CREATE INDEX IF NOT EXISTS session_events_session_trace
                     ON session_events (session_id, trace_id);
                 CREATE TABLE IF NOT EXISTS sessions (
                     session_id TEXT PRIMARY KEY,
                     source TEXT NOT NULL,
                     first_sequence INTEGER NOT NULL UNIQUE,
                     last_sequence INTEGER NOT NULL,
                     event_count INTEGER NOT NULL,
                     started_at TEXT NOT NULL,
                     updated_at TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS import_sessions (
                     harness TEXT NOT NULL,
                     source_namespace TEXT NOT NULL,
                     native_session_id TEXT NOT NULL,
                     session_id TEXT NOT NULL UNIQUE,
                     PRIMARY KEY (harness, source_namespace, native_session_id)
                 );
                 CREATE TABLE IF NOT EXISTS artifacts (
                     digest TEXT PRIMARY KEY,
                     size INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS import_snapshots (
                     snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
                     harness TEXT NOT NULL,
                     source_namespace TEXT NOT NULL,
                     native_session_id TEXT NOT NULL,
                     stream TEXT NOT NULL,
                     native_record_id TEXT NOT NULL,
                     fingerprint TEXT NOT NULL,
                     event_id TEXT NOT NULL UNIQUE,
                     artifact_digest TEXT NOT NULL,
                     UNIQUE (
                         harness, source_namespace, native_session_id, stream,
                         native_record_id, fingerprint
                     )
                 );
                 CREATE INDEX IF NOT EXISTS import_snapshots_logical_identity
                     ON import_snapshots (
                         harness, source_namespace, native_session_id, stream,
                         native_record_id
                     );
                 CREATE TABLE IF NOT EXISTS import_acquisitions (
                     snapshot_id INTEGER NOT NULL,
                     source_path TEXT NOT NULL,
                     source_digest TEXT NOT NULL DEFAULT '',
                     member_path TEXT NOT NULL DEFAULT '',
                     source_position TEXT NOT NULL DEFAULT '',
                     observed_at TEXT NOT NULL,
                     UNIQUE (
                         snapshot_id, source_path, source_digest,
                         member_path, source_position
                     )
                );
                 CREATE TABLE IF NOT EXISTS files (
                     id TEXT PRIMARY KEY,
                     digest TEXT NOT NULL,
                     size INTEGER NOT NULL,
                     filename TEXT NOT NULL,
                     purpose TEXT NOT NULL,
                     created_at INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS provider_files (
                     infer_id TEXT NOT NULL,
                     provider TEXT NOT NULL,
                     provider_file_id TEXT NOT NULL,
                     PRIMARY KEY (infer_id, provider)
                 );
                 COMMIT;",
                )
                .context("initialize trace index")?;
            if version == 3 {
                // The immutable event proves the original acquisition's position.
                // Later legacy receipts have no position evidence: retain them
                // unchanged rather than guessing or discarding provenance.
                connection
                    .execute_batch(
                        "BEGIN IMMEDIATE;
                         ALTER TABLE import_acquisitions RENAME TO import_acquisitions_v3;
                         CREATE TABLE import_acquisitions (
                             snapshot_id INTEGER NOT NULL,
                             source_path TEXT NOT NULL,
                             source_digest TEXT NOT NULL DEFAULT '',
                             member_path TEXT NOT NULL DEFAULT '',
                             source_position TEXT NOT NULL DEFAULT '',
                             observed_at TEXT NOT NULL,
                             UNIQUE (
                                 snapshot_id, source_path, source_digest,
                                 member_path, source_position
                             )
                         );
                         INSERT INTO import_acquisitions
                             (snapshot_id, source_path, source_position, observed_at)
                             SELECT a.snapshot_id, a.source_path,
                                    CASE WHEN a.observed_at = e.received_at
                                         AND a.rowid = (
                                             SELECT MIN(candidate.rowid)
                                             FROM import_acquisitions_v3 candidate
                                             WHERE candidate.snapshot_id = a.snapshot_id
                                         )
                                         THEN COALESCE(
                                             json_extract(e.event_json, '$.payload.position'),
                                             ''
                                         )
                                         ELSE '' END,
                                    a.observed_at
                             FROM import_acquisitions_v3 a
                             LEFT JOIN import_snapshots s ON s.snapshot_id = a.snapshot_id
                             LEFT JOIN session_events e ON e.id = s.event_id;
                         DROP TABLE import_acquisitions_v3;
                         PRAGMA user_version = 4;
                         COMMIT;",
                    )
                    .context("migrate trace index to schema 4")?;
            } else if version < 4 {
                connection.pragma_update(None, "user_version", 4)?;
            }
            protect_sidecars(&root)?;
            sync_directory(&root)?;
            if let Some(parent) = root.parent() {
                sync_directory(parent)?;
            }
            Ok(StoreInner {
                root,
                connection: Mutex::new(Some(connection)),
            })
        })
        .await
        .context("trace initialization worker failed")??;
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    async fn blocking<T, F>(&self, work: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection, &Path) -> Result<T> + Send + 'static,
    {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let mut connection = inner
                .connection
                .lock()
                .map_err(|_| anyhow::anyhow!("trace index lock poisoned"))?;
            work(
                connection.as_mut().context("trace index already closed")?,
                &inner.root,
            )
        })
        .await
        .context("trace storage worker failed")?
    }

    pub async fn start(&self, mut meta: TraceStart) -> Result<TraceWriter> {
        validate_id(&meta.id)?;
        redact_headers(&mut meta.request_headers);
        redact_headers(&mut meta.upstream_headers);
        let id = meta.id.clone();
        let metadata = bounded_json(&json!({
            "id": meta.id,
            "provider": meta.provider,
            "method": meta.method,
            "path": meta.path,
            "request_headers": meta.request_headers,
            "upstream_url": meta.upstream_url,
            "upstream_headers": meta.upstream_headers,
            "started_at": timestamp(),
        }))?;
        let worker_id = id.clone();
        let (request, response) = self
            .blocking(move |connection, root| {
                // Commit the incomplete row before touching body files. A crash
                // or disk error during setup remains visible in the index.
                connection
                    .execute(
                        "INSERT INTO traces (id, metadata) VALUES (?1, ?2)",
                        params![worker_id, metadata],
                    )
                    .context("start trace metadata")?;
                let directory = root.join(&worker_id);
                create_private_directory(&directory, false)?;
                let request = create_private_file(&directory.join(BODY_FILES[0]))?;
                let response = create_private_file(&directory.join(BODY_FILES[1]))?;
                // The incomplete row is durable already. Empty files need no
                // fsync until finish() persists the bodies and directory entries.
                Ok((request, response))
            })
            .await?;
        Ok(TraceWriter {
            store: self.clone(),
            id,
            files: [
                Some(File::from_std(request)),
                Some(File::from_std(response)),
                None,
                None,
            ],
            failed: false,
        })
    }

    /// Returns `{traces: [...], next_before: UUID | null}`. Limits outside
    /// 1..=MAX_TRACE_ROWS and unknown cursors are rejected, never silently clamped.
    pub async fn list(&self, limit: usize, before: Option<String>) -> Result<Value> {
        validate_page(limit, before.as_deref())?;
        self.blocking(move |connection, root| {
            let mut rows = select_traces(connection, limit + 1, before.as_deref())?;
            let has_more = rows.len() > limit;
            rows.truncate(limit);
            let next = if has_more {
                rows.last().map(|row| row.id.clone())
            } else {
                None
            };
            let traces = rows
                .into_iter()
                .map(|row| describe_trace(root, row))
                .collect::<Result<Vec<_>>>()?;
            let mut page = serde_json::Map::new();
            page.insert("traces".to_owned(), Value::Array(traces));
            page.insert(
                "next_before".to_owned(),
                next.map_or(Value::Null, Value::String),
            );
            Ok(Value::Object(page))
        })
        .await
    }

    /// Append atomically in ingestion order. Identical retries retain their receipt.
    pub async fn put_event(&self, event: SessionEvent) -> Result<Value> {
        self.blocking(move |connection, _| {
            event.validate_fields()
                .map_err(|error| InvalidSessionEvent(error.to_string()))?;
            let encoded = serde_json::to_string(&event)
                .map_err(|error| InvalidSessionEvent(error.to_string()))?;
            if encoded.len() > MAX_SESSION_EVENT_BYTES {
                return Err(InvalidSessionEvent(format!(
                    "session event exceeds {MAX_SESSION_EVENT_BYTES} bytes"
                )).into());
            }
            let transaction =
                connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let existing: Option<(i64, String)> = transaction
                .query_row(
                    "SELECT sequence, event_json FROM session_events WHERE id = ?1",
                    [&event.id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            if let Some((sequence, previous)) = existing {
                if previous != encoded {
                    return Err(EventConflict { id: event.id }.into());
                }
                return Ok(json!({"id": event.id, "sequence": sequence}));
            }
            let received_at = timestamp();
            transaction.execute(
                "INSERT INTO session_events
                 (id, session_id, source, kind, occurred_at, trace_id, received_at, event_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    event.id, event.session_id, event.source, event.kind,
                    event.occurred_at, event.trace_id, received_at, encoded
                ],
            )?;
            let sequence = transaction.last_insert_rowid();
            transaction.execute(
                "INSERT INTO sessions
                 (session_id, source, first_sequence, last_sequence, event_count, started_at, updated_at)
                 VALUES (?1, ?2, ?3, ?3, 1, ?4, ?4)
                 ON CONFLICT(session_id) DO UPDATE SET
                     last_sequence = excluded.last_sequence,
                     event_count = sessions.event_count + 1,
                     updated_at = excluded.updated_at",
                params![event.session_id, event.source, sequence, received_at],
            )?;
            transaction.commit().context("commit session event")?;
            Ok(json!({"id": event.id, "sequence": sequence}))
        })
        .await
    }

    /// Retain a complete imported source without manufacturing a session event.
    pub async fn put_import_artifact(&self, raw: ImportRaw) -> Result<Value> {
        let root = self.inner.root.clone();
        let artifact = tokio::task::spawn_blocking(move || match raw {
            ImportRaw::Bytes(bytes) => persist_artifact(&root, &bytes),
            ImportRaw::File { path, max_bytes } => persist_artifact_file(&root, &path, max_bytes),
        })
        .await
        .context("artifact storage worker failed")??;
        self.blocking(move |connection, _| {
            connection.execute(
                "INSERT INTO artifacts (digest, size) VALUES (?1, ?2)
                 ON CONFLICT(digest) DO NOTHING",
                params![artifact.0, artifact.1],
            )?;
            Ok(json!({"digest": artifact.0, "size": artifact.1}))
        })
        .await
    }

    /// Persist one native import observation. The source-to-UUID mapping,
    /// immutable event, and acquisition receipt commit in one SQLite transaction.
    pub async fn put_import_snapshot(&self, snapshot: ImportSnapshot) -> Result<Value> {
        validate_import_snapshot(&snapshot)?;
        let root = self.inner.root.clone();
        let raw = snapshot.raw;
        let artifact = tokio::task::spawn_blocking(move || match raw {
            ImportRaw::Bytes(bytes) => persist_artifact(&root, &bytes),
            ImportRaw::File { path, max_bytes } => persist_artifact_file(&root, &path, max_bytes),
        })
        .await
        .context("artifact storage worker failed")??;
        self.blocking(move |connection, _| {
            let observed_at = timestamp();
            let transaction =
                connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let existing: Option<(i64, String, i64)> = transaction
                .query_row(
                    "SELECT s.snapshot_id, s.event_id, e.sequence
                     FROM import_snapshots s
                     JOIN session_events e ON e.id = s.event_id
                     WHERE s.harness = ?1 AND s.source_namespace = ?2
                       AND s.native_session_id = ?3 AND s.stream = ?4
                       AND s.native_record_id = ?5 AND s.fingerprint = ?6",
                    params![
                        snapshot.adapter,
                        snapshot.source_namespace,
                        snapshot.native_session_id,
                        snapshot.stream,
                        snapshot.native_record_id,
                        artifact.0,
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            let acquisition = &snapshot.acquisition;
            let source_digest = acquisition.source_digest.as_deref().unwrap_or("");
            let member_path = acquisition.member_path.as_deref().unwrap_or("");
            let source_position = acquisition.position.as_deref().unwrap_or("");
            if let Some((snapshot_id, event_id, sequence)) = existing {
                transaction.execute(
                    "INSERT OR IGNORE INTO import_acquisitions
                     (snapshot_id, source_path, source_digest, member_path,
                      source_position, observed_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        snapshot_id,
                        acquisition.source_path,
                        source_digest,
                        member_path,
                        source_position,
                        observed_at,
                    ],
                )?;
                transaction.commit().context("commit import acquisition")?;
                return Ok(json!({
                    "event_id": event_id,
                    "sequence": sequence,
                    "imported": false,
                }));
            }

            let session_id: String = transaction
                .query_row(
                    "SELECT session_id FROM import_sessions
                     WHERE harness = ?1 AND source_namespace = ?2 AND native_session_id = ?3",
                    params![
                        snapshot.adapter,
                        snapshot.source_namespace,
                        snapshot.native_session_id,
                    ],
                    |row| row.get(0),
                )
                .optional()?
                .unwrap_or_else(|| format!("import-{}", Uuid::new_v4()));
            transaction.execute(
                "INSERT OR IGNORE INTO import_sessions
                 (harness, source_namespace, native_session_id, session_id)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    snapshot.adapter,
                    snapshot.source_namespace,
                    snapshot.native_session_id,
                    session_id,
                ],
            )?;
            let revision: i64 = transaction.query_row(
                "SELECT COUNT(*) + 1 FROM import_snapshots
                 WHERE harness = ?1 AND source_namespace = ?2
                   AND native_session_id = ?3 AND stream = ?4
                   AND native_record_id = ?5",
                params![
                    snapshot.adapter,
                    snapshot.source_namespace,
                    snapshot.native_session_id,
                    snapshot.stream,
                    snapshot.native_record_id,
                ],
                |row| row.get(0),
            )?;
            let event_id = Uuid::new_v4().to_string();
            let occurrence_basis = if snapshot.occurred_at.is_some() {
                "native"
            } else {
                "import_observation"
            };
            let occurred_at = snapshot
                .occurred_at
                .clone()
                .unwrap_or_else(|| observed_at.clone());
            let native_inline = snapshot.native.is_some();
            let payload = json!({
                "schema": snapshot.payload_schema,
                "source_adapter": snapshot.adapter,
                "source_namespace": snapshot.source_namespace,
                "source_format": snapshot.format,
                "native_session_id": snapshot.native_session_id,
                "native_record_id": snapshot.native_record_id,
                "stream": snapshot.stream,
                "position": snapshot.position,
                "revision": revision,
                "parse_status": snapshot.parse_status,
                "native_occurred_at": snapshot.occurred_at,
                "occurrence_basis": occurrence_basis,
                "native": snapshot.native,
                "native_inline": native_inline,
                "raw_artifact": {
                    "digest": artifact.0,
                    "size": artifact.1,
                    "download_path": format!("/artifacts/{}", artifact.0),
                },
            });
            let mut event = SessionEvent {
                id: event_id.clone(),
                session_id: session_id.clone(),
                source: snapshot.event_source,
                kind: if occurrence_basis == "native" {
                    "native_record".to_owned()
                } else {
                    "import_observation".to_owned()
                },
                occurred_at,
                trace_id: None,
                payload,
            };
            event.validate_fields()
                .map_err(|error| InvalidSessionEvent(error.to_string()))?;
            let mut encoded = serde_json::to_string(&event)
                .map_err(|error| InvalidSessionEvent(error.to_string()))?;
            if encoded.len() > MAX_SESSION_EVENT_BYTES && native_inline {
                event.payload["native"] = Value::Null;
                event.payload["native_inline"] = Value::Bool(false);
                encoded = serde_json::to_string(&event)
                    .map_err(|error| InvalidSessionEvent(error.to_string()))?;
            }
            ensure!(
                encoded.len() <= MAX_SESSION_EVENT_BYTES,
                "import event metadata exceeds {MAX_SESSION_EVENT_BYTES} bytes"
            );
            transaction.execute(
                "INSERT INTO session_events
                 (id, session_id, source, kind, occurred_at, trace_id, received_at, event_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7)",
                params![
                    event.id,
                    event.session_id,
                    event.source,
                    event.kind,
                    event.occurred_at,
                    observed_at,
                    encoded,
                ],
            )?;
            let sequence = transaction.last_insert_rowid();
            transaction.execute(
                "INSERT INTO sessions
                 (session_id, source, first_sequence, last_sequence, event_count, started_at, updated_at)
                 VALUES (?1, ?2, ?3, ?3, 1, ?4, ?4)
                 ON CONFLICT(session_id) DO UPDATE SET
                     last_sequence = excluded.last_sequence,
                     event_count = sessions.event_count + 1,
                     updated_at = excluded.updated_at",
                params![session_id, event.source, sequence, observed_at],
            )?;
            transaction.execute(
                "INSERT INTO artifacts (digest, size) VALUES (?1, ?2)
                 ON CONFLICT(digest) DO NOTHING",
                params![artifact.0, artifact.1],
            )?;
            transaction.execute(
                "INSERT INTO import_snapshots
                 (harness, source_namespace, native_session_id, stream,
                  native_record_id, fingerprint, event_id, artifact_digest)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?6)",
                params![
                    snapshot.adapter,
                    snapshot.source_namespace,
                    snapshot.native_session_id,
                    snapshot.stream,
                    snapshot.native_record_id,
                    artifact.0,
                    event_id,
                ],
            )?;
            let snapshot_id = transaction.last_insert_rowid();
            transaction.execute(
                "INSERT INTO import_acquisitions
                 (snapshot_id, source_path, source_digest, member_path,
                  source_position, observed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    snapshot_id,
                    acquisition.source_path,
                    source_digest,
                    member_path,
                    source_position,
                    observed_at,
                ],
            )?;
            transaction.commit().context("commit imported snapshot")?;
            Ok(json!({
                "event_id": event_id,
                "session_id": session_id,
                "sequence": sequence,
                "revision": revision,
                "imported": true,
                "artifact_digest": artifact.0,
            }))
        })
        .await
    }

    pub async fn artifact(&self, digest: &str) -> Result<Option<File>> {
        validate_digest(digest)?;
        let digest = digest.to_owned();
        let file = self
            .blocking(move |connection, root| {
                let exists: bool = connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM artifacts WHERE digest = ?1)",
                    [&digest],
                    |row| row.get(0),
                )?;
                if !exists {
                    return Ok(None);
                }
                open_artifact(root, &digest)
            })
            .await?;
        Ok(file.map(File::from_std))
    }

    pub async fn put_file(
        &self,
        bytes: Vec<u8>,
        filename: String,
        purpose: String,
    ) -> Result<OwnedFile> {
        ensure!(!bytes.is_empty(), "file is empty");
        ensure!(
            matches!(purpose.as_str(), "user_data" | "vision"),
            "purpose must be user_data or vision"
        );
        let root = self.inner.root.clone();
        let (digest, size) = tokio::task::spawn_blocking(move || persist_artifact(&root, &bytes))
            .await
            .context("file storage worker failed")??;
        let stored = OwnedFile {
            id: format!("file-{}", uuid::Uuid::new_v4().simple()),
            bytes: size,
            created_at: chrono::Utc::now().timestamp(),
            filename,
            purpose,
            digest: digest.clone(),
        };
        self.blocking(move |connection, _| {
            connection.execute(
                "INSERT INTO files (id, digest, size, filename, purpose, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    stored.id,
                    stored.digest,
                    stored.bytes,
                    stored.filename,
                    stored.purpose,
                    stored.created_at
                ],
            )?;
            connection.execute(
                "INSERT INTO artifacts (digest, size) VALUES (?1, ?2)
                 ON CONFLICT(digest) DO NOTHING",
                params![digest, size],
            )?;
            Ok(stored)
        })
        .await
    }

    pub async fn file(&self, id: &str) -> Result<Option<OwnedFile>> {
        validate_file_id(id)?;
        let id = id.to_owned();
        self.blocking(move |connection, _| file_row(connection, &id))
            .await
    }

    pub async fn delete_file(&self, id: &str) -> Result<bool> {
        validate_file_id(id)?;
        let id = id.to_owned();
        self.blocking(move |connection, _| {
            connection.execute("DELETE FROM provider_files WHERE infer_id = ?1", [&id])?;
            Ok(connection.execute("DELETE FROM files WHERE id = ?1", [&id])? > 0)
        })
        .await
    }

    pub async fn file_body(&self, id: &str) -> Result<Option<std::fs::File>> {
        validate_file_id(id)?;
        let id = id.to_owned();
        self.blocking(move |connection, root| {
            let Some(file) = file_row(connection, &id)? else {
                return Ok(None);
            };
            open_artifact(root, &file.digest)
        })
        .await
    }

    pub async fn list_files(&self, limit: i64) -> Result<Vec<OwnedFile>> {
        ensure!(
            (1..=100).contains(&limit),
            "file list limit must be 1..=100"
        );
        self.blocking(move |connection, _| {
            let mut statement = connection.prepare(
                "SELECT id, size, created_at, filename, purpose, digest
                 FROM files ORDER BY created_at DESC LIMIT ?1",
            )?;
            let mut rows = statement.query([limit])?;
            let mut files = Vec::new();
            while let Some(row) = rows.next()? {
                files.push(OwnedFile {
                    id: row.get(0)?,
                    bytes: row.get(1)?,
                    created_at: row.get(2)?,
                    filename: row.get(3)?,
                    purpose: row.get(4)?,
                    digest: row.get(5)?,
                });
            }
            Ok(files)
        })
        .await
    }

    pub async fn provider_file(&self, infer_id: &str, provider: &str) -> Result<Option<String>> {
        let infer_id = infer_id.to_owned();
        let provider = provider.to_owned();
        self.blocking(move |connection, _| {
            let mut statement = connection.prepare(
                "SELECT provider_file_id FROM provider_files WHERE infer_id = ?1 AND provider = ?2",
            )?;
            let mut rows = statement.query(params![infer_id, provider])?;
            Ok(rows.next()?.map(|row| row.get(0)).transpose()?)
        })
        .await
    }

    pub async fn remember_provider_file(
        &self,
        infer_id: &str,
        provider: &str,
        provider_file_id: &str,
    ) -> Result<()> {
        let infer_id = infer_id.to_owned();
        let provider = provider.to_owned();
        let provider_file_id = provider_file_id.to_owned();
        self.blocking(move |connection, _| {
            connection.execute(
                "INSERT INTO provider_files (infer_id, provider, provider_file_id)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(infer_id, provider) DO UPDATE SET provider_file_id = excluded.provider_file_id",
                params![infer_id, provider, provider_file_id],
            )?;
            Ok(())
        })
        .await
    }

    /// Newest first by immutable first_sequence; source is the first event's source.
    /// Summary timestamps are server receipt times, not client-supplied event times.
    pub async fn list_sessions(&self, limit: usize, before: Option<i64>) -> Result<Value> {
        validate_page(limit, None)?;
        ensure!(
            before.is_none_or(|cursor| cursor > 0),
            "invalid session cursor"
        );
        self.blocking(move |connection, _| {
            if let Some(cursor) = before {
                let exists: bool = connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM sessions WHERE first_sequence = ?1)",
                    [cursor],
                    |row| row.get(0),
                )?;
                ensure!(exists, "session pagination cursor does not exist");
            }
            let mut statement = connection.prepare(
                "SELECT session_id, source, first_sequence, last_sequence, event_count,
                        started_at, updated_at
                 FROM sessions WHERE (?1 IS NULL OR first_sequence < ?1)
                 ORDER BY first_sequence DESC LIMIT ?2",
            )?;
            let rows = statement.query_map(params![before, (limit + 1) as i64], |row| {
                Ok(json!({
                    "session_id": row.get::<_, String>(0)?,
                    "source": row.get::<_, String>(1)?,
                    "first_sequence": row.get::<_, i64>(2)?,
                    "last_sequence": row.get::<_, i64>(3)?,
                    "event_count": row.get::<_, i64>(4)?,
                    "started_at": row.get::<_, String>(5)?,
                    "updated_at": row.get::<_, String>(6)?,
                }))
            })?;
            let mut sessions = rows.collect::<rusqlite::Result<Vec<_>>>()?;
            let has_more = sessions.len() > limit;
            sessions.truncate(limit);
            let next = has_more.then(|| sessions.last().unwrap()["first_sequence"].clone());
            Ok(json!({"sessions": sessions, "next_before": next}))
        })
        .await
    }

    /// Ascending ingestion sequence, bounded by both row count and aggregate event bytes.
    /// Missing sessions return an empty page. No event is ever split or truncated.
    pub async fn session_events(
        &self,
        session_id: &str,
        limit: usize,
        after: u64,
    ) -> Result<Value> {
        validate_identifier(session_id, 128, "session id")?;
        validate_page(limit, None)?;
        let after = i64::try_from(after).context("session event cursor is out of range")?;
        let session_id = session_id.to_owned();
        self.blocking(move |connection, _| {
            let mut statement = connection.prepare(
                "SELECT sequence, received_at, event_json FROM session_events
                 WHERE session_id = ?1 AND sequence > ?2 ORDER BY sequence ASC LIMIT ?3",
            )?;
            let mut rows = statement.query(params![session_id, after, (limit + 1) as i64])?;
            let mut events = Vec::new();
            let mut remaining = MAX_SESSION_EVENT_BYTES;
            let mut has_more = false;
            while let Some(row) = rows.next()? {
                if events.len() == limit {
                    has_more = true;
                    break;
                }
                let encoded = row.get_ref(2)?.as_str()?;
                ensure!(
                    encoded.len() <= MAX_SESSION_EVENT_BYTES,
                    "stored session event exceeds {MAX_SESSION_EVENT_BYTES} bytes"
                );
                if encoded.len() > remaining {
                    has_more = true;
                    break;
                }
                remaining -= encoded.len();
                let event = crate::json::from_slice(encoded.as_bytes())?;
                let event_id = event["id"]
                    .as_str()
                    .context("stored session event is missing its id")?;
                let mut acquisitions = connection.prepare(
                    "SELECT a.source_path, a.source_digest, a.member_path,
                            a.source_position, a.observed_at
                     FROM import_acquisitions a
                     JOIN import_snapshots s ON s.snapshot_id = a.snapshot_id
                     WHERE s.event_id = ?1
                     ORDER BY a.observed_at, a.source_path, a.member_path LIMIT 101",
                )?;
                let acquisition_rows = acquisitions.query_map([event_id], |row| {
                    let mut receipt = serde_json::Map::new();
                    receipt.insert("source_path".to_owned(), Value::String(row.get(0)?));
                    for (name, index) in [("source_digest", 1), ("member_path", 2), ("position", 3)]
                    {
                        let value: String = row.get(index)?;
                        if !value.is_empty() {
                            receipt.insert(name.to_owned(), Value::String(value));
                        }
                    }
                    receipt.insert("observed_at".to_owned(), Value::String(row.get(4)?));
                    Ok(Value::Object(receipt))
                })?;
                let acquisition_rows = acquisition_rows.collect::<rusqlite::Result<Vec<_>>>()?;
                let has_acquisitions = !acquisition_rows.is_empty();
                let mut provenance_truncated = acquisition_rows.len() > 100;
                let mut provenance = Vec::new();
                for receipt in acquisition_rows.into_iter().take(100) {
                    let size = serde_json::to_vec(&receipt)?.len() + 64;
                    if size > remaining {
                        provenance_truncated = true;
                        break;
                    }
                    remaining -= size;
                    provenance.push(receipt);
                }
                let mut entry = serde_json::Map::new();
                entry.insert("sequence".to_owned(), Value::from(row.get::<_, i64>(0)?));
                entry.insert("received_at".to_owned(), Value::String(row.get(1)?));
                entry.insert("event".to_owned(), event);
                if has_acquisitions {
                    entry.insert("acquisitions".to_owned(), Value::Array(provenance));
                    entry.insert(
                        "acquisitions_truncated".to_owned(),
                        Value::Bool(provenance_truncated),
                    );
                }
                events.push(Value::Object(entry));
            }
            let next = has_more.then(|| events.last().unwrap()["sequence"].clone());
            let mut page = serde_json::Map::new();
            page.insert("events".to_owned(), Value::Array(events));
            page.insert("next_after".to_owned(), next.unwrap_or(Value::Null));
            Ok(Value::Object(page))
        })
        .await
    }

    /// Distinct locally available inference traces linked by this session's events.
    pub async fn session_traces(
        &self,
        session_id: &str,
        limit: usize,
        before: Option<String>,
    ) -> Result<Value> {
        validate_identifier(session_id, 128, "session id")?;
        validate_page(limit, before.as_deref())?;
        let session_id = session_id.to_owned();
        self.blocking(move |connection, root| {
            let cursor = trace_cursor(connection, before.as_deref())?;
            let mut statement = connection.prepare(
                "SELECT id, metadata, complete, status, response_headers, error, completed_at
                 FROM traces
                 WHERE (?1 IS NULL OR sequence < ?1)
                   AND id IN (SELECT trace_id FROM session_events WHERE session_id = ?2)
                 ORDER BY sequence DESC LIMIT ?3",
            )?;
            let rows = statement.query_map(
                params![cursor, session_id, (limit + 1) as i64],
                read_indexed_trace,
            )?;
            let mut traces = rows.collect::<rusqlite::Result<Vec<_>>>()?;
            let has_more = traces.len() > limit;
            traces.truncate(limit);
            let next = if has_more {
                traces.last().map(|trace| trace.id.clone())
            } else {
                None
            };
            let traces = traces
                .into_iter()
                .map(|trace| describe_trace(root, trace))
                .collect::<Result<Vec<_>>>()?;
            Ok(json!({"traces": traces, "next_before": next}))
        })
        .await
    }

    pub async fn get(&self, id: &str) -> Result<Option<Value>> {
        validate_id(id)?;
        let id = id.to_owned();
        self.blocking(move |connection, root| {
            find_trace(connection, &id)?
                .map(|row| describe_trace(root, row))
                .transpose()
        })
        .await
    }

    pub async fn body(&self, id: &str, kind: &str) -> Result<Option<File>> {
        validate_id(id)?;
        let index = body_index(kind)?;
        let id = id.to_owned();
        let file = self
            .blocking(move |connection, root| {
                let exists: bool = connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM traces WHERE id = ?1)",
                    [&id],
                    |row| row.get(0),
                )?;
                if !exists {
                    return Ok(None);
                }
                open_body(root, &id, index)
            })
            .await?;
        Ok(file.map(File::from_std))
    }

    /// Exported trace rows retain metadata and every available body. JSON bodies use
    /// `{encoding: "json", data: value}`; all other bytes (including SSE) use
    /// `{encoding: "base64", data: string}`. Exact JSON bytes remain in body().
    /// Incomplete rows are explicitly marked and expose their current on-disk
    /// bytes, not an assertion that the request or response finished.
    pub async fn export(&self, limit: usize, before: Option<String>) -> Result<Vec<Value>> {
        validate_page(limit, before.as_deref())?;
        let rows = self
            .blocking(move |connection, _| select_traces(connection, limit, before.as_deref()))
            .await?;
        let root = self.inner.root.clone();
        // File reading and JSON encoding must not hold the inference index lock.
        tokio::task::spawn_blocking(move || {
            let mut remaining = MAX_EXPORT_BODY_BYTES;
            let mut result = Vec::with_capacity(rows.len());
            for row in rows {
                let id = row.id.clone();
                let complete = row.complete;
                let metadata = describe_trace(&root, row)?;
                let mut bodies = serde_json::Map::new();
                for (index, kind) in BODY_KINDS.iter().enumerate() {
                    let Some(file) = open_body(&root, &id, index)? else {
                        ensure!(!complete || index >= 2, "completed trace {id} is missing its {kind} body");
                        continue;
                    };
                    let size = file.metadata()?.len();
                    ensure!(size <= remaining, "trace export exceeds {MAX_EXPORT_BODY_BYTES} raw body bytes; request fewer rows or download individual bodies");
                    let mut bytes = Vec::with_capacity(size as usize);
                    // A live incomplete writer may append after metadata(). Read
                    // at most the remaining budget plus one, then reject if it
                    // grew past the cap rather than returning a truncated body.
                    file.take(remaining + 1)
                        .read_to_end(&mut bytes)
                        .with_context(|| format!("read {kind} body for export"))?;
                    ensure!(bytes.len() as u64 <= remaining, "trace export exceeds {MAX_EXPORT_BODY_BYTES} raw body bytes; request fewer rows or download individual bodies");
                    remaining -= bytes.len() as u64;
                    let size = bytes.len();
                    let (encoding, data) = match crate::json::from_slice(&bytes) {
                        Ok(data) => ("json", data),
                        Err(_) => ("base64", Value::String(STANDARD.encode(&bytes))),
                    };
                    let mut body = serde_json::Map::new();
                    body.insert("encoding".to_owned(), Value::String(encoding.to_owned()));
                    body.insert("size".to_owned(), Value::from(size));
                    body.insert("data".to_owned(), data);
                    bodies.insert((*kind).to_owned(), Value::Object(body));
                }
                let mut exported = serde_json::Map::new();
                exported.insert("metadata".to_owned(), metadata);
                exported.insert("bodies".to_owned(), Value::Object(bodies));
                result.push(Value::Object(exported));
            }
            Ok(result)
        })
        .await.context("trace export worker failed")?
    }
}
pub struct OwnedFile {
    pub id: String,
    pub bytes: i64,
    pub created_at: i64,
    pub filename: String,
    pub purpose: String,
    pub digest: String,
}

impl OwnedFile {
    pub fn json(&self) -> Value {
        json!({
            "id": self.id,
            "object": "file",
            "bytes": self.bytes,
            "created_at": self.created_at,
            "filename": self.filename,
            "purpose": self.purpose,
            "status": "stored",
            "provider_file_id": Value::Null,
        })
    }
}

pub(crate) fn is_infer_file_id(id: &str) -> bool {
    let Some(rest) = id.strip_prefix("file-") else {
        return false;
    };
    rest.len() == 32 && rest.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_file_id(id: &str) -> Result<()> {
    ensure!(is_infer_file_id(id), "invalid infer file id");
    Ok(())
}

fn file_row(connection: &Connection, id: &str) -> Result<Option<OwnedFile>> {
    let mut statement = connection.prepare(
        "SELECT id, size, created_at, filename, purpose, digest FROM files WHERE id = ?1",
    )?;
    let mut rows = statement.query([id])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    Ok(Some(OwnedFile {
        id: row.get(0)?,
        bytes: row.get(1)?,
        created_at: row.get(2)?,
        filename: row.get(3)?,
        purpose: row.get(4)?,
        digest: row.get(5)?,
    }))
}

impl TraceWriter {
    /// Resolve an initially automatic route after the accepted request has been
    /// recorded, and persist the resolved route before any upstream request.
    pub async fn route(
        &mut self,
        provider: &str,
        upstream_url: &str,
        mut upstream_headers: Value,
    ) -> Result<()> {
        ensure!(
            !self.failed,
            "trace writer previously failed or was interrupted"
        );
        self.failed = true;
        redact_headers(&mut upstream_headers);
        let provider = provider.to_owned();
        let upstream_url = upstream_url.to_owned();
        let id = self.id.clone();
        self.store
            .blocking(move |connection, _| {
                let source: String = connection.query_row(
                    "SELECT metadata FROM traces WHERE id = ?1 AND complete = 0",
                    [&id],
                    |row| row.get(0),
                )?;
                let mut metadata = crate::json::from_slice(source.as_bytes())?;
                metadata["provider"] = Value::String(provider);
                metadata["upstream_url"] = Value::String(upstream_url);
                metadata["upstream_headers"] = upstream_headers;
                let metadata = bounded_json(&metadata)?;
                let changed = connection.execute(
                    "UPDATE traces SET metadata = ?1 WHERE id = ?2 AND complete = 0",
                    params![metadata, id],
                )?;
                ensure!(changed == 1, "trace route update lost its incomplete row");
                Ok(())
            })
            .await?;
        self.failed = false;
        Ok(())
    }

    pub async fn request(&mut self, chunk: &[u8]) -> Result<()> {
        self.append(0, chunk).await
    }

    pub async fn response(&mut self, chunk: &[u8]) -> Result<()> {
        self.append(1, chunk).await
    }

    pub async fn upstream_request(&mut self, chunk: &[u8]) -> Result<()> {
        self.append(2, chunk).await
    }

    pub async fn upstream_response(&mut self, chunk: &[u8]) -> Result<()> {
        self.append(3, chunk).await
    }

    async fn append(&mut self, index: usize, chunk: &[u8]) -> Result<()> {
        ensure!(
            !self.failed,
            "trace writer previously failed or was interrupted"
        );
        // Set before the first await so cancellation also prevents completion.
        self.failed = true;
        if self.files[index].is_none() {
            let path = self.store.inner.root.join(&self.id).join(BODY_FILES[index]);
            let mut options = tokio::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            self.files[index] = Some(
                options
                    .open(path)
                    .await
                    .context("create upstream trace body")?,
            );
        }
        let file = self.files[index]
            .as_mut()
            .context("trace body writer missing")?;
        file.write_all(chunk).await.context("write trace body")?;
        // Tokio can acknowledge a buffered write before the underlying blocking
        // write finishes. Flush here so the proxy never forwards a chunk whose
        // disk write has already failed. finish() additionally fsyncs all files.
        file.flush().await.context("flush trace body")?;
        self.failed = false;
        Ok(())
    }

    pub async fn finish(
        mut self,
        status: u16,
        mut response_headers: Value,
        error: Option<String>,
    ) -> Result<()> {
        ensure!(
            !self.failed,
            "cannot complete a failed or interrupted trace writer"
        );
        redact_headers(&mut response_headers);
        let response_headers = bounded_json(&response_headers)?;
        ensure!(
            error.as_ref().map_or(0, String::len) <= MAX_METADATA_BYTES,
            "trace error metadata exceeds {MAX_METADATA_BYTES} bytes"
        );
        for file in self.files.iter_mut().flatten() {
            file.flush().await.context("flush completed trace body")?;
            file.sync_all().await.context("sync completed trace body")?;
        }
        let id = self.id;
        self.store
            .blocking(move |connection, root| {
                // Persist file names and directory entry before the SQLite
                // commit that advertises completion (WAL + synchronous=FULL).
                sync_directory(&root.join(&id))?;
                sync_directory(root)?;
                let changed = connection
                    .execute(
                        "UPDATE traces SET complete = 1, status = ?1,
                     response_headers = ?2, error = ?3, completed_at = ?4
                     WHERE id = ?5 AND complete = 0",
                        params![status, response_headers, error, timestamp(), id],
                    )
                    .context("commit trace completion")?;
                ensure!(changed == 1, "trace completion lost its incomplete row");
                Ok(())
            })
            .await
    }
}

fn timestamp() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

fn validate_identifier(value: &str, max_bytes: usize, name: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= max_bytes
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte)),
        "{name} must contain 1..={max_bytes} ASCII letters, digits, underscores, dots, or hyphens"
    );
    Ok(())
}

fn validate_id(id: &str) -> Result<Uuid> {
    let parsed = Uuid::parse_str(id).context("trace id must be a canonical UUID")?;
    let mut buffer = Uuid::encode_buffer();
    ensure!(
        parsed.hyphenated().encode_lower(&mut buffer) == id,
        "trace id must be a canonical lowercase UUID"
    );
    Ok(parsed)
}

fn body_index(kind: &str) -> Result<usize> {
    BODY_KINDS
        .iter()
        .position(|allowed| *allowed == kind)
        .context("body kind must be request, response, upstream_request, or upstream_response")
}

fn validate_page(limit: usize, before: Option<&str>) -> Result<()> {
    ensure!(
        (1..=MAX_TRACE_ROWS).contains(&limit),
        "trace row limit must be between 1 and {MAX_TRACE_ROWS}"
    );
    if let Some(id) = before {
        validate_id(id)?;
    }
    Ok(())
}

fn bounded_json(value: &Value) -> Result<String> {
    let encoded = serde_json::to_string(value)?;
    ensure!(
        encoded.len() <= MAX_METADATA_BYTES,
        "trace metadata exceeds {MAX_METADATA_BYTES} bytes"
    );
    Ok(encoded)
}

fn redact_headers(headers: &mut Value) {
    match headers {
        Value::Object(object) => {
            let named_secret = ["name", "key"].iter().any(|key| {
                object
                    .get(*key)
                    .and_then(Value::as_str)
                    .is_some_and(is_sensitive_header)
            });
            for (name, value) in object.iter_mut() {
                if is_sensitive_header(name)
                    || (named_secret && matches!(name.as_str(), "value" | "values"))
                {
                    *value = Value::String("[REDACTED]".to_owned());
                } else {
                    redact_headers(value);
                }
            }
        }
        Value::Array(array) => {
            if array.len() == 2 && array[0].as_str().is_some_and(is_sensitive_header) {
                array[1] = Value::String("[REDACTED]".to_owned());
            } else {
                for value in array {
                    redact_headers(value);
                }
            }
        }
        _ => {}
    }
}

fn read_indexed_trace(row: &rusqlite::Row<'_>) -> rusqlite::Result<IndexedTrace> {
    Ok(IndexedTrace {
        id: row.get(0)?,
        metadata: row.get(1)?,
        complete: row.get(2)?,
        status: row.get(3)?,
        response_headers: row.get(4)?,
        error: row.get(5)?,
        completed_at: row.get(6)?,
    })
}

fn find_trace(connection: &Connection, id: &str) -> Result<Option<IndexedTrace>> {
    connection
        .query_row(
            "SELECT id, metadata, complete, status, response_headers, error, completed_at
         FROM traces WHERE id = ?1",
            [id],
            read_indexed_trace,
        )
        .optional()
        .context("inspect trace metadata")
}

fn select_traces(
    connection: &Connection,
    limit: usize,
    before: Option<&str>,
) -> Result<Vec<IndexedTrace>> {
    let cursor = trace_cursor(connection, before)?;
    let mut statement = connection.prepare(
        "SELECT id, metadata, complete, status, response_headers, error, completed_at
         FROM traces WHERE (?1 IS NULL OR sequence < ?1)
         ORDER BY sequence DESC LIMIT ?2",
    )?;
    let rows = statement.query_map(params![cursor, limit as i64], read_indexed_trace)?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("list trace metadata")
}

fn trace_cursor(connection: &Connection, before: Option<&str>) -> Result<Option<i64>> {
    before
        .map(|id| {
            connection
                .query_row("SELECT sequence FROM traces WHERE id = ?1", [id], |row| {
                    row.get(0)
                })
                .optional()?
                .context("trace pagination cursor does not exist")
        })
        .transpose()
}

fn describe_trace(root: &Path, row: IndexedTrace) -> Result<Value> {
    validate_id(&row.id)?;
    let mut value =
        crate::json::from_slice(row.metadata.as_bytes()).context("decode stored trace metadata")?;
    ensure!(value.is_object(), "stored trace metadata is not an object");
    value["complete"] = Value::Bool(row.complete);
    value["status"] = row.status.map_or(Value::Null, |status| json!(status));
    value["completed_at"] = row.completed_at.map_or(Value::Null, Value::String);
    value["error"] = row.error.map_or(Value::Null, Value::String);
    value["response_headers"] = row
        .response_headers
        .map(|headers| crate::json::from_slice(headers.as_bytes()))
        .transpose()?
        .unwrap_or(Value::Null);
    let mut bodies = serde_json::Map::new();
    for (index, kind) in BODY_KINDS.iter().enumerate() {
        if let Some(file) = open_body(root, &row.id, index)? {
            bodies.insert(
                (*kind).to_owned(),
                json!({
                    "size": file.metadata()?.len(),
                    "file": format!("{}/{}", row.id, BODY_FILES[index]),
                }),
            );
        }
    }
    value["bodies"] = Value::Object(bodies);
    Ok(value)
}

fn create_private_directory(path: &Path, recursive: bool) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(recursive);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => {}
        Err(error) if recursive && error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error).context("create private trace directory"),
    }
    let metadata = fs::symlink_metadata(path).context("inspect trace directory")?;
    ensure!(
        metadata.file_type().is_dir(),
        "trace directory must be a real directory, not a symlink"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn create_private_file(path: &Path) -> Result<StdFile> {
    let mut options = OpenOptions::new();
    options.write(true).read(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).context("create private trace file")
}

fn create_private_database(path: &Path) -> Result<()> {
    match create_private_file(path) {
        Ok(file) => file.sync_all().context("sync new trace index")?,
        Err(error)
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|error| error.kind() == io::ErrorKind::AlreadyExists) =>
        {
            protect_existing_file(path)?;
        }
        Err(error) => return Err(error),
    }
    Ok(())
}

fn protect_existing_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_file(),
        "trace index and sidecars must be regular files, not symlinks"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn protect_sidecars(root: &Path) -> Result<()> {
    for name in [
        "index.sqlite3-wal",
        "index.sqlite3-shm",
        "index.sqlite3-journal",
    ] {
        let path = root.join(name);
        match protect_existing_file(&path) {
            Ok(()) => {}
            Err(error)
                if error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|error| error.kind() == io::ErrorKind::NotFound) => {}
            Err(error) => return Err(error).context("protect trace index sidecar"),
        }
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).context("inspect trace directory before sync")?;
    ensure!(
        metadata.file_type().is_dir(),
        "trace directory must not be replaced with a symlink"
    );
    StdFile::open(path)?
        .sync_all()
        .context("sync trace directory")
}

fn open_body(root: &Path, id: &str, index: usize) -> Result<Option<StdFile>> {
    let directory = root.join(id);
    match fs::symlink_metadata(&directory) {
        Ok(metadata) => ensure!(
            metadata.file_type().is_dir(),
            "trace body directory must not be a symlink"
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect trace body directory"),
    }
    let path = directory.join(BODY_FILES[index]);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect trace body file"),
    };
    ensure!(
        metadata.file_type().is_file(),
        "trace body must be a regular file, not a symlink"
    );
    let file = StdFile::open(&path).context("open trace body")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = file.metadata()?;
        ensure!(
            metadata.dev() == opened.dev() && metadata.ino() == opened.ino(),
            "trace body changed while opening"
        );
    }
    Ok(Some(file))
}

fn validate_import_snapshot(snapshot: &ImportSnapshot) -> Result<()> {
    ensure!(
        matches!(
            snapshot.adapter.as_str(),
            "omp"
                | "claude_code"
                | "codex"
                | "grok_build"
                | "chatgpt_export"
                | "claude_export"
                | "grok_export"
                | "provider_export_attachment"
        ),
        "unsupported import adapter"
    );
    for (name, value) in [
        ("adapter", snapshot.adapter.as_str()),
        ("event source", snapshot.event_source.as_str()),
        ("payload schema", snapshot.payload_schema.as_str()),
        ("source namespace", snapshot.source_namespace.as_str()),
        ("native session id", snapshot.native_session_id.as_str()),
        ("stream", snapshot.stream.as_str()),
        ("native record id", snapshot.native_record_id.as_str()),
        ("source format", snapshot.format.as_str()),
        ("position", snapshot.position.as_str()),
        ("parse status", snapshot.parse_status.as_str()),
        ("source path", snapshot.acquisition.source_path.as_str()),
    ] {
        ensure!(!value.is_empty(), "{name} must not be empty");
        ensure!(value.len() <= 4096, "{name} exceeds 4096 bytes");
        ensure!(
            !value.chars().any(char::is_control),
            "{name} contains control characters"
        );
    }
    if let Some(digest) = &snapshot.acquisition.source_digest {
        validate_digest(digest)?;
    }
    for (name, value) in [
        ("member path", snapshot.acquisition.member_path.as_deref()),
        ("source position", snapshot.acquisition.position.as_deref()),
    ] {
        if let Some(value) = value {
            ensure!(!value.is_empty(), "{name} must not be empty");
            ensure!(value.len() <= 4096, "{name} exceeds 4096 bytes");
            ensure!(
                !value.chars().any(char::is_control),
                "{name} contains control characters"
            );
        }
    }
    if let Some(occurred_at) = &snapshot.occurred_at {
        chrono::DateTime::parse_from_rfc3339(occurred_at)
            .context("native occurrence time must be RFC3339")?;
    }
    Ok(())
}

fn validate_digest(digest: &str) -> Result<()> {
    ensure!(
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "invalid SHA-256 artifact digest"
    );
    Ok(())
}

fn artifact_path(root: &Path, digest: &str) -> PathBuf {
    root.join("artifacts")
        .join("sha256")
        .join(&digest[..2])
        .join(digest)
}

fn persist_artifact(root: &Path, bytes: &[u8]) -> Result<(String, i64)> {
    let digest = format!("{:x}", Sha256::digest(bytes));
    let size = i64::try_from(bytes.len()).context("artifact size exceeds SQLite range")?;
    let path = artifact_path(root, &digest);
    let parent = path.parent().context("artifact path has no parent")?;
    create_private_directory(parent, true)?;
    if let Some(existing) = open_artifact(root, &digest)? {
        verify_artifact(existing, &digest, size)?;
        return Ok((digest, size));
    }
    let temporary = parent.join(format!(".tmp-{}", Uuid::new_v4()));
    let mut file = create_private_file(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    match fs::hard_link(&temporary, &path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let existing = open_artifact(root, &digest)?
                .context("artifact appeared without a readable regular file")?;
            verify_artifact(existing, &digest, size)?;
        }
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            return Err(error).context("publish imported artifact");
        }
    }
    fs::remove_file(&temporary)?;
    sync_directory(parent)?;
    if let Some(grandparent) = parent.parent() {
        sync_directory(grandparent)?;
    }
    Ok((digest, size))
}

fn persist_artifact_file(root: &Path, source: &Path, max_bytes: u64) -> Result<(String, i64)> {
    ensure!(max_bytes > 0, "artifact byte limit must be positive");
    let source_metadata = fs::symlink_metadata(source).context("inspect source artifact")?;
    ensure!(
        source_metadata.file_type().is_file(),
        "source artifact must be a regular file, not a symlink"
    );
    ensure!(
        source_metadata.len() <= max_bytes,
        "artifact exceeds configured {max_bytes} byte limit"
    );
    let mut input = StdFile::open(source).context("open source artifact")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = input.metadata()?;
        ensure!(
            source_metadata.dev() == opened.dev() && source_metadata.ino() == opened.ino(),
            "source artifact changed while opening"
        );
    }
    let staging = root
        .join("artifacts")
        .join(format!(".tmp-{}", Uuid::new_v4()));
    let mut output = create_private_file(&staging)?;
    let result = (|| -> Result<(String, i64)> {
        let mut hash = Sha256::new();
        let mut size = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let read = input.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            size = size
                .checked_add(read as u64)
                .context("artifact size overflow")?;
            ensure!(
                size <= max_bytes,
                "artifact grew beyond configured {max_bytes} byte limit"
            );
            hash.update(&buffer[..read]);
            output.write_all(&buffer[..read])?;
        }
        let final_metadata = input.metadata()?;
        ensure!(
            final_metadata.len() == size
                && size == source_metadata.len()
                && final_metadata.modified().ok() == source_metadata.modified().ok(),
            "source artifact changed during import"
        );
        output.sync_all()?;
        let digest = format!("{:x}", hash.finalize());
        let path = artifact_path(root, &digest);
        let parent = path.parent().context("artifact path has no parent")?;
        create_private_directory(parent, true)?;
        match fs::hard_link(&staging, &path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let existing = open_artifact(root, &digest)?
                    .context("artifact appeared without a readable regular file")?;
                verify_artifact(existing, &digest, i64::try_from(size)?)?;
            }
            Err(error) => return Err(error).context("publish imported artifact"),
        }
        sync_directory(parent)?;
        if let Some(grandparent) = parent.parent() {
            sync_directory(grandparent)?;
        }
        Ok((digest, i64::try_from(size)?))
    })();
    let cleanup = fs::remove_file(&staging).context("remove artifact staging file");
    match (result, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

fn verify_artifact(mut file: StdFile, digest: &str, size: i64) -> Result<()> {
    ensure!(
        file.metadata()?.len() == u64::try_from(size)?,
        "content-addressed artifact size does not match its index"
    );
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    ensure!(
        format!("{:x}", hash.finalize()) == digest,
        "content-addressed artifact does not match its digest"
    );
    Ok(())
}

fn open_artifact(root: &Path, digest: &str) -> Result<Option<StdFile>> {
    validate_digest(digest)?;
    let path = artifact_path(root, digest);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect imported artifact"),
    };
    ensure!(
        metadata.file_type().is_file(),
        "imported artifact must be a regular file, not a symlink"
    );
    let file = StdFile::open(&path).context("open imported artifact")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = file.metadata()?;
        ensure!(
            metadata.dev() == opened.dev() && metadata.ino() == opened.ino(),
            "imported artifact changed while opening"
        );
    }
    Ok(Some(file))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    const FIRST: &str = "00000000-0000-4000-8000-000000000001";
    const SECOND: &str = "00000000-0000-4000-8000-000000000002";
    const THIRD: &str = "00000000-0000-4000-8000-000000000003";

    fn event(id: &str, session_id: &str) -> SessionEvent {
        SessionEvent {
            id: id.to_owned(),
            session_id: session_id.to_owned(),
            source: "omp".to_owned(),
            kind: "tool_execution_end".to_owned(),
            occurred_at: "2026-10-22T12:34:56.123456Z".to_owned(),
            trace_id: None,
            payload: json!({"output": "complete tool output", "success": true}),
        }
    }

    #[tokio::test]
    async fn session_event_retries_are_canonical_idempotent_and_conflicts_are_typed() {
        let temp = tempfile::tempdir().unwrap();
        let store = TraceStore::open(temp.path()).await.unwrap();
        let original = event(FIRST, "session-a");
        let receipt = store.put_event(original.clone()).await.unwrap();
        assert_eq!(receipt["id"], FIRST);
        assert_eq!(receipt, store.put_event(original.clone()).await.unwrap());
        let wire = format!(
            r#"{{"payload":{{"success":true,"output":"complete tool output"}},"occurred_at":"2026-10-22T12:34:56.123456Z","kind":"tool_execution_end","source":"omp","session_id":"session-a","id":"{FIRST}"}}"#
        );
        let decoded = SessionEvent::decode(wire.as_bytes()).unwrap();
        assert_eq!(receipt, store.put_event(decoded).await.unwrap());
        let mut changed = original.clone();
        changed.payload["output"] = json!("changed");
        let error = store.put_event(changed).await.unwrap_err();
        assert_eq!(error.downcast_ref::<EventConflict>().unwrap().id, FIRST);
        let mut changed = original;
        changed.session_id = "other-session".to_owned();
        assert!(
            store
                .put_event(changed)
                .await
                .unwrap_err()
                .is::<EventConflict>()
        );
        let sessions = store.list_sessions(50, None).await.unwrap();
        assert_eq!(sessions["sessions"].as_array().unwrap().len(), 1);
        assert_eq!(sessions["sessions"][0]["event_count"], 1);
        let saved = store.session_events("session-a", 50, 0).await.unwrap();
        assert_eq!(saved["events"].as_array().unwrap().len(), 1);
        assert_eq!(
            saved["events"][0]["event"]["payload"]["output"],
            "complete tool output"
        );
        assert_eq!(saved["events"][0]["sequence"], receipt["sequence"]);
        assert!(
            chrono::DateTime::parse_from_rfc3339(
                saved["events"][0]["received_at"].as_str().unwrap()
            )
            .is_ok()
        );
    }

    #[tokio::test]
    async fn session_pages_remain_stable_when_existing_sessions_receive_events() {
        let temp = tempfile::tempdir().unwrap();
        let store = TraceStore::open(temp.path()).await.unwrap();
        let first = store.put_event(event(FIRST, "a")).await.unwrap();
        store.put_event(event(SECOND, "b")).await.unwrap();
        store.put_event(event(THIRD, "c")).await.unwrap();
        let newest = store.list_sessions(1, None).await.unwrap();
        assert_eq!(newest["sessions"][0]["session_id"], "c");
        let cursor = newest["next_before"].as_i64().unwrap();
        let later = store
            .put_event(event(&Uuid::new_v4().to_string(), "a"))
            .await
            .unwrap();
        store
            .put_event(event(&Uuid::new_v4().to_string(), "d"))
            .await
            .unwrap();
        let rest = store.list_sessions(50, Some(cursor)).await.unwrap();
        assert_eq!(
            rest["sessions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|session| session["session_id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["b", "a"]
        );
        assert_eq!(rest["sessions"][1]["first_sequence"], first["sequence"]);
        assert_eq!(rest["sessions"][1]["last_sequence"], later["sequence"]);
        assert_eq!(rest["sessions"][1]["event_count"], 2);
        assert!(rest["next_before"].is_null());
        let page = store.session_events("a", 1, 0).await.unwrap();
        assert_eq!(page["events"][0]["sequence"], first["sequence"]);
        assert_eq!(page["next_after"], first["sequence"]);
        let page = store
            .session_events("a", 1, page["next_after"].as_u64().unwrap())
            .await
            .unwrap();
        assert_eq!(page["events"][0]["sequence"], later["sequence"]);
        assert!(page["next_after"].is_null());
        for session in ["b", "c", "d"] {
            let page = store.session_events(session, 50, 0).await.unwrap();
            assert_eq!(page["events"].as_array().unwrap().len(), 1);
            assert_eq!(page["events"][0]["event"]["session_id"], session);
        }
        assert!(
            store.session_events("missing", 50, 0).await.unwrap()["events"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(store.list_sessions(0, None).await.is_err());
        assert!(store.list_sessions(1, Some(9999)).await.is_err());
        assert!(store.list_sessions(1, Some(0)).await.is_err());
        assert!(store.session_events("a", 101, 0).await.is_err());
        assert!(store.session_events("a", 1, u64::MAX).await.is_err());
        assert!(store.session_events("../a", 1, 0).await.is_err());
    }

    #[tokio::test]
    async fn session_event_size_cap_preserves_one_full_event_and_paginates_before_aggregate_overflow()
     {
        let temp = tempfile::tempdir().unwrap();
        let store = TraceStore::open(temp.path()).await.unwrap();
        let mut large = event(FIRST, "large");
        large.payload = Value::String(String::new());
        let overhead = serde_json::to_vec(&large).unwrap().len();
        large.payload = Value::String("x".repeat(MAX_SESSION_EVENT_BYTES - overhead));
        large.validate().unwrap();
        let mut oversized = large.clone();
        if let Value::String(text) = &mut oversized.payload {
            text.push('x');
        }
        assert!(
            oversized
                .validate()
                .unwrap_err()
                .is::<InvalidSessionEvent>()
        );
        assert!(
            store
                .put_event(oversized)
                .await
                .unwrap_err()
                .is::<InvalidSessionEvent>()
        );
        let first = store.put_event(large).await.unwrap();
        store.put_event(event(SECOND, "large")).await.unwrap();
        let page = store.session_events("large", 50, 0).await.unwrap();
        assert_eq!(page["events"].as_array().unwrap().len(), 1);
        assert_eq!(
            page["events"][0]["event"]["payload"]
                .as_str()
                .unwrap()
                .len(),
            MAX_SESSION_EVENT_BYTES - overhead
        );
        assert_eq!(page["next_after"], first["sequence"]);
        let page = store
            .session_events("large", 50, first["sequence"].as_u64().unwrap())
            .await
            .unwrap();
        assert_eq!(page["events"][0]["event"]["id"], SECOND);
        assert!(page["next_after"].is_null());
    }

    #[tokio::test]
    async fn session_payload_preserves_literal_serde_tokens_and_arbitrary_precision() {
        let temp = tempfile::tempdir().unwrap();
        let store = TraceStore::open(temp.path()).await.unwrap();
        let wire = format!(
            r#"{{"id":"{FIRST}","session_id":"literal","source":"omp","kind":"message_update","occurred_at":"2026-10-22T00:00:00Z","payload":{{"$serde_json::private::Number":"123","nested":[{{"$serde_json::private::RawValue":"{{\"literal\":true}}"}}],"precise":123456789012345678901234567890.1234567890123456789}}}}"#
        );
        let original = SessionEvent::decode(wire.as_bytes()).unwrap();
        let expected = original.payload.clone();
        store.put_event(original).await.unwrap();
        let page = store.session_events("literal", 50, 0).await.unwrap();
        assert_eq!(page["events"][0]["event"]["payload"], expected);
        assert_eq!(expected["$serde_json::private::Number"], "123");
        assert_eq!(
            expected["precise"].to_string(),
            "123456789012345678901234567890.1234567890123456789"
        );
    }

    #[test]
    fn session_event_validation_rejects_unknown_fields_invalid_identifiers_and_timestamps() {
        let valid = event(FIRST, &"a".repeat(128));
        valid.validate().unwrap();
        for (field, replacement) in [
            ("id", "00000000-0000-1000-8000-000000000001"),
            ("id", "00000000000040008000000000000001"),
            ("id", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"),
            ("session_id", ""),
            ("session_id", "../escape"),
            ("session_id", "non-ascii-é"),
            ("source", "not allowed"),
            ("kind", "tool/execution"),
            ("occurred_at", "2026-10-22"),
            ("trace_id", "not-a-uuid"),
        ] {
            let mut wire = serde_json::to_value(&valid).unwrap();
            wire[field] = json!(replacement);
            let invalid = SessionEvent::decode(&serde_json::to_vec(&wire).unwrap()).unwrap();
            assert!(
                invalid.validate().is_err(),
                "{field} accepted {replacement}"
            );
        }
        for field in ["session_id", "source", "kind"] {
            let mut wire = serde_json::to_value(&valid).unwrap();
            wire[field] = json!("a".repeat(129));
            assert!(
                SessionEvent::decode(&serde_json::to_vec(&wire).unwrap())
                    .unwrap()
                    .validate()
                    .is_err()
            );
        }
        let mut unknown = serde_json::to_value(&valid).unwrap();
        unknown["unknown"] = json!(true);
        assert!(SessionEvent::decode(&serde_json::to_vec(&unknown).unwrap()).is_err());
        let mut missing = serde_json::to_value(&valid).unwrap();
        missing.as_object_mut().unwrap().remove("payload");
        assert!(SessionEvent::decode(&serde_json::to_vec(&missing).unwrap()).is_err());
    }

    #[tokio::test]
    async fn session_traces_are_distinct_isolated_and_use_existing_trace_pagination() {
        let temp = tempfile::tempdir().unwrap();
        let store = TraceStore::open(temp.path()).await.unwrap();
        for id in [FIRST, SECOND, THIRD] {
            store
                .start(start(id))
                .await
                .unwrap()
                .finish(200, json!({}), None)
                .await
                .unwrap();
        }
        for (session, trace) in [("a", FIRST), ("a", SECOND), ("a", SECOND), ("b", THIRD)] {
            let mut linked = event(&Uuid::new_v4().to_string(), session);
            linked.trace_id = Some(trace.to_owned());
            store.put_event(linked).await.unwrap();
        }
        let mut imported = event(&Uuid::new_v4().to_string(), "a");
        imported.trace_id = Some("00000000-0000-4000-8000-000000000099".to_owned());
        store.put_event(imported).await.unwrap();
        let page = store.session_traces("a", 1, None).await.unwrap();
        assert_eq!(page["traces"].as_array().unwrap().len(), 1);
        assert_eq!(page["traces"][0]["id"], SECOND);
        assert_eq!(page["traces"][0]["complete"], true);
        assert_eq!(page["traces"][0]["bodies"]["request"]["size"], 0);
        assert_eq!(page["next_before"], SECOND);
        let page = store
            .session_traces("a", 50, Some(SECOND.to_owned()))
            .await
            .unwrap();
        assert_eq!(page["traces"].as_array().unwrap().len(), 1);
        assert_eq!(page["traces"][0]["id"], FIRST);
        assert!(page["next_before"].is_null());
        let page = store.session_traces("b", 50, None).await.unwrap();
        assert_eq!(page["traces"][0]["id"], THIRD);
        assert!(
            store.session_traces("missing", 50, None).await.unwrap()["traces"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .session_traces("a", 1, Some("invalid".to_owned()))
                .await
                .is_err()
        );
        assert!(
            store
                .session_traces(
                    "a",
                    1,
                    Some("00000000-0000-4000-8000-000000000099".to_owned())
                )
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn v1_migration_preserves_legacy_traces_and_session_events_survive_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_owned();
        let fixture_root = root.clone();
        tokio::task::spawn_blocking(move || {
            let connection = Connection::open(fixture_root.join("index.sqlite3")).unwrap();
            connection.execute_batch(
                "CREATE TABLE traces (
                     sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                     id TEXT NOT NULL UNIQUE,
                     metadata TEXT NOT NULL,
                     complete INTEGER NOT NULL DEFAULT 0 CHECK (complete IN (0, 1)),
                     status INTEGER,
                     response_headers TEXT,
                     error TEXT,
                     completed_at TEXT
                 );
                 PRAGMA user_version = 1;"
            ).unwrap();
            connection.execute(
                "INSERT INTO traces (id, metadata, complete, status, response_headers)
                 VALUES (?1, ?2, 1, 200, '{}')",
                params![FIRST, json!({"id": FIRST, "provider": "legacy", "started_at": "2026-01-01T00:00:00Z"}).to_string()],
            ).unwrap();
            create_private_directory(&fixture_root.join(FIRST), false).unwrap();
            fs::write(fixture_root.join(FIRST).join("request.body"), b"legacy request").unwrap();
            fs::write(fixture_root.join(FIRST).join("response.body"), b"legacy response").unwrap();
        }).await.unwrap();
        let store = TraceStore::open(&root).await.unwrap();
        assert_eq!(read_body(&store, FIRST, "request").await, b"legacy request");
        assert_eq!(
            store.get(FIRST).await.unwrap().unwrap()["provider"],
            "legacy"
        );
        let mut linked = event(SECOND, "persisted");
        linked.trace_id = Some(FIRST.to_owned());
        let receipt = store.put_event(linked.clone()).await.unwrap();
        drop(store);
        let store = TraceStore::open(&root).await.unwrap();
        assert_eq!(store.put_event(linked).await.unwrap(), receipt);
        assert_eq!(
            read_body(&store, FIRST, "response").await,
            b"legacy response"
        );
        assert_eq!(
            store.list(50, None).await.unwrap()["traces"][0]["id"],
            FIRST
        );
        let page = store.session_events("persisted", 50, 0).await.unwrap();
        assert_eq!(page["events"][0]["event"]["id"], SECOND);
        assert_eq!(page["events"][0]["sequence"], receipt["sequence"]);
        assert_eq!(
            store.list_sessions(50, None).await.unwrap()["sessions"][0]["event_count"],
            1
        );
        assert_eq!(
            store.session_traces("persisted", 50, None).await.unwrap()["traces"][0]["id"],
            FIRST
        );
        let sequence = store.put_event(event(THIRD, "persisted")).await.unwrap()["sequence"]
            .as_u64()
            .unwrap();
        assert!(sequence > receipt["sequence"].as_u64().unwrap());
    }

    fn start(id: &str) -> TraceStart {
        TraceStart {
            id: id.to_owned(),
            provider: "auto".to_owned(),
            method: "POST".to_owned(),
            path: "/v1/messages?example=1".to_owned(),
            request_headers: json!({"content-type": "application/json", "Authorization": "private"}),
            upstream_url: String::new(),
            upstream_headers: json!({}),
        }
    }

    async fn read_body(store: &TraceStore, id: &str, kind: &str) -> Vec<u8> {
        let mut file = store.body(id, kind).await.unwrap().unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).await.unwrap();
        bytes
    }

    #[tokio::test]
    async fn complete_trace_persists_after_reopen_and_route_is_durable() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("traces");
        let store = TraceStore::open(&root).await.unwrap();
        let mut writer = store.start(start(FIRST)).await.unwrap();
        writer.request(b" {\"hello\":").await.unwrap();
        writer.request(b"\"world\"} ").await.unwrap();
        writer
            .route(
                "openai",
                "https://example.test/v1/responses",
                json!({"x-api-key": "secret"}),
            )
            .await
            .unwrap();
        let pending = store.get(FIRST).await.unwrap().unwrap();
        assert_eq!(pending["provider"], "openai");
        assert_eq!(pending["complete"], false);
        assert_eq!(pending["upstream_headers"]["x-api-key"], "[REDACTED]");
        writer.response(b"{\"ok\":true}").await.unwrap();
        writer
            .finish(
                201,
                json!({"set-cookie": "secret", "content-type": "application/json"}),
                None,
            )
            .await
            .unwrap();
        drop(store);
        let store = TraceStore::open(&root).await.unwrap();
        let metadata = store.get(FIRST).await.unwrap().unwrap();
        assert_eq!(metadata["complete"], true);
        assert_eq!(metadata["status"], 201);
        assert!(metadata["completed_at"].is_string());
        assert_eq!(metadata["response_headers"]["set-cookie"], "[REDACTED]");
        assert_eq!(metadata["request_headers"]["Authorization"], "[REDACTED]");
        assert_eq!(
            read_body(&store, FIRST, "request").await,
            b" {\"hello\":\"world\"} "
        );
        assert!(
            store
                .body(FIRST, "upstream_request")
                .await
                .unwrap()
                .is_none()
        );
        let export = store.export(1, None).await.unwrap();
        assert_eq!(export[0]["bodies"]["request"]["encoding"], "json");
        assert_eq!(
            export[0]["bodies"]["request"]["data"],
            json!({"hello": "world"})
        );
    }

    #[tokio::test]
    async fn dropping_writer_keeps_current_bytes_and_incomplete_state_after_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let store = TraceStore::open(temp.path()).await.unwrap();
        let mut writer = store.start(start(FIRST)).await.unwrap();
        writer.request(b"partial request\0\xff").await.unwrap();
        writer.response(b"event: delta\ndata: ").await.unwrap();
        drop(writer);
        drop(store);
        let store = TraceStore::open(temp.path()).await.unwrap();
        let metadata = store.get(FIRST).await.unwrap().unwrap();
        assert_eq!(metadata["complete"], false);
        assert!(metadata["completed_at"].is_null());
        assert!(metadata["status"].is_null());
        assert_eq!(
            read_body(&store, FIRST, "request").await,
            b"partial request\0\xff"
        );
        assert_eq!(
            store.export(1, None).await.unwrap()[0]["metadata"]["complete"],
            false
        );
    }

    #[tokio::test]
    async fn binary_sse_and_translated_bodies_remain_separate_and_exact() {
        let temp = tempfile::tempdir().unwrap();
        let store = TraceStore::open(temp.path()).await.unwrap();
        let mut writer = store.start(start(FIRST)).await.unwrap();
        let binary = b"\0\xff\xfe\r\n\x80";
        let sse = b"event: response.delta\r\ndata: {\"delta\":\"x\"}\r\n\r\ndata: [DONE]\n\n";
        writer.request(binary).await.unwrap();
        writer
            .upstream_request(b"{\"translated\":true}")
            .await
            .unwrap();
        for byte in sse {
            writer.upstream_response(&[*byte]).await.unwrap();
        }
        writer.response(b"client stream\0").await.unwrap();
        writer.finish(200, json!({}), None).await.unwrap();
        let export = store.export(1, None).await.unwrap();
        for (kind, expected) in [
            ("request", binary.as_slice()),
            ("upstream_response", sse.as_slice()),
            ("response", b"client stream\0".as_slice()),
        ] {
            assert_eq!(read_body(&store, FIRST, kind).await, expected);
            let body = &export[0]["bodies"][kind];
            assert_eq!(body["encoding"], "base64");
            assert_eq!(
                STANDARD.decode(body["data"].as_str().unwrap()).unwrap(),
                expected
            );
        }
        assert_eq!(
            export[0]["bodies"]["upstream_request"]["data"],
            json!({"translated":true})
        );
    }

    #[tokio::test]
    async fn pagination_uses_insertion_order_and_rejects_unknown_or_unbounded_cursors() {
        let temp = tempfile::tempdir().unwrap();
        let store = TraceStore::open(temp.path()).await.unwrap();
        for id in [THIRD, FIRST, SECOND] {
            let writer = store.start(start(id)).await.unwrap();
            writer
                .finish(400, json!({}), Some("rejected before upstream".to_owned()))
                .await
                .unwrap();
        }
        let page = store.list(2, None).await.unwrap();
        assert_eq!(page["traces"][0]["id"], SECOND);
        assert_eq!(page["traces"][1]["id"], FIRST);
        assert_eq!(page["next_before"], FIRST);
        let page = store.list(2, Some(FIRST.to_owned())).await.unwrap();
        assert_eq!(page["traces"].as_array().unwrap().len(), 1);
        assert_eq!(page["traces"][0]["id"], THIRD);
        assert!(page["next_before"].is_null());
        assert!(store.list(0, None).await.is_err());
        assert!(store.list(MAX_TRACE_ROWS + 1, None).await.is_err());
        assert!(store.export(MAX_TRACE_ROWS + 1, None).await.is_err());
        assert!(
            store
                .list(1, Some("00000000-0000-4000-8000-000000000099".to_owned()))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn invalid_ids_kinds_and_duplicate_ids_cannot_touch_other_files() {
        let temp = tempfile::tempdir().unwrap();
        let store = TraceStore::open(temp.path()).await.unwrap();
        for id in [
            "../outside",
            "/etc/passwd",
            "00000000000040008000000000000001",
            "{00000000-0000-4000-8000-000000000001}",
            "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
        ] {
            assert!(store.start(start(id)).await.is_err());
            assert!(store.get(id).await.is_err());
            assert!(store.body(id, "request").await.is_err());
        }
        let mut writer = store.start(start(FIRST)).await.unwrap();
        writer.request(b"keep me").await.unwrap();
        assert!(store.start(start(FIRST)).await.is_err());
        assert_eq!(read_body(&store, FIRST, "request").await, b"keep me");
        for kind in [
            "../index.sqlite3",
            "request.body",
            "../../outside",
            "REQUEST",
        ] {
            assert!(store.body(FIRST, kind).await.is_err());
        }
        assert!(store.get(SECOND).await.unwrap().is_none());
        assert!(store.body(SECOND, "request").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn oversized_export_is_rejected_without_truncating_stored_body() {
        let temp = tempfile::tempdir().unwrap();
        let store = TraceStore::open(temp.path()).await.unwrap();
        let writer = store.start(start(FIRST)).await.unwrap();
        writer.finish(200, json!({}), None).await.unwrap();
        let body_path = temp.path().join(FIRST).join("request.body");
        let file = OpenOptions::new().write(true).open(&body_path).unwrap();
        file.set_len(MAX_EXPORT_BODY_BYTES + 1).unwrap();
        assert!(store.export(1, None).await.is_err());
        assert_eq!(
            store
                .body(FIRST, "request")
                .await
                .unwrap()
                .unwrap()
                .metadata()
                .await
                .unwrap()
                .len(),
            MAX_EXPORT_BODY_BYTES + 1
        );
    }

    #[tokio::test]
    async fn failed_completion_does_not_mark_success() {
        let temp = tempfile::tempdir().unwrap();
        let store = TraceStore::open(temp.path()).await.unwrap();
        let mut writer = store.start(start(FIRST)).await.unwrap();
        writer.request(b"recorded").await.unwrap();
        fs::remove_dir_all(temp.path().join(FIRST)).unwrap();
        assert!(writer.finish(200, json!({}), None).await.is_err());
        assert_eq!(store.get(FIRST).await.unwrap().unwrap()["complete"], false);
    }

    #[tokio::test]
    async fn rejected_route_metadata_poisoning_prevents_later_success() {
        let temp = tempfile::tempdir().unwrap();
        let store = TraceStore::open(temp.path()).await.unwrap();
        let mut writer = store.start(start(FIRST)).await.unwrap();
        assert!(
            writer
                .route(
                    "openai",
                    "https://example.test",
                    json!({"large": "x".repeat(MAX_METADATA_BYTES)})
                )
                .await
                .is_err()
        );
        assert!(writer.response(b"not recorded").await.is_err());
        assert!(writer.finish(200, json!({}), None).await.is_err());
        assert_eq!(store.get(FIRST).await.unwrap().unwrap()["complete"], false);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn files_are_private_and_symlinks_cannot_escape_store() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("traces");
        let store = TraceStore::open(&root).await.unwrap();
        let writer = store.start(start(FIRST)).await.unwrap();
        writer.finish(200, json!({}), None).await.unwrap();
        for path in [&root, &root.join(FIRST)] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        for name in ["index.sqlite3", "index.sqlite3-wal", "index.sqlite3-shm"] {
            let path = root.join(name);
            if path.exists() {
                assert_eq!(
                    fs::metadata(path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
        let body = root.join(FIRST).join("request.body");
        assert_eq!(
            fs::metadata(&body).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let outside = temp.path().join("outside");
        fs::write(&outside, b"private outside file").unwrap();
        fs::remove_file(&body).unwrap();
        symlink(&outside, &body).unwrap();
        assert!(store.body(FIRST, "request").await.is_err());
        assert!(store.get(FIRST).await.is_err());
        assert!(store.export(1, None).await.is_err());
        let alias = temp.path().join("alias");
        symlink(&root, &alias).unwrap();
        assert!(TraceStore::open(&alias).await.is_err());
    }

    #[tokio::test]
    async fn header_maps_pairs_and_named_records_redact_credentials() {
        let temp = tempfile::tempdir().unwrap();
        let store = TraceStore::open(temp.path()).await.unwrap();
        let mut meta = start(FIRST);
        meta.request_headers = json!([
            ["Authorization", "bearer secret"],
            {"name":"Cookie", "value":"session=secret"},
            {"key":"X-API-KEY", "values":["secret"]},
            ["content-type", "application/json"]
        ]);
        let writer = store.start(meta).await.unwrap();
        writer
            .finish(
                403,
                json!({"Proxy-Authorization":"secret"}),
                Some("upstream rejected".to_owned()),
            )
            .await
            .unwrap();
        let metadata = store.get(FIRST).await.unwrap().unwrap();
        let encoded = serde_json::to_string(&metadata).unwrap();
        assert!(!encoded.contains("secret"));
        assert_eq!(metadata["error"], "upstream rejected");
        assert_eq!(metadata["request_headers"][3][1], "application/json");
    }

    #[tokio::test]
    async fn store_redacts_custom_credentials_in_start_route_and_finish_metadata() {
        let temp = tempfile::tempdir().unwrap();
        let store = TraceStore::open(temp.path()).await.unwrap();
        let mut meta = start(FIRST);
        meta.request_headers = json!({
            "x-goog-api-key": ["dummy-request-primary", "dummy-request-secondary"],
            "x-auth-email": ["request-primary@example.invalid", "request-secondary@example.invalid"]
        });
        let mut writer = store.start(meta).await.unwrap();
        writer
            .route(
                "openai",
                "https://example.test/v1/native",
                json!({
                    "x-goog-api-key": ["dummy-upstream-primary", "dummy-upstream-secondary"],
                    "x-auth-email": ["upstream-primary@example.invalid", "upstream-secondary@example.invalid"]
                }),
            )
            .await
            .unwrap();
        writer
            .finish(
                200,
                json!({
                    "upstream": {
                        "x-goog-api-key": ["dummy-response-primary", "dummy-response-secondary"],
                        "x-auth-email": ["response-primary@example.invalid", "response-secondary@example.invalid"]
                    }
                }),
                None,
            )
            .await
            .unwrap();

        let metadata = store.get(FIRST).await.unwrap().unwrap();
        assert_eq!(metadata["request_headers"]["x-goog-api-key"], "[REDACTED]");
        assert_eq!(metadata["request_headers"]["x-auth-email"], "[REDACTED]");
        assert_eq!(metadata["upstream_headers"]["x-goog-api-key"], "[REDACTED]");
        assert_eq!(metadata["upstream_headers"]["x-auth-email"], "[REDACTED]");
        assert_eq!(
            metadata["response_headers"]["upstream"]["x-goog-api-key"],
            "[REDACTED]"
        );
        assert_eq!(
            metadata["response_headers"]["upstream"]["x-auth-email"],
            "[REDACTED]"
        );
        let encoded = serde_json::to_string(&metadata).unwrap();
        for secret in [
            "dummy-request-primary",
            "dummy-request-secondary",
            "dummy-upstream-primary",
            "dummy-upstream-secondary",
            "dummy-response-primary",
            "dummy-response-secondary",
            "request-primary@example.invalid",
            "request-secondary@example.invalid",
            "upstream-primary@example.invalid",
            "upstream-secondary@example.invalid",
            "response-primary@example.invalid",
            "response-secondary@example.invalid",
        ] {
            assert!(!encoded.contains(secret));
        }
    }
}
