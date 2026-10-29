use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use infer::{
    import::{self, DiscoveryOptions, DiscoveryScope, Harness, ImportOptions, SourceKind},
    trace::TraceStore,
};
use rusqlite::Connection;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::io::AsyncReadExt;

struct Fixture {
    temp: TempDir,
    roots: BTreeMap<Harness, Vec<PathBuf>>,
    omp: PathBuf,
    codex_rollout: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let omp_root = temp.path().join("omp");
        let omp = omp_root.join("agent/sessions/-work/omp-session.jsonl");
        write(
            &omp,
            concat!(
                "{\"type\":\"session\",\"version\":3,\"id\":\"native-shared\",\"timestamp\":\"2026-10-22T10:00:00Z\",\"cwd\":\"/work\"}\n",
                "{\"type\":\"message\",\"id\":\"m1\",\"parentId\":null,\"timestamp\":\"2026-10-22T10:00:01Z\",\"message\":{\"role\":\"toolResult\",\"content\":[{\"type\":\"text\",\"text\":\"exact omp\"}]}}\n"
            )
            .as_bytes(),
        );
        let blob = b"sanitized image bytes";
        let blob_digest = format!("{:x}", Sha256::digest(blob));
        write(&omp_root.join("agent/blobs").join(&blob_digest), blob);
        writeln!(
            fs::OpenOptions::new().append(true).open(&omp).unwrap(),
            "{}",
            json!({
                "type": "custom",
                "id": "blob-ref",
                "parentId": "m1",
                "timestamp": "2026-10-22T10:00:02Z",
                "content": format!("blob:sha256:{blob_digest}"),
            })
        )
        .unwrap();
        write(
            &omp.with_file_name("omp-session").join("terminal/tool.log"),
            b"opaque omp artifact\0\xff",
        );

        let claude_root = temp.path().join("claude");
        let claude = claude_root.join("projects/-work/claude-session.jsonl");
        write(
            &claude,
            concat!(
                "{\"type\":\"mode\",\"sessionId\":\"native-shared\",\"mode\":\"default\"}\n",
                "{\"type\":\"assistant\",\"uuid\":\"c1\",\"parentUuid\":null,\"sessionId\":\"native-shared\",\"timestamp\":\"2026-10-22T11:00:00Z\",\"isSidechain\":true,\"message\":{\"role\":\"assistant\",\"content\":[{\"type\":\"tool_use\",\"id\":\"tool-1\",\"name\":\"Read\",\"input\":{\"path\":\"sample\"}}]}}\n",
                "{\"type\":\"system\",\"uuid\":\"c2\",\"parentUuid\":\"c1\",\"sessionId\":\"native-shared\",\"timestamp\":\"2026-10-22T11:00:01Z\",\"subtype\":\"compact_boundary\",\"content\":\"summary\"}\n",
                "{\"type\":\"permission-mode\",\"sessionId\":\"native-shared\",\"mode\":\"acceptEdits\"}\n",
                "{\"type\":\"permission-mode\",\"sessionId\":\"native-shared\",\"mode\":\"acceptEdits\"}\n",
                "{malformed}\n",
                "{\"type\":\"last-prompt\",\"sessionId\":\"native-shared\""
            )
            .as_bytes(),
        );

        let codex_root = temp.path().join("codex");
        let codex_rollout = codex_root.join("sessions/2026/10/22/rollout.jsonl.zst");
        fs::create_dir_all(codex_rollout.parent().unwrap()).unwrap();
        let rollout = concat!(
            "{\"timestamp\":\"2026-10-22T12:00:00Z\",\"ordinal\":0,\"type\":\"session_meta\",\"payload\":{\"id\":\"codex-thread\",\"session_id\":\"codex-thread\",\"source\":{\"subagent\":{\"other\":\"child\"}},\"history_mode\":\"paginated\"}}\n",
            "{\"timestamp\":\"2026-10-22T12:00:01Z\",\"ordinal\":1,\"type\":\"response_item\",\"payload\":{\"type\":\"function_call\",\"call_id\":\"call-1\",\"arguments\":{\"precise\":12345678901234567890.123456789}}}\n",
            "{\"timestamp\":\"2026-10-22T12:00:02Z\",\"ordinal\":2,\"type\":\"compacted\",\"payload\":{\"replacement_history\":[]}}\n"
        );
        let mut encoder =
            zstd::stream::write::Encoder::new(fs::File::create(&codex_rollout).unwrap(), 1)
                .unwrap();
        encoder.write_all(rollout.as_bytes()).unwrap();
        encoder.finish().unwrap();
        let history = codex_root.join("thread_history_1.sqlite");
        let connection = Connection::open(&history).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE thread_items (
                    thread_id TEXT, turn_id TEXT, item_id TEXT, rollout_ordinal INTEGER,
                    created_at_ms INTEGER, item_json TEXT, item_type TEXT,
                    updated_at_ordinal INTEGER, started_at_ms INTEGER, completed_at_ms INTEGER
                 );
                 INSERT INTO thread_items VALUES (
                    'codex-thread', 'turn-1', 'item-1', 1, 1792660801000,
                    '{\"type\":\"subAgentActivity\", \"child\":\"agent-1\"}',
                    'subAgentActivity', 1, NULL, NULL
                 );",
            )
            .unwrap();
        drop(connection);

        let grok_root = temp.path().join("grok");
        let grok = grok_root.join("sessions/%2Fwork/018f-session");
        write(
            &grok.join("summary.json"),
            br#"{"info":{"id":"grok-session","cwd":"/work"},"chat_format_version":1,"unknown_summary":{"keep":true}}"#,
        );
        write(
            &grok.join("updates.jsonl"),
            concat!(
                "{\"method\":\"session/update\",\"params\":{\"sessionId\":\"grok-session\",\"update\":{\"sessionUpdate\":\"subagent_spawned\",\"child_session_id\":\"child-1\"},\"_meta\":{\"eventId\":\"018f-event-1\",\"agentTimestampMs\":1792664400000}},\"timestamp\":1792664400}\n",
                "{\"method\":\"_x.ai/session/update\",\"params\":{\"sessionId\":\"grok-session\",\"update\":{\"sessionUpdate\":\"compaction_checkpoint\",\"checkpoint_id\":\"cp-1\"},\"_meta\":{\"eventId\":\"018f-event-2\"}},\"timestamp\":1792664401}\n"
            )
            .as_bytes(),
        );
        write(
            &grok.join("chat_history.jsonl"),
            b"{\"type\":\"reasoning\",\"encrypted_content\":\"opaque\",\"id\":\"reason-1\",\"status\":\"complete\"}\n",
        );
        write(
            &grok.join("compaction_checkpoints/cp-1.json"),
            br#"{"checkpoint_id":"cp-1","schema_version":1,"compacted_history":[{"type":"user","content":"kept"}]}"#,
        );

        let roots = BTreeMap::from([
            (Harness::Omp, vec![omp_root]),
            (Harness::ClaudeCode, vec![claude_root]),
            (Harness::Codex, vec![codex_root]),
            (Harness::GrokBuild, vec![grok_root]),
        ]);
        Self {
            temp,
            roots,
            omp,
            codex_rollout,
        }
    }

    fn discovery(&self) -> import::DiscoveryReport {
        import::discover(&DiscoveryOptions {
            harnesses: Harness::ALL.into_iter().collect::<BTreeSet<_>>(),
            roots: self.roots.clone(),
            sources: Vec::new(),
            scope: DiscoveryScope::All,
            max_sources: 100,
        })
        .unwrap()
    }
}

fn write(path: &Path, bytes: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

fn codex_database_discovery(database: &Path) -> import::DiscoveryReport {
    import::discover(&DiscoveryOptions {
        harnesses: BTreeSet::from([Harness::Codex]),
        roots: BTreeMap::from([(Harness::Codex, Vec::new())]),
        sources: vec![(Harness::Codex, database.to_owned())],
        scope: DiscoveryScope::Managed,
        max_sources: 10,
    })
    .unwrap()
}

async fn all_events(store: &TraceStore) -> Vec<Value> {
    let sessions = store.list_sessions(100, None).await.unwrap();
    let mut events = Vec::new();
    for session in sessions["sessions"].as_array().unwrap() {
        let page = store
            .session_events(session["session_id"].as_str().unwrap(), 100, 0)
            .await
            .unwrap();
        events.extend(page["events"].as_array().unwrap().iter().cloned());
    }
    events
}

#[tokio::test]
async fn native_record_limits_exclude_lf_and_crlf_delimiters() {
    let temp = tempfile::tempdir().unwrap();
    let transcript = temp.path().join("session.jsonl");
    let record = serde_json::to_vec(&json!({
        "type": "user", "sessionId": "line-boundary", "message": "exact bytes"
    }))
    .unwrap();
    for delimiter in [b"\n".as_slice(), b"\r\n".as_slice()] {
        fs::write(&transcript, [record.as_slice(), delimiter].concat()).unwrap();
        let discovery = import::discover(&DiscoveryOptions {
            harnesses: BTreeSet::from([Harness::ClaudeCode]),
            roots: BTreeMap::from([(Harness::ClaudeCode, Vec::new())]),
            sources: vec![(Harness::ClaudeCode, transcript.clone())],
            ..DiscoveryOptions::default()
        })
        .unwrap();
        for (limit, accepted) in [(record.len(), true), (record.len() - 1, false)] {
            let report = import::dry_run_sources(
                &discovery,
                &ImportOptions {
                    max_record_bytes: limit,
                    dry_run: true,
                    ..ImportOptions::default()
                },
            )
            .await
            .unwrap();
            assert_eq!(
                report.failures.is_empty(),
                accepted,
                "{:?}",
                report.failures
            );
            assert_eq!(report.records_seen, u64::from(accepted));
        }
    }
}

#[test]
fn event_spool_import_accepts_a_maximum_size_event_with_crlf() {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("store");
    let config = temp.path().join("infer.toml");
    fs::write(
        &config,
        format!(
            "proxy_token_env = \"UNUSED_PROXY\"\ncontrol_token_env = \"UNUSED_CONTROL\"\n\
             default_provider = \"local\"\ntrace_dir = {}\n\
             [providers.local]\nkind = \"llama\"\nbase_url = \"http://127.0.0.1:1\"\n",
            serde_json::to_string(&directory.to_string_lossy()).unwrap()
        ),
    )
    .unwrap();
    let mut event = json!({
        "id": "11111111-1111-4111-8111-111111111111",
        "session_id": "max-spool-event",
        "source": "review",
        "kind": "boundary",
        "occurred_at": "2026-10-22T12:00:00Z",
        "trace_id": null,
        "payload": {"text": ""}
    });
    let maximum = infer::trace::MAX_SESSION_EVENT_BYTES;
    let overhead = serde_json::to_vec(&event).unwrap().len();
    event["payload"]["text"] = Value::String("x".repeat(maximum - overhead));
    let mut line = serde_json::to_vec(&event).unwrap();
    assert_eq!(line.len(), maximum);
    line.extend_from_slice(b"\r\n");
    let spool = temp.path().join("events.jsonl");
    fs::write(&spool, line).unwrap();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_infer"))
        .args(["--config", config.to_str().unwrap(), "import-events"])
        .arg(&spool)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let connection = Connection::open(directory.join("index.sqlite3")).unwrap();
    let size: usize = connection
        .query_row("SELECT length(event_json) FROM session_events", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(size, maximum);
}

#[tokio::test]
async fn maximum_native_record_limit_accepts_small_records_and_json_artifacts() {
    let fixture = Fixture::new();
    write(
        &fixture.omp.with_extension("").join("terminal/details.json"),
        br#"{"retained":true}"#,
    );
    let discovery = fixture.discovery();
    let store = TraceStore::open(&fixture.temp.path().join("store"))
        .await
        .unwrap();
    for dry_run in [true, false] {
        let options = ImportOptions {
            max_record_bytes: usize::MAX,
            max_artifact_bytes: usize::MAX,
            dry_run,
        };
        let report = if dry_run {
            import::dry_run_sources(&discovery, &options).await.unwrap()
        } else {
            import::import_sources(&store, &discovery, &options)
                .await
                .unwrap()
        };
        assert!(report.failures.is_empty(), "{:?}", report.failures);
        assert!(report.records_seen > 0);
    }
}

fn insert_codex_thread(connection: &Connection, id: &str, rollout: &Path) {
    connection
        .execute(
            "INSERT INTO threads
             (id, rollout_path, created_at, updated_at, source, model_provider,
              cwd, title, sandbox_policy, approval_mode)
             VALUES (?1, ?2, 1792660800, 1792664400, 'cli', 'openai',
                     '/work', ?1, '{}', 'never')",
            [id, rollout.to_str().unwrap()],
        )
        .unwrap();
}

#[tokio::test]
async fn codex_sqlite_native_keys_group_rollouts_and_survive_rowid_reuse() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("codex");
    fs::create_dir_all(&root).unwrap();
    let database = root.join("state_1.sqlite");
    let connection = Connection::open(&database).unwrap();
    connection
        .execute_batch(include_str!("fixtures/codex_state.sql"))
        .unwrap();
    let history = Connection::open(root.join("thread_history_1.sqlite")).unwrap();
    history
        .execute_batch(include_str!("fixtures/codex_history.sql"))
        .unwrap();
    for id in ["thread-a", "thread-b"] {
        let rollout = root.join(format!("sessions/{id}.jsonl"));
        write(
            &rollout,
            format!("{{\"type\":\"session_meta\",\"payload\":{{\"id\":\"{id}\"}}}}\n").as_bytes(),
        );
        insert_codex_thread(&connection, id, &rollout);
        history
            .execute(
                "INSERT INTO thread_history_projection_state VALUES (?1, 42, 3)",
                [id],
            )
            .unwrap();
        history
            .execute(
                "INSERT INTO thread_realtime_items VALUES
                 (?1, 'realtime-1', 2, 1792660801000, 'realtime_session_started', '{}')",
                [id],
            )
            .unwrap();
    }
    for (id, turn, ordinal) in [
        ("thread-a", "turn-1", 0),
        ("thread-a", "turn-2", 1),
        ("thread-b", "turn-1", 0),
    ] {
        history
            .execute(
                "INSERT INTO thread_items VALUES
                 (?1, ?2, 'reused-item', ?3, 1792660801000, '{}')",
                rusqlite::params![id, turn, ordinal],
            )
            .unwrap();
        history
            .execute(
                "INSERT INTO thread_turns (thread_id, turn_id, rollout_ordinal, status)
                 VALUES (?1, ?2, ?3, 'completed')",
                rusqlite::params![id, turn, ordinal],
            )
            .unwrap();
    }
    drop(history);
    let discovery = import::discover(&DiscoveryOptions {
        harnesses: BTreeSet::from([Harness::Codex]),
        roots: BTreeMap::from([(Harness::Codex, vec![root.clone()])]),
        sources: Vec::new(),
        scope: DiscoveryScope::All,
        max_sources: 10,
    })
    .unwrap();
    let store = TraceStore::open(&temp.path().join("store")).await.unwrap();
    let first = import::import_sources(&store, &discovery, &ImportOptions::default())
        .await
        .unwrap();
    assert!(first.failures.is_empty(), "{:?}", first.failures);
    assert_eq!(first.imported, 14);
    let events = all_events(&store).await;
    let mut sessions = BTreeMap::new();
    let mut streams = BTreeMap::<&str, BTreeSet<&str>>::new();
    for row in &events {
        let event = &row["event"];
        let payload = &event["payload"];
        let native_id = payload["native_session_id"].as_str().unwrap();
        let session_id = event["session_id"].as_str().unwrap();
        let expected = sessions.entry(native_id).or_insert(session_id);
        assert_eq!(*expected, session_id);
        streams
            .entry(native_id)
            .or_default()
            .insert(payload["stream"].as_str().unwrap());
        assert_eq!(payload["revision"], 1);
        if payload["stream"] == "sqlite:threads" {
            assert_eq!(
                payload["native_record_id"],
                format!("threads:id:{native_id}")
            );
            assert_eq!(payload["occurrence_basis"], "native");
            assert_eq!(event["occurred_at"], "2026-10-22T09:20:00Z");
            assert_eq!(payload["native"]["created_at"], 1792660800_i64);
        }
    }
    assert_eq!(sessions.len(), 2);
    assert_ne!(sessions["thread-a"], sessions["thread-b"]);
    assert_eq!(streams["thread-a"], streams["thread-b"]);
    assert_eq!(streams["thread-a"].len(), 6);
    let item_ids: BTreeSet<_> = events
        .iter()
        .filter(|row| {
            row["event"]["payload"]["native_session_id"] == "thread-a"
                && row["event"]["payload"]["stream"] == "sqlite:thread_items"
        })
        .map(|row| {
            row["event"]["payload"]["native_record_id"]
                .as_str()
                .unwrap()
        })
        .collect();
    assert_eq!(item_ids.len(), 2);
    let replay = import::import_sources(&store, &discovery, &ImportOptions::default())
        .await
        .unwrap();
    assert_eq!(replay.imported, 0);
    assert_eq!(replay.already_present, 14);

    connection
        .execute("DELETE FROM threads WHERE id = 'thread-b'", [])
        .unwrap();
    insert_codex_thread(
        &connection,
        "thread-c",
        &root.join("sessions/thread-c.jsonl"),
    );
    let rowid: i64 = connection
        .query_row(
            "SELECT rowid FROM threads WHERE id = 'thread-c'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rowid, 2);
    let replacement = import::import_sources(&store, &discovery, &ImportOptions::default())
        .await
        .unwrap();
    assert!(
        replacement.failures.is_empty(),
        "{:?}",
        replacement.failures
    );
    assert_eq!(replacement.imported, 1);
    assert_eq!(replacement.already_present, 13);
    let events = all_events(&store).await;
    assert_eq!(events.len(), 15);
    let new_thread = events
        .iter()
        .find(|row| row["event"]["payload"]["native_session_id"] == "thread-c")
        .unwrap();
    assert_eq!(
        new_thread["event"]["payload"]["native_record_id"],
        "threads:id:thread-c"
    );
    assert_eq!(new_thread["event"]["payload"]["revision"], 1);
    connection
        .execute("UPDATE threads SET rowid = 50 WHERE id = 'thread-a'", [])
        .unwrap();
    let moved = import::import_sources(&store, &discovery, &ImportOptions::default())
        .await
        .unwrap();
    assert!(moved.failures.is_empty(), "{:?}", moved.failures);
    assert_eq!(moved.imported, 0);
    assert_eq!(moved.already_present, 14);
}

#[tokio::test]
async fn codex_state_timestamps_prefer_milliseconds_and_fall_back_to_epoch_seconds() {
    let temp = tempfile::tempdir().unwrap();
    let database = temp.path().join("state_1.sqlite");
    let connection = Connection::open(&database).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE threads (id TEXT PRIMARY KEY, created_at INTEGER,
             updated_at INTEGER, created_at_ms INTEGER, updated_at_ms INTEGER);
             INSERT INTO threads VALUES ('seconds', 1792660800, 1792664400, NULL, NULL);
             INSERT INTO threads VALUES ('milliseconds', 1792660800, 1792664400, 1792660800123, 1792664400456);
             INSERT INTO threads VALUES ('updated-seconds', NULL, 1792664400, NULL, NULL);
             INSERT INTO threads VALUES ('updated-milliseconds', NULL, 1792664400, NULL, 1792664400456);
             INSERT INTO threads VALUES ('epoch-zero', 0, 1792664400, NULL, NULL);",
        )
        .unwrap();
    drop(connection);
    let discovery = codex_database_discovery(&database);
    let store = TraceStore::open(&temp.path().join("store")).await.unwrap();
    let report = import::import_sources(&store, &discovery, &ImportOptions::default())
        .await
        .unwrap();
    assert!(report.failures.is_empty(), "{:?}", report.failures);
    let events = all_events(&store).await;
    let expected = BTreeMap::from([
        ("seconds", "2026-10-22T09:20:00Z"),
        ("milliseconds", "2026-10-22T09:20:00.123Z"),
        ("updated-seconds", "2026-10-22T10:20:00Z"),
        ("updated-milliseconds", "2026-10-22T10:20:00.456Z"),
        ("epoch-zero", "1970-01-01T00:00:00Z"),
    ]);
    assert_eq!(events.len(), expected.len());
    for row in events {
        let event = &row["event"];
        let payload = &event["payload"];
        let id = payload["native_session_id"].as_str().unwrap();
        assert_eq!(event["occurred_at"], expected[id]);
        assert_eq!(payload["native_occurred_at"], expected[id]);
        assert_eq!(payload["occurrence_basis"], "native");
        assert_eq!(event["kind"], "native_record");
    }
}

#[tokio::test]
async fn corrected_codex_state_identity_preserves_legacy_events_and_replays_once() {
    use infer::trace::{ImportAcquisition, ImportRaw, ImportSnapshot};

    let temp = tempfile::tempdir().unwrap();
    let database = temp.path().join("state_1.sqlite");
    let connection = Connection::open(&database).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE threads (id TEXT PRIMARY KEY, created_at INTEGER);
             INSERT INTO threads VALUES ('thread-a', 1792660800);",
        )
        .unwrap();
    drop(connection);
    let discovery = codex_database_discovery(&database);
    let store = TraceStore::open(&temp.path().join("store")).await.unwrap();
    let native = json!({
        "_table": "threads",
        "id": {"encoding": "utf8", "value": "thread-a"},
        "created_at": 1792660800_i64
    });
    store
        .put_import_snapshot(ImportSnapshot {
            adapter: "codex".to_owned(),
            event_source: "local_codex".to_owned(),
            payload_schema: "infer.local_trace.v1".to_owned(),
            source_namespace: discovery.sources[0].source_namespace.clone(),
            native_session_id: "codex-sqlite-index".to_owned(),
            stream: "sqlite:threads".to_owned(),
            native_record_id: "threads:rowid:1".to_owned(),
            format: "sqlite_projection".to_owned(),
            position: "rowid:1".to_owned(),
            occurred_at: None,
            parse_status: "sqlite_row".to_owned(),
            raw: ImportRaw::Bytes(serde_json::to_vec(&native).unwrap()),
            native: Some(native),
            acquisition: ImportAcquisition {
                source_path: database.to_string_lossy().into_owned(),
                source_digest: None,
                member_path: None,
                position: Some("rowid:1".to_owned()),
            },
        })
        .await
        .unwrap();
    let legacy = all_events(&store).await.pop().unwrap();
    let corrected = import::import_sources(&store, &discovery, &ImportOptions::default())
        .await
        .unwrap();
    assert!(corrected.failures.is_empty(), "{:?}", corrected.failures);
    assert_eq!(corrected.imported, 1);
    let events = all_events(&store).await;
    assert_eq!(events.len(), 2);
    assert!(events.contains(&legacy));
    let replay = import::import_sources(&store, &discovery, &ImportOptions::default())
        .await
        .unwrap();
    assert_eq!(replay.imported, 0);
    assert_eq!(replay.already_present, 1);
    assert_eq!(all_events(&store).await.len(), 2);
}

#[tokio::test]
async fn explicit_sources_do_not_repartition_sources_in_selected_roots() {
    let fixture = Fixture::new();
    let original = fixture.discovery();
    let store = TraceStore::open(&fixture.temp.path().join("store"))
        .await
        .unwrap();
    let first = import::import_sources(&store, &original, &ImportOptions::default())
        .await
        .unwrap();
    assert!(first.failures.is_empty(), "{:?}", first.failures);
    let combined = import::discover(&DiscoveryOptions {
        harnesses: Harness::ALL.into_iter().collect(),
        roots: fixture.roots.clone(),
        sources: original
            .sources
            .iter()
            .map(|source| (source.harness, source.path.clone()))
            .collect(),
        scope: DiscoveryScope::All,
        max_sources: 100,
    })
    .unwrap();
    assert_eq!(combined.sources.len(), original.sources.len());
    for (before, after) in original.sources.iter().zip(&combined.sources) {
        assert_eq!(after.path, before.path);
        assert_eq!(after.source_namespace, before.source_namespace);
    }
    let replay = import::import_sources(&store, &combined, &ImportOptions::default())
        .await
        .unwrap();
    assert!(replay.failures.is_empty(), "{:?}", replay.failures);
    assert_eq!(replay.imported, 0);
    assert_eq!(replay.already_present, first.imported);
    assert_eq!(all_events(&store).await.len() as u64, first.imported);

    let outside = fixture.temp.path().join("outside/session.jsonl");
    write(
        &outside,
        b"{\"type\":\"session\",\"id\":\"outside-session\"}\n",
    );
    let extended = import::discover(&DiscoveryOptions {
        harnesses: Harness::ALL.into_iter().collect(),
        roots: fixture.roots.clone(),
        sources: vec![(Harness::Omp, outside.clone())],
        scope: DiscoveryScope::All,
        max_sources: 100,
    })
    .unwrap();
    assert_eq!(extended.sources.len(), original.sources.len() + 1);
    assert!(
        extended
            .sources
            .iter()
            .any(|source| source.path == outside.canonicalize().unwrap())
    );
}

#[tokio::test]
async fn omp_discovery_and_import_accept_large_opaque_companion_files() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("omp");
    let transcript = root.join("agent/sessions/work/session.jsonl");
    write(
        &transcript,
        b"{\"type\":\"session\",\"id\":\"large-companion\"}\n",
    );
    let raw = vec![b'x'; 1024 * 1024 + 1];
    write(
        &transcript.with_extension("").join("terminal/output.log"),
        &raw,
    );
    let discovery = import::discover(&DiscoveryOptions {
        harnesses: BTreeSet::from([Harness::Omp]),
        roots: BTreeMap::from([(Harness::Omp, vec![root])]),
        sources: Vec::new(),
        scope: DiscoveryScope::Managed,
        max_sources: 10,
    })
    .unwrap();
    assert_eq!(discovery.sources.len(), 1);
    assert_eq!(
        discovery.sources[0].path,
        transcript.canonicalize().unwrap()
    );
    let store = TraceStore::open(&temp.path().join("store")).await.unwrap();
    let options = ImportOptions {
        max_record_bytes: 128,
        ..ImportOptions::default()
    };
    let report = import::import_sources(&store, &discovery, &options)
        .await
        .unwrap();
    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert_eq!(report.imported, 2);
    assert_eq!(report.artifacts, 1);
    let events = all_events(&store).await;
    let companion = events
        .iter()
        .find(|row| {
            row.pointer("/event/payload/native_record_id")
                == Some(&json!("artifact:terminal/output.log"))
        })
        .unwrap();
    let digest = companion
        .pointer("/event/payload/raw_artifact/digest")
        .and_then(Value::as_str)
        .unwrap();
    let mut artifact = store.artifact(digest).await.unwrap().unwrap();
    let mut roundtrip = Vec::new();
    artifact.read_to_end(&mut roundtrip).await.unwrap();
    assert_eq!(roundtrip, raw);
}

#[tokio::test]
async fn sqlite_record_limit_accepts_exact_serialized_boundary() {
    for (filename, table) in [
        ("state_1.sqlite", "threads"),
        ("thread_history_1.sqlite", "thread_items"),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join(filename);
        let connection = Connection::open(&database).unwrap();
        connection
            .execute_batch(&format!(
                "CREATE TABLE {table} (thread_id TEXT, item_id TEXT, item_json TEXT);
                 INSERT INTO {table} VALUES ('thread', 'item-1', '{{\"text\":\"hello\"}}');"
            ))
            .unwrap();
        drop(connection);
        let raw = serde_json::to_vec(&json!({
            "_table": table,
            "thread_id": {"encoding": "utf8", "value": "thread"},
            "item_id": {"encoding": "utf8", "value": "item-1"},
            "item_json": {
                "encoding": "utf8", "value": "{\"text\":\"hello\"}",
                "json": {"text": "hello"}
            }
        }))
        .unwrap();
        let discovery = codex_database_discovery(&database);
        let store = TraceStore::open(&temp.path().join("store")).await.unwrap();
        for dry_run in [true, false] {
            for (limit, accepted) in [(raw.len() - 1, false), (raw.len(), true)] {
                let options = ImportOptions {
                    max_record_bytes: limit,
                    dry_run,
                    ..ImportOptions::default()
                };
                let report = if dry_run {
                    import::dry_run_sources(&discovery, &options).await.unwrap()
                } else {
                    import::import_sources(&store, &discovery, &options)
                        .await
                        .unwrap()
                };
                assert_eq!(
                    report.failures.is_empty(),
                    accepted,
                    "{:?}",
                    report.failures
                );
                assert_eq!(report.records_seen, u64::from(accepted));
                assert_eq!(report.imported, u64::from(accepted && !dry_run));
            }
        }
        let events = all_events(&store).await;
        assert_eq!(events.len(), 1);
        let digest = events[0]
            .pointer("/event/payload/raw_artifact/digest")
            .and_then(Value::as_str)
            .unwrap();
        let mut artifact = store.artifact(digest).await.unwrap().unwrap();
        let mut roundtrip = Vec::new();
        artifact.read_to_end(&mut roundtrip).await.unwrap();
        assert_eq!(roundtrip, raw);
    }
}

#[tokio::test]
async fn sqlite_record_limit_rejects_oversized_rows_and_preserves_replayable_prefix() {
    use rusqlite::types::Value as SqliteValue;

    for oversized in [
        SqliteValue::Text("x".repeat(4096)),
        SqliteValue::Text("\n".repeat(100)),
        SqliteValue::Text(format!("{{\"text\":\"{}\"}}", "x".repeat(90))),
        SqliteValue::Blob(vec![0xff; 180]),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("thread_history_1.sqlite");
        let connection = Connection::open(&database).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE thread_items (thread_id TEXT, item_id TEXT, item_json);
                 INSERT INTO thread_items VALUES ('thread', 'item-1', 'small');",
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO thread_items VALUES ('thread', 'item-2', ?1)",
                [oversized],
            )
            .unwrap();
        connection
            .execute_batch("INSERT INTO thread_items VALUES ('thread', 'item-3', 'small');")
            .unwrap();
        drop(connection);
        let discovery = codex_database_discovery(&database);
        let store = TraceStore::open(&temp.path().join("store")).await.unwrap();
        let options = ImportOptions {
            max_record_bytes: 256,
            ..ImportOptions::default()
        };
        let dry_run = import::dry_run_sources(
            &discovery,
            &ImportOptions {
                dry_run: true,
                ..options.clone()
            },
        )
        .await
        .unwrap();
        let first = import::import_sources(&store, &discovery, &options)
            .await
            .unwrap();
        for report in [&dry_run, &first] {
            assert_eq!(report.records_seen, 1);
            assert_eq!(report.failures.len(), 1);
            assert!(report.failures[0].error.contains("thread_items rowid 2"));
            assert!(
                report.failures[0]
                    .error
                    .contains("native record exceeds configured 256 byte limit")
            );
        }
        assert_eq!(first.imported, 1);
        assert_eq!(all_events(&store).await.len(), 1);
        let retry = import::import_sources(&store, &discovery, &options)
            .await
            .unwrap();
        assert_eq!(retry.imported, 0);
        assert_eq!(retry.already_present, 1);
        assert_eq!(retry.failures.len(), 1);
        let resumed = import::import_sources(&store, &discovery, &ImportOptions::default())
            .await
            .unwrap();
        assert!(resumed.failures.is_empty(), "{:?}", resumed.failures);
        assert_eq!(resumed.already_present, 1);
        assert_eq!(resumed.imported, 2);
        assert_eq!(all_events(&store).await.len(), 3);
    }
}

#[tokio::test]
async fn sqlite_projection_preserves_non_utf8_text_blobs_and_infinite_reals_on_replay() {
    let temp = tempfile::tempdir().unwrap();
    let database = temp.path().join("thread_history_1.sqlite");
    let connection = Connection::open(&database).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE thread_items (
                 thread_id TEXT, turn_id TEXT, item_id BLOB,
                 opaque_text TEXT, opaque_blob BLOB, finite REAL, infinite REAL
             );",
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO thread_items VALUES (
                 CAST(X'80FF' AS TEXT), CAST(X'80' AS TEXT), X'80FF',
                 CAST(X'80FF' AS TEXT), X'80FF', 1.5, ?1
             )",
            [f64::INFINITY],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO thread_items VALUES (
                 'thread-b', 'turn-b', X'01', 'ordinary text', X'01', -2.5, ?1
             )",
            [f64::NEG_INFINITY],
        )
        .unwrap();
    drop(connection);

    let discovery = codex_database_discovery(&database);
    let store = TraceStore::open(&temp.path().join("store")).await.unwrap();
    let first = import::import_sources(&store, &discovery, &ImportOptions::default())
        .await
        .unwrap();
    assert!(first.failures.is_empty(), "{:?}", first.failures);
    assert_eq!(first.imported, 2);

    let events = all_events(&store).await;
    let row = events
        .iter()
        .find(|row| {
            row.pointer("/event/payload/stream") == Some(&json!("sqlite:thread_items"))
                && row.pointer("/event/payload/native/thread_id/value") == Some(&json!("gP8="))
        })
        .unwrap();
    let payload = &row["event"]["payload"];
    assert_eq!(
        payload["native"]["thread_id"],
        json!({
            "encoding": "base64", "sqlite_type": "text", "value": "gP8="
        })
    );
    assert_eq!(
        payload["native"]["turn_id"],
        json!({
            "encoding": "base64", "sqlite_type": "text", "value": "gA=="
        })
    );
    assert_eq!(
        payload["native"]["item_id"],
        json!({
            "encoding": "base64", "value": "gP8="
        })
    );
    assert_eq!(
        payload["native"]["opaque_text"],
        json!({
            "encoding": "base64", "sqlite_type": "text", "value": "gP8="
        })
    );
    assert_eq!(
        payload["native"]["opaque_blob"],
        json!({
            "encoding": "base64", "value": "gP8="
        })
    );
    assert_eq!(payload["native"]["finite"], 1.5);
    assert_eq!(
        payload["native"]["infinite"],
        json!({
            "encoding": "sqlite_real_non_finite", "value": "Infinity"
        })
    );

    let digest = payload["raw_artifact"]["digest"].as_str().unwrap();
    let mut artifact = store.artifact(digest).await.unwrap().unwrap();
    let mut bytes = Vec::new();
    artifact.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap(),
        payload["native"]
    );

    let negative = events
        .iter()
        .find(|row| row.pointer("/event/payload/native_session_id") == Some(&json!("thread-b")))
        .unwrap();
    assert_eq!(negative["event"]["payload"]["native"]["finite"], -2.5);
    assert_eq!(
        negative["event"]["payload"]["native"]["infinite"],
        json!({
            "encoding": "sqlite_real_non_finite", "value": "-Infinity"
        })
    );

    let replay = import::import_sources(&store, &discovery, &ImportOptions::default())
        .await
        .unwrap();
    assert!(replay.failures.is_empty(), "{:?}", replay.failures);
    assert_eq!(replay.imported, 0);
    assert_eq!(replay.already_present, 2);
    assert_eq!(all_events(&store).await, events);

    let connection = Connection::open(&database).unwrap();
    connection
        .execute("UPDATE thread_items SET rowid = rowid + 100", [])
        .unwrap();
    let relocated = import::import_sources(&store, &discovery, &ImportOptions::default())
        .await
        .unwrap();
    assert!(relocated.failures.is_empty(), "{:?}", relocated.failures);
    assert_eq!(relocated.imported, 0);
    assert_eq!(relocated.already_present, 2);
    let after_relocation = all_events(&store).await;
    assert_eq!(
        after_relocation
            .iter()
            .map(|row| &row["event"])
            .collect::<Vec<_>>(),
        events.iter().map(|row| &row["event"]).collect::<Vec<_>>()
    );

    connection
        .execute(
            "UPDATE thread_items SET opaque_blob = X'0102'
             WHERE hex(thread_id) = '80FF'",
            [],
        )
        .unwrap();
    let changed = import::import_sources(&store, &discovery, &ImportOptions::default())
        .await
        .unwrap();
    assert!(changed.failures.is_empty(), "{:?}", changed.failures);
    assert_eq!(changed.imported, 1);
    assert_eq!(changed.already_present, 1);
    let after_change = all_events(&store).await;
    assert_eq!(after_change.len(), 3);
    let revision = after_change
        .iter()
        .find(|row| row["event"]["payload"]["revision"] == 2)
        .unwrap();
    assert_eq!(revision["event"]["session_id"], row["event"]["session_id"]);
    assert_eq!(
        revision["event"]["payload"]["native_session_id"],
        payload["native_session_id"]
    );
    assert_eq!(
        revision["event"]["payload"]["native_record_id"],
        payload["native_record_id"]
    );
    assert_eq!(
        revision["event"]["payload"]["native"]["opaque_blob"]["value"],
        "AQI="
    );
}

#[test]
fn max_sources_counts_unique_omp_registry_and_codex_rollout_sources_at_admission() {
    let temp = tempfile::tempdir().unwrap();
    let omp_root = temp.path().join("omp");
    let managed = omp_root.join("agent/sessions/work/one.jsonl");
    write(&managed, b"{\"type\":\"session\",\"id\":\"one\"}\n");
    let markers = omp_root.join("agent/custom-session-files");
    fs::create_dir_all(&markers).unwrap();
    fs::write(
        markers.join("duplicate"),
        managed.to_string_lossy().as_bytes(),
    )
    .unwrap();
    let omp = import::discover(&DiscoveryOptions {
        harnesses: BTreeSet::from([Harness::Omp]),
        roots: BTreeMap::from([(Harness::Omp, vec![omp_root.clone()])]),
        sources: Vec::new(),
        scope: DiscoveryScope::All,
        max_sources: 1,
    })
    .unwrap();
    assert_eq!(
        omp.sources.len(),
        1,
        "duplicate registry source counts once"
    );

    let outside = temp.path().join("outside.jsonl");
    write(&outside, b"{\"type\":\"session\",\"id\":\"outside\"}\n");
    fs::write(markers.join("unique"), outside.to_string_lossy().as_bytes()).unwrap();
    let error = import::discover(&DiscoveryOptions {
        harnesses: BTreeSet::from([Harness::Omp]),
        roots: BTreeMap::from([(Harness::Omp, vec![omp_root])]),
        sources: Vec::new(),
        scope: DiscoveryScope::All,
        max_sources: 1,
    })
    .unwrap_err();
    assert!(error.to_string().contains("discovery exceeded 1 sources"));

    let explicit_duplicate = import::discover(&DiscoveryOptions {
        harnesses: BTreeSet::from([Harness::Omp]),
        roots: BTreeMap::from([(Harness::Omp, Vec::new())]),
        sources: vec![
            (Harness::Omp, outside.clone()),
            (Harness::Omp, outside.clone()),
        ],
        scope: DiscoveryScope::All,
        max_sources: 1,
    })
    .unwrap();
    assert_eq!(explicit_duplicate.sources.len(), 1);

    let second_explicit = temp.path().join("second-explicit.jsonl");
    write(
        &second_explicit,
        b"{\"type\":\"session\",\"id\":\"second\"}\n",
    );
    let error = import::discover(&DiscoveryOptions {
        harnesses: BTreeSet::from([Harness::Omp]),
        roots: BTreeMap::from([(Harness::Omp, Vec::new())]),
        sources: vec![(Harness::Omp, outside), (Harness::Omp, second_explicit)],
        scope: DiscoveryScope::All,
        max_sources: 1,
    })
    .unwrap_err();
    assert!(error.to_string().contains("discovery exceeded 1 sources"));

    let codex_root = temp.path().join("codex");
    fs::create_dir_all(&codex_root).unwrap();
    let rollout = codex_root.join("unmanaged/rollout.jsonl");
    write(&rollout, b"{}\n");
    let database = codex_root.join("state_1.sqlite");
    let connection = Connection::open(&database).unwrap();
    connection
        .execute("CREATE TABLE threads (id TEXT, rollout_path TEXT)", [])
        .unwrap();
    connection
        .execute(
            "INSERT INTO threads VALUES ('thread', ?1)",
            [rollout.to_string_lossy().as_ref()],
        )
        .unwrap();
    drop(connection);
    let error = import::discover(&DiscoveryOptions {
        harnesses: BTreeSet::from([Harness::Codex]),
        roots: BTreeMap::from([(Harness::Codex, vec![codex_root])]),
        sources: Vec::new(),
        scope: DiscoveryScope::All,
        max_sources: 1,
    })
    .unwrap_err();
    assert!(error.to_string().contains("discovery exceeded 1 sources"));
}

#[tokio::test]
async fn all_native_formats_round_trip_and_reimport_without_duplicate_snapshots() {
    let fixture = Fixture::new();
    let discovery = fixture.discovery();
    assert!(Harness::ALL.into_iter().all(|harness| {
        discovery
            .sources
            .iter()
            .any(|source| source.harness == harness)
    }));
    assert!(
        discovery
            .sources
            .iter()
            .any(|source| source.kind == SourceKind::ZstdJsonl)
    );
    assert!(
        discovery
            .sources
            .iter()
            .any(|source| source.kind == SourceKind::CodexHistoryDb)
    );
    let dry_run = import::dry_run_sources(
        &discovery,
        &ImportOptions {
            dry_run: true,
            ..ImportOptions::default()
        },
    )
    .await
    .unwrap();
    assert!(dry_run.failures.is_empty());
    assert_eq!(dry_run.imported, 0);
    assert!(dry_run.records_seen >= 16);

    let store = TraceStore::open(&fixture.temp.path().join("store"))
        .await
        .unwrap();
    let first = import::import_sources(&store, &discovery, &ImportOptions::default())
        .await
        .unwrap();
    assert!(first.failures.is_empty(), "{:?}", first.failures);
    assert!(first.imported >= 14);
    assert_eq!(first.malformed_records, 1);
    assert_eq!(first.deferred_incomplete_tails, 1);

    let events = all_events(&store).await;
    let harnesses = events
        .iter()
        .filter_map(|row| {
            row.pointer("/event/payload/source_adapter")
                .and_then(Value::as_str)
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        harnesses,
        BTreeSet::from(["omp", "claude_code", "codex", "grok_build"])
    );
    let omp = events
        .iter()
        .find(|row| row.pointer("/event/payload/native_record_id") == Some(&json!("m1")))
        .unwrap();
    let digest = omp
        .pointer("/event/payload/raw_artifact/digest")
        .and_then(Value::as_str)
        .unwrap();
    let mut artifact = store.artifact(digest).await.unwrap().unwrap();
    let mut bytes = Vec::new();
    artifact.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, br#"{"type":"message","id":"m1","parentId":null,"timestamp":"2026-10-22T10:00:01Z","message":{"role":"toolResult","content":[{"type":"text","text":"exact omp"}]}}"#);
    assert_eq!(
        omp["acquisitions"][0]["source_path"],
        fixture
            .omp
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .as_ref()
    );
    assert!(events.iter().any(|row| {
        row.pointer("/event/payload/native_inline") == Some(&Value::Bool(true))
            && row.pointer("/event/payload/native/params/update/sessionUpdate")
                == Some(&json!("subagent_spawned"))
    }));
    assert!(events.iter().any(|row| {
        row.pointer("/event/payload/occurrence_basis") == Some(&json!("import_observation"))
            && row.pointer("/event/payload/native/type") == Some(&json!("mode"))
    }));
    let blob_event = events
        .iter()
        .find(|row| {
            row.pointer("/event/payload/stream")
                .and_then(Value::as_str)
                .is_some_and(|stream| stream.starts_with("blobs/sha256/"))
        })
        .unwrap();
    let blob_digest = blob_event
        .pointer("/event/payload/raw_artifact/digest")
        .and_then(Value::as_str)
        .unwrap();
    let mut blob = store.artifact(blob_digest).await.unwrap().unwrap();
    let mut blob_bytes = Vec::new();
    blob.read_to_end(&mut blob_bytes).await.unwrap();
    assert_eq!(blob_bytes, b"sanitized image bytes");
    assert_eq!(
        events
            .iter()
            .filter(|row| {
                row.pointer("/event/payload/native/type") == Some(&json!("permission-mode"))
            })
            .count(),
        2
    );

    let second = import::import_sources(&store, &discovery, &ImportOptions::default())
        .await
        .unwrap();
    assert_eq!(second.imported, 0);
    assert_eq!(second.already_present, first.imported);
    assert_eq!(all_events(&store).await.len() as u64, first.imported);
}

#[tokio::test]
async fn changed_native_identity_appends_revision_and_codex_archive_move_keeps_identity() {
    let fixture = Fixture::new();
    let plain_rollout = fixture.codex_rollout.with_extension("");
    zstd::stream::copy_decode(
        fs::File::open(&fixture.codex_rollout).unwrap(),
        fs::File::create(&plain_rollout).unwrap(),
    )
    .unwrap();
    let store = TraceStore::open(&fixture.temp.path().join("store"))
        .await
        .unwrap();
    let discovery = fixture.discovery();
    let first = import::import_sources(&store, &discovery, &ImportOptions::default())
        .await
        .unwrap();
    assert!(first.failures.is_empty());

    let original = fs::read_to_string(&fixture.omp).unwrap();
    fs::write(&fixture.omp, original.replace("exact omp", "changed omp")).unwrap();
    let changed = import::import_sources(&store, &fixture.discovery(), &ImportOptions::default())
        .await
        .unwrap();
    assert_eq!(changed.imported, 1);
    let mut revisions = all_events(&store)
        .await
        .into_iter()
        .filter(|row| row.pointer("/event/payload/native_record_id") == Some(&json!("m1")))
        .map(|row| {
            row.pointer("/event/payload/revision")
                .and_then(Value::as_i64)
                .unwrap()
        })
        .collect::<Vec<_>>();
    revisions.sort();
    assert_eq!(revisions, vec![1, 2]);

    let archived =
        fixture.roots.get(&Harness::Codex).unwrap()[0].join("archived_sessions/rollout.jsonl.zst");
    fs::create_dir_all(archived.parent().unwrap()).unwrap();
    fs::rename(&fixture.codex_rollout, &archived).unwrap();
    fs::remove_file(&plain_rollout).unwrap();
    let moved = import::import_sources(&store, &fixture.discovery(), &ImportOptions::default())
        .await
        .unwrap();
    assert_eq!(moved.imported, 0);
    assert!(moved.failures.is_empty());
    assert_eq!(moved.already_present, first.imported);
}

#[cfg(unix)]
#[tokio::test]
async fn discovery_skips_symlinks_and_artifacts_remain_private() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let fixture = Fixture::new();
    let outside = fixture.temp.path().join("outside.jsonl");
    fs::write(&outside, b"{\"secret\":true}\n").unwrap();
    let link =
        fixture.roots.get(&Harness::ClaudeCode).unwrap()[0].join("projects/-work/link.jsonl");
    symlink(&outside, &link).unwrap();
    let discovery = fixture.discovery();
    assert_eq!(discovery.skipped_symlinks, 1);
    assert!(
        !discovery
            .sources
            .iter()
            .any(|source| source.path == outside)
    );

    let store_root = fixture.temp.path().join("store");
    let store = TraceStore::open(&store_root).await.unwrap();
    let report = import::import_sources(&store, &discovery, &ImportOptions::default())
        .await
        .unwrap();
    assert!(report.failures.is_empty());
    let event = all_events(&store).await.pop().unwrap();
    let digest = event
        .pointer("/event/payload/raw_artifact/digest")
        .and_then(Value::as_str)
        .unwrap();
    let artifact = store_root
        .join("artifacts/sha256")
        .join(&digest[..2])
        .join(digest);
    assert_eq!(
        fs::metadata(artifact).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[cfg(unix)]
#[test]
fn codex_state_rollout_pointers_cannot_escape_selected_roots() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().canonicalize().unwrap();
    let root = base.join("codex");
    let safe = root.join("sessions/safe.jsonl");
    let escaped = base.join("escaped.jsonl");
    let link_target = base.join("link-target.jsonl");
    for path in [&safe, &escaped, &link_target] {
        write(
            path,
            b"{\"type\":\"session_meta\",\"payload\":{\"id\":\"scope-fixture\"}}\n",
        );
    }
    let link = root.join("linked.jsonl");
    symlink(&link_target, &link).unwrap();
    let database = root.join("state_1.sqlite");
    let connection = Connection::open(&database).unwrap();
    connection
        .execute_batch("CREATE TABLE threads (rollout_path TEXT NOT NULL)")
        .unwrap();
    for path in [&safe, &root.join("../escaped.jsonl"), &link] {
        connection
            .execute(
                "INSERT INTO threads (rollout_path) VALUES (?1)",
                [path.to_str().unwrap()],
            )
            .unwrap();
    }
    drop(connection);
    let report = import::discover(&DiscoveryOptions {
        harnesses: BTreeSet::from([Harness::Codex]),
        roots: BTreeMap::from([(Harness::Codex, vec![root])]),
        sources: Vec::new(),
        scope: DiscoveryScope::All,
        max_sources: 100,
    })
    .unwrap();
    let actual = report
        .sources
        .iter()
        .map(|source| source.path.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual,
        BTreeSet::from([
            database.canonicalize().unwrap(),
            safe.canonicalize().unwrap()
        ])
    );
}

#[tokio::test]
async fn fitting_native_projections_are_not_dropped_by_raw_size() {
    for companion in [false, true] {
        // Large JSON content and whitespace-heavy JSON both fit when serialized
        // into an event. The latter even has raw bytes above the envelope cap.
        for padded in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("omp");
            let transcript = root.join("agent/sessions/work/session.jsonl");
            write(&transcript, b"{\"type\":\"session\",\"id\":\"fitting\"}\n");
            let native = json!({
                "type":"message",
                "id":"fitting-record",
                "text": if padded { "small".to_owned() } else { "x".repeat(9 * 1024 * 1024) },
            });
            let mut raw = serde_json::to_vec(&native).unwrap();
            if padded {
                raw.resize(raw.len() + 17 * 1024 * 1024, b' ');
            }
            let record_id = if companion {
                write(&transcript.with_extension("").join("checkpoint.json"), &raw);
                "artifact:checkpoint.json"
            } else {
                let mut file = fs::OpenOptions::new()
                    .append(true)
                    .open(&transcript)
                    .unwrap();
                file.write_all(&raw).unwrap();
                file.write_all(b"\n").unwrap();
                "fitting-record"
            };
            let discovery = import::discover(&DiscoveryOptions {
                harnesses: BTreeSet::from([Harness::Omp]),
                roots: BTreeMap::from([(Harness::Omp, vec![root])]),
                ..DiscoveryOptions::default()
            })
            .unwrap();
            let store = TraceStore::open(&temp.path().join("store")).await.unwrap();
            let report = import::import_sources(&store, &discovery, &ImportOptions::default())
                .await
                .unwrap();
            assert!(report.failures.is_empty(), "{:?}", report.failures);
            let events = all_events(&store).await;
            let row = events
                .iter()
                .find(|row| row["event"]["payload"]["native_record_id"] == record_id)
                .unwrap();
            let payload = &row["event"]["payload"];
            assert_eq!(
                payload["native_inline"], true,
                "companion={companion}, padded={padded}"
            );
            assert_eq!(payload["native"], native);
            let mut artifact = store
                .artifact(payload["raw_artifact"]["digest"].as_str().unwrap())
                .await
                .unwrap()
                .unwrap();
            let mut restored = Vec::new();
            artifact.read_to_end(&mut restored).await.unwrap();
            assert_eq!(restored, raw);
            let replay = import::import_sources(&store, &discovery, &ImportOptions::default())
                .await
                .unwrap();
            assert!(replay.failures.is_empty(), "{:?}", replay.failures);
            assert_eq!(replay.imported, 0);
            assert_eq!(replay.already_present, report.imported);
        }
    }
}

#[tokio::test]
async fn record_larger_than_event_limit_round_trips_through_artifact_storage() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("omp");
    let transcript = root.join("agent/sessions/work/large.jsonl");
    fs::create_dir_all(transcript.parent().unwrap()).unwrap();
    let mut file = fs::File::create(&transcript).unwrap();
    writeln!(
        file,
        "{}",
        json!({
            "type": "session",
            "version": 3,
            "id": "large-session",
            "timestamp": "2026-10-22T10:00:00Z"
        })
    )
    .unwrap();
    let raw = serde_json::to_vec(&json!({
        "type": "message",
        "id": "large-record",
        "timestamp": "2026-10-22T10:00:01Z",
        "opaque": "x".repeat(17 * 1024 * 1024)
    }))
    .unwrap();
    file.write_all(&raw).unwrap();
    file.write_all(b"\n").unwrap();
    drop(file);

    let discovery = import::discover(&DiscoveryOptions {
        harnesses: BTreeSet::from([Harness::Omp]),
        roots: BTreeMap::from([(Harness::Omp, vec![root])]),
        sources: Vec::new(),
        scope: DiscoveryScope::All,
        max_sources: 10,
    })
    .unwrap();
    let store = TraceStore::open(&temp.path().join("store")).await.unwrap();
    let report = import::import_sources(
        &store,
        &discovery,
        &ImportOptions {
            max_record_bytes: 32 * 1024 * 1024,
            max_artifact_bytes: 32 * 1024 * 1024,
            dry_run: false,
        },
    )
    .await
    .unwrap();
    assert!(report.failures.is_empty(), "{:?}", report.failures);
    let events = all_events(&store).await;
    let large = events
        .iter()
        .find(|row| row.pointer("/event/payload/native_record_id") == Some(&json!("large-record")))
        .unwrap();
    assert_eq!(
        large.pointer("/event/payload/native_inline"),
        Some(&Value::Bool(false))
    );
    assert!(large.pointer("/event/payload/native").unwrap().is_null());
    let digest = large
        .pointer("/event/payload/raw_artifact/digest")
        .and_then(Value::as_str)
        .unwrap();
    let mut artifact = store.artifact(digest).await.unwrap().unwrap();
    let mut roundtrip = Vec::new();
    artifact.read_to_end(&mut roundtrip).await.unwrap();
    assert_eq!(roundtrip, raw);
}

#[test]
fn codex_plain_rollout_is_preferred_over_compressed_sibling() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("codex");
    let directory = root.join("sessions/2026/10/22");
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join("rollout.jsonl"), b"{}\n").unwrap();
    fs::write(
        directory.join("rollout.jsonl.zst"),
        b"not-read-during-discovery",
    )
    .unwrap();
    let discovery = import::discover(&DiscoveryOptions {
        harnesses: BTreeSet::from([Harness::Codex]),
        roots: BTreeMap::from([(Harness::Codex, vec![root])]),
        sources: Vec::new(),
        scope: DiscoveryScope::All,
        max_sources: 10,
    })
    .unwrap();
    assert_eq!(discovery.sources.len(), 1);
    assert_eq!(discovery.sources[0].kind, SourceKind::Jsonl);
    assert_eq!(
        discovery.sources[0]
            .path
            .file_name()
            .and_then(|name| name.to_str()),
        Some("rollout.jsonl")
    );
}

#[tokio::test]
async fn schema_three_upgrade_preserves_provenance_without_replay_duplicates() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("omp");
    let source = root.join("agent/sessions/work/session.jsonl");
    write(
        &source,
        concat!(
            "{\"type\":\"session\",\"version\":3,\"id\":\"migration-session\",\"timestamp\":\"2026-10-22T10:00:00Z\"}\n",
            "{\"type\":\"message\",\"id\":\"m1\",\"parentId\":null,\"timestamp\":\"2026-10-22T10:00:01Z\",\"message\":{\"role\":\"user\",\"content\":[{\"type\":\"text\",\"text\":\"fixture\"}]}}\n"
        )
        .as_bytes(),
    );
    let discovery = import::discover(&DiscoveryOptions {
        harnesses: BTreeSet::from([Harness::Omp]),
        roots: BTreeMap::from([(Harness::Omp, vec![root])]),
        sources: Vec::new(),
        scope: DiscoveryScope::All,
        max_sources: 10,
    })
    .unwrap();
    let directory = temp.path().join("store");
    let store = TraceStore::open(&directory).await.unwrap();
    let first = import::import_sources(&store, &discovery, &ImportOptions::default())
        .await
        .unwrap();
    assert!(first.failures.is_empty(), "{:?}", first.failures);
    assert_eq!(first.imported, 2);
    let original = all_events(&store).await;
    drop(store);

    // Recreate the actual v3 receipt schema. Later acquisitions never stored
    // positions, and their source files may no longer exist during upgrade.
    let connection = Connection::open(directory.join("index.sqlite3")).unwrap();
    connection
        .execute_batch(
            "BEGIN IMMEDIATE;
             ALTER TABLE import_acquisitions RENAME TO import_acquisitions_v4;
             CREATE TABLE import_acquisitions (
                 snapshot_id INTEGER NOT NULL,
                 source_path TEXT NOT NULL,
                 observed_at TEXT NOT NULL,
                 UNIQUE (snapshot_id, source_path)
             );
             INSERT INTO import_acquisitions
                 SELECT snapshot_id, source_path, observed_at
                 FROM import_acquisitions_v4;
             INSERT INTO import_acquisitions
                 SELECT snapshot_id, '/unavailable/historical-source.jsonl',
                        '2001-01-01T00:00:00Z'
                 FROM import_snapshots;
             DROP TABLE import_acquisitions_v4;
             PRAGMA user_version = 3;
             COMMIT;",
        )
        .unwrap();
    drop(connection);

    let store = TraceStore::open(&directory).await.unwrap();
    let upgraded = all_events(&store).await;
    assert_eq!(upgraded.len(), original.len());
    for (before, after) in original.iter().zip(&upgraded) {
        assert_eq!(after["event"], before["event"]);
        let receipts = after["acquisitions"].as_array().unwrap();
        assert_eq!(receipts.len(), 2);
        assert!(receipts.contains(&before["acquisitions"][0]));
        assert!(receipts.contains(&json!({
            "source_path": "/unavailable/historical-source.jsonl",
            "observed_at": "2001-01-01T00:00:00Z",
        })));
    }
    let replay = import::import_sources(&store, &discovery, &ImportOptions::default())
        .await
        .unwrap();
    assert!(replay.failures.is_empty(), "{:?}", replay.failures);
    assert_eq!(replay.imported, 0);
    assert_eq!(replay.already_present, 2);
    assert_eq!(all_events(&store).await, upgraded);
}

#[tokio::test]
async fn omp_companion_symlink_is_not_imported() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("omp/agent/sessions/-work");
    let session = root.join("sess.jsonl");
    fs::create_dir_all(session.parent().unwrap()).unwrap();
    fs::write(
        &session,
        b"{\"type\":\"session\",\"version\":3,\"id\":\"sess\",\"timestamp\":\"2026-10-22T10:00:00Z\",\"cwd\":\"/work\"}\n",
    )
    .unwrap();
    let secret = temp.path().join("secret");
    fs::create_dir_all(&secret).unwrap();
    fs::write(secret.join("id_rsa"), b"private-key").unwrap();
    std::os::unix::fs::symlink(&secret, session.with_file_name("sess")).unwrap();
    let store_dir = temp.path().join("store");
    let store = TraceStore::open(&store_dir).await.unwrap();
    let mut roots = BTreeMap::new();
    roots.insert(Harness::Omp, vec![temp.path().join("omp")]);
    let discovery = import::discover(&DiscoveryOptions {
        harnesses: [Harness::Omp].into(),
        roots,
        ..DiscoveryOptions::default()
    })
    .unwrap();
    let report = import::import_sources(&store, &discovery, &ImportOptions::default())
        .await
        .unwrap();
    assert!(report.failures.is_empty(), "{:?}", report.failures);
    let mut leaked = false;
    for entry in walkdir_files(&store_dir) {
        if fs::read(&entry)
            .unwrap()
            .windows(11)
            .any(|window| window == b"private-key")
        {
            leaked = true;
        }
    }
    assert!(!leaked, "symlink companion was imported");
}

fn walkdir_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_owned()];
    while let Some(directory) = stack.pop() {
        let Ok(entries) = fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.is_file() {
                files.push(path);
            }
        }
    }
    files
}

#[tokio::test]
async fn omp_referenced_blob_cap_precedes_digest_validation_in_both_import_modes() {
    let limit = 64 * 1024 + 1;
    for dry_run in [true, false] {
        for (size, valid_digest, expected_error) in [
            (limit + 1, false, Some("artifact exceeds configured")),
            (
                limit - 1,
                false,
                Some("do not match referenced SHA-256 digest"),
            ),
            (limit - 1, true, None),
            (limit, true, None),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("omp");
            let transcript = root.join("agent/sessions/-work/blob-cap.jsonl");
            let bytes = vec![b'x'; size];
            let digest = if valid_digest {
                format!("{:x}", Sha256::digest(&bytes))
            } else {
                "0".repeat(64)
            };
            write(&root.join("agent/blobs").join(&digest), &bytes);
            write(
                &transcript,
                format!(
                    "{}\n{}\n",
                    json!({"type": "session", "version": 3, "id": "blob-cap"}),
                    json!({
                        "type": "custom",
                        "id": "blob-reference",
                        "content": format!("blob:sha256:{digest}")
                    }),
                )
                .as_bytes(),
            );
            let discovery = import::discover(&DiscoveryOptions {
                harnesses: BTreeSet::from([Harness::Omp]),
                roots: BTreeMap::from([(Harness::Omp, Vec::new())]),
                sources: vec![(Harness::Omp, transcript)],
                ..DiscoveryOptions::default()
            })
            .unwrap();
            let options = ImportOptions {
                max_artifact_bytes: limit,
                dry_run,
                ..ImportOptions::default()
            };
            let report = if dry_run {
                import::dry_run_sources(&discovery, &options).await.unwrap()
            } else {
                let store = TraceStore::open(&temp.path().join("store")).await.unwrap();
                import::import_sources(&store, &discovery, &options)
                    .await
                    .unwrap()
            };
            if let Some(expected_error) = expected_error {
                assert_eq!(report.failures.len(), 1, "{:?}", report.failures);
                assert!(
                    report.failures[0].error.contains(expected_error),
                    "dry_run={dry_run}, size={size}: {:?}",
                    report.failures
                );
                if size > limit {
                    assert!(
                        !report.failures[0].error.contains("SHA-256"),
                        "{:?}",
                        report.failures
                    );
                }
            } else {
                assert!(report.failures.is_empty(), "{:?}", report.failures);
                if !dry_run {
                    let store = TraceStore::open(&temp.path().join("store")).await.unwrap();
                    let mut artifact = store.artifact(&digest).await.unwrap().unwrap();
                    let mut restored = Vec::new();
                    artifact.read_to_end(&mut restored).await.unwrap();
                    assert_eq!(restored, bytes);
                }
            }
        }
    }
}

#[tokio::test]
async fn sqlite_typed_native_keys_keep_sessions_and_composite_records_stable_after_rowid_moves() {
    let temp = tempfile::tempdir().unwrap();
    let database = temp.path().join("thread_history_1.sqlite");
    let connection = Connection::open(&database).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE thread_turns (thread_id, turn_id, marker TEXT);
             CREATE TABLE thread_items (thread_id, turn_id, item_id, marker TEXT);",
        )
        .unwrap();
    let session_keys = [
        "CAST(X'80FF' AS TEXT)",
        "X'80FF'",
        "'~sqlite:text:gP8='",
        "'~sqlite:blob:gP8='",
        "'~sqlite:utf8:fnNxbGl0ZTp0ZXh0OmdQOD0='",
        "'thread'",
        "X'746872656164'",
        "X''",
    ];
    for (index, key) in session_keys.iter().enumerate() {
        connection
            .execute(
                &format!("INSERT INTO thread_turns VALUES ({key}, 'same-turn', ?1)"),
                [format!("session-{index}")],
            )
            .unwrap();
    }
    let record_keys = [
        ("CAST(X'80FF' AS TEXT)", "'same'"),
        ("X'80FF'", "'same'"),
        ("'~sqlite:text:gP8='", "'same'"),
        ("'~sqlite:blob:gP8='", "'same'"),
        ("'same'", "CAST(X'80FF' AS TEXT)"),
        ("'same'", "X'80FF'"),
        ("'same'", "'~sqlite:text:gP8='"),
        ("'same'", "'~sqlite:blob:gP8='"),
        ("'a,b'", "'c'"),
        ("'a'", "'b,c'"),
        ("'ab'", "'c'"),
        ("'a'", "'bc'"),
    ];
    for (index, (turn, item)) in record_keys.iter().enumerate() {
        connection
            .execute(
                &format!("INSERT INTO thread_items VALUES ('record-session', {turn}, {item}, ?1)"),
                [format!("record-{index}")],
            )
            .unwrap();
    }
    let discovery = codex_database_discovery(&database);
    let store = TraceStore::open(&temp.path().join("store")).await.unwrap();
    let expected_records = (session_keys.len() + record_keys.len()) as u64;
    let first = import::import_sources(&store, &discovery, &ImportOptions::default())
        .await
        .unwrap();
    assert!(first.failures.is_empty(), "{:?}", first.failures);
    assert_eq!(first.imported, expected_records);
    let events = all_events(&store).await;
    assert_eq!(events.len(), expected_records as usize);
    assert!(
        events
            .iter()
            .all(|row| row["event"]["payload"]["revision"] == 1)
    );
    let sessions: BTreeSet<_> = events
        .iter()
        .map(|row| row["event"]["session_id"].as_str().unwrap())
        .collect();
    assert_eq!(sessions.len(), session_keys.len() + 1);
    let native_sessions: BTreeSet<_> = events
        .iter()
        .map(|row| {
            row["event"]["payload"]["native_session_id"]
                .as_str()
                .unwrap()
        })
        .collect();
    assert_eq!(native_sessions.len(), session_keys.len() + 1);
    let records: BTreeSet<_> = events
        .iter()
        .filter(|row| row["event"]["payload"]["stream"] == "sqlite:thread_items")
        .map(|row| {
            row["event"]["payload"]["native_record_id"]
                .as_str()
                .unwrap()
        })
        .collect();
    assert_eq!(records.len(), record_keys.len());
    let ordinary = events
        .iter()
        .find(|row| {
            row["event"]["payload"]["native"]["thread_id"]
                == json!({"encoding": "utf8", "value": "thread"})
        })
        .unwrap();
    assert_eq!(ordinary["event"]["payload"]["native_session_id"], "thread");

    connection
        .execute_batch(
            "UPDATE thread_turns SET rowid = rowid + 1000;
             UPDATE thread_items SET rowid = rowid + 1000;",
        )
        .unwrap();
    let replay = import::import_sources(&store, &discovery, &ImportOptions::default())
        .await
        .unwrap();
    assert!(replay.failures.is_empty(), "{:?}", replay.failures);
    assert_eq!(replay.imported, 0);
    assert_eq!(replay.already_present, expected_records);
    let after_relocation = all_events(&store).await;
    assert_eq!(after_relocation.len(), events.len());
    assert_eq!(
        after_relocation
            .iter()
            .map(|row| &row["event"])
            .collect::<Vec<_>>(),
        events.iter().map(|row| &row["event"]).collect::<Vec<_>>()
    );
}
