use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use infer::{
    provider_export::{self, ImportOptions, Provider, ProviderSelection},
    trace::TraceStore,
};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::io::AsyncReadExt;
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

fn chatgpt() -> Value {
    json!([{
        "id": "chat-conversation",
        "title": "sanitized",
        "create_time": serde_json::from_str::<Value>("1700000000.123456789").unwrap(),
        "update_time": null,
        "current_node": "assistant-b",
        "unknown_root": {"precise": 123456789012345678901234567890i128},
        "mapping": {
            "root": {"id": "root", "parent": null, "children": ["user"], "message": null},
            "user": {"id": "user", "parent": "root", "children": ["assistant-a", "assistant-b"], "message": {
                "id": "message-user", "author": {"role": "user", "name": null},
                "recipient": "all", "channel": null, "create_time": null,
                "content": {"content_type": "multimodal_text", "parts": [
                    {"content_type": "image_asset_pointer", "asset_pointer": "file-service://missing", "size_bytes": 9},
                    "sanitized prompt"
                ]}, "metadata": {"unknown": true}
            }},
            "assistant-a": {"id": "assistant-a", "parent": "user", "children": [], "message": {
                "id": "message-a", "author": {"role": "assistant"}, "recipient": "all", "channel": "final",
                "content": {"content_type": "text", "parts": ["branch a"]}, "metadata": {}
            }},
            "assistant-b": {"id": "assistant-b", "parent": "user", "children": [], "message": {
                "id": "message-b", "author": {"role": "assistant"}, "recipient": "all", "channel": "final",
                "content": {"content_type": "text", "parts": ["branch b"]}, "metadata": {"model_slug": "example"}
            }}
        }
    }])
}

fn claude() -> Value {
    json!([{
        "uuid": "claude-conversation",
        "name": "sanitized",
        "summary": null,
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:01:00Z",
        "account": {"uuid": "account-fixture"},
        "chat_messages": [{
            "uuid": "claude-message",
            "sender": "assistant",
            "text": "<antThinking>literal fixture text</antThinking><antArtifact identifier=\"a\">literal artifact</antArtifact>",
            "content": [{"type": "text", "text": "literal block"}],
            "created_at": "2024-01-01T00:00:30Z",
            "updated_at": "2024-01-01T00:00:31Z",
            "parent_message_uuid": null,
            "attachments": [{"file_name": "declared-only.bin"}],
            "files": [{"file_name": "declared-only.bin"}],
            "unknown_message": {"kept": true}
        }],
        "unknown_conversation": [1, 2, 3]
    }])
}

fn grok() -> Value {
    json!({"conversations": [{
        "conversation": {
            "id": "grok-conversation", "user_id": "fixture-user", "title": "sanitized",
            "create_time": "native-unknown-shape", "modify_time": null, "starred": false,
            "unknown_conversation": {"kept": true}
        },
        "responses": [{"response": {
            "_id": "grok-response", "conversation_id": "grok-conversation",
            "message": "sanitized response", "sender": "assistant", "model": "fixture-model",
            "create_time": {"$date": {"$numberLong": "1700000000123"}},
            "agent_thinking_traces": [{"thinking_trace": "native optional fixture field"}],
            "unknown_response": ["kept"]
        }}],
        "unknown_wrapper": true
    }]})
}

fn write_json(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}

fn write_zip(
    path: &Path,
    member: &str,
    value: &Value,
    opaque: Option<(&str, &[u8])>,
    stored: bool,
) {
    let file = fs::File::create(path).unwrap();
    let mut zip = ZipWriter::new(file);
    let method = if stored {
        CompressionMethod::Stored
    } else {
        CompressionMethod::Deflated
    };
    let options = SimpleFileOptions::default().compression_method(method);
    zip.start_file(member, options).unwrap();
    zip.write_all(&serde_json::to_vec(value).unwrap()).unwrap();
    if let Some((name, bytes)) = opaque {
        zip.start_file(name, options).unwrap();
        zip.write_all(bytes).unwrap();
    }
    zip.finish().unwrap();
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
async fn maximum_export_byte_limits_accept_small_json_and_zip_sources() {
    let temp = tempfile::tempdir().unwrap();
    let raw = temp.path().join("conversations.json");
    let zip = temp.path().join("export.zip");
    write_json(&raw, &claude());
    write_zip(
        &zip,
        "conversations.json",
        &claude(),
        Some(("attachments/binary.bin", b"binary bytes")),
        true,
    );
    for dry_run in [true, false] {
        let store = if dry_run {
            None
        } else {
            Some(TraceStore::open(&temp.path().join("store")).await.unwrap())
        };
        let report = provider_export::import_sources(
            store.as_ref(),
            &[raw.clone(), zip.clone()],
            ProviderSelection::Auto,
            "maximum-byte-limit",
            &ImportOptions {
                dry_run,
                max_total_bytes: u64::MAX,
                max_member_bytes: u64::MAX,
                ..ImportOptions::default()
            },
        )
        .await
        .unwrap();
        assert!(report.failures.is_empty(), "{:?}", report.failures);
        assert_eq!(report.conversations_seen, 2);
        assert_eq!(report.opaque_members_seen, 1);
    }
}

struct Fixtures {
    temp: TempDir,
    raw: Vec<PathBuf>,
    zip: Vec<PathBuf>,
    binary: Vec<u8>,
}

impl Fixtures {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let chat_raw = temp.path().join("chat-without-suffix");
        let claude_raw = temp.path().join("claude.misleading");
        let grok_raw = temp.path().join("grok.json");
        write_json(&chat_raw, &chatgpt());
        write_json(&claude_raw, &claude());
        write_json(&grok_raw, &grok());
        let chat_zip = temp.path().join("chat.zip");
        let claude_zip = temp.path().join("claude.zip");
        let grok_zip = temp.path().join("grok.zip");
        let binary = vec![0, 159, 146, 150, 255, 1, 2, 3];
        write_zip(
            &chat_zip,
            "conversations.json",
            &chatgpt(),
            Some(("opaque/non-utf8.bin", &binary)),
            false,
        );
        write_zip(&claude_zip, "conversations.json", &claude(), None, false);
        write_zip(&grok_zip, "prod-grok-backend.json", &grok(), None, true);
        Self {
            temp,
            raw: vec![chat_raw, claude_raw, grok_raw],
            zip: vec![chat_zip, claude_zip, grok_zip],
            binary,
        }
    }
}

#[tokio::test]
async fn native_json_and_zip_preserve_provider_shapes_and_opaque_members() {
    let fixtures = Fixtures::new();
    let original_bytes = fixtures
        .raw
        .iter()
        .chain(&fixtures.zip)
        .map(fs::read)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let store = TraceStore::open(&fixtures.temp.path().join("store"))
        .await
        .unwrap();
    let first = provider_export::import_sources(
        Some(&store),
        &fixtures.raw,
        ProviderSelection::Auto,
        "fixture-account",
        &ImportOptions::default(),
    )
    .await
    .unwrap();
    assert!(first.failures.is_empty(), "{:?}", first.failures);
    assert_eq!(first.imported, 3);
    assert_eq!(first.providers.len(), 3);

    let second = provider_export::import_sources(
        Some(&store),
        &fixtures.zip,
        ProviderSelection::Auto,
        "fixture-account",
        &ImportOptions::default(),
    )
    .await
    .unwrap();
    assert!(second.failures.is_empty(), "{:?}", second.failures);
    assert_eq!(second.already_present, 3);
    assert_eq!(second.imported, 1);
    assert_eq!(second.opaque_members_seen, 1);

    let events = all_events(&store).await;
    assert_eq!(events.len(), 4);
    let chat = events
        .iter()
        .find(|row| row.pointer("/event/payload/source_adapter") == Some(&json!("chatgpt_export")))
        .unwrap();
    assert_eq!(
        chat.pointer("/event/payload/native/mapping/user/children"),
        Some(&json!(["assistant-a", "assistant-b"]))
    );
    assert!(
        chat.pointer("/event/payload/native/mapping/root/message")
            .unwrap()
            .is_null()
    );
    assert_eq!(
        chat.pointer("/event/payload/parse_status"),
        Some(&json!(
            "validated_native_conversation_unresolved_references"
        ))
    );
    assert_eq!(
        chat.pointer("/event/occurred_at"),
        Some(&json!("2023-11-14T22:13:20.123456789Z"))
    );
    assert_eq!(chat["acquisitions"].as_array().unwrap().len(), 2);
    assert!(
        chat["acquisitions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|receipt| {
                receipt["member_path"] == "conversations.json"
                    && receipt["source_digest"].as_str().is_some()
            })
    );

    let claude_event = events
        .iter()
        .find(|row| row.pointer("/event/payload/source_adapter") == Some(&json!("claude_export")))
        .unwrap();
    assert!(
        claude_event
            .pointer("/event/payload/native/chat_messages/0/text")
            .and_then(Value::as_str)
            .unwrap()
            .contains("<antThinking>")
    );
    let grok_event = events
        .iter()
        .find(|row| row.pointer("/event/payload/source_adapter") == Some(&json!("grok_export")))
        .unwrap();
    assert_eq!(
        grok_event.pointer(
            "/event/payload/native/responses/0/response/agent_thinking_traces/0/thinking_trace"
        ),
        Some(&json!("native optional fixture field"))
    );
    assert_eq!(
        grok_event.pointer("/event/occurred_at"),
        Some(&json!("2023-11-14T22:13:20.123Z"))
    );

    let opaque = events
        .iter()
        .find(|row| {
            row.pointer("/event/payload/source_adapter")
                == Some(&json!("provider_export_attachment"))
        })
        .unwrap();
    assert_eq!(
        opaque.pointer("/event/payload/native/association"),
        Some(&json!("unassociated"))
    );
    let digest = opaque
        .pointer("/event/payload/raw_artifact/digest")
        .and_then(Value::as_str)
        .unwrap();
    let mut artifact = store.artifact(digest).await.unwrap().unwrap();
    let mut binary = Vec::new();
    artifact.read_to_end(&mut binary).await.unwrap();
    assert_eq!(binary, fixtures.binary);

    let final_bytes = fixtures
        .raw
        .iter()
        .chain(&fixtures.zip)
        .map(fs::read)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(final_bytes, original_bytes);
}

#[tokio::test]
async fn identity_survives_move_repack_and_accounts_while_changes_append_revisions() {
    let fixtures = Fixtures::new();
    let store = TraceStore::open(&fixtures.temp.path().join("store"))
        .await
        .unwrap();
    let source = &fixtures.raw[0];
    let initial = provider_export::import_sources(
        Some(&store),
        std::slice::from_ref(source),
        ProviderSelection::Provider(Provider::Chatgpt),
        "account-a",
        &ImportOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(initial.imported, 1);

    let moved = fixtures.temp.path().join("moved-and-repacked.zip");
    write_zip(&moved, "conversations.json", &chatgpt(), None, true);
    let replay = provider_export::import_sources(
        Some(&store),
        std::slice::from_ref(&moved),
        ProviderSelection::Auto,
        "account-a",
        &ImportOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(replay.imported, 0);
    assert_eq!(replay.already_present, 1);

    let isolated = provider_export::import_sources(
        Some(&store),
        std::slice::from_ref(&moved),
        ProviderSelection::Auto,
        "account-b",
        &ImportOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(isolated.imported, 1);

    let mut changed = chatgpt();
    changed[0]["title"] = json!("changed snapshot");
    write_json(source, &changed);
    let revision = provider_export::import_sources(
        Some(&store),
        std::slice::from_ref(source),
        ProviderSelection::Auto,
        "account-a",
        &ImportOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(revision.imported, 1);
    let mut revisions = all_events(&store)
        .await
        .into_iter()
        .filter(|row| {
            row.pointer("/event/payload/native_record_id") == Some(&json!("chat-conversation"))
                && row.pointer("/event/payload/source_namespace")
                    == Some(&json!("provider:chatgpt:account:account-a"))
        })
        .map(|row| {
            row.pointer("/event/payload/revision")
                .unwrap()
                .as_i64()
                .unwrap()
        })
        .collect::<Vec<_>>();
    revisions.sort_unstable();
    assert_eq!(revisions, vec![1, 2]);
}

fn malicious_zip(path: &Path, members: &[(&str, &[u8])]) {
    let file = fs::File::create(path).unwrap();
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for (name, bytes) in members {
        zip.start_file(*name, options).unwrap();
        zip.write_all(bytes).unwrap();
    }
    zip.finish().unwrap();
}

fn rename_zip_member_bytes(path: &Path, from: &[u8], to: &[u8]) {
    assert_eq!(from.len(), to.len());
    let mut bytes = fs::read(path).unwrap();
    let mut offset = 0;
    while let Some(relative) = bytes[offset..]
        .windows(from.len())
        .position(|window| window == from)
    {
        let start = offset + relative;
        bytes[start..start + to.len()].copy_from_slice(to);
        offset = start + to.len();
    }
    fs::write(path, bytes).unwrap();
}

#[tokio::test]
async fn recognition_and_archive_boundaries_fail_without_hiding_valid_sources() {
    let temp = tempfile::tempdir().unwrap();
    let generic = temp.path().join("generic.json");
    write_json(
        &generic,
        &json!({"messages": [{"role": "user", "content": "not evidence"}]}),
    );
    let traversal = temp.path().join("traversal.zip");
    malicious_zip(
        &traversal,
        &[
            (
                "conversations.json",
                &serde_json::to_vec(&chatgpt()).unwrap(),
            ),
            ("safe/escape.bin", b"no"),
        ],
    );
    rename_zip_member_bytes(&traversal, b"safe/escape.bin", b"../x/escape.bin");
    let duplicate = temp.path().join("duplicate.zip");
    let chat = serde_json::to_vec(&chatgpt()).unwrap();
    malicious_zip(
        &duplicate,
        &[("conversation1.json", &chat), ("conversation2.json", &chat)],
    );
    rename_zip_member_bytes(&duplicate, b"conversation1.json", b"conversations.json");
    rename_zip_member_bytes(&duplicate, b"conversation2.json", b"conversations.json");
    let nested = temp.path().join("nested.zip");
    malicious_zip(
        &nested,
        &[
            ("conversations.json", &chat),
            ("opaque/inner.zip", b"PK\x03\x04xx"),
        ],
    );
    let sidecar = temp.path().join("sidecar.zip");
    malicious_zip(&sidecar, &[("account.json", br#"{"uuid":"only-sidecar"}"#)]);
    let valid = temp.path().join("valid.json");
    write_json(&valid, &grok());
    let destination = temp.path().join("dry-run-destination");
    let sources = vec![generic, traversal, duplicate, nested, sidecar, valid];
    let report = provider_export::import_sources(
        None,
        &sources,
        ProviderSelection::Auto,
        "fixture-account",
        &ImportOptions {
            dry_run: true,
            ..ImportOptions::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(report.failures.len(), 5, "{report:?}");
    assert_eq!(report.conversations_seen, 1);
    assert_eq!(report.providers, ["grok".to_owned()].into_iter().collect());
    assert!(!destination.exists());

    let mismatch = provider_export::import_sources(
        None,
        std::slice::from_ref(&sources[5]),
        ProviderSelection::Provider(Provider::Claude),
        "fixture-account",
        &ImportOptions {
            dry_run: true,
            ..ImportOptions::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(mismatch.failures.len(), 1);
}
