//! Conservative imports of provider-supplied ChatGPT, Claude, and Grok exports.

use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{self, BufReader, Read},
    path::{Component, Path, PathBuf},
    str::FromStr,
    time::SystemTime,
};

use anyhow::{Context, Result, bail, ensure};
use chrono::{SecondsFormat, TimeZone, Utc};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use zip::{CompressionMethod, ZipArchive};

use crate::trace::{ImportAcquisition, ImportRaw, ImportSnapshot, TraceStore};

pub const DEFAULT_MAX_MEMBERS: usize = 10_000;
pub const DEFAULT_MAX_MEMBER_BYTES: u64 = 256 * 1024 * 1024;
pub const DEFAULT_MAX_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;
pub const DEFAULT_MAX_COMPRESSION_RATIO: u64 = 100;
pub const DEFAULT_MAX_CONVERSATIONS: usize = 1_000_000;
pub const DEFAULT_MAX_JSON_DEPTH: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    Chatgpt,
    Claude,
    Grok,
}

impl Provider {
    fn adapter(self) -> &'static str {
        match self {
            Self::Chatgpt => "chatgpt_export",
            Self::Claude => "claude_export",
            Self::Grok => "grok_export",
        }
    }

    fn event_source(self) -> &'static str {
        match self {
            Self::Chatgpt => "provider_export_chatgpt",
            Self::Claude => "provider_export_claude",
            Self::Grok => "provider_export_grok",
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Chatgpt => "chatgpt",
            Self::Claude => "claude",
            Self::Grok => "grok",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ProviderSelection {
    #[default]
    Auto,
    Provider(Provider),
}

impl FromStr for ProviderSelection {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "auto" => Ok(Self::Auto),
            "chatgpt" => Ok(Self::Provider(Provider::Chatgpt)),
            "claude" => Ok(Self::Provider(Provider::Claude)),
            "grok" => Ok(Self::Provider(Provider::Grok)),
            _ => bail!("unsupported provider {value}; expected auto, chatgpt, claude, or grok"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ImportOptions {
    pub dry_run: bool,
    pub max_members: usize,
    pub max_member_bytes: u64,
    pub max_total_bytes: u64,
    pub max_compression_ratio: u64,
    pub max_conversations: usize,
    pub max_json_depth: usize,
}

impl Default for ImportOptions {
    fn default() -> Self {
        Self {
            dry_run: false,
            max_members: DEFAULT_MAX_MEMBERS,
            max_member_bytes: DEFAULT_MAX_MEMBER_BYTES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            max_compression_ratio: DEFAULT_MAX_COMPRESSION_RATIO,
            max_conversations: DEFAULT_MAX_CONVERSATIONS,
            max_json_depth: DEFAULT_MAX_JSON_DEPTH,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ImportFailure {
    pub path: PathBuf,
    pub error: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ImportReport {
    pub sources: u64,
    pub source_artifacts: u64,
    pub conversations_seen: u64,
    pub opaque_members_seen: u64,
    pub imported: u64,
    pub already_present: u64,
    pub providers: BTreeSet<String>,
    pub failures: Vec<ImportFailure>,
}

#[derive(Clone)]
struct SourceStamp {
    len: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl SourceStamp {
    fn matches(&self, metadata: &fs::Metadata) -> bool {
        if self.len != metadata.len() || self.modified != metadata.modified().ok() {
            return false;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            self.device == metadata.dev() && self.inode == metadata.ino()
        }
        #[cfg(not(unix))]
        {
            true
        }
    }
}

#[derive(Clone)]
struct OpaqueMember {
    index: usize,
    name: String,
    size: u64,
}

struct ParsedSource {
    provider: Provider,
    format: &'static str,
    digest: String,
    records: Vec<Value>,
    member_path: Option<String>,
    opaque_members: Vec<OpaqueMember>,
    is_zip: bool,
}

pub async fn import_sources(
    store: Option<&TraceStore>,
    sources: &[PathBuf],
    selection: ProviderSelection,
    account_scope: &str,
    options: &ImportOptions,
) -> Result<ImportReport> {
    validate_options(sources, account_scope, options)?;
    ensure!(
        options.dry_run || store.is_some(),
        "trace store is required unless dry_run is enabled"
    );
    let mut report = ImportReport::default();
    for source in sources {
        report.sources += 1;
        if let Err(error) = import_source(
            store,
            source,
            selection,
            account_scope,
            options,
            &mut report,
        )
        .await
        {
            report.failures.push(ImportFailure {
                path: source.clone(),
                error: format!("{error:#}"),
            });
        }
    }
    Ok(report)
}

fn validate_options(
    sources: &[PathBuf],
    account_scope: &str,
    options: &ImportOptions,
) -> Result<()> {
    ensure!(!sources.is_empty(), "at least one --source is required");
    ensure!(
        !account_scope.is_empty() && account_scope.len() <= 512,
        "account scope must contain 1 to 512 bytes"
    );
    ensure!(
        !account_scope.chars().any(char::is_control),
        "account scope contains control characters"
    );
    ensure!(options.max_members > 0, "max_members must be positive");
    ensure!(
        options.max_member_bytes > 0,
        "max_member_bytes must be positive"
    );
    ensure!(
        options.max_total_bytes > 0,
        "max_total_bytes must be positive"
    );
    ensure!(
        options.max_compression_ratio > 0,
        "max_compression_ratio must be positive"
    );
    ensure!(
        options.max_conversations > 0,
        "max_conversations must be positive"
    );
    ensure!(
        (1..=128).contains(&options.max_json_depth),
        "max_json_depth must be between 1 and 128"
    );
    Ok(())
}

async fn import_source(
    store: Option<&TraceStore>,
    source: &Path,
    selection: ProviderSelection,
    account_scope: &str,
    options: &ImportOptions,
    report: &mut ImportReport,
) -> Result<()> {
    let (mut file, stamp) = open_source(source)?;
    ensure!(
        stamp.len <= options.max_total_bytes,
        "source exceeds configured {} byte limit",
        options.max_total_bytes
    );
    let digest = hash_reader(&mut file)?;
    drop(file);
    let mut magic = [0u8; 4];
    let mut probe = open_source(source)?.0;
    let read = probe.read(&mut magic)?;
    drop(probe);
    let mut parsed = if read == magic.len() && magic == [b'P', b'K', 3, 4] {
        parse_zip(source, selection, options, digest.clone())?
    } else {
        parse_json(source, selection, options, digest.clone())?
    };
    ensure_source_unchanged(source, &stamp)?;

    report.source_artifacts += 1;
    report.conversations_seen += u64::try_from(parsed.records.len())?;
    report.opaque_members_seen += u64::try_from(parsed.opaque_members.len())?;
    report.providers.insert(parsed.provider.as_str().to_owned());
    if !options.dry_run {
        let store = store.context("trace store unavailable")?;
        let receipt = store
            .put_import_artifact(ImportRaw::File {
                path: source.to_path_buf(),
                max_bytes: options.max_total_bytes,
            })
            .await?;
        ensure!(
            receipt["digest"].as_str() == Some(parsed.digest.as_str()),
            "source changed while retaining its artifact"
        );
    }

    let namespace = format!(
        "provider:{}:account:{account_scope}",
        parsed.provider.as_str()
    );
    for (index, native) in parsed.records.drain(..).enumerate() {
        let identity = record_identity(parsed.provider, &native)?;
        let occurred_at = native_timestamp(parsed.provider, &native);
        let raw = serde_json::to_vec(&native)?;
        let logical_position = format!("conversation:{identity}");
        let acquisition_position = format!("index:{index}");
        let receipt = put_snapshot(
            store,
            options,
            ImportSnapshot {
                adapter: parsed.provider.adapter().to_owned(),
                event_source: parsed.provider.event_source().to_owned(),
                payload_schema: "infer.provider_export.v1".to_owned(),
                source_namespace: namespace.clone(),
                native_session_id: identity.clone(),
                stream: "conversations".to_owned(),
                native_record_id: identity,
                format: parsed.format.to_owned(),
                position: logical_position,
                occurred_at,
                parse_status: if has_unresolved_declarations(parsed.provider, &native) {
                    "validated_native_conversation_unresolved_references".to_owned()
                } else {
                    "validated_native_conversation".to_owned()
                },
                native: Some(native),
                raw: ImportRaw::Bytes(raw),
                acquisition: ImportAcquisition {
                    source_path: source.to_string_lossy().into_owned(),
                    source_digest: Some(parsed.digest.clone()),
                    member_path: parsed.member_path.clone(),
                    position: Some(acquisition_position),
                },
            },
        )
        .await?;
        count_receipt(receipt.as_ref(), report);
    }

    if parsed.is_zip {
        for member in parsed.opaque_members {
            if options.dry_run {
                continue;
            }
            let temporary = stage_zip_member(source, &member, options)?;
            let member_name = member.name.clone();
            let native = json!({
                "member_path": member_name,
                "declared_size": member.size,
                "association": "unassociated",
                "bytes_present": true,
            });
            let receipt = put_snapshot(
                store,
                options,
                ImportSnapshot {
                    adapter: "provider_export_attachment".to_owned(),
                    event_source: parsed.provider.event_source().to_owned(),
                    payload_schema: "infer.provider_export.v1".to_owned(),
                    source_namespace: namespace.clone(),
                    native_session_id: "unassociated-artifacts".to_owned(),
                    stream: "opaque_members".to_owned(),
                    native_record_id: member_name.clone(),
                    format: "zip_member".to_owned(),
                    position: format!("member:{member_name}"),
                    occurred_at: None,
                    parse_status: "opaque_unassociated_member".to_owned(),
                    native: Some(native),
                    raw: ImportRaw::File {
                        path: temporary.path().to_path_buf(),
                        max_bytes: options.max_member_bytes,
                    },
                    acquisition: ImportAcquisition {
                        source_path: source.to_string_lossy().into_owned(),
                        source_digest: Some(parsed.digest.clone()),
                        member_path: Some(member_name),
                        position: None,
                    },
                },
            )
            .await?;
            count_receipt(receipt.as_ref(), report);
        }
    }
    ensure_source_unchanged(source, &stamp)?;
    Ok(())
}

async fn put_snapshot(
    store: Option<&TraceStore>,
    options: &ImportOptions,
    snapshot: ImportSnapshot,
) -> Result<Option<Value>> {
    if options.dry_run {
        return Ok(None);
    }
    Ok(Some(
        store
            .context("trace store unavailable")?
            .put_import_snapshot(snapshot)
            .await?,
    ))
}

fn count_receipt(receipt: Option<&Value>, report: &mut ImportReport) {
    match receipt.and_then(|value| value["imported"].as_bool()) {
        Some(true) => report.imported += 1,
        Some(false) => report.already_present += 1,
        None => {}
    }
}

fn parse_json(
    source: &Path,
    selection: ProviderSelection,
    options: &ImportOptions,
    digest: String,
) -> Result<ParsedSource> {
    let mut bytes = Vec::new();
    open_source(source)?
        .0
        .take(options.max_total_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    ensure!(
        u64::try_from(bytes.len())? <= options.max_total_bytes,
        "JSON source exceeds configured byte limit"
    );
    let value = crate::json::from_slice(&bytes).context("decode provider export JSON")?;
    drop(bytes);
    validate_json_depth(&value, options.max_json_depth)?;
    let (provider, records) = recognize(value, selection, options.max_conversations)?;
    Ok(ParsedSource {
        provider,
        format: "native_json",
        digest,
        records,
        member_path: None,
        opaque_members: Vec::new(),
        is_zip: false,
    })
}

fn parse_zip(
    source: &Path,
    selection: ProviderSelection,
    options: &ImportOptions,
    digest: String,
) -> Result<ParsedSource> {
    let file = open_source(source)?.0;
    let mut archive = ZipArchive::new(BufReader::new(file)).context("open ZIP export")?;
    ensure!(
        archive.len() <= options.max_members,
        "ZIP has more than {} members",
        options.max_members
    );
    archive
        .validate_header_consistency()
        .context("validate ZIP local headers")?;
    ensure!(
        !archive.has_overlapping_entries()?,
        "ZIP contains overlapping entries"
    );
    let mut directory_names = BTreeSet::new();
    for name in archive.file_names() {
        let name = name.context("decode ZIP central-directory name")?;
        ensure!(
            directory_names.insert(name.into_owned()),
            "ZIP contains a duplicate member name"
        );
    }
    let mut names = BTreeSet::new();
    let mut total = 0u64;
    let mut candidate = None;
    let mut opaque_members = Vec::new();
    for index in 0..archive.len() {
        let mut member = archive.by_index(index).context("read ZIP member header")?;
        let name = validate_member(&member, &mut names, options)?;
        if member.is_dir() {
            continue;
        }
        total = total
            .checked_add(member.size())
            .context("ZIP size overflow")?;
        ensure!(
            total <= options.max_total_bytes,
            "ZIP decoded data exceeds configured {} byte limit",
            options.max_total_bytes
        );
        let known_conversation = name == "conversations.json" || name == "prod-grok-backend.json";
        if known_conversation {
            ensure!(
                candidate.is_none(),
                "ZIP contains multiple supported conversation members"
            );
            let mut bytes = Vec::new();
            (&mut member)
                .take(options.max_member_bytes.saturating_add(1))
                .read_to_end(&mut bytes)?;
            ensure!(
                u64::try_from(bytes.len())? <= options.max_member_bytes,
                "conversation member exceeds configured byte limit"
            );
            let value = crate::json::from_slice(&bytes)
                .with_context(|| format!("decode provider member {name}"))?;
            drop(bytes);
            validate_json_depth(&value, options.max_json_depth)?;
            let (provider, records) = recognize(value, selection, options.max_conversations)?;
            ensure!(
                (provider == Provider::Grok) == (name == "prod-grok-backend.json"),
                "provider shape does not match documented ZIP member name"
            );
            candidate = Some((provider, records, name));
        } else {
            let mut first = [0u8; 6];
            let mut read = 0usize;
            let mut buffer = [0u8; 64 * 1024];
            let mut decoded = 0u64;
            loop {
                let count = member.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                let capture = (first.len() - read).min(count);
                first[read..read + capture].copy_from_slice(&buffer[..capture]);
                read += capture;
                decoded = decoded
                    .checked_add(u64::try_from(count)?)
                    .context("ZIP size overflow")?;
                ensure!(
                    decoded <= options.max_member_bytes,
                    "ZIP member exceeds byte limit"
                );
            }
            ensure!(decoded == member.size(), "ZIP member decoded size mismatch");
            ensure!(
                !is_nested_archive(&name, &first[..read]),
                "nested archive member is unsupported"
            );
            opaque_members.push(OpaqueMember {
                index,
                name,
                size: decoded,
            });
        }
    }
    let (provider, records, member_path) =
        candidate.context("ZIP contains no supported provider conversation member")?;
    Ok(ParsedSource {
        provider,
        format: "zip_export",
        digest,
        records,
        member_path: Some(member_path),
        opaque_members,
        is_zip: true,
    })
}

fn validate_member<R: Read>(
    member: &zip::read::ZipFile<R>,
    names: &mut BTreeSet<String>,
    options: &ImportOptions,
) -> Result<String> {
    ensure!(!member.encrypted(), "encrypted ZIP members are unsupported");
    ensure!(
        matches!(
            member.compression(),
            CompressionMethod::Stored | CompressionMethod::Deflated
        ),
        "unsupported ZIP compression method"
    );
    ensure!(
        member.size() <= options.max_member_bytes,
        "ZIP member exceeds configured {} byte limit",
        options.max_member_bytes
    );
    if member.size() > 0 {
        ensure!(
            member.compressed_size() > 0,
            "ZIP member has an invalid compression ratio"
        );
        ensure!(
            member.size()
                <= member
                    .compressed_size()
                    .saturating_mul(options.max_compression_ratio),
            "ZIP member exceeds configured compression ratio"
        );
    }
    let name = member.name().context("decode ZIP member name")?;
    ensure!(!name.is_empty(), "ZIP member name is empty");
    ensure!(
        !name.contains('\\'),
        "ZIP member uses backslash path separators"
    );
    ensure!(
        !name.chars().any(char::is_control),
        "ZIP member name contains control characters"
    );
    ensure!(!name.starts_with('/'), "ZIP member path is absolute");
    ensure!(
        !(name.len() >= 2 && name.as_bytes()[1] == b':'),
        "ZIP member path uses a drive prefix"
    );
    let path = Path::new(name.as_ref());
    for component in path.components() {
        ensure!(
            matches!(component, Component::Normal(_)),
            "ZIP member path is not confined"
        );
    }
    let normalized = path.to_string_lossy().into_owned();
    ensure!(
        names.insert(normalized.clone()),
        "ZIP contains a duplicate member name"
    );
    ensure!(
        member.is_file() || member.is_dir(),
        "ZIP links and special entries are unsupported"
    );
    Ok(normalized)
}

fn is_nested_archive(name: &str, prefix: &[u8]) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".zip")
        || lower.ends_with(".tar")
        || lower.ends_with(".tar.gz")
        || lower.ends_with(".tgz")
        || lower.ends_with(".7z")
        || lower.ends_with(".rar")
        || prefix.starts_with(b"PK\x03\x04")
        || prefix.starts_with(&[0x1f, 0x8b])
        || prefix.starts_with(b"7z\xbc\xaf\x27\x1c")
}

fn stage_zip_member(
    source: &Path,
    member: &OpaqueMember,
    options: &ImportOptions,
) -> Result<NamedTempFile> {
    let file = open_source(source)?.0;
    let mut archive = ZipArchive::new(BufReader::new(file))?;
    let input = archive.by_index(member.index)?;
    ensure!(
        input
            .name()
            .context("decode staged ZIP member name")?
            .as_ref()
            == member.name,
        "ZIP member order changed during import"
    );
    let mut temporary = NamedTempFile::new().context("create private ZIP member staging file")?;
    let copied = io::copy(
        &mut input.take(options.max_member_bytes.saturating_add(1)),
        &mut temporary,
    )?;
    ensure!(copied == member.size, "ZIP member changed during import");
    temporary.as_file().sync_all()?;
    Ok(temporary)
}

fn recognize(
    value: Value,
    selection: ProviderSelection,
    max_conversations: usize,
) -> Result<(Provider, Vec<Value>)> {
    let detected = detect_provider(&value)?;
    if let ProviderSelection::Provider(expected) = selection {
        ensure!(
            detected == expected,
            "export JSON does not match the selected provider shape"
        );
    }
    // Move the validated record array out of the root. Cloning here briefly
    // held two complete conversation trees for large, otherwise bounded exports.
    let records = match (detected, value) {
        (Provider::Chatgpt | Provider::Claude, Value::Array(records)) => records,
        (Provider::Grok, Value::Object(mut root)) => match root.remove("conversations") {
            Some(Value::Array(records)) => records,
            _ => bail!("validated Grok export lost conversations"),
        },
        _ => bail!("validated provider export lost its root shape"),
    };
    ensure!(
        records.len() <= max_conversations,
        "export exceeds conversation limit"
    );
    Ok((detected, records))
}

fn detect_provider(value: &Value) -> Result<Provider> {
    if let Some(records) = value.as_array() {
        ensure!(
            !records.is_empty(),
            "empty arrays are not provider conversation evidence"
        );
        let chatgpt = records.iter().all(valid_chatgpt_conversation);
        let claude = records.iter().all(valid_claude_conversation);
        return match (chatgpt, claude) {
            (true, false) => Ok(Provider::Chatgpt),
            (false, true) => Ok(Provider::Claude),
            (false, false) => {
                bail!("JSON does not match a supported ChatGPT or Claude export shape")
            }
            (true, true) => bail!("provider export shape is ambiguous"),
        };
    }
    if valid_grok_root(value) {
        return Ok(Provider::Grok);
    }
    bail!("JSON does not match a supported provider export shape")
}

fn valid_chatgpt_conversation(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    let has_id = object.get("id").and_then(Value::as_str).is_some()
        || object
            .get("conversation_id")
            .and_then(Value::as_str)
            .is_some();
    let Some(mapping) = object.get("mapping").and_then(Value::as_object) else {
        return false;
    };
    has_id
        && !mapping.is_empty()
        && mapping.iter().all(|(node_id, node)| {
            !node_id.is_empty()
                && node.as_object().is_some_and(|node| {
                    node.get("id").and_then(Value::as_str).is_some()
                        && node.get("children").is_some_and(Value::is_array)
                        && node.get("message").is_some_and(|message| {
                            message.is_null()
                                || message.as_object().is_some_and(|message| {
                                    message.get("id").and_then(Value::as_str).is_some()
                                        && message.get("author").is_some_and(Value::is_object)
                                        && message.get("content").is_some_and(Value::is_object)
                                })
                        })
                })
        })
}

fn valid_claude_conversation(value: &Value) -> bool {
    value.as_object().is_some_and(|conversation| {
        conversation.get("uuid").and_then(Value::as_str).is_some()
            && conversation
                .get("chat_messages")
                .and_then(Value::as_array)
                .is_some_and(|messages| {
                    messages.iter().all(|message| {
                        message.as_object().is_some_and(|message| {
                            message.get("uuid").and_then(Value::as_str).is_some()
                                && message.get("sender").and_then(Value::as_str).is_some()
                                && (message.contains_key("text") || message.contains_key("content"))
                        })
                    })
                })
    })
}

fn valid_grok_root(value: &Value) -> bool {
    value
        .get("conversations")
        .and_then(Value::as_array)
        .is_some_and(|records| {
            !records.is_empty()
                && records.iter().all(|item| {
                    let Some(conversation) = item.get("conversation").and_then(Value::as_object)
                    else {
                        return false;
                    };
                    conversation.get("id").and_then(Value::as_str).is_some()
                        && item.get("responses").and_then(Value::as_array).is_some_and(
                            |responses| {
                                responses.iter().all(|wrapper| {
                                    wrapper
                                        .get("response")
                                        .and_then(Value::as_object)
                                        .is_some_and(|response| {
                                            response.get("_id").and_then(Value::as_str).is_some()
                                                && response
                                                    .get("sender")
                                                    .and_then(Value::as_str)
                                                    .is_some()
                                                && response.contains_key("message")
                                        })
                                })
                            },
                        )
                })
        })
}

fn has_unresolved_declarations(provider: Provider, value: &Value) -> bool {
    match provider {
        Provider::Chatgpt => {
            let mut pending = vec![value];
            while let Some(value) = pending.pop() {
                match value {
                    Value::Array(values) => pending.extend(values),
                    Value::Object(values) => {
                        if values
                            .get("asset_pointer")
                            .and_then(Value::as_str)
                            .is_some()
                        {
                            return true;
                        }
                        pending.extend(values.values());
                    }
                    _ => {}
                }
            }
            false
        }
        Provider::Claude => value
            .get("chat_messages")
            .and_then(Value::as_array)
            .is_some_and(|messages| {
                messages.iter().any(|message| {
                    ["attachments", "files"].iter().any(|field| {
                        message
                            .get(field)
                            .and_then(Value::as_array)
                            .is_some_and(|values| !values.is_empty())
                    })
                })
            }),
        Provider::Grok => false,
    }
}

fn record_identity(provider: Provider, value: &Value) -> Result<String> {
    let identity = match provider {
        Provider::Chatgpt => value
            .get("id")
            .or_else(|| value.get("conversation_id"))
            .and_then(Value::as_str),
        Provider::Claude => value.get("uuid").and_then(Value::as_str),
        Provider::Grok => value
            .get("conversation")
            .and_then(|conversation| conversation.get("id"))
            .and_then(Value::as_str),
    }
    .context("validated conversation lost its native identity")?;
    ensure!(
        !identity.is_empty() && identity.len() <= 4096,
        "native conversation ID is invalid"
    );
    ensure!(
        !identity.chars().any(char::is_control),
        "native conversation ID contains controls"
    );
    Ok(identity.to_owned())
}

fn native_timestamp(provider: Provider, value: &Value) -> Option<String> {
    match provider {
        Provider::Chatgpt => value
            .get("update_time")
            .and_then(epoch_seconds)
            .or_else(|| value.get("create_time").and_then(epoch_seconds)),
        Provider::Claude => value
            .get("updated_at")
            .and_then(rfc3339)
            .or_else(|| value.get("created_at").and_then(rfc3339)),
        Provider::Grok => value
            .get("responses")
            .and_then(Value::as_array)
            .and_then(|responses| responses.last())
            .and_then(|wrapper| wrapper.pointer("/response/create_time/$date/$numberLong"))
            .and_then(Value::as_str)
            .and_then(|millis| millis.parse::<i64>().ok())
            .and_then(|millis| Utc.timestamp_millis_opt(millis).single())
            .map(|timestamp| timestamp.to_rfc3339_opts(SecondsFormat::Millis, true)),
    }
}

fn rfc3339(value: &Value) -> Option<String> {
    value
        .as_str()
        .filter(|timestamp| chrono::DateTime::parse_from_rfc3339(timestamp).is_ok())
        .map(str::to_owned)
}

fn epoch_seconds(value: &Value) -> Option<String> {
    let text = value.as_number()?.to_string();
    let (seconds, fraction) = text.split_once('.').unwrap_or((&text, ""));
    let seconds = seconds.parse::<i64>().ok()?;
    if fraction.len() > 9 || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let mut nanos = fraction.to_owned();
    nanos.extend(std::iter::repeat_n('0', 9 - nanos.len()));
    let nanos = if nanos.is_empty() {
        0
    } else {
        nanos.parse::<u32>().ok()?
    };
    Utc.timestamp_opt(seconds, nanos)
        .single()
        .map(|timestamp| timestamp.to_rfc3339_opts(SecondsFormat::AutoSi, true))
}

fn validate_json_depth(value: &Value, maximum: usize) -> Result<()> {
    let mut pending = vec![(value, 1usize)];
    while let Some((value, depth)) = pending.pop() {
        ensure!(depth <= maximum, "JSON exceeds configured nesting depth");
        match value {
            Value::Array(values) => pending.extend(values.iter().map(|value| (value, depth + 1))),
            Value::Object(values) => {
                pending.extend(values.values().map(|value| (value, depth + 1)))
            }
            _ => {}
        }
    }
    Ok(())
}

fn open_source(path: &Path) -> Result<(File, SourceStamp)> {
    let metadata = fs::symlink_metadata(path).context("inspect provider export source")?;
    ensure!(
        metadata.file_type().is_file(),
        "source must be a regular file, not a symlink"
    );
    let file = File::open(path).context("open provider export source")?;
    let opened = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            metadata.dev() == opened.dev() && metadata.ino() == opened.ino(),
            "provider export source changed while opening"
        );
    }
    Ok((
        file,
        SourceStamp {
            len: opened.len(),
            modified: opened.modified().ok(),
            #[cfg(unix)]
            device: {
                use std::os::unix::fs::MetadataExt;
                opened.dev()
            },
            #[cfg(unix)]
            inode: {
                use std::os::unix::fs::MetadataExt;
                opened.ino()
            },
        },
    ))
}

fn ensure_source_unchanged(path: &Path, stamp: &SourceStamp) -> Result<()> {
    let metadata = fs::symlink_metadata(path).context("reinspect provider export source")?;
    ensure!(
        metadata.file_type().is_file(),
        "provider export source type changed"
    );
    ensure!(
        stamp.matches(&metadata),
        "provider export source changed during import"
    );
    Ok(())
}

fn hash_reader(reader: &mut File) -> Result<String> {
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hash.finalize()))
}
