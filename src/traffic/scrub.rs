//! Scrub captures before they can be committed, and reject token-shaped fixtures.
//!
//! Raw recordings stay outside the repository. A committed fixture may contain
//! the placeholders this module writes and must not contain the patterns below.

use std::{fs, path::Path};

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value};

const PLACEHOLDER_REDACTED: &str = "<redacted>";
const PLACEHOLDER_JWT: &str = "<jwt>";
const PLACEHOLDER_SECRET: &str = "<secret>";
const PLACEHOLDER_BLOB: &str = "<blob>";
const PLACEHOLDER_EMAIL: &str = "<email>";

/// Header names removed from objects stored under a `headers` key. A
/// placeholder value would still be an auth or cookie header in the fixture.
const REMOVED_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "api-key",
    "x-api-key",
    "x-auth-key",
    "x-auth-email",
    "x-auth-token",
    "x-access-token",
    "x-infer-key",
    "chatgpt-account-id",
];

pub fn scrub_value(value: Value) -> Value {
    scrub(value, false)
}

fn scrub(value: Value, headers: bool) -> Value {
    match value {
        Value::Object(map) => Value::Object(scrub_object(map, headers)),
        Value::Array(items) => {
            Value::Array(items.into_iter().map(|item| scrub(item, false)).collect())
        }
        Value::String(text) => Value::String(scrub_text(&text)),
        other => other,
    }
}

fn scrub_object(map: Map<String, Value>, headers: bool) -> Map<String, Value> {
    let mut out = Map::new();
    for (key, value) in map {
        if headers && remove_header(&key) {
            continue;
        }
        let nested = key.eq_ignore_ascii_case("headers");
        out.insert(key, scrub(value, nested));
    }
    out
}

fn remove_header(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    REMOVED_HEADERS.contains(&name.as_str())
        || name.ends_with("-api-key")
        || name.contains("token")
        || name.contains("secret")
}

pub fn scrub_text(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::new();
    let mut index = 0;
    while index < bytes.len() {
        if let Some(end) = bearer_at(bytes, index) {
            out.push_str(PLACEHOLDER_REDACTED);
            index = end;
            continue;
        }
        if let Some(end) = jwt_at(bytes, index) {
            out.push_str(PLACEHOLDER_JWT);
            index = end;
            continue;
        }
        if let Some(end) = secret_key_at(bytes, index) {
            out.push_str(PLACEHOLDER_SECRET);
            index = end;
            continue;
        }
        if let Some(end) = email_at(bytes, index) {
            out.push_str(PLACEHOLDER_EMAIL);
            index = end;
            continue;
        }
        if let Some(end) = long_base64_at(bytes, index) {
            out.push_str(PLACEHOLDER_BLOB);
            index = end;
            continue;
        }
        let ch = text[index..]
            .chars()
            .next()
            .expect("index on a char boundary");
        out.push(ch);
        index += ch.len_utf8();
    }
    out
}

/// Reasons a committed fixture must be rejected. Empty means the text is clean.
pub fn findings(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    let bytes = text.as_bytes();
    let mut index = 0;
    let mut bearer = false;
    let mut jwt = false;
    let mut secret = false;
    let mut email = false;
    let mut blob = false;
    while index < bytes.len() {
        if let Some(end) = bearer_at(bytes, index) {
            bearer = true;
            index = end;
            continue;
        }
        if let Some(end) = jwt_at(bytes, index) {
            jwt = true;
            index = end;
            continue;
        }
        if let Some(end) = secret_key_at(bytes, index) {
            secret = true;
            index = end;
            continue;
        }
        if let Some(end) = email_at(bytes, index) {
            email = true;
            index = end;
            continue;
        }
        if let Some(end) = long_base64_at(bytes, index) {
            blob = true;
            index = end;
            continue;
        }
        index += text[index..]
            .chars()
            .next()
            .expect("index on a char boundary")
            .len_utf8();
    }
    if bearer {
        found.push("bearer token".to_owned());
    }
    if jwt {
        found.push("JWT".to_owned());
    }
    if secret {
        found.push("sk- key".to_owned());
    }
    if email {
        found.push("email address".to_owned());
    }
    if blob {
        found.push("long base64 blob".to_owned());
    }
    let lowered = text.to_ascii_lowercase();
    for name in REMOVED_HEADERS {
        if lowered.contains(&format!("\"{name}\"")) {
            found.push(format!("{name} header"));
        }
    }
    found
}

pub fn assert_clean(dir: &Path) -> Result<()> {
    let mut files = Vec::new();
    collect_files(dir, &mut files)?;
    files.sort();
    if files.is_empty() {
        bail!("{} has no fixtures", dir.display());
    }
    for path in files {
        let text = fs::read_to_string(&path)
            .with_context(|| format!("{} is not UTF-8 text", path.display()))?;
        let found = findings(&text);
        if !found.is_empty() {
            bail!("{} contains {}", path.display(), found.join(", "));
        }
    }
    Ok(())
}

fn collect_files(dir: &Path, files: &mut Vec<std::path::PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            collect_files(&path, files)?;
        } else {
            files.push(path);
        }
    }
    Ok(())
}

fn bearer_at(bytes: &[u8], start: usize) -> Option<usize> {
    let rest = bytes.get(start..)?;
    if rest.len() < 7 || !rest[..6].eq_ignore_ascii_case(b"bearer") {
        return None;
    }
    if start > 0 && bytes[start - 1].is_ascii_alphanumeric() {
        return None;
    }
    let space = *rest.get(6)?;
    if !space.is_ascii_whitespace() {
        return None;
    }
    let token = token_len(&rest[7..]);
    (token >= 8).then_some(start + 7 + token)
}

fn token_len(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .take_while(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+' | b'/' | b'=')
        })
        .count()
}

fn jwt_at(bytes: &[u8], start: usize) -> Option<usize> {
    let rest = bytes.get(start..)?;
    if !rest.starts_with(b"eyJ") {
        return None;
    }
    if start > 0 && is_base64url(bytes[start - 1]) {
        return None;
    }
    let mut cursor = 3;
    cursor = b64_segment(rest, cursor, 8)?;
    if rest.get(cursor) != Some(&b'.') {
        return None;
    }
    cursor = b64_segment(rest, cursor + 1, 8)?;
    if rest.get(cursor) != Some(&b'.') {
        return None;
    }
    cursor = b64_segment(rest, cursor + 1, 4)?;
    Some(start + cursor)
}

fn secret_key_at(bytes: &[u8], start: usize) -> Option<usize> {
    let rest = bytes.get(start..)?;
    if rest.len() < 11 || !rest[..3].eq_ignore_ascii_case(b"sk-") {
        return None;
    }
    if start > 0 && bytes[start - 1].is_ascii_alphanumeric() {
        return None;
    }
    let token = rest[3..]
        .iter()
        .take_while(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        .count();
    (token >= 8).then_some(start + 3 + token)
}

fn email_at(bytes: &[u8], start: usize) -> Option<usize> {
    if start > 0 && is_email_char(bytes[start - 1]) {
        return None;
    }
    let rest = bytes.get(start..)?;
    let local = rest
        .iter()
        .take_while(|byte| is_email_char(**byte) && **byte != b'@')
        .count();
    if local == 0 || rest.get(local) != Some(&b'@') {
        return None;
    }
    let domain = rest
        .get(local + 1..)?
        .iter()
        .take_while(|byte| is_email_char(**byte) && **byte != b'@')
        .count();
    let domain_bytes = rest.get(local + 1..local + 1 + domain)?;
    if !domain_bytes.contains(&b'.')
        || domain_bytes.starts_with(b".")
        || domain_bytes.ends_with(b".")
    {
        return None;
    }
    Some(start + local + 1 + domain)
}

fn is_email_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'%' | b'+' | b'-' | b'@')
}

fn long_base64_at(bytes: &[u8], start: usize) -> Option<usize> {
    if start > 0 && is_base64_char(bytes[start - 1]) {
        return None;
    }
    let rest = bytes.get(start..)?;
    let token = rest
        .iter()
        .take_while(|byte| is_base64_char(**byte))
        .count();
    (token >= 80).then_some(start + token)
}

fn is_base64_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'_' | b'-')
}

fn is_base64url(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

fn b64_segment(bytes: &[u8], start: usize, minimum: usize) -> Option<usize> {
    let token = bytes
        .get(start..)?
        .iter()
        .take_while(|byte| is_base64url(**byte))
        .count();
    (token >= minimum).then_some(start + token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn scrub_replaces_token_shapes_and_drops_auth_headers() {
        let blob = "A".repeat(80);
        let dirty = json!({
            "headers": {
                "authorization": "Bearer super-secret-token",
                "cookie": "session=abc",
                "chatgpt-account-id": "acct_123",
                "originator": "codex_cli_rs"
            },
            "usage": {"input_tokens": 2},
            "note": format!("mail person@example.com jwt eyJhbGciOiJub25lIn0.eyJhIjoiYiJ9.signature key sk-proj-abcdefghijklmnop blob {blob}")
        });
        let clean = scrub_value(dirty);
        let text = serde_json::to_string(&clean).unwrap();
        assert!(findings(&text).is_empty(), "{text} {:?}", findings(&text));
        assert!(!text.contains("authorization"));
        assert!(!text.contains("cookie"));
        assert!(text.contains("input_tokens"), "{text}");
        assert!(text.contains("codex_cli_rs"));
        assert!(text.contains("<email>"));
        assert!(text.contains("<jwt>"));
        assert!(text.contains("<secret>"));
        assert!(text.contains("<blob>"));
    }

    #[test]
    fn scanner_reports_each_shape() {
        assert!(findings("Bearer abcdefghij").contains(&"bearer token".to_owned()));
        assert!(findings("eyJhbGciOiJub25lIn0.eyJhIjoiYiJ9.signature").contains(&"JWT".to_owned()));
        assert!(findings("sk-abcdefghijklmnop").contains(&"sk- key".to_owned()));
        assert!(findings("a@b.co").contains(&"email address".to_owned()));
        assert!(findings("\"cookie\": \"x\"").contains(&"cookie header".to_owned()));
    }
}
