//! Normalization applied before a recorded request is compared with infer.
//!
//! The default is strict JSON equality and exact header values. Each function
//! below is one opt-in allowance. Nothing else is rewritten or dropped.

use anyhow::{Result, bail};
use serde_json::{Map, Value};

use super::{ActualRequest, ObservedRequest};
use crate::traffic::Harness;

/// Compare one upstream call with a fixture request.
pub fn align(
    harness: &dyn Harness,
    expected: &ObservedRequest,
    actual: &ActualRequest,
) -> Result<()> {
    let method = actual.method.to_ascii_uppercase();
    if method != expected.method.to_ascii_uppercase() {
        bail!(
            "method: expected {}, got {method}",
            expected.method.to_ascii_uppercase()
        );
    }
    let path = relative_path(&actual.path, harness.api_base_path());
    if path != expected.path {
        bail!("path: expected {}, got {path}", expected.path);
    }
    if actual.query != expected.query {
        bail!(
            "query: expected {:?}, got {:?}",
            expected.query,
            actual.query
        );
    }
    let mut expected_ids = Ids::default();
    let mut actual_ids = Ids::default();
    let expected_headers = header_values(&expected.headers)?;
    let actual_headers = header_values(&actual.headers)?;
    for name in harness.forbidden_headers() {
        if actual_headers.contains_key(*name) {
            bail!("upstream request must not send {name}");
        }
    }
    for name in harness.compared_headers() {
        let left = expected_headers
            .get(*name)
            .and_then(Value::as_str)
            .map(|value| normalize_header(name, value, &mut expected_ids));
        let right = actual_headers
            .get(*name)
            .and_then(Value::as_str)
            .map(|value| normalize_header(name, value, &mut actual_ids));
        if left != right {
            bail!("header {name}: expected {left:?}, got {right:?}");
        }
    }
    let actual_body: Value = serde_json::from_slice(&actual.body)
        .map_err(|_| anyhow::anyhow!("upstream body is not JSON"))?;
    let left = normalize_json(&expected.body, &mut expected_ids);
    let right = normalize_json(&actual_body, &mut actual_ids);
    if left != right {
        bail!(
            "body:\nexpected {}\nactual {}",
            serde_json::to_string_pretty(&left).unwrap_or_default(),
            serde_json::to_string_pretty(&right).unwrap_or_default()
        );
    }
    Ok(())
}

/// `https://chatgpt.com/backend-api/codex` + `/responses` arrives as
/// `/backend-api/codex/responses`. Comparisons use the path under the API base.
fn relative_path(path: &str, base: &str) -> String {
    let base = base.trim_end_matches('/');
    match path.strip_prefix(base) {
        Some("") => "/".to_owned(),
        Some(rest) if rest.starts_with('/') => rest.to_owned(),
        _ => path.to_owned(),
    }
}

fn header_values(headers: &Map<String, Value>) -> Result<Map<String, Value>> {
    let mut out = Map::new();
    for (name, value) in headers {
        let Some(text) = value.as_str() else {
            bail!("header {name} is not a string");
        };
        out.insert(name.to_ascii_lowercase(), Value::String(text.to_owned()));
    }
    Ok(out)
}

fn normalize_header(name: &str, value: &str, ids: &mut Ids) -> String {
    // Charset and boundary parameters are transport framing, not the Codex
    // contract. `application/json` and `application/json; charset=utf-8` match.
    let value = if name == "accept" || name == "content-type" {
        value
            .split(';')
            .next()
            .unwrap_or(value)
            .trim()
            .to_ascii_lowercase()
    } else {
        value.to_owned()
    };
    normalize_text(&value, ids)
}

fn normalize_json(value: &Value, ids: &mut Ids) -> Value {
    match value {
        Value::Object(map) => {
            // Sorted keys make the first-seen id numbering follow the data,
            // not whichever side happened to serialize a key first.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = Map::new();
            for key in keys {
                out.insert(key.clone(), normalize_json(&map[key], ids));
            }
            Value::Object(out)
        }
        Value::Array(items) => {
            Value::Array(items.iter().map(|item| normalize_json(item, ids)).collect())
        }
        Value::String(text) => Value::String(normalize_text(text, ids)),
        other => other.clone(),
    }
}

fn normalize_text(text: &str, ids: &mut Ids) -> String {
    // An address that is the whole value is account identity. A longer string
    // that merely mentions an address stays intact, so prompt text is strict.
    if is_email(text) {
        return "<email>".to_owned();
    }
    let without_times = replace_timestamps(text);
    ids.replace_uuids(&without_times)
}

/// Clocks differ on every run and are not part of the request contract.
fn replace_timestamps(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::new();
    let mut index = 0;
    while index < bytes.len() {
        if let Some(end) = timestamp_at(bytes, index) {
            out.push_str("<timestamp>");
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

fn timestamp_at(bytes: &[u8], start: usize) -> Option<usize> {
    // YYYY-MM-DDTHH:MM:SS[.fraction][Z|+HH:MM|-HH:MM]
    let rest = bytes.get(start..)?;
    if rest.len() < 20 || !is_date_prefix(rest) {
        return None;
    }
    let mut end = start + 19;
    if bytes.get(end) == Some(&b'.') {
        let digits = bytes[end + 1..]
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        if digits == 0 {
            return None;
        }
        end += 1 + digits;
    }
    match bytes.get(end) {
        Some(b'Z') => Some(end + 1),
        Some(b'+' | b'-')
            if bytes.get(end + 1..end + 6).is_some_and(|offset| {
                offset.len() == 5
                    && offset[0].is_ascii_digit()
                    && offset[1].is_ascii_digit()
                    && offset[2] == b':'
                    && offset[3].is_ascii_digit()
                    && offset[4].is_ascii_digit()
            }) =>
        {
            Some(end + 6)
        }
        _ => None,
    }
}

fn is_date_prefix(bytes: &[u8]) -> bool {
    let pattern = b"xxxx-xx-xxTxx:xx:xx";
    bytes.len() >= pattern.len()
        && pattern.iter().zip(bytes).all(|(expected, actual)| {
            if *expected == b'x' {
                actual.is_ascii_digit()
            } else {
                actual == expected
            }
        })
}

fn is_email(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !local.contains('@')
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !value.chars().any(char::is_whitespace)
        && value.is_ascii()
}

/// Per-turn ids. The same UUID stays one placeholder, in the order the
/// canonical walk first sees it, so three headers that share an id still have
/// to share an id after normalization. A different id gets a different number.
#[derive(Default)]
struct Ids {
    assigned: Vec<(String, String)>,
}

impl Ids {
    fn replace_uuids(&mut self, text: &str) -> String {
        let bytes = text.as_bytes();
        let mut out = String::new();
        let mut index = 0;
        while index < bytes.len() {
            if let Some(end) = uuid_at(bytes, index) {
                let id = text[index..end].to_ascii_lowercase();
                out.push_str(self.placeholder(&id));
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

    fn placeholder(&mut self, id: &str) -> &str {
        if let Some(position) = self.assigned.iter().position(|(seen, _)| seen == id) {
            return &self.assigned[position].1;
        }
        let placeholder = format!("<uuid:{}>", self.assigned.len() + 1);
        self.assigned.push((id.to_owned(), placeholder));
        &self.assigned.last().expect("just pushed").1
    }
}

fn uuid_at(bytes: &[u8], start: usize) -> Option<usize> {
    // 8-4-4-4-12 hex. Item ids such as `msg_<uuid>` are covered because the
    // UUID is found inside the surrounding text and only that span is replaced.
    let rest = bytes.get(start..start + 36)?;
    let groups = [8, 4, 4, 4, 12];
    let mut cursor = 0;
    for (group, length) in groups.into_iter().enumerate() {
        if group > 0 {
            if rest.get(cursor) != Some(&b'-') {
                return None;
            }
            cursor += 1;
        }
        if !rest
            .get(cursor..cursor + length)?
            .iter()
            .all(|byte| byte.is_ascii_hexdigit())
        {
            return None;
        }
        cursor += length;
    }
    (cursor == 36).then_some(start + 36)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct Sample;

    impl Harness for Sample {
        fn id(&self) -> &'static str {
            "sample"
        }
        fn api_base_path(&self) -> &'static str {
            "/backend-api/codex"
        }
        fn compared_headers(&self) -> &'static [&'static str] {
            &[
                "accept",
                "content-type",
                "originator",
                "session-id",
                "thread-id",
                "x-client-request-id",
            ]
        }
        fn forbidden_headers(&self) -> &'static [&'static str] {
            &["openai-beta"]
        }
    }

    fn request(headers: Value, body: Value) -> ObservedRequest {
        ObservedRequest {
            method: "POST".into(),
            path: "/responses".into(),
            query: String::new(),
            headers: headers.as_object().unwrap().clone(),
            body,
        }
    }

    fn actual(headers: Value, body: Value) -> ActualRequest {
        ActualRequest {
            method: "POST".into(),
            path: "/backend-api/codex/responses".into(),
            query: String::new(),
            headers: headers.as_object().unwrap().clone(),
            body: serde_json::to_vec(&body).unwrap(),
        }
    }

    fn headers() -> Value {
        json!({
            "accept": "text/event-stream",
            "content-type": "application/json",
            "originator": "codex_cli_rs",
            "session-id": "00000000-0000-4000-8000-000000000001",
            "thread-id": "00000000-0000-4000-8000-000000000001",
            "x-client-request-id": "00000000-0000-4000-8000-000000000001"
        })
    }

    #[test]
    fn shared_ids_match_across_different_uuid_text() {
        let harness = Sample;
        let expected = request(headers(), json!({"model": "gpt-5.5", "store": false}));
        let mut live = headers();
        let generated = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
        for name in ["session-id", "thread-id", "x-client-request-id"] {
            live[name] = json!(generated);
        }
        live["content-type"] = json!("application/json; charset=utf-8");
        live["user-agent"] = json!("infer/0.1.0");
        live["authorization"] = json!("Bearer secret-token");
        let actual = actual(live, json!({"store": false, "model": "gpt-5.5"}));
        align(&harness, &expected, &actual).unwrap();
    }

    #[test]
    fn split_session_ids_do_not_collapse() {
        let harness = Sample;
        let expected = request(headers(), json!({}));
        let mut live = headers();
        live["thread-id"] = json!("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");
        let actual = actual(live, json!({}));
        assert!(align(&harness, &expected, &actual).is_err());
    }

    #[test]
    fn extra_body_fields_stay_strict() {
        let harness = Sample;
        let expected = request(headers(), json!({"model": "gpt-5.5"}));
        let actual = actual(
            headers(),
            json!({"model": "gpt-5.5", "client_metadata": {}}),
        );
        let error = align(&harness, &expected, &actual).unwrap_err();
        assert!(error.to_string().contains("client_metadata"), "{error}");
    }

    #[test]
    fn invented_beta_header_is_rejected() {
        let harness = Sample;
        let expected = request(headers(), json!({}));
        let mut live = headers();
        live["openai-beta"] = json!("responses=experimental");
        let actual = actual(live, json!({}));
        assert!(align(&harness, &expected, &actual).is_err());
    }

    #[test]
    fn emails_and_timestamps_normalize_only_as_documented() {
        let harness = Sample;
        let expected = request(
            headers(),
            json!({"note": "person@example.com", "at": "2026-11-13T18:00:00Z"}),
        );
        let seen = actual(
            headers(),
            json!({"note": "other@example.com", "at": "2026-01-02T03:04:05.125+00:00"}),
        );
        align(&harness, &expected, &seen).unwrap();
        let expected = request(headers(), json!({"text": "mail person@example.com please"}));
        let seen = actual(headers(), json!({"text": "mail other@example.com please"}));
        assert!(align(&harness, &expected, &seen).is_err());
    }
}
