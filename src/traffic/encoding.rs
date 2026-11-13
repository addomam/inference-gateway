//! Decode a captured body so a fixture stores JSON, not compressed bytes.
//!
//! The official Codex CLI sends `content-encoding: zstd` on `POST /responses`.
//! The original coding is kept beside the decoded bytes. Scrub then walks the
//! JSON. A base64 wrapper that still cannot be decoded is an error, not `<blob>`.

use std::io::Read;

use anyhow::{Context, Result, bail};
use base64::Engine;
use serde_json::{Map, Value, json};

pub(super) const BODY_LIMIT: usize = 32 * 1024 * 1024;

pub(super) struct PreparedBody {
    pub value: Value,
    /// Canonical coding, such as `zstd` or `zstd, gzip`. Absent for identity.
    pub coding: Option<String>,
    /// Present when a content-coding was removed from `value`'s bytes.
    pub decoded: Option<Vec<u8>>,
}

/// `header` is the raw Content-Encoding value. The returned body is JSON when
/// the decoded bytes are JSON, text when they are UTF-8, and a one-key
/// `base64` object only when they are still opaque.
pub(super) fn prepare_body(bytes: &[u8], header: Option<&str>) -> PreparedBody {
    let Some(coding) = recorded_coding(header) else {
        return PreparedBody {
            value: body_from_bytes(bytes),
            coding: None,
            decoded: None,
        };
    };
    match decode_coding(bytes, &coding) {
        Ok(decoded) => PreparedBody {
            value: body_from_bytes(&decoded),
            coding: Some(coding),
            decoded: Some(decoded),
        },
        Err(_) => PreparedBody {
            value: body_from_bytes(bytes),
            coding: Some(coding),
            decoded: None,
        },
    }
}

/// Turn a stored body into the value scrub should walk.
///
/// A capture from before decoding, or a coding this process could not remove,
/// is still `{"base64": "..."}`. That wrapper must not be scrubbed into `<blob>`.
pub(super) fn materialize(value: &Value, coding: Option<&str>) -> Result<Value> {
    let Some(encoded) = opaque_base64(value) else {
        return Ok(value.clone());
    };
    let Some(coding) = recorded_coding(coding) else {
        bail!(
            "captured body is an undecoded base64 blob ({} chars) with no content-encoding; scrub refuses to replace it with <blob>",
            encoded.len()
        );
    };
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .context(
            "captured body is an undecoded base64 blob; scrub refuses to replace it with <blob>",
        )?;
    let decoded = decode_coding(&bytes, &coding).with_context(|| {
        format!(
            "captured body has content-encoding {coding} but could not be decoded; scrub refuses to replace it with <blob>"
        )
    })?;
    let value = body_from_bytes(&decoded);
    if opaque_base64(&value).is_some() {
        bail!(
            "captured body stayed an undecoded base64 blob after {coding}; scrub refuses to replace it with <blob>"
        );
    }
    Ok(value)
}

pub(super) fn header_coding(headers: &Map<String, Value>) -> Option<String> {
    recorded_coding(headers.get("content-encoding").and_then(Value::as_str))
}

/// `None`, empty, and `identity` are absent. Other codings are lowercase and
/// comma-separated, in the order they were applied.
pub(super) fn recorded_coding(value: Option<&str>) -> Option<String> {
    let layers = coding_layers(value.unwrap_or(""));
    if layers.is_empty() {
        None
    } else {
        Some(layers.join(", "))
    }
}

/// Label used when two requests are compared. Absent is `identity`.
pub(super) fn coding_label(value: Option<&str>) -> String {
    recorded_coding(value).unwrap_or_else(|| "identity".to_owned())
}

pub(super) fn decode_coding(bytes: &[u8], coding: &str) -> Result<Vec<u8>> {
    // Applied left to right, so the last coding is the outer wrapper.
    let layers = coding_layers(coding);
    if layers.is_empty() {
        bail!("content-encoding {coding} has no coding to decode");
    }
    let mut current = bytes.to_vec();
    for layer in layers.into_iter().rev() {
        current = decode_one(&current, &layer)?;
    }
    Ok(current)
}

fn coding_layers(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|part| part.trim().to_ascii_lowercase())
        .filter(|part| !part.is_empty() && part != "identity")
        .collect()
}

fn decode_one(bytes: &[u8], coding: &str) -> Result<Vec<u8>> {
    match coding {
        "zstd" => {
            let decoder =
                zstd::stream::read::Decoder::new(bytes).context("zstd content-encoding")?;
            read_capped(decoder).context("zstd content-encoding")
        }
        "gzip" | "x-gzip" => {
            read_capped(flate2::read::GzDecoder::new(bytes)).context("gzip content-encoding")
        }
        "deflate" => decode_deflate(bytes),
        "br" => read_capped(brotli_decompressor::Decompressor::new(bytes, 4096))
            .context("br content-encoding"),
        other => bail!("unsupported content-encoding {other}"),
    }
}

fn decode_deflate(bytes: &[u8]) -> Result<Vec<u8>> {
    // RFC 9110: `deflate` is zlib (RFC 1950). Some clients send raw DEFLATE.
    if looks_like_zlib(bytes) {
        return read_capped(flate2::read::ZlibDecoder::new(bytes))
            .context("deflate content-encoding");
    }
    read_capped(flate2::read::DeflateDecoder::new(bytes)).context("deflate content-encoding")
}

fn looks_like_zlib(bytes: &[u8]) -> bool {
    if bytes.len() < 2 {
        return false;
    }
    let cmf = u16::from(bytes[0]);
    let flg = u16::from(bytes[1]);
    cmf & 0x0f == 8 && (cmf * 256 + flg).is_multiple_of(31)
}

fn read_capped(mut reader: impl Read) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buf).context("read decoded body")?;
        if read == 0 {
            return Ok(out);
        }
        if out.len().saturating_add(read) > BODY_LIMIT {
            bail!("decoded body exceeds 32 MiB");
        }
        out.extend_from_slice(&buf[..read]);
    }
}

pub(super) fn body_from_bytes(bytes: &[u8]) -> Value {
    if let Ok(value) = serde_json::from_slice::<Value>(bytes) {
        return value;
    }
    match String::from_utf8(bytes.to_vec()) {
        Ok(text) => Value::String(text),
        Err(error) => json!({
            "base64": base64::engine::general_purpose::STANDARD.encode(error.as_bytes())
        }),
    }
}

fn opaque_base64(value: &Value) -> Option<&str> {
    let object = value.as_object()?;
    if object.len() != 1 {
        return None;
    }
    object.get("base64")?.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn json_bytes() -> &'static [u8] {
        br#"{"model":"gpt-6.1-sol"}"#
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn zlib(bytes: &[u8]) -> Vec<u8> {
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn raw_deflate(bytes: &[u8]) -> Vec<u8> {
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn brotli(bytes: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        {
            let mut writer = brotli::CompressorWriter::new(&mut output, 4096, 5, 22);
            writer.write_all(bytes).unwrap();
        }
        output
    }

    fn assert_model(prepared: &PreparedBody, coding: &str) {
        assert_eq!(prepared.coding.as_deref(), Some(coding));
        assert_eq!(prepared.value["model"], "gpt-6.1-sol");
        assert!(prepared.decoded.is_some());
    }

    #[test]
    fn json_codings_decode_to_the_object() {
        assert_model(
            &prepare_body(&zstd::encode_all(json_bytes(), 3).unwrap(), Some(" Zstd ")),
            "zstd",
        );
        assert_model(&prepare_body(&gzip(json_bytes()), Some("gzip")), "gzip");
        assert_model(&prepare_body(&gzip(json_bytes()), Some("x-gzip")), "x-gzip");
        assert_model(
            &prepare_body(&zlib(json_bytes()), Some("deflate")),
            "deflate",
        );
        assert_model(
            &prepare_body(&raw_deflate(json_bytes()), Some("deflate")),
            "deflate",
        );
        assert_model(&prepare_body(&brotli(json_bytes()), Some("br")), "br");
        let layered = gzip(&zstd::encode_all(json_bytes(), 1).unwrap());
        assert_model(&prepare_body(&layered, Some("zstd, gzip")), "zstd, gzip");
    }

    #[test]
    fn identity_stays_json_without_a_coding() {
        let prepared = prepare_body(json_bytes(), Some("identity"));
        assert!(prepared.coding.is_none());
        assert!(prepared.decoded.is_none());
        assert_eq!(prepared.value["model"], "gpt-6.1-sol");
        assert_eq!(coding_label(None), "identity");
        assert_eq!(coding_label(Some("identity")), "identity");
    }

    #[test]
    fn a_coding_that_cannot_be_removed_fails_instead_of_becoming_a_blob() {
        let prepared = prepare_body(&[0xff, 0xfe, 0xfd], Some("snappy"));
        assert_eq!(prepared.coding.as_deref(), Some("snappy"));
        let error = materialize(&prepared.value, prepared.coding.as_deref()).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("<blob>"), "{message}");
        assert!(
            message.contains("could not be decoded") || message.contains("unsupported"),
            "{message}"
        );
        let bare = json!({"base64": "A".repeat(90)});
        let error = materialize(&bare, None).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("no content-encoding"), "{message}");
        assert!(message.contains("<blob>"), "{message}");
    }
}
