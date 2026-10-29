//! TypeSafe's routed request transports. Native provider passthrough never decodes bodies.
use std::{io::Read, ops::Range};

use http::{HeaderMap, StatusCode};
use serde_json::Value;

pub(crate) const MAX_BODY: usize = 32 * 1024 * 1024;

#[derive(Debug)]
pub(crate) struct Error {
    pub status: StatusCode,
    pub message: &'static str,
}

fn invalid(message: &'static str) -> Error {
    Error {
        status: StatusCode::BAD_REQUEST,
        message,
    }
}

fn too_large() -> Error {
    Error {
        status: StatusCode::PAYLOAD_TOO_LARGE,
        message: "System One encoded, decoded, or rewritten body exceeds the request limit",
    }
}

fn unsupported(message: &'static str) -> Error {
    Error {
        status: StatusCode::UNSUPPORTED_MEDIA_TYPE,
        message,
    }
}

/// Keep the decoded representation only until routing decides whether to rewrite.
/// Unchanged requests always send the original wire bytes, including compression.
pub(crate) struct Transport {
    decoded: Option<Vec<u8>>,
    json_part: Option<Multipart>,
}

struct Multipart {
    headers: Range<usize>,
    json: Range<usize>,
}

impl Transport {
    pub fn parse(wire: &[u8], headers: &HeaderMap, limit: usize) -> Result<(Value, Self), Error> {
        let limit = limit.min(MAX_BODY);
        if wire.len() > limit {
            return Err(too_large());
        }
        let mut encodings = headers.get_all("content-encoding").iter();
        let encoding = encodings
            .next()
            .map(|h| h.to_str())
            .transpose()
            .map_err(|_| unsupported("invalid System One Content-Encoding"))?;
        if encodings.next().is_some() {
            return Err(unsupported(
                "System One permits only one Content-Encoding layer",
            ));
        }
        let decoded = match encoding.map(str::trim) {
            None => None,
            Some(e) if e.eq_ignore_ascii_case("identity") => None,
            Some(e) if e.eq_ignore_ascii_case("gzip") || e.eq_ignore_ascii_case("x-gzip") => Some(
                read_bounded(flate2::bufread::MultiGzDecoder::new(wire), limit)?,
            ),
            Some(e) if e.eq_ignore_ascii_case("zstd") => {
                let mut decoder = zstd::stream::read::Decoder::with_buffer(wire)
                    .map_err(|_| invalid("invalid System One zstd body"))?;
                decoder
                    .window_log_max(23)
                    .map_err(|_| invalid("cannot bound System One zstd window"))?;
                Some(read_bounded(decoder, limit)?)
            }
            Some(_) => {
                return Err(unsupported(
                    "System One supports one gzip, x-gzip, or zstd encoding layer",
                ));
            }
        };
        let body = decoded.as_deref().unwrap_or(wire);
        let mut types = headers.get_all("content-type").iter();
        let content_type = types
            .next()
            .map(|h| h.to_str())
            .transpose()
            .map_err(|_| unsupported("invalid System One Content-Type"))?;
        if types.next().is_some() {
            return Err(unsupported("ambiguous System One Content-Type"));
        }
        let json_part = match content_type {
            None => None,
            Some(value) => {
                let media: mime::Mime = value
                    .parse()
                    .map_err(|_| unsupported("invalid System One Content-Type"))?;
                match media.essence_str() {
                    "application/json" => None,
                    "multipart/form-data" => {
                        let boundary = media
                            .get_param(mime::BOUNDARY)
                            .ok_or_else(|| invalid("System One multipart boundary is missing"))?;
                        Some(request_part(body, boundary.as_str())?)
                    }
                    _ => {
                        return Err(unsupported(
                            "System One requires JSON or multipart/form-data",
                        ));
                    }
                }
            }
        };
        let json = json_part
            .as_ref()
            .map_or(body, |part| &body[part.json.clone()]);
        let value = crate::json::from_slice(json)
            .map_err(|_| invalid("invalid System One request JSON"))?;
        Ok((value, Self { decoded, json_part }))
    }

    /// Rewrites are sent decoded. The multipart JSON part's stale length/digests
    /// are removed; all binary parts, boundaries and epilogue remain intact.
    pub fn rewrite(self, wire: &[u8], value: &Value, limit: usize) -> Result<Vec<u8>, Error> {
        let json = serde_json::to_vec(value)
            .map_err(|_| invalid("cannot encode System One request JSON"))?;
        let limit = limit.min(MAX_BODY);
        let Some(part) = self.json_part else {
            return if json.len() > limit {
                Err(too_large())
            } else {
                Ok(json)
            };
        };
        let body = self.decoded.as_deref().unwrap_or(wire);
        // parse() already checked that these headers are UTF-8 and colon-delimited.
        let retained = std::str::from_utf8(&body[part.headers.clone()])
            .unwrap()
            .split_inclusive("\r\n")
            .filter(|line| {
                let name = line.split_once(':').unwrap().0;
                ![
                    "content-length",
                    "content-digest",
                    "repr-digest",
                    "digest",
                    "content-md5",
                ]
                .iter()
                .any(|stale| name.eq_ignore_ascii_case(stale))
            });
        let retained_length: usize = retained.clone().map(str::len).sum();
        let length = part.headers.start + retained_length + 2 + body.len() - part.json.end;
        let length = length
            .checked_add(json.len())
            .filter(|&n| n <= limit)
            .ok_or_else(too_large)?;
        let mut output = Vec::with_capacity(length);
        output.extend_from_slice(&body[..part.headers.start]);
        for line in retained {
            output.extend_from_slice(line.as_bytes());
        }
        output.extend_from_slice(b"\r\n");
        output.extend_from_slice(&json);
        output.extend_from_slice(&body[part.json.end..]);
        Ok(output)
    }
}

fn read_bounded(reader: impl Read, limit: usize) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    reader
        .take(limit as u64 + 1)
        .read_to_end(&mut output)
        .map_err(|_| {
            invalid("malformed System One compressed body or zstd window exceeds 8 MiB")
        })?;
    if output.len() > limit {
        return Err(too_large());
    }
    Ok(output)
}

fn find(bytes: &[u8], needle: &[u8]) -> Option<usize> {
    bytes
        .windows(needle.len())
        .position(|window| window == needle)
}

fn request_part(body: &[u8], boundary: &str) -> Result<Multipart, Error> {
    if boundary.is_empty()
        || boundary.len() > 70
        || !boundary
            .bytes()
            .all(|b| b.is_ascii() && !b.is_ascii_control())
        || boundary.ends_with(' ')
    {
        return Err(invalid("invalid System One multipart boundary"));
    }
    let opening = format!("--{boundary}\r\n");
    let start = if body.starts_with(opening.as_bytes()) {
        opening.len()
    } else {
        let marker = format!("\r\n{opening}");
        find(body, marker.as_bytes())
            .ok_or_else(|| invalid("missing System One multipart opening boundary"))?
            + marker.len()
    };
    let header_start = start;
    let header_end = find(&body[start..], b"\r\n\r\n")
        .ok_or_else(|| invalid("incomplete System One multipart request headers"))?
        + start;
    let headers = std::str::from_utf8(&body[start..header_end])
        .map_err(|_| invalid("invalid System One multipart request headers"))?;
    let mut disposition = None;
    let mut content_type = None;
    for header in headers.split("\r\n") {
        let (name, value) = header
            .split_once(':')
            .ok_or_else(|| invalid("invalid multipart header"))?;
        let slot = if name.eq_ignore_ascii_case("content-disposition") {
            Some(&mut disposition)
        } else if name.eq_ignore_ascii_case("content-type") {
            Some(&mut content_type)
        } else {
            None
        };
        if let Some(slot) = slot
            && slot.replace(value.trim()).is_some()
        {
            return Err(invalid("duplicate multipart request header"));
        }
    }
    if !disposition.is_some_and(is_request_disposition) {
        return Err(invalid(
            "first System One multipart part must be named request",
        ));
    }
    if content_type
        .and_then(|v| v.parse::<mime::Mime>().ok())
        .is_none_or(|m| m.essence_str() != "application/json")
    {
        return Err(invalid(
            "System One multipart request part must be application/json",
        ));
    }
    let start = header_end + 4;
    let marker = format!("\r\n--{boundary}");
    let mut offset = start;
    while let Some(relative) = find(&body[offset..], marker.as_bytes()) {
        let end = offset + relative;
        let tail = &body[end + marker.len()..];
        if tail.starts_with(b"\r\n") || tail == b"--" || tail.starts_with(b"--\r\n") {
            return Ok(Multipart {
                headers: header_start..header_end + 2,
                json: start..end,
            });
        }
        offset = end + marker.len();
    }
    Err(invalid("incomplete System One multipart request part"))
}

// Split only at unquoted semicolons: filenames may contain text like '; name=request'.
fn is_request_disposition(header: &str) -> bool {
    let Some((kind, mut params)) = header.split_once(';') else {
        return false;
    };
    if !kind.trim().eq_ignore_ascii_case("form-data") {
        return false;
    }
    let mut named_request = false;
    let mut saw_name = false;
    while !params.is_empty() {
        let mut quoted = false;
        let mut escaped = false;
        let mut end = params.len();
        for (i, byte) in params.bytes().enumerate() {
            if escaped {
                escaped = false;
                continue;
            }
            if quoted && byte == b'\\' {
                escaped = true;
                continue;
            }
            if byte == b'"' {
                quoted = !quoted;
            }
            if byte == b';' && !quoted {
                end = i;
                break;
            }
        }
        if quoted || escaped {
            return false;
        }
        let Some((name, value)) = params[..end].split_once('=') else {
            return false;
        };
        if name.trim().eq_ignore_ascii_case("name") {
            if saw_name {
                return false;
            }
            saw_name = true;
            let value = value.trim();
            named_request =
                if let Some(value) = value.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
                    let mut bytes = value.bytes();
                    let unescaped = std::iter::from_fn(|| {
                        bytes
                            .next()
                            .and_then(|b| if b == b'\\' { bytes.next() } else { Some(b) })
                    });
                    unescaped.eq(b"request".iter().copied())
                } else {
                    value == "request"
                };
        }
        params = if end == params.len() {
            ""
        } else {
            &params[end + 1..]
        };
    }
    named_request
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;
    use serde_json::json;
    use std::io::Write;

    fn gzip(body: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(body).unwrap();
        encoder.finish().unwrap()
    }

    fn headers(encoding: &str, content_type: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("content-encoding", HeaderValue::from_str(encoding).unwrap());
        headers.insert("content-type", HeaderValue::from_str(content_type).unwrap());
        headers
    }

    fn status(wire: &[u8], headers: &HeaderMap, limit: usize) -> StatusCode {
        Transport::parse(wire, headers, limit)
            .err()
            .expect("request must fail")
            .status
    }

    #[test]
    fn encoded_and_decoded_limits_are_independent_and_inclusive() {
        let body = serde_json::to_vec(&json!({"model":"m","state":"x".repeat(4096)})).unwrap();
        for encoding in ["gzip", "x-gzip", "zstd"] {
            let wire = if encoding == "zstd" {
                zstd::encode_all(body.as_slice(), 1).unwrap()
            } else {
                gzip(&body)
            };
            let headers = headers(encoding, "application/json");
            assert_eq!(
                Transport::parse(&wire, &headers, body.len()).unwrap().0["model"],
                "m"
            );
            assert_eq!(
                status(&wire, &headers, body.len() - 1),
                StatusCode::PAYLOAD_TOO_LARGE
            );
            assert_eq!(
                status(&wire, &headers, wire.len() - 1),
                StatusCode::PAYLOAD_TOO_LARGE
            );
            assert_eq!(
                status(&wire[..wire.len() - 1], &headers, body.len()),
                StatusCode::BAD_REQUEST
            );
            let mut trailing = wire;
            trailing.extend_from_slice(b"not another frame");
            assert_eq!(
                status(&trailing, &headers, body.len()),
                StatusCode::BAD_REQUEST
            );
        }
    }

    #[test]
    fn encoding_lists_repetitions_and_unsupported_encodings_are_rejected() {
        for encoding in ["gzip, zstd", "gzip, gzip", "br", ""] {
            assert_eq!(
                status(b"{}", &headers(encoding, "application/json"), 1024),
                StatusCode::UNSUPPORTED_MEDIA_TYPE
            );
        }
        let mut repeated = headers("gzip", "application/json");
        repeated.append("content-encoding", HeaderValue::from_static("gzip"));
        assert_eq!(
            status(&gzip(b"{}"), &repeated, 1024),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
    }

    #[test]
    fn zstd_large_window_is_rejected_before_output_allocation() {
        // Valid streaming frame: 16 MiB window, one final raw byte, no checksum.
        let frame = [0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x70, 0x09, 0x00, 0x00, b'a'];
        assert_eq!(zstd::decode_all(frame.as_slice()).unwrap(), b"a");
        assert_eq!(
            status(&frame, &headers("zstd", "application/json"), MAX_BODY),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn malformed_first_part_cannot_route_using_an_image_filename() {
        let content_type = "multipart/form-data; boundary=b";
        for disposition in [
            "form-data; name=\"photo\"; filename=\"x; name=request\"",
            "form-data; name=\"request\"; name=\"photo\"",
            "form-data; name=\"request",
        ] {
            let wire = format!(
                "--b\r\nContent-Disposition: {disposition}\r\nContent-Type: application/json\r\n\r\n{{\"model\":\"m\"}}\r\n--b--\r\n"
            );
            assert_eq!(
                status(wire.as_bytes(), &headers("identity", content_type), 4096),
                StatusCode::BAD_REQUEST
            );
        }
        let wire = b"--b\r\nContent-Disposition: form-data; name=request\r\nContent-Type: image/png\r\n\r\n{}\r\n--b--\r\n";
        assert_eq!(
            status(wire, &headers("identity", content_type), 4096),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn multipart_rewrite_does_not_confuse_binary_boundaries_or_stale_part_metadata() {
        let first = b"--b\r\nContent-Disposition: form-data; name=\"request\"; filename=\"x; ignored=yes\"\r\nContent-Type: application/json\r\nContent-Length: 13\r\nContent-MD5: stale\r\n\r\n{\"model\":\"m\"}";
        let image = b"\r\n--b\r\nContent-Disposition: form-data; name=\"photo\"; filename=\"photo.png\"\r\nContent-Type: image/png\r\nContent-MD5: image-digest\r\n\r\n\x89PNG\0\xff\r\n--b-not-a-boundary\r\n--b--\r\nepilogue";
        let wire = [first.as_slice(), image.as_slice()].concat();
        for compressed in [false, true] {
            let encoded = if compressed {
                gzip(&wire)
            } else {
                wire.clone()
            };
            let (mut value, transport) = Transport::parse(
                &encoded,
                &headers(
                    if compressed { "gzip" } else { "identity" },
                    "multipart/form-data; boundary=\"b\"",
                ),
                4096,
            )
            .unwrap();
            value["model"] = json!("resolved");
            let output = transport.rewrite(&encoded, &value, 4096).unwrap();
            assert!(output.ends_with(image));
            let prefix = std::str::from_utf8(&output[..output.len() - image.len()]).unwrap();
            assert!(!prefix.contains("Content-Length") && !prefix.contains("Content-MD5"));
            assert!(prefix.ends_with("{\"model\":\"resolved\"}"));
        }
    }

    #[test]
    fn rewritten_model_cannot_expand_request_past_the_limit() {
        let wire = b"{\"model\":\"m\"}";
        let (mut value, transport) = Transport::parse(wire, &HeaderMap::new(), wire.len()).unwrap();
        value["model"] = json!("longer-model-name");
        assert_eq!(
            transport
                .rewrite(wire, &value, wire.len())
                .unwrap_err()
                .status,
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }
}
