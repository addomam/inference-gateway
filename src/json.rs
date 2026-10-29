//! Wire JSON decoding without interpreting literal objects as serde's private tokens.

use std::fmt;

use serde::{
    Deserializer,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Value, value::RawValue};

/// Decode wire JSON while preserving literal objects and arbitrary-precision numbers.
pub(crate) fn from_slice(bytes: &[u8]) -> serde_json::Result<Value> {
    // With arbitrary_precision/raw_value, Value treats certain first object keys as
    // internal number/raw tokens. A literal spelling contains this prefix; any
    // alternative JSON spelling of those ASCII keys needs a Unicode escape.
    // Neither candidate present means Value's ordinary single-pass decode is safe.
    // Matches inside strings are harmless false positives, not embedded JSON.
    if !bytes
        .windows(b"$serde_json::private::".len())
        .any(|window| window == b"$serde_json::private::")
        && !bytes.windows(2).any(|window| window == br"\u")
    {
        return serde_json::from_slice(bytes);
    }

    decode(bytes, 128)
}

fn decode(bytes: &[u8], remaining_depth: u8) -> serde_json::Result<Value> {
    let token = bytes
        .iter()
        .find(|&&byte| !matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
        .copied();
    if !matches!(token, Some(b'{' | b'[')) {
        // Actual scalar tokens cannot be confused with literal objects. In
        // particular, serde_json retains its full numeric precision here.
        return serde_json::from_slice(bytes);
    }

    // RawValue skips serde_json's recursion checks. Count actual containers here
    // instead, using the same 128 initial budget and pre-entry decrement: at most
    // 127 nested objects/arrays, including empty containers, may be decoded.
    if remaining_depth <= 1 {
        return Err(de::Error::custom("recursion limit exceeded"));
    }
    let visitor = ContainerVisitor {
        remaining_depth: remaining_depth - 1,
    };
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = if token == Some(b'{') {
        deserializer.deserialize_map(visitor)?
    } else {
        deserializer.deserialize_seq(visitor)?
    };
    deserializer.end()?;
    Ok(value)
}

struct ContainerVisitor {
    remaining_depth: u8,
}

impl<'de> Visitor<'de> for ContainerVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON object or array")
    }

    fn visit_map<A>(self, mut access: A) -> Result<Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut object = Map::new();
        while let Some((key, raw)) = access.next_entry::<String, &RawValue>()? {
            let value =
                decode(raw.get().as_bytes(), self.remaining_depth).map_err(de::Error::custom)?;
            object.insert(key, value);
        }
        // Construct the actual wire object directly; never give its keys to
        // Value's private-token discriminator. RawValue borrows each subtree,
        // and values go straight into the final map without an intermediate map.
        Ok(Value::Object(object))
    }

    fn visit_seq<A>(self, mut access: A) -> Result<Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut array = Vec::new();
        while let Some(raw) = access.next_element::<&RawValue>()? {
            array.push(
                decode(raw.get().as_bytes(), self.remaining_depth).map_err(de::Error::custom)?,
            );
        }
        Ok(Value::Array(array))
    }
}

#[cfg(test)]
mod tests {
    use super::from_slice;
    use serde_json::{Map, Value};

    const NUMBER: &str = "$serde_json::private::Number";
    const RAW: &str = "$serde_json::private::RawValue";

    fn object(entries: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
        Value::Object(
            entries
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect::<Map<_, _>>(),
        )
    }

    #[test]
    fn literal_private_token_objects_survive_at_root_nested_and_in_arrays() {
        for (key, text) in [(NUMBER, "123"), (RAW, r#"{"decoded":true}"#)] {
            let literal = object([(key, Value::String(text.to_owned()))]);
            let root = serde_json::to_vec(&literal).unwrap();
            assert_eq!(from_slice(&root).unwrap(), literal);

            let nested = object([("value", literal.clone())]);
            let bytes = serde_json::to_vec(&nested).unwrap();
            assert_eq!(from_slice(&bytes).unwrap(), nested);

            let array = Value::Array(vec![literal.clone(), object([("nested", literal)])]);
            let bytes = serde_json::to_vec(&array).unwrap();
            assert_eq!(from_slice(&bytes).unwrap(), array);
        }
    }

    #[test]
    fn invalid_private_token_values_and_siblings_are_ordinary_json() {
        for key in [NUMBER, RAW] {
            for value in [
                Value::Null,
                Value::Bool(false),
                Value::from(123),
                Value::String("not valid number or JSON".to_owned()),
                Value::Array(vec![Value::Null]),
                object([("inner", Value::Bool(true))]),
            ] {
                for literal in [
                    object([(key, value.clone())]),
                    object([(key, value.clone()), ("sibling", Value::from(7))]),
                    object([("!first", Value::Bool(true)), (key, value)]),
                ] {
                    let bytes = serde_json::to_vec(&literal).unwrap();
                    assert_eq!(from_slice(&bytes).unwrap(), literal);
                }
            }
        }
    }

    #[test]
    fn unicode_escaped_private_keys_are_literal_objects() {
        for (input, key) in [
            (r#"{"\u0024serde_json::private::Number":"123"}"#, NUMBER),
            (r#"{"$serde_json\u003a:private::Number":"123"}"#, NUMBER),
            (r#"{"$serde_json::private::\u0052awValue":"123"}"#, RAW),
            (
                r#"{"\u0024\u0073\u0065\u0072\u0064\u0065\u005f\u006a\u0073\u006f\u006e\u003a\u003a\u0070\u0072\u0069\u0076\u0061\u0074\u0065\u003a\u003a\u004e\u0075\u006d\u0062\u0065\u0072":"123"}"#,
                NUMBER,
            ),
        ] {
            let expected = object([(key, Value::String("123".to_owned()))]);
            assert_eq!(from_slice(input.as_bytes()).unwrap(), expected);
            let nested = format!(r#"[{{"nested":{input}}}]"#);
            assert_eq!(
                from_slice(nested.as_bytes()).unwrap(),
                Value::Array(vec![object([("nested", expected)])])
            );
        }
    }

    #[test]
    fn marker_text_and_embedded_json_in_strings_remain_strings() {
        for text in [
            NUMBER,
            RAW,
            r#"{"$serde_json::private::Number":"123"}"#,
            r#"{"$serde_json::private::RawValue":"true"}"#,
            r"\u0024serde_json::private::Number",
        ] {
            let value = Value::String(text.to_owned());
            let bytes = serde_json::to_vec(&value).unwrap();
            assert_eq!(from_slice(&bytes).unwrap(), value);
            let nested = object([("text", value)]);
            let bytes = serde_json::to_vec(&nested).unwrap();
            assert_eq!(from_slice(&bytes).unwrap(), nested);
        }
    }

    #[test]
    fn literal_markers_coexist_with_arbitrary_precision_numbers() {
        let input = br#"{"literal":{"$serde_json::private::Number":"123"},"raw":{"$serde_json::private::RawValue":"false"},"numbers":[1234567890123456789012345678901234567890,0.123456789012345678901234567890123456789,-987654321098765432109876543210987654321,1e+999]}"#;
        let value = from_slice(input).unwrap();
        assert_eq!(value["literal"], object([(NUMBER, Value::from("123"))]));
        assert_eq!(value["raw"], object([(RAW, Value::from("false"))]));
        for (number, expected) in value["numbers"].as_array().unwrap().iter().zip([
            "1234567890123456789012345678901234567890",
            "0.123456789012345678901234567890123456789",
            "-987654321098765432109876543210987654321",
            "1e+999",
        ]) {
            assert!(number.is_number());
            assert_eq!(number.to_string(), expected);
        }
    }

    #[test]
    fn malformed_and_trailing_input_are_rejected_on_both_paths() {
        for input in [
            "",
            "[1,]",
            r#"{"x":01}"#,
            r#"{"x":"\ud800"}"#,
            "null true",
            r#"{"$serde_json::private::Number":"123",}"#,
            r#"{"$serde_json::private::RawValue":01}"#,
            r#"{"$serde_json::private::Number":tru}"#,
            r#"{"$serde_json::private::Number":"\ud800"}"#,
            r#"{"$serde_json::private::Number":"123","\ud800":0}"#,
            r#"{"$serde_json::private::RawValue":"true"} false"#,
            r#"["$serde_json::private::Number",1,]"#,
            r#"{"\u0024serde_json::private::Number":"123"} {}"#,
            r#""\u0024serde_json::private::Number" false"#,
        ] {
            assert!(from_slice(input.as_bytes()).is_err(), "accepted {input}");
        }
        assert!(from_slice(b"\"$serde_json::private::Number\xff\"").is_err());
    }

    #[test]
    fn nesting_limit_counts_all_containers_even_with_raw_candidates() {
        // A scalar under 127 arrays is allowed, but array 128 is not. A marker
        // object consumes one of the same container slots as an ordinary object.
        for (leaf, leaf_depth) in [
            ("null", 0),
            (r#""$serde_json::private::Number""#, 0),
            (r#""\u0061""#, 0),
            (r#"{"$serde_json::private::Number":"123"}"#, 1),
            (r#"{"\u0024serde_json::private::RawValue":false}"#, 1),
            (r#"{"ordinary":[]}"#, 2),
        ] {
            for (containers, valid) in [(127, true), (128, false), (256, false)] {
                let arrays = containers - leaf_depth;
                let input = format!("{}{}{}", "[".repeat(arrays), leaf, "]".repeat(arrays));
                assert_eq!(
                    from_slice(input.as_bytes()).is_ok(),
                    valid,
                    "{containers} containers around {leaf}"
                );
            }
        }

        // A candidate elsewhere must not grant a deeply nested ordinary subtree
        // a fresh recursion budget, and object nesting shares the array budget.
        for (depth, valid) in [(126, true), (127, false)] {
            let input = format!(
                r#"{{"$serde_json::private::Number":"123","other":{}null{}}}"#,
                r#"{"x":"#.repeat(depth),
                "}".repeat(depth)
            );
            assert_eq!(from_slice(input.as_bytes()).is_ok(), valid);
        }
    }
}
