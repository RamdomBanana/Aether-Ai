//! Structural pre-scan of untrusted JSON: nesting depth and duplicate object keys.
//!
//! `serde_json` accepts duplicate keys silently (the last one wins), which is a classic
//! parser-differential attack: two components could disagree about which `method` or
//! `params` a message carries. It also cannot enforce a depth limit below its fixed
//! recursion limit of 128. This pass closes both gaps *before* a message is interpreted.
//!
//! Precondition: the input is a complete, syntactically valid JSON text, which
//! [`crate::parse_line`] guarantees by running `serde_json` first. The scanner is
//! single-pass and allocates only one hash set per open object.

use std::collections::HashSet;

use crate::errors::RpcError;

/// Why a document was refused by [`scan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanError {
    /// Containers are nested deeper than the limit.
    TooDeep {
        /// The depth limit that was exceeded.
        limit: usize,
    },
    /// An object repeats a key (compared after unescaping, so `"a"` equals `"\u0061"`).
    DuplicateKey(String),
    /// The input was not valid JSON, which violates the precondition.
    Malformed,
}

impl From<ScanError> for RpcError {
    fn from(err: ScanError) -> Self {
        match err {
            ScanError::TooDeep { limit } => {
                RpcError::invalid_request("JSON nesting is too deep").with_data("reason", "too_deep").with_data("limit", limit as u64)
            }
            ScanError::DuplicateKey(_) => RpcError::invalid_request("object contains a duplicate key").with_data("reason", "duplicate_key"),
            ScanError::Malformed => RpcError::parse_error("invalid JSON"),
        }
    }
}

enum Frame {
    Array,
    Object { keys: HashSet<String>, expect_key: bool },
}

/// Checks that `bytes` nests at most `max_depth` containers deep (the top-level value is
/// depth 1) and that no object repeats a key.
pub fn scan(bytes: &[u8], max_depth: usize) -> Result<(), ScanError> {
    let mut stack: Vec<Frame> = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                let start = i;
                i += 1;
                while i < bytes.len() {
                    match bytes[i] {
                        b'\\' => i += 2,
                        b'"' => break,
                        _ => i += 1,
                    }
                }
                // `i` is at the closing quote; valid JSON guarantees it exists.
                if let Some(Frame::Object { keys, expect_key }) = stack.last_mut() {
                    if *expect_key {
                        let end = (i + 1).min(bytes.len());
                        let key: String = serde_json::from_slice(&bytes[start..end]).map_err(|_| ScanError::Malformed)?;
                        if !keys.insert(key.clone()) {
                            return Err(ScanError::DuplicateKey(key));
                        }
                        *expect_key = false;
                    }
                }
            }
            b'{' => {
                if stack.len() >= max_depth {
                    return Err(ScanError::TooDeep { limit: max_depth });
                }
                stack.push(Frame::Object { keys: HashSet::new(), expect_key: true });
            }
            b'[' => {
                if stack.len() >= max_depth {
                    return Err(ScanError::TooDeep { limit: max_depth });
                }
                stack.push(Frame::Array);
            }
            b'}' | b']' => {
                stack.pop();
            }
            b',' => {
                if let Some(Frame::Object { expect_key, .. }) = stack.last_mut() {
                    *expect_key = true;
                }
            }
            _ => {}
        }
        i += 1;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(s: &str) {
        assert_eq!(scan(s.as_bytes(), 32), Ok(()), "{s}");
    }

    #[test]
    fn accepts_ordinary_documents() {
        ok(r#"{"a":1,"b":{"c":[1,2,{"d":null}]},"e":"text"}"#);
        ok("[]");
        ok("{}");
        ok("5");
        ok(r#""just a string""#);
    }

    #[test]
    fn same_key_at_different_levels_or_in_siblings_is_fine() {
        ok(r#"{"a":1,"b":{"a":2}}"#);
        ok(r#"[{"a":1},{"a":2}]"#);
        ok(r#"{"x":{"a":1},"y":{"a":2}}"#);
    }

    #[test]
    fn rejects_duplicate_keys() {
        assert_eq!(scan(br#"{"a":1,"a":2}"#, 32), Err(ScanError::DuplicateKey("a".into())));
        assert_eq!(scan(br#"{"m":{"k":1,"j":2,"k":3}}"#, 32), Err(ScanError::DuplicateKey("k".into())));
        assert_eq!(scan(br#"[{"a":1,"a":2}]"#, 32), Err(ScanError::DuplicateKey("a".into())));
    }

    #[test]
    fn duplicates_are_detected_after_unescaping() {
        assert_eq!(scan(br#"{"a":1,"\u0061":2}"#, 32), Err(ScanError::DuplicateKey("a".into())));
        assert_eq!(scan(br#"{"a\"b":1,"a\u0022b":2}"#, 32), Err(ScanError::DuplicateKey("a\"b".into())));
    }

    #[test]
    fn values_are_never_mistaken_for_keys() {
        ok(r#"{"a":"a","b":"a"}"#);
        ok(r#"{"a":["a","a"],"b":"a"}"#);
    }

    #[test]
    fn structural_characters_inside_strings_are_ignored() {
        ok(r#"{"a":"x,{\"a\":1}","b":2}"#);
        ok(r#"{"a":"}]","b":"[{"}"#);
        ok(r#"{"a\\":1,"b":"\\"}"#);
    }

    #[test]
    fn depth_limit_is_inclusive() {
        let deep_ok = format!("{}{}", "[".repeat(32), "]".repeat(32));
        let too_deep = format!("{}{}", "[".repeat(33), "]".repeat(33));
        assert_eq!(scan(deep_ok.as_bytes(), 32), Ok(()));
        assert_eq!(scan(too_deep.as_bytes(), 32), Err(ScanError::TooDeep { limit: 32 }));
        let objects = format!("{}1{}", r#"{"a":"#.repeat(33), "}".repeat(33));
        assert_eq!(scan(objects.as_bytes(), 32), Err(ScanError::TooDeep { limit: 32 }));
    }

    #[test]
    fn maps_to_rpc_errors() {
        let e: RpcError = ScanError::TooDeep { limit: 32 }.into();
        assert_eq!(e.code, crate::errors::code::INVALID_REQUEST);
        assert_eq!(e.data.as_ref().unwrap()["reason"], "too_deep");
        let e: RpcError = ScanError::DuplicateKey("secret".into()).into();
        assert!(!e.message.contains("secret"), "never echo attacker-controlled keys");
        assert_eq!(e.data.as_ref().unwrap()["reason"], "duplicate_key");
    }
}
