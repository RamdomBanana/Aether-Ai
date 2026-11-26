//! From one NDJSON line to messages, and from replies back to one line.
//!
//! JSON-RPC 2.0 batch rules, as implemented here:
//!
//! * A line holding an array is a batch of 1..=[`Limits::max_batch`] messages. An empty
//!   or oversized array is a single `InvalidRequest` error (id `null`).
//! * Each element is judged independently: an invalid element yields its own error
//!   response and does not poison the others.
//! * Notifications produce no reply. If a batch produced no replies at all, nothing is
//!   written ([`assemble`] returns `None`).
//! * Replies to a batch may be sent in any order; callers match them by id.

use serde::ser::{Serialize, Serializer};
use serde_json::Value;

use crate::decode::{decode_message, Rejection};
use crate::errors::RpcError;
use crate::scan::scan;
use crate::types::{ErrorResponse, Message, Response};
use crate::Limits;

/// The result of parsing one line.
#[derive(Debug, Clone, PartialEq)]
pub enum Incoming {
    /// A single message (or the reason it was rejected).
    Single(Result<Message, Rejection>),
    /// A batch; each element succeeded or was rejected independently.
    Batch(Vec<Result<Message, Rejection>>),
    /// The line as a whole is unusable: invalid JSON, too deep, duplicate keys, or an
    /// empty or oversized batch. Answer with one error response whose id is `null`.
    Fatal(RpcError),
}

impl Incoming {
    /// Normalises to `(was_batch, items)`, or to the ready-made error response for a
    /// [`Incoming::Fatal`] line.
    #[allow(clippy::result_large_err)]
    pub fn into_items(self) -> Result<(bool, Vec<Result<Message, Rejection>>), Response> {
        match self {
            Incoming::Single(item) => Ok((false, vec![item])),
            Incoming::Batch(items) => Ok((true, items)),
            Incoming::Fatal(error) => Err(Response::Error(ErrorResponse::new(None, error))),
        }
    }
}

/// Parses one line (no terminator) into messages.
///
/// Order of checks: JSON syntax (`serde_json`, which also bounds recursion at 128), then
/// the stricter depth limit and duplicate-key scan, then per-message validation.
pub fn parse_line(line: &[u8], limits: &Limits) -> Incoming {
    let value: Value = match serde_json::from_slice(line) {
        Ok(value) => value,
        Err(err) => {
            let detail = format!("invalid JSON ({:?} at column {})", err.classify(), err.column());
            return Incoming::Fatal(RpcError::parse_error(detail));
        }
    };
    if let Err(err) = scan(line, limits.max_depth) {
        return Incoming::Fatal(err.into());
    }
    match value {
        Value::Array(items) => {
            if items.is_empty() {
                return Incoming::Fatal(RpcError::invalid_request("empty batch").with_data("reason", "empty_batch"));
            }
            if items.len() > limits.max_batch {
                return Incoming::Fatal(
                    RpcError::invalid_request("batch too large").with_data("reason", "batch_too_large").with_data("limit", limits.max_batch as u64),
                );
            }
            Incoming::Batch(items.into_iter().map(decode_message).collect())
        }
        other => Incoming::Single(decode_message(other)),
    }
}

/// What to write back for one incoming line.
#[derive(Debug, Clone, PartialEq)]
pub enum Outgoing {
    /// One response object.
    Single(Response),
    /// An array of responses, answering a batch.
    Batch(Vec<Response>),
}

impl Serialize for Outgoing {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Outgoing::Single(response) => response.serialize(serializer),
            Outgoing::Batch(responses) => responses.serialize(serializer),
        }
    }
}

/// Packages replies for the line they answer. Returns `None` when there is nothing to say
/// (only notifications were received), and a bare object for a non-batch line.
pub fn assemble(was_batch: bool, responses: Vec<Response>) -> Option<Outgoing> {
    if responses.is_empty() {
        None
    } else if was_batch {
        Some(Outgoing::Batch(responses))
    } else {
        responses.into_iter().next().map(Outgoing::Single)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec_ndjson::encode_line;
    use crate::errors::code;
    use crate::types::{Id, Success};
    use serde_json::{json, Map};

    fn parse(s: &str) -> Incoming {
        parse_line(s.as_bytes(), &Limits::default())
    }

    fn fatal_code(s: &str) -> i64 {
        match parse(s) {
            Incoming::Fatal(e) => e.code,
            other => panic!("expected Fatal, got {other:?}"),
        }
    }

    #[test]
    fn single_request() {
        match parse(r#"{"jsonrpc":"2.0","id":1,"method":"engine.status","params":{}}"#) {
            Incoming::Single(Ok(Message::Request(r))) => assert_eq!(r.method.as_str(), "engine.status"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn invalid_json_is_a_parse_error() {
        assert_eq!(fatal_code("{not json"), code::PARSE_ERROR);
        assert_eq!(fatal_code(""), code::PARSE_ERROR);
        assert_eq!(fatal_code("\u{feff}{}"), code::PARSE_ERROR, "a BOM is not allowed");
        assert_eq!(fatal_code(r#"{"a":1} trailing"#), code::PARSE_ERROR);
    }

    #[test]
    fn duplicate_keys_are_fatal_even_though_serde_would_accept_them() {
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"a.b","method":"c.d","params":{}}"#;
        assert!(serde_json::from_str::<Value>(line).is_ok(), "premise: serde_json merges duplicates");
        assert_eq!(fatal_code(line), code::INVALID_REQUEST);
        let nested = r#"{"jsonrpc":"2.0","id":1,"method":"a.b","params":{"x":1,"x":2}}"#;
        assert_eq!(fatal_code(nested), code::INVALID_REQUEST);
    }

    #[test]
    fn nesting_beyond_the_limit_is_fatal() {
        let deep = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"a.b","params":{}}}"#, "[".repeat(40) + &"]".repeat(40));
        assert_eq!(fatal_code(&deep), code::INVALID_REQUEST);
    }

    #[test]
    fn invalid_single_message_keeps_its_id() {
        match parse(r#"{"jsonrpc":"2.0","id":7,"method":"nope","params":{}}"#) {
            Incoming::Single(Err(rej)) => assert_eq!(rej.id, Some(Id::Int(7))),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn batch_elements_are_judged_independently() {
        let line = r#"[{"jsonrpc":"2.0","id":1,"method":"a.b","params":{}},{"jsonrpc":"2.0","method":"a.c","params":{}},5,{"jsonrpc":"2.0","id":2,"method":"a.d","params":[]}]"#;
        match parse(line) {
            Incoming::Batch(items) => {
                assert_eq!(items.len(), 4);
                assert!(matches!(&items[0], Ok(Message::Request(_))));
                assert!(matches!(&items[1], Ok(Message::Notification(_))));
                assert!(matches!(&items[2], Err(r) if r.id.is_none()));
                assert!(matches!(&items[3], Err(r) if r.id == Some(Id::Int(2))));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn empty_and_oversized_batches_are_fatal() {
        assert_eq!(fatal_code("[]"), code::INVALID_REQUEST);
        let notification = r#"{"jsonrpc":"2.0","method":"a.b","params":{}}"#;
        let at_limit = format!("[{}]", vec![notification; 64].join(","));
        let over_limit = format!("[{}]", vec![notification; 65].join(","));
        assert!(matches!(parse(&at_limit), Incoming::Batch(items) if items.len() == 64));
        assert_eq!(fatal_code(&over_limit), code::INVALID_REQUEST);
    }

    #[test]
    fn into_items_normalises_all_three_shapes() {
        let (was_batch, items) = parse(r#"{"jsonrpc":"2.0","id":1,"method":"a.b","params":{}}"#).into_items().unwrap();
        assert!(!was_batch && items.len() == 1);
        let (was_batch, items) = parse(r#"[{"jsonrpc":"2.0","id":1,"method":"a.b","params":{}}]"#).into_items().unwrap();
        assert!(was_batch && items.len() == 1);
        let resp = parse("garbage").into_items().unwrap_err();
        assert!(resp.is_error() && resp.id().is_none());
    }

    #[test]
    fn assemble_follows_the_batch_rules() {
        let ok = |n: i64| Response::Success(Success::new(Id::Int(n), Map::new()));
        assert_eq!(assemble(false, vec![]), None);
        assert_eq!(assemble(true, vec![]), None, "an all-notification batch is answered with nothing");
        assert_eq!(assemble(false, vec![ok(1)]), Some(Outgoing::Single(ok(1))));
        assert_eq!(assemble(true, vec![ok(1)]), Some(Outgoing::Batch(vec![ok(1)])), "a batch of one stays an array");
        assert_eq!(assemble(true, vec![ok(1), ok(2)]), Some(Outgoing::Batch(vec![ok(1), ok(2)])));
    }

    #[test]
    fn outgoing_encodes_as_one_line() {
        let ok = Response::Success(Success::new(Id::Int(1), json!({"a": 1}).as_object().unwrap().clone()));
        let single = encode_line(&Outgoing::Single(ok.clone())).unwrap();
        assert_eq!(single, b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"a\":1}}\n");
        let batch = encode_line(&Outgoing::Batch(vec![ok.clone(), ok])).unwrap();
        assert_eq!(batch.iter().filter(|&&b| b == b'\n').count(), 1);
        assert_eq!(batch[0], b'[');
    }

    #[test]
    fn full_server_loop_for_a_mixed_batch() {
        let line = r#"[{"jsonrpc":"2.0","id":"a","method":"x.y","params":{}},{"jsonrpc":"2.0","method":"x.z","params":{}},{"nope":true}]"#;
        let (was_batch, items) = parse(line).into_items().unwrap();
        let mut replies = Vec::new();
        for item in items {
            match item {
                Ok(Message::Request(req)) => replies.push(Response::Success(Success::new(req.id, Map::new()))),
                Ok(Message::Notification(_)) | Ok(Message::Response(_)) => {}
                Err(rej) => replies.push(rej.into_response()),
            }
        }
        match assemble(was_batch, replies) {
            Some(Outgoing::Batch(r)) => {
                assert_eq!(r.len(), 2, "request answered, notification silent, malformed element rejected");
                assert!(!r[0].is_error() && r[1].is_error());
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}
