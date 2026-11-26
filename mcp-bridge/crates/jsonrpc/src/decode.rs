//! Strict decoding of one JSON value into a [`Message`].
//!
//! Failures are [`Rejection`]s: an `InvalidRequest` error plus the id to answer with.
//! The id is whatever valid `id` the offending message carried (so a client can match
//! the error to its request), and `None` when there was none, which serialises as `null`.

use serde_json::{Map, Value};

use crate::errors::RpcError;
use crate::types::{ErrorResponse, Id, Message, Method, Notification, Params, Request, Response, Success};
use crate::MAX_ERROR_MESSAGE_CHARS;

/// A message that could not be accepted, and how to answer it.
#[derive(Debug, Clone, PartialEq)]
pub struct Rejection {
    /// The id for the error response; `None` serialises as `null`.
    pub id: Option<Id>,
    /// Always code `-32600` with `data.pointer` locating the problem.
    pub error: RpcError,
}

impl Rejection {
    /// Turns the rejection into the error response to send back.
    pub fn into_response(self) -> Response {
        Response::Error(ErrorResponse::new(self.id, self.error))
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Request,
    Notification,
    Success,
    Error,
}

fn reject(id: Option<Id>, pointer: &str, detail: &str) -> Rejection {
    Rejection { id, error: RpcError::invalid_request(detail).with_pointer(pointer) }
}

/// RFC 6901 escaping of one reference token.
fn escape_token(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

/// Decodes one JSON value as a request, notification, or response.
///
/// Accepted shapes, with no members beyond those listed:
///
/// * request: `jsonrpc, id, method, params`
/// * notification: `jsonrpc, method, params`
/// * success: `jsonrpc, id, result` (result is an object)
/// * error: `jsonrpc, id, error` (id may be null)
pub fn decode_message(value: Value) -> Result<Message, Rejection> {
    let Value::Object(mut obj) = value else {
        return Err(reject(None, "", "a message must be a JSON object"));
    };

    let id_hint = obj.get("id").and_then(|v| Id::from_value(v).ok());

    if !matches!(obj.get("jsonrpc"), Some(Value::String(s)) if s == "2.0") {
        return Err(reject(id_hint, "/jsonrpc", "\"jsonrpc\" must be the string \"2.0\""));
    }

    let has_id = obj.contains_key("id");
    let kind = match (obj.contains_key("method"), obj.contains_key("result"), obj.contains_key("error")) {
        (true, false, false) => {
            if has_id {
                Kind::Request
            } else {
                Kind::Notification
            }
        }
        (false, true, false) => Kind::Success,
        (false, false, true) => Kind::Error,
        _ => {
            return Err(reject(id_hint, "", "a message must be exactly one of: request, notification, success response, error response"));
        }
    };

    let allowed: &[&str] = match kind {
        Kind::Request => &["jsonrpc", "id", "method", "params"],
        Kind::Notification => &["jsonrpc", "method", "params"],
        Kind::Success => &["jsonrpc", "id", "result"],
        Kind::Error => &["jsonrpc", "id", "error"],
    };
    if let Some(unknown) = obj.keys().find(|k| !allowed.contains(&k.as_str())) {
        return Err(reject(id_hint, &format!("/{}", escape_token(unknown)), "unknown member"));
    }

    match kind {
        Kind::Request => {
            let Some(raw_id) = obj.remove("id") else {
                return Err(reject(None, "/id", "missing id"));
            };
            let id = Id::from_value(&raw_id).map_err(|detail| reject(None, "/id", detail))?;
            let method = take_method(&mut obj, Some(&id))?;
            let params = take_params(&mut obj, Some(&id))?;
            Ok(Message::Request(Request { id, method, params }))
        }
        Kind::Notification => {
            let method = take_method(&mut obj, None)?;
            let params = take_params(&mut obj, None)?;
            Ok(Message::Notification(Notification { method, params }))
        }
        Kind::Success => {
            let Some(raw_id) = obj.remove("id") else {
                return Err(reject(None, "/id", "missing id"));
            };
            let id = Id::from_value(&raw_id).map_err(|detail| reject(None, "/id", detail))?;
            match obj.remove("result") {
                Some(Value::Object(result)) => Ok(Message::Response(Response::Success(Success { id, result }))),
                _ => Err(reject(Some(id), "/result", "result must be a JSON object")),
            }
        }
        Kind::Error => {
            let id = match obj.remove("id") {
                Some(Value::Null) => None,
                Some(raw_id) => Some(Id::from_value(&raw_id).map_err(|detail| reject(None, "/id", detail))?),
                None => return Err(reject(None, "/id", "missing id (use null when it is unknown)")),
            };
            let Some(raw_error) = obj.remove("error") else {
                return Err(reject(id, "/error", "missing error"));
            };
            match decode_error_object(raw_error) {
                Ok(error) => Ok(Message::Response(Response::Error(ErrorResponse { id, error }))),
                Err((suffix, detail)) => Err(reject(id, &format!("/error{suffix}"), detail)),
            }
        }
    }
}

fn take_method(obj: &mut Map<String, Value>, id: Option<&Id>) -> Result<Method, Rejection> {
    match obj.remove("method") {
        Some(Value::String(s)) => Method::parse(&s).map_err(|detail| reject(id.cloned(), "/method", detail)),
        _ => Err(reject(id.cloned(), "/method", "method must be a string")),
    }
}

fn take_params(obj: &mut Map<String, Value>, id: Option<&Id>) -> Result<Params, Rejection> {
    match obj.remove("params") {
        Some(Value::Object(params)) => Ok(params),
        Some(_) => Err(reject(id.cloned(), "/params", "params must be a JSON object (positional arrays are not supported)")),
        None => Err(reject(id.cloned(), "/params", "params is required; send {} when there are none")),
    }
}

/// Decodes an error object. On failure returns `(pointer suffix, detail)`.
fn decode_error_object(value: Value) -> Result<RpcError, (String, &'static str)> {
    let Value::Object(mut o) = value else {
        return Err((String::new(), "error must be an object"));
    };
    if let Some(unknown) = o.keys().find(|k| !matches!(k.as_str(), "code" | "message" | "data")) {
        return Err((format!("/{}", escape_token(unknown)), "unknown member"));
    }
    let code = match o.remove("code") {
        Some(Value::Number(n)) => n.as_i64().ok_or(("/code".to_owned(), "code must be an integer"))?,
        _ => return Err(("/code".to_owned(), "code must be an integer")),
    };
    let message = match o.remove("message") {
        Some(Value::String(s)) if s.chars().count() <= MAX_ERROR_MESSAGE_CHARS => s,
        Some(Value::String(_)) => return Err(("/message".to_owned(), "message is longer than 1024 characters")),
        _ => return Err(("/message".to_owned(), "message must be a string")),
    };
    let data = match o.remove("data") {
        None => None,
        Some(Value::Object(m)) => Some(m),
        Some(_) => return Err(("/data".to_owned(), "data must be an object")),
    };
    Ok(RpcError { code, message, data })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::code;
    use serde_json::json;

    fn pointer(r: &Rejection) -> String {
        r.error.data.as_ref().and_then(|d| d.get("pointer")).and_then(Value::as_str).unwrap_or("").to_owned()
    }

    fn rejected(v: Value) -> Rejection {
        decode_message(v).unwrap_err()
    }

    #[test]
    fn decodes_a_request() {
        let m = decode_message(json!({"jsonrpc":"2.0","id":"c1","method":"web.crawl_and_index","params":{"_meta":{"trace_id":"tr_1"}}})).unwrap();
        match m {
            Message::Request(r) => {
                assert_eq!(r.id, Id::Str("c1".into()));
                assert_eq!(r.method.as_str(), "web.crawl_and_index");
                assert!(r.params.contains_key("_meta"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn decodes_a_notification_with_empty_params() {
        let m = decode_message(json!({"jsonrpc":"2.0","method":"stream.citation","params":{}})).unwrap();
        assert!(matches!(m, Message::Notification(n) if n.method.as_str() == "stream.citation"));
    }

    #[test]
    fn decodes_both_response_kinds() {
        let ok = decode_message(json!({"jsonrpc":"2.0","id":3,"result":{"cancelled":true}})).unwrap();
        assert!(matches!(ok, Message::Response(Response::Success(s)) if s.id == Id::Int(3)));
        let err = decode_message(json!({"jsonrpc":"2.0","id":"c-7f3b","error":{"code":-32006,"message":"budget","data":{"limit":8}}})).unwrap();
        match err {
            Message::Response(Response::Error(e)) => {
                assert_eq!(e.id, Some(Id::Str("c-7f3b".into())));
                assert_eq!(e.error.code, code::BUDGET_EXHAUSTED);
                assert_eq!(e.error.data.unwrap()["limit"], 8);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn error_response_may_have_null_id() {
        let m = decode_message(json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}})).unwrap();
        assert!(matches!(m, Message::Response(Response::Error(e)) if e.id.is_none()));
    }

    #[test]
    fn rejects_non_objects() {
        for v in [json!(5), json!("x"), json!(null), json!([1, 2]), json!(true)] {
            let r = rejected(v);
            assert_eq!(r.error.code, code::INVALID_REQUEST);
            assert!(r.id.is_none());
        }
    }

    #[test]
    fn rejects_wrong_or_missing_version() {
        assert_eq!(pointer(&rejected(json!({"jsonrpc":"1.0","id":1,"method":"a.b","params":{}}))), "/jsonrpc");
        assert_eq!(pointer(&rejected(json!({"id":1,"method":"a.b","params":{}}))), "/jsonrpc");
        assert_eq!(pointer(&rejected(json!({"jsonrpc":2.0,"id":1,"method":"a.b","params":{}}))), "/jsonrpc");
    }

    #[test]
    fn null_request_id_is_rejected_with_null_reply_id() {
        let r = rejected(json!({"jsonrpc":"2.0","id":null,"method":"a.b","params":{}}));
        assert_eq!(pointer(&r), "/id");
        assert!(r.id.is_none());
    }

    #[test]
    fn positional_params_are_rejected_but_the_id_is_echoed() {
        let r = rejected(json!({"jsonrpc":"2.0","id":1,"method":"a.b","params":[1,2]}));
        assert_eq!(pointer(&r), "/params");
        assert_eq!(r.id, Some(Id::Int(1)));
    }

    #[test]
    fn missing_params_are_rejected() {
        assert_eq!(pointer(&rejected(json!({"jsonrpc":"2.0","id":1,"method":"a.b"}))), "/params");
        assert_eq!(pointer(&rejected(json!({"jsonrpc":"2.0","method":"a.b"}))), "/params");
    }

    #[test]
    fn unknown_members_are_rejected_with_an_escaped_pointer() {
        let r = rejected(json!({"jsonrpc":"2.0","id":1,"method":"a.b","params":{},"extra":1}));
        assert_eq!(pointer(&r), "/extra");
        let r = rejected(json!({"jsonrpc":"2.0","id":1,"method":"a.b","params":{},"a/b~c":1}));
        assert_eq!(pointer(&r), "/a~1b~0c");
    }

    #[test]
    fn invalid_method_is_rejected_and_the_id_is_echoed() {
        let r = rejected(json!({"jsonrpc":"2.0","id":"x","method":"rpc.hello","params":{}}));
        assert_eq!(pointer(&r), "/method");
        assert_eq!(r.id, Some(Id::Str("x".into())));
        assert_eq!(pointer(&rejected(json!({"jsonrpc":"2.0","id":1,"method":7,"params":{}}))), "/method");
    }

    #[test]
    fn ambiguous_shapes_are_rejected() {
        let both = rejected(json!({"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1,"message":"x"}}));
        assert_eq!(both.error.code, code::INVALID_REQUEST);
        assert!(decode_message(json!({"jsonrpc":"2.0","id":1})).is_err());
        assert!(decode_message(json!({"jsonrpc":"2.0","id":1,"method":"a.b","params":{},"result":{}})).is_err());
    }

    #[test]
    fn response_validation() {
        assert_eq!(pointer(&rejected(json!({"jsonrpc":"2.0","id":1,"result":[1]}))), "/result");
        assert_eq!(pointer(&rejected(json!({"jsonrpc":"2.0","result":{}}))), "/id");
        assert_eq!(pointer(&rejected(json!({"jsonrpc":"2.0","error":{"code":1,"message":"m"}}))), "/id");
        assert_eq!(pointer(&rejected(json!({"jsonrpc":"2.0","id":1,"error":"boom"}))), "/error");
        assert_eq!(pointer(&rejected(json!({"jsonrpc":"2.0","id":1,"error":{"code":1.5,"message":"m"}}))), "/error/code");
        assert_eq!(pointer(&rejected(json!({"jsonrpc":"2.0","id":1,"error":{"code":1}}))), "/error/message");
        assert_eq!(pointer(&rejected(json!({"jsonrpc":"2.0","id":1,"error":{"code":1,"message":"m","data":[1]}}))), "/error/data");
        assert_eq!(pointer(&rejected(json!({"jsonrpc":"2.0","id":1,"error":{"code":1,"message":"m","foo":1}}))), "/error/foo");
        let long = "x".repeat(1025);
        assert_eq!(pointer(&rejected(json!({"jsonrpc":"2.0","id":1,"error":{"code":1,"message":long}}))), "/error/message");
        let max = "x".repeat(1024);
        assert!(decode_message(json!({"jsonrpc":"2.0","id":1,"error":{"code":1,"message":max}})).is_ok());
    }

    #[test]
    fn rejection_becomes_an_error_response() {
        let resp = rejected(json!({"jsonrpc":"2.0","id":9,"method":"bad","params":{}})).into_response();
        assert!(resp.is_error());
        assert_eq!(resp.id(), Some(&Id::Int(9)));
    }

    #[test]
    fn round_trips_through_serialisation() {
        let original = json!({"jsonrpc":"2.0","id":"c1","method":"engine.cancel","params":{"turn_id":"t_1","_meta":{"trace_id":"tr_1"}}});
        let msg = decode_message(original.clone()).unwrap();
        let again: Value = serde_json::from_str(&serde_json::to_string(&msg).unwrap()).unwrap();
        assert_eq!(again, original);
    }
}
