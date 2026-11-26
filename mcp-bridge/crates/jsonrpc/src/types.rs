//! JSON-RPC 2.0 envelope types.
//!
//! Values of these types are always *valid* by construction: [`Id`] and [`Method`] can
//! only be built through validating constructors, and decoding goes through
//! [`crate::decode_message`]. Serialisation writes members in the canonical order
//! `jsonrpc, id, method|result|error, params`, independent of serde_json feature flags.

use std::fmt;

use serde::ser::{Serialize, SerializeMap, Serializer};
use serde_json::{Map, Value};

use crate::errors::RpcError;
use crate::{MAX_ID_STRING_CHARS, MAX_METHOD_BYTES, MAX_SAFE_INTEGER};

/// By-name parameters. Always an object, never a positional array.
pub type Params = Map<String, Value>;

/// A request id: a non-empty string (at most 128 characters) or an integer within
/// +/-(2^53-1). Floating-point ids such as `1.0` are rejected even though JSON Schema
/// would call them integers, because they do not round-trip through every client.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Id {
    /// A string id.
    Str(String),
    /// An integer id.
    Int(i64),
}

impl Id {
    /// Validates a decoded JSON value as a request id.
    pub fn from_value(value: &Value) -> Result<Id, &'static str> {
        match value {
            Value::String(s) => {
                let chars = s.chars().count();
                if chars == 0 || chars > MAX_ID_STRING_CHARS {
                    Err("string id must be 1 to 128 characters")
                } else {
                    Ok(Id::Str(s.clone()))
                }
            }
            Value::Number(n) => match n.as_i64() {
                Some(i) if (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&i) => Ok(Id::Int(i)),
                _ => Err("numeric id must be an integer within +/-(2^53-1)"),
            },
            Value::Null => Err("id must not be null"),
            _ => Err("id must be a string or an integer"),
        }
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Id::Str(s) => f.write_str(s),
            Id::Int(i) => write!(f, "{i}"),
        }
    }
}

impl Serialize for Id {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Id::Str(s) => serializer.serialize_str(s),
            Id::Int(i) => serializer.serialize_i64(*i),
        }
    }
}

/// A validated method name: at least two dot-separated `lower_snake_case` segments, each
/// starting with a letter, at most 64 bytes, and never starting with the reserved `rpc.`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Method(String);

impl Method {
    /// Validates and wraps a method name.
    pub fn parse(s: &str) -> Result<Method, &'static str> {
        if is_valid_method(s) {
            Ok(Method(s.to_owned()))
        } else {
            Err("method must be dotted lower_snake_case (for example web.crawl_and_index), at most 64 bytes, and must not start with rpc.")
        }
    }

    /// The method name as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The first segment, such as `web` for `web.crawl_and_index`.
    pub fn namespace(&self) -> &str {
        self.0.split('.').next().unwrap_or("")
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn is_valid_method(s: &str) -> bool {
    if s.is_empty() || s.len() > MAX_METHOD_BYTES {
        return false;
    }
    let mut segments = 0usize;
    for (index, segment) in s.split('.').enumerate() {
        let mut chars = segment.chars();
        match chars.next() {
            Some(c) if c.is_ascii_lowercase() => {}
            _ => return false,
        }
        if !chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
            return false;
        }
        if index == 0 && segment == "rpc" {
            return false;
        }
        segments += 1;
    }
    segments >= 2
}

/// A request: expects exactly one response carrying the same id.
#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    /// Correlates the response.
    pub id: Id,
    /// The method to invoke.
    pub method: Method,
    /// By-name parameters, including `_meta`.
    pub params: Params,
}

impl Request {
    /// Builds a request, validating the method name.
    pub fn new(id: Id, method: &str, params: Params) -> Result<Self, RpcError> {
        let method = Method::parse(method).map_err(|m| RpcError::invalid_request(m).with_pointer("/method"))?;
        Ok(Request { id, method, params })
    }
}

/// A notification: no id, never answered.
#[derive(Debug, Clone, PartialEq)]
pub struct Notification {
    /// The method to invoke.
    pub method: Method,
    /// By-name parameters.
    pub params: Params,
}

impl Notification {
    /// Builds a notification, validating the method name.
    pub fn new(method: &str, params: Params) -> Result<Self, RpcError> {
        let method = Method::parse(method).map_err(|m| RpcError::invalid_request(m).with_pointer("/method"))?;
        Ok(Notification { method, params })
    }
}

/// A success response. `result` is always an object in this protocol.
#[derive(Debug, Clone, PartialEq)]
pub struct Success {
    /// Echoes the request id.
    pub id: Id,
    /// The method's result object.
    pub result: Map<String, Value>,
}

impl Success {
    /// Builds a success response.
    pub fn new(id: Id, result: Map<String, Value>) -> Self {
        Success { id, result }
    }
}

/// An error response. `id` is `None` (serialised as `null`) only when the id of the
/// failed request could not be determined.
#[derive(Debug, Clone, PartialEq)]
pub struct ErrorResponse {
    /// Echoes the request id, when known.
    pub id: Option<Id>,
    /// What went wrong.
    pub error: RpcError,
}

impl ErrorResponse {
    /// Builds an error response.
    pub fn new(id: Option<Id>, error: RpcError) -> Self {
        ErrorResponse { id, error }
    }
}

/// Either kind of response.
#[derive(Debug, Clone, PartialEq)]
pub enum Response {
    /// `result` present.
    Success(Success),
    /// `error` present.
    Error(ErrorResponse),
}

impl Response {
    /// The id this response answers, if known.
    pub fn id(&self) -> Option<&Id> {
        match self {
            Response::Success(s) => Some(&s.id),
            Response::Error(e) => e.id.as_ref(),
        }
    }

    /// `true` for an error response.
    pub fn is_error(&self) -> bool {
        matches!(self, Response::Error(_))
    }
}

/// Any single JSON-RPC message.
#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    /// A request.
    Request(Request),
    /// A notification.
    Notification(Notification),
    /// A response.
    Response(Response),
}

const VERSION: &str = "2.0";

impl Serialize for Request {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(4))?;
        map.serialize_entry("jsonrpc", VERSION)?;
        map.serialize_entry("id", &self.id)?;
        map.serialize_entry("method", self.method.as_str())?;
        map.serialize_entry("params", &self.params)?;
        map.end()
    }
}

impl Serialize for Notification {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("jsonrpc", VERSION)?;
        map.serialize_entry("method", self.method.as_str())?;
        map.serialize_entry("params", &self.params)?;
        map.end()
    }
}

impl Serialize for Success {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("jsonrpc", VERSION)?;
        map.serialize_entry("id", &self.id)?;
        map.serialize_entry("result", &self.result)?;
        map.end()
    }
}

impl Serialize for ErrorResponse {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("jsonrpc", VERSION)?;
        map.serialize_entry("id", &self.id)?;
        map.serialize_entry("error", &self.error)?;
        map.end()
    }
}

impl Serialize for Response {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Response::Success(s) => s.serialize(serializer),
            Response::Error(e) => e.serialize(serializer),
        }
    }
}

impl Serialize for Message {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Message::Request(r) => r.serialize(serializer),
            Message::Notification(n) => n.serialize(serializer),
            Message::Response(r) => r.serialize(serializer),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn params(v: Value) -> Params {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn valid_methods() {
        for m in ["web.crawl_and_index", "engine.status", "learn.checkpoint.rollback", "a.b", "stream.tool_call", "memory.hybrid_search", "x1.y2_z3"] {
            assert!(Method::parse(m).is_ok(), "{m}");
        }
    }

    #[test]
    fn invalid_methods() {
        let too_long = format!("a.{}", "b".repeat(63)); // 65 bytes
        let max_len = format!("a.{}", "b".repeat(62)); // 64 bytes
        for m in ["", "status", "rpc.foo", "rpc.a.b", "Web.crawl", "web.", ".web", "web..x", "web.1x", "web.a-b", "web.a b", "web.é", too_long.as_str()] {
            assert!(Method::parse(m).is_err(), "{m:?}");
        }
        assert!(Method::parse(&max_len).is_ok());
        assert!(Method::parse("rpcx.status").is_ok(), "only the exact rpc. namespace is reserved");
    }

    #[test]
    fn method_namespace() {
        assert_eq!(Method::parse("web.crawl_and_index").unwrap().namespace(), "web");
        assert_eq!(Method::parse("learn.checkpoint.rollback").unwrap().namespace(), "learn");
    }

    #[test]
    fn id_validation() {
        assert_eq!(Id::from_value(&json!("c1")), Ok(Id::Str("c1".into())));
        assert_eq!(Id::from_value(&json!(5)), Ok(Id::Int(5)));
        assert_eq!(Id::from_value(&json!(-5)), Ok(Id::Int(-5)));
        assert_eq!(Id::from_value(&json!(9_007_199_254_740_991_i64)), Ok(Id::Int(9_007_199_254_740_991)));
        assert!(Id::from_value(&json!(9_007_199_254_740_992_i64)).is_err());
        assert!(Id::from_value(&json!(-9_007_199_254_740_992_i64)).is_err());
        assert!(Id::from_value(&json!(u64::MAX)).is_err());
        assert!(Id::from_value(&json!(1.5)).is_err());
        assert!(Id::from_value(&json!(1.0)).is_err());
        assert!(Id::from_value(&json!("")).is_err());
        assert!(Id::from_value(&json!("x".repeat(128))).is_ok());
        assert!(Id::from_value(&json!("x".repeat(129))).is_err());
        assert!(Id::from_value(&json!("é".repeat(128))).is_ok(), "limit counts characters, not bytes");
        assert!(Id::from_value(&Value::Null).is_err());
        assert!(Id::from_value(&json!(true)).is_err());
        assert!(Id::from_value(&json!([1])).is_err());
    }

    #[test]
    fn request_serialises_in_canonical_order() {
        let req = Request::new(Id::Str("c1".into()), "engine.cancel", params(json!({"turn_id": "t_1"}))).unwrap();
        assert_eq!(serde_json::to_string(&req).unwrap(), r#"{"jsonrpc":"2.0","id":"c1","method":"engine.cancel","params":{"turn_id":"t_1"}}"#);
    }

    #[test]
    fn notification_has_no_id() {
        let n = Notification::new("stream.citation", params(json!({}))).unwrap();
        assert_eq!(serde_json::to_string(&n).unwrap(), r#"{"jsonrpc":"2.0","method":"stream.citation","params":{}}"#);
    }

    #[test]
    fn success_and_error_responses() {
        let ok = Response::Success(Success::new(Id::Int(7), params(json!({"cancelled": true}))));
        assert_eq!(serde_json::to_string(&ok).unwrap(), r#"{"jsonrpc":"2.0","id":7,"result":{"cancelled":true}}"#);
        let err = Response::Error(ErrorResponse::new(None, RpcError::parse_error("bad")));
        assert_eq!(serde_json::to_string(&err).unwrap(), r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"bad"}}"#);
        assert!(err.is_error() && err.id().is_none());
        assert_eq!(ok.id(), Some(&Id::Int(7)));
    }

    #[test]
    fn constructors_reject_bad_methods() {
        assert!(Request::new(Id::Int(1), "status", Params::new()).is_err());
        assert!(Notification::new("rpc.x", Params::new()).is_err());
    }

    #[test]
    fn no_raw_newline_is_ever_emitted() {
        let req = Request::new(Id::Str("a\nb".into()), "x.y", params(json!({"t": "line1\nline2\r\n\u{2028}"}))).unwrap();
        assert!(!serde_json::to_string(&req).unwrap().contains('\n'));
    }
}
