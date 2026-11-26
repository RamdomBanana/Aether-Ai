//! Error model: [`RpcError`] is the JSON-RPC error object, [`CodecError`] is a framing fault.

use std::fmt;

use serde::Serialize;
use serde_json::{Map, Value};

use crate::MAX_ERROR_MESSAGE_CHARS;

/// Assigned error codes. Mirrors `x-aether-error-codes` in `common.schema.json`.
pub mod code {
    /// Invalid JSON.
    pub const PARSE_ERROR: i64 = -32700;
    /// Not a valid JSON-RPC 2.0 request object.
    pub const INVALID_REQUEST: i64 = -32600;
    /// Unknown method, or no route lists the caller as a peer.
    pub const METHOD_NOT_FOUND: i64 = -32601;
    /// Params failed schema validation.
    pub const INVALID_PARAMS: i64 = -32602;
    /// Unexpected server fault.
    pub const INTERNAL_ERROR: i64 = -32603;
    /// Deadline or per-call timeout exceeded.
    pub const TIMEOUT: i64 = -32001;
    /// Sandboxed code attempted a forbidden operation.
    pub const SANDBOX_VIOLATION: i64 = -32002;
    /// Upstream socket down, model not loaded, or component starting.
    pub const UNAVAILABLE: i64 = -32003;
    /// Token bucket or concurrency limit hit.
    pub const RATE_LIMITED: i64 = -32004;
    /// Toolbus policy refused the call.
    pub const POLICY_DENIED: i64 = -32005;
    /// Per-turn tool-call budget used up.
    pub const BUDGET_EXHAUSTED: i64 = -32006;
    /// Cancelled by the caller, by disconnect or by backpressure.
    pub const CANCELLED: i64 = -32007;
    /// Referenced document, checkpoint, job or turn does not exist.
    pub const NOT_FOUND: i64 = -32008;

    /// Symbolic name of an assigned code, or `None` for any other integer.
    pub fn name(value: i64) -> Option<&'static str> {
        Some(match value {
            PARSE_ERROR => "ParseError",
            INVALID_REQUEST => "InvalidRequest",
            METHOD_NOT_FOUND => "MethodNotFound",
            INVALID_PARAMS => "InvalidParams",
            INTERNAL_ERROR => "InternalError",
            TIMEOUT => "Timeout",
            SANDBOX_VIOLATION => "SandboxViolation",
            UNAVAILABLE => "Unavailable",
            RATE_LIMITED => "RateLimited",
            POLICY_DENIED => "PolicyDenied",
            BUDGET_EXHAUSTED => "BudgetExhausted",
            CANCELLED => "Cancelled",
            NOT_FOUND => "NotFound",
            _ => return None,
        })
    }

    /// Whether retrying the same call later can succeed.
    pub fn is_retryable(value: i64) -> bool {
        matches!(value, TIMEOUT | UNAVAILABLE | RATE_LIMITED)
    }
}

/// The JSON-RPC error object (`ErrorObject` in `common.schema.json`).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RpcError {
    /// Integer error code; see [`code`].
    pub code: i64,
    /// Human-readable summary, at most 1024 characters.
    pub message: String,
    /// Optional machine-readable detail (`retryable`, `retry_after_ms`, `pointer`, ...).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Map<String, Value>>,
}

impl RpcError {
    /// Builds an error. The message is truncated to 1024 characters on a character
    /// boundary, and `data.retryable = true` is set automatically for retryable codes.
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        let err = RpcError {
            code,
            message: truncate_chars(message.into(), MAX_ERROR_MESSAGE_CHARS),
            data: None,
        };
        if self::code::is_retryable(code) {
            err.with_data("retryable", true)
        } else {
            err
        }
    }

    /// Adds or replaces one member of `data`.
    pub fn with_data(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.data.get_or_insert_with(Map::new).insert(key.to_owned(), value.into());
        self
    }

    /// Adds `data.pointer`, an RFC 6901 pointer to the offending member.
    pub fn with_pointer(self, pointer: &str) -> Self {
        self.with_data("pointer", pointer)
    }

    /// `-32700`: the line is not valid JSON.
    pub fn parse_error(detail: impl Into<String>) -> Self {
        Self::new(code::PARSE_ERROR, detail)
    }

    /// `-32600`: valid JSON that is not a valid request.
    pub fn invalid_request(detail: impl Into<String>) -> Self {
        Self::new(code::INVALID_REQUEST, detail)
    }

    /// `-32601`: no such method for this caller.
    pub fn method_not_found(method: &str) -> Self {
        Self::new(code::METHOD_NOT_FOUND, format!("method not found: {method}"))
    }

    /// `-32602`: params failed validation; `pointer` locates the offending member.
    pub fn invalid_params(pointer: &str, detail: impl Into<String>) -> Self {
        Self::new(code::INVALID_PARAMS, detail).with_pointer(pointer)
    }

    /// `-32603`: unexpected internal fault. Never put secrets or paths in `detail`.
    pub fn internal(detail: impl Into<String>) -> Self {
        Self::new(code::INTERNAL_ERROR, detail)
    }

    /// `-32001`: deadline exceeded (retryable).
    pub fn timeout(detail: impl Into<String>) -> Self {
        Self::new(code::TIMEOUT, detail)
    }

    /// `-32002`: sandboxed code attempted a forbidden operation.
    pub fn sandbox_violation(violation: &str) -> Self {
        Self::new(code::SANDBOX_VIOLATION, "sandbox violation").with_data("violation", violation)
    }

    /// `-32003`: upstream unavailable (retryable).
    pub fn unavailable(detail: impl Into<String>) -> Self {
        Self::new(code::UNAVAILABLE, detail)
    }

    /// `-32004`: rate limited (retryable); the caller should wait `retry_after_ms`.
    pub fn rate_limited(retry_after_ms: u64) -> Self {
        Self::new(code::RATE_LIMITED, "rate limited").with_data("retry_after_ms", retry_after_ms)
    }

    /// `-32005`: policy refused the call.
    pub fn policy_denied(reason: &str) -> Self {
        Self::new(code::POLICY_DENIED, "denied by policy").with_data("reason", reason)
    }

    /// `-32006`: the per-turn tool-call budget is used up.
    pub fn budget_exhausted(limit: u64) -> Self {
        Self::new(code::BUDGET_EXHAUSTED, "per-turn tool budget exhausted").with_data("limit", limit)
    }

    /// `-32007`: cancelled; `reason` is for example `"disconnect"` or `"backpressure"`.
    pub fn cancelled(reason: &str) -> Self {
        Self::new(code::CANCELLED, "cancelled").with_data("reason", reason)
    }

    /// `-32008`: the referenced object does not exist.
    pub fn not_found(what: &str) -> Self {
        Self::new(code::NOT_FOUND, format!("not found: {what}"))
    }
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match code::name(self.code) {
            Some(name) => write!(f, "{name} ({}): {}", self.code, self.message),
            None => write!(f, "error {}: {}", self.code, self.message),
        }
    }
}

impl std::error::Error for RpcError {}

/// A framing fault found by [`crate::NdjsonDecoder`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    /// A line exceeded the configured limit. The decoder has already resynchronised:
    /// the rest of that line is discarded and decoding continues with the next one.
    LineTooLong {
        /// The limit that was exceeded, in bytes.
        limit: usize,
    },
    /// The stream ended in the middle of a line.
    Truncated,
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodecError::LineTooLong { limit } => write!(f, "line exceeds {limit} bytes"),
            CodecError::Truncated => f.write_str("stream ended mid-line"),
        }
    }
}

impl std::error::Error for CodecError {}

impl From<CodecError> for RpcError {
    fn from(err: CodecError) -> Self {
        match err {
            CodecError::LineTooLong { limit } => {
                RpcError::invalid_request("line too long").with_data("reason", "line_too_long").with_data("limit", limit as u64)
            }
            CodecError::Truncated => RpcError::parse_error("stream ended mid-line"),
        }
    }
}

fn truncate_chars(mut s: String, max_chars: usize) -> String {
    let cut = s.char_indices().nth(max_chars).map(|(index, _)| index);
    if let Some(index) = cut {
        s.truncate(index);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_is_truncated_on_a_char_boundary() {
        let err = RpcError::new(code::INTERNAL_ERROR, "é".repeat(2000));
        assert_eq!(err.message.chars().count(), MAX_ERROR_MESSAGE_CHARS);
        assert!(err.message.is_char_boundary(err.message.len()));
    }

    #[test]
    fn short_message_is_untouched() {
        assert_eq!(RpcError::new(code::INTERNAL_ERROR, "boom").message, "boom");
    }

    #[test]
    fn retryable_codes_are_flagged_automatically() {
        for c in [code::TIMEOUT, code::UNAVAILABLE, code::RATE_LIMITED] {
            let err = RpcError::new(c, "x");
            assert_eq!(err.data.as_ref().unwrap()["retryable"], true, "code {c}");
        }
        for c in [code::PARSE_ERROR, code::INVALID_PARAMS, code::POLICY_DENIED, code::BUDGET_EXHAUSTED, code::CANCELLED, code::NOT_FOUND] {
            assert!(RpcError::new(c, "x").data.is_none(), "code {c}");
        }
    }

    #[test]
    fn builders_set_documented_data() {
        let rl = RpcError::rate_limited(1500);
        assert_eq!(rl.code, code::RATE_LIMITED);
        assert_eq!(rl.data.as_ref().unwrap()["retry_after_ms"], 1500u64);
        let b = RpcError::budget_exhausted(8);
        assert_eq!(b.data.as_ref().unwrap()["limit"], 8u64);
        let p = RpcError::invalid_params("/params/depth", "depth must be <= 3");
        assert_eq!(p.data.as_ref().unwrap()["pointer"], "/params/depth");
        assert_eq!(RpcError::cancelled("backpressure").data.as_ref().unwrap()["reason"], "backpressure");
    }

    #[test]
    fn every_assigned_code_has_a_name() {
        let all = [-32700, -32600, -32601, -32602, -32603, -32001, -32002, -32003, -32004, -32005, -32006, -32007, -32008];
        for c in all {
            assert!(code::name(c).is_some(), "code {c}");
        }
        assert!(code::name(-1).is_none());
    }

    #[test]
    fn serialises_without_data_when_absent() {
        let json = serde_json::to_string(&RpcError::new(code::PARSE_ERROR, "bad")).unwrap();
        assert_eq!(json, r#"{"code":-32700,"message":"bad"}"#);
    }

    #[test]
    fn codec_error_maps_to_rpc_error() {
        let e: RpcError = CodecError::LineTooLong { limit: 10 }.into();
        assert_eq!(e.code, code::INVALID_REQUEST);
        assert_eq!(e.data.as_ref().unwrap()["limit"], 10u64);
        let e: RpcError = CodecError::Truncated.into();
        assert_eq!(e.code, code::PARSE_ERROR);
    }
}
