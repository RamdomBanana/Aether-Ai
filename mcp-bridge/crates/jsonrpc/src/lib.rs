//! Strict JSON-RPC 2.0 for the AETHER nervous system.
//!
//! This crate implements the envelope, error model and NDJSON framing defined in
//! `proto/schemas/common.schema.json`. It is deliberately schema-agnostic: it knows
//! nothing about individual methods, so toolbus (and everything else) validates
//! `params` against the method schemas separately.
//!
//! Stricter than the JSON-RPC 2.0 text, to match the wire contract:
//!
//! * `params` must be a JSON **object**. Positional arrays are rejected.
//! * Request ids are non-null strings (1..=128 chars) or integers within +/-(2^53-1).
//!   `null` is accepted only as the id of an error response.
//! * Unknown members are rejected, never ignored.
//! * Method names are dotted `lower_snake_case`; the reserved `rpc.` prefix is rejected.
//! * Duplicate object keys and nesting deeper than [`Limits::max_depth`] are rejected
//!   before any message is interpreted (see [`scan`]).
//!
//! The crate is runtime-agnostic: [`NdjsonDecoder`] is a push parser you feed from any
//! reader (tokio, std, a test), and nothing here performs I/O.
//!
//! ```
//! use aether_jsonrpc::{assemble, encode_line, parse_line, Limits, Message, Response, Success};
//! use serde_json::Map;
//!
//! let limits = Limits::default();
//! let line = br#"{"jsonrpc":"2.0","id":"c1","method":"bus.list_tools","params":{"_meta":{"trace_id":"tr_1"}}}"#;
//! let (was_batch, items) = parse_line(line, &limits).into_items().expect("parseable");
//! let mut replies = Vec::new();
//! for item in items {
//!     match item {
//!         Ok(Message::Request(req)) => replies.push(Response::Success(Success::new(req.id, Map::new()))),
//!         Ok(_) => {}
//!         Err(rejection) => replies.push(rejection.into_response()),
//!     }
//! }
//! let out = assemble(was_batch, replies).expect("one reply");
//! let bytes = encode_line(&out).expect("serialisable");
//! assert_eq!(bytes, b"{\"jsonrpc\":\"2.0\",\"id\":\"c1\",\"result\":{}}\n");
//! ```

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod batch;
pub mod codec_ndjson;
pub mod decode;
pub mod errors;
pub mod scan;
pub mod types;

pub use batch::{assemble, parse_line, Incoming, Outgoing};
pub use codec_ndjson::{encode_line, NdjsonDecoder};
pub use decode::{decode_message, Rejection};
pub use errors::{code, CodecError, RpcError};
pub use scan::ScanError;
pub use types::{ErrorResponse, Id, Message, Method, Notification, Params, Request, Response, Success};

/// Longest string id, in Unicode scalar values (schema: `JsonRpcId`).
pub const MAX_ID_STRING_CHARS: usize = 128;
/// Longest method name in bytes; method names are ASCII (schema: `JsonRpcMethod`).
pub const MAX_METHOD_BYTES: usize = 64;
/// Longest error message in Unicode scalar values (schema: `ErrorObject.message`).
pub const MAX_ERROR_MESSAGE_CHARS: usize = 1024;
/// Largest integer a JavaScript client can represent exactly (2^53 - 1).
pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

/// Resource limits applied while reading untrusted input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Longest single NDJSON line, excluding the newline.
    ///
    /// The default of 32 MiB is sized for `sandbox.execute_python` with its maximum
    /// 16 base64 files. Toolbus additionally enforces a much smaller aggregate budget.
    pub max_line_bytes: usize,
    /// Deepest allowed container nesting (the top-level value is depth 1).
    pub max_depth: usize,
    /// Most messages in one batch (schema: `JsonRpcBatchRequest.maxItems`).
    pub max_batch: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { max_line_bytes: 32 * 1024 * 1024, max_depth: 32, max_batch: 64 }
    }
}
