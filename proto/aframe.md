# AFRAME v1: AETHER binary framing

AFRAME is the framing used on `engine.sock`, the inference hot path between the
engine and its clients (gateway, crawler, learn). Everything else in AETHER uses
NDJSON JSON-RPC 2.0 (see `schemas/common.schema.json`).

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

Status: **v1, stable**. The wire version is the `version` byte in every header.

---

## 1. Transport

- `AF_UNIX`, `SOCK_STREAM`, path `$AETHER_RUN/engine.sock`. The directory is mode `0700` and the socket is mode `0600`.
- On `accept`, the server MUST read `SO_PEERCRED` and close the connection unless the peer uid equals the server uid. Filesystem permissions are not the only barrier.
- One connection multiplexes many concurrent streams. Both peers MUST read continuously in a dedicated task, so a slow stream never blocks control frames.
- The server MUST NOT accept TCP or any non-UDS transport for AFRAME.

## 2. Conventions

- All multi-byte integers are **little-endian**. There is no implicit padding. Every pad byte is explicit and MUST be zero on send.
- `f32` is IEEE 754 binary32. `f16` is IEEE 754 binary16. Both are little-endian.
- Text is UTF-8. JSON is RFC 8259, with no BOM and no trailing newline.
- A frame is a 16-byte header immediately followed by `payload_len` bytes of payload. Nothing sits between frames.

## 3. Frame header (16 bytes)

| Offset | Size | Type | Field | Value / meaning |
|---:|---:|---|---|---|
| 0 | 2 | `u8[2]` | `magic` | `0xAE 0x7E` |
| 2 | 1 | `u8` | `version` | `1` |
| 3 | 1 | `u8` | `type` | see §5 |
| 4 | 2 | `u16` | `flags` | see §4 |
| 6 | 2 | `u16` | `reserved` | MUST be `0` on send; ignored on receive |
| 8 | 4 | `u32` | `stream_id` | see §6 |
| 12 | 4 | `u32` | `payload_len` | `0 ..= 16_777_216` (16 MiB) |

```
 0       1       2       3       4       5       6       7
+-------+-------+-------+-------+-------+-------+-------+-------+
| 0xAE  | 0x7E  |  ver  | type  |  flags (u16)  | reserved(u16) |
+-------+-------+-------+-------+-------+-------+-------+-------+
|        stream_id (u32)        |       payload_len (u32)       |
+-------+-------+-------+-------+-------+-------+-------+-------+
 8       9      10      11      12      13      14      15
```

Reference parser (the receiver MUST validate `payload_len` **before** allocating or reading the payload):

```rust
pub const MAX_PAYLOAD: u32 = 16 * 1024 * 1024;

pub fn parse_header(b: &[u8; 16]) -> Result<Header, ProtocolError> {
    if b[0] != 0xAE || b[1] != 0x7E { return Err(ProtocolError::BadMagic); }
    if b[2] != 1 { return Err(ProtocolError::UnsupportedVersion(b[2])); }
    let payload_len = u32::from_le_bytes([b[12], b[13], b[14], b[15]]);
    if payload_len > MAX_PAYLOAD { return Err(ProtocolError::PayloadTooLarge(payload_len)); }
    Ok(Header {
        ty: b[3],
        flags: u16::from_le_bytes([b[4], b[5]]),
        stream_id: u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
        payload_len,
    })
}
```

Python: `HEADER = struct.Struct("<2sBBHHII")` has `size == 16`.
C/C++: `#pragma pack(push, 1)` struct, with the same field order, on little-endian targets (x86-64, AArch64).

## 4. Flags (`u16`)

| Bit | Name | Meaning |
|---:|---|---|
| 0 | `END_STREAM` | The sender will send no further frames on this `stream_id` |
| 1 | `ERROR` | The payload is a JSON-RPC **error response** (`RPC` frames only) |
| 2-15 | | Reserved. MUST be `0` on send; receivers MUST ignore unknown bits |

`ERROR` lets a multiplexer classify a terminal frame without parsing JSON. It is set if and only if the JSON payload contains `error`.

## 5. Frame types

| Type | Name | Stream | Payload |
|---:|---|---|---|
| `0x01` | `RPC` | `>= 1` (and `0` for `conn.*`) | one JSON-RPC 2.0 message |
| `0x10` | `TOKENS` | `>= 1` | binary token delta (§5.2) |
| `0x20` | `PING` | `0` | 8 opaque bytes |
| `0x21` | `PONG` | `0` | the same 8 bytes echoed |
| `0x30` | `VECTORS` | `>= 1` | binary embedding block (§5.3) |
| `0x40`-`0x7F` | extension | any | MUST be skipped by receivers that do not understand it |

Any other type value is a protocol error (§8). Introducing a new non-extension type requires `version = 2`.

### 5.1 `RPC` (0x01)

The payload is exactly **one** JSON-RPC 2.0 message: a request, notification, success response or error response. Batches are not used on AFRAME. Schemas are in `schemas/engine.schema.json`.

- A request is sent by the client on a fresh odd `stream_id` with `END_STREAM` set. The client half-closes immediately, and all cancellation goes through `engine.cancel` on a **new** stream.
- Server notifications (`stream.*`) carry no `id` and no `END_STREAM`.
- The response is the **final** frame on the stream and always carries `END_STREAM`. If it is an error response it also carries `ERROR`.
- Every stream therefore ends with exactly one response frame.

### 5.2 `TOKENS` (0x10)

A streaming delta of generated output. `END_STREAM` is never set on `TOKENS`; the stream ends with the `RPC` response.

| Payload offset | Size | Type | Field |
|---:|---:|---|---|
| 0 | 4 | `u32` | `seq`: starts at 0 per stream and increments by 1 per `TOKENS` frame, across channels |
| 4 | 1 | `u8` | `channel`: `0` answer, `1` thought, `2` tool |
| 5 | 1 | `u8` | pad, `0` |
| 6 | 2 | `u16` | `n`: number of tokens, `0 ..= 4096` |
| 8 | `8n` | `{u32 token_id, f32 logprob}[n]` | tokens, 8-byte aligned when the frame starts on an 8-byte boundary |
| `8 + 8n` | 4 | `u32` | `text_len` |
| `12 + 8n` | `text_len` | UTF-8 | `text` delta |

Invariant: `payload_len == 12 + 8*n + text_len`. A violation is a protocol error.

Rules:

1. **UTF-8 safety.** `text` never ends inside a code point. The engine holds back an incomplete trailing sequence and prepends it to the next frame. If generation ends with an unfinished sequence, the engine emits U+FFFD. Consequently `text` in frame *k* may contain bytes belonging to tokens of frame *k-1*, and receivers MUST NOT assume a 1:1 token-to-text mapping within a frame.
2. **One channel per frame.** The engine starts a new frame when the channel changes.
3. **Control tokens.** `<thought>`, `</thought>`, `<tool_call>` and similar markers switch the channel. They appear in the token list (by id) but never in `text`.
4. **Logprobs.** If logprobs are not computed, every `logprob` is the canonical quiet NaN `0x7FC00000`.
5. `n = 0` is legal. It is used to flush held-back bytes or announce a channel switch.

### 5.3 `VECTORS` (0x30): embedding blocks

Used only by `engine.embed`. Vectors are **L2-normalised** by the engine before quantisation to `f16`. Consumers MUST NOT re-normalise.

| Payload offset | Size | Type | Field |
|---:|---:|---|---|
| 0 | 4 | `u32` | `first_index`: row index of the first vector in this frame |
| 4 | 4 | `u32` | `count`: rows in this frame, `>= 1` |
| 8 | 4 | `u32` | `dim`: components per row, `1 ..= 16384` |
| 12 | 4 | `u32` | `flags`: `0`, reserved |
| 16 | `2 * count * dim` | `f16[count][dim]` | row-major data |

Invariant: `payload_len == 16 + 2*count*dim`.

Flow for `engine.embed`:

1. The client sends the request (`RPC`, `END_STREAM`).
2. The server sends **one or more `VECTORS` frames** on the same stream. Their `[first_index, first_index+count)` ranges are contiguous, ascending and non-overlapping, and together cover `[0, count_total)`. Frames split so that each payload stays within 16 MiB.
3. The server sends the final `RPC` **response** (`END_STREAM`). It is the commit. Its `result.count` and `result.dim` MUST match the vectors received.
4. If the engine fails at any point, only an error response is sent. The client MUST discard any `VECTORS` already received on that stream.

## 6. Streams

- `stream_id = 0` is connection-scoped: `PING`, `PONG` and `conn.*` notifications only.
- Client-initiated streams use **odd** ids, strictly increasing, never reused within a connection. Even ids are reserved for server-initiated streams, which v1 does not use.
- Before reaching `2^31 - 1`, the client MUST open a new connection.
- A stream is *open* from the client's request until the server's `END_STREAM`. Default limit: 256 concurrent open streams per connection. Beyond that, the server answers `-32004 RateLimited` with `data.retryable = true`.
- After a peer sets `END_STREAM`, any further frame from that peer on the stream is a **stream error** (§8).

## 7. Ordering, deadlines, cancellation, backpressure

- Frames on one stream are delivered in order. There is no ordering across streams.
- `params._meta.deadline_unix_ms` is enforced by the server. After the deadline it MUST terminate the work with `-32001 Timeout`.
- Client disconnect: the gateway MUST send `engine.cancel` for every turn whose HTTP client has gone. Closing the AFRAME connection cancels all streams opened on it.
- Backpressure: each stream has a bounded send queue in the engine (default 1024 frames). If a consumer stalls and the queue is full, the engine cancels that stream with `-32007 Cancelled` and `data.reason = "backpressure"`. The decode loop never blocks on a socket write.
- Keepalive: when a connection is idle for 15 s, either peer sends `PING` (8 opaque bytes). If no `PONG` arrives within 10 s, the connection is closed.

## 8. Errors

| Class | Examples | Required action |
|---|---|---|
| **Connection error** | bad magic, unsupported version, unknown non-extension type, `payload_len > MAX_PAYLOAD`, invalid `TOKENS`/`VECTORS` length invariants, non-zero-stream `PING`, frame on stream 0 other than `PING`/`PONG`/`conn.*` | Send `conn.goaway` on stream 0 (best effort), then close |
| **Stream error** | frame after `END_STREAM`, request with an even `stream_id`, malformed JSON in an `RPC` frame | Reply on that stream with an error response (`ERROR\|END_STREAM`, code `-32700` or `-32600`), ignore later frames on it, keep the connection |

`conn.goaway` is defined in `schemas/engine.schema.json`.

## 9. Limits (normative defaults)

| Limit | Value |
|---|---|
| Max `payload_len` | 16 MiB |
| Max concurrent streams / connection | 256 |
| Max tokens per `TOKENS` frame | 4096 |
| Max `engine.embed` inputs per request | 512 |
| Idle ping interval / pong timeout | 15 s / 10 s |
| Per-stream engine send queue | 1024 frames |

## 10. Conformance vectors

Header bytes are shown in hex. Implementations in every language MUST reproduce them byte-for-byte.

**RPC request**, stream 1, flags `END_STREAM`, payload 107 bytes:
```
AE 7E 01 01 01 00 00 00 01 00 00 00 6B 00 00 00
```
payload (ASCII, no trailing newline):
```
{"jsonrpc":"2.0","id":"c1","method":"engine.cancel","params":{"turn_id":"t_1","_meta":{"trace_id":"tr_1"}}}
```

**PING**, stream 0, payload `01..08`:
```
AE 7E 01 20 00 00 00 00 00 00 00 00 08 00 00 00 01 02 03 04 05 06 07 08
```

**TOKENS**, stream 1, `seq=0`, channel answer, one token (id 256, logprob -1.0), text `Hi`, payload 22 bytes:
```
header:  AE 7E 01 10 00 00 00 00 01 00 00 00 16 00 00 00
payload: 00 00 00 00 00 00 01 00 00 01 00 00 00 00 80 BF 02 00 00 00 48 69
```

**VECTORS**, stream 3, `first_index=0`, `count=1`, `dim=2`, data `[1.0, -2.0]`, payload 20 bytes:
```
header:  AE 7E 01 30 00 00 00 00 03 00 00 00 14 00 00 00
payload: 00 00 00 00 01 00 00 00 02 00 00 00 00 00 00 00 00 3C 00 C0
```

## 11. Security notes

- Never allocate from an unvalidated length. Check `payload_len` against §9 and against the type invariants first.
- JSON payloads are parsed with a depth limit of 32 and rejected on duplicate keys.
- The engine treats all `messages[*].content` and tool results as untrusted data. Framing carries no authority.
