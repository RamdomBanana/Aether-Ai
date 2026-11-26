//! One connection's read, dispatch and write loop, independent of the transport.
//!
//! It works over any `Read` plus `Write`, so the same code serves a Unix socket, stdin and
//! stdout, or an in-memory buffer in tests.
//!
//! * Lines are framed by [`NdjsonDecoder`] with the configured limits; an over-long line gets
//!   one error reply and the connection carries on.
//! * Each line is handled on its own scoped thread, so a slow crawl never delays a fast
//!   search on the same connection. Replies are written whole, under a lock, so they never
//!   interleave. Replies may therefore come back out of order; callers match them by id.
//! * At most `max_in_flight` lines are being worked on at once. A line that arrives beyond
//!   that is answered immediately with `-32004 RateLimited` (retryable), never queued without
//!   bound.
//! * Notifications and stray responses from the peer are ignored: toolbus serves requests only.
//! * When the peer closes its side, in-flight calls still finish and are answered (the write
//!   may fail if the peer is gone, which is fine). An unterminated final line is reported as a
//!   framing error and is never executed.
//! * A failed write marks the connection broken and the read loop stops.

use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

use aether_jsonrpc::{assemble, encode_line, parse_line, ErrorResponse, Id, Limits, Message, NdjsonDecoder, Outgoing, Rejection, Response, RpcError};

use crate::dispatch::{Backends, Toolbus};
use crate::registry::Peer;

/// Per-connection settings.
#[derive(Debug, Clone)]
pub struct ConnConfig {
    /// Framing, depth and batch limits.
    pub limits: Limits,
    /// Most lines being worked on at once on this connection.
    pub max_in_flight: usize,
}

impl Default for ConnConfig {
    fn default() -> Self {
        ConnConfig { limits: Limits::default(), max_in_flight: 16 }
    }
}

type Items = Vec<Result<Message, Rejection>>;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn send<W: Write>(out: &Mutex<W>, broken: &AtomicBool, outgoing: &Outgoing) {
    let Ok(bytes) = encode_line(outgoing) else { return };
    let mut writer = lock(out);
    let written = writer.write_all(&bytes);
    if written.and_then(|()| writer.flush()).is_err() {
        broken.store(true, Ordering::SeqCst);
    }
}

fn send_error(out: &Mutex<impl Write>, broken: &AtomicBool, id: Option<Id>, error: RpcError) {
    send(out, broken, &Outgoing::Single(Response::Error(ErrorResponse::new(id, error))));
}

fn request_ids(items: &Items) -> Vec<Id> {
    items
        .iter()
        .filter_map(|item| match item {
            Ok(Message::Request(request)) => Some(request.id.clone()),
            _ => None,
        })
        .collect()
}

fn run_items(items: Items, caller: Peer, bus: &Toolbus, backends: &(dyn Backends + Sync)) -> Vec<Response> {
    let mut replies = Vec::new();
    for item in items {
        match item {
            Ok(Message::Request(request)) => replies.push(bus.handle(caller, request, backends)),
            Ok(Message::Notification(_)) | Ok(Message::Response(_)) => {}
            Err(rejection) => replies.push(rejection.into_response()),
        }
    }
    replies
}

/// Serves one connection until the peer closes it or a write fails.
///
/// Returns `Err` only for a read error other than interruption; protocol problems are answered
/// on the wire and do not end the connection.
pub fn serve_connection<R: Read, W: Write + Send>(
    mut reader: R,
    writer: W,
    caller: Peer,
    bus: &Toolbus,
    backends: &(dyn Backends + Sync),
    cfg: &ConnConfig,
) -> io::Result<()> {
    let out = Mutex::new(writer);
    let in_flight = AtomicUsize::new(0);
    let broken = AtomicBool::new(false);

    std::thread::scope(|scope| -> io::Result<()> {
        let mut decoder = NdjsonDecoder::with_limits(&cfg.limits);
        let mut chunk = vec![0u8; 64 * 1024];
        while !broken.load(Ordering::SeqCst) {
            let read = match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            decoder.push(&chunk[..read]);
            while let Some(framed) = decoder.next_line() {
                let line = match framed {
                    Ok(line) => line,
                    Err(codec) => {
                        send_error(&out, &broken, None, codec.into());
                        continue;
                    }
                };
                let (was_batch, items) = match parse_line(&line, &cfg.limits).into_items() {
                    Ok(parts) => parts,
                    Err(response) => {
                        send(&out, &broken, &Outgoing::Single(response));
                        continue;
                    }
                };

                if in_flight.fetch_add(1, Ordering::SeqCst) >= cfg.max_in_flight {
                    in_flight.fetch_sub(1, Ordering::SeqCst);
                    let replies: Vec<Response> = items
                        .into_iter()
                        .filter_map(|item| match item {
                            Ok(Message::Request(request)) => Some(Response::Error(ErrorResponse::new(Some(request.id), RpcError::rate_limited(250)))),
                            Err(rejection) => Some(rejection.into_response()),
                            _ => None,
                        })
                        .collect();
                    if let Some(outgoing) = assemble(was_batch, replies) {
                        send(&out, &broken, &outgoing);
                    }
                    continue;
                }

                let ids = request_ids(&items);
                let (out_ref, in_flight_ref, broken_ref) = (&out, &in_flight, &broken);
                let spawned = std::thread::Builder::new().name("toolbus-call".to_owned()).spawn_scoped(scope, move || {
                    let replies = run_items(items, caller, bus, backends);
                    if let Some(outgoing) = assemble(was_batch, replies) {
                        send(out_ref, broken_ref, &outgoing);
                    }
                    in_flight_ref.fetch_sub(1, Ordering::SeqCst);
                });
                if spawned.is_err() {
                    in_flight.fetch_sub(1, Ordering::SeqCst);
                    let replies: Vec<Response> =
                        ids.into_iter().map(|id| Response::Error(ErrorResponse::new(Some(id), RpcError::unavailable("toolbus could not start a worker")))).collect();
                    if let Some(outgoing) = assemble(was_batch, replies) {
                        send(&out, &broken, &outgoing);
                    }
                }
            }
        }
        if let Err(codec) = decoder.finish() {
            send_error(&out, &broken, None, codec.into());
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::SharedBuffer;
    use crate::audit::{AuditLog, GENESIS_HASH};
    use crate::dispatch::{Clock, SystemClock, ToolbusConfig};
    use aether_jsonrpc::{code, Params};
    use serde_json::{json, Map, Value};
    use std::collections::HashMap;
    use std::io::Cursor;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    #[derive(Default)]
    struct SyncFake {
        replies: Mutex<HashMap<String, Result<Map<String, Value>, RpcError>>>,
        delays_ms: Mutex<HashMap<String, u64>>,
    }

    impl SyncFake {
        fn reply(&self, method: &str, value: Value) {
            lock(&self.replies).insert(method.to_owned(), Ok(value.as_object().unwrap().clone()));
        }

        fn delay(&self, method: &str, ms: u64) {
            lock(&self.delays_ms).insert(method.to_owned(), ms);
        }

        fn answer(&self, method: &str) -> Result<Map<String, Value>, RpcError> {
            let delay = lock(&self.delays_ms).get(method).copied().unwrap_or(0);
            if delay > 0 {
                std::thread::sleep(Duration::from_millis(delay));
            }
            let reply = lock(&self.replies).get(method).cloned();
            reply.unwrap_or_else(|| Err(RpcError::internal("no reply configured")))
        }
    }

    impl Backends for SyncFake {
        fn forward(&self, _server: Peer, method: &str, _params: Params, _wait_ms: u64) -> Result<Map<String, Value>, RpcError> {
            self.answer(method)
        }

        fn local(&self, method: &str, _params: Params, _wait_ms: u64) -> Result<Map<String, Value>, RpcError> {
            self.answer(method)
        }
    }

    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<u8>>>);

    impl Write for Sink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            lock(&self.0).extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct BrokenPipe;

    impl Write for BrokenPipe {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "gone"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn bus() -> Toolbus {
        let audit = AuditLog::new(Box::new(SharedBuffer::default()), 0, GENESIS_HASH.to_owned());
        Toolbus::from_embedded(ToolbusConfig::default(), audit, Box::new(SystemClock)).unwrap()
    }

    const LIST: &str = r#"{"jsonrpc":"2.0","id":"a","method":"bus.list_tools","params":{"_meta":{"trace_id":"tr_1"}}}"#;

    fn crawl(id: &str) -> String {
        json!({"jsonrpc": "2.0", "id": id, "method": "web.crawl_and_index",
               "params": {"urls": ["https://example.org/post"], "_meta": {"trace_id": "tr_1", "session_id": "s_1", "turn_id": "t_1", "deadline_unix_ms": SystemClock.now_ms() + 60_000}}})
        .to_string()
    }

    fn crawl_result() -> Value {
        json!({"job_id": "j_1", "state": "complete", "pages": [], "stats": {"fetched": 1, "indexed": 1, "skipped": 0, "took_ms": 5}})
    }

    fn fake() -> SyncFake {
        let f = SyncFake::default();
        f.reply("bus.list_tools", json!({"tools": []}));
        f.reply("web.crawl_and_index", crawl_result());
        f
    }

    fn run_with(cfg: &ConnConfig, input: &str, backends: &SyncFake) -> Vec<Value> {
        let sink = Sink::default();
        serve_connection(Cursor::new(input.as_bytes().to_vec()), sink.clone(), Peer::Engine, &bus(), backends, cfg).unwrap();
        let text = String::from_utf8(lock(&sink.0).clone()).unwrap();
        text.lines().map(|l| serde_json::from_str(l).unwrap()).collect()
    }

    fn run(input: &str, backends: &SyncFake) -> Vec<Value> {
        run_with(&ConnConfig::default(), input, backends)
    }

    #[test]
    fn one_request_gets_one_response_line() {
        let out = run(&format!("{LIST}\n"), &fake());
        assert_eq!(out.len(), 1);
        assert_eq!((out[0]["id"].as_str(), out[0]["result"].clone()), (Some("a"), json!({"tools": []})));
    }

    #[test]
    fn garbage_gets_a_null_id_error_and_the_connection_survives() {
        let out = run(&format!("this is not json\n{LIST}\n"), &fake());
        assert_eq!(out.len(), 2);
        assert_eq!((out[0]["error"]["code"].clone(), out[0]["id"].clone()), (json!(code::PARSE_ERROR), Value::Null));
        assert!(out[1].get("result").is_some());
    }

    #[test]
    fn a_batch_is_answered_with_one_array_and_notifications_stay_silent() {
        let notification = r#"{"jsonrpc":"2.0","method":"stream.citation","params":{}}"#;
        let out = run(&format!("[{LIST},{notification},5]\n"), &fake());
        assert_eq!(out.len(), 1, "one reply line for the whole batch");
        let replies = out[0].as_array().unwrap();
        assert_eq!(replies.len(), 2, "request answered, notification silent, junk element rejected");
        assert!(replies.iter().any(|r| r.get("result").is_some()) && replies.iter().any(|r| r["error"]["code"] == code::INVALID_REQUEST));
    }

    #[test]
    fn nothing_at_all_is_sent_for_notifications_only() {
        let out = run("{\"jsonrpc\":\"2.0\",\"method\":\"stream.citation\",\"params\":{}}\n", &fake());
        assert!(out.is_empty());
    }

    #[test]
    fn an_over_long_line_is_rejected_and_the_next_line_is_still_served() {
        let cfg = ConnConfig { limits: Limits { max_line_bytes: 300, ..Limits::default() }, ..ConnConfig::default() };
        let out = run_with(&cfg, &format!("{}\n{LIST}\n", "x".repeat(400)), &fake());
        assert_eq!(out.len(), 2);
        assert_eq!(out[0]["error"]["data"]["reason"], "line_too_long");
        assert!(out[1].get("result").is_some());
    }

    #[test]
    fn an_unterminated_final_line_is_reported_and_never_executed() {
        let f = fake();
        f.delay("bus.list_tools", 0);
        let out = run(LIST, &f); // no trailing newline
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["error"]["code"], code::PARSE_ERROR);
        assert!(out[0].get("result").is_none());
    }

    #[test]
    fn a_slow_call_does_not_delay_a_fast_one() {
        let f = fake();
        f.delay("web.crawl_and_index", 400);
        let started = Instant::now();
        let out = run(&format!("{}\n{LIST}\n", crawl("slow")), &f);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0]["id"], "a", "the fast call finished first even though it was sent second");
        assert_eq!(out[1]["id"], "slow");
        assert!(started.elapsed() >= Duration::from_millis(400));
    }

    #[test]
    fn calls_beyond_the_in_flight_cap_are_refused_immediately_not_queued() {
        let f = fake();
        f.delay("web.crawl_and_index", 400);
        let cfg = ConnConfig { max_in_flight: 1, ..ConnConfig::default() };
        let out = run_with(&cfg, &format!("{}\n{}\n", crawl("first"), crawl("second")), &f);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0]["id"], "second", "refused at once while the first is still running");
        assert_eq!(out[0]["error"]["code"], code::RATE_LIMITED);
        assert_eq!(out[0]["error"]["data"]["retryable"], true);
        assert_eq!(out[1]["id"], "first");
        assert!(out[1].get("result").is_some(), "the admitted call still completes");
    }

    #[test]
    fn end_of_input_waits_for_in_flight_calls_and_still_answers_them() {
        let f = fake();
        f.delay("web.crawl_and_index", 200);
        let out = run(&format!("{}\n", crawl("late")), &f);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["id"], "late");
    }

    #[test]
    fn a_dead_peer_ends_the_connection_without_hanging_or_panicking() {
        let input: String = (0..50).map(|_| format!("{LIST}\n")).collect();
        let result = serve_connection(Cursor::new(input.into_bytes()), BrokenPipe, Peer::Engine, &bus(), &fake(), &ConnConfig::default());
        assert!(result.is_ok());
    }

    #[test]
    fn the_connection_serves_the_engine_only_so_other_callers_get_method_not_found() {
        let sink = Sink::default();
        serve_connection(Cursor::new(format!("{}\n", crawl("x")).into_bytes()), sink.clone(), Peer::Gateway, &bus(), &fake(), &ConnConfig::default()).unwrap();
        let text = String::from_utf8(lock(&sink.0).clone()).unwrap();
        let reply: Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(reply["error"]["code"], code::METHOD_NOT_FOUND);
    }
}
