//! Unix-domain-socket transport: serving the engine, calling the crawler and learn daemons,
//! and the checks around the run directory.
//!
//! **Access control.** The run directory must be mode `0700` and owned by the running user, and
//! the socket is set to `0600`, so only that user (and root) can reach it. The kernel-level
//! `SO_PEERCRED` check that `proto/aframe.md` requires of `engine.sock` is *not* performed here:
//! the standard library has no stable API for it, and adding it would need `unsafe` code
//! (forbidden in this workspace) or a dependency whose API I could not verify offline. The
//! directory checks stop other users; they do not stop another process of the same user.
//! Closing that gap is a recorded follow-up, not something to rely on being done.
//!
//! **Upstream calls.** One short-lived connection per call keeps correlation trivial and a stuck
//! upstream from affecting any other call. Tool calls are rare (a handful per turn), so connection
//! setup cost is irrelevant. Every wait is bounded by the call's deadline.

use std::collections::HashMap;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use aether_jsonrpc::{encode_line, parse_line, Id, Incoming, Limits, Message, NdjsonDecoder, Params, Request, Response, RpcError};
use serde_json::{Map, Value};

use crate::conn::{serve_connection, ConnConfig};
use crate::dispatch::{Backends, Toolbus};
use crate::registry::{Peer, Registry};
use crate::sandbox::SandboxRunner;

/// `true` if neither group nor others have any access.
pub(crate) fn mode_is_private(mode: u32) -> bool {
    mode & 0o077 == 0
}

/// Whether files created by this process in `dir` belong to the same owner as `dir`.
/// Done by creating and removing a probe file, which needs no `unsafe` and no extra crate.
fn owned_by_current_user(dir: &Path, dir_uid: u32) -> io::Result<bool> {
    let probe = dir.join(format!(".owner-probe-{}", std::process::id()));
    let file = OpenOptions::new().write(true).create_new(true).open(&probe)?;
    let uid = file.metadata()?.uid();
    drop(file);
    fs::remove_file(&probe)?;
    Ok(uid == dir_uid)
}

/// Creates the run directory with mode `0700`, or checks that an existing one is private and
/// owned by the current user. Refuses anything else.
pub fn prepare_run_dir(dir: &Path) -> io::Result<()> {
    match fs::metadata(dir) {
        Ok(meta) => {
            if !meta.is_dir() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "the run directory path is not a directory"));
            }
            if !mode_is_private(meta.permissions().mode()) {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "the run directory must not be accessible to group or others; run chmod 700 on it"));
            }
            if !owned_by_current_user(dir, meta.uid())? {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "the run directory is owned by another user"));
            }
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => DirBuilder::new().recursive(true).mode(0o700).create(dir),
        Err(e) => Err(e),
    }
}

/// Binds a listening socket at `path` with mode `0600`.
///
/// A stale socket file (no one listening) is replaced; a live one is refused so two toolbus
/// instances cannot fight over the same path; anything that is not a socket is left alone.
pub fn bind_socket(path: &Path) -> io::Result<UnixListener> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if !meta.file_type().is_socket() {
                return Err(io::Error::new(io::ErrorKind::AlreadyExists, "a file that is not a socket is in the way"));
            }
            if UnixStream::connect(path).is_ok() {
                return Err(io::Error::new(io::ErrorKind::AddrInUse, "another toolbus is already listening on this socket"));
            }
            fs::remove_file(path)?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    // Between bind and chmod the socket has umask-derived permissions; the 0700 run directory
    // is what keeps that window harmless.
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Accepts connections until `stop` is set, serving each on its own thread.
///
/// Connections beyond `max_connections` are closed at once. After `stop` is set the function
/// waits for open connections to end; they end when their peers disconnect.
pub fn serve(
    listener: &UnixListener,
    bus: &Toolbus,
    backends: &(dyn Backends + Sync),
    caller: Peer,
    cfg: &ConnConfig,
    max_connections: usize,
    stop: &AtomicBool,
) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    let active = AtomicUsize::new(0);
    std::thread::scope(|scope| -> io::Result<()> {
        while !stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    if active.fetch_add(1, Ordering::SeqCst) >= max_connections {
                        active.fetch_sub(1, Ordering::SeqCst);
                        continue; // dropping the stream closes it
                    }
                    // Accepted sockets may inherit the listener's non-blocking mode on some platforms.
                    let reader = match stream.set_nonblocking(false).and_then(|()| stream.try_clone()) {
                        Ok(clone) => clone,
                        Err(_) => {
                            active.fetch_sub(1, Ordering::SeqCst);
                            continue;
                        }
                    };
                    let active_ref = &active;
                    let spawned = std::thread::Builder::new().name("toolbus-conn".to_owned()).spawn_scoped(scope, move || {
                        let _ = serve_connection(reader, stream, caller, bus, backends, cfg);
                        active_ref.fetch_sub(1, Ordering::SeqCst);
                    });
                    if spawned.is_err() {
                        active.fetch_sub(1, Ordering::SeqCst);
                    }
                }
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock) => std::thread::sleep(Duration::from_millis(25)),
                Err(e) if matches!(e.kind(), io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    })
}

/// Calls another server over NDJSON on a Unix socket.
pub struct UdsClient {
    limits: Limits,
    counter: AtomicU64,
}

impl UdsClient {
    /// Creates a client that bounds upstream replies by `limits`.
    pub fn new(limits: Limits) -> Self {
        UdsClient { limits, counter: AtomicU64::new(1) }
    }

    /// Sends one request and waits at most `wait_ms` for its reply.
    ///
    /// Upstream failures map to `-32003 Unavailable` (could not connect, closed, unreadable),
    /// `-32001 Timeout` (no reply in time) and `-32603 Internal` (malformed or oversized reply).
    /// An upstream error object is returned as-is; the dispatch pipeline sanitises it.
    pub fn call(&self, socket: &Path, method: &str, params: Params, wait_ms: u64) -> Result<Map<String, Value>, RpcError> {
        let started = Instant::now();
        let budget = Duration::from_millis(wait_ms.max(1));
        let unavailable = |why: &str| RpcError::unavailable(format!("upstream unavailable: {why}"));
        let timed_out = || RpcError::timeout("upstream did not answer in time");

        let mut stream = UnixStream::connect(socket).map_err(|_| unavailable("cannot connect"))?;
        let id = Id::Str(format!("tb-{}", self.counter.fetch_add(1, Ordering::Relaxed)));
        let request = Request::new(id.clone(), method, params)?;
        let line = encode_line(&request).map_err(|_| RpcError::internal("cannot encode the upstream request"))?;
        stream.set_write_timeout(Some(budget)).map_err(|_| unavailable("socket setup failed"))?;
        stream.write_all(&line).map_err(|_| unavailable("write failed"))?;

        let mut decoder = NdjsonDecoder::with_limits(&self.limits);
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            let Some(left) = budget.checked_sub(started.elapsed()).filter(|d| !d.is_zero()) else {
                return Err(timed_out());
            };
            stream.set_read_timeout(Some(left)).map_err(|_| unavailable("socket setup failed"))?;
            let read = match stream.read(&mut chunk) {
                Ok(0) => return Err(unavailable("connection closed before a reply")),
                Ok(n) => n,
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => return Err(timed_out()),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(unavailable("read failed")),
            };
            decoder.push(&chunk[..read]);
            while let Some(framed) = decoder.next_line() {
                let line = framed.map_err(|_| RpcError::internal("upstream reply too large").with_data("reason", "upstream_reply_too_large"))?;
                match parse_line(&line, &self.limits) {
                    Incoming::Single(Ok(Message::Response(response))) => {
                        // An error with a null id answers a request the upstream could not even parse; ours is the only one in flight.
                        let ours = response.id() == Some(&id) || matches!(&response, Response::Error(e) if e.id.is_none());
                        if !ours {
                            continue;
                        }
                        return match response {
                            Response::Success(success) => Ok(success.result),
                            Response::Error(error) => Err(error.error),
                        };
                    }
                    _ => return Err(RpcError::internal("upstream sent an unexpected message").with_data("reason", "upstream_protocol_error")),
                }
            }
        }
    }
}

/// The real [`Backends`]: forwards to the crawler and learn sockets, answers `bus.list_tools`
/// from a catalogue built at startup, and hands sandbox calls to a [`SandboxRunner`].
pub struct ForwardingBackends {
    run_dir: PathBuf,
    sockets: HashMap<Peer, String>,
    client: UdsClient,
    tools: Map<String, Value>,
    sandbox: Box<dyn SandboxRunner>,
}

impl ForwardingBackends {
    /// Builds the backends, checking that each downstream server is declared and speaks NDJSON.
    pub fn new(run_dir: PathBuf, registry: &Registry, tools: Map<String, Value>, sandbox: Box<dyn SandboxRunner>, limits: Limits) -> Result<Self, String> {
        let mut sockets = HashMap::new();
        for peer in [Peer::Crawler, Peer::Learn] {
            let info = registry.server(peer).ok_or_else(|| format!("no socket is declared for {peer}"))?;
            if !info.ndjson {
                return Err(format!("{peer} must speak NDJSON"));
            }
            if info.socket.is_empty() || info.socket.contains('/') || info.socket.contains("..") {
                return Err(format!("the socket name for {peer} is not a plain file name"));
            }
            sockets.insert(peer, info.socket.clone());
        }
        Ok(ForwardingBackends { run_dir, sockets, client: UdsClient::new(limits), tools, sandbox })
    }
}

impl Backends for ForwardingBackends {
    fn forward(&self, server: Peer, method: &str, params: Params, wait_ms: u64) -> Result<Map<String, Value>, RpcError> {
        let Some(name) = self.sockets.get(&server) else {
            return Err(RpcError::internal("no socket is configured for that server"));
        };
        self.client.call(&self.run_dir.join(name), method, params, wait_ms)
    }

    fn local(&self, method: &str, params: Params, wait_ms: u64) -> Result<Map<String, Value>, RpcError> {
        match method {
            "bus.list_tools" => Ok(self.tools.clone()),
            "sandbox.execute_python" => self.sandbox.run(params, wait_ms),
            _ => Err(RpcError::method_not_found(method)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::SharedBuffer;
    use crate::audit::{verify_chain, AuditLog, GENESIS_HASH};
    use crate::dispatch::{Clock, SystemClock, ToolbusConfig};
    use crate::sandbox::DisabledSandbox;
    use crate::tools::list_tools;
    use aether_jsonrpc::code;
    use serde_json::json;
    use std::io::BufRead;

    /// A scratch directory removed on drop, even if the test panics. Names stay short because
    /// Unix socket paths are limited to roughly 104 bytes.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> TempDir {
            let path = std::env::temp_dir().join(format!("tb{}-{name}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            TempDir(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn read_request(stream: &UnixStream) -> Value {
        let mut line = String::new();
        io::BufReader::new(stream).read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }

    fn reply(mut stream: &UnixStream, value: Value) {
        writeln!(stream, "{value}").unwrap();
    }

    fn params(v: Value) -> Params {
        v.as_object().unwrap().clone()
    }

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn privacy_of_modes() {
        for (mode, private) in [(0o700, true), (0o600, true), (0o400, true), (0o710, false), (0o707, false), (0o770, false), (0o750, false), (0o755, false), (0o701, false)] {
            assert_eq!(mode_is_private(mode), private, "{mode:o}");
        }
        assert!(mode_is_private(0o40700), "file-type bits are ignored");
    }

    #[test]
    fn the_run_dir_is_created_private_and_accepted_when_it_exists() {
        let tmp = TempDir::new("rd1");
        let dir = tmp.path().join("a").join("run");
        prepare_run_dir(&dir).unwrap();
        assert_eq!(mode_of(&dir), 0o700);
        prepare_run_dir(&dir).unwrap();
        assert!(fs::read_dir(&dir).unwrap().next().is_none(), "the ownership probe leaves nothing behind");
    }

    #[test]
    fn a_run_dir_open_to_others_or_not_a_directory_is_refused() {
        let tmp = TempDir::new("rd2");
        fs::create_dir_all(tmp.path()).unwrap();
        let open = tmp.path().join("open");
        fs::create_dir(&open).unwrap();
        fs::set_permissions(&open, fs::Permissions::from_mode(0o770)).unwrap();
        assert_eq!(prepare_run_dir(&open).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        let file = tmp.path().join("file");
        fs::write(&file, b"x").unwrap();
        assert_eq!(prepare_run_dir(&file).unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn sockets_are_private_stale_ones_are_replaced_and_live_ones_are_respected() {
        let tmp = TempDir::new("bs");
        prepare_run_dir(tmp.path()).unwrap();
        let path = tmp.path().join("t.sock");
        let first = bind_socket(&path).unwrap();
        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(bind_socket(&path).err().unwrap().kind(), io::ErrorKind::AddrInUse, "a live listener is not stolen");
        drop(first); // the socket file stays behind, with no one listening
        assert!(fs::symlink_metadata(&path).is_ok());
        let second = bind_socket(&path).expect("a stale socket file is replaced");
        drop(second);
        let plain = tmp.path().join("plain");
        fs::write(&plain, b"not a socket").unwrap();
        assert_eq!(bind_socket(&plain).err().unwrap().kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&plain).unwrap(), b"not a socket", "a file that is not ours is never deleted");
    }

    fn serve_once<F: FnOnce(UnixStream) + Send + 'static>(path: &Path, handler: F) -> std::thread::JoinHandle<()> {
        let listener = bind_socket(path).unwrap();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handler(stream);
        })
    }

    fn client_call(socket: &Path, wait_ms: u64) -> Result<Map<String, Value>, RpcError> {
        UdsClient::new(Limits::default()).call(socket, "memory.hybrid_search", params(json!({"query": "x", "_meta": {"trace_id": "tr_1"}})), wait_ms)
    }

    #[test]
    fn a_reply_is_matched_by_id_and_stray_replies_are_ignored() {
        let tmp = TempDir::new("c1");
        prepare_run_dir(tmp.path()).unwrap();
        let sock = tmp.path().join("s.sock");
        let server = serve_once(&sock, |stream| {
            let req = read_request(&stream);
            assert_eq!(req["method"], "memory.hybrid_search");
            reply(&stream, json!({"jsonrpc": "2.0", "id": "someone-else", "result": {"wrong": true}}));
            reply(&stream, json!({"jsonrpc": "2.0", "id": req["id"], "result": {"ok": true}}));
        });
        assert_eq!(client_call(&sock, 2_000).unwrap()["ok"], true);
        server.join().unwrap();
    }

    #[test]
    fn upstream_error_objects_are_returned_for_the_pipeline_to_sanitise() {
        let tmp = TempDir::new("c2");
        prepare_run_dir(tmp.path()).unwrap();
        let sock = tmp.path().join("s.sock");
        let server = serve_once(&sock, |stream| {
            let req = read_request(&stream);
            reply(&stream, json!({"jsonrpc": "2.0", "id": req["id"], "error": {"code": -32008, "message": "no such document"}}));
        });
        let err = client_call(&sock, 2_000).unwrap_err();
        assert_eq!((err.code, err.message.as_str()), (code::NOT_FOUND, "no such document"));
        server.join().unwrap();
    }

    #[test]
    fn a_null_id_error_from_upstream_answers_our_request() {
        let tmp = TempDir::new("c3");
        prepare_run_dir(tmp.path()).unwrap();
        let sock = tmp.path().join("s.sock");
        let server = serve_once(&sock, |stream| {
            let _ = read_request(&stream);
            reply(&stream, json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "Parse error"}}));
        });
        assert_eq!(client_call(&sock, 2_000).unwrap_err().code, code::PARSE_ERROR);
        server.join().unwrap();
    }

    #[test]
    fn a_silent_upstream_times_out_within_the_budget() {
        let tmp = TempDir::new("c4");
        prepare_run_dir(tmp.path()).unwrap();
        let sock = tmp.path().join("s.sock");
        let server = serve_once(&sock, |stream| {
            let _ = read_request(&stream);
            std::thread::sleep(Duration::from_millis(500));
        });
        let started = Instant::now();
        let err = client_call(&sock, 120).unwrap_err();
        assert_eq!(err.code, code::TIMEOUT);
        assert!(started.elapsed() < Duration::from_millis(450), "gave up at the budget, not when the server finished");
        server.join().unwrap();
    }

    #[test]
    fn unreachable_or_hanging_up_upstreams_are_unavailable() {
        let tmp = TempDir::new("c5");
        prepare_run_dir(tmp.path()).unwrap();
        assert_eq!(client_call(&tmp.path().join("missing.sock"), 500).unwrap_err().code, code::UNAVAILABLE);
        let sock = tmp.path().join("s.sock");
        let server = serve_once(&sock, |stream| {
            let _ = read_request(&stream);
            drop(stream);
        });
        let err = client_call(&sock, 2_000).unwrap_err();
        assert_eq!(err.code, code::UNAVAILABLE);
        assert_eq!(err.data.as_ref().unwrap()["retryable"], true);
        server.join().unwrap();
    }

    #[test]
    fn oversized_and_malformed_upstream_replies_are_internal_errors() {
        let tmp = TempDir::new("c6");
        prepare_run_dir(tmp.path()).unwrap();
        let sock = tmp.path().join("s.sock");
        let server = serve_once(&sock, |stream| {
            let req = read_request(&stream);
            reply(&stream, json!({"jsonrpc": "2.0", "id": req["id"], "result": {"blob": "x".repeat(2_000)}}));
        });
        let small = Limits { max_line_bytes: 200, ..Limits::default() };
        let err = UdsClient::new(small).call(&sock, "memory.hybrid_search", params(json!({"query": "x", "_meta": {"trace_id": "tr_1"}})), 2_000).unwrap_err();
        assert_eq!((err.code, err.data.as_ref().unwrap()["reason"].clone()), (code::INTERNAL_ERROR, json!("upstream_reply_too_large")));
        server.join().unwrap();

        let sock2 = tmp.path().join("s2.sock");
        let server2 = serve_once(&sock2, |stream| {
            let _ = read_request(&stream);
            reply(&stream, json!({"jsonrpc": "2.0", "id": 1, "method": "x.y", "params": {}}));
        });
        let err = client_call(&sock2, 2_000).unwrap_err();
        assert_eq!((err.code, err.data.as_ref().unwrap()["reason"].clone()), (code::INTERNAL_ERROR, json!("upstream_protocol_error")));
        server2.join().unwrap();
    }

    fn real_bus(audit: &SharedBuffer) -> Toolbus {
        let log = AuditLog::new(Box::new(audit.clone()), 0, GENESIS_HASH.to_owned());
        Toolbus::from_embedded(ToolbusConfig::default(), log, Box::new(SystemClock)).unwrap()
    }

    fn backends_for(dir: &Path, bus: &Toolbus) -> ForwardingBackends {
        let tools = list_tools(bus.schemas(), bus.registry()).unwrap();
        ForwardingBackends::new(dir.to_path_buf(), bus.registry(), tools, Box::new(DisabledSandbox), Limits::default()).unwrap()
    }

    #[test]
    fn local_methods_and_unreachable_servers_through_the_forwarding_backends() {
        let tmp = TempDir::new("fb");
        prepare_run_dir(tmp.path()).unwrap();
        let bus = real_bus(&SharedBuffer::default());
        let backends = backends_for(tmp.path(), &bus);
        assert_eq!(backends.local("bus.list_tools", Params::new(), 1_000).unwrap()["tools"].as_array().unwrap().len(), 4);
        assert_eq!(backends.local("sandbox.execute_python", Params::new(), 1_000).unwrap_err().code, code::POLICY_DENIED);
        assert_eq!(backends.local("web.crawl_and_index", Params::new(), 1_000).unwrap_err().code, code::METHOD_NOT_FOUND);
        let err = backends.forward(Peer::Crawler, "memory.hybrid_search", params(json!({"query": "x", "_meta": {"trace_id": "tr_1"}})), 500).unwrap_err();
        assert_eq!(err.code, code::UNAVAILABLE, "no crawler.sock exists in this directory");
        assert_eq!(backends.forward(Peer::Gateway, "x.y", Params::new(), 500).unwrap_err().code, code::INTERNAL_ERROR);
    }

    fn deadline() -> u64 {
        SystemClock.now_ms() + 60_000
    }

    #[test]
    fn end_to_end_over_real_sockets_with_a_fake_crawler() {
        let tmp = TempDir::new("e2e");
        prepare_run_dir(tmp.path()).unwrap();
        let crawler = serve_once(&tmp.path().join("crawler.sock"), |stream| {
            let req = read_request(&stream);
            assert_eq!(req["method"], "web.crawl_and_index");
            assert!(req["params"]["timeout_ms"].as_u64().unwrap() <= 20_000, "toolbus made the timeout explicit");
            reply(
                &stream,
                json!({"jsonrpc": "2.0", "id": req["id"], "result": {"job_id": "j_81", "state": "complete", "pages": [], "stats": {"fetched": 1, "indexed": 1, "skipped": 0, "took_ms": 5}}}),
            );
        });

        let audit = SharedBuffer::default();
        let bus = real_bus(&audit);
        let backends = backends_for(tmp.path(), &bus);
        let listener = bind_socket(&tmp.path().join("toolbus.sock")).unwrap();
        let stop = AtomicBool::new(false);
        let cfg = ConnConfig::default();

        std::thread::scope(|scope| {
            scope.spawn(|| serve(&listener, &bus, &backends, Peer::Engine, &cfg, 4, &stop).unwrap());
            {
                let mut client = UnixStream::connect(tmp.path().join("toolbus.sock")).unwrap();
                let mut lines = io::BufReader::new(client.try_clone().unwrap());
                let mut ask = |request: Value| -> Value {
                    writeln!(client, "{request}").unwrap();
                    let mut line = String::new();
                    lines.read_line(&mut line).unwrap();
                    serde_json::from_str(&line).unwrap()
                };

                let tools = ask(json!({"jsonrpc": "2.0", "id": 1, "method": "bus.list_tools", "params": {"_meta": {"trace_id": "tr_1"}}}));
                assert_eq!(tools["result"]["tools"].as_array().unwrap().len(), 4);

                let crawl = ask(json!({"jsonrpc": "2.0", "id": 2, "method": "web.crawl_and_index",
                    "params": {"urls": ["https://example.org/post"], "_meta": {"trace_id": "tr_1", "session_id": "s_1", "turn_id": "t_1", "deadline_unix_ms": deadline()}}}));
                assert_eq!(crawl["result"]["job_id"], "j_81");

                let ssrf = ask(json!({"jsonrpc": "2.0", "id": 3, "method": "web.crawl_and_index",
                    "params": {"urls": ["http://169.254.169.254/latest/meta-data/"], "_meta": {"trace_id": "tr_1", "session_id": "s_1", "turn_id": "t_1", "deadline_unix_ms": deadline()}}}));
                assert_eq!(ssrf["error"]["code"], code::POLICY_DENIED);

                let sandbox = ask(json!({"jsonrpc": "2.0", "id": 4, "method": "sandbox.execute_python",
                    "params": {"code": "print(1)", "_meta": {"trace_id": "tr_1", "session_id": "s_1", "turn_id": "t_1", "deadline_unix_ms": deadline()}}}));
                assert_eq!(sandbox["error"]["data"]["reason"], "sandbox_disabled");
            }
            stop.store(true, Ordering::SeqCst);
        });
        crawler.join().unwrap();

        let summary = verify_chain(audit.text().as_bytes()).unwrap();
        assert_eq!(summary.records, 7, "list_tools 2 + crawl 2 + ssrf 1 + sandbox 2");
        assert!(audit.text().contains("169.254.169.254"), "the refused target is on record");
    }
}
