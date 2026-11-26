# AETHER

A self-hosted, no-third-party-API autonomous AI platform. This repository currently holds the
wire contracts (`proto/`) and Layer 4, the nervous system between the model and its tools.

| Path | What it is | Status |
|---|---|---|
| `proto/` | AFRAME binary framing spec, JSON Schemas for every wire message, a 271-case conformance corpus | complete |
| `mcp-bridge/crates/jsonrpc` | Strict JSON-RPC 2.0 over NDJSON | written, tests included |
| `mcp-bridge/crates/toolbus` | Schema validation, routing, SSRF policy, per-turn budgets, hash-chained audit log, tool catalogue, socket server, `aether-toolbus` binary | written, tests included |
| sandbox runner, gateway, crawler, engine, UI | not started | |

**None of the Rust has been compiled by its author.** It was written without a toolchain and
checked by review plus Python ports run against the same test cases; expect to fix a few compile
errors on first build and report them.

## Run the tests

Linux, macOS, or WSL2 on Windows. Rust is pinned to 1.85.0 by `rust-toolchain.toml`; `rustup`
installs it automatically. The first build downloads dependencies, so it needs network access.

    cargo test --workspace

Expected on Linux: `aether-jsonrpc` 65 unit tests and 1 doctest; `aether-toolbus` 123 unit tests
and 2 integration tests. Native Windows (MSVC) builds both crates but skips the Unix-socket tests.

For offline builds, run `scripts/vendor.sh` once while online.

## Try the toolbus by hand

    cargo run -q -p aether-toolbus -- --stdio --run-dir /tmp/aether-run --audit-log /tmp/aether-audit.jsonl

then type one JSON-RPC request per line, for example:

    {"jsonrpc":"2.0","id":"1","method":"bus.list_tools","params":{"_meta":{"trace_id":"tr_1"}}}

Tool calls need a turn deadline in `_meta` (`deadline_unix_ms`, milliseconds since the epoch,
in the future). A crawl of a private address is refused by policy; a crawl of a public one
returns "unavailable" until a crawler is listening in the run directory. Sandbox execution is
disabled until the sandbox runner exists.

Without `--stdio`, the binary listens on `<run-dir>/toolbus.sock` (directory mode 0700).

## Known gaps

* No `SO_PEERCRED` check on sockets (needs `unsafe` or an extra crate); the 0700 run directory
  and 0600 socket stop other users, not other processes of the same user.
* The SSRF filter checks literal hosts only. The crawler must re-check resolved addresses at
  connect time using `aether_toolbus::is_public_ip`.
* The audit chain proves internal consistency, not authenticity; copy the latest hash somewhere
  the writer cannot modify.
