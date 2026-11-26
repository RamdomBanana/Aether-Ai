//! Wiring for the `aether-toolbus` binary: options in, running service out.

use std::fs::DirBuilder;
use std::os::unix::fs::DirBuilderExt;
use std::sync::atomic::AtomicBool;

use aether_jsonrpc::Limits;

use crate::audit::AuditLog;
use crate::cli::{self, Options, Parsed};
use crate::conn::{serve_connection, ConnConfig};
use crate::dispatch::{SystemClock, Toolbus, ToolbusConfig};
use crate::net::{bind_socket, prepare_run_dir, serve, ForwardingBackends};
use crate::policy::Policy;
use crate::registry::Peer;
use crate::sandbox::DisabledSandbox;
use crate::tools::list_tools;

/// Runs the binary and returns its exit code: `0` success, `1` startup or runtime failure,
/// `2` bad arguments.
pub fn run(args: Vec<String>) -> i32 {
    let env = |key: &str| std::env::var(key).ok();
    let options = match cli::parse(&args, &env) {
        Ok(Parsed::Run(options)) => options,
        Ok(Parsed::Help) => {
            println!("{}", cli::USAGE);
            return 0;
        }
        Err(message) => {
            eprintln!("aether-toolbus: {message}\n\n{}", cli::USAGE);
            return 2;
        }
    };
    match start(&options) {
        Ok(()) => 0,
        Err(message) => {
            eprintln!("aether-toolbus: {message}");
            1
        }
    }
}

fn start(options: &Options) -> Result<(), String> {
    let mut ports = Policy::default().allowed_ports;
    ports.extend(&options.extra_ports);
    ports.sort_unstable();
    ports.dedup();
    let policy = Policy { allowed_ports: ports, allowed_hosts: options.allow_hosts.clone(), allow_browser_render: options.browser_render, ..Policy::default() };
    let config = ToolbusConfig { policy, ..ToolbusConfig::default() };

    if let Some(parent) = options.audit_log.parent().filter(|p| !p.as_os_str().is_empty()) {
        DirBuilder::new().recursive(true).mode(0o700).create(parent).map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    let audit = AuditLog::open_file(&options.audit_log, options.fsync).map_err(|e| format!("audit log {}: {e}", options.audit_log.display()))?;
    eprintln!("aether-toolbus: audit log {} verified, {} records", options.audit_log.display(), audit.last_seq());

    let bus = Toolbus::from_embedded(config, audit, Box::new(SystemClock))?;
    let tools = list_tools(bus.schemas(), bus.registry())?;
    let limits = Limits::default();
    let backends = ForwardingBackends::new(options.run_dir.clone(), bus.registry(), tools, Box::new(DisabledSandbox), limits)?;
    let conn = ConnConfig { limits, ..ConnConfig::default() };

    if options.stdio {
        eprintln!("aether-toolbus: serving one connection on stdin/stdout as the engine; sandbox execution is disabled");
        let stdin = std::io::stdin();
        return serve_connection(stdin.lock(), std::io::stdout(), Peer::Engine, &bus, &backends, &conn).map_err(|e| format!("stdio: {e}"));
    }

    prepare_run_dir(&options.run_dir).map_err(|e| format!("run directory {}: {e}", options.run_dir.display()))?;
    let socket_name = bus.registry().server(Peer::Toolbus).map(|s| s.socket.clone()).ok_or("the toolbus socket is not declared in the schemas")?;
    let socket_path = options.run_dir.join(socket_name);
    let listener = bind_socket(&socket_path).map_err(|e| format!("socket {}: {e}", socket_path.display()))?;
    eprintln!("aether-toolbus: listening on {}; sandbox execution is disabled", socket_path.display());
    // The process runs until it is signalled. Nothing needs flushing on exit: every audit record
    // is written (and by default synced) before the call it describes proceeds.
    let stop = AtomicBool::new(false);
    serve(&listener, &bus, &backends, Peer::Engine, &conn, options.max_connections, &stop).map_err(|e| format!("accept loop: {e}"))
}
