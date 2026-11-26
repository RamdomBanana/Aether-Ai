//! Command-line options for the `aether-toolbus` binary.
//!
//! Hand-rolled so the binary has no argument-parsing dependency. Parsing is pure: environment
//! access goes through a closure, so every rule is unit-testable.

use std::path::{Path, PathBuf};

/// Usage text, printed for `--help` and after an argument error.
pub const USAGE: &str = "\
aether-toolbus: policy, budgets and audit between the model and everything it can do

USAGE:
    aether-toolbus [OPTIONS]

OPTIONS:
    --stdio                  Serve one connection on stdin/stdout, as the engine, then exit.
                             Handy for trying the bus by hand: type JSON-RPC lines.
    --run-dir DIR            Directory holding the sockets (default: $AETHER_RUN, else ~/.aether/run).
    --audit-log FILE         Tamper-evident audit log (default: $AETHER_AUDIT, else
                             ~/.aether/logs/toolbus-audit.jsonl). It is verified at startup.
    --no-fsync               Do not force each audit record to disk (faster, less durable).
    --allow-host HOST        Exempt a host or IP literal from the private-address checks. Repeatable.
    --allow-port PORT        Allow crawling this port in addition to 80, 443, 8080, 8443. Repeatable.
    --no-browser-render      Refuse render=browser (headless Chromium) crawl requests.
    --max-connections N      Most simultaneous socket connections, 1 to 64 (default 8).
    -h, --help               Show this text.
";

/// Everything the binary needs to start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// Directory containing the sockets.
    pub run_dir: PathBuf,
    /// Audit log file.
    pub audit_log: PathBuf,
    /// Serve stdin/stdout instead of a socket.
    pub stdio: bool,
    /// Force each audit record to stable storage.
    pub fsync: bool,
    /// Hosts exempt from address checks.
    pub allow_hosts: Vec<String>,
    /// Extra crawlable ports.
    pub extra_ports: Vec<u16>,
    /// Whether `render: "browser"` is permitted.
    pub browser_render: bool,
    /// Most simultaneous connections.
    pub max_connections: usize,
}

/// What the arguments asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    /// Start with these options.
    Run(Options),
    /// Print [`USAGE`] and exit successfully.
    Help,
}

fn value<'a>(args: &'a [String], index: &mut usize, flag: &str) -> Result<&'a str, String> {
    let next = args.get(*index).ok_or_else(|| format!("{flag} needs a value"))?;
    *index += 1;
    Ok(next.as_str())
}

/// Parses `args` (without the program name). `env` looks up environment variables.
pub fn parse(args: &[String], env: &dyn Fn(&str) -> Option<String>) -> Result<Parsed, String> {
    let (mut run_dir, mut audit_log) = (None, None);
    let (mut stdio, mut fsync, mut browser_render) = (false, true, true);
    let (mut allow_hosts, mut extra_ports) = (Vec::new(), Vec::new());
    let mut max_connections = 8usize;

    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        i += 1;
        match flag {
            "-h" | "--help" => return Ok(Parsed::Help),
            "--stdio" => stdio = true,
            "--no-fsync" => fsync = false,
            "--no-browser-render" => browser_render = false,
            "--run-dir" => run_dir = Some(PathBuf::from(value(args, &mut i, flag)?)),
            "--audit-log" => audit_log = Some(PathBuf::from(value(args, &mut i, flag)?)),
            "--allow-host" => {
                let host = value(args, &mut i, flag)?.to_ascii_lowercase();
                if host.is_empty() || host.contains(|c: char| c.is_whitespace() || matches!(c, '/' | '@' | '\\')) {
                    return Err(format!("--allow-host {host:?} is not a plain host name or IP literal"));
                }
                allow_hosts.push(host);
            }
            "--allow-port" => {
                let raw = value(args, &mut i, flag)?;
                match raw.parse::<u16>() {
                    Ok(port) if port != 0 => extra_ports.push(port),
                    _ => return Err(format!("--allow-port {raw:?} is not a port number from 1 to 65535")),
                }
            }
            "--max-connections" => {
                let raw = value(args, &mut i, flag)?;
                match raw.parse::<usize>() {
                    Ok(n) if (1..=64).contains(&n) => max_connections = n,
                    _ => return Err(format!("--max-connections {raw:?} must be a number from 1 to 64")),
                }
            }
            other => return Err(format!("unknown option {other:?}")),
        }
    }

    let home = env("HOME");
    let under_home = |tail: &[&str]| home.as_ref().map(|h| tail.iter().fold(Path::new(h).join(".aether"), |p, part| p.join(part)));
    let run_dir = run_dir
        .or_else(|| env("AETHER_RUN").map(PathBuf::from))
        .or_else(|| under_home(&["run"]))
        .ok_or("cannot choose a run directory: pass --run-dir or set AETHER_RUN")?;
    let audit_log = audit_log
        .or_else(|| env("AETHER_AUDIT").map(PathBuf::from))
        .or_else(|| under_home(&["logs", "toolbus-audit.jsonl"]))
        .ok_or("cannot choose an audit log path: pass --audit-log or set AETHER_AUDIT")?;

    Ok(Parsed::Run(Options { run_dir, audit_log, stdio, fsync, allow_hosts, extra_ports, browser_render, max_connections }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    fn env_home(key: &str) -> Option<String> {
        (key == "HOME").then(|| "/home/ada".to_owned())
    }

    fn no_env(_: &str) -> Option<String> {
        None
    }

    fn run(list: &[&str]) -> Options {
        match parse(&args(list), &env_home) {
            Ok(Parsed::Run(o)) => o,
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn defaults_live_under_the_home_directory() {
        let o = run(&[]);
        assert_eq!(o.run_dir, PathBuf::from("/home/ada/.aether/run"));
        assert_eq!(o.audit_log, PathBuf::from("/home/ada/.aether/logs/toolbus-audit.jsonl"));
        assert!(!o.stdio && o.fsync && o.browser_render && o.allow_hosts.is_empty() && o.extra_ports.is_empty());
        assert_eq!(o.max_connections, 8);
    }

    #[test]
    fn environment_overrides_home_and_flags_override_environment() {
        let env = |k: &str| match k {
            "HOME" => Some("/home/ada".to_owned()),
            "AETHER_RUN" => Some("/srv/run".to_owned()),
            "AETHER_AUDIT" => Some("/srv/audit.jsonl".to_owned()),
            _ => None,
        };
        match parse(&args(&[]), &env).unwrap() {
            Parsed::Run(o) => assert_eq!((o.run_dir, o.audit_log), (PathBuf::from("/srv/run"), PathBuf::from("/srv/audit.jsonl"))),
            Parsed::Help => panic!(),
        }
        match parse(&args(&["--run-dir", "/x", "--audit-log", "/y"]), &env).unwrap() {
            Parsed::Run(o) => assert_eq!((o.run_dir, o.audit_log), (PathBuf::from("/x"), PathBuf::from("/y"))),
            Parsed::Help => panic!(),
        }
    }

    #[test]
    fn every_flag_is_understood() {
        let o = run(&["--stdio", "--no-fsync", "--no-browser-render", "--allow-host", "Wiki.Corp", "--allow-host", "10.1.2.3", "--allow-port", "8000", "--allow-port", "9000", "--max-connections", "3"]);
        assert!(o.stdio && !o.fsync && !o.browser_render);
        assert_eq!(o.allow_hosts, ["wiki.corp", "10.1.2.3"], "hosts are lowercased");
        assert_eq!(o.extra_ports, [8000, 9000]);
        assert_eq!(o.max_connections, 3);
    }

    #[test]
    fn help_wins_wherever_it_appears_before_an_error() {
        assert_eq!(parse(&args(&["--help"]), &no_env), Ok(Parsed::Help));
        assert_eq!(parse(&args(&["--stdio", "-h"]), &no_env), Ok(Parsed::Help));
        assert!(USAGE.contains("--stdio") && USAGE.contains("--audit-log"));
    }

    #[test]
    fn bad_arguments_are_explained() {
        for (list, needle) in [
            (&["--bogus"][..], "unknown option"),
            (&["--run-dir"][..], "needs a value"),
            (&["--allow-port", "0"][..], "port number"),
            (&["--allow-port", "70000"][..], "port number"),
            (&["--allow-port", "http"][..], "port number"),
            (&["--max-connections", "0"][..], "1 to 64"),
            (&["--max-connections", "65"][..], "1 to 64"),
            (&["--allow-host", "a/b"][..], "plain host"),
            (&["--allow-host", "user@host"][..], "plain host"),
            (&["--allow-host", "a b"][..], "plain host"),
            (&["--allow-host", ""][..], "plain host"),
        ] {
            let err = parse(&args(list), &env_home).unwrap_err();
            assert!(err.contains(needle), "{list:?}: {err}");
        }
    }

    #[test]
    fn without_a_home_or_environment_the_user_must_choose_paths() {
        assert!(parse(&args(&[]), &no_env).unwrap_err().contains("run directory"));
        assert!(parse(&args(&["--run-dir", "/r"]), &no_env).unwrap_err().contains("audit log"));
        assert!(parse(&args(&["--run-dir", "/r", "--audit-log", "/a"]), &no_env).is_ok());
    }
}
