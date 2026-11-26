//! The seam between toolbus and the sandbox runner.
//!
//! Toolbus validates and budgets `sandbox.execute_python`, then hands the call to a
//! [`SandboxRunner`]. Until the real runner (namespaces, Landlock, seccomp, cgroups) exists,
//! [`DisabledSandbox`] refuses every call, so enabling code execution is an explicit act.

use aether_jsonrpc::{Params, RpcError};
use serde_json::{Map, Value};

/// Executes validated sandbox calls.
pub trait SandboxRunner: Send + Sync {
    /// Runs the call and returns a `SandboxExecutePythonResult` object. `wait_ms` is the hard
    /// ceiling for the whole call; the runner must enforce `params.timeout_ms` inside it.
    fn run(&self, params: Params, wait_ms: u64) -> Result<Map<String, Value>, RpcError>;
}

/// Refuses every call. The default until a real runner is installed.
pub struct DisabledSandbox;

impl SandboxRunner for DisabledSandbox {
    fn run(&self, _params: Params, _wait_ms: u64) -> Result<Map<String, Value>, RpcError> {
        // PolicyDenied, not Unavailable: Unavailable is retryable and the model would retry.
        Err(RpcError::policy_denied("sandbox_disabled"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether_jsonrpc::code;

    #[test]
    fn the_default_runner_denies_and_is_not_retryable() {
        let err = DisabledSandbox.run(Params::new(), 1_000).unwrap_err();
        assert_eq!(err.code, code::POLICY_DENIED);
        assert_eq!(err.data.as_ref().unwrap()["reason"], "sandbox_disabled");
        assert!(err.data.as_ref().unwrap().get("retryable").is_none());
    }
}
