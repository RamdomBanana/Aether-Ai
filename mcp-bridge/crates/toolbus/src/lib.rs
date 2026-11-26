//! AETHER toolbus core.
//!
//! The toolbus sits between the inference engine and everything the model can *do*. A model
//! that has read attacker-controlled web text is not a trusted caller, so this crate treats
//! every tool call as hostile input and decides, in this order, whether it may run:
//!
//! 1. [`registry`]: is this method real, and is this caller a peer for it?
//! 2. [`schema`]: do the params satisfy the wire schema in `proto/schemas`, exactly?
//! 3. [`policy`]: SSRF filtering, sandbox input limits, evidence rules.
//! 4. [`budget`]: per-turn call, page and invalid-call budgets, and a deadline that cannot
//!    be extended.
//! 5. [`audit`]: a hash-chained record written *before* anything executes.
//!
//! [`dispatch::Toolbus`] runs that pipeline and then hands the call to a [`Backends`]
//! implementation, validates what comes back, and records the outcome.
//!
//! [`conn`] is the transport-independent read/dispatch/write loop; [`net`] (Unix only) adds
//! the socket server, the upstream client and the run-directory checks; [`tools`] builds the
//! tool catalogue the model sees; [`sandbox`] is the seam for the sandbox runner (disabled until
//! one exists); [`cli`] and [`app`] are the `aether-toolbus` binary. Everything except `net` and
//! `app` also builds and tests on Windows.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod audit;
pub mod budget;
pub mod cli;
pub mod conn;
pub mod dispatch;
pub mod embedded;
pub mod policy;
pub mod registry;
pub mod sandbox;
pub mod schema;
pub mod tools;

#[cfg(unix)]
pub mod app;
#[cfg(unix)]
pub mod net;

pub use audit::{verify_chain, AuditLog, FileSink};
pub use budget::{BudgetConfig, TurnKey};
pub use conn::{serve_connection, ConnConfig};
pub use dispatch::{Backends, Clock, SystemClock, Toolbus, ToolbusConfig};
pub use policy::{is_public_ip, Policy};
pub use registry::{Peer, Registry, Target};
pub use schema::{SchemaRef, SchemaSet, Violation};
