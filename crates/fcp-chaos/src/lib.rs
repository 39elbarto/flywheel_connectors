//! Staging-only chaos scenario harness.
//!
//! The crate is intentionally small in this phase: it parses declarative
//! scenario TOML, refuses production initialization, enforces declared blast
//! radius, and records rollback execution in the returned outcome.

#![forbid(unsafe_code)]

pub mod dsl;
pub mod injector;
pub mod scenarios;

pub use dsl::{ChaosScenario, DslError, RollbackStep};
pub use injector::{ChaosError, ChaosInjector, ChaosOutcome, ChaosStatus, Env, run_scenario};
