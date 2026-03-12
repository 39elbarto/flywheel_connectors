//! FCP Host - Node Gateway/Orchestrator for the Flywheel Connector Protocol
//!
//! This crate implements the host/orchestrator that:
//! - Supervises connector binaries in sandboxes
//! - Exposes an agent-facing API (local or mesh-facing)
//! - Delegates enforcement decisions to the `MeshNode` + policy engine
//! - Manages lifecycle (install/verify, configure, health, restart)
//!
//! Based on FCP Specification Section 10 (Gateway Architecture) and
//! bead `flywheel_connectors-oip0`.

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

mod admin_state;
mod batch;
mod budget;
mod cancellation;
mod discovery;
mod doctor;
mod enforcement;
mod error;
mod health;
mod progress;
mod redaction;
mod resilience;
mod rollout;
mod supervisor;
mod supply_chain;

pub use admin_state::*;
pub use batch::*;
pub use budget::*;
pub use cancellation::*;
pub use discovery::*;
pub use doctor::*;
pub use enforcement::*;
pub use error::*;
pub use health::*;
pub use progress::*;
pub use redaction::*;
pub use resilience::*;
pub use rollout::*;
pub use supervisor::*;
pub use supply_chain::*;
