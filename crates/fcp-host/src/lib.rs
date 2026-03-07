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

mod batch;
mod budget;
mod cancellation;
mod discovery;
mod doctor;
mod error;
mod progress;
mod resilience;
mod rollout;
mod supply_chain;

pub use batch::*;
pub use budget::*;
pub use cancellation::*;
pub use discovery::*;
pub use doctor::*;
pub use error::*;
pub use progress::*;
pub use resilience::*;
pub use rollout::*;
pub use supply_chain::*;
