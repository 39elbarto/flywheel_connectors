//! FCP Core - legacy compatibility barrel for shared FCP primitives and
//! not-yet-carved platform semantics.
//!
//! During the FCP3 split, the semantic owner crates are `fcp-kernel`,
//! `fcp-policy`, and `fcp-evidence`, but many of their type definitions still
//! physically live here and are re-exported outward. The long-term goal is for
//! `fcp-core` to shrink to a narrow shared-primitive surface.
//!
//! See `docs/FCP3_Semantic_Ownership_Inventory.md` for the current residue map.

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

mod audit;
mod capability;
mod checkpoint;
mod connector;
mod connector_artifacts;
mod connector_descriptors;
mod connector_state;
mod crdt;
mod credential;
mod enforcement;
mod enrollment;
mod error;
mod event;
mod health;
mod lease;
mod lifecycle;
mod object;
mod operation;
pub mod pcs;
mod policy;
mod posture;
mod protocol;
mod provenance;
mod provisioning;
mod quorum;
mod ratelimit;
mod release;
mod revocation;
mod secret;
mod supply_chain;
mod telemetry;
pub mod tool_schema;
pub mod util;
mod zone_keys;

// Legacy wildcard barrel during the FCP3 carve-out. New semantic ownership
// should be assigned to the split owner crates, not added here by default.
pub use audit::*;
pub use capability::*;
pub use checkpoint::*;
pub use connector::*;
pub use connector_artifacts::*;
pub use connector_descriptors::*;
pub use connector_state::*;
pub use crdt::*;
pub use credential::*;
pub use enforcement::*;
pub use enrollment::*;
pub use error::*;
pub use event::*;
pub use health::*;
pub use lease::*;
pub use lifecycle::*;
pub use object::*;
pub use operation::*;
pub use policy::*;
pub use posture::*;
pub use protocol::*;
pub use provenance::*;
pub use provisioning::*;
pub use quorum::*;
pub use ratelimit::*;
pub use release::*;
pub use revocation::*;
pub use secret::*;
pub use supply_chain::*;
pub use telemetry::*;
pub use zone_keys::*;

// Re-export commonly used external types
pub use async_trait::async_trait;
pub use chrono::{DateTime, Utc};
pub use uuid::Uuid;
