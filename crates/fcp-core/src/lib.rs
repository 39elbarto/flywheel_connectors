//! FCP Core - Core types and traits for the Flywheel Connector Protocol
//!
//! This crate provides the foundational types, traits, and error handling for
//! FCP connectors.
//!
//! This crate is being migrated to the `FCP_Specification_V2.md` contract.

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

mod audit;
mod capability;
mod checkpoint;
mod connector;
mod connector_state;
mod crdt;
mod credential;
mod enrollment;
mod error;
mod event;
mod health;
mod lease;
mod lifecycle;
mod object;
mod operation;
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
mod telemetry;
pub mod util;
mod zone_keys;

pub use audit::*;
pub use capability::*;
pub use checkpoint::*;
pub use connector::*;
pub use connector_state::*;
pub use crdt::*;
pub use credential::*;
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
pub use telemetry::*;
pub use zone_keys::*;

// Re-export commonly used external types
pub use async_trait::async_trait;
pub use chrono::{DateTime, Utc};
pub use uuid::Uuid;
