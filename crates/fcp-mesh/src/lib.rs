//! FCP2 mesh node orchestration (routing, admission, gossip, leases).
//!
//! This crate provides:
//! - [`admission`] - Admission control with per-peer budgets and anti-amplification
//! - [`device`] - Device profile types for execution planning and capability reporting
//! - [`gossip`] - Gossip protocol for metadata and object announcement
//! - [`session`] - Session layer with authenticated handshake, key schedule, and anti-replay
//! - [`symbol_request`] - Symbol request handling with bounded requests and targeted repair
//! - [`transport`] - Transport path ranking + deterministic multipath selection


#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]
// Allow patterns common in mesh/gossip code
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::unused_self)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::clone_on_copy)]
#![allow(clippy::unwrap_or_default)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::field_reassign_with_default)]

pub mod admission;
pub mod degraded;

pub mod device;
pub mod gossip;
pub mod node;
pub mod planner;
pub mod session;
pub mod symbol_request;
pub mod transport;

pub use admission::*;
pub use degraded::*;

pub use device::*;
pub use gossip::*;
pub use node::*;
pub use planner::*;
pub use session::*;
pub use symbol_request::*;
pub use transport::*;

