//! Live-capable n8n secret broker wrapper.
//!
//! The non-live protocol and fixed-socket client live in
//! `fcp-n8n-broker-protocol`; this package adds only the feature-gated fixed
//! KeePass backend and its binary entry point.

#![forbid(unsafe_code)]

pub use fcp_n8n_broker_protocol::*;

#[cfg(feature = "live-backend")]
pub mod live;
