//! FCP2 Tailscale integration (mesh identity and peer discovery).
//!
//! This crate abstracts Tailscale as the authenticated mesh substrate for FCP.
//!
//! # Overview
//!
//! - [`MeshIdentity`] - Node identity including Tailscale `node_id`, keys, and ACL tags
//! - [`NodeKeyAttestation`] - Owner-signed binding of `node_id` ↔ keys ↔ tags
//! - [`TailscaleClient`] - Trait for `LocalAPI` abstraction (mockable for tests)
//! - [`ZoneTagMapping`] - Zone ↔ `tag:fcp-<suffix>` mapping utilities
//!
//! # Example
//!
//! ```rust,no_run
//! use fcp_tailscale::{MeshIdentity, TailscaleTag, ZoneTagMapping};
//!
//! // Map a zone to its Tailscale tag
//! let zone_id = "z:work".to_string();
//! let tag = ZoneTagMapping::zone_to_tag(&zone_id).unwrap();
//! assert_eq!(tag.as_str(), "tag:fcp-work");
//!
//! // Reverse mapping
//! let tag = TailscaleTag::new("tag:fcp-community").unwrap();
//! let zone = ZoneTagMapping::tag_to_zone(&tag).unwrap();
//! assert_eq!(zone, "z:community");
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod client;
mod error;
mod identity;
mod tag;

pub use client::{LocalApiClient, MockTailscaleClient, PeerInfo, TailscaleClient, TailscaleStatus};
pub use error::{TailscaleError, TailscaleResult};
pub use identity::{MeshIdentity, NodeId, NodeKeyAttestation, NodeKeys};
pub use tag::{TailscaleTag, ZoneAclGenerator, ZoneAclRule, ZoneTagMapping};

/// FCP Tailscale tag prefix (NORMATIVE).
pub const FCP_TAG_PREFIX: &str = "tag:fcp-";

/// Default Tailscale `LocalAPI` socket path.
pub const DEFAULT_LOCALAPI_SOCKET: &str = "/var/run/tailscale/tailscaled.sock";
