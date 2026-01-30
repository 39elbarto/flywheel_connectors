//! FCP Twitter/X Connector
//!
//! A Flywheel Connector Protocol implementation for the Twitter/X API.
//!
//! This connector implements three archetypes:
//! - Operational: REST actions (search, post, etc.)
//! - Streaming: Filtered stream ingestion
//! - Bidirectional: Read + publish workflows
//!
//! ## Capabilities
//!
//! ### Read Operations (Safe)
//! - `twitter.read.public` - Search and public tweets
//! - `twitter.read.account` - Timelines, mentions
//! - `twitter.read.dms` - Direct message inbox (Risky)
//!
//! ### Write Operations (Dangerous)
//! - `twitter.write.tweets` - Create, reply, thread, delete
//! - `twitter.write.dms` - Send direct messages
//!
//! ### Streaming (Safe)
//! - `twitter.stream.read` - Filtered stream ingestion

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]
#![allow(dead_code)] // Connector API types/methods wired incrementally

mod client;
mod config;
mod connector;
mod error;
mod oauth;
mod stream;
mod types;

pub use config::TwitterConfig;
pub use connector::TwitterConnector;
pub use error::TwitterError;

#[cfg(test)]
mod tests {
    use fcp_manifest::ConnectorManifest;
    use std::path::PathBuf;

    #[test]
    fn manifest_interface_hash_is_deterministic() {
        let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("manifest.toml");
        if !manifest_path.exists() {
            eprintln!("manifest.toml missing; skipping interface_hash check");
            return;
        }
        let raw = std::fs::read_to_string(&manifest_path).expect("read manifest");

        let manifest = ConnectorManifest::parse_str(&raw).expect("manifest should validate");
        let computed = manifest
            .compute_interface_hash()
            .expect("compute interface hash");
        assert_eq!(manifest.manifest.interface_hash, computed);

        let manifest2 = ConnectorManifest::parse_str_unchecked(&raw).expect("parse unchecked");
        let computed2 = manifest2
            .compute_interface_hash()
            .expect("compute interface hash");
        assert_eq!(computed, computed2);
    }
}
