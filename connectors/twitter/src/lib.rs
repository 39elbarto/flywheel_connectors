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
