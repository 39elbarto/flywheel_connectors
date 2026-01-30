//! FCP Discord Connector
//!
//! A Flywheel Connector Protocol implementation for the Discord Bot API.
//!
//! This connector implements the Bidirectional archetype, supporting:
//! - Sending messages, embeds, files
//! - Receiving events via Gateway WebSocket
//! - Managing channels, roles, and members
//! - Slash commands and interactions
//!
//! Based on clawdbot's Discord integration patterns.

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]
#![allow(dead_code)] // Connector API types/methods wired incrementally

mod api;
mod config;
mod connector;
mod error;
mod gateway;
mod types;

pub use config::DiscordConfig;
pub use connector::DiscordConnector;
pub use error::DiscordError;
