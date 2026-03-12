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
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::float_cmp,
    clippy::future_not_send,
    clippy::large_enum_variant,
    clippy::map_unwrap_or,
    clippy::match_same_arms,
    clippy::match_wildcard_for_single_variants,
    clippy::missing_errors_doc,
    clippy::option_if_let_else,
    clippy::or_fun_call,
    clippy::redundant_closure_for_method_calls,
    clippy::assertions_on_constants,
    clippy::struct_field_names,
    clippy::too_many_lines,
    clippy::unnecessary_wraps,
    clippy::unreadable_literal,
    clippy::unused_async,
    clippy::wildcard_imports
)]

mod api;
mod config;
mod connector;
mod error;
mod gateway;
pub mod limits;
mod types;

pub use config::DiscordConfig;
pub use connector::DiscordConnector;
pub use error::DiscordError;

// Re-export for integration tests
pub use api::DiscordApiClient;
