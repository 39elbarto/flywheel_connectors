//! `iMessage` connector via `BlueBubbles` for FCP.
//!
//! Communicates with a self-hosted `BlueBubbles` server that bridges `iMessage`
//! over a REST API.

#![forbid(unsafe_code)]

pub mod client;
pub mod connector;
pub mod error;
pub mod types;

pub use connector::BlueBubblesConnector;
