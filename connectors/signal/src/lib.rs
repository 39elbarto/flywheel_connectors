//! Signal messenger connector for FCP.
//!
//! Supports the signal-cli REST daemon mode (HTTP API) and CLI subprocess mode.

#![forbid(unsafe_code)]

pub mod bridge;
pub mod client;
pub mod connector;
pub mod error;
pub mod types;

pub use connector::SignalConnector;
