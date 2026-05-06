//! Moonshot/Kimi connector.

#![allow(clippy::missing_errors_doc)]

pub mod client;
pub mod connector;
pub mod error;
pub mod types;

pub use connector::MoonshotConnector;
