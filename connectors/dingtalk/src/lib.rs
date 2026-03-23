//! FCP `DingTalk` connector.

#![forbid(unsafe_code)]

pub mod client;
pub mod connector;
pub mod error;
pub mod types;

pub use connector::DingTalkConnector;
