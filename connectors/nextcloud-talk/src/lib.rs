#![forbid(unsafe_code)]

pub mod client;
pub mod config;
pub mod connector;
pub mod error;
pub mod types;

pub use connector::NextcloudTalkConnector;
