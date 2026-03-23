//! `Synology Chat` connector.

#![forbid(unsafe_code)]
#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::struct_field_names,
    clippy::too_many_lines
)]

pub mod client;
pub mod connector;
pub mod error;
pub mod types;

pub use connector::SynologyChatConnector;
