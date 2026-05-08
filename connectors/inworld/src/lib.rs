//! FCP Inworld connector library.
//!
//! This connector models Inworld's current Realtime WebSocket character and
//! voice-agent surface. It deliberately avoids older Studio/Runtime REST
//! operation names that are not present in the current public documentation.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc, clippy::unused_async)]

pub mod client;
pub mod connector;
pub mod error;
pub mod types;

pub use connector::InworldConnector;
