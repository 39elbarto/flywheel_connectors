//! Strictly read-only Google Drive Activity API v2 connector.

#![forbid(unsafe_code)]
#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::unused_async
)]

pub mod client;
pub mod connector;
pub mod error;
