//! Plivo voice-call connector.
//!
//! This crate keeps Plivo as a standalone FCP connector while sharing webhook
//! HMAC verification, replay, session, call-auth, and redaction primitives
//! through `fcp-voice-call`.

pub mod client;
pub mod connector;
pub mod error;
pub mod types;

pub use connector::PlivoConnector;
