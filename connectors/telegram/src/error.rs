//! Error types for the Telegram connector.
//!
//! The canonical error type [`TelegramError`] and its
//! [`ConnectorErrorMapping`](fcp_sdk::migration::ConnectorErrorMapping)
//! implementation live in [`crate::client`]. This module re-exports them
//! for consistency with the standard FCP connector layout.

pub use crate::client::TelegramError;

/// Convenience alias used throughout the connector.
pub type TelegramResult<T> = Result<T, TelegramError>;
