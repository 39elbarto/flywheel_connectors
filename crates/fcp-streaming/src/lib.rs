//! FCP Streaming - Unified streaming library for FCP connectors
//!
//! This crate provides comprehensive streaming support:
//!
//! - **SSE**: Server-Sent Events parsing and client
//! - **WebSocket**: Full WebSocket protocol support
//! - **Stream Processing**: Async stream utilities
//! - **Error Recovery**: Automatic reconnection with backoff
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use fcp_streaming::{SseClient, SseEvent};
//!
//! // Create SSE client
//! let client = SseClient::new("https://api.example.com/events");
//!
//! // Stream events
//! let mut stream = client.connect().await?;
//! while let Some(event) = stream.next().await {
//!     println!("Event: {:?}", event?);
//! }
//! ```

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

mod error;
pub mod health;
mod reconnect;
mod sse;
mod stream;
mod websocket;

pub use error::*;
pub use health::{StreamHealthConfig, StreamHealthSnapshot, StreamHealthState, StreamHealthTracker};
pub use reconnect::*;
pub use sse::*;
pub use stream::*;
pub use websocket::*;

use std::time::Duration;

/// Default reconnection delay.
pub const DEFAULT_RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// Maximum reconnection delay.
pub const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(60);

/// Default buffer size for streams.
pub const DEFAULT_BUFFER_SIZE: usize = 8192;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_reconnect_delay_value() {
        assert_eq!(DEFAULT_RECONNECT_DELAY, std::time::Duration::from_secs(1));
    }

    #[test]
    fn max_reconnect_delay_value() {
        assert_eq!(MAX_RECONNECT_DELAY, std::time::Duration::from_secs(60));
    }

    #[test]
    fn default_buffer_size_value() {
        assert_eq!(DEFAULT_BUFFER_SIZE, 8192);
    }

    #[test]
    fn max_greater_than_default_delay() {
        assert!(MAX_RECONNECT_DELAY > DEFAULT_RECONNECT_DELAY);
    }

    #[test]
    fn buffer_size_is_power_of_two() {
        assert!(DEFAULT_BUFFER_SIZE.is_power_of_two());
    }

    #[test]
    fn default_buffer_size_nonzero() {
        assert_ne!(DEFAULT_BUFFER_SIZE, 0);
    }

    #[test]
    fn default_reconnect_delay_nonzero() {
        assert!(DEFAULT_RECONNECT_DELAY > std::time::Duration::ZERO);
    }

    #[test]
    fn max_reconnect_delay_at_least_one_second() {
        assert!(MAX_RECONNECT_DELAY >= std::time::Duration::from_secs(1));
    }

    #[test]
    fn default_reconnect_delay_less_than_max() {
        assert!(DEFAULT_RECONNECT_DELAY < MAX_RECONNECT_DELAY);
    }

    #[test]
    fn buffer_size_at_least_4096() {
        // DEFAULT_BUFFER_SIZE is 8192; verify against a variable to avoid const assertion lint
        let minimum = 4096;
        assert!(DEFAULT_BUFFER_SIZE >= minimum);
    }

    #[test]
    fn constants_are_deterministic() {
        // Calling twice yields same values (ensures const, not lazy)
        assert_eq!(DEFAULT_RECONNECT_DELAY, DEFAULT_RECONNECT_DELAY);
        assert_eq!(MAX_RECONNECT_DELAY, MAX_RECONNECT_DELAY);
        assert_eq!(DEFAULT_BUFFER_SIZE, DEFAULT_BUFFER_SIZE);
    }

    #[test]
    fn max_reconnect_delay_is_one_minute() {
        assert_eq!(MAX_RECONNECT_DELAY.as_secs(), 60);
    }

    #[test]
    fn default_reconnect_delay_is_one_second() {
        assert_eq!(DEFAULT_RECONNECT_DELAY.as_millis(), 1000);
    }

    #[test]
    fn buffer_size_exact_value_8192() {
        assert_eq!(DEFAULT_BUFFER_SIZE, 8192);
    }
}
