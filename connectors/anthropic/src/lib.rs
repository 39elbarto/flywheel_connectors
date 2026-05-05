//! FCP Anthropic Connector library.
//!
//! Provides the Anthropic Claude API connector implementing the
//! Flywheel Connector Protocol. Re-exported for integration tests.

#![forbid(unsafe_code)]
#![allow(dead_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::derivable_impls,
    clippy::future_not_send,
    clippy::float_cmp,
    clippy::manual_unwrap_or_default,
    clippy::match_same_arms,
    clippy::option_if_let_else,
    clippy::or_fun_call,
    clippy::redundant_closure_for_method_calls,
    clippy::assertions_on_constants,
    clippy::struct_field_names,
    clippy::suboptimal_flops,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::trivially_copy_pass_by_ref,
    clippy::unreadable_literal,
    clippy::unused_async
)]

pub mod client;
pub mod connector;
pub mod error;
pub mod types;

/// Fuzz-only entry points for Anthropic response parsers.
///
/// Exposed for `fuzz_anthropic_error_response` so the fuzz crate can drive the
/// private error-response parser and retry-after header parser directly.
///
/// Bead flywheel_connectors-wwp46.
#[doc(hidden)]
pub mod __fuzz {
    use bytes::Bytes;
    use reqwest::StatusCode;

    use crate::{
        client::{
            MAX_SSE_BUFFER_BYTES, parse_error_response, parse_retry_after_header_value,
            parse_sse_event_bytes,
        },
        error::AnthropicError,
        types::StreamEvent,
    };

    /// Parse a raw Anthropic API error body with a caller-supplied HTTP status.
    pub fn parse_error_response_bytes(
        status_code: u16,
        body: &[u8],
        retry_after_header: Option<&str>,
    ) -> AnthropicError {
        let status = StatusCode::from_u16(status_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        parse_error_response(
            status,
            &Bytes::copy_from_slice(body),
            retry_after_header.and_then(parse_retry_after_header_value),
        )
    }

    /// Parse a `Retry-After` header value into bounded milliseconds.
    #[must_use]
    pub fn parse_retry_after_header(header_value: &str) -> Option<u64> {
        parse_retry_after_header_value(header_value)
    }

    /// Parse a single SSE event byte-slice. Drives the internal
    /// `parse_sse_event_bytes` for fuzz coverage of:
    ///
    /// - oversized event rejection (`> MAX_SSE_BUFFER_BYTES`)
    /// - invalid-UTF-8 rejection
    /// - `data:` line joining
    /// - unknown-event-type skipping
    /// - envelope-vs-payload type mismatch detection
    ///
    /// Bead `flywheel_connectors-dzveq`.
    #[must_use]
    pub fn parse_sse_event_bytes_fuzz(
        event_bytes: &[u8],
    ) -> Option<Result<StreamEvent, AnthropicError>> {
        parse_sse_event_bytes(event_bytes)
    }

    /// Expose `MAX_SSE_BUFFER_BYTES` so the fuzz target can hit the
    /// boundary directly without hard-coding the cap.
    pub const FUZZ_MAX_SSE_BUFFER_BYTES: usize = MAX_SSE_BUFFER_BYTES;
}
