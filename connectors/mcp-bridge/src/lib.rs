//! FCP `MCP Bridge` Connector library.
//!
//! Bridges the Flywheel Connector Protocol to Model Context Protocol (MCP)
//! servers, forwarding tool, resource, and prompt requests via JSON-RPC 2.0
//! over HTTP (Streamable HTTP transport).

#![forbid(unsafe_code)]
#![allow(dead_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::derivable_impls,
    clippy::future_not_send,
    clippy::manual_unwrap_or_default,
    clippy::match_same_arms,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::option_if_let_else,
    clippy::or_fun_call,
    clippy::redundant_closure_for_method_calls,
    clippy::struct_field_names,
    clippy::too_many_lines,
    clippy::trivially_copy_pass_by_ref,
    clippy::unreadable_literal,
    clippy::unused_async
)]

pub mod client;
pub mod connector;
pub mod error;
pub mod protocol;
pub mod security;
pub mod types;

/// Exercise the actual closed native projector in cross-connector tests.
/// This feature does not construct authority or perform provider calls.
#[cfg(feature = "n8n-test-support")]
pub fn project_n8n_read_test_fixture(
    input: serde_json::Value,
    server: &str,
    native: &serde_json::Value,
) -> Result<serde_json::Value, &'static str> {
    let read: types::TypedN8nRead =
        serde_json::from_value(input).map_err(|_| "typed_n8n_read_input_invalid")?;
    read.arguments()?;
    read.project(server, native)
}
