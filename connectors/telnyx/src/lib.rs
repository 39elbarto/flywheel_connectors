//! FCP Telnyx voice-call connector library.
//!
//! This crate is intentionally voice-call only. It keeps Telnyx as its own
//! one-binary, one-manifest connector while sharing provider-neutral webhook,
//! replay, session, and call-auth primitives with Twilio and Plivo through
//! `fcp-voice-call`.

#![forbid(unsafe_code)]
#![allow(dead_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::derivable_impls,
    clippy::doc_markdown,
    clippy::future_not_send,
    clippy::manual_unwrap_or_default,
    clippy::match_same_arms,
    clippy::missing_const_for_fn,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::option_if_let_else,
    clippy::or_fun_call,
    clippy::redundant_closure_for_method_calls,
    clippy::similar_names,
    clippy::struct_field_names,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

pub mod client;
pub mod connector;
pub mod error;
pub mod types;
