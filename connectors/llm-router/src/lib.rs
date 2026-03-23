//! FCP LLM Router Connector library.
//!
//! Provides the LLM Router meta-connector implementing the
//! Flywheel Connector Protocol. Routes requests to multiple
//! AI providers based on cost, latency, and capability strategies.

#![forbid(unsafe_code)]
#![allow(dead_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::derivable_impls,
    clippy::future_not_send,
    clippy::float_cmp,
    clippy::manual_div_ceil,
    clippy::manual_unwrap_or_default,
    clippy::map_unwrap_or,
    clippy::match_same_arms,
    clippy::missing_const_for_fn,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::new_without_default,
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
    clippy::unused_async,
    clippy::use_self
)]

pub mod client;
pub mod connector;
pub mod error;
pub mod routing;
pub mod types;
