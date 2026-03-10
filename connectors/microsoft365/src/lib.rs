//! FCP Microsoft 365 Connector library.
//!
//! Implements the Flywheel Connector Protocol for the Microsoft Graph API,
//! providing access to Outlook mail, OneDrive files, Calendar events,
//! To Do tasks, OneNote notes, webhook subscriptions, and delta sync.

#![forbid(unsafe_code)]
#![allow(dead_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::derivable_impls,
    clippy::doc_markdown,
    clippy::future_not_send,
    clippy::float_cmp,
    clippy::manual_unwrap_or_default,
    clippy::match_same_arms,
    clippy::missing_const_for_fn,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
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
pub mod excel;
pub mod onenote;
pub mod planner;
pub mod sharepoint;
pub mod types;
