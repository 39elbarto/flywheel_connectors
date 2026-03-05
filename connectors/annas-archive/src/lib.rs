#![allow(
    clippy::module_name_repetitions,
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::redundant_closure_for_method_calls,
    clippy::too_many_lines,
    clippy::wildcard_imports,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::items_after_statements,
    clippy::unnecessary_wraps,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::unused_async,
    clippy::missing_const_for_fn,
    clippy::missing_fields_in_debug,
    clippy::unreadable_literal
)]

pub mod client;
pub mod connector;
pub mod error;
pub mod types;
