#![forbid(unsafe_code)]
#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::option_if_let_else,
    clippy::struct_field_names,
    clippy::too_many_lines
)]

pub mod client;
pub mod connector;
pub mod error;
pub mod types;
