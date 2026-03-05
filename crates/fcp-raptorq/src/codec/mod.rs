//! Internal RaptorQ codec implementation (GF(256) arithmetic, linear algebra,
//! systematic index table, and RFC 6330 codec routines).
//!
//! This module is under active development; suppress work-in-progress lints.
#![allow(
    dead_code,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::doc_markdown,
    clippy::missing_const_for_fn,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::option_if_let_else,
    clippy::similar_names,
    clippy::too_many_lines
)]

pub mod decoder;
pub mod gf256;
pub mod linalg;
pub mod rfc6330;
pub mod systematic;
