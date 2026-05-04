//! FCP Google Meet connector foundation.
//!
//! The foundation owns auth, manifest metadata, base URL validation, and local
//! Meet-space normalization. Concrete API artifact operations are split into
//! follow-up Beads so this crate never advertises unimplemented operations.

#![forbid(unsafe_code)]
#![allow(
    dead_code,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::too_many_lines,
    clippy::unused_async
)]

pub mod client;
pub mod connector;
pub mod error;
