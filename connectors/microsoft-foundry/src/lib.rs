#![forbid(unsafe_code)]
#![allow(
    clippy::missing_const_for_fn,
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::needless_pass_by_value,
    clippy::too_many_lines,
    clippy::unused_async
)]

pub mod client;
pub mod connector;
pub mod error;
pub mod types;

pub use client::{
    DEFAULT_MODEL, MicrosoftFoundryAuth, MicrosoftFoundryClient, MicrosoftFoundryEndpointClass,
    MicrosoftFoundryProvider,
};
pub use connector::MicrosoftFoundryConnector;
pub use error::{MicrosoftFoundryError, openai_error_to_fcp};
