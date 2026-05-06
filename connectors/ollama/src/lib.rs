#![forbid(unsafe_code)]
#![allow(
    clippy::derive_partial_eq_without_eq,
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
    DEFAULT_BASE_URL, DEFAULT_EMBEDDING_MODEL, DEFAULT_MODEL, OllamaAuth, OllamaClient,
    OllamaProvider, OllamaUrlPolicy, classify_ollama_base_url, normalize_ollama_base_url,
};
pub use connector::OllamaConnector;
pub use error::{OllamaError, openai_error_to_fcp};
