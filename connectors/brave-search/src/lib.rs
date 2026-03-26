#![forbid(unsafe_code)]

pub mod connector;
pub mod error;

pub use connector::BraveSearchConnector;
pub use error::BraveSearchError;
