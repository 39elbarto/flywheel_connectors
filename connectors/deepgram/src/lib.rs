#![forbid(unsafe_code)]

pub mod connector;
pub mod error;

pub use connector::DeepgramConnector;
pub use error::DeepgramError;
