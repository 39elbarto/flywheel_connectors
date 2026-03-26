#![forbid(unsafe_code)]

pub mod connector;
pub mod error;

pub use connector::OpenRouterConnector;
pub use error::OpenRouterError;
