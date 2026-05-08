#![forbid(unsafe_code)]

pub mod connector;
pub mod error;

pub use connector::AzureSpeechConnector;
pub use error::AzureSpeechError;
