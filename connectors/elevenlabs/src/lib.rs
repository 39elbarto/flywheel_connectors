#![forbid(unsafe_code)]

pub mod connector;
pub mod error;

pub use connector::ElevenlabsConnector;
pub use error::ElevenLabsError;
