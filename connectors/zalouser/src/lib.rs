#![forbid(unsafe_code)]

pub mod connector;
pub mod error;

pub use connector::ZalouserConnector;
pub use error::ZaloUserError;
