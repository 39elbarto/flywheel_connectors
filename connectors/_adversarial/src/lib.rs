#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::unused_async)]

pub mod connector;

pub use connector::{AdversarialConnector, AdversarialConnectorError, AdversarialScenario};
