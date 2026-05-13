//! Opt-in adversarial connector for hostile provider-response tests.

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

pub mod connector;

pub use connector::{
    AdversarialConnector, AdversarialConnectorError, AdversarialScenario, CONNECTOR_ID,
    OP_ADVERSARIAL_EMIT,
};
