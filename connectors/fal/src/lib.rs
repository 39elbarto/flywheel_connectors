#![forbid(unsafe_code)]

pub mod connector;

pub use connector::{
    CONNECTOR_ID, CONNECTOR_VERSION, FalConnector, MediaOutputSummary, redacted_media_summary,
};
