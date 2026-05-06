#![forbid(unsafe_code)]

pub mod connector;

pub use connector::{
    CONNECTOR_ID, CONNECTOR_VERSION, RunwayConnector, TaskOutputSummary,
    redacted_task_output_summary,
};
