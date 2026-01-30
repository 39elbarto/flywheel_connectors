//! FCP Vector Database Connector Binary
//!
//! Provider-selectable connector supporting Pinecone, Qdrant, and other vector stores.

#![forbid(unsafe_code)]

use fcp_vectordb::VectorDbConnector;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

fn main() {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    // Create connector
    let _connector = VectorDbConnector::new();

    // TODO: Implement JSONL IPC protocol
    // For now, just print a message
    eprintln!("fcp-vectordb: JSONL IPC not yet implemented");
    eprintln!("See lib.rs for connector implementation");
    std::process::exit(1);
}
