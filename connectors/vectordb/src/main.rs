//! FCP Vector Database Connector Binary
//!
//! Provider-selectable connector supporting Pinecone, Qdrant, and other vector stores.

#![forbid(unsafe_code)]

use anyhow::Result;
use fcp_vectordb::VectorDbConnector;
use serde::Serialize;
use std::io::{BufRead, Write};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    tracing::info!("FCP Vector Database Connector starting");

    run_fcp_loop()?;

    Ok(())
}

/// Run the FCP JSON-RPC style protocol loop.
fn run_fcp_loop() -> Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut connector = VectorDbConnector::new();

    let runtime = fcp_async_core::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    for line in stdin.lock().lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }

        let response = runtime.block_on(async { handle_message(&mut connector, &line).await });

        let response_json = serde_json::to_string(&response)?;
        writeln!(stdout, "{response_json}")?;
        stdout.flush()?;
    }

    Ok(())
}

/// Handle a single FCP message.
async fn handle_message(connector: &mut VectorDbConnector, message: &str) -> serde_json::Value {
    let request: serde_json::Value = match serde_json::from_str(message) {
        Ok(v) => v,
        Err(e) => {
            return serde_json::json!({
                "error": {
                    "code": "FCP-1001",
                    "message": format!("Invalid JSON: {e}")
                }
            });
        }
    };

    let method = request.get("method").and_then(|v| v.as_str()).unwrap_or("");
    let id = request.get("id").cloned();
    let params = request
        .get("params")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));

    let result = match method {
        "configure" => connector.handle_configure(params).await,
        "handshake" => connector.handle_handshake(params).await,
        "health" => Ok(connector.handle_health()),
        "doctor" => connector
            .handle_doctor()
            .await
            .and_then(|doctor| serialize_response_value(doctor, "doctor")),
        "self_check" => connector.handle_self_check().await,
        "simulate" => connector.handle_simulate(params).await,
        "introspect" => serialize_response_value(connector.handle_introspect(), "introspect"),
        "invoke" => connector.handle_invoke(params).await,
        _ => Err(fcp_core::FcpError::InvalidRequest {
            code: 1002,
            message: format!("Unknown method: {method}"),
        }),
    };

    match result {
        Ok(value) => {
            let mut response = serde_json::json!({
                "jsonrpc": "2.0",
                "result": value
            });
            if let Some(id) = id {
                response["id"] = id;
            }
            response
        }
        Err(e) => {
            let err_response = e.to_response();
            let mut response = serde_json::json!({
                "jsonrpc": "2.0",
                "error": err_response
            });
            if let Some(id) = id {
                response["id"] = id;
            }
            response
        }
    }
}

fn serialize_response_value<T: Serialize>(
    value: T,
    method: &str,
) -> std::result::Result<serde_json::Value, fcp_core::FcpError> {
    serde_json::to_value(value).map_err(|error| fcp_core::FcpError::Internal {
        message: format!("Failed to serialize {method} response: {error}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serializer;
    use serde::ser::Error as _;

    struct FailingSerialize;

    impl Serialize for FailingSerialize {
        fn serialize<S>(&self, _serializer: S) -> std::result::Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            Err(S::Error::custom("forced failure"))
        }
    }

    #[test]
    fn serialize_response_value_surfaces_internal_error() {
        let err = serialize_response_value(FailingSerialize, "doctor")
            .expect_err("serialization failures must be surfaced");
        match err {
            fcp_core::FcpError::Internal { message } => {
                assert!(message.contains("doctor"));
                assert!(message.contains("forced failure"));
            }
            other => panic!("expected internal error, got {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn handle_message_introspect_returns_json_rpc_result() {
        let mut connector = VectorDbConnector::new();
        let response = handle_message(
            &mut connector,
            r#"{"jsonrpc":"2.0","id":7,"method":"introspect"}"#,
        )
        .await;

        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 7);
        assert!(
            response["result"]["operations"].is_array(),
            "introspect must produce a JSON-RPC result payload",
        );
    }
}
