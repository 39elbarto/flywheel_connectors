//! FCP `MCP Bridge` Connector - Main entrypoint
//!
//! An MCP Bridge connector implementing the Flywheel Connector Protocol.
//! Bridges FCP operations to MCP server tools, resources, and prompts.

#![forbid(unsafe_code)]
#![allow(dead_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::derivable_impls,
    clippy::future_not_send,
    clippy::manual_unwrap_or_default,
    clippy::match_same_arms,
    clippy::option_if_let_else,
    clippy::or_fun_call,
    clippy::redundant_closure_for_method_calls,
    clippy::struct_field_names,
    clippy::too_many_lines,
    clippy::trivially_copy_pass_by_ref,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use std::io::{BufRead, Write};

use anyhow::Result;
use fcp_async_core::runtime::Builder;
use fcp_core::{FcpError, FcpResult, InvokeRequest, InvokeResponse, RequestId};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use fcp_mcp_bridge::connector::McpBridgeConnector;

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    tracing::info!("FCP MCP Bridge Connector starting");
    run_fcp_loop()?;
    Ok(())
}

fn run_fcp_loop() -> Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut connector = McpBridgeConnector::new();

    let runtime = Builder::new_multi_thread().enable_all().build()?;

    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
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

async fn handle_message(connector: &mut McpBridgeConnector, message: &str) -> serde_json::Value {
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

    let method = request
        .get("method")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let id = request.get("id").cloned();
    let params = request
        .get("params")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));

    let result = match method {
        "configure" => connector.handle_configure(params).await,
        "handshake" => connector.handle_handshake(params).await,
        "health" => connector.handle_health().await,
        "doctor" => connector.handle_doctor().await,
        "self_check" => connector.handle_self_check().await,
        "introspect" => connector.handle_introspect().await,
        "invoke" => handle_invoke(connector, params).await,
        "simulate" => connector.handle_simulate(params).await,
        "shutdown" => connector.handle_shutdown(params).await,
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
                response
                    .as_object_mut()
                    .unwrap()
                    .insert("id".to_string(), id);
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
                response
                    .as_object_mut()
                    .unwrap()
                    .insert("id".to_string(), id);
            }
            response
        }
    }
}

async fn handle_invoke(
    connector: &McpBridgeConnector,
    params: serde_json::Value,
) -> FcpResult<serde_json::Value> {
    let request: InvokeRequest =
        serde_json::from_value(params.clone()).map_err(|error| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid invoke request: {error}"),
        })?;
    serialize_invoke_response(request.id, connector.handle_invoke(params).await)
}

fn serialize_invoke_response(
    request_id: RequestId,
    outcome: FcpResult<serde_json::Value>,
) -> FcpResult<serde_json::Value> {
    let response = match outcome {
        Ok(output) => InvokeResponse::ok(request_id, output),
        Err(error) => InvokeResponse::error(request_id, error),
    };
    serde_json::to_value(response).map_err(|error| FcpError::Internal {
        message: format!("Failed to serialize invoke response: {error}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invoke_results_use_normative_response_envelope() {
        let success = serialize_invoke_response(
            RequestId::new("test-success"),
            Ok(serde_json::json!({"accepted": true})),
        )
        .expect("serialize successful invoke response");
        assert_eq!(success["type"], "response");
        assert_eq!(success["id"], "test-success");
        assert_eq!(success["status"], "ok");
        assert_eq!(success["result"]["accepted"], true);

        let failure = serialize_invoke_response(
            RequestId::new("test-failure"),
            Err(FcpError::InvalidRequest {
                code: 1003,
                message: "rejected".to_string(),
            }),
        )
        .expect("serialize failed invoke response");
        assert_eq!(failure["type"], "response");
        assert_eq!(failure["id"], "test-failure");
        assert_eq!(failure["status"], "error");
        assert!(failure.get("error").is_some());
        assert!(failure.get("result").is_none());
    }
}
