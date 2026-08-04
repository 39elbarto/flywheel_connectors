//! JSONL entry point for the Drive Activity connector.

#![forbid(unsafe_code)]

use std::io::{BufRead, BufReader, Write};

use anyhow::Result;
use fcp_async_core::runtime::Builder;
use fcp_google_drive_activity::connector::DriveActivityConnector;
use fcp_prelude::{FcpError, FcpResult, InvokeRequest, InvokeResponse, RequestId};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();
    run_fcp_loop_with_io(std::io::stdin().lock(), &mut std::io::stdout())
}

fn run_fcp_loop_with_io<R: std::io::Read, W: Write>(reader: R, output: &mut W) -> Result<()> {
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    let mut connector = DriveActivityConnector::new();
    for line in BufReader::new(reader).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let response = runtime.block_on(handle_message(&mut connector, &line));
        writeln!(output, "{}", serde_json::to_string(&response)?)?;
        output.flush()?;
    }
    Ok(())
}

async fn handle_message(
    connector: &mut DriveActivityConnector,
    message: &str,
) -> serde_json::Value {
    let request: serde_json::Value = match serde_json::from_str(message) {
        Ok(value) => value,
        Err(error) => {
            return serde_json::json!({"jsonrpc":"2.0","id":null,"error":{"code":"FCP-1001","message":format!("Invalid JSON: {error}")}});
        }
    };
    let id = request.get("id").cloned();
    let params = request
        .get("params")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let result = match request
        .get("method")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
    {
        "configure" => connector.handle_configure(params).await,
        "handshake" => connector.handle_handshake(params).await,
        "health" => connector.handle_health().await,
        "doctor" => connector.handle_doctor().await,
        "self_check" => connector.handle_self_check().await,
        "introspect" => connector.handle_introspect().await,
        "invoke" => handle_invoke(connector, params).await,
        "simulate" => connector.handle_simulate(params).await,
        "shutdown" => connector.handle_shutdown(params).await,
        method => Err(fcp_core::FcpError::InvalidRequest {
            code: 1002,
            message: format!("Unknown method: {method}"),
        }),
    };
    let mut response = match result {
        Ok(value) => serde_json::json!({"jsonrpc":"2.0","result":value}),
        Err(error) => serde_json::json!({"jsonrpc":"2.0","error":error.to_response()}),
    };
    if let Some(id) = id {
        response["id"] = id;
    }
    response
}

async fn handle_invoke(
    connector: &mut DriveActivityConnector,
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
        .unwrap();
        assert_eq!(success["type"], "response");
        assert_eq!(success["status"], "ok");
        assert_eq!(success["result"]["accepted"], true);

        let failure =
            serialize_invoke_response(RequestId::new("test-error"), Err(FcpError::NotConfigured))
                .unwrap();
        assert_eq!(failure["type"], "response");
        assert_eq!(failure["status"], "error");
        assert!(failure["error"].is_object());
    }

    #[fcp_async_core::test]
    async fn malformed_json_is_framed_as_jsonrpc_error() {
        let mut connector = DriveActivityConnector::new();
        let response = handle_message(&mut connector, "{").await;
        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["error"]["code"], "FCP-1001");
    }

    #[test]
    fn protocol_loop_skips_empty_lines_and_handles_health() {
        let input = b"\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"health\"}\n";
        let mut output = Vec::new();
        run_fcp_loop_with_io(&input[..], &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(text.contains("not_configured"));
    }
}
