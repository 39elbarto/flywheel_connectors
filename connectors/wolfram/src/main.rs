//! FCP Wolfram Alpha Connector Binary

#![forbid(unsafe_code)]

use anyhow::Result;
use fcp_wolfram::WolframConnector;
use std::io::{BufRead, Write};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    tracing::info!("FCP Wolfram Alpha Connector starting");
    run_fcp_loop()?;
    Ok(())
}

fn run_fcp_loop() -> Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut connector = WolframConnector::new();

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

async fn handle_message(connector: &mut WolframConnector, message: &str) -> serde_json::Value {
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
        "doctor" => connector.handle_doctor().await,
        "self_check" => connector.handle_self_check().await,
        "simulate" => connector.handle_simulate(params).await,
        "introspect" => serde_json::to_value(connector.handle_introspect()).map_err(|e| {
            fcp_core::FcpError::Internal {
                message: format!("Failed to serialize introspection: {e}"),
            }
        }),
        "invoke" => connector.handle_invoke(params).await,
        "shutdown" => {
            connector.shutdown();
            Ok(serde_json::json!({"status": "shutdown"}))
        }
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
