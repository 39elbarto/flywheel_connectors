#![forbid(unsafe_code)]

use std::io::{BufRead, Write};

use anyhow::Result;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use fcp_qwen::QwenConnector;

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    run_fcp_loop()
}

fn run_fcp_loop() -> Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut connector = QwenConnector::new();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let response =
            fcp_async_core::runtime::block_on_sync(handle_message(&mut connector, &line))
                .unwrap_or_else(|error| {
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "error": {
                            "code": "FCP-9001",
                            "message": format!("Runtime error: {error}")
                        }
                    })
                });

        writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
        stdout.flush()?;
    }

    Ok(())
}

async fn handle_message(connector: &mut QwenConnector, message: &str) -> serde_json::Value {
    let request: serde_json::Value = match serde_json::from_str(message) {
        Ok(value) => value,
        Err(error) => {
            return serde_json::json!({
                "jsonrpc": "2.0",
                "id": null,
                "error": {
                    "code": "FCP-1001",
                    "message": format!("Invalid JSON: {error}")
                }
            });
        }
    };

    let method = request
        .get("method")
        .and_then(|value| value.as_str())
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
        "invoke" => connector.handle_invoke(params).await,
        "simulate" => connector.handle_simulate(params).await,
        "shutdown" => connector.handle_shutdown(params).await,
        _ => Err(fcp_core::FcpError::InvalidRequest {
            code: 1002,
            message: format!("Unknown method: {method}"),
        }),
    };

    match result {
        Ok(value) => json_rpc_response("result", value, id),
        Err(error) => json_rpc_response("error", serde_json::json!(error.to_response()), id),
    }
}

fn json_rpc_response(
    payload_field: &'static str,
    payload: serde_json::Value,
    id: Option<serde_json::Value>,
) -> serde_json::Value {
    let mut response = serde_json::Map::new();
    response.insert("jsonrpc".into(), serde_json::Value::String("2.0".into()));
    if let Some(id) = id {
        response.insert("id".into(), id);
    }
    response.insert(payload_field.into(), payload);
    serde_json::Value::Object(response)
}
