use std::io::{self, BufRead};

use anyhow::Result;
use fcp_moonshot::MoonshotConnector;
use serde_json::{Value, json};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt as _, util::SubscriberInitExt as _};

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    let stdin = io::stdin();
    let mut connector = MoonshotConnector::new();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let response =
            match fcp_async_core::runtime::block_on_sync(handle_message(&mut connector, &line)) {
                Ok(Ok(value)) => value,
                Ok(Err(error)) => runtime_error_response(&format!("Handler error: {error}")),
                Err(error) => runtime_error_response(&format!("Runtime error: {error}")),
            };
        println!("{}", serde_json::to_string(&response)?);
    }
    Ok(())
}

fn runtime_error_response(message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "error": {
            "code": "FCP-9001",
            "message": message
        }
    })
}

async fn handle_message(connector: &mut MoonshotConnector, line: &str) -> Result<Value> {
    let request: Value = serde_json::from_str(line)?;
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
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
        other => Err(fcp_prelude::FcpError::InvalidRequest {
            code: 1002,
            message: format!("Unknown method: {other}"),
        }),
    };

    match result {
        Ok(mut value) => {
            if let Value::Object(ref mut object) = value {
                object.insert("id".into(), id);
            }
            Ok(json!({"jsonrpc": "2.0", "result": value}))
        }
        Err(error) => Ok(json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": format!("{error:?}"),
                "message": error.to_string()
            }
        })),
    }
}
