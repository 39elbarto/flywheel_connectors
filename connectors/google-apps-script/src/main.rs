//! FCP Google Apps Script connector JSON-RPC entrypoint.

#![forbid(unsafe_code)]

use std::io::{BufRead, BufReader, Write};

use anyhow::Result;
use fcp_async_core::runtime::Builder;
use fcp_google_apps_script::connector::AppsScriptConnector;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

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
    let mut connector = AppsScriptConnector::new();
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    for line in BufReader::new(stdin.lock()).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let response = runtime.block_on(handle_message(&mut connector, &line));
        writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
        stdout.flush()?;
    }
    Ok(())
}

async fn handle_message(connector: &mut AppsScriptConnector, message: &str) -> serde_json::Value {
    let request: serde_json::Value = match serde_json::from_str(message) {
        Ok(value) => value,
        Err(error) => {
            return serde_json::json!({"jsonrpc":"2.0","id":null,"error":{"code":"FCP-1001","message":format!("Invalid JSON: {error}")}});
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
        "invoke" => connector.handle_invoke(params).await,
        "simulate" => connector.handle_simulate(params).await,
        "shutdown" => connector.handle_shutdown(params).await,
        _ => Err(fcp_core::FcpError::InvalidRequest {
            code: 1002,
            message: format!("Unknown method: {method}"),
        }),
    };
    match result {
        Ok(value) => {
            let mut response = serde_json::json!({"jsonrpc":"2.0","result":value});
            if let Some(id) = id {
                response["id"] = id;
            }
            response
        }
        Err(error) => {
            let mut response = serde_json::json!({"jsonrpc":"2.0","error":error.to_response()});
            if let Some(id) = id {
                response["id"] = id;
            }
            response
        }
    }
}
