//! FCP Google Admin Reports Connector - Main entrypoint

#![forbid(unsafe_code)]
#![allow(dead_code, clippy::too_many_lines, clippy::unused_async)]

use std::io::{BufRead, Write};

use anyhow::Result;
use fcp_async_core::runtime::Builder;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use fcp_google_admin_reports::connector::AdminReportsConnector;

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    tracing::info!("FCP Google Admin Reports Connector starting");
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut connector = AdminReportsConnector::new();
    let runtime = Builder::new_multi_thread().enable_all().build()?;

    for line in stdin.lock().lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }
        let request: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let err = serde_json::json!({"error":{"code":"FCP-1001","message":format!("Invalid JSON: {e}")}});
                writeln!(stdout, "{}", serde_json::to_string(&err)?)?;
                stdout.flush()?;
                continue;
            }
        };

        let method = request.get("method").and_then(|v| v.as_str()).unwrap_or("");
        let id = request.get("id").cloned();
        let params = request
            .get("params")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));

        let result = runtime.block_on(async {
            match method {
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
            }
        });

        let response = match result {
            Ok(value) => {
                let mut r = serde_json::json!({"jsonrpc":"2.0","result":value});
                if let Some(id) = id {
                    r["id"] = id;
                }
                r
            }
            Err(e) => {
                let mut r = serde_json::json!({"jsonrpc":"2.0","error":e.to_response()});
                if let Some(id) = id {
                    r["id"] = id;
                }
                r
            }
        };

        writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
        stdout.flush()?;
    }

    Ok(())
}
