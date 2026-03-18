#![forbid(unsafe_code)]

use std::io::{BufRead, Write};

use fcp_core::{FcpError, HandshakeRequest, InvokeRequest, ShutdownRequest};
use fcp_mattermost::MattermostConnector;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    tracing::info!("FCP Mattermost Connector starting");
    run_fcp_loop()?;
    Ok(())
}

fn run_fcp_loop() -> anyhow::Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut connector = MattermostConnector::new();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }

        let response = handle_message(&mut connector, &line);

        let response_json = serde_json::to_string(&response)?;
        writeln!(stdout, "{response_json}")?;
        stdout.flush()?;
    }
    Ok(())
}

fn handle_message(connector: &mut MattermostConnector, message: &str) -> serde_json::Value {
    let request: serde_json::Value = match serde_json::from_str(message) {
        Ok(v) => v,
        Err(e) => {
            return serde_json::json!({
                "jsonrpc": "2.0",
                "error": {"code": "FCP-1001", "message": format!("Invalid JSON: {e}")}
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
        "configure" => connector
            .configure(params)
            .map(|()| serde_json::json!({"status": "configured"})),
        "handshake" => serde_json::from_value::<HandshakeRequest>(params)
            .map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: e.to_string(),
            })
            .and_then(|req| connector.handshake(&req))
            .and_then(|resp| {
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })
            }),
        "health" => {
            let snapshot = connector.health();
            serde_json::to_value(snapshot).map_err(|e| FcpError::Internal {
                message: e.to_string(),
            })
        }
        "introspect" => {
            let intro = connector.introspect();
            serde_json::to_value(intro).map_err(|e| FcpError::Internal {
                message: e.to_string(),
            })
        }
        "invoke" => serde_json::from_value::<InvokeRequest>(params)
            .map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: e.to_string(),
            })
            .and_then(|req| {
                fcp_async_core::runtime::block_on_sync(connector.invoke(req))
                    .unwrap_or_else(|e| {
                        Err(FcpError::Internal {
                            message: e.to_string(),
                        })
                    })
            })
            .and_then(|resp| {
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })
            }),
        "shutdown" => serde_json::from_value::<ShutdownRequest>(params)
            .map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: e.to_string(),
            })
            .and_then(|req| connector.shutdown(req))
            .map(|()| serde_json::json!({"status": "shutdown_accepted"})),
        _ => Err(FcpError::InvalidRequest {
            code: 1002,
            message: format!("Unknown method: {method}"),
        }),
    };

    match result {
        Ok(value) => serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": value
        }),
        Err(e) => {
            let err_value = serde_json::to_value(&e).unwrap_or_else(|_| {
                serde_json::json!({
                    "code": "FCP-9000",
                    "message": e.to_string()
                })
            });
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": err_value
            })
        }
    }
}
