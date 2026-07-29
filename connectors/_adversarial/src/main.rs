//! FCP adversarial connector binary entry point.

#![forbid(unsafe_code)]

use std::io::{BufRead, Write};

use anyhow::Result;
use fcp_adversarial::AdversarialConnector;
use fcp_prelude::{
    FcpConnector, FcpError, FcpResult, HandshakeRequest, InvokeRequest, ShutdownRequest,
    SimulateRequest, SubscribeRequest, UnsubscribeRequest,
};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    let mut connector = AdversarialConnector::try_new_from_env()?;
    run_fcp_loop(&mut connector)?;
    Ok(())
}

fn run_fcp_loop(connector: &mut AdversarialConnector) -> Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }

        let response = fcp_async_core::runtime::block_on_sync(handle_message(connector, &line))
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

fn encode<T: serde::Serialize>(value: &T) -> FcpResult<serde_json::Value> {
    serde_json::to_value(value).map_err(|error| FcpError::Internal {
        message: format!("failed to serialize response: {error}"),
    })
}

async fn handle_message(connector: &mut AdversarialConnector, message: &str) -> serde_json::Value {
    let request: serde_json::Value = match serde_json::from_str(message) {
        Ok(value) => value,
        Err(error) => {
            return serde_json::json!({
                "jsonrpc": "2.0",
                "error": {
                    "code": "FCP-1001",
                    "message": format!("invalid JSON: {error}")
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

    let result: FcpResult<serde_json::Value> = async {
        match method {
            "configure" => {
                connector.configure(params).await?;
                Ok(serde_json::json!({ "status": "configured" }))
            }
            "handshake" => {
                let req: HandshakeRequest = decode_params(params, "handshake")?;
                encode(&connector.handshake(req).await?)
            }
            "health" => encode(&connector.health().await),
            "introspect" => encode(&connector.introspect()),
            "invoke" => {
                let req: InvokeRequest = decode_params(params, "invoke")?;
                encode(&connector.invoke(req).await?)
            }
            "simulate" => {
                let req: SimulateRequest = decode_params(params, "simulate")?;
                encode(&connector.simulate(req).await?)
            }
            "subscribe" => {
                let req: SubscribeRequest = decode_params(params, "subscribe")?;
                encode(&connector.subscribe(req).await?)
            }
            "unsubscribe" => {
                let req: UnsubscribeRequest = decode_params(params, "unsubscribe")?;
                connector.unsubscribe(req).await?;
                Ok(serde_json::json!({ "status": "unsubscribed" }))
            }
            "shutdown" => {
                let req: ShutdownRequest = decode_params(params, "shutdown")?;
                connector.shutdown(req).await?;
                Ok(serde_json::json!({ "status": "shutdown" }))
            }
            _ => Err(FcpError::InvalidRequest {
                code: 1002,
                message: format!("unknown method: {method}"),
            }),
        }
    }
    .await;

    match result {
        Ok(value) => serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": value
        }),
        Err(error) => serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": error
        }),
    }
}

fn decode_params<T: serde::de::DeserializeOwned>(
    params: serde_json::Value,
    method: &str,
) -> FcpResult<T> {
    serde_json::from_value(params).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("invalid {method} request: {error}"),
    })
}
