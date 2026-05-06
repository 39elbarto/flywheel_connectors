//! FCP Telnyx Connector - Main entrypoint.

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::option_if_let_else,
    clippy::or_fun_call,
    clippy::unused_async
)]

use std::io::{BufRead, Write};

use anyhow::Result;
use fcp_async_core::runtime::Builder;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use fcp_telnyx::connector::TelnyxConnector;

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    tracing::info!("FCP Telnyx Connector starting");
    run_fcp_loop()
}

fn run_fcp_loop() -> Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut connector = TelnyxConnector::new();
    let runtime = Builder::new_multi_thread().enable_all().build()?;

    for line in stdin.lock().lines() {
        let line = line?;
        if should_skip_protocol_line(&line) {
            continue;
        }
        let response = runtime.block_on(async { handle_message(&mut connector, &line).await });
        let response_json = serde_json::to_string(&response)?;
        writeln!(stdout, "{response_json}")?;
        stdout.flush()?;
    }
    Ok(())
}

fn should_skip_protocol_line(line: &str) -> bool {
    line.trim().is_empty()
}

fn parse_error_response(error: impl std::fmt::Display) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": null,
        "error": {
            "code": "FCP-1001",
            "message": format!("Invalid JSON: {error}")
        }
    })
}

async fn handle_message(connector: &mut TelnyxConnector, message: &str) -> serde_json::Value {
    let request: serde_json::Value = match serde_json::from_str(message) {
        Ok(value) => value,
        Err(error) => return parse_error_response(error),
    };

    let method = request
        .get("method")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let id = request.get("id").cloned();
    let params = request
        .get("params")
        .cloned()
        .unwrap_or(serde_json::json!({}));

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
            let mut response = serde_json::json!({ "jsonrpc": "2.0", "result": value });
            if let Some(id) = id {
                response["id"] = id;
            }
            response
        }
        Err(error) => {
            let mut response =
                serde_json::json!({ "jsonrpc": "2.0", "error": error.to_response() });
            if let Some(id) = id {
                response["id"] = id;
            }
            response
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_loop_skips_whitespace_only_lines() {
        assert!(should_skip_protocol_line(""));
        assert!(should_skip_protocol_line(" \t "));
        assert!(!should_skip_protocol_line("{\"jsonrpc\":\"2.0\"}"));
    }

    #[fcp_async_core::runtime::test]
    async fn invalid_json_is_wrapped_in_jsonrpc_parse_error() {
        let mut connector = TelnyxConnector::new();
        let response = handle_message(&mut connector, "{not json").await;

        assert_eq!(response["jsonrpc"], "2.0");
        assert!(response["id"].is_null());
        assert_eq!(response["error"]["code"], "FCP-1001");
        assert!(
            response["error"]["message"]
                .as_str()
                .is_some_and(|message| message.starts_with("Invalid JSON:"))
        );
    }
}
