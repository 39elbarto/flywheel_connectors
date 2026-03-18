//! FCP Google Docs Connector - Main entrypoint

#![forbid(unsafe_code)]
#![allow(dead_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::derivable_impls,
    clippy::future_not_send,
    clippy::float_cmp,
    clippy::manual_unwrap_or_default,
    clippy::match_same_arms,
    clippy::option_if_let_else,
    clippy::or_fun_call,
    clippy::redundant_closure_for_method_calls,
    clippy::assertions_on_constants,
    clippy::struct_field_names,
    clippy::suboptimal_flops,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::trivially_copy_pass_by_ref,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use std::io::{BufRead, BufReader, Write};

use anyhow::Result;
use fcp_async_core::runtime::Builder;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use fcp_google_docs::connector::DocsConnector;

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    tracing::info!("FCP Google Docs Connector starting");
    run_fcp_loop()?;
    Ok(())
}

fn run_fcp_loop() -> Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    run_fcp_loop_with_io(stdin.lock(), &mut stdout)
}

fn run_fcp_loop_with_io<R, W>(reader: R, stdout: &mut W) -> Result<()>
where
    R: std::io::Read,
    W: Write,
{
    let mut connector = DocsConnector::new();
    let runtime = Builder::new_multi_thread().enable_all().build()?;

    for line in BufReader::new(reader).lines() {
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

async fn handle_message(connector: &mut DocsConnector, message: &str) -> serde_json::Value {
    let request: serde_json::Value = match serde_json::from_str(message) {
        Ok(v) => v,
        Err(e) => return parse_error_response(e),
    };

    let method = request.get("method").and_then(|v| v.as_str()).unwrap_or("");
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

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor, Read};

    use super::*;

    struct ErrorAfterBytes {
        bytes: Cursor<Vec<u8>>,
        fail_after: usize,
    }

    impl ErrorAfterBytes {
        fn new(contents: &str, fail_after: usize) -> Self {
            Self {
                bytes: Cursor::new(contents.as_bytes().to_vec()),
                fail_after,
            }
        }
    }

    impl Read for ErrorAfterBytes {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.bytes.position() as usize >= self.fail_after {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "simulated read failure",
                ));
            }

            let remaining_before_failure = self.fail_after - self.bytes.position() as usize;
            let max_len = remaining_before_failure.min(buf.len());
            self.bytes.read(&mut buf[..max_len])
        }
    }

    #[test]
    fn protocol_loop_skips_whitespace_only_lines() {
        assert!(should_skip_protocol_line(""));
        assert!(should_skip_protocol_line(" \t "));
        assert!(!should_skip_protocol_line("{\"jsonrpc\":\"2.0\"}"));
    }

    #[test]
    fn protocol_loop_propagates_input_read_errors() {
        let reader = ErrorAfterBytes::new("{\"jsonrpc\":\"2.0\",\"method\":\"health\"}\n", 8);
        let mut output = Vec::new();

        let error = run_fcp_loop_with_io(reader, &mut output)
            .expect_err("input read failure should be returned");

        assert!(
            error.to_string().contains("simulated read failure"),
            "unexpected error: {error:?}"
        );
    }

    #[fcp_async_core::test]
    async fn invalid_json_is_wrapped_in_jsonrpc_parse_error() {
        let mut connector = DocsConnector::new();

        let response = handle_message(&mut connector, "{").await;

        assert_eq!(response["jsonrpc"], "2.0");
        assert!(response["id"].is_null());
        assert_eq!(response["error"]["code"], "FCP-1001");
        assert!(
            response["error"]["message"]
                .as_str()
                .expect("error message should be a string")
                .contains("Invalid JSON")
        );
    }
}
