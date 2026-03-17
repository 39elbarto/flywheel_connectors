//! FCP `Reddit` Connector binary.

use std::io::{BufRead, Write};

use anyhow::Result;
use fcp_reddit::connector::RedditConnector;
use serde_json::json;

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    run_fcp_loop()
}

fn run_fcp_loop() -> Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut connector = RedditConnector::new();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let response = execute_request(&mut connector, &line);
        write_response(&mut stdout, &response)?;
    }

    Ok(())
}

fn execute_request(connector: &mut RedditConnector, line: &str) -> serde_json::Value {
    fcp_async_core::runtime::block_on_sync(handle_message(connector, line)).unwrap_or_else(|e| {
        json!({
            "jsonrpc": "2.0",
            "id": null,
            "error": {
                "code": "FCP-9001",
                "message": format!("Runtime error: {e}")
            }
        })
    })
}

fn write_response<W: Write>(writer: &mut W, response: &serde_json::Value) -> Result<()> {
    let response_json = serde_json::to_string(response)?;
    writeln!(writer, "{response_json}")?;
    writer.flush()?;
    Ok(())
}

async fn handle_message(connector: &mut RedditConnector, message: &str) -> serde_json::Value {
    let request: serde_json::Value = match serde_json::from_str(message) {
        Ok(value) => value,
        Err(err) => {
            return json!({
                "jsonrpc": "2.0",
                "id": null,
                "error": {
                    "code": -32700,
                    "message": err.to_string()
                }
            });
        }
    };

    let id = request.get("id").cloned();
    let method = request
        .get("method")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string();
    let params = request.get("params").cloned().unwrap_or_else(|| json!({}));

    let result = match method.as_str() {
        "configure" => connector.handle_configure(params).await,
        "handshake" => connector.handle_handshake(params).await,
        "health" => connector.handle_health().await,
        "invoke" => connector.handle_invoke(params).await,
        "simulate" => connector.handle_simulate(params).await,
        "shutdown" => connector.handle_shutdown(params).await,
        "self_check" => connector.handle_self_check().await,
        "introspect" => connector.handle_introspect().await,
        "doctor" => connector.handle_doctor().await,
        _ => Err(fcp_core::FcpError::InvalidRequest {
            code: 1002,
            message: format!("Unknown method: {method}"),
        }),
    };

    match result {
        Ok(value) => json!({"jsonrpc": "2.0", "id": id, "result": value}),
        Err(err) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32000,
                "message": err.to_string()
            }
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FlushTrackingWriter {
        buffer: Vec<u8>,
        flush_count: usize,
    }

    impl Write for FlushTrackingWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.buffer.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.flush_count += 1;
            Ok(())
        }
    }

    #[test]
    fn write_response_flushes_each_message() {
        let mut writer = FlushTrackingWriter::default();
        write_response(
            &mut writer,
            &json!({"jsonrpc": "2.0", "result": {"ok": true}}),
        )
        .unwrap();

        assert_eq!(writer.flush_count, 1);
        let body = String::from_utf8(writer.buffer).unwrap();
        assert!(body.ends_with('\n'));
        let response: serde_json::Value = serde_json::from_str(body.trim_end()).unwrap();
        assert_eq!(response["result"]["ok"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn handle_message_wraps_unknown_methods() {
        let mut connector = RedditConnector::new();
        let response = handle_message(
            &mut connector,
            r#"{"jsonrpc":"2.0","id":7,"method":"reddit.nope","params":{}}"#,
        )
        .await;

        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 7);
        assert_eq!(response["error"]["code"], -32000);
        assert!(
            response["error"]["message"]
                .as_str()
                .unwrap()
                .contains("Unknown method: reddit.nope")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn execute_request_surfaces_runtime_bridge_errors_as_json() {
        let mut connector = RedditConnector::new();
        let response = execute_request(
            &mut connector,
            r#"{"jsonrpc":"2.0","id":1,"method":"health","params":{}}"#,
        );

        assert_eq!(response["jsonrpc"], "2.0");
        assert!(response["id"].is_null());
        assert_eq!(response["error"]["code"], "FCP-9001");
        assert!(
            response["error"]["message"]
                .as_str()
                .unwrap()
                .starts_with("Runtime error:")
        );
    }
}
