//! FCP `Reddit` Connector binary.

use std::io::{BufRead, Write};

use fcp_reddit::connector::RedditConnector;
use serde_json::json;

fn main() {
    tracing_subscriber::fmt::init();
    let mut connector = RedditConnector::new();
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();

    for line in stdin.lock().lines() {
        let Ok(line) = line else {
            break;
        };
        if line.trim().is_empty() {
            continue;
        }

        let req: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let _ = writeln!(
                    stdout.lock(),
                    "{}",
                    json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":e.to_string()}})
                );
                continue;
            }
        };

        let id = req.get("id").cloned();
        let method = req
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or("")
            .to_string();
        let params = req.get("params").cloned().unwrap_or_else(|| json!({}));

        let rt = fcp_async_core::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let result = rt.block_on(async {
            match method.as_str() {
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
            }
        });

        let resp = match result {
            Ok(val) => json!({"jsonrpc":"2.0","id":id,"result":val}),
            Err(e) => {
                json!({"jsonrpc":"2.0","id":id,"error":{"code":-32000,"message":e.to_string()}})
            }
        };
        let _ = writeln!(stdout.lock(), "{resp}");
    }
}
