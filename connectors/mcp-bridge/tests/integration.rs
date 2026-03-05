//! Integration tests for the FCP MCP Bridge connector.

#![allow(
    clippy::cast_possible_truncation,
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use serde_json::json;
use wiremock::matchers::{body_partial_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_mcp_bridge::connector::McpBridgeConnector;

async fn setup_connector(mock_url: &str) -> McpBridgeConnector {
    let mut c = McpBridgeConnector::new();
    c.handle_configure(json!({
        "mcp_url": mock_url,
        "api_key": "test-api-key",
    }))
    .await
    .unwrap();
    c.handle_handshake(json!({"session_id": "test"}))
        .await
        .unwrap();
    c
}

async fn setup_connector_no_auth(mock_url: &str) -> McpBridgeConnector {
    let mut c = McpBridgeConnector::new();
    c.handle_configure(json!({
        "mcp_url": mock_url,
    }))
    .await
    .unwrap();
    c.handle_handshake(json!({"session_id": "test"}))
        .await
        .unwrap();
    c
}

// -- Lifecycle ---------------------------------------------------------------

#[tokio::test]
async fn lifecycle_health_unconfigured() {
    let c = McpBridgeConnector::new();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "unconfigured");
}

#[tokio::test]
async fn lifecycle_full() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "healthy");
}

#[tokio::test]
async fn lifecycle_handshake_before_configure_fails() {
    let mut c = McpBridgeConnector::new();
    assert!(c.handle_handshake(json!({})).await.is_err());
}

#[tokio::test]
async fn lifecycle_shutdown() {
    let server = MockServer::start().await;
    let mut c = setup_connector(&server.uri()).await;
    c.handle_shutdown(json!({})).await.unwrap();
    assert_eq!(c.handle_health().await.unwrap()["status"], "unconfigured");
}

#[tokio::test]
async fn lifecycle_self_check() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "ready");
}

#[tokio::test]
async fn lifecycle_self_check_unconfigured() {
    let c = McpBridgeConnector::new();
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "unconfigured");
}

#[tokio::test]
async fn lifecycle_doctor() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert_eq!(c.handle_doctor().await.unwrap()["status"], "healthy");
}

#[tokio::test]
async fn lifecycle_doctor_unconfigured() {
    let c = McpBridgeConnector::new();
    assert_eq!(c.handle_doctor().await.unwrap()["status"], "unhealthy");
}

#[tokio::test]
async fn lifecycle_introspect() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    assert_eq!(intro["operations"].as_array().unwrap().len(), 5);
}

#[tokio::test]
async fn lifecycle_health_configured_not_handshaken() {
    let mut c = McpBridgeConnector::new();
    c.handle_configure(json!({
        "mcp_url": "http://localhost:3000",
    }))
    .await
    .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "degraded");
}

// -- tools/list --------------------------------------------------------------

#[tokio::test]
async fn tools_list_basic() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(header("Authorization", "Bearer test-api-key"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [
                    {
                        "name": "read_file",
                        "description": "Read a file from disk",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"path": {"type": "string"}},
                            "required": ["path"]
                        }
                    },
                    {
                        "name": "list_dir",
                        "description": "List directory contents"
                    }
                ]
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "mcp.tools.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["tools"].as_array().unwrap().len(), 2);
    assert_eq!(result["tools"][0]["name"], "read_file");
}

#[tokio::test]
async fn tools_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": []}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "mcp.tools.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["tools"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn tools_list_without_auth() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "ping"}]}
        })))
        .mount(&server)
        .await;

    let c = setup_connector_no_auth(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "mcp.tools.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["tools"].as_array().unwrap().len(), 1);
}

// -- tools/call --------------------------------------------------------------

#[tokio::test]
async fn tools_call_basic() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {"path": "/tmp/data.txt"}
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [
                    {"type": "text", "text": "file contents here"}
                ]
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "mcp.tools.call",
            "input": {
                "name": "read_file",
                "arguments": {"path": "/tmp/data.txt"}
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["content"][0]["text"], "file contents here");
}

#[tokio::test]
async fn tools_call_missing_name() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mcp.tools.call",
            "input": {"arguments": {"key": "value"}}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn tools_call_with_empty_arguments() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({
            "method": "tools/call",
            "params": {"name": "ping"}
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [{"type": "text", "text": "pong"}]
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "mcp.tools.call",
            "input": {"name": "ping"}
        }))
        .await
        .unwrap();
    assert_eq!(result["content"][0]["text"], "pong");
}

#[tokio::test]
async fn tools_call_invalid_arguments_type() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mcp.tools.call",
            "input": {
                "name": "test_tool",
                "arguments": "not an object"
            }
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn tools_call_with_complex_result() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/call"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [
                    {"type": "text", "text": "line 1"},
                    {"type": "text", "text": "line 2"},
                    {"type": "image", "data": "base64data", "mimeType": "image/png"}
                ],
                "isError": false
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "mcp.tools.call",
            "input": {"name": "multi_result", "arguments": {}}
        }))
        .await
        .unwrap();
    assert_eq!(result["content"].as_array().unwrap().len(), 3);
}

// -- resources/list ----------------------------------------------------------

#[tokio::test]
async fn resources_list_basic() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "resources/list"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "resources": [
                    {
                        "uri": "file:///tmp/data.txt",
                        "name": "data.txt",
                        "mimeType": "text/plain"
                    },
                    {
                        "uri": "file:///tmp/config.json",
                        "name": "config.json",
                        "mimeType": "application/json"
                    }
                ]
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "mcp.resources.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["resources"].as_array().unwrap().len(), 2);
    assert_eq!(result["resources"][0]["uri"], "file:///tmp/data.txt");
}

#[tokio::test]
async fn resources_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "resources/list"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"resources": []}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "mcp.resources.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["resources"].as_array().unwrap().is_empty());
}

// -- resources/read ----------------------------------------------------------

#[tokio::test]
async fn resources_read_text() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({
            "method": "resources/read",
            "params": {"uri": "file:///tmp/data.txt"}
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "contents": [
                    {
                        "uri": "file:///tmp/data.txt",
                        "mimeType": "text/plain",
                        "text": "Hello, world!"
                    }
                ]
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "mcp.resources.read",
            "input": {"uri": "file:///tmp/data.txt"}
        }))
        .await
        .unwrap();
    assert_eq!(result["contents"][0]["text"], "Hello, world!");
}

#[tokio::test]
async fn resources_read_binary() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "resources/read"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "contents": [
                    {
                        "uri": "file:///tmp/image.png",
                        "mimeType": "image/png",
                        "blob": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGNgYPgPAAEDAQAIicLsAAAAASUVORK5CYII="
                    }
                ]
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "mcp.resources.read",
            "input": {"uri": "file:///tmp/image.png"}
        }))
        .await
        .unwrap();
    assert!(result["contents"][0]["blob"].as_str().is_some());
}

#[tokio::test]
async fn resources_read_missing_uri() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mcp.resources.read",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- prompts/list ------------------------------------------------------------

#[tokio::test]
async fn prompts_list_basic() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "prompts/list"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "prompts": [
                    {
                        "name": "summarize",
                        "description": "Summarize text",
                        "arguments": [
                            {"name": "text", "description": "Text to summarize", "required": true}
                        ]
                    },
                    {
                        "name": "translate",
                        "description": "Translate text"
                    }
                ]
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "mcp.prompts.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["prompts"].as_array().unwrap().len(), 2);
    assert_eq!(result["prompts"][0]["name"], "summarize");
}

#[tokio::test]
async fn prompts_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "prompts/list"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"prompts": []}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "mcp.prompts.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["prompts"].as_array().unwrap().is_empty());
}

// -- JSON-RPC error handling -------------------------------------------------

#[tokio::test]
async fn jsonrpc_error_method_not_found() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32601,
                "message": "Method not found"
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mcp.tools.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn jsonrpc_error_invalid_params() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32602,
                "message": "Invalid params"
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mcp.tools.call",
            "input": {"name": "bad_tool", "arguments": {}}
        }))
        .await
        .is_err()
    );
}

// -- HTTP error handling -----------------------------------------------------

#[tokio::test]
async fn error_401() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(json!({"message": "Invalid API key"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mcp.tools.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn error_403() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({"message": "Forbidden"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mcp.tools.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn error_404() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"message": "Not found"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mcp.resources.read",
            "input": {"uri": "file:///nonexistent"}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({"message": "Too many requests"}))
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mcp.tools.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn error_500() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(json!({"message": "Internal server error"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mcp.tools.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Unknown op / Simulate ---------------------------------------------------

#[tokio::test]
async fn unknown_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mcp.nope",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn simulate_known_tools_list() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "mcp.tools.list"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[tokio::test]
async fn simulate_known_tools_call() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "mcp.tools.call"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[tokio::test]
async fn simulate_known_resources_list() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "mcp.resources.list"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[tokio::test]
async fn simulate_known_resources_read() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "mcp.resources.read"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[tokio::test]
async fn simulate_known_prompts_list() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "mcp.prompts.list"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[tokio::test]
async fn simulate_unknown() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        !c.handle_simulate(json!({"operation_id": "mcp.nope"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

// -- Counters ----------------------------------------------------------------

#[tokio::test]
async fn counters_increment() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": []}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "mcp.tools.list",
        "input": {}
    }))
    .await
    .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 0);
}

#[tokio::test]
async fn counters_error_increment() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(json!({"message": "Internal error"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "mcp.tools.list",
            "input": {}
        }))
        .await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 1);
}

#[tokio::test]
async fn counters_multiple_requests() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": []}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    for _ in 0..3 {
        c.handle_invoke(json!({
            "operation_id": "mcp.tools.list",
            "input": {}
        }))
        .await
        .unwrap();
    }
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 3);
    assert_eq!(h["errors"], 0);
}

// -- Handshake response ------------------------------------------------------

#[tokio::test]
async fn handshake_returns_capabilities() {
    let server = MockServer::start().await;
    let mut c = McpBridgeConnector::new();
    c.handle_configure(json!({
        "mcp_url": server.uri(),
    }))
    .await
    .unwrap();
    let hs = c
        .handle_handshake(json!({"session_id": "s1"}))
        .await
        .unwrap();
    assert_eq!(hs["connector_id"], "fcp.mcp-bridge");
    assert_eq!(hs["protocol_version"], "2.0");
    let caps = hs["capabilities"].as_array().unwrap();
    assert!(caps.iter().any(|c| c == "mcp.tools.read"));
    assert!(caps.iter().any(|c| c == "mcp.tools.write"));
    assert!(caps.iter().any(|c| c == "mcp.resources.read"));
    assert!(caps.iter().any(|c| c == "mcp.prompts.read"));
}

// -- Invoke before ready -----------------------------------------------------

#[tokio::test]
async fn invoke_before_configure_fails() {
    let c = McpBridgeConnector::new();
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mcp.tools.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Configure with various params -------------------------------------------

#[tokio::test]
async fn configure_without_api_key() {
    let mut c = McpBridgeConnector::new();
    let result = c
        .handle_configure(json!({
            "mcp_url": "http://localhost:3000",
        }))
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn configure_rejects_empty_url() {
    let mut c = McpBridgeConnector::new();
    let result = c
        .handle_configure(json!({
            "mcp_url": "",
        }))
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn configure_rejects_missing_url() {
    let mut c = McpBridgeConnector::new();
    let result = c.handle_configure(json!({})).await;
    assert!(result.is_err());
}
