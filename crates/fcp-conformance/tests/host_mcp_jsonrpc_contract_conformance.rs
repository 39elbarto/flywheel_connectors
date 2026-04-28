//! `fcp_host` MCP JSON-RPC envelope and error-code conformance.
//!
//! These tests pin the agent-facing wire shape for JSON-RPC requests,
//! responses, and known MCP error codes.

use fcp_host::{
    McpErrorCode, McpJsonRpcError, McpJsonRpcErrorResponse, McpJsonRpcRequest, McpJsonRpcResponse,
};
use serde_json::json;

const ERROR_CODES: &[(McpErrorCode, i32, &str, bool)] = &[
    (
        McpErrorCode::InvalidRequest,
        -32600,
        "Invalid request",
        true,
    ),
    (
        McpErrorCode::MethodNotFound,
        -32601,
        "Method not found",
        true,
    ),
    (McpErrorCode::InvalidParams, -32602, "Invalid params", true),
    (McpErrorCode::InternalError, -32603, "Internal error", true),
    (McpErrorCode::ToolNotFound, -32001, "Tool not found", false),
    (
        McpErrorCode::ToolExecutionError,
        -32002,
        "Tool execution error",
        false,
    ),
    (
        McpErrorCode::ResourceNotFound,
        -32003,
        "Resource not found",
        false,
    ),
    (
        McpErrorCode::AuthenticationRequired,
        -32004,
        "Authentication required",
        false,
    ),
    (
        McpErrorCode::PermissionDenied,
        -32005,
        "Permission denied",
        false,
    ),
    (McpErrorCode::RateLimited, -32006, "Rate limited", false),
];

#[test]
fn mcp_error_codes_pin_numeric_wire_values_and_categories() {
    for &(code, wire, message, standard_jsonrpc) in ERROR_CODES {
        assert_eq!(code.code(), wire);
        assert_eq!(McpErrorCode::from_code(wire), Some(code));
        assert_eq!(code.default_message(), message);
        assert_eq!(code.is_standard_jsonrpc(), standard_jsonrpc);
        assert_eq!(code.is_mcp_specific(), !standard_jsonrpc);
        assert_eq!(
            serde_json::to_value(code).expect("serialize code"),
            json!(wire)
        );

        let parsed: McpErrorCode = serde_json::from_value(json!(wire)).expect("parse code");
        assert_eq!(parsed, code);
    }

    for unknown in [-32700, -32000, -32099, -1, 0, 200] {
        assert_eq!(McpErrorCode::from_code(unknown), None);
        assert!(serde_json::from_value::<McpErrorCode>(json!(unknown)).is_err());
    }
}

#[test]
fn jsonrpc_request_constructor_omits_absent_params_and_validates_version() {
    let request = McpJsonRpcRequest::new(json!("req-1"), "tools/list");
    assert!(request.is_valid());

    let value = serde_json::to_value(&request).expect("serialize request");
    assert_eq!(value["jsonrpc"], json!("2.0"));
    assert_eq!(value["id"], json!("req-1"));
    assert_eq!(value["method"], json!("tools/list"));
    assert!(value.get("params").is_none());

    let parsed: McpJsonRpcRequest = serde_json::from_value(value).expect("parse request");
    assert!(parsed.is_valid());

    let invalid_version = McpJsonRpcRequest {
        jsonrpc: "1.0".to_string(),
        id: json!(7),
        method: "ping".to_string(),
        params: None,
    };
    assert!(!invalid_version.is_valid());

    let empty_method = McpJsonRpcRequest::new(json!(7), "");
    assert!(!empty_method.is_valid());
}

#[test]
fn jsonrpc_request_with_params_preserves_structured_payload() {
    let request = McpJsonRpcRequest::with_params(
        json!(42),
        "tools/call",
        json!({
            "name": "fcp.test.echo",
            "arguments": { "message": "hello" }
        }),
    );

    let value = serde_json::to_value(&request).expect("serialize request");
    assert_eq!(value["jsonrpc"], json!("2.0"));
    assert_eq!(value["id"], json!(42));
    assert_eq!(value["params"]["name"], json!("fcp.test.echo"));
    assert_eq!(value["params"]["arguments"]["message"], json!("hello"));

    let parsed: McpJsonRpcRequest = serde_json::from_value(value).expect("parse request");
    assert!(parsed.is_valid());
    assert_eq!(
        parsed.params.expect("params present")["arguments"]["message"],
        json!("hello")
    );
}

#[test]
fn jsonrpc_success_response_contains_result_not_error() {
    let response = McpJsonRpcResponse::success(json!("req-2"), json!({ "ok": true }));

    let value = serde_json::to_value(&response).expect("serialize response");
    assert_eq!(value["jsonrpc"], json!("2.0"));
    assert_eq!(value["id"], json!("req-2"));
    assert_eq!(value["result"], json!({ "ok": true }));
    assert!(value.get("error").is_none());

    let parsed: McpJsonRpcResponse = serde_json::from_value(value).expect("parse response");
    assert_eq!(parsed.result, json!({ "ok": true }));
}

#[test]
fn jsonrpc_error_response_contains_error_not_result_and_omits_absent_data() {
    let response = McpJsonRpcErrorResponse {
        jsonrpc: "2.0".to_string(),
        id: json!("req-3"),
        error: McpJsonRpcError {
            code: McpErrorCode::InvalidParams.code(),
            message: McpErrorCode::InvalidParams.default_message().to_string(),
            data: None,
        },
    };

    let value = serde_json::to_value(&response).expect("serialize error response");
    assert_eq!(value["jsonrpc"], json!("2.0"));
    assert_eq!(value["id"], json!("req-3"));
    assert_eq!(value["error"]["code"], json!(-32602));
    assert_eq!(value["error"]["message"], json!("Invalid params"));
    assert!(value["error"].get("data").is_none());
    assert!(value.get("result").is_none());

    let parsed: McpJsonRpcErrorResponse =
        serde_json::from_value(value).expect("parse error response");
    assert_eq!(parsed.error.code, -32602);
    assert_eq!(parsed.error.data, None);
}

#[test]
fn jsonrpc_error_response_preserves_structured_data() {
    let response = McpJsonRpcErrorResponse {
        jsonrpc: "2.0".to_string(),
        id: serde_json::Value::Null,
        error: McpJsonRpcError {
            code: McpErrorCode::RateLimited.code(),
            message: McpErrorCode::RateLimited.default_message().to_string(),
            data: Some(json!({ "retry_after_ms": 1500 })),
        },
    };

    let value = serde_json::to_value(&response).expect("serialize error response");
    assert_eq!(value["id"], serde_json::Value::Null);
    assert_eq!(value["error"]["code"], json!(-32006));
    assert_eq!(value["error"]["data"]["retry_after_ms"], json!(1500));

    let parsed: McpJsonRpcErrorResponse =
        serde_json::from_value(value).expect("parse error response");
    assert_eq!(
        parsed.error.data.expect("data present")["retry_after_ms"],
        json!(1500)
    );
}
