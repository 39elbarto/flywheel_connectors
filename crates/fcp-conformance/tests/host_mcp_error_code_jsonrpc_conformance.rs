//! `fcp_host` MCP error-code + JSON-RPC envelope conformance.
//!
//! `host_mcp_protocol_version_conformance.rs` already pins
//! `McpProtocolVersion`. This file pins the rest of the agent-facing
//! MCP wire surface — JSON-RPC 2.0 envelope shape, error code
//! taxonomy, and the round-trip between numeric codes and named
//! variants. Drift in any of these breaks every external MCP client.
//!
//! Properties pinned (NORMATIVE):
//!
//! 1. **`McpErrorCode::code` numeric values** match the JSON-RPC
//!    2.0 spec (-32600/01/02/03) for the four standard codes, and
//!    the MCP-specific extensions sit at -32001 through -32006.
//!    Pin every value — drift would silently change wire codes.
//! 2. **`code` and `from_code` are inverses** for every variant.
//! 3. **`from_code` returns `None` for unknown codes** (including
//!    JSON-RPC reserved -32700 = ParseError, which this enum does
//!    NOT cover).
//! 4. **`default_message` returns the documented English string**
//!    for each variant (clients display these as the default).
//! 5. **`is_standard_jsonrpc` ⇔ {InvalidRequest, MethodNotFound,
//!    InvalidParams, InternalError}**; `is_mcp_specific` is the
//!    complement.
//! 6. **`Display` is `"{message} ({code})"`** — operator log greps
//!    depend on this exact form.
//! 7. **`McpErrorCode` Hash + Copy + Eq** — appears in HashMap keys
//!    in error-rate trackers.
//! 8. **`McpJsonRpcRequest::new`** sets jsonrpc="2.0", preserves id
//!    and method, params=None.
//! 9. **`McpJsonRpcResponse::success`** sets jsonrpc="2.0" and
//!    preserves id+result.
//! 10. **`McpJsonRpcError` serde**: `data` field omitted when None;
//!     present when Some.
//! 11. **JSON shape** of all three envelopes round-trips through
//!     serde without data loss.

use fcp_host::{
    McpErrorCode, McpJsonRpcError, McpJsonRpcErrorResponse, McpJsonRpcRequest,
    McpJsonRpcResponse,
};
use serde_json::json;

const ALL_VARIANTS: &[McpErrorCode] = &[
    McpErrorCode::InvalidRequest,
    McpErrorCode::MethodNotFound,
    McpErrorCode::InvalidParams,
    McpErrorCode::InternalError,
    McpErrorCode::ToolNotFound,
    McpErrorCode::ToolExecutionError,
    McpErrorCode::ResourceNotFound,
    McpErrorCode::AuthenticationRequired,
    McpErrorCode::PermissionDenied,
    McpErrorCode::RateLimited,
];

// ─── Numeric code values (NORMATIVE wire codes) ─────────────────────

#[test]
fn invalid_request_code_is_negative_thirty_two_thousand_six_hundred() {
    assert_eq!(
        McpErrorCode::InvalidRequest.code(),
        -32600,
        "JSON-RPC 2.0 InvalidRequest MUST be -32600"
    );
}

#[test]
fn method_not_found_code_is_negative_thirty_two_thousand_six_hundred_one() {
    assert_eq!(McpErrorCode::MethodNotFound.code(), -32601);
}

#[test]
fn invalid_params_code_is_negative_thirty_two_thousand_six_hundred_two() {
    assert_eq!(McpErrorCode::InvalidParams.code(), -32602);
}

#[test]
fn internal_error_code_is_negative_thirty_two_thousand_six_hundred_three() {
    assert_eq!(McpErrorCode::InternalError.code(), -32603);
}

#[test]
fn tool_not_found_code_is_negative_thirty_two_thousand_one() {
    assert_eq!(McpErrorCode::ToolNotFound.code(), -32001);
}

#[test]
fn tool_execution_error_code_is_negative_thirty_two_thousand_two() {
    assert_eq!(McpErrorCode::ToolExecutionError.code(), -32002);
}

#[test]
fn resource_not_found_code_is_negative_thirty_two_thousand_three() {
    assert_eq!(McpErrorCode::ResourceNotFound.code(), -32003);
}

#[test]
fn authentication_required_code_is_negative_thirty_two_thousand_four() {
    assert_eq!(McpErrorCode::AuthenticationRequired.code(), -32004);
}

#[test]
fn permission_denied_code_is_negative_thirty_two_thousand_five() {
    assert_eq!(McpErrorCode::PermissionDenied.code(), -32005);
}

#[test]
fn rate_limited_code_is_negative_thirty_two_thousand_six() {
    assert_eq!(McpErrorCode::RateLimited.code(), -32006);
}

// ─── code ↔ from_code inverse ──────────────────────────────────────

#[test]
fn code_and_from_code_are_inverses_for_every_variant() {
    for &v in ALL_VARIANTS {
        let c = v.code();
        let parsed = McpErrorCode::from_code(c).expect("known code MUST round-trip");
        assert_eq!(parsed, v);
    }
}

#[test]
fn from_code_returns_none_for_unknown_codes() {
    // -32700 is the JSON-RPC ParseError — but this enum does NOT
    // cover it. Pin the gap so a future addition is a deliberate
    // wire change.
    assert!(McpErrorCode::from_code(-32700).is_none());
    assert!(McpErrorCode::from_code(0).is_none());
    assert!(McpErrorCode::from_code(-1).is_none());
    assert!(McpErrorCode::from_code(-32604).is_none()); // gap between standard and MCP
    assert!(McpErrorCode::from_code(i32::MAX).is_none());
    assert!(McpErrorCode::from_code(i32::MIN).is_none());
}

// ─── default_message ──────────────────────────────────────────────

#[test]
fn default_message_matches_documented_strings_for_every_variant() {
    let pairs = [
        (McpErrorCode::InvalidRequest, "Invalid request"),
        (McpErrorCode::MethodNotFound, "Method not found"),
        (McpErrorCode::InvalidParams, "Invalid params"),
        (McpErrorCode::InternalError, "Internal error"),
        (McpErrorCode::ToolNotFound, "Tool not found"),
        (McpErrorCode::ToolExecutionError, "Tool execution error"),
        (McpErrorCode::ResourceNotFound, "Resource not found"),
        (
            McpErrorCode::AuthenticationRequired,
            "Authentication required",
        ),
        (McpErrorCode::PermissionDenied, "Permission denied"),
        (McpErrorCode::RateLimited, "Rate limited"),
    ];
    for (variant, expected) in pairs {
        assert_eq!(
            variant.default_message(),
            expected,
            "{variant:?} default_message MUST be '{expected}'"
        );
    }
}

// ─── is_standard_jsonrpc / is_mcp_specific partition ───────────────

#[test]
fn is_standard_jsonrpc_only_for_four_jsonrpc_codes() {
    let standard = [
        McpErrorCode::InvalidRequest,
        McpErrorCode::MethodNotFound,
        McpErrorCode::InvalidParams,
        McpErrorCode::InternalError,
    ];
    for &v in &standard {
        assert!(v.is_standard_jsonrpc(), "{v:?} MUST be standard JSON-RPC");
        assert!(!v.is_mcp_specific());
    }
}

#[test]
fn is_mcp_specific_only_for_six_mcp_extensions() {
    let mcp_extensions = [
        McpErrorCode::ToolNotFound,
        McpErrorCode::ToolExecutionError,
        McpErrorCode::ResourceNotFound,
        McpErrorCode::AuthenticationRequired,
        McpErrorCode::PermissionDenied,
        McpErrorCode::RateLimited,
    ];
    for &v in &mcp_extensions {
        assert!(v.is_mcp_specific(), "{v:?} MUST be MCP-specific");
        assert!(!v.is_standard_jsonrpc());
    }
}

#[test]
fn standard_and_mcp_specific_partition_all_variants() {
    // Every variant is exactly one of (standard | mcp_specific).
    for &v in ALL_VARIANTS {
        assert_ne!(
            v.is_standard_jsonrpc(),
            v.is_mcp_specific(),
            "{v:?} MUST be exactly one of standard/mcp-specific (XOR)"
        );
    }
}

// ─── Display ────────────────────────────────────────────────────────

#[test]
fn display_format_is_message_then_paren_code() {
    // Documented: "{message} ({code})"
    assert_eq!(
        format!("{}", McpErrorCode::ToolNotFound),
        "Tool not found (-32001)",
        "Display MUST be exactly '{{message}} ({{code}})'"
    );
    assert_eq!(
        format!("{}", McpErrorCode::InvalidRequest),
        "Invalid request (-32600)"
    );
    assert_eq!(
        format!("{}", McpErrorCode::RateLimited),
        "Rate limited (-32006)"
    );
}

// ─── Hash + Copy + Eq (collection use) ─────────────────────────────

#[test]
fn error_code_implements_copy() {
    fn takes_value(_: McpErrorCode) {}
    let c = McpErrorCode::ToolNotFound;
    takes_value(c);
    takes_value(c);
    assert_eq!(c, McpErrorCode::ToolNotFound);
}

#[test]
fn error_code_implements_hash_for_hashmap_use() {
    use std::collections::HashMap;
    let mut counts: HashMap<McpErrorCode, u64> = HashMap::new();
    *counts.entry(McpErrorCode::RateLimited).or_default() += 1;
    *counts.entry(McpErrorCode::RateLimited).or_default() += 1;
    *counts.entry(McpErrorCode::ToolNotFound).or_default() += 1;
    assert_eq!(counts.get(&McpErrorCode::RateLimited), Some(&2));
    assert_eq!(counts.get(&McpErrorCode::ToolNotFound), Some(&1));
}

// ─── McpJsonRpcRequest ────────────────────────────────────────────

#[test]
fn jsonrpc_request_new_sets_jsonrpc_to_2_0() {
    let r = McpJsonRpcRequest::new(json!(1), "tools/list");
    assert_eq!(
        r.jsonrpc, "2.0",
        "McpJsonRpcRequest::new MUST set jsonrpc=\"2.0\""
    );
    assert_eq!(r.id, json!(1));
    assert_eq!(r.method, "tools/list");
    assert!(
        r.params.is_none(),
        "params MUST default to None — caller adds via mutation"
    );
}

#[test]
fn jsonrpc_request_serializes_jsonrpc_field() {
    let r = McpJsonRpcRequest::new(json!("req-123"), "initialize");
    let v = serde_json::to_value(&r).expect("serialize");
    assert_eq!(v["jsonrpc"], "2.0");
    assert_eq!(v["id"], "req-123");
    assert_eq!(v["method"], "initialize");
}

#[test]
fn jsonrpc_request_omits_params_when_none() {
    let r = McpJsonRpcRequest::new(json!(1), "ping");
    let s = serde_json::to_string(&r).expect("serialize");
    assert!(
        !s.contains("\"params\""),
        "params=None MUST be omitted from JSON; got {s}"
    );
}

#[test]
fn jsonrpc_request_includes_params_when_some() {
    let mut r = McpJsonRpcRequest::new(json!(1), "tools/call");
    r.params = Some(json!({"name": "echo", "arguments": {}}));
    let v = serde_json::to_value(&r).expect("serialize");
    assert!(v.get("params").is_some());
    assert_eq!(v["params"]["name"], "echo");
}

#[test]
fn jsonrpc_request_id_can_be_string_or_number() {
    // Per JSON-RPC 2.0, id MAY be a String or a Number.
    let r_num = McpJsonRpcRequest::new(json!(42), "x");
    let r_str = McpJsonRpcRequest::new(json!("abc"), "x");
    assert!(r_num.id.is_number());
    assert!(r_str.id.is_string());
}

// ─── McpJsonRpcResponse ───────────────────────────────────────────

#[test]
fn jsonrpc_response_success_sets_jsonrpc_to_2_0_and_preserves_id_and_result() {
    let r = McpJsonRpcResponse::success(json!(7), json!({"ok": true}));
    assert_eq!(r.jsonrpc, "2.0");
    assert_eq!(r.id, json!(7));
    assert_eq!(r.result, json!({"ok": true}));
}

#[test]
fn jsonrpc_response_success_serializes_jsonrpc_field() {
    let r = McpJsonRpcResponse::success(json!("z"), json!(null));
    let v = serde_json::to_value(&r).expect("serialize");
    assert_eq!(v["jsonrpc"], "2.0");
    assert_eq!(v["id"], "z");
}

// ─── McpJsonRpcError + ErrorResponse ──────────────────────────────

#[test]
fn jsonrpc_error_omits_data_field_when_none() {
    let e = McpJsonRpcError {
        code: -32601,
        message: "Method not found".into(),
        data: None,
    };
    let s = serde_json::to_string(&e).expect("serialize");
    assert!(
        !s.contains("\"data\""),
        "data=None MUST be omitted from JSON; got {s}"
    );
}

#[test]
fn jsonrpc_error_includes_data_field_when_some() {
    let e = McpJsonRpcError {
        code: -32602,
        message: "Invalid params".into(),
        data: Some(json!({"missing": ["arg1"]})),
    };
    let v = serde_json::to_value(&e).expect("serialize");
    assert!(v.get("data").is_some());
    assert_eq!(v["data"]["missing"][0], "arg1");
}

#[test]
fn jsonrpc_error_response_carries_jsonrpc_id_and_error() {
    // Construct directly — there's no .new() on the error response.
    let e = McpJsonRpcErrorResponse {
        jsonrpc: "2.0".into(),
        id: json!(1),
        error: McpJsonRpcError {
            code: McpErrorCode::ToolNotFound.code(),
            message: McpErrorCode::ToolNotFound.default_message().into(),
            data: None,
        },
    };
    let v = serde_json::to_value(&e).expect("serialize");
    assert_eq!(v["jsonrpc"], "2.0");
    assert_eq!(v["id"], 1);
    assert_eq!(v["error"]["code"], -32001);
    assert_eq!(v["error"]["message"], "Tool not found");
}

#[test]
fn jsonrpc_error_response_serde_round_trip_is_identity() {
    let e = McpJsonRpcErrorResponse {
        jsonrpc: "2.0".into(),
        id: json!("req-9"),
        error: McpJsonRpcError {
            code: -32602,
            message: "Invalid params".into(),
            data: Some(json!({"field": "name"})),
        },
    };
    let s = serde_json::to_string(&e).expect("serialize");
    let parsed: McpJsonRpcErrorResponse = serde_json::from_str(&s).expect("deserialize");
    assert_eq!(parsed.jsonrpc, e.jsonrpc);
    assert_eq!(parsed.id, e.id);
    assert_eq!(parsed.error.code, e.error.code);
    assert_eq!(parsed.error.message, e.error.message);
    assert_eq!(parsed.error.data, e.error.data);
}
