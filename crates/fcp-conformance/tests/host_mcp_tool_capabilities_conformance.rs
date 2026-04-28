//! `fcp_host` MCP tool/list + tool/call + server capabilities
//! conformance.
//!
//! `host_mcp_initialize_resource_conformance.rs` covered server/
//! client info + resource list. This file pins the tools surface
//! plus the `McpServerCapabilities` matrix the host advertises
//! during initialize:
//!
//! - `McpToolListRequest` / `McpToolListEntry` / `McpToolListResponse`
//! - `McpToolCallRequest` (with `arguments` defaulting to `null`)
//! - `McpServerCapabilities` constructors (`with_tools`, `full`,
//!   `default==with_tools`) + `has_*` predicates
//! - `McpToolCapability` `listChanged` camelCase
//! - `McpLoggingCapability` (presence-indicator unit struct)
//! - `McpClientCapabilities` (sampling + roots optionals)
//!
//! Properties pinned (NORMATIVE):
//!
//! - `McpServerCapabilities::default == with_tools()` (just-tools
//!   advertisement is the documented default).
//! - `with_tools()` sets `tools.list_changed = Some(true)` and
//!   leaves resources/prompts/logging None.
//! - `full()` sets every capability with `list_changed = Some(true)`
//!   plus resource subscriptions.
//! - `has_tools` / `has_resources` / `has_prompts` predicates
//!   reflect Option presence.
//! - `McpToolListRequest` cursor skip-when-None; empty body when
//!   None.
//! - `McpToolListEntry`: `name` + `input_schema` required;
//!   `description` + `annotations` skip-when-None; `input_schema`
//!   is `inputSchema` camelCase.
//! - `McpToolListResponse`: `nextCursor` camelCase + skip-when-None.
//! - `McpToolCallRequest`: `name` required; `arguments` defaults to
//!   `null` when absent (serde `default`).
//! - `McpLoggingCapability` empty struct serializes to `{}`.
//! - `McpClientCapabilities` sampling + roots both skip-when-None.

use fcp_host::{
    McpClientCapabilities, McpLoggingCapability, McpServerCapabilities, McpToolCallRequest,
    McpToolCapability, McpToolListEntry, McpToolListRequest, McpToolListResponse,
};
use serde_json::json;

// ─── McpServerCapabilities constructors + predicates ──────────────

#[test]
fn server_capabilities_default_equals_with_tools() {
    let d = McpServerCapabilities::default();
    let w = McpServerCapabilities::with_tools();
    assert!(d.has_tools(), "default MUST advertise tools capability");
    assert!(w.has_tools());
    assert!(!d.has_resources(), "default MUST NOT advertise resources");
    assert!(!d.has_prompts(), "default MUST NOT advertise prompts");
}

#[test]
fn server_capabilities_with_tools_sets_list_changed_true() {
    let c = McpServerCapabilities::with_tools();
    let tools = c.tools.expect("tools MUST be Some");
    assert_eq!(
        tools.list_changed,
        Some(true),
        "with_tools MUST set tools.list_changed=Some(true)"
    );
}

#[test]
fn server_capabilities_full_advertises_every_capability() {
    let c = McpServerCapabilities::full();
    assert!(c.has_tools());
    assert!(c.has_resources());
    assert!(c.has_prompts());
    assert!(c.logging.is_some(), "full MUST include logging capability");
}

#[test]
fn server_capabilities_full_resources_carry_subscribe_and_list_changed() {
    let c = McpServerCapabilities::full();
    let res = c.resources.expect("resources Some");
    assert_eq!(res.subscribe, Some(true));
    assert_eq!(res.list_changed, Some(true));
}

#[test]
fn server_capabilities_serde_camelcase_for_list_changed() {
    let c = McpServerCapabilities::with_tools();
    let v = serde_json::to_value(&c).expect("serialize");
    // tools.listChanged at the nested level.
    assert_eq!(
        v["tools"]["listChanged"], true,
        "tools.list_changed MUST embed as 'listChanged'"
    );
}

#[test]
fn server_capabilities_omits_optional_capabilities_when_none() {
    let c = McpServerCapabilities::with_tools();
    let s = serde_json::to_string(&c).expect("serialize");
    assert!(
        !s.contains("\"resources\""),
        "resources=None MUST be omitted; got {s}"
    );
    assert!(
        !s.contains("\"prompts\""),
        "prompts=None MUST be omitted; got {s}"
    );
    assert!(
        !s.contains("\"logging\""),
        "logging=None MUST be omitted; got {s}"
    );
}

// ─── McpToolCapability ────────────────────────────────────────────

#[test]
fn tool_capability_list_changed_uses_camelcase() {
    let c = McpToolCapability {
        list_changed: Some(true),
    };
    let v = serde_json::to_value(&c).expect("serialize");
    assert_eq!(v["listChanged"], true);
    assert!(v.get("list_changed").is_none());
}

#[test]
fn tool_capability_omits_list_changed_when_none() {
    let c = McpToolCapability { list_changed: None };
    let s = serde_json::to_string(&c).expect("serialize");
    assert_eq!(
        s, "{}",
        "all-None McpToolCapability MUST serialize to '{{}}'"
    );
}

// ─── McpLoggingCapability ─────────────────────────────────────────

#[test]
fn logging_capability_serializes_to_empty_object() {
    let c = McpLoggingCapability {};
    let s = serde_json::to_string(&c).expect("serialize");
    assert_eq!(
        s, "{}",
        "McpLoggingCapability is a presence-indicator unit struct — MUST serialize to '{{}}'"
    );
}

// ─── McpClientCapabilities ────────────────────────────────────────

#[test]
fn client_capabilities_omits_sampling_and_roots_when_none() {
    let c = McpClientCapabilities {
        sampling: None,
        roots: None,
    };
    let s = serde_json::to_string(&c).expect("serialize");
    assert_eq!(
        s, "{}",
        "all-None McpClientCapabilities MUST serialize to '{{}}'"
    );
}

#[test]
fn client_capabilities_includes_populated_fields() {
    let c = McpClientCapabilities {
        sampling: Some(json!({"enabled": true})),
        roots: Some(json!([{"uri": "file:///x"}])),
    };
    let v = serde_json::to_value(&c).expect("serialize");
    assert_eq!(v["sampling"]["enabled"], true);
    assert_eq!(v["roots"][0]["uri"], "file:///x");
}

// ─── McpToolListRequest ───────────────────────────────────────────

#[test]
fn tool_list_request_omits_cursor_when_none() {
    let r = McpToolListRequest { cursor: None };
    let s = serde_json::to_string(&r).expect("serialize");
    assert_eq!(s, "{}");
}

#[test]
fn tool_list_request_includes_cursor_when_some() {
    let r = McpToolListRequest {
        cursor: Some("page-2-token".into()),
    };
    let v = serde_json::to_value(&r).expect("serialize");
    assert_eq!(v["cursor"], "page-2-token");
}

// ─── McpToolListEntry ─────────────────────────────────────────────

#[test]
fn tool_list_entry_serializes_input_schema_as_camelcase() {
    let e = McpToolListEntry {
        name: "send.message".into(),
        description: Some("send a message".into()),
        input_schema: json!({"type": "object"}),
        annotations: None,
    };
    let v = serde_json::to_value(&e).expect("serialize");
    assert_eq!(v["name"], "send.message");
    assert_eq!(v["description"], "send a message");
    assert_eq!(
        v["inputSchema"]["type"], "object",
        "input_schema MUST embed as 'inputSchema' (camelCase)"
    );
    assert!(v.get("input_schema").is_none());
}

#[test]
fn tool_list_entry_omits_description_and_annotations_when_none() {
    let e = McpToolListEntry {
        name: "bare".into(),
        description: None,
        input_schema: json!({}),
        annotations: None,
    };
    let s = serde_json::to_string(&e).expect("serialize");
    assert!(
        !s.contains("\"description\""),
        "description=None MUST be omitted; got {s}"
    );
    assert!(
        !s.contains("\"annotations\""),
        "annotations=None MUST be omitted; got {s}"
    );
    // name + inputSchema MUST appear.
    let v: serde_json::Value = serde_json::from_str(&s).expect("parse");
    assert!(v.get("name").is_some());
    assert!(v.get("inputSchema").is_some());
}

#[test]
fn tool_list_entry_serde_roundtrip_preserves_all_fields() {
    let e = McpToolListEntry {
        name: "echo".into(),
        description: Some("echo input".into()),
        input_schema: json!({"type": "object", "properties": {"text": {"type": "string"}}}),
        annotations: None,
    };
    let json_str = serde_json::to_string(&e).expect("serialize");
    let parsed: McpToolListEntry = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(parsed.name, e.name);
    assert_eq!(parsed.description, e.description);
    assert_eq!(parsed.input_schema, e.input_schema);
}

// ─── McpToolListResponse ──────────────────────────────────────────

#[test]
fn tool_list_response_omits_next_cursor_when_none() {
    let r = McpToolListResponse {
        tools: vec![],
        next_cursor: None,
    };
    let s = serde_json::to_string(&r).expect("serialize");
    assert!(
        !s.contains("nextCursor"),
        "next_cursor=None MUST be omitted; got {s}"
    );
}

#[test]
fn tool_list_response_serializes_next_cursor_as_camelcase_when_some() {
    let r = McpToolListResponse {
        tools: vec![],
        next_cursor: Some("p2".into()),
    };
    let v = serde_json::to_value(&r).expect("serialize");
    assert_eq!(v["nextCursor"], "p2");
    assert!(v.get("next_cursor").is_none());
}

// ─── McpToolCallRequest ───────────────────────────────────────────

#[test]
fn tool_call_request_arguments_defaults_to_null_when_absent_in_json() {
    // serde(default) on arguments: missing field MUST deserialize
    // as serde_json::Value::Null.
    let json_str = json!({"name": "ping"}).to_string();
    let parsed: McpToolCallRequest =
        serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(parsed.name, "ping");
    assert_eq!(
        parsed.arguments,
        serde_json::Value::Null,
        "arguments MUST default to Null when absent (serde(default))"
    );
}

#[test]
fn tool_call_request_carries_arguments_payload_when_present() {
    let req = McpToolCallRequest {
        name: "send.message".into(),
        arguments: json!({"to": "alice@example.com", "subject": "hi"}),
    };
    let json_str = serde_json::to_string(&req).expect("serialize");
    let parsed: McpToolCallRequest = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(parsed.name, "send.message");
    assert_eq!(parsed.arguments["to"], "alice@example.com");
    assert_eq!(parsed.arguments["subject"], "hi");
}

#[test]
fn tool_call_request_serde_roundtrip_preserves_arbitrary_arguments() {
    // arguments is serde_json::Value — accepts any JSON shape.
    for args in [
        json!(null),
        json!({}),
        json!([1, 2, 3]),
        json!({"nested": {"deep": ["a", "b"]}}),
    ] {
        let req = McpToolCallRequest {
            name: "x".into(),
            arguments: args.clone(),
        };
        let json_str = serde_json::to_string(&req).expect("serialize");
        let parsed: McpToolCallRequest =
            serde_json::from_str(&json_str).expect("deserialize");
        assert_eq!(parsed.arguments, args);
    }
}
