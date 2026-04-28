//! `fcp_host` MCP initialize-handshake + resource-list + session-
//! predicate conformance.
//!
//! Three groups:
//!
//! 1. **Initialize handshake** — `McpServerInfo`, `McpClientInfo`,
//!    `McpInitializeResponse`, `McpServerCapabilities` constituents.
//!    The `fcp_host()` and `fcp_default()` constructors set
//!    documented identity + protocol-version fallback.
//! 2. **Resource list** — `McpResourceListRequest`/`McpResourceEntry`/
//!    `McpResourceListResponse` with camelCase serde + skip-when-None.
//! 3. **SessionStatus predicates** — `is_alive` / `is_ended` /
//!    `Display` (complement to host_mcp_method_routing_conformance
//!    which pinned only the serde wire form + distinctness).
//!
//! Properties pinned (NORMATIVE):
//!
//! - `McpServerInfo::fcp_host()` returns name="fcp-host" and
//!   version=non-empty (CARGO_PKG_VERSION at compile time).
//! - `McpInitializeResponse::fcp_default(V2025_03)` keeps
//!   protocol_version=V2025_03; same for V2024_11 (negotiation
//!   accepts both supported versions).
//! - `McpServerInfo` and `McpClientInfo` use camelCase serde
//!   (no rename effect since fields are single-token, but pin the
//!   roundtrip).
//! - `McpResourceEntry.mime_type` serializes as `mimeType`
//!   (camelCase rename, matching MCP spec).
//! - `McpResourceEntry` description and mime_type skip-when-None.
//! - `McpResourceListRequest.cursor` skip-when-None.
//! - `McpResourceListResponse.next_cursor` serializes as
//!   `nextCursor` and skip-when-None; `resources` is required.
//! - `McpResourceCapability.subscribe` / `list_changed` →
//!   `subscribe` / `listChanged` camelCase.
//! - `McpPromptCapability.list_changed` → `listChanged`.
//! - `SessionStatus::is_alive` ⇔ {Active, Idle}.
//! - `SessionStatus::is_ended` ⇔ {Expired, Terminated}.
//! - `SessionStatus::Display` returns the snake_case string for each.

use fcp_host::{
    McpClientInfo, McpInitializeResponse, McpProtocolVersion, McpPromptCapability,
    McpResourceCapability, McpResourceEntry, McpResourceListRequest, McpResourceListResponse,
    McpServerInfo, SessionStatus,
};

// ─── McpServerInfo + McpClientInfo + McpInitializeResponse ───────

#[test]
fn server_info_fcp_host_uses_documented_name() {
    let info = McpServerInfo::fcp_host();
    assert_eq!(
        info.name, "fcp-host",
        "McpServerInfo::fcp_host MUST identify as 'fcp-host'"
    );
    assert!(
        !info.version.is_empty(),
        "version MUST be non-empty (CARGO_PKG_VERSION)"
    );
}

#[test]
fn server_info_serde_roundtrip_preserves_name_and_version() {
    let info = McpServerInfo {
        name: "test-server".into(),
        version: "1.2.3".into(),
    };
    let json_str = serde_json::to_string(&info).expect("serialize");
    let parsed: McpServerInfo = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(parsed.name, info.name);
    assert_eq!(parsed.version, info.version);
}

#[test]
fn client_info_serde_roundtrip() {
    let info = McpClientInfo {
        name: "test-client".into(),
        version: "0.9.0".into(),
    };
    let json_str = serde_json::to_string(&info).expect("serialize");
    let parsed: McpClientInfo = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(parsed.name, info.name);
    assert_eq!(parsed.version, info.version);
}

#[test]
fn initialize_response_fcp_default_keeps_v2025_03() {
    let resp = McpInitializeResponse::fcp_default(McpProtocolVersion::V2025_03);
    assert_eq!(
        resp.protocol_version,
        McpProtocolVersion::V2025_03,
        "fcp_default(V2025_03) MUST keep protocol_version=V2025_03"
    );
    assert_eq!(resp.server_info.name, "fcp-host");
}

#[test]
fn initialize_response_fcp_default_keeps_v2024_11() {
    let resp = McpInitializeResponse::fcp_default(McpProtocolVersion::V2024_11);
    assert_eq!(
        resp.protocol_version,
        McpProtocolVersion::V2024_11,
        "fcp_default(V2024_11) MUST keep protocol_version=V2024_11 \
         (both supported versions are accepted)"
    );
}

// ─── McpResourceCapability + McpPromptCapability camelCase ────────

#[test]
fn resource_capability_uses_camelcase_for_list_changed() {
    let cap = McpResourceCapability {
        subscribe: Some(true),
        list_changed: Some(false),
    };
    let v = serde_json::to_value(&cap).expect("serialize");
    assert_eq!(v["subscribe"], true);
    assert_eq!(
        v["listChanged"], false,
        "list_changed MUST embed as 'listChanged' (camelCase)"
    );
    assert!(v.get("list_changed").is_none());
}

#[test]
fn resource_capability_omits_optional_fields_when_none() {
    let cap = McpResourceCapability {
        subscribe: None,
        list_changed: None,
    };
    let s = serde_json::to_string(&cap).expect("serialize");
    assert!(!s.contains("subscribe"), "subscribe=None MUST be omitted; got {s}");
    assert!(!s.contains("listChanged"), "list_changed=None MUST be omitted; got {s}");
}

#[test]
fn prompt_capability_uses_camelcase_for_list_changed() {
    let cap = McpPromptCapability {
        list_changed: Some(true),
    };
    let v = serde_json::to_value(&cap).expect("serialize");
    assert_eq!(v["listChanged"], true);
    assert!(v.get("list_changed").is_none());
}

// ─── McpResourceListRequest ───────────────────────────────────────

#[test]
fn resource_list_request_omits_cursor_when_none() {
    let req = McpResourceListRequest { cursor: None };
    let s = serde_json::to_string(&req).expect("serialize");
    assert!(!s.contains("cursor"), "cursor=None MUST be omitted; got {s}");
    // Empty body when no fields set.
    assert_eq!(s, "{}");
}

#[test]
fn resource_list_request_includes_cursor_when_some() {
    let req = McpResourceListRequest {
        cursor: Some("opaque-cursor-token".into()),
    };
    let v = serde_json::to_value(&req).expect("serialize");
    assert_eq!(v["cursor"], "opaque-cursor-token");
}

// ─── McpResourceEntry ─────────────────────────────────────────────

#[test]
fn resource_entry_serializes_mime_type_as_camelcase() {
    let e = McpResourceEntry {
        uri: "file:///x.txt".into(),
        name: "doc".into(),
        description: Some("a text file".into()),
        mime_type: Some("text/plain".into()),
    };
    let v = serde_json::to_value(&e).expect("serialize");
    assert_eq!(v["uri"], "file:///x.txt");
    assert_eq!(v["name"], "doc");
    assert_eq!(v["description"], "a text file");
    assert_eq!(
        v["mimeType"], "text/plain",
        "mime_type MUST embed as 'mimeType' camelCase rename"
    );
    // Snake-case form MUST NOT appear.
    assert!(v.get("mime_type").is_none());
}

#[test]
fn resource_entry_omits_description_and_mime_type_when_none() {
    let e = McpResourceEntry {
        uri: "file:///x".into(),
        name: "doc".into(),
        description: None,
        mime_type: None,
    };
    let s = serde_json::to_string(&e).expect("serialize");
    assert!(
        !s.contains("\"description\""),
        "description=None MUST be omitted; got {s}"
    );
    assert!(
        !s.contains("mimeType"),
        "mime_type=None MUST be omitted (camelCase form); got {s}"
    );
    // uri + name MUST appear.
    let v: serde_json::Value = serde_json::from_str(&s).expect("parse");
    assert_eq!(v["uri"], "file:///x");
    assert_eq!(v["name"], "doc");
}

#[test]
fn resource_entry_serde_roundtrip_preserves_all_four_fields() {
    let e = McpResourceEntry {
        uri: "file:///deep/path.json".into(),
        name: "config".into(),
        description: Some("daemon config".into()),
        mime_type: Some("application/json".into()),
    };
    let json_str = serde_json::to_string(&e).expect("serialize");
    let parsed: McpResourceEntry = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(parsed.uri, e.uri);
    assert_eq!(parsed.name, e.name);
    assert_eq!(parsed.description, e.description);
    assert_eq!(parsed.mime_type, e.mime_type);
}

// ─── McpResourceListResponse ──────────────────────────────────────

#[test]
fn resource_list_response_omits_next_cursor_when_none() {
    let resp = McpResourceListResponse {
        resources: vec![],
        next_cursor: None,
    };
    let s = serde_json::to_string(&resp).expect("serialize");
    assert!(
        !s.contains("nextCursor"),
        "next_cursor=None MUST be omitted (camelCase form); got {s}"
    );
    // resources MUST appear (non-optional vec).
    let v: serde_json::Value = serde_json::from_str(&s).expect("parse");
    assert!(v.get("resources").is_some());
}

#[test]
fn resource_list_response_serializes_next_cursor_as_camelcase_when_some() {
    let resp = McpResourceListResponse {
        resources: vec![],
        next_cursor: Some("next-page-token".into()),
    };
    let v = serde_json::to_value(&resp).expect("serialize");
    assert_eq!(
        v["nextCursor"], "next-page-token",
        "next_cursor MUST embed as 'nextCursor' camelCase rename"
    );
    assert!(v.get("next_cursor").is_none());
}

#[test]
fn resource_list_response_with_resources_round_trips() {
    let resp = McpResourceListResponse {
        resources: vec![
            McpResourceEntry {
                uri: "file:///a".into(),
                name: "a".into(),
                description: None,
                mime_type: None,
            },
            McpResourceEntry {
                uri: "file:///b".into(),
                name: "b".into(),
                description: Some("second".into()),
                mime_type: Some("text/plain".into()),
            },
        ],
        next_cursor: Some("token".into()),
    };
    let json_str = serde_json::to_string(&resp).expect("serialize");
    let parsed: McpResourceListResponse =
        serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(parsed.resources.len(), 2);
    assert_eq!(parsed.resources[0].uri, "file:///a");
    assert_eq!(parsed.resources[1].uri, "file:///b");
    assert_eq!(parsed.next_cursor.as_deref(), Some("token"));
}

// ─── SessionStatus predicates + Display ───────────────────────────

#[test]
fn session_status_is_alive_covers_active_and_idle() {
    assert!(SessionStatus::Active.is_alive());
    assert!(
        SessionStatus::Idle.is_alive(),
        "Idle MUST be alive — session is suspended, not ended"
    );
    assert!(!SessionStatus::Expired.is_alive());
    assert!(!SessionStatus::Terminated.is_alive());
}

#[test]
fn session_status_is_ended_covers_expired_and_terminated() {
    assert!(!SessionStatus::Active.is_ended());
    assert!(!SessionStatus::Idle.is_ended());
    assert!(SessionStatus::Expired.is_ended());
    assert!(SessionStatus::Terminated.is_ended());
}

#[test]
fn session_status_is_alive_and_is_ended_partition_all_variants() {
    let all = [
        SessionStatus::Active,
        SessionStatus::Idle,
        SessionStatus::Expired,
        SessionStatus::Terminated,
    ];
    for variant in all {
        assert_ne!(
            variant.is_alive(),
            variant.is_ended(),
            "{variant:?} MUST be exactly one of alive/ended (XOR)"
        );
    }
}

#[test]
fn session_status_display_uses_snake_case_for_each_variant() {
    assert_eq!(format!("{}", SessionStatus::Active), "active");
    assert_eq!(format!("{}", SessionStatus::Idle), "idle");
    assert_eq!(format!("{}", SessionStatus::Expired), "expired");
    assert_eq!(format!("{}", SessionStatus::Terminated), "terminated");
}
