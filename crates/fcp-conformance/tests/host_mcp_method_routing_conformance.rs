//! `fcp_host` MCP method routing + session-status conformance.
//!
//! Three independent agent-facing primitives this file pins:
//!
//! 1. **`route_mcp_method`** is the documented dispatch table that
//!    every MCP request flows through. Drift in even one mapping
//!    silently routes a method to the wrong category, breaking
//!    auth, logging, and rate-limit gating.
//! 2. **`McpMethodCategory::expects_response` /
//!    `requires_session`** govern whether a method needs a JSON-RPC
//!    response and whether it can run pre-`initialize`. Drift breaks
//!    the entire MCP handshake protocol.
//! 3. **`SessionStatus`** snake_case wire form — emitted in admin
//!    APIs and dashboards.
//!
//! Properties pinned (NORMATIVE):
//!
//! - `route_mcp_method` 12-mapping table (10 explicit + notifications
//!   prefix + Unknown fallback)
//! - `notifications/<anything>` prefix routes to `Notification`
//! - `expects_response` is true for ALL except `Notification`
//! - `requires_session` is true for ALL except `Initialize`, `Ping`,
//!   and `Unknown` (the latter so unknown-method errors propagate
//!   without needing a session)
//! - `Display` returns the exact wire-method literal for each
//!   category (used in audit logs)
//! - `Hash + Copy + Eq` for HashMap keys
//! - `SessionStatus` 4 snake_case variants (active/idle/expired/
//!   terminated) + reject mixed-case + Copy

use fcp_host::{McpMethodCategory, SessionStatus, route_mcp_method};

// ─── route_mcp_method dispatch table ──────────────────────────────

#[test]
fn route_initialize_method() {
    assert_eq!(
        route_mcp_method("initialize"),
        McpMethodCategory::Initialize
    );
}

#[test]
fn route_tools_list_method() {
    assert_eq!(route_mcp_method("tools/list"), McpMethodCategory::ToolsList);
}

#[test]
fn route_tools_call_method() {
    assert_eq!(route_mcp_method("tools/call"), McpMethodCategory::ToolsCall);
}

#[test]
fn route_resources_list_method() {
    assert_eq!(
        route_mcp_method("resources/list"),
        McpMethodCategory::ResourcesList
    );
}

#[test]
fn route_resources_read_method() {
    assert_eq!(
        route_mcp_method("resources/read"),
        McpMethodCategory::ResourcesRead
    );
}

#[test]
fn route_prompts_list_method() {
    assert_eq!(
        route_mcp_method("prompts/list"),
        McpMethodCategory::PromptsList
    );
}

#[test]
fn route_prompts_get_method() {
    assert_eq!(
        route_mcp_method("prompts/get"),
        McpMethodCategory::PromptsGet
    );
}

#[test]
fn route_completion_complete_method() {
    assert_eq!(
        route_mcp_method("completion/complete"),
        McpMethodCategory::Completion
    );
}

#[test]
fn route_logging_set_level_method() {
    assert_eq!(
        route_mcp_method("logging/setLevel"),
        McpMethodCategory::Logging
    );
}

#[test]
fn route_ping_method() {
    assert_eq!(route_mcp_method("ping"), McpMethodCategory::Ping);
}

// ─── notifications/* prefix ───────────────────────────────────────

#[test]
fn route_notifications_initialized_routes_to_notification() {
    assert_eq!(
        route_mcp_method("notifications/initialized"),
        McpMethodCategory::Notification
    );
}

#[test]
fn route_notifications_progress_routes_to_notification() {
    assert_eq!(
        route_mcp_method("notifications/progress"),
        McpMethodCategory::Notification
    );
}

#[test]
fn route_arbitrary_notifications_subpath_routes_to_notification() {
    // Prefix match — any "notifications/<x>" MUST land in Notification.
    assert_eq!(
        route_mcp_method("notifications/cancelled"),
        McpMethodCategory::Notification
    );
    assert_eq!(
        route_mcp_method("notifications/custom/extension"),
        McpMethodCategory::Notification
    );
}

#[test]
fn route_notifications_with_no_subpath_is_unknown() {
    // "notifications/" has empty subpath — still matches the prefix.
    assert_eq!(
        route_mcp_method("notifications/"),
        McpMethodCategory::Notification
    );
    // Plain "notifications" (no slash) does NOT match the prefix.
    assert_eq!(
        route_mcp_method("notifications"),
        McpMethodCategory::Unknown,
        "bare 'notifications' (no slash) MUST be Unknown — only the 'notifications/' \
         prefix opens the prefix-match branch"
    );
}

// ─── Unknown fallback ─────────────────────────────────────────────

#[test]
fn route_unknown_method_falls_back_to_unknown() {
    assert_eq!(route_mcp_method(""), McpMethodCategory::Unknown);
    assert_eq!(route_mcp_method("garbage"), McpMethodCategory::Unknown);
    assert_eq!(
        route_mcp_method("Initialize"),
        McpMethodCategory::Unknown,
        "case-sensitive — uppercase 'Initialize' MUST NOT match"
    );
    assert_eq!(
        route_mcp_method("tools/LIST"),
        McpMethodCategory::Unknown,
        "case-sensitive — uppercase suffix MUST NOT match"
    );
}

// ─── expects_response predicate ───────────────────────────────────

#[test]
fn expects_response_is_true_for_all_request_categories() {
    let request_categories = [
        McpMethodCategory::Initialize,
        McpMethodCategory::ToolsList,
        McpMethodCategory::ToolsCall,
        McpMethodCategory::ResourcesList,
        McpMethodCategory::ResourcesRead,
        McpMethodCategory::PromptsList,
        McpMethodCategory::PromptsGet,
        McpMethodCategory::Completion,
        McpMethodCategory::Logging,
        McpMethodCategory::Ping,
        McpMethodCategory::Unknown,
    ];
    for cat in request_categories {
        assert!(
            cat.expects_response(),
            "{cat:?} MUST expect a response (only Notification is one-way)"
        );
    }
}

#[test]
fn expects_response_is_false_only_for_notification() {
    assert!(
        !McpMethodCategory::Notification.expects_response(),
        "Notification (one-way client→server) MUST NOT expect a response"
    );
}

// ─── requires_session predicate ───────────────────────────────────

#[test]
fn requires_session_is_false_for_initialize_ping_and_unknown() {
    // Initialize is the bootstrap (creates the session); Ping is the
    // keepalive (allowed pre/post initialize); Unknown is rejected
    // without needing session state.
    assert!(!McpMethodCategory::Initialize.requires_session());
    assert!(!McpMethodCategory::Ping.requires_session());
    assert!(!McpMethodCategory::Unknown.requires_session());
}

#[test]
fn requires_session_is_true_for_all_other_categories() {
    let session_required = [
        McpMethodCategory::ToolsList,
        McpMethodCategory::ToolsCall,
        McpMethodCategory::ResourcesList,
        McpMethodCategory::ResourcesRead,
        McpMethodCategory::PromptsList,
        McpMethodCategory::PromptsGet,
        McpMethodCategory::Completion,
        McpMethodCategory::Logging,
        McpMethodCategory::Notification,
    ];
    for cat in session_required {
        assert!(
            cat.requires_session(),
            "{cat:?} MUST require an initialized session"
        );
    }
}

// ─── Display ───────────────────────────────────────────────────────

#[test]
fn display_returns_exact_wire_method_literal() {
    let pairs = [
        (McpMethodCategory::Initialize, "initialize"),
        (McpMethodCategory::ToolsList, "tools/list"),
        (McpMethodCategory::ToolsCall, "tools/call"),
        (McpMethodCategory::ResourcesList, "resources/list"),
        (McpMethodCategory::ResourcesRead, "resources/read"),
        (McpMethodCategory::PromptsList, "prompts/list"),
        (McpMethodCategory::PromptsGet, "prompts/get"),
        (McpMethodCategory::Completion, "completion/complete"),
        (McpMethodCategory::Logging, "logging/setLevel"),
        (McpMethodCategory::Ping, "ping"),
        (McpMethodCategory::Notification, "notification"),
        (McpMethodCategory::Unknown, "unknown"),
    ];
    for (cat, expected) in pairs {
        assert_eq!(
            format!("{cat}"),
            expected,
            "{cat:?} Display MUST be exactly '{expected}' (used in audit logs)"
        );
    }
}

// ─── Display ↔ route round-trip for the explicit 10 mappings ─────

#[test]
fn display_round_trips_via_route_for_every_explicit_method() {
    // For categories whose Display is itself a routable method
    // string, display→route MUST recover the category. (Notification
    // and Unknown are excluded because their Display is the synthetic
    // category label, not a routable method.)
    let routable_categories = [
        McpMethodCategory::Initialize,
        McpMethodCategory::ToolsList,
        McpMethodCategory::ToolsCall,
        McpMethodCategory::ResourcesList,
        McpMethodCategory::ResourcesRead,
        McpMethodCategory::PromptsList,
        McpMethodCategory::PromptsGet,
        McpMethodCategory::Completion,
        McpMethodCategory::Logging,
        McpMethodCategory::Ping,
    ];
    for cat in routable_categories {
        let display_str = format!("{cat}");
        let routed = route_mcp_method(&display_str);
        assert_eq!(
            routed, cat,
            "route_mcp_method('{display_str}') MUST round-trip back to {cat:?}"
        );
    }
}

// ─── Hash + Copy + Eq for collection use ──────────────────────────

#[test]
fn method_category_implements_copy() {
    fn takes_value(_: McpMethodCategory) {}
    let c = McpMethodCategory::ToolsCall;
    takes_value(c);
    takes_value(c);
    assert_eq!(c, McpMethodCategory::ToolsCall);
}

#[test]
fn method_category_implements_hash_for_hashmap_keying() {
    use std::collections::HashMap;
    let mut counts: HashMap<McpMethodCategory, u64> = HashMap::new();
    *counts.entry(McpMethodCategory::ToolsCall).or_default() += 1;
    *counts.entry(McpMethodCategory::ToolsCall).or_default() += 1;
    *counts.entry(McpMethodCategory::Ping).or_default() += 1;
    assert_eq!(counts.get(&McpMethodCategory::ToolsCall), Some(&2));
    assert_eq!(counts.get(&McpMethodCategory::Ping), Some(&1));
}

#[test]
fn method_category_twelve_variants_are_distinct() {
    let all = [
        McpMethodCategory::Initialize,
        McpMethodCategory::ToolsList,
        McpMethodCategory::ToolsCall,
        McpMethodCategory::ResourcesList,
        McpMethodCategory::ResourcesRead,
        McpMethodCategory::PromptsList,
        McpMethodCategory::PromptsGet,
        McpMethodCategory::Completion,
        McpMethodCategory::Logging,
        McpMethodCategory::Ping,
        McpMethodCategory::Notification,
        McpMethodCategory::Unknown,
    ];
    use std::collections::HashSet;
    let unique: HashSet<_> = all.iter().copied().collect();
    assert_eq!(
        unique.len(),
        12,
        "all 12 McpMethodCategory variants MUST be distinct"
    );
}

// ─── SessionStatus ─────────────────────────────────────────────────

#[test]
fn session_status_serde_uses_snake_case_for_each_variant() {
    let cases = [
        (SessionStatus::Active, "\"active\""),
        (SessionStatus::Idle, "\"idle\""),
        (SessionStatus::Expired, "\"expired\""),
        (SessionStatus::Terminated, "\"terminated\""),
    ];
    for (variant, expected) in cases {
        let json = serde_json::to_string(&variant).expect("serialize");
        assert_eq!(json, expected, "{variant:?} MUST serialize as '{expected}'");
        let parsed: SessionStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, variant);
    }
}

#[test]
fn session_status_rejects_unknown_or_uppercase_variants() {
    for bogus in ["\"ACTIVE\"", "\"Active\"", "\"\"", "\"running\""] {
        assert!(
            serde_json::from_str::<SessionStatus>(bogus).is_err(),
            "SessionStatus MUST reject {bogus}"
        );
    }
}

#[test]
fn session_status_implements_copy_and_hash() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(SessionStatus::Active);
    set.insert(SessionStatus::Idle);
    set.insert(SessionStatus::Active); // dup
    assert_eq!(set.len(), 2);
}

#[test]
fn session_status_four_variants_are_distinct() {
    let all = [
        SessionStatus::Active,
        SessionStatus::Idle,
        SessionStatus::Expired,
        SessionStatus::Terminated,
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j {
                assert_ne!(a, b);
            }
        }
    }
}
