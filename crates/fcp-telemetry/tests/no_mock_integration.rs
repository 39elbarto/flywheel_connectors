//! No-mock integration tests for `fcp-telemetry`.
//!
//! Tests cross-module interactions without external services:
//! - `TraceContext` (binary W3C) / `TelemetryContext` builder
//! - `RedactionPolicy` / `CapturedTrace` pipeline
//! - `TraceCapture` buffer management + JSON/CBOR roundtrips
//! - `CapabilityUsageStore` / `recommend_capabilities` / report
//! - `HealthResponse` builder + serialization
//! - Redact-sensitive logging pipeline
//! - `LegacyTraceContext` (`tracing_layer`) header inject/extract
//! - Metrics helpers (`Timer`, `TimerGuard`, counters, gauges)

use std::collections::HashMap;

use fcp_telemetry::{
    // usage.rs
    CapabilityRecommendationReport,
    CapabilitySuggestionKind,
    CapabilityUsageAggregate,
    CapabilityUsageStore,
    // context.rs
    ContextGuard,
    // tracing_layer re-exports
    FcpSpan,
    // export.rs
    HealthResponse,
    LegacyTraceContext,
    RecommendationConfig,
    SPAN_ID_SIZE,
    TRACE_FLAG_SAMPLED,
    TRACE_ID_SIZE,
    TRACEPARENT_HEADER,
    TRACESTATE_HEADER,
    // lib.rs
    TelemetryConfig,
    TelemetryContext,
    TelemetryError,
    TraceContext,
    TraceContextError,
    UsageTelemetryConfig,
    extract_trace_context,
    inject_trace_context,
    // metrics.rs
    metrics::{
        HealthStatusMetric, Timer, TimerGuard, decrement_gauge, get_counter, get_gauge,
        get_histogram, increment_counter, increment_counter_by, increment_gauge,
        record_diversity_violation, record_event_dropped, record_event_emitted, record_histogram,
        record_request_error, record_request_success, record_symbol_coverage, set_gauge,
        update_health_status, update_rate_limit,
    },
    prometheus_text_format,
    recommend_capabilities,
    // logging.rs
    redact_sensitive,
    // trace_capture.rs
    trace_capture::{
        AdmissionOutcome, CapturedTrace, GossipEvent, LeaseEvent, PolicyDecision, RedactionPolicy,
        RoutingDecision, SessionEvent, TRACE_VERSION, TraceCapture, TraceCaptureConfig, TraceError,
        TraceEvent, TraceExportFormat,
    },
};

use fcp_core::{CapabilityId, ConnectorId, OperationId, PrincipalId, SafetyTier, ZoneId};
use fcp_telemetry::{CapabilityUsageEvent, CapabilityUsageKey, CapabilityUsageOutcome};

// ============================================================================
// Helpers
// ============================================================================

fn make_routing(ts: u64, trace_id: &str) -> TraceEvent {
    TraceEvent::Routing(RoutingDecision {
        timestamp: ts,
        trace_id: trace_id.to_string(),
        source_node: "node-a".to_string(),
        target_node: Some("node-b".to_string()),
        object_id: "obj-1".to_string(),
        path_type: "direct".to_string(),
        decision: "routed".to_string(),
        reason: None,
    })
}

fn make_session(ts: u64, trace_id: &str, session_id: &str) -> TraceEvent {
    TraceEvent::Session(SessionEvent {
        timestamp: ts,
        trace_id: trace_id.to_string(),
        session_id: session_id.to_string(),
        kind: "established".to_string(),
        peer_node: "peer-1".to_string(),
        suite: Some("aes256-gcm".to_string()),
        failure_reason: None,
    })
}

fn make_usage_event(
    zone: ZoneId,
    connector: &'static str,
    capability: &'static str,
    tier: SafetyTier,
    outcome: CapabilityUsageOutcome,
    ts: u64,
) -> CapabilityUsageEvent {
    CapabilityUsageEvent::new(
        CapabilityUsageKey::new(
            zone,
            ConnectorId::from_static(connector),
            CapabilityId::from_static(capability),
        ),
        PrincipalId::new("user:alice").expect("valid principal"),
        tier,
        OperationId::from_static("op.test"),
        outcome,
        ts,
    )
}

// ============================================================================
// 1. TraceContext (binary W3C) cross-module tests
// ============================================================================

#[test]
fn trace_context_generate_and_traceparent_roundtrip() {
    let ctx = TraceContext::generate();
    let header = ctx.to_traceparent();
    let parsed = TraceContext::from_traceparent(&header).unwrap();

    assert_eq!(ctx.trace_id, parsed.trace_id);
    assert_eq!(ctx.span_id, parsed.span_id);
    assert_eq!(ctx.trace_flags, parsed.trace_flags);
}

#[test]
fn trace_context_new_span_preserves_trace_id() {
    let parent = TraceContext::generate();
    let child = parent.new_span();

    assert_eq!(parent.trace_id, child.trace_id);
    assert_ne!(parent.span_id, child.span_id);
    assert_eq!(parent.trace_flags, child.trace_flags);
}

#[test]
fn trace_context_sampled_flag_toggle() {
    let ctx = TraceContext::generate().with_sampled(false);
    assert!(!ctx.is_sampled());

    let ctx2 = ctx.with_sampled(true);
    assert!(ctx2.is_sampled());
}

#[test]
fn trace_context_with_trace_state_preserved_in_child() {
    let parent = TraceContext::generate().with_trace_state("vendor=data");
    let child = parent.new_span();
    assert_eq!(child.trace_state, Some("vendor=data".to_string()));
}

#[test]
fn trace_context_display_matches_traceparent() {
    let ctx = TraceContext::generate();
    assert_eq!(format!("{ctx}"), ctx.to_traceparent());
}

#[test]
fn trace_context_serde_roundtrip() {
    let ctx = TraceContext::generate().with_trace_state("fcp=test");
    let json = serde_json::to_string(&ctx).unwrap();
    let parsed: TraceContext = serde_json::from_str(&json).unwrap();

    assert_eq!(ctx.trace_id, parsed.trace_id);
    assert_eq!(ctx.span_id, parsed.span_id);
    assert_eq!(ctx.trace_flags, parsed.trace_flags);
}

#[test]
fn trace_context_from_traceparent_rejects_all_zero_trace_id() {
    let header = "00-00000000000000000000000000000000-b7ad6b7169203331-01";
    let err = TraceContext::from_traceparent(header).unwrap_err();
    assert!(matches!(err, TraceContextError::InvalidFormat(_)));
}

#[test]
fn trace_context_from_traceparent_rejects_all_zero_span_id() {
    let header = "00-0af7651916cd43dd8448eb211c80319c-0000000000000000-01";
    let err = TraceContext::from_traceparent(header).unwrap_err();
    assert!(matches!(err, TraceContextError::InvalidFormat(_)));
}

#[test]
fn trace_context_from_traceparent_rejects_unsupported_version() {
    let header = "01-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
    let err = TraceContext::from_traceparent(header).unwrap_err();
    assert!(matches!(err, TraceContextError::UnsupportedVersion(_)));
}

#[test]
fn trace_context_hex_accessors() {
    let ctx = TraceContext::new([0xAB; TRACE_ID_SIZE], [0xCD; SPAN_ID_SIZE]);
    assert_eq!(ctx.trace_id_hex(), "abababababababababababababababab");
    assert_eq!(ctx.span_id_hex(), "cdcdcdcdcdcdcdcd");
}

// ============================================================================
// 2. TelemetryContext builder + integration with TraceContext
// ============================================================================

#[test]
fn telemetry_context_with_trace_derives_correlation_id() {
    let ctx = TelemetryContext::with_trace();
    let trace_ctx = ctx.get_trace_context().expect("trace context present");
    let expected_corr = trace_ctx.trace_id_hex();
    assert_eq!(ctx.correlation_id, Some(expected_corr));
}

#[test]
fn telemetry_context_child_span_preserves_trace_id() {
    let parent = TelemetryContext::with_trace()
        .zone_id("z:work")
        .connector_id("fcp.test");
    let child = parent.child_span();

    let parent_tc = parent.get_trace_context().unwrap();
    let child_tc = child.get_trace_context().unwrap();

    assert_eq!(parent_tc.trace_id, child_tc.trace_id);
    assert_ne!(parent_tc.span_id, child_tc.span_id);
    assert_eq!(child.zone_id, Some("z:work".to_string()));
    assert_eq!(child.connector_id, Some("fcp.test".to_string()));
}

#[test]
fn telemetry_context_all_fields_includes_trace_fields() {
    let trace_ctx = TraceContext::generate().with_trace_state("fcp=v1");
    let telem_ctx = TelemetryContext::new()
        .trace_context(trace_ctx.clone())
        .zone_id("z:work")
        .connector_id("fcp.demo")
        .operation_id("op.read")
        .principal_id("user:bob")
        .node_id("node-42")
        .decision("allow")
        .reason_code("CAP_VALID");

    telem_ctx.add_field("custom_key", "custom_value");

    let fields = telem_ctx.all_fields();
    let field_map: HashMap<_, _> = fields.into_iter().collect();

    assert_eq!(field_map["trace_id"], trace_ctx.trace_id_hex());
    assert_eq!(field_map["span_id"], trace_ctx.span_id_hex());
    assert_eq!(field_map["trace_state"], "fcp=v1");
    assert_eq!(field_map["zone_id"], "z:work");
    assert_eq!(field_map["connector_id"], "fcp.demo");
    assert_eq!(field_map["operation_id"], "op.read");
    assert_eq!(field_map["principal_id"], "user:bob");
    assert_eq!(field_map["node_id"], "node-42");
    assert_eq!(field_map["decision"], "allow");
    assert_eq!(field_map["reason_code"], "CAP_VALID");
    assert_eq!(field_map["custom_key"], "custom_value");
}

#[test]
fn telemetry_context_request_id_in_all_fields() {
    let uuid = uuid::Uuid::new_v4();
    let ctx = TelemetryContext::new().request_id(uuid);
    let fields = ctx.all_fields();
    let field_map: HashMap<_, _> = fields.into_iter().collect();
    assert_eq!(field_map["request_id"], uuid.to_string());
}

#[test]
fn telemetry_context_clone_preserves_custom_fields() {
    let ctx = TelemetryContext::with_trace()
        .zone_id("z:test")
        .connector_id("fcp.clone");
    ctx.add_field("f1", "v1");
    ctx.add_field("f2", "v2");

    let cloned = ctx.clone();
    // Verify original is still usable after clone
    assert!(ctx.correlation_id.is_some());
    let fields = cloned.all_fields();
    let field_map: HashMap<_, _> = fields.into_iter().collect();
    assert_eq!(field_map["f1"], "v1");
    assert_eq!(field_map["f2"], "v2");
    assert_eq!(field_map["zone_id"], "z:test");
}

#[test]
fn context_guard_creates_span_without_panic() {
    let ctx = TelemetryContext::with_trace()
        .connector_id("fcp.guard-test")
        .operation_id("op.read");
    let _guard = ContextGuard::new(&ctx, "test_operation");
    // Guard dropped here without panic
}

// ============================================================================
// 3. RedactionPolicy ↔ CapturedTrace pipeline
// ============================================================================

#[test]
fn redaction_policy_applied_to_captured_trace() {
    let mut trace = CapturedTrace::new("redact-test");
    trace.push(make_session(1000, "t1", "secret-session-abc"));
    trace.push(make_routing(2000, "t1"));

    let policy = RedactionPolicy::default().with_field("session_id");
    let redacted = trace.with_redaction(&policy);

    assert!(redacted.redacted);
    assert_eq!(redacted.events.len(), 2);

    if let TraceEvent::Session(s) = &redacted.events[0] {
        assert_eq!(s.session_id, "[REDACTED]");
    } else {
        panic!("expected Session event at index 0");
    }
}

#[test]
fn redaction_policy_hash_produces_deterministic_output() {
    let policy = RedactionPolicy::default().with_hash_redacted(true);
    let v1 = policy.redact_value("my-secret");
    let v2 = policy.redact_value("my-secret");
    assert_eq!(v1, v2);
    assert!(v1.starts_with("[REDACTED:"));
    assert!(v1.ends_with(']'));

    let v3 = policy.redact_value("other-secret");
    assert_ne!(v1, v3);
}

#[test]
fn redaction_policy_custom_marker() {
    let policy = RedactionPolicy::none()
        .with_field("password")
        .with_marker("***REMOVED***");
    assert_eq!(policy.redact_value("anything"), "***REMOVED***");
}

#[test]
fn redaction_policy_prefix_matching() {
    let policy = RedactionPolicy::none()
        .with_prefix("x-auth-")
        .with_prefix("secret_");
    assert!(policy.should_redact("x-auth-token"));
    assert!(policy.should_redact("X-AUTH-BEARER")); // case insensitive
    assert!(policy.should_redact("secret_key"));
    assert!(!policy.should_redact("public-data"));
}

// ============================================================================
// 4. TraceCapture buffer management + serialization roundtrips
// ============================================================================

#[test]
fn trace_capture_records_and_snapshots() {
    let config = TraceCaptureConfig::new().enabled().with_max_events(100);
    let mut capture = TraceCapture::new("cap-1", config);
    capture.record(make_routing(100, "t1")).unwrap();
    capture.record(make_session(200, "t1", "sess-1")).unwrap();

    let snap = capture.snapshot();
    assert_eq!(snap.len(), 2);
    assert_eq!(snap.events[0].timestamp(), 100);
    assert_eq!(snap.events[1].timestamp(), 200);
}

#[test]
fn trace_capture_respects_max_events_limit() {
    let config = TraceCaptureConfig::new().enabled().with_max_events(2);
    let mut capture = TraceCapture::new("cap-limit", config);

    capture.record(make_routing(1, "t1")).unwrap();
    capture.record(make_routing(2, "t1")).unwrap();

    let err = capture.record(make_routing(3, "t1")).unwrap_err();
    assert!(matches!(err, TraceError::BufferFull));
}

#[test]
fn trace_capture_zero_sample_rate_drops_events() {
    let config = TraceCaptureConfig::new().enabled().with_sample_rate(0.0);
    let mut capture = TraceCapture::new("cap-nosample", config);
    capture.record(make_routing(1, "t1")).unwrap();
    assert!(capture.snapshot().is_empty());
}

#[test]
fn trace_capture_disabled_drops_events() {
    let config = TraceCaptureConfig::new(); // not enabled
    let mut capture = TraceCapture::new("cap-disabled", config);
    capture.record(make_routing(1, "t1")).unwrap();
    assert!(capture.snapshot().is_empty());
}

#[test]
fn trace_capture_redacted_snapshot_applies_policy() {
    let policy = RedactionPolicy::default().with_field("session_id");
    let config = TraceCaptureConfig::new().enabled().with_redaction(policy);
    let mut capture = TraceCapture::new("cap-redact", config);
    capture.record(make_session(1, "t1", "secret-123")).unwrap();

    let redacted = capture.redacted_snapshot();
    assert!(redacted.redacted);
    if let TraceEvent::Session(s) = &redacted.events[0] {
        assert_eq!(s.session_id, "[REDACTED]");
    }
}

#[test]
fn trace_capture_finish_sets_ended_at() {
    let config = TraceCaptureConfig::new().enabled();
    let mut capture = TraceCapture::new("cap-finish", config);
    capture.record(make_routing(1, "t1")).unwrap();
    capture.finish();

    let snap = capture.snapshot();
    assert!(snap.ended_at.is_some());
    assert!(snap.duration_ms().is_some());
}

#[test]
fn trace_capture_accessors() {
    let config = TraceCaptureConfig::new().enabled();
    let capture = TraceCapture::new("my-trace", config).with_node("node-99");
    assert_eq!(capture.trace_id(), "my-trace");
    assert_eq!(capture.capture_id(), "my-trace");
    assert!(capture.config().enabled);
}

#[test]
fn captured_trace_json_roundtrip_all_event_types() {
    let mut trace = CapturedTrace::new("json-all").with_node("n1");

    trace.push(make_routing(1, "t1"));
    trace.push(TraceEvent::Admission(AdmissionOutcome {
        timestamp: 2,
        trace_id: "t1".to_string(),
        peer_node: "peer".to_string(),
        request_type: "invoke".to_string(),
        decision: "admit".to_string(),
        reason_code: Some("FCP-2001".to_string()),
        budget_remaining: Some(500),
        authenticated: true,
    }));
    trace.push(TraceEvent::Gossip(GossipEvent {
        timestamp: 3,
        trace_id: "t1".to_string(),
        gossip_type: "reconcile".to_string(),
        object_count: 42,
        peer_node: Some("peer-2".to_string()),
        success: true,
    }));
    trace.push(TraceEvent::Lease(LeaseEvent {
        timestamp: 4,
        trace_id: "t1".to_string(),
        operation: "acquire".to_string(),
        subject_id: "sub-1".to_string(),
        purpose: "singleton_writer".to_string(),
        node_id: "n1".to_string(),
        success: true,
        conflict_holder: None,
    }));
    trace.push(make_session(5, "t1", "sess-1"));
    trace.push(TraceEvent::Policy(PolicyDecision {
        timestamp: 6,
        trace_id: "t1".to_string(),
        zone_id: "z:work".to_string(),
        operation: "invoke".to_string(),
        connector_id: "fcp.test".to_string(),
        decision: "allow".to_string(),
        reason_code: "CAPABILITY_VALID".to_string(),
        evidence: vec!["e1".to_string()],
    }));

    trace.finish();

    let json = trace.to_json().unwrap();
    let parsed = CapturedTrace::from_json(&json).unwrap();

    assert_eq!(parsed.id, "json-all");
    assert_eq!(parsed.events.len(), 6);
    assert_eq!(parsed.version, TRACE_VERSION);
    assert_eq!(parsed.capturing_node, Some("n1".to_string()));
    assert!(parsed.ended_at.is_some());

    // Verify each event type survived the roundtrip
    assert_eq!(parsed.events[0].timestamp(), 1);
    assert_eq!(parsed.events[1].timestamp(), 2);
    assert_eq!(parsed.events[2].timestamp(), 3);
    assert_eq!(parsed.events[3].timestamp(), 4);
    assert_eq!(parsed.events[4].timestamp(), 5);
    assert_eq!(parsed.events[5].timestamp(), 6);

    assert_eq!(parsed.events[0].trace_id(), "t1");
}

#[test]
fn captured_trace_cbor_roundtrip() {
    let mut trace = CapturedTrace::new("cbor-rt");
    trace.push(make_routing(100, "abc"));
    trace.push(TraceEvent::Gossip(GossipEvent {
        timestamp: 200,
        trace_id: "abc".to_string(),
        gossip_type: "announce".to_string(),
        object_count: 7,
        peer_node: None,
        success: false,
    }));

    let cbor_bytes = trace.to_cbor().unwrap();
    let parsed = CapturedTrace::from_cbor(&cbor_bytes).unwrap();

    assert_eq!(parsed.id, "cbor-rt");
    assert_eq!(parsed.events.len(), 2);
    assert_eq!(parsed.events[1].timestamp(), 200);
}

#[test]
fn captured_trace_file_roundtrip_json() {
    let dir = std::env::temp_dir().join("fcp-telemetry-test-json");
    std::fs::create_dir_all(&dir).ok();
    let path = dir.join("trace.json");

    let mut trace = CapturedTrace::new("file-json");
    trace.push(make_routing(1, "t1"));
    trace.write_json(&path).unwrap();

    let contents = std::fs::read_to_string(&path).unwrap();
    let loaded = CapturedTrace::from_json(&contents).unwrap();
    assert_eq!(loaded.id, "file-json");
    assert_eq!(loaded.events.len(), 1);

    std::fs::remove_file(&path).ok();
}

#[test]
fn captured_trace_file_roundtrip_cbor() {
    let dir = std::env::temp_dir().join("fcp-telemetry-test-cbor");
    std::fs::create_dir_all(&dir).ok();
    let path = dir.join("trace.cbor");

    let mut trace = CapturedTrace::new("file-cbor");
    trace.push(make_routing(1, "t1"));
    trace.write_cbor(&path).unwrap();

    let bytes = std::fs::read(&path).unwrap();
    let loaded = CapturedTrace::from_cbor(&bytes).unwrap();
    assert_eq!(loaded.id, "file-cbor");
    assert_eq!(loaded.events.len(), 1);

    std::fs::remove_file(&path).ok();
}

#[test]
fn trace_capture_export_to_path_redacted() {
    let dir = std::env::temp_dir().join("fcp-telemetry-export");
    std::fs::create_dir_all(&dir).ok();
    let path = dir.join("export-redacted.json");

    let policy = RedactionPolicy::default().with_field("session_id");
    let config = TraceCaptureConfig::new().enabled().with_redaction(policy);
    let mut capture = TraceCapture::new("export-test", config);
    capture
        .record(make_session(1, "t1", "secret-sess"))
        .unwrap();

    capture
        .export_to_path(&path, true, TraceExportFormat::Json)
        .unwrap();

    let json = std::fs::read_to_string(&path).unwrap();
    assert!(json.contains("[REDACTED]"));
    assert!(!json.contains("secret-sess"));

    std::fs::remove_file(&path).ok();
}

#[test]
fn trace_capture_max_size_bytes_enforced() {
    let config = TraceCaptureConfig::new()
        .enabled()
        .with_max_events(1000)
        .with_max_size_bytes(1000); // small enough to fill within ~5 events
    let mut capture = TraceCapture::new("size-limit", config);

    // Fill until we hit the size limit
    let mut hit_limit = false;
    for i in 1..100 {
        if capture.record(make_routing(i, "t1")).is_err() {
            hit_limit = true;
            break;
        }
    }
    assert!(hit_limit, "should have hit size limit");
    assert!(
        !capture.snapshot().is_empty(),
        "should have recorded some events"
    );
}

// ============================================================================
// 5. CapabilityUsageStore → recommend_capabilities → report
// ============================================================================

#[test]
fn usage_store_records_and_produces_aggregates() {
    let store = CapabilityUsageStore::new(UsageTelemetryConfig::default());

    let e1 = make_usage_event(
        ZoneId::work(),
        "fcp.a:request-response:1",
        "fcp.a.read",
        SafetyTier::Safe,
        CapabilityUsageOutcome::Allow,
        100,
    );
    let e2 = make_usage_event(
        ZoneId::work(),
        "fcp.a:request-response:1",
        "fcp.a.read",
        SafetyTier::Safe,
        CapabilityUsageOutcome::Deny,
        200,
    );

    assert!(store.record(&e1));
    assert!(store.record(&e2));

    let snap = store.snapshot();
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].total, 2);
    assert_eq!(snap[0].allowed, 1);
    assert_eq!(snap[0].denied, 1);
    assert_eq!(snap[0].first_seen, 100);
    assert_eq!(snap[0].last_seen, 200);
}

#[test]
fn usage_store_zero_sampling_rejects_all() {
    let config = UsageTelemetryConfig {
        sample_rate_bps: 0,
        ..UsageTelemetryConfig::default()
    };
    let store = CapabilityUsageStore::new(config);
    let e = make_usage_event(
        ZoneId::work(),
        "fcp.x:request-response:1",
        "fcp.x.read",
        SafetyTier::Safe,
        CapabilityUsageOutcome::Allow,
        100,
    );
    assert!(!store.record(&e));
    assert!(store.snapshot().is_empty());
}

#[test]
fn usage_store_max_entries_rejects_new_keys() {
    let config = UsageTelemetryConfig {
        max_entries: 1,
        ..UsageTelemetryConfig::default()
    };
    let store = CapabilityUsageStore::new(config);

    let e1 = make_usage_event(
        ZoneId::work(),
        "fcp.a:request-response:1",
        "fcp.a.read",
        SafetyTier::Safe,
        CapabilityUsageOutcome::Allow,
        10,
    );
    assert!(store.record(&e1));

    // Same key still works
    assert!(store.record(&e1));

    // Different key rejected
    let e2 = make_usage_event(
        ZoneId::private(),
        "fcp.b:request-response:1",
        "fcp.b.write",
        SafetyTier::Risky,
        CapabilityUsageOutcome::Allow,
        20,
    );
    assert!(!store.record(&e2));
}

#[test]
fn usage_store_retention_prunes_stale() {
    let config = UsageTelemetryConfig {
        retention_secs: 10,
        ..UsageTelemetryConfig::default()
    };
    let store = CapabilityUsageStore::new(config);

    let old = make_usage_event(
        ZoneId::work(),
        "fcp.old:request-response:1",
        "fcp.old.read",
        SafetyTier::Safe,
        CapabilityUsageOutcome::Allow,
        100,
    );
    store.record(&old);

    // New event with ts far in the future triggers prune
    let fresh = make_usage_event(
        ZoneId::work(),
        "fcp.fresh:request-response:1",
        "fcp.fresh.read",
        SafetyTier::Safe,
        CapabilityUsageOutcome::Allow,
        200,
    );
    store.record(&fresh);

    let snap = store.snapshot();
    // Old entry should be pruned (200 - 100 = 100 > 10)
    assert_eq!(snap.len(), 1);
    assert_eq!(
        snap[0].key.connector_id.as_str(),
        "fcp.fresh:request-response:1"
    );
}

#[test]
fn recommendations_end_to_end() {
    let store = CapabilityUsageStore::new(UsageTelemetryConfig::default());

    // Active safe capability
    store.record(&make_usage_event(
        ZoneId::work(),
        "fcp.a:request-response:1",
        "fcp.a.read",
        SafetyTier::Safe,
        CapabilityUsageOutcome::Allow,
        90,
    ));

    // Stale dangerous capability
    store.record(&make_usage_event(
        ZoneId::work(),
        "fcp.b:request-response:1",
        "fcp.b.write",
        SafetyTier::Dangerous,
        CapabilityUsageOutcome::Deny,
        10,
    ));

    // Active critical capability
    store.record(&make_usage_event(
        ZoneId::private(),
        "fcp.c:request-response:1",
        "fcp.c.admin",
        SafetyTier::Critical,
        CapabilityUsageOutcome::Error,
        95,
    ));

    let aggregates = store.snapshot();
    let report = recommend_capabilities(
        &aggregates,
        100,
        RecommendationConfig {
            unused_after_secs: 50,
        },
    );

    assert_eq!(report.recommendations.len(), 3);

    let summary = report.summary();
    assert_eq!(summary.total, 3);
    // fcp.a.read: active + safe → Keep
    // fcp.b.write: stale (100-10=90 > 50) → RemoveUnused
    // fcp.c.admin: active + critical → ReviewRisky
    assert_eq!(summary.keep, 1);
    assert_eq!(summary.remove_unused, 1);
    assert_eq!(summary.review_risky, 1);

    // Risk summaries
    assert_eq!(report.risk_summaries.len(), 2);
}

#[test]
fn recommendation_report_json_roundtrip() {
    let key = CapabilityUsageKey::new(
        ZoneId::work(),
        ConnectorId::from_static("fcp.test:request-response:1"),
        CapabilityId::from_static("fcp.test.read"),
    );
    let report = CapabilityRecommendationReport {
        generated_at: 1000,
        recommendations: vec![fcp_telemetry::CapabilityRecommendation {
            key,
            suggestion: CapabilitySuggestionKind::Keep,
            reason_code: "active_usage".to_string(),
            usage_total: 5,
            last_seen: 999,
            risk_tier: SafetyTier::Safe,
        }],
        risk_summaries: vec![fcp_telemetry::ZoneRiskSummary {
            zone_id: "z:work".to_string(),
            safe: 5,
            risky: 0,
            dangerous: 0,
            critical: 0,
            forbidden: 0,
        }],
    };

    let json = report.to_json().unwrap();
    let decoded: CapabilityRecommendationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, report);

    let pretty = report.to_json_pretty().unwrap();
    assert!(pretty.contains('\n'));
}

#[test]
fn recommendation_by_suggestion_filter() {
    let aggregates = vec![
        CapabilityUsageAggregate {
            key: CapabilityUsageKey::new(
                ZoneId::work(),
                ConnectorId::from_static("fcp.a:request-response:1"),
                CapabilityId::from_static("fcp.a.read"),
            ),
            total: 1,
            allowed: 1,
            denied: 0,
            errors: 0,
            first_seen: 90,
            last_seen: 95,
            last_risk_tier: SafetyTier::Safe,
        },
        CapabilityUsageAggregate {
            key: CapabilityUsageKey::new(
                ZoneId::work(),
                ConnectorId::from_static("fcp.b:request-response:1"),
                CapabilityId::from_static("fcp.b.write"),
            ),
            total: 1,
            allowed: 0,
            denied: 1,
            errors: 0,
            first_seen: 5,
            last_seen: 5,
            last_risk_tier: SafetyTier::Forbidden,
        },
    ];

    let report = recommend_capabilities(
        &aggregates,
        100,
        RecommendationConfig {
            unused_after_secs: 50,
        },
    );

    let kept = report.by_suggestion(CapabilitySuggestionKind::Keep);
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].key.capability_id.as_str(), "fcp.a.read");

    let removed = report.by_suggestion(CapabilitySuggestionKind::RemoveUnused);
    assert_eq!(removed.len(), 1);
}

// ============================================================================
// 6. HealthResponse builder + serialization
// ============================================================================

#[test]
fn health_response_healthy_with_checks() {
    let resp = HealthResponse::healthy("2.1.0", 7200)
        .with_check("database", true, Some("Connected"))
        .with_check("cache", true, None)
        .with_check("api", true, Some("OK"));

    assert!(resp.is_healthy());
    assert_eq!(resp.checks.len(), 3);
    assert_eq!(resp.version, "2.1.0");
    assert_eq!(resp.uptime_seconds, 7200);
}

#[test]
fn health_response_unhealthy_with_failed_check() {
    let resp =
        HealthResponse::healthy("1.0.0", 100).with_check("db", false, Some("Connection refused"));

    assert!(!resp.is_healthy());
}

#[test]
fn health_response_unhealthy_constructor() {
    let resp = HealthResponse::unhealthy("1.0.0", 50, "OOM");
    assert!(!resp.is_healthy());
    assert_eq!(resp.status, "unhealthy");
    assert_eq!(resp.checks.len(), 1);
    assert_eq!(resp.checks[0].name, "main");
    assert_eq!(resp.checks[0].status, "fail");
    assert_eq!(resp.checks[0].message, Some("OOM".to_string()));
}

#[test]
fn health_response_json_serialization() {
    let resp = HealthResponse::healthy("1.0.0", 3600).with_check("db", true, Some("OK"));

    let json = serde_json::to_string(&resp).unwrap();
    assert!(json.contains("\"status\":\"healthy\""));
    assert!(json.contains("\"version\":\"1.0.0\""));
    assert!(json.contains("\"uptime_seconds\":3600"));
    assert!(json.contains("\"name\":\"db\""));
}

#[test]
fn health_response_skip_none_message() {
    let resp = HealthResponse::healthy("1.0.0", 0).with_check("api", true, None);

    let json = serde_json::to_string(&resp).unwrap();
    assert!(!json.contains("\"message\":null"));
}

#[test]
fn prometheus_text_format_returns_non_empty() {
    let text = prometheus_text_format();
    assert!(!text.is_empty());
}

// ============================================================================
// 7. Redact-sensitive logging pipeline
// ============================================================================

#[test]
fn redact_sensitive_nested_objects() {
    let value = serde_json::json!({
        "request": {
            "headers": {
                "Authorization": "Bearer xxx",
                "Content-Type": "application/json"
            },
            "body": {
                "user": "admin",
                "password": "s3cret",
                "api_key": "sk-123"
            }
        }
    });

    let fields = vec![
        "password".to_string(),
        "api_key".to_string(),
        "authorization".to_string(),
    ];

    let redacted = redact_sensitive(&value, &fields);
    assert_eq!(
        redacted["request"]["headers"]["Authorization"],
        "[REDACTED]"
    );
    assert_eq!(
        redacted["request"]["headers"]["Content-Type"],
        "application/json"
    );
    assert_eq!(redacted["request"]["body"]["user"], "admin");
    assert_eq!(redacted["request"]["body"]["password"], "[REDACTED]");
    assert_eq!(redacted["request"]["body"]["api_key"], "[REDACTED]");
}

#[test]
fn redact_sensitive_arrays() {
    let value = serde_json::json!({
        "users": [
            {"name": "alice", "token": "tok-1"},
            {"name": "bob", "token": "tok-2"}
        ]
    });

    let redacted = redact_sensitive(&value, &["token".to_string()]);
    assert_eq!(redacted["users"][0]["name"], "alice");
    assert_eq!(redacted["users"][0]["token"], "[REDACTED]");
    assert_eq!(redacted["users"][1]["name"], "bob");
    assert_eq!(redacted["users"][1]["token"], "[REDACTED]");
}

#[test]
fn redact_sensitive_case_insensitive() {
    let value = serde_json::json!({
        "PASSWORD": "p1",
        "Password": "p2",
        "password": "p3"
    });

    let redacted = redact_sensitive(&value, &["password".to_string()]);
    assert_eq!(redacted["PASSWORD"], "[REDACTED]");
    assert_eq!(redacted["Password"], "[REDACTED]");
    assert_eq!(redacted["password"], "[REDACTED]");
}

#[test]
fn redact_sensitive_preserves_primitives() {
    let value = serde_json::json!(42);
    let redacted = redact_sensitive(&value, &["password".to_string()]);
    assert_eq!(redacted, 42);
}

#[test]
fn redact_sensitive_empty_fields_list() {
    let value = serde_json::json!({"secret": "visible"});
    let redacted = redact_sensitive(&value, &[]);
    assert_eq!(redacted["secret"], "visible");
}

// ============================================================================
// 8. LegacyTraceContext (tracing_layer) header inject/extract
// ============================================================================

#[test]
fn legacy_trace_context_roundtrip_via_headers() {
    let ctx = LegacyTraceContext::new();
    let mut headers = HashMap::new();
    inject_trace_context(&ctx, &mut headers);

    assert!(headers.contains_key(TRACEPARENT_HEADER));

    let extracted = extract_trace_context(&headers).unwrap();
    assert_eq!(ctx.trace_id, extracted.trace_id);
    assert_eq!(ctx.parent_span_id, extracted.parent_span_id);
    assert_eq!(ctx.trace_flags, extracted.trace_flags);
}

#[test]
fn legacy_trace_context_with_trace_state() {
    let mut ctx = LegacyTraceContext::new();
    ctx.trace_state = Some("vendor=value".to_string());

    let mut headers = HashMap::new();
    inject_trace_context(&ctx, &mut headers);

    assert!(headers.contains_key(TRACESTATE_HEADER));
    assert_eq!(headers[TRACESTATE_HEADER], "vendor=value");
}

#[test]
fn legacy_trace_context_child_preserves_trace_id() {
    let parent = LegacyTraceContext::new();
    let child = parent.child();

    assert_eq!(parent.trace_id, child.trace_id);
    assert_ne!(parent.parent_span_id, child.parent_span_id);
}

#[test]
fn legacy_trace_context_sampled_check() {
    let ctx = LegacyTraceContext::new();
    assert!(ctx.is_sampled()); // default is sampled

    let known = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00";
    let parsed = LegacyTraceContext::from_traceparent(known).unwrap();
    assert!(!parsed.is_sampled());
}

#[test]
fn extract_trace_context_missing_header() {
    let headers: HashMap<String, String> = HashMap::new();
    assert!(extract_trace_context(&headers).is_none());
}

#[test]
fn extract_trace_context_invalid_format() {
    let mut headers = HashMap::new();
    headers.insert(TRACEPARENT_HEADER.to_string(), "garbage".to_string());
    assert!(extract_trace_context(&headers).is_none());
}

// ============================================================================
// 9. FcpSpan + SpanGuard
// ============================================================================

#[test]
fn fcp_span_builder_creates_span_guard() {
    let span = FcpSpan::new("integration-test")
        .connector_id("fcp.test")
        .operation("read")
        .request_id("req-001")
        .attribute("zone", "work");

    let mut guard = span.start();
    guard.set_attribute("result", "success");
    guard.set_ok();
    // guard dropped here
}

#[test]
fn fcp_span_client_server_kinds() {
    let _g1 = FcpSpan::new("client-span").client().start();
    let _g2 = FcpSpan::new("server-span").server().start();
}

#[test]
fn span_guard_record_error() {
    let mut guard = FcpSpan::new("error-span").start();
    guard.record_error("connection timeout");
    // No panic on drop
}

// ============================================================================
// 10. Metrics helpers
// ============================================================================

#[test]
fn timer_measures_elapsed_time() {
    let timer = Timer::start("test_timer", &[("op", "read")]);
    std::thread::sleep(std::time::Duration::from_millis(10));
    let ms = timer.elapsed_ms();
    assert!(ms >= 10);
}

#[test]
fn timer_stop_and_return_elapsed() {
    let timer = Timer::start("stop_return", &[]);
    std::thread::sleep(std::time::Duration::from_millis(5));
    let elapsed = timer.stop_and_return();
    assert!(elapsed >= 0.005);
}

#[test]
fn timer_guard_raii_drop() {
    {
        let guard = TimerGuard::new("guard_test", &[("scope", "test")]);
        let e = guard.elapsed_seconds();
        assert!(e >= 0.0);
    }
    // No panic on drop
}

#[test]
fn metrics_helpers_no_panic() {
    increment_counter("integ_counter", &[("test", "true")]);
    increment_counter_by("integ_counter_by", 5, &[("test", "true")]);
    set_gauge("integ_gauge", 42.0, &[("test", "true")]);
    increment_gauge("integ_inc_gauge", 1.0, &[]);
    decrement_gauge("integ_dec_gauge", 1.0, &[]);
    record_histogram("integ_hist", 0.123, &[("op", "read")]);
}

#[test]
fn metrics_handle_getters() {
    let c = get_counter("integ_get_counter", &[("x", "y")]);
    c.increment(1);

    let g = get_gauge("integ_get_gauge", &[("x", "y")]);
    g.set(99.0);
    g.increment(1.0);
    g.decrement(0.5);

    let h = get_histogram("integ_get_hist", &[("x", "y")]);
    h.record(0.5);
}

#[test]
fn record_request_success_and_error_no_panic() {
    record_request_success("integ-conn", "list", 0.05);
    record_request_error("integ-conn", "create", "timeout", 1.5);
}

#[test]
fn update_health_status_all_variants() {
    update_health_status("integ-conn", HealthStatusMetric::Ready);
    update_health_status("integ-conn", HealthStatusMetric::Degraded);
    update_health_status("integ-conn", HealthStatusMetric::Error);
}

#[test]
fn update_rate_limit_variants() {
    update_rate_limit("integ-conn", 100, false);
    update_rate_limit("integ-conn", 0, true);
}

#[test]
fn record_events_no_panic() {
    record_event_emitted("integ-conn", "message_received");
    record_event_dropped("integ-conn", "message", "buffer_full");
}

#[test]
fn record_symbol_coverage_no_panic() {
    record_symbol_coverage("z:work", 3, 10000, 4000, 10000);
    record_diversity_violation("z:work", 3, 1);
}

// ============================================================================
// 11. TelemetryConfig builder
// ============================================================================

#[test]
#[allow(clippy::float_cmp)]
fn telemetry_config_full_builder_chain() {
    let config = TelemetryConfig::new("my-connector")
        .with_log_level("trace")
        .with_json_logs(false)
        .with_prometheus(9091)
        .with_otlp("http://collector:4317")
        .with_sample_rate(0.5)
        .with_redact_fields(vec!["custom_secret".to_string()]);

    assert_eq!(config.service_name, "my-connector");
    assert_eq!(config.log_level, "trace");
    assert!(!config.json_logs);
    assert!(config.prometheus_enabled);
    assert_eq!(config.prometheus_port, 9091);
    assert!(config.otlp_enabled);
    assert_eq!(
        config.otlp_endpoint,
        Some("http://collector:4317".to_string())
    );
    assert_eq!(config.trace_sample_rate, 0.5);
    assert!(config.redact_fields.contains(&"custom_secret".to_string()));
    // Default fields still present
    assert!(config.redact_fields.contains(&"password".to_string()));
}

// ============================================================================
// 12. TelemetryError
// ============================================================================

#[test]
fn telemetry_error_variants_display() {
    let e1 = TelemetryError::LoggingInit("log fail".to_string());
    assert!(format!("{e1}").contains("Failed to initialize logging"));
    assert!(format!("{e1}").contains("log fail"));

    let e2 = TelemetryError::MetricsInit("metrics fail".to_string());
    assert!(format!("{e2}").contains("Failed to initialize metrics"));

    let e3 = TelemetryError::TracingInit("trace fail".to_string());
    assert!(format!("{e3}").contains("Failed to initialize tracing"));

    let e4 = TelemetryError::Config("bad config".to_string());
    assert!(format!("{e4}").contains("Configuration error"));
}

// ============================================================================
// 13. Cross-module integration: trace capture → redaction → export
// ============================================================================

#[test]
fn full_trace_pipeline_capture_redact_export() {
    // Create capture with redaction
    let policy = RedactionPolicy::default()
        .with_field("session_id")
        .with_hash_redacted(true);
    let config = TraceCaptureConfig::new()
        .enabled()
        .with_max_events(100)
        .with_redaction(policy);
    let mut capture = TraceCapture::new("pipeline-test", config).with_node("node-1");

    // Record various events
    capture.record(make_routing(100, "t1")).unwrap();
    capture
        .record(make_session(200, "t1", "secret-session-id"))
        .unwrap();
    capture
        .record(TraceEvent::Policy(PolicyDecision {
            timestamp: 300,
            trace_id: "t1".to_string(),
            zone_id: "z:work".to_string(),
            operation: "invoke".to_string(),
            connector_id: "fcp.test".to_string(),
            decision: "allow".to_string(),
            reason_code: "CAP_VALID".to_string(),
            evidence: vec!["e1".to_string()],
        }))
        .unwrap();

    capture.finish();

    // Unredacted snapshot
    let raw = capture.snapshot();
    assert_eq!(raw.events.len(), 3);
    assert!(!raw.redacted);
    if let TraceEvent::Session(s) = &raw.events[1] {
        assert_eq!(s.session_id, "secret-session-id");
    }

    // Redacted snapshot
    let redacted = capture.redacted_snapshot();
    assert!(redacted.redacted);
    if let TraceEvent::Session(s) = &redacted.events[1] {
        assert!(s.session_id.starts_with("[REDACTED:"));
    }

    // JSON roundtrip of redacted trace
    let json = redacted.to_json().unwrap();
    let parsed = CapturedTrace::from_json(&json).unwrap();
    assert_eq!(parsed.events.len(), 3);
    assert!(parsed.redacted);
}

// ============================================================================
// 14. Cross-module: TelemetryContext + TraceContext binary format
// ============================================================================

#[test]
fn telemetry_context_trace_context_to_traceparent() {
    let telem = TelemetryContext::with_trace()
        .zone_id("z:work")
        .connector_id("fcp.demo");

    let tc = telem.get_trace_context().unwrap();
    let header = tc.to_traceparent();

    // Should be valid W3C format
    let parts: Vec<&str> = header.split('-').collect();
    assert_eq!(parts.len(), 4);
    assert_eq!(parts[0], "00");
    assert_eq!(parts[1].len(), 32);
    assert_eq!(parts[2].len(), 16);
    assert_eq!(parts[3].len(), 2);

    // Parse it back
    let parsed = TraceContext::from_traceparent(&header).unwrap();
    assert_eq!(tc.trace_id, parsed.trace_id);
    assert_eq!(tc.span_id, parsed.span_id);
}

// ============================================================================
// 15. TraceEvent timestamp and trace_id accessors
// ============================================================================

#[test]
fn trace_event_accessors_all_variants() {
    let events = [
        make_routing(10, "r1"),
        TraceEvent::Admission(AdmissionOutcome {
            timestamp: 20,
            trace_id: "a1".to_string(),
            peer_node: "p".to_string(),
            request_type: "invoke".to_string(),
            decision: "admit".to_string(),
            reason_code: None,
            budget_remaining: None,
            authenticated: false,
        }),
        TraceEvent::Gossip(GossipEvent {
            timestamp: 30,
            trace_id: "g1".to_string(),
            gossip_type: "merge".to_string(),
            object_count: 5,
            peer_node: None,
            success: true,
        }),
        TraceEvent::Lease(LeaseEvent {
            timestamp: 40,
            trace_id: "l1".to_string(),
            operation: "renew".to_string(),
            subject_id: "s1".to_string(),
            purpose: "operation".to_string(),
            node_id: "n1".to_string(),
            success: false,
            conflict_holder: Some("other-node".to_string()),
        }),
        make_session(50, "s1", "sess-x"),
        TraceEvent::Policy(PolicyDecision {
            timestamp: 60,
            trace_id: "p1".to_string(),
            zone_id: "z".to_string(),
            operation: "op".to_string(),
            connector_id: "c".to_string(),
            decision: "deny".to_string(),
            reason_code: "FCP-5001".to_string(),
            evidence: vec![],
        }),
    ];

    let timestamps = [10, 20, 30, 40, 50, 60];
    let trace_ids = ["r1", "a1", "g1", "l1", "s1", "p1"];

    for (i, event) in events.iter().enumerate() {
        assert_eq!(event.timestamp(), timestamps[i]);
        assert_eq!(event.trace_id(), trace_ids[i]);
    }
}

// ============================================================================
// 16. TraceEvent with_redaction per variant
// ============================================================================

#[test]
fn trace_event_with_redaction_routing_is_identity() {
    let event = make_routing(1, "t1");
    let policy = RedactionPolicy::default();
    let redacted = event.with_redaction(&policy);
    assert_eq!(event, redacted);
}

#[test]
fn trace_event_with_redaction_session_redacts_session_id() {
    let event = make_session(1, "t1", "secret-sess");
    let policy = RedactionPolicy::default().with_field("session_id");
    let redacted = event.with_redaction(&policy);

    if let TraceEvent::Session(s) = &redacted {
        assert_eq!(s.session_id, "[REDACTED]");
        // Other fields preserved
        assert_eq!(s.kind, "established");
        assert_eq!(s.peer_node, "peer-1");
    } else {
        panic!("Expected Session variant");
    }
}

// ============================================================================
// 17. TraceError display
// ============================================================================

#[test]
fn trace_error_display_all_variants() {
    let e1 = TraceError::Serialization("ser".to_string());
    assert!(format!("{e1}").contains("serialization"));

    let e2 = TraceError::Deserialization("deser".to_string());
    assert!(format!("{e2}").contains("deserialization"));

    let e3 = TraceError::BufferFull;
    assert!(format!("{e3}").contains("buffer full"));

    let e4 = TraceError::UnsupportedVersion(99);
    assert!(format!("{e4}").contains("99"));

    let e5 = TraceError::Io("disk full".to_string());
    assert!(format!("{e5}").contains("IO"));
}

// ============================================================================
// 18. TraceCaptureConfig builder
// ============================================================================

#[test]
#[allow(clippy::float_cmp)]
fn trace_capture_config_builder() {
    let config = TraceCaptureConfig::new()
        .enabled()
        .with_max_events(500)
        .with_max_size_bytes(1024 * 1024)
        .with_sample_rate(0.75);

    assert!(config.enabled);
    assert_eq!(config.max_events, 500);
    assert_eq!(config.max_size_bytes, 1024 * 1024);
    assert_eq!(config.sample_rate, 0.75);
}

#[test]
fn trace_capture_config_default_values() {
    let config = TraceCaptureConfig::default();
    assert!(!config.enabled);
    assert_eq!(config.max_events, 10_000);
    assert_eq!(config.max_size_bytes, 10 * 1024 * 1024);
}

// ============================================================================
// 19. CapabilitySuggestionKind serde
// ============================================================================

#[test]
fn suggestion_kind_serde_snake_case() {
    let json = serde_json::to_string(&CapabilitySuggestionKind::RemoveUnused).unwrap();
    assert_eq!(json, "\"remove_unused\"");

    let json = serde_json::to_string(&CapabilitySuggestionKind::ReviewRisky).unwrap();
    assert_eq!(json, "\"review_risky\"");

    let json = serde_json::to_string(&CapabilitySuggestionKind::Keep).unwrap();
    assert_eq!(json, "\"keep\"");
}

// ============================================================================
// 20. W3C constants
// ============================================================================

#[test]
fn w3c_constants_correct() {
    assert_eq!(TRACE_ID_SIZE, 16);
    assert_eq!(SPAN_ID_SIZE, 8);
    assert_eq!(TRACE_FLAG_SAMPLED, 0x01);
    assert_eq!(TRACEPARENT_HEADER, "traceparent");
    assert_eq!(TRACESTATE_HEADER, "tracestate");
}
