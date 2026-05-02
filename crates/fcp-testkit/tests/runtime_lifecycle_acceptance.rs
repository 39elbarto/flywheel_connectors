//! Runtime lifecycle acceptance tests.
//!
//! These tests verify that the SDK runtime primitives, streaming health model,
//! session scripts, and supervisor infrastructure compose correctly for
//! non-mock acceptance scenarios.
//!
//! Bead: `flywheel_connectors-49z0b.7.2`
//!
//! # What these tests prove
//!
//! - Health tracker state transitions align with production `HealthSnapshot`.
//! - Supervisor configuration defaults are production-safe.
//! - Session-script DSL drives full lifecycle descriptions.
//! - Evidence collection captures structured artifacts from lifecycle events.
//! - Cleanup guards run deterministically on test teardown.
//! - Live-suite infrastructure integrates with supervisor budget tracking.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use fcp_prelude::HealthState;
use fcp_sdk::runtime::{
    HealthTracker, HealthTransition, InMemoryPollingCursor, InMemoryStreamingSession, PollResult,
    StreamingSession, SupervisorConfig,
};
use fcp_testkit::evidence_helpers::EvidenceCollector;
use fcp_testkit::live_suite::{
    BudgetAlert, CleanupGuard, EnvironmentManifest, LiveEnvironment, StaleResourceReport,
    SyntheticTenant,
};
use fcp_testkit::session_script::{Fault, ScriptHealthState, ScriptStep, SessionScript, Transport};
use fcp_testkit::streaming_fixture::SseEvent;
use serde_json::json;

// ─────────────────────────────────────────────────────────────────────────────
// Health Tracker lifecycle
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn health_tracker_starts_in_starting_state() {
    let tracker = HealthTracker::new();
    assert!(matches!(tracker.state(), HealthState::Starting));
    assert_eq!(tracker.consecutive_failures(), 0);
}

#[test]
fn health_tracker_full_lifecycle() {
    let mut tracker = HealthTracker::new();

    // Transition to ready
    assert!(tracker.transition(HealthTransition::ToHealthy));
    assert!(matches!(tracker.state(), HealthState::Ready));

    // Record a failure
    tracker.record_failure("timeout");
    assert_eq!(tracker.consecutive_failures(), 1);

    // Record success resets failure count
    tracker.record_success();
    assert_eq!(tracker.consecutive_failures(), 0);
    assert_eq!(tracker.consecutive_successes(), 1);
}

#[test]
fn health_tracker_degraded_lifecycle() {
    let mut tracker = HealthTracker::new();
    tracker.transition(HealthTransition::ToHealthy);

    // Transition to degraded
    assert!(tracker.transition(HealthTransition::ToDegraded {
        reason: "high latency".into(),
    }));
    assert!(tracker.is_degraded());

    // Record success then transition back to healthy
    tracker.record_success();
    assert!(tracker.transition(HealthTransition::ToHealthy));
    assert!(tracker.is_healthy());
}

#[test]
fn health_tracker_unhealthy_on_many_failures() {
    let mut tracker = HealthTracker::new();
    tracker.transition(HealthTransition::ToHealthy);

    // Record enough failures
    for i in 0..5 {
        tracker.record_failure(&format!("failure {i}"));
    }
    assert_eq!(tracker.consecutive_failures(), 5);

    // Transition to unhealthy
    assert!(tracker.transition(HealthTransition::ToUnhealthy {
        reason: "too many failures".into(),
    }));
    assert!(tracker.is_unhealthy());
}

#[test]
fn health_tracker_snapshot_contract() {
    let mut tracker = HealthTracker::new();
    tracker.transition(HealthTransition::ToHealthy);

    let snap = tracker.snapshot();
    let json = serde_json::to_value(&snap).unwrap();

    // HealthSnapshot must serialize with expected fields
    assert!(json["status"].is_object() || json["status"].is_string());
    assert!(json["uptime_ms"].is_number());
}

// ─────────────────────────────────────────────────────────────────────────────
// Supervisor configuration validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn supervisor_config_defaults_are_production_safe() {
    let config = SupervisorConfig::default();

    // Verify documented defaults from the study docs
    assert_eq!(config.base_backoff_ms, 1000, "base backoff should be 1s");
    assert_eq!(config.max_backoff_ms, 60_000, "max backoff should be 60s");
    assert!(config.jitter_enabled, "jitter should be on by default");
    assert_eq!(
        config.max_consecutive_failures, 5,
        "max failures should be 5"
    );
}

#[test]
fn supervisor_config_builder_pattern() {
    let config = SupervisorConfig::new()
        .with_base_backoff_ms(500)
        .with_max_backoff_ms(30_000)
        .with_jitter(false)
        .with_max_consecutive_failures(10);

    assert_eq!(config.base_backoff_ms, 500);
    assert_eq!(config.max_backoff_ms, 30_000);
    assert!(!config.jitter_enabled);
    assert_eq!(config.max_consecutive_failures, 10);
}

#[test]
fn supervisor_config_serialization_roundtrip() {
    let config = SupervisorConfig::new()
        .with_base_backoff_ms(2000)
        .with_max_consecutive_failures(7);

    let json = serde_json::to_string(&config).unwrap();
    let parsed: SupervisorConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.base_backoff_ms, 2000);
    assert_eq!(parsed.max_consecutive_failures, 7);
}

// ─────────────────────────────────────────────────────────────────────────────
// Polling cursor lifecycle
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn polling_cursor_tracks_offset() {
    use fcp_sdk::runtime::PollingCursor;

    let mut cursor = InMemoryPollingCursor::new();
    assert!(cursor.offset().is_none());

    cursor.set_offset(42);
    assert_eq!(cursor.offset(), Some(42));

    cursor.record_poll(Instant::now(), 5);
    assert_eq!(cursor.last_poll_count(), 5);
    assert!(cursor.last_poll_at().is_some());
}

#[test]
fn polling_cursor_with_initial_offset() {
    use fcp_sdk::runtime::PollingCursor;

    let cursor = InMemoryPollingCursor::with_offset(100);
    assert_eq!(cursor.offset(), Some(100));
}

#[test]
fn polling_cursor_persist_and_restore() {
    use fcp_sdk::runtime::PollingCursor;

    let mut cursor = InMemoryPollingCursor::new();
    cursor.set_offset(99);

    // In-memory persist/restore should succeed
    assert!(cursor.persist().is_ok());
    assert!(cursor.restore().is_ok());
}

// ─────────────────────────────────────────────────────────────────────────────
// Streaming session lifecycle
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn streaming_session_resume_token_lifecycle() {
    let mut session = InMemoryStreamingSession::new();

    // No resume token initially
    assert!(session.resume_token().is_none());

    // Set a resume token
    session.set_resume_token("tok-abc123".into());
    assert_eq!(session.resume_token(), Some("tok-abc123".into()));

    // Clear it
    session.clear_resume_token();
    assert!(session.resume_token().is_none());
}

#[test]
fn streaming_session_sequence_tracking() {
    let mut session = InMemoryStreamingSession::new();

    assert_eq!(session.sequence(), 0);
    session.set_sequence(42);
    assert_eq!(session.sequence(), 42);
}

#[test]
fn streaming_session_heartbeat_tracking() {
    let mut session = InMemoryStreamingSession::new();

    let now = Instant::now();
    session.record_heartbeat_sent(now);
    assert_eq!(session.last_heartbeat_sent(), Some(now));
    assert_eq!(session.heartbeat_seq(), 1);

    // Record ack
    let ack_time = Instant::now();
    session.record_heartbeat_ack(ack_time);
    assert_eq!(session.last_heartbeat_ack(), Some(ack_time));
    assert_eq!(session.ack_seq(), 1);
}

#[test]
fn streaming_session_unacked_heartbeat_detection() {
    let mut session = InMemoryStreamingSession::new();

    // No unacked heartbeats initially
    assert!(session.first_unacked_heartbeat_sent().is_none());

    // Send a heartbeat without acking
    let sent_time = Instant::now();
    session.record_heartbeat_sent(sent_time);
    assert!(session.first_unacked_heartbeat_sent().is_some());

    // Ack it
    session.record_heartbeat_ack(Instant::now());
    assert!(session.first_unacked_heartbeat_sent().is_none());
}

// ─────────────────────────────────────────────────────────────────────────────
// Session script + lifecycle integration
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn session_script_full_streaming_lifecycle() {
    let script = SessionScript::new("streaming.health_lifecycle")
        .step(ScriptStep::connect(Transport::Sse, "/events"))
        .step(ScriptStep::assert_health(ScriptHealthState::Connected))
        .step(ScriptStep::expect_message(json!({"type": "hello"})))
        .step(ScriptStep::send_message(
            json!({"type": "subscribe", "channel": "test"}),
        ))
        .step(ScriptStep::expect_message(json!({"type": "subscribed"})))
        .step(ScriptStep::inject_fault(Fault::ConnectionDrop))
        .step(ScriptStep::assert_health(ScriptHealthState::Reconnecting))
        .step(ScriptStep::wait(Duration::from_millis(100)))
        .step(ScriptStep::assert_health(ScriptHealthState::Connected))
        .step(ScriptStep::disconnect());

    assert_eq!(script.steps.len(), 10);
    assert_eq!(script.scenario_id, "streaming.health_lifecycle");

    // Script should be serializable for evidence
    let json = serde_json::to_value(&script).unwrap();
    assert!(json["scenario_id"].is_string());
    assert!(json["steps"].is_array());
    assert_eq!(json["steps"].as_array().unwrap().len(), 10);
}

#[test]
fn session_script_webhook_ingress_lifecycle() {
    let script = SessionScript::new("webhook.delivery_lifecycle")
        .step(ScriptStep::connect(Transport::WebhookIngress, "/webhook"))
        .step(ScriptStep::assert_health(ScriptHealthState::Connected))
        .step(ScriptStep::send_message(json!({
            "event": "push",
            "repository": "test/repo"
        })))
        .step(ScriptStep::expect_message(json!({"status": "accepted"})))
        .step(ScriptStep::inject_fault(Fault::Latency {
            duration: Duration::from_millis(50),
        }))
        .step(ScriptStep::disconnect());

    assert_eq!(script.steps.len(), 6);

    let json = serde_json::to_value(&script).unwrap();
    let steps = json["steps"].as_array().unwrap();
    // Verify the first step is a Connect step
    let first_step = &steps[0];
    let first_str = serde_json::to_string(first_step).unwrap();
    assert!(
        first_str.contains("webhook_ingress") || first_str.contains("Connect"),
        "First step should be a Connect with webhook_ingress transport"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// SSE event construction contract
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn sse_event_builder_contract() {
    let event = SseEvent::typed("greeting", r#"{"msg":"hello"}"#)
        .with_id("evt-1")
        .with_retry(5000);

    assert_eq!(event.event.as_deref(), Some("greeting"));
    assert_eq!(event.data, r#"{"msg":"hello"}"#);
    assert_eq!(event.id.as_deref(), Some("evt-1"));
    assert_eq!(event.retry_ms, Some(5000));
}

#[test]
fn sse_event_data_only() {
    let event = SseEvent::data("ping");
    assert!(event.event.is_none());
    assert_eq!(event.data, "ping");
    assert!(event.id.is_none());
    assert!(event.retry_ms.is_none());
}

#[test]
fn sse_event_serialization_roundtrip() {
    let event = SseEvent::typed("message", "hello").with_id("1");
    let json = serde_json::to_string(&event).unwrap();
    let parsed: SseEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, event);
}

// ─────────────────────────────────────────────────────────────────────────────
// Evidence collection across lifecycle phases
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn evidence_collector_records_full_connector_lifecycle() {
    let mut collector = EvidenceCollector::new();

    // Simulate lifecycle phases
    collector.record_audit_event(
        "configure",
        "discord.configure",
        json!({"zone": "z:community"}),
    );
    collector.record_audit_event("handshake", "discord.handshake", json!({"version": "3.0"}));
    collector.record_receipt("req-1", "discord.send_message", true);
    collector.record_receipt("req-2", "discord.send_message", true);
    collector.record_audit_event(
        "shutdown",
        "discord.shutdown",
        json!({"reason": "graceful"}),
    );

    assert_eq!(collector.audit_events.len(), 3);
    assert_eq!(collector.receipts.len(), 2);
    assert!(collector.audit_events[0].zone_scoped);
    assert!(collector.receipts.iter().all(|r| r.success));

    let json = collector.to_json();
    // to_json() returns counts, not arrays
    assert_eq!(json["audit_events"], 3);
    assert_eq!(json["receipts"], 2);
    assert_eq!(json["total_artifacts"], 5);
}

// ─────────────────────────────────────────────────────────────────────────────
// Live-suite + supervisor integration
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn live_environment_budget_tracking_during_polling() {
    // Use local manifest with explicit budget for testing cost tracking
    let manifest = EnvironmentManifest::local("sqlite").with_budget(1.0);
    let env = LiveEnvironment::from_manifest(manifest);

    // Simulate API calls during supervised polling
    env.budget.record_api_call("sqlite.query", 0.001);
    env.budget.record_api_call("sqlite.query", 0.001);
    env.budget.record_api_call("sqlite.insert", 0.002);

    assert!(env.budget.within_limits());
    assert_eq!(env.budget.alert_level(), BudgetAlert::Ok);
    assert_eq!(env.budget.entries().len(), 3);

    let summary = env.evidence_summary();
    assert!(summary["budget"]["within_limits"].as_bool().unwrap());
}

#[test]
fn cleanup_guard_with_synthetic_tenant_teardown() {
    let tenant = SyntheticTenant::with_run_id("discord", "test-run");
    let guard = CleanupGuard::new();

    let prefix = tenant.run_prefix();
    let cleaned = Arc::new(AtomicU32::new(0));
    let c1 = Arc::clone(&cleaned);
    guard.register(
        &format!("Delete {prefix}-channel"),
        Box::new(move || {
            c1.fetch_add(1, Ordering::SeqCst);
        }),
    );
    let c2 = Arc::clone(&cleaned);
    guard.register(
        &format!("Delete {prefix}-role"),
        Box::new(move || {
            c2.fetch_add(1, Ordering::SeqCst);
        }),
    );

    let results = guard.run_cleanup();
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(|r| r.success));
    assert_eq!(cleaned.load(Ordering::SeqCst), 2);
}

#[test]
fn stale_resource_detection_for_orphaned_test_artifacts() {
    let old_date = (chrono::Utc::now() - chrono::Duration::days(60)).format("%Y%m%d");
    let names = [
        format!("fcp-test-discord-channel-run1-{old_date}"),
        format!("fcp-test-discord-role-run1-{old_date}"),
        format!(
            "fcp-test-discord-user-run2-{}",
            chrono::Utc::now().format("%Y%m%d")
        ),
        "production-channel-real".to_string(),
    ];
    let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();

    let report = StaleResourceReport::scan(&name_refs, 30);
    assert_eq!(report.scanned, 4);
    assert_eq!(report.stale.len(), 2);
    assert!(
        report
            .stale
            .iter()
            .all(|s| s.connector.as_deref() == Some("discord"))
    );
    assert!(report.stale.iter().all(|s| s.age_days.unwrap() >= 59));
}

// ─────────────────────────────────────────────────────────────────────────────
// Health state serialization contract
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn health_state_ready_serializes_correctly() {
    let state = HealthState::Ready;
    let json = serde_json::to_value(&state).unwrap();
    assert_eq!(json["state"], "ready");
}

#[test]
fn health_state_degraded_includes_reason() {
    let state = HealthState::Degraded {
        reason: "high latency".into(),
    };
    let json = serde_json::to_value(&state).unwrap();
    assert_eq!(json["state"], "degraded");
    assert_eq!(json["reason"], "high latency");
}

#[test]
fn health_state_error_includes_reason() {
    let state = HealthState::Error {
        reason: "connection refused".into(),
    };
    let json = serde_json::to_value(&state).unwrap();
    assert_eq!(json["state"], "error");
    assert_eq!(json["reason"], "connection refused");
}

// ─────────────────────────────────────────────────────────────────────────────
// Environment manifest prerequisite validation for runtime crates
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn runtime_crates_need_only_local_manifests() {
    for crate_name in ["fcp-sdk", "fcp-host", "fcp-streaming", "fcp-webhook"] {
        let manifest = EnvironmentManifest::local(crate_name);
        let env = LiveEnvironment::from_manifest(manifest);
        assert!(
            env.is_ready(),
            "{crate_name} should be ready with local manifest"
        );
    }
}

#[test]
fn prerequisite_report_for_runtime_acceptance() {
    let manifest = EnvironmentManifest::local("fcp-sdk")
        .with_metadata("test_scope", json!("runtime_lifecycle"));
    let report = manifest.prerequisite_report();

    assert!(report.is_ready());
    assert!(report.gate_enabled);
    assert!(report.secrets_complete);
    assert!(report.env_vars_complete);
    assert!(report.budget_configured);
}

// ─────────────────────────────────────────────────────────────────────────────
// PollResult contract
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn poll_result_variants_cover_all_outcomes() {
    let success: PollResult<String> = PollResult::success(vec!["a".into(), "b".into()]);
    assert!(matches!(success, PollResult::Success(_)));

    let empty: PollResult<String> = PollResult::empty();
    assert!(matches!(empty, PollResult::Success(ref v) if v.is_empty()));

    let recoverable: PollResult<String> = PollResult::recoverable("timeout");
    assert!(matches!(recoverable, PollResult::RecoverableError { .. }));

    let rate_limited: PollResult<String> = PollResult::rate_limited("429", 5000);
    assert!(matches!(
        rate_limited,
        PollResult::RecoverableError {
            retry_after_ms: Some(5000),
            ..
        }
    ));

    let fatal: PollResult<String> = PollResult::fatal("auth revoked");
    assert!(matches!(fatal, PollResult::FatalError { .. }));
}
