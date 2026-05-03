//! `fcp_host::resilience` retry / circuit-breaker / bulkhead /
//! load-shed routing-decision conformance.
//!
//! `ResilienceLayer` is the host-side retry contract every connector
//! invocation flows through. It composes circuit breakers, bulkheads,
//! health-based routing, and adaptive load shedding. Documented
//! defaults are NORMATIVE — drift means a release silently changes
//! how aggressively the host gives up on a flaky connector or sheds
//! load under pressure.
//!
//! Properties pinned (NORMATIVE):
//!
//! 1. **`CircuitBreakerConfig::default`** — failure_threshold=3,
//!    success_threshold=2, open_duration=5s, window=30s,
//!    failure_predicate=AnyError. These four numbers ARE the host's
//!    default tolerance to upstream flakiness.
//! 2. **`BulkheadConfig::default`** — max_concurrent=16,
//!    max_queued=32, queue_timeout=250ms.
//! 3. **`HealthRouterConfig::default`** — unhealthy_threshold=3,
//!    recovery_success_threshold=2, latency_degraded_threshold=750ms,
//!    error_rate_degraded_threshold_per_mille=500,
//!    probe_interval=5s, error_window=30s, latency_alpha_per_mille=200.
//! 4. **`LoadShedConfig::default`** — shed_threshold_per_mille=850,
//!    full_shed_threshold_per_mille=1000, sheddable_priorities=[Low,
//!    Normal] (Critical and High are NEVER shed by default).
//! 5. **`ResilienceConfig::default()::operation_timeout` is None**
//!    — no per-op timeout unless the host opts in.
//! 6. **`RoutingDecision` four variants**: Allow, AllowDegraded,
//!    AllowProbe, Reject. Equality and cloning match.
//! 7. **`CircuitState` three variants**: Closed, Open, HalfOpen.
//! 8. **`RequestPriority` four-level enum**: Critical, High, Normal,
//!    Low — Hash + Copy + Eq.
//! 9. **`ResilienceError` Display contract** — every variant produces
//!    a non-empty diagnostic string with the right keywords (callers
//!    grep these in incident logs).
//! 10. **`ResilienceMetricsSnapshot::default`** is all zero — fresh
//!     layer state has no observed traffic.

use fcp_host::{
    BulkheadConfig, CircuitBreakerConfig, CircuitState, FailurePredicate, HealthRouterConfig,
    LoadShedConfig, RequestPriority, ResilienceConfig, ResilienceError, ResilienceLayer,
    ResilienceMetricsSnapshot, RoutingDecision,
};
use fcp_prelude::ConnectorId;
use std::time::Duration;

// ─── CircuitBreakerConfig defaults ──────────────────────────────────

#[test]
fn circuit_breaker_default_failure_threshold_is_three() {
    let c = CircuitBreakerConfig::default();
    assert_eq!(
        c.failure_threshold, 3,
        "default failure_threshold MUST be 3 — drift here changes default flakiness tolerance"
    );
}

#[test]
fn circuit_breaker_default_success_threshold_is_two() {
    let c = CircuitBreakerConfig::default();
    assert_eq!(c.success_threshold, 2);
}

#[test]
fn circuit_breaker_default_open_duration_is_five_seconds() {
    let c = CircuitBreakerConfig::default();
    assert_eq!(c.open_duration, Duration::from_secs(5));
}

#[test]
fn circuit_breaker_default_window_duration_is_thirty_seconds() {
    let c = CircuitBreakerConfig::default();
    assert_eq!(c.window_duration, Duration::from_secs(30));
}

#[test]
fn circuit_breaker_default_predicate_is_any_error() {
    let c = CircuitBreakerConfig::default();
    assert_eq!(c.failure_predicate, FailurePredicate::AnyError);
}

// ─── BulkheadConfig defaults ────────────────────────────────────────

#[test]
fn bulkhead_default_max_concurrent_is_sixteen() {
    let b = BulkheadConfig::default();
    assert_eq!(b.max_concurrent, 16);
}

#[test]
fn bulkhead_default_max_queued_is_thirty_two() {
    let b = BulkheadConfig::default();
    assert_eq!(b.max_queued, 32);
}

#[test]
fn bulkhead_default_queue_timeout_is_two_fifty_ms() {
    let b = BulkheadConfig::default();
    assert_eq!(b.queue_timeout, Duration::from_millis(250));
}

// ─── HealthRouterConfig defaults ────────────────────────────────────

#[test]
fn health_router_default_unhealthy_threshold_is_three() {
    let h = HealthRouterConfig::default();
    assert_eq!(h.unhealthy_threshold, 3);
}

#[test]
fn health_router_default_recovery_success_threshold_is_two() {
    let h = HealthRouterConfig::default();
    assert_eq!(h.recovery_success_threshold, 2);
}

#[test]
fn health_router_default_latency_threshold_is_seven_fifty_ms() {
    let h = HealthRouterConfig::default();
    assert_eq!(h.latency_degraded_threshold, Duration::from_millis(750));
}

#[test]
fn health_router_default_error_rate_threshold_is_five_hundred_per_mille() {
    let h = HealthRouterConfig::default();
    assert_eq!(
        h.error_rate_degraded_threshold_per_mille, 500,
        "50% error-rate threshold (500‰) is the documented default"
    );
}

#[test]
fn health_router_default_probe_interval_is_five_seconds() {
    let h = HealthRouterConfig::default();
    assert_eq!(h.probe_interval, Duration::from_secs(5));
}

#[test]
fn health_router_default_error_window_is_thirty_seconds() {
    let h = HealthRouterConfig::default();
    assert_eq!(h.error_window, Duration::from_secs(30));
}

#[test]
fn health_router_default_latency_alpha_is_two_hundred_per_mille() {
    let h = HealthRouterConfig::default();
    assert_eq!(
        h.latency_alpha_per_mille, 200,
        "EWMA alpha 200‰ (0.2) is the documented default smoothing factor"
    );
}

// ─── LoadShedConfig defaults ────────────────────────────────────────

#[test]
fn load_shed_default_shed_threshold_is_eight_fifty_per_mille() {
    let l = LoadShedConfig::default();
    assert_eq!(
        l.shed_threshold_per_mille, 850,
        "load shedding starts at 85% load by default"
    );
}

#[test]
fn load_shed_default_full_shed_threshold_is_one_thousand_per_mille() {
    let l = LoadShedConfig::default();
    assert_eq!(
        l.full_shed_threshold_per_mille, 1_000,
        "full shedding at 100% load by default"
    );
}

#[test]
fn load_shed_default_sheddable_priorities_excludes_critical_and_high() {
    let l = LoadShedConfig::default();
    assert_eq!(
        l.sheddable_priorities,
        vec![RequestPriority::Low, RequestPriority::Normal],
        "default sheddable list MUST be [Low, Normal] — Critical and High are NEVER shed by default"
    );
    assert!(!l.sheddable_priorities.contains(&RequestPriority::Critical));
    assert!(!l.sheddable_priorities.contains(&RequestPriority::High));
}

// ─── ResilienceConfig top-level default ─────────────────────────────

#[test]
fn resilience_config_default_has_no_operation_timeout() {
    let c = ResilienceConfig::default();
    assert!(
        c.operation_timeout.is_none(),
        "operation_timeout default MUST be None — no per-op timeout unless host opts in"
    );
}

#[test]
fn resilience_config_default_composes_documented_subdefaults() {
    let c = ResilienceConfig::default();
    assert_eq!(c.circuit_breaker.failure_threshold, 3);
    assert_eq!(c.bulkhead.max_concurrent, 16);
    assert_eq!(c.health.unhealthy_threshold, 3);
    assert_eq!(c.load_shed.shed_threshold_per_mille, 850);
}

// ─── RoutingDecision variants ───────────────────────────────────────

#[test]
fn routing_decision_allow_equals_allow() {
    assert_eq!(RoutingDecision::Allow, RoutingDecision::Allow);
}

#[test]
fn routing_decision_allow_degraded_carries_reason() {
    let d = RoutingDecision::AllowDegraded {
        reason: "high latency".into(),
    };
    let cloned = d.clone();
    assert_eq!(d, cloned);
}

#[test]
fn routing_decision_allow_probe_is_distinct_from_allow() {
    assert_ne!(
        RoutingDecision::Allow,
        RoutingDecision::AllowProbe,
        "AllowProbe MUST be a distinct variant — probe metrics depend on this"
    );
}

#[test]
fn routing_decision_reject_carries_reason() {
    let d = RoutingDecision::Reject {
        reason: "circuit open".into(),
    };
    match d {
        RoutingDecision::Reject { reason } => assert_eq!(reason, "circuit open"),
        other => panic!("expected Reject, got {other:?}"),
    }
}

// ─── CircuitState variants ──────────────────────────────────────────

#[test]
fn circuit_state_three_variants_are_distinct() {
    assert_ne!(CircuitState::Closed, CircuitState::Open);
    assert_ne!(CircuitState::Open, CircuitState::HalfOpen);
    assert_ne!(CircuitState::Closed, CircuitState::HalfOpen);
}

#[test]
fn fresh_resilience_layer_starts_in_closed_circuit() {
    let layer = ResilienceLayer::default();
    let cid = ConnectorId::from_static("fcp:test:v1");
    layer.ensure_connector(&cid);
    assert_eq!(
        layer.circuit_state(&cid),
        CircuitState::Closed,
        "freshly-initialised connector circuit MUST start Closed (normal operation)"
    );
}

// ─── RequestPriority ────────────────────────────────────────────────

#[test]
fn request_priority_four_variants_are_distinct() {
    let all = [
        RequestPriority::Critical,
        RequestPriority::High,
        RequestPriority::Normal,
        RequestPriority::Low,
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i == j {
                assert_eq!(a, b);
            } else {
                assert_ne!(a, b, "RequestPriority variants MUST be distinct");
            }
        }
    }
}

#[test]
fn request_priority_implements_hash_for_use_in_hashmap() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(RequestPriority::Critical);
    set.insert(RequestPriority::High);
    set.insert(RequestPriority::Normal);
    set.insert(RequestPriority::Low);
    set.insert(RequestPriority::Critical); // dup
    assert_eq!(set.len(), 4, "Hash impl MUST collapse duplicates");
}

// ─── FailurePredicate variants ──────────────────────────────────────

#[test]
fn failure_predicate_four_variants_are_distinct() {
    let a = FailurePredicate::AnyError;
    let b = FailurePredicate::TimeoutsOnly;
    let c = FailurePredicate::SlowResponses {
        threshold: Duration::from_millis(100),
    };
    let d = FailurePredicate::ErrorOrSlowResponses {
        threshold: Duration::from_millis(100),
    };
    assert_ne!(a, b);
    assert_ne!(a, c);
    assert_ne!(a, d);
    assert_ne!(b, c);
    assert_ne!(c, d);
}

// ─── ResilienceError Display contract ───────────────────────────────

#[test]
fn resilience_error_load_shed_display_mentions_per_mille_load() {
    let e: ResilienceError<&str> = ResilienceError::LoadShed {
        load_per_mille: 950,
    };
    let s = format!("{e}");
    assert!(
        s.contains("950"),
        "LoadShed Display MUST include the load value; got {s}"
    );
    assert!(
        s.contains("shed") || s.contains("load"),
        "LoadShed Display MUST mention shedding/load; got {s}"
    );
}

#[test]
fn resilience_error_unhealthy_display_includes_reason() {
    let e: ResilienceError<&str> = ResilienceError::Unhealthy {
        reason: "5xx-spike".into(),
    };
    let s = format!("{e}");
    assert!(
        s.contains("5xx-spike"),
        "Unhealthy Display MUST include reason text; got {s}"
    );
    assert!(s.contains("unhealthy"));
}

#[test]
fn resilience_error_circuit_open_display_includes_retry_after() {
    let e: ResilienceError<&str> = ResilienceError::CircuitOpen {
        retry_after: Duration::from_millis(1234),
    };
    let s = format!("{e}");
    assert!(
        s.contains("1234"),
        "CircuitOpen Display MUST include retry_after ms; got {s}"
    );
    assert!(s.contains("circuit"));
}

#[test]
fn resilience_error_half_open_limited_display_is_specific() {
    let e: ResilienceError<&str> = ResilienceError::HalfOpenLimited;
    let s = format!("{e}");
    assert!(
        s.contains("half-open") || s.contains("probe"),
        "HalfOpenLimited Display MUST mention half-open or probe; got {s}"
    );
}

#[test]
fn resilience_error_bulkhead_full_display_mentions_bulkhead() {
    let e: ResilienceError<&str> = ResilienceError::BulkheadFull;
    let s = format!("{e}");
    assert!(
        s.contains("bulkhead"),
        "BulkheadFull Display MUST mention bulkhead; got {s}"
    );
}

#[test]
fn resilience_error_queue_timeout_display_includes_timeout() {
    let e: ResilienceError<&str> = ResilienceError::QueueTimeout {
        timeout: Duration::from_millis(250),
    };
    let s = format!("{e}");
    assert!(s.contains("250"), "got {s}");
    assert!(s.contains("queue") || s.contains("bulkhead"), "got {s}");
}

#[test]
fn resilience_error_timed_out_display_includes_timeout() {
    let e: ResilienceError<&str> = ResilienceError::TimedOut {
        timeout: Duration::from_millis(500),
    };
    let s = format!("{e}");
    assert!(s.contains("500"), "got {s}");
    assert!(s.contains("timed out"), "got {s}");
}

#[test]
fn resilience_error_inner_display_propagates_inner_error() {
    let e: ResilienceError<&str> = ResilienceError::Inner("upstream-500");
    let s = format!("{e}");
    assert!(
        s.contains("upstream-500"),
        "Inner Display MUST surface inner error text; got {s}"
    );
}

// ─── ResilienceMetricsSnapshot defaults ─────────────────────────────

#[test]
fn metrics_snapshot_default_is_all_zero() {
    let m = ResilienceMetricsSnapshot::default();
    assert_eq!(m.requests, 0);
    assert_eq!(m.successes, 0);
    assert_eq!(m.failures, 0);
    assert_eq!(m.timeouts, 0);
    assert_eq!(m.circuit_rejections, 0);
    assert_eq!(m.circuit_opened, 0);
    assert_eq!(m.bulkhead_rejections, 0);
    assert_eq!(m.load_shed, 0);
    assert_eq!(m.probe_requests, 0);
}

#[test]
fn fresh_resilience_layer_metrics_for_new_connector_are_zero() {
    let layer = ResilienceLayer::default();
    let cid = ConnectorId::from_static("fcp:fresh:v1");
    layer.ensure_connector(&cid);
    let m = layer.metrics(&cid);
    assert_eq!(
        m,
        ResilienceMetricsSnapshot::default(),
        "freshly-ensured connector MUST have all-zero metrics"
    );
}
