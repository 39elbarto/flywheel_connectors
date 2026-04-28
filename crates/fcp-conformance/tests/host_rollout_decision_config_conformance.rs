//! `fcp_host::rollout` controller config + `RolloutDecision` wire
//! format conformance.
//!
//! Staged-deploy decisions flow through `RolloutDecision` and the
//! host's `RolloutControllerConfig` gates auto-promotion. Drift in
//! either silently changes how aggressively the host promotes /
//! rolls back canary deployments — every release-engineering
//! dashboard and rollout-audit consumer depends on these.
//!
//! Properties pinned (NORMATIVE):
//!
//! 1. **`RolloutControllerConfig::default`** — 4 documented values:
//!    - `min_uptime_secs_for_promotion = 60` (1 minute soak)
//!    - `allow_unsupported_self_check_promotion = true`
//!    - `crash_loop_threshold = 3`
//!    - `crash_loop_window_secs = 300` (5 minute window)
//! 2. **`RolloutDecision` 4 snake_case variants** — `scheduled` /
//!    `hold` / `promote` / `rollback`.
//! 3. **`RolloutDecision::as_str` returns the same snake_case
//!    string** as the serde wire form (logs ↔ JSON parity).
//! 4. **`RolloutDecision` rejects unknown / mixed-case JSON values.**
//! 5. **`RolloutDecision` Copy + Eq** — used in dashboard counters.
//! 6. **`RolloutObservation::new`** initialises latency=None,
//!    uptime=0, pinned=false, crashed=false, observed_at=now.
//! 7. **`with_latency_ms` / `with_uptime_secs`** builders preserve
//!    the policy + invocation_succeeded fields they carry through.

use chrono::Utc;
use fcp_core::RolloutPolicy;
use fcp_host::{RolloutControllerConfig, RolloutDecision, RolloutObservation};

// ─── RolloutControllerConfig defaults ──────────────────────────────

#[test]
fn rollout_controller_config_default_min_uptime_for_promotion_is_sixty_seconds() {
    let c = RolloutControllerConfig::default();
    assert_eq!(
        c.min_uptime_secs_for_promotion, 60,
        "default min_uptime_secs_for_promotion MUST be 60s — drift changes \
         how quickly canaries auto-promote"
    );
}

#[test]
fn rollout_controller_config_default_allows_unsupported_self_check_promotion() {
    let c = RolloutControllerConfig::default();
    assert!(
        c.allow_unsupported_self_check_promotion,
        "default MUST be true — connectors without self-check still auto-promote \
         under the documented host policy"
    );
}

#[test]
fn rollout_controller_config_default_crash_loop_threshold_is_three() {
    let c = RolloutControllerConfig::default();
    assert_eq!(
        c.crash_loop_threshold, 3,
        "default crash_loop_threshold MUST be 3 (3 crashes within window)"
    );
}

#[test]
fn rollout_controller_config_default_crash_loop_window_is_five_minutes() {
    let c = RolloutControllerConfig::default();
    assert_eq!(
        c.crash_loop_window_secs, 300,
        "default crash_loop_window_secs MUST be 300s (5 min)"
    );
}

// ─── RolloutDecision wire format ──────────────────────────────────

#[test]
fn rollout_decision_serde_uses_snake_case_for_each_variant() {
    let cases = [
        (RolloutDecision::Scheduled, "\"scheduled\""),
        (RolloutDecision::Hold, "\"hold\""),
        (RolloutDecision::Promote, "\"promote\""),
        (RolloutDecision::Rollback, "\"rollback\""),
    ];
    for (variant, expected) in cases {
        let json = serde_json::to_string(&variant).expect("serialize");
        assert_eq!(
            json, expected,
            "{variant:?} MUST serialize as snake_case '{expected}'"
        );
        let parsed: RolloutDecision = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, variant);
    }
}

#[test]
fn rollout_decision_as_str_matches_serde_wire_form() {
    // Stable string representation MUST match what serde emits.
    // Logging code uses as_str(); JSON consumers see the serde form;
    // they MUST be identical.
    for (variant, snake) in [
        (RolloutDecision::Scheduled, "scheduled"),
        (RolloutDecision::Hold, "hold"),
        (RolloutDecision::Promote, "promote"),
        (RolloutDecision::Rollback, "rollback"),
    ] {
        assert_eq!(variant.as_str(), snake);
        let json = serde_json::to_string(&variant).expect("serialize");
        let stripped = json.trim_matches('"');
        assert_eq!(
            stripped,
            variant.as_str(),
            "as_str ({}) MUST match serde wire form ({stripped}) for log/JSON parity",
            variant.as_str()
        );
    }
}

#[test]
fn rollout_decision_rejects_unknown_or_uppercase_variants() {
    for bogus in [
        "\"SCHEDULED\"",
        "\"Scheduled\"",
        "\"\"",
        "\"unknown\"",
        "\"forward\"",
    ] {
        assert!(
            serde_json::from_str::<RolloutDecision>(bogus).is_err(),
            "RolloutDecision MUST reject {bogus}"
        );
    }
}

#[test]
fn rollout_decision_implements_copy() {
    fn takes_value(_: RolloutDecision) {}
    let d = RolloutDecision::Promote;
    takes_value(d);
    takes_value(d);
    assert_eq!(d, RolloutDecision::Promote);
}

#[test]
fn rollout_decision_four_variants_are_distinct() {
    let all = [
        RolloutDecision::Scheduled,
        RolloutDecision::Hold,
        RolloutDecision::Promote,
        RolloutDecision::Rollback,
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j {
                assert_ne!(a, b, "RolloutDecision variants MUST be distinct");
            }
        }
    }
}

// ─── RolloutObservation builders ──────────────────────────────────

#[test]
fn rollout_observation_new_initialises_documented_defaults() {
    let policy = RolloutPolicy::default();
    let before = Utc::now();
    let obs = RolloutObservation::new(true, policy.clone());
    let after = Utc::now();

    assert!(
        obs.invocation_succeeded,
        "invocation_succeeded MUST reflect the constructor argument"
    );
    assert!(
        obs.latency_ms.is_none(),
        "latency_ms MUST default to None — caller adds via builder"
    );
    assert_eq!(obs.uptime_secs, 0, "uptime_secs MUST default to 0");
    assert!(!obs.pinned, "pinned MUST default to false");
    assert!(!obs.crashed, "crashed MUST default to false");
    assert!(
        obs.observed_at >= before && obs.observed_at <= after,
        "observed_at MUST be 'now' at constructor call time; before={before}, observed_at={}, after={after}",
        obs.observed_at
    );
}

#[test]
fn with_latency_ms_sets_latency_field_only() {
    let policy = RolloutPolicy::default();
    let obs = RolloutObservation::new(true, policy).with_latency_ms(123);
    assert_eq!(obs.latency_ms, Some(123));
    // Other fields preserved.
    assert!(obs.invocation_succeeded);
    assert_eq!(obs.uptime_secs, 0);
    assert!(!obs.pinned);
    assert!(!obs.crashed);
}

#[test]
fn with_uptime_secs_sets_uptime_field_only() {
    let policy = RolloutPolicy::default();
    let obs = RolloutObservation::new(true, policy).with_uptime_secs(3600);
    assert_eq!(obs.uptime_secs, 3600);
    assert!(obs.latency_ms.is_none());
    assert!(obs.invocation_succeeded);
}

#[test]
fn observation_builder_chain_preserves_all_fields() {
    let policy = RolloutPolicy::default();
    let obs = RolloutObservation::new(false, policy)
        .with_latency_ms(50)
        .with_uptime_secs(120);
    assert!(!obs.invocation_succeeded);
    assert_eq!(obs.latency_ms, Some(50));
    assert_eq!(obs.uptime_secs, 120);
    assert!(!obs.pinned);
    assert!(!obs.crashed);
}

// ─── Cross-default sanity ─────────────────────────────────────────

#[test]
fn config_default_is_safe_for_test_construction() {
    // Constructible without panic — sanity check the Default impl
    // doesn't depend on env or file state.
    let _ = RolloutControllerConfig::default();
}
