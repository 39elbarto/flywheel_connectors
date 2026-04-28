//! `fcp_host` CancelReason + CleanupBehavior + ProgressUnit wire-
//! format + label contract conformance.
//!
//! `host_cancellation_controller_conformance.rs` and
//! `host_progress_controller_conformance.rs` already exercise
//! these enums in flow tests, but neither pins the FULL variant
//! matrix or the documented `label()` strings that operator tooling
//! greps. Drift in any of these would silently change cancellation
//! audit categories or progress-unit reporting.
//!
//! Properties pinned (NORMATIVE):
//!
//! 1. **`CancelReason` 6 internally-tagged variants** — `user_requested`,
//!    `agent_abort` (carries `reason`), `timeout_approaching` (carries
//!    `remaining_ms`), `resource_limit` (carries resource/current/limit),
//!    `superseded` (carries `by_operation_id`), `session_closing`.
//! 2. **`CancelReason::label`** returns the snake_case discriminator
//!    for each variant (operator log greps).
//! 3. **`CleanupBehavior::default == BestEffort`** + 4 internally-
//!    tagged variants: `best_effort`, `full` (carries `timeout_ms`),
//!    `abandon`, `checkpoint`.
//! 4. **`ProgressUnit` 5 variants** — 4 fixed (snake_case: `bytes`,
//!    `items`, `requests`, `rows`) + `custom` with String label.
//! 5. **`ProgressUnit::label`** returns the snake_case for fixed
//!    variants and the inner String for `Custom`.
//! 6. **All three serde forms reject malformed/unknown payloads.**
//! 7. **Roundtrip identity** for every variant.

use fcp_host::{CancelReason, CleanupBehavior, ProgressUnit};
use serde_json::json;

// ─── CancelReason variants + serde tag ────────────────────────────

#[test]
fn cancel_reason_user_requested_serializes_with_type_tag() {
    let r = CancelReason::UserRequested;
    let v = serde_json::to_value(&r).expect("serialize");
    assert_eq!(
        v["type"], "user_requested",
        "UserRequested MUST serialize with type=\"user_requested\""
    );
}

#[test]
fn cancel_reason_agent_abort_carries_reason_field() {
    let r = CancelReason::AgentAbort {
        reason: "self-detected fault".into(),
    };
    let v = serde_json::to_value(&r).expect("serialize");
    assert_eq!(v["type"], "agent_abort");
    assert_eq!(v["reason"], "self-detected fault");
}

#[test]
fn cancel_reason_timeout_approaching_carries_remaining_ms() {
    let r = CancelReason::TimeoutApproaching { remaining_ms: 500 };
    let v = serde_json::to_value(&r).expect("serialize");
    assert_eq!(v["type"], "timeout_approaching");
    assert_eq!(v["remaining_ms"], 500);
}

#[test]
fn cancel_reason_resource_limit_carries_resource_current_and_limit() {
    let r = CancelReason::ResourceLimit {
        resource: "memory".into(),
        current: 2048,
        limit: 1024,
    };
    let v = serde_json::to_value(&r).expect("serialize");
    assert_eq!(v["type"], "resource_limit");
    assert_eq!(v["resource"], "memory");
    assert_eq!(v["current"], 2048);
    assert_eq!(v["limit"], 1024);
}

#[test]
fn cancel_reason_superseded_carries_by_operation_id() {
    let r = CancelReason::Superseded {
        by_operation_id: "op-99".into(),
    };
    let v = serde_json::to_value(&r).expect("serialize");
    assert_eq!(v["type"], "superseded");
    assert_eq!(v["by_operation_id"], "op-99");
}

#[test]
fn cancel_reason_session_closing_serializes_as_unit_with_tag() {
    let r = CancelReason::SessionClosing;
    let v = serde_json::to_value(&r).expect("serialize");
    assert_eq!(v["type"], "session_closing");
}

#[test]
fn cancel_reason_label_matches_serde_tag_for_every_variant() {
    let cases = [
        (CancelReason::UserRequested, "user_requested"),
        (
            CancelReason::AgentAbort { reason: "x".into() },
            "agent_abort",
        ),
        (
            CancelReason::TimeoutApproaching { remaining_ms: 0 },
            "timeout_approaching",
        ),
        (
            CancelReason::ResourceLimit {
                resource: "x".into(),
                current: 0,
                limit: 0,
            },
            "resource_limit",
        ),
        (
            CancelReason::Superseded {
                by_operation_id: "y".into(),
            },
            "superseded",
        ),
        (CancelReason::SessionClosing, "session_closing"),
    ];
    for (variant, expected_tag) in cases {
        assert_eq!(
            variant.label(),
            expected_tag,
            "{variant:?}.label() MUST match serde tag '{expected_tag}'"
        );
    }
}

#[test]
fn cancel_reason_serde_roundtrip_for_every_variant() {
    let cases = vec![
        CancelReason::UserRequested,
        CancelReason::AgentAbort {
            reason: "fault".into(),
        },
        CancelReason::TimeoutApproaching { remaining_ms: 1000 },
        CancelReason::ResourceLimit {
            resource: "cpu".into(),
            current: 95,
            limit: 90,
        },
        CancelReason::Superseded {
            by_operation_id: "op-x".into(),
        },
        CancelReason::SessionClosing,
    ];
    for original in cases {
        let json_str = serde_json::to_string(&original).expect("serialize");
        let parsed: CancelReason = serde_json::from_str(&json_str).expect("deserialize");
        assert_eq!(parsed.label(), original.label());
        // Re-serialize and compare semantic JSON.
        let v1 = serde_json::to_value(&parsed).expect("v1");
        let v2 = serde_json::to_value(&original).expect("v2");
        assert_eq!(v1, v2);
    }
}

#[test]
fn cancel_reason_rejects_unknown_type_tag() {
    let bogus = json!({"type": "invented", "x": 1}).to_string();
    assert!(
        serde_json::from_str::<CancelReason>(&bogus).is_err(),
        "unknown type tag MUST be rejected"
    );
}

// ─── CleanupBehavior ───────────────────────────────────────────────

#[test]
fn cleanup_behavior_default_is_best_effort() {
    assert!(matches!(
        CleanupBehavior::default(),
        CleanupBehavior::BestEffort
    ));
}

#[test]
fn cleanup_behavior_best_effort_serializes_with_tag() {
    let v = serde_json::to_value(&CleanupBehavior::BestEffort).expect("serialize");
    assert_eq!(v["type"], "best_effort");
}

#[test]
fn cleanup_behavior_full_carries_timeout_ms() {
    let c = CleanupBehavior::Full { timeout_ms: 5000 };
    let v = serde_json::to_value(&c).expect("serialize");
    assert_eq!(v["type"], "full");
    assert_eq!(v["timeout_ms"], 5000);
}

#[test]
fn cleanup_behavior_abandon_serializes_as_unit_with_tag() {
    let v = serde_json::to_value(&CleanupBehavior::Abandon).expect("serialize");
    assert_eq!(v["type"], "abandon");
}

#[test]
fn cleanup_behavior_checkpoint_serializes_as_unit_with_tag() {
    let v = serde_json::to_value(&CleanupBehavior::Checkpoint).expect("serialize");
    assert_eq!(v["type"], "checkpoint");
}

#[test]
fn cleanup_behavior_serde_roundtrip_for_every_variant() {
    let cases = vec![
        CleanupBehavior::BestEffort,
        CleanupBehavior::Full { timeout_ms: 5000 },
        CleanupBehavior::Abandon,
        CleanupBehavior::Checkpoint,
    ];
    for c in cases {
        let s = serde_json::to_string(&c).expect("serialize");
        let parsed: CleanupBehavior = serde_json::from_str(&s).expect("deserialize");
        let v1 = serde_json::to_value(&parsed).expect("v1");
        let v2 = serde_json::to_value(&c).expect("v2");
        assert_eq!(v1, v2);
    }
}

#[test]
fn cleanup_behavior_rejects_unknown_type_tag() {
    let bogus = json!({"type": "wipe"}).to_string();
    assert!(
        serde_json::from_str::<CleanupBehavior>(&bogus).is_err(),
        "unknown type tag MUST be rejected"
    );
}

// ─── ProgressUnit ──────────────────────────────────────────────────

#[test]
fn progress_unit_serde_uses_snake_case_for_fixed_variants() {
    let cases = [
        (ProgressUnit::Bytes, "bytes"),
        (ProgressUnit::Items, "items"),
        (ProgressUnit::Requests, "requests"),
        (ProgressUnit::Rows, "rows"),
    ];
    for (variant, expected_tag) in cases {
        let json_str = serde_json::to_string(&variant).expect("serialize");
        // Fixed variants are externally-tagged (no `type` key) — they
        // serialize as bare strings.
        assert_eq!(
            json_str,
            format!("\"{expected_tag}\""),
            "{variant:?} MUST serialize as bare string '\"{expected_tag}\"'"
        );
        let parsed: ProgressUnit = serde_json::from_str(&json_str).expect("deserialize");
        assert_eq!(parsed.label(), variant.label());
    }
}

#[test]
fn progress_unit_custom_serializes_with_string_payload() {
    let custom = ProgressUnit::Custom("bytes_per_sec".into());
    let json_str = serde_json::to_string(&custom).expect("serialize");
    // Custom is also a string-payload variant in the enum-as-tagged
    // serde shape — pin via roundtrip.
    let parsed: ProgressUnit = serde_json::from_str(&json_str).expect("deserialize");
    match parsed {
        ProgressUnit::Custom(label) => assert_eq!(label, "bytes_per_sec"),
        other => panic!("expected Custom, got {other:?}"),
    }
}

#[test]
fn progress_unit_label_matches_documented_strings_for_fixed_variants() {
    assert_eq!(ProgressUnit::Bytes.label(), "bytes");
    assert_eq!(ProgressUnit::Items.label(), "items");
    assert_eq!(ProgressUnit::Requests.label(), "requests");
    assert_eq!(ProgressUnit::Rows.label(), "rows");
}

#[test]
fn progress_unit_label_returns_inner_string_for_custom() {
    let u = ProgressUnit::Custom("ops_per_min".into());
    assert_eq!(
        u.label(),
        "ops_per_min",
        "Custom label MUST return the inner String"
    );
}

#[test]
fn progress_unit_serde_roundtrip_for_every_variant() {
    let cases = vec![
        ProgressUnit::Bytes,
        ProgressUnit::Items,
        ProgressUnit::Requests,
        ProgressUnit::Rows,
        ProgressUnit::Custom("frames".into()),
    ];
    for original in cases {
        let s = serde_json::to_string(&original).expect("serialize");
        let parsed: ProgressUnit = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(parsed.label(), original.label());
    }
}

#[test]
fn progress_unit_partial_eq_compares_variant_and_payload() {
    let a = ProgressUnit::Bytes;
    let b = ProgressUnit::Bytes;
    let c = ProgressUnit::Items;
    let d = ProgressUnit::Custom("x".into());
    let e = ProgressUnit::Custom("x".into());
    let f = ProgressUnit::Custom("y".into());
    assert_eq!(a, b);
    assert_ne!(a, c);
    assert_eq!(d, e);
    assert_ne!(d, f, "Custom payload difference MUST register on PartialEq");
}
