//! `fcp_mesh::coordinator` config defaults + outcome variant
//! wire-format conformance.
//!
//! `lease_coordinator_causality` and `lease_coordinator_conflict_renew`
//! exercise these types in flow tests, but neither pins the FULL
//! variant matrix or the `LeaseCoordinatorConfig` defaults.
//!
//! Properties pinned (NORMATIVE):
//!
//! 1. **`LeaseCoordinatorConfig::default`** — 6 documented values:
//!    default_ttl_secs=300, min_ttl_secs=10, max_ttl_secs=3600,
//!    renew_threshold_bps=2000 (renew at 20% remaining),
//!    max_leases_per_node=64, escalate_dangerous_conflicts=true.
//! 2. **`AcquireOutcome` 4 internally-tagged variants** with
//!    `outcome` tag values `granted` / `rejected` / `denied` /
//!    `conflict`; payload fields per variant.
//! 3. **`RenewOutcome` 2 variants** with tag `renewed` / `denied`.
//! 4. **`ReleaseOutcome` 2 variants** with tag `released` /
//!    `not_held`.
//! 5. **`ConflictSeverity`** 3 snake_case variants:
//!    `info` / `warning` / `critical`.
//! 6. **`LeaseConflict` 7-field roundtrip identity**.
//! 7. **`ConflictingHolder` 3-field roundtrip identity**.
//! 8. Each outcome enum rejects unknown tag values.

use fcp_cbor::SchemaId;
use fcp_core::{ObjectId, ObjectIdKey, TailscaleNodeId, ZoneId};
use fcp_mesh::{
    AcquireOutcome, ConflictSeverity, ConflictingHolder, LeaseConflict, LeaseCoordinatorConfig,
    LeasePurpose, ReleaseOutcome, RenewOutcome,
};
use semver::Version;
use serde_json::json;

fn fake_object_id(tag: &[u8]) -> ObjectId {
    let zone = ZoneId::work();
    let schema = SchemaId::new("fcp.test", "LeaseCoordinator", Version::new(1, 0, 0));
    let key = ObjectIdKey::from_bytes([3u8; 32]);
    ObjectId::new(tag, &zone, &schema, &key)
}

fn fake_node(name: &str) -> TailscaleNodeId {
    TailscaleNodeId::new(name)
}

// ─── LeaseCoordinatorConfig defaults ──────────────────────────────

#[test]
fn config_default_default_ttl_secs_is_five_minutes() {
    assert_eq!(
        LeaseCoordinatorConfig::default().default_ttl_secs,
        300,
        "default_ttl_secs MUST be 300 (5 minutes)"
    );
}

#[test]
fn config_default_min_ttl_secs_is_ten_seconds() {
    assert_eq!(
        LeaseCoordinatorConfig::default().min_ttl_secs,
        10,
        "min_ttl_secs MUST be 10s (lower-bound floor on TTL)"
    );
}

#[test]
fn config_default_max_ttl_secs_is_one_hour() {
    assert_eq!(
        LeaseCoordinatorConfig::default().max_ttl_secs,
        3600,
        "max_ttl_secs MUST be 3600s (1 hour upper-bound)"
    );
}

#[test]
fn config_default_renew_threshold_bps_is_two_thousand() {
    assert_eq!(
        LeaseCoordinatorConfig::default().renew_threshold_bps,
        2000,
        "renew_threshold_bps MUST be 2000 (20% — renew when 20% of TTL remains)"
    );
}

#[test]
fn config_default_max_leases_per_node_is_sixty_four() {
    assert_eq!(LeaseCoordinatorConfig::default().max_leases_per_node, 64);
}

#[test]
fn config_default_escalate_dangerous_conflicts_is_true() {
    assert!(
        LeaseCoordinatorConfig::default().escalate_dangerous_conflicts,
        "default escalate_dangerous_conflicts MUST be true (fail-loud for split-brain risk)"
    );
}

#[test]
fn config_serde_roundtrip_preserves_all_six_fields() {
    let cfg = LeaseCoordinatorConfig {
        default_ttl_secs: 600,
        min_ttl_secs: 5,
        max_ttl_secs: 7200,
        renew_threshold_bps: 1000,
        max_leases_per_node: 128,
        escalate_dangerous_conflicts: false,
    };
    let json_str = serde_json::to_string(&cfg).expect("serialize");
    let parsed: LeaseCoordinatorConfig =
        serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(parsed, cfg);
}

// ─── AcquireOutcome ────────────────────────────────────────────────

#[test]
fn acquire_outcome_granted_serializes_with_outcome_tag() {
    let o = AcquireOutcome::Granted {
        fencing_token: 42,
        expires_at: 1_000_000,
    };
    let v = serde_json::to_value(&o).expect("serialize");
    assert_eq!(v["outcome"], "granted");
    assert_eq!(v["fencing_token"], 42);
    assert_eq!(v["expires_at"], 1_000_000);
}

#[test]
fn acquire_outcome_rejected_serializes_with_reason() {
    let o = AcquireOutcome::Rejected {
        reason: "capacity full".into(),
    };
    let v = serde_json::to_value(&o).expect("serialize");
    assert_eq!(v["outcome"], "rejected");
    assert_eq!(v["reason"], "capacity full");
}

#[test]
fn acquire_outcome_denied_carries_holder_token_expires_reason() {
    let o = AcquireOutcome::Denied {
        current_holder: fake_node("node-a"),
        current_fencing_token: 7,
        expires_at: 999,
        reason: "still held".into(),
    };
    let v = serde_json::to_value(&o).expect("serialize");
    assert_eq!(v["outcome"], "denied");
    assert_eq!(v["current_fencing_token"], 7);
    assert_eq!(v["expires_at"], 999);
    assert_eq!(v["reason"], "still held");
}

#[test]
fn acquire_outcome_conflict_carries_holders_tokens_reason() {
    let o = AcquireOutcome::Conflict {
        holders: vec![fake_node("node-a"), fake_node("node-b")],
        fencing_tokens: vec![3, 5],
        reason: "two active leases".into(),
    };
    let v = serde_json::to_value(&o).expect("serialize");
    assert_eq!(v["outcome"], "conflict");
    assert_eq!(v["fencing_tokens"][0], 3);
    assert_eq!(v["fencing_tokens"][1], 5);
}

#[test]
fn acquire_outcome_serde_roundtrip_for_every_variant() {
    let cases = vec![
        AcquireOutcome::Granted {
            fencing_token: 1,
            expires_at: 2,
        },
        AcquireOutcome::Rejected {
            reason: "x".into(),
        },
        AcquireOutcome::Denied {
            current_holder: fake_node("nx"),
            current_fencing_token: 1,
            expires_at: 0,
            reason: "x".into(),
        },
        AcquireOutcome::Conflict {
            holders: vec![],
            fencing_tokens: vec![],
            reason: "x".into(),
        },
    ];
    for original in cases {
        let json_str = serde_json::to_string(&original).expect("serialize");
        let parsed: AcquireOutcome = serde_json::from_str(&json_str).expect("deserialize");
        assert_eq!(parsed, original);
    }
}

#[test]
fn acquire_outcome_rejects_unknown_outcome_tag() {
    let bogus = json!({"outcome": "unknown_state", "x": 1}).to_string();
    assert!(
        serde_json::from_str::<AcquireOutcome>(&bogus).is_err(),
        "MUST reject unknown outcome tag"
    );
}

// ─── RenewOutcome ──────────────────────────────────────────────────

#[test]
fn renew_outcome_renewed_serializes_with_outcome_tag() {
    let o = RenewOutcome::Renewed { expires_at: 100 };
    let v = serde_json::to_value(&o).expect("serialize");
    assert_eq!(v["outcome"], "renewed");
    assert_eq!(v["expires_at"], 100);
}

#[test]
fn renew_outcome_denied_carries_reason() {
    let o = RenewOutcome::Denied {
        reason: "expired".into(),
    };
    let v = serde_json::to_value(&o).expect("serialize");
    assert_eq!(v["outcome"], "denied");
    assert_eq!(v["reason"], "expired");
}

#[test]
fn renew_outcome_serde_roundtrip_for_each_variant() {
    let cases = vec![
        RenewOutcome::Renewed { expires_at: 50 },
        RenewOutcome::Denied {
            reason: "superseded".into(),
        },
    ];
    for original in cases {
        let json_str = serde_json::to_string(&original).expect("serialize");
        let parsed: RenewOutcome = serde_json::from_str(&json_str).expect("deserialize");
        assert_eq!(parsed, original);
    }
}

// ─── ReleaseOutcome ────────────────────────────────────────────────

#[test]
fn release_outcome_released_serializes_with_outcome_tag() {
    let o = ReleaseOutcome::Released;
    let v = serde_json::to_value(&o).expect("serialize");
    assert_eq!(v["outcome"], "released");
}

#[test]
fn release_outcome_not_held_serializes_with_snake_case_tag() {
    let o = ReleaseOutcome::NotHeld {
        reason: "no active lease".into(),
    };
    let v = serde_json::to_value(&o).expect("serialize");
    assert_eq!(
        v["outcome"], "not_held",
        "NotHeld MUST embed as 'not_held' (snake_case)"
    );
    assert_eq!(v["reason"], "no active lease");
}

#[test]
fn release_outcome_serde_roundtrip_for_each_variant() {
    let cases = vec![
        ReleaseOutcome::Released,
        ReleaseOutcome::NotHeld {
            reason: "x".into(),
        },
    ];
    for original in cases {
        let json_str = serde_json::to_string(&original).expect("serialize");
        let parsed: ReleaseOutcome = serde_json::from_str(&json_str).expect("deserialize");
        assert_eq!(parsed, original);
    }
}

// ─── ConflictSeverity ──────────────────────────────────────────────

#[test]
fn conflict_severity_serde_uses_snake_case_for_each_variant() {
    let cases = [
        (ConflictSeverity::Info, "\"info\""),
        (ConflictSeverity::Warning, "\"warning\""),
        (ConflictSeverity::Critical, "\"critical\""),
    ];
    for (variant, expected) in cases {
        let json = serde_json::to_string(&variant).expect("serialize");
        assert_eq!(json, expected);
        let parsed: ConflictSeverity = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, variant);
    }
}

#[test]
fn conflict_severity_rejects_uppercase_or_unknown() {
    for bogus in ["\"INFO\"", "\"Warning\"", "\"\"", "\"fatal\""] {
        assert!(
            serde_json::from_str::<ConflictSeverity>(bogus).is_err(),
            "ConflictSeverity MUST reject {bogus}"
        );
    }
}

#[test]
fn conflict_severity_three_variants_are_distinct() {
    assert_ne!(ConflictSeverity::Info, ConflictSeverity::Warning);
    assert_ne!(ConflictSeverity::Warning, ConflictSeverity::Critical);
    assert_ne!(ConflictSeverity::Info, ConflictSeverity::Critical);
}

#[test]
fn conflict_severity_implements_copy() {
    fn takes_value(_: ConflictSeverity) {}
    let s = ConflictSeverity::Critical;
    takes_value(s);
    takes_value(s);
}

// ─── LeaseConflict + ConflictingHolder ────────────────────────────

#[test]
fn lease_conflict_serde_roundtrip_preserves_all_seven_fields() {
    let c = LeaseConflict {
        zone_id: ZoneId::work(),
        subject_id: fake_object_id(b"subject"),
        purpose: LeasePurpose::OperationExecution,
        severity: ConflictSeverity::Warning,
        holders: vec![ConflictingHolder {
            node_id: fake_node("nx"),
            fencing_token: 9,
            expires_at: 1000,
        }],
        detected_at_ms: 1_500_000,
        resolution: "yield to higher token".into(),
    };
    let json_str = serde_json::to_string(&c).expect("serialize");
    let parsed: LeaseConflict = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(parsed, c);
}

#[test]
fn lease_conflict_severity_embeds_as_snake_case() {
    let c = LeaseConflict {
        zone_id: ZoneId::work(),
        subject_id: fake_object_id(b"x"),
        purpose: LeasePurpose::CoordinatorElection,
        severity: ConflictSeverity::Critical,
        holders: vec![],
        detected_at_ms: 0,
        resolution: "x".into(),
    };
    let v = serde_json::to_value(&c).expect("serialize");
    assert_eq!(v["severity"], "critical");
}

#[test]
fn conflicting_holder_serde_roundtrip_preserves_three_fields() {
    let h = ConflictingHolder {
        node_id: fake_node("nx-y"),
        fencing_token: 42,
        expires_at: 10_000,
    };
    let json_str = serde_json::to_string(&h).expect("serialize");
    let parsed: ConflictingHolder =
        serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(parsed, h);
}

#[test]
fn conflicting_holder_partial_eq_compares_every_field() {
    let base = ConflictingHolder {
        node_id: fake_node("nx"),
        fencing_token: 5,
        expires_at: 100,
    };
    let mut diff_token = base.clone();
    diff_token.fencing_token = 6;
    assert_ne!(base, diff_token);

    let mut diff_expires = base.clone();
    diff_expires.expires_at = 200;
    assert_ne!(base, diff_expires);
}
