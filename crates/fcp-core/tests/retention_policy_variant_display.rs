//! Pin `UsageBudgetPolicy` + paired serde shape — the closest
//! analogue to "RetentionPolicy variant Display + serde tag"
//! (flywheel_connectors-g2up1).
//!
//! Bead asks for `RetentionPolicy variant Display + serde tag`. No
//! type literally named `RetentionPolicy` exists in fcp-core. The
//! retention/policy classifier surface covers many already-pinned
//! enums:
//!  - `EvictionPolicy` (= `RetentionClass`, externally-tagged
//!    Pinned/Lease/Ephemeral) already pinned by x2yxk.
//!  - `FreshnessPolicy` (Strict/Warn/BestEffort) already pinned by
//!    `recall_policy_variant_matrix.rs`.
//!  - `BudgetEnforcement` already pinned by b6x37.
//!  - `ZoneTransportPolicy` already pinned by cfwab.
//!  - `DecisionReceiptPolicy` already pinned via
//!    `zone_admission_policy_serde.rs`.
//!
//! The unpinned `<Foo>Policy`-shaped surface in policy.rs is the
//! usage-budget cluster:
//!
//!  - `UsageBudgetPolicy` (policy.rs:113) — 2-field struct
//!    (enforcement: BudgetEnforcement + budgets: Vec<UsageBudgetLimit>)
//!  - `UsageBudgetLimit` (policy.rs:102) — 3-field struct
//!    (metric / limit / window_seconds)
//!  - `UsageBudgetUsage` (policy.rs:132) — 7-field usage report
//!  - `UsageBudgetSnapshot` (policy.rs:151) — 4-field zone snapshot
//!
//! Targets:
//!
//!   1. **`UsageBudgetPolicy` 2-field JSON shape** with nested
//!      enforcement enum + Vec<UsageBudgetLimit>.
//!   2. **JSON + CBOR round-trip** preserves all fields including
//!      nested vec.
//!   3. **`UsageBudgetLimit` 3-field JSON shape** with nested
//!      `metric: UsageMetricKind` (snake_case) tag.
//!   4. **`UsageBudgetLimit` round-trip** at boundary u64 values.
//!   5. **`UsageBudgetUsage` 7-field shape** with nested
//!      BudgetStatus tag.
//!   6. **`UsageBudgetSnapshot` 4-field shape** with nested
//!      UsageBudgetUsage list ordering preserved.
//!   7. **Empty `budgets` Vec** preserved through round-trip
//!      (NOT omitted — there's no `skip_serializing_if`).
//!   8. **Distinct metrics produce distinct serializations**.

use fcp_core::{
    BudgetEnforcement, BudgetStatus, UsageBudgetLimit, UsageBudgetPolicy, UsageBudgetSnapshot,
    UsageBudgetUsage, UsageMetricKind, ZoneId,
};

fn sample_limit(metric: UsageMetricKind, limit: u64) -> UsageBudgetLimit {
    UsageBudgetLimit {
        metric,
        limit,
        window_seconds: 3_600,
    }
}

fn sample_policy() -> UsageBudgetPolicy {
    UsageBudgetPolicy {
        enforcement: BudgetEnforcement::Deny,
        budgets: vec![
            sample_limit(UsageMetricKind::ApiCredits, 10_000),
            sample_limit(UsageMetricKind::Tokens, 1_000_000),
        ],
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. UsageBudgetPolicy 2-field JSON shape
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn usage_budget_policy_json_shape_pinned() {
    let policy = sample_policy();
    let value = serde_json::to_value(&policy).expect("serialize");
    let obj = value
        .as_object()
        .expect("UsageBudgetPolicy is JSON object");
    assert_eq!(obj.len(), 2, "exactly 2 fields: enforcement + budgets");
    assert_eq!(
        obj.get("enforcement").and_then(|v| v.as_str()),
        Some("deny"),
        "enforcement field MUST serialize as the BudgetEnforcement snake_case token"
    );
    let budgets = obj
        .get("budgets")
        .and_then(|v| v.as_array())
        .expect("budgets array");
    assert_eq!(budgets.len(), 2);
}

#[test]
fn usage_budget_policy_with_warn_enforcement_json_shape() {
    let policy = UsageBudgetPolicy {
        enforcement: BudgetEnforcement::Warn,
        budgets: vec![],
    };
    let value = serde_json::to_value(&policy).expect("serialize");
    assert_eq!(
        value,
        serde_json::json!({"enforcement": "warn", "budgets": []}),
        "Warn + empty budgets produce minimal shape"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. UsageBudgetPolicy JSON + CBOR round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn usage_budget_policy_json_roundtrip_preserves_all_fields() {
    let original = sample_policy();
    let json = serde_json::to_string(&original).expect("serialize");
    let back: UsageBudgetPolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.budgets.len(), original.budgets.len());
    // BudgetEnforcement is Copy + Eq.
    assert_eq!(format!("{:?}", back.enforcement), format!("{:?}", original.enforcement));
    for (b, o) in back.budgets.iter().zip(&original.budgets) {
        assert_eq!(b.metric, o.metric);
        assert_eq!(b.limit, o.limit);
        assert_eq!(b.window_seconds, o.window_seconds);
    }
}

#[test]
fn usage_budget_policy_cbor_roundtrip_preserves_all_fields() {
    let original = sample_policy();
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&original, &mut buf).expect("encode");
    let back: UsageBudgetPolicy = ciborium::de::from_reader(buf.as_slice()).expect("decode");
    assert_eq!(back.budgets.len(), original.budgets.len());
    for (b, o) in back.budgets.iter().zip(&original.budgets) {
        assert_eq!(b.metric, o.metric);
        assert_eq!(b.limit, o.limit);
        assert_eq!(b.window_seconds, o.window_seconds);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. UsageBudgetLimit 3-field JSON shape
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn usage_budget_limit_json_shape_pinned() {
    let limit = sample_limit(UsageMetricKind::DurationMs, 60_000);
    let value = serde_json::to_value(&limit).expect("serialize");
    assert_eq!(
        value,
        serde_json::json!({
            "metric": "duration_ms",
            "limit": 60_000,
            "window_seconds": 3_600,
        }),
        "UsageBudgetLimit shape: 3 fields with metric as UsageMetricKind snake_case tag"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. UsageBudgetLimit round-trip at boundary values
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn usage_budget_limit_zero_round_trips() {
    let limit = UsageBudgetLimit {
        metric: UsageMetricKind::Bytes,
        limit: 0,
        window_seconds: 0,
    };
    let json = serde_json::to_string(&limit).expect("serialize");
    let back: UsageBudgetLimit = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.metric, UsageMetricKind::Bytes);
    assert_eq!(back.limit, 0);
    assert_eq!(back.window_seconds, 0);
}

#[test]
fn usage_budget_limit_u64_max_round_trips_through_json_and_cbor() {
    let limit = UsageBudgetLimit {
        metric: UsageMetricKind::Requests,
        limit: u64::MAX,
        window_seconds: u64::MAX,
    };
    let json = serde_json::to_string(&limit).expect("serialize");
    let from_json: UsageBudgetLimit =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(from_json.limit, u64::MAX);
    assert_eq!(from_json.window_seconds, u64::MAX);

    let mut buf = Vec::new();
    ciborium::ser::into_writer(&limit, &mut buf).expect("CBOR encode");
    let from_cbor: UsageBudgetLimit =
        ciborium::de::from_reader(buf.as_slice()).expect("CBOR decode");
    assert_eq!(from_cbor.limit, u64::MAX);
    assert_eq!(from_cbor.window_seconds, u64::MAX);
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. UsageBudgetUsage 7-field shape with nested BudgetStatus
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn usage_budget_usage_json_shape_pinned() {
    let usage = UsageBudgetUsage {
        metric: UsageMetricKind::Tokens,
        used: 750_000,
        limit: 1_000_000,
        remaining: 250_000,
        window_started_at: 1_700_000_000,
        window_resets_at: 1_700_003_600,
        status: BudgetStatus::Ok,
    };
    let value = serde_json::to_value(&usage).expect("serialize");
    assert_eq!(
        value,
        serde_json::json!({
            "metric": "tokens",
            "used": 750_000,
            "limit": 1_000_000,
            "remaining": 250_000,
            "window_started_at": 1_700_000_000_u64,
            "window_resets_at": 1_700_003_600_u64,
            "status": "ok",
        }),
        "UsageBudgetUsage 7-field shape with metric + status as nested enum tags"
    );
}

#[test]
fn usage_budget_usage_exceeded_status_round_trips() {
    let usage = UsageBudgetUsage {
        metric: UsageMetricKind::ApiCredits,
        used: 11_000,
        limit: 10_000,
        remaining: 0,
        window_started_at: 1_000,
        window_resets_at: 4_600,
        status: BudgetStatus::Exceeded,
    };
    let json = serde_json::to_string(&usage).expect("serialize");
    let back: UsageBudgetUsage = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.status, BudgetStatus::Exceeded);
    assert_eq!(back.remaining, 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. UsageBudgetSnapshot 4-field shape
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn usage_budget_snapshot_4_field_shape_with_nested_usage_list() {
    let snapshot = UsageBudgetSnapshot {
        zone_id: ZoneId::work(),
        enforcement: BudgetEnforcement::Warn,
        budgets: vec![
            UsageBudgetUsage {
                metric: UsageMetricKind::ApiCredits,
                used: 100,
                limit: 1_000,
                remaining: 900,
                window_started_at: 1_700_000_000,
                window_resets_at: 1_700_003_600,
                status: BudgetStatus::Ok,
            },
            UsageBudgetUsage {
                metric: UsageMetricKind::Bytes,
                used: 1_500_000,
                limit: 1_000_000,
                remaining: 0,
                window_started_at: 1_700_000_000,
                window_resets_at: 1_700_003_600,
                status: BudgetStatus::Exceeded,
            },
        ],
        updated_at: 1_700_000_500,
    };
    let value = serde_json::to_value(&snapshot).expect("serialize");
    let obj = value.as_object().expect("object");
    assert_eq!(obj.len(), 4, "exactly 4 fields");
    assert_eq!(obj.get("zone_id").and_then(|v| v.as_str()), Some("z:work"));
    assert_eq!(obj.get("enforcement").and_then(|v| v.as_str()), Some("warn"));
    assert_eq!(obj.get("updated_at").and_then(|v| v.as_u64()), Some(1_700_000_500));
    let budgets = obj
        .get("budgets")
        .and_then(|v| v.as_array())
        .expect("budgets array");
    assert_eq!(budgets.len(), 2);
}

#[test]
fn usage_budget_snapshot_preserves_budget_list_order() {
    let snapshot = UsageBudgetSnapshot {
        zone_id: ZoneId::work(),
        enforcement: BudgetEnforcement::Deny,
        budgets: vec![
            UsageBudgetUsage {
                metric: UsageMetricKind::Tokens,
                used: 1,
                limit: 100,
                remaining: 99,
                window_started_at: 1,
                window_resets_at: 2,
                status: BudgetStatus::Ok,
            },
            UsageBudgetUsage {
                metric: UsageMetricKind::Bytes,
                used: 1,
                limit: 100,
                remaining: 99,
                window_started_at: 1,
                window_resets_at: 2,
                status: BudgetStatus::Ok,
            },
            UsageBudgetUsage {
                metric: UsageMetricKind::Requests,
                used: 1,
                limit: 100,
                remaining: 99,
                window_started_at: 1,
                window_resets_at: 2,
                status: BudgetStatus::Ok,
            },
        ],
        updated_at: 1_700_000_000,
    };
    let json = serde_json::to_string(&snapshot).expect("serialize");
    let back: UsageBudgetSnapshot = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.budgets.len(), 3);
    assert_eq!(back.budgets[0].metric, UsageMetricKind::Tokens);
    assert_eq!(back.budgets[1].metric, UsageMetricKind::Bytes);
    assert_eq!(back.budgets[2].metric, UsageMetricKind::Requests);

    // Reversing the order produces a different serialization.
    let mut reversed = snapshot.clone();
    reversed.budgets.reverse();
    let reversed_json = serde_json::to_string(&reversed).expect("serialize reversed");
    assert_ne!(json, reversed_json);
}

#[test]
fn usage_budget_snapshot_cbor_round_trip_preserves_all_fields() {
    let snapshot = UsageBudgetSnapshot {
        zone_id: ZoneId::owner(),
        enforcement: BudgetEnforcement::Deny,
        budgets: vec![UsageBudgetUsage {
            metric: UsageMetricKind::ApiCredits,
            used: 50,
            limit: 100,
            remaining: 50,
            window_started_at: 0,
            window_resets_at: 60,
            status: BudgetStatus::Ok,
        }],
        updated_at: 1_700_000_000,
    };
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&snapshot, &mut buf).expect("encode");
    let back: UsageBudgetSnapshot = ciborium::de::from_reader(buf.as_slice()).expect("decode");
    assert_eq!(back.zone_id, snapshot.zone_id);
    assert_eq!(back.budgets.len(), 1);
    assert_eq!(back.budgets[0].metric, UsageMetricKind::ApiCredits);
    assert_eq!(back.updated_at, snapshot.updated_at);
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Empty budgets Vec preserved through round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn usage_budget_policy_empty_budgets_present_in_wire_form() {
    // Pin: budgets has NO `#[serde(skip_serializing_if = "Vec::is_empty")]`
    // — empty Vec MUST be present as `[]` in the wire form.
    let policy = UsageBudgetPolicy {
        enforcement: BudgetEnforcement::Warn,
        budgets: vec![],
    };
    let value = serde_json::to_value(&policy).expect("serialize");
    let obj = value.as_object().expect("object");
    assert!(
        obj.contains_key("budgets"),
        "budgets MUST be present as `[]` even when empty (no skip_serializing_if)"
    );
    assert_eq!(
        obj.get("budgets"),
        Some(&serde_json::json!([])),
        "empty budgets MUST serialize as JSON empty array"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Distinct metrics produce distinct serializations
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn distinct_metric_in_limit_produces_distinct_json() {
    let a = sample_limit(UsageMetricKind::Bytes, 1_000);
    let b = sample_limit(UsageMetricKind::Tokens, 1_000);
    assert_ne!(
        serde_json::to_string(&a).unwrap(),
        serde_json::to_string(&b).unwrap()
    );
}

#[test]
fn distinct_window_seconds_produces_distinct_json() {
    let a = UsageBudgetLimit {
        metric: UsageMetricKind::Bytes,
        limit: 1_000,
        window_seconds: 60,
    };
    let b = UsageBudgetLimit {
        metric: UsageMetricKind::Bytes,
        limit: 1_000,
        window_seconds: 3_600,
    };
    assert_ne!(
        serde_json::to_string(&a).unwrap(),
        serde_json::to_string(&b).unwrap()
    );
}

#[test]
fn distinct_enforcement_in_policy_produces_distinct_json() {
    let warn_policy = UsageBudgetPolicy {
        enforcement: BudgetEnforcement::Warn,
        budgets: vec![sample_limit(UsageMetricKind::Bytes, 100)],
    };
    let deny_policy = UsageBudgetPolicy {
        enforcement: BudgetEnforcement::Deny,
        budgets: vec![sample_limit(UsageMetricKind::Bytes, 100)],
    };
    assert_ne!(
        serde_json::to_string(&warn_policy).unwrap(),
        serde_json::to_string(&deny_policy).unwrap()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. Cross-format consistency
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn json_and_cbor_decode_to_same_usage_budget_policy() {
    let original = sample_policy();
    let json = serde_json::to_string(&original).expect("JSON serialize");
    let from_json: UsageBudgetPolicy =
        serde_json::from_str(&json).expect("JSON deserialize");

    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&original, &mut cbor).expect("CBOR encode");
    let from_cbor: UsageBudgetPolicy =
        ciborium::de::from_reader(cbor.as_slice()).expect("CBOR decode");

    assert_eq!(from_json.budgets.len(), from_cbor.budgets.len());
    for (j, c) in from_json.budgets.iter().zip(&from_cbor.budgets) {
        assert_eq!(j.metric, c.metric);
        assert_eq!(j.limit, c.limit);
        assert_eq!(j.window_seconds, c.window_seconds);
    }
}
