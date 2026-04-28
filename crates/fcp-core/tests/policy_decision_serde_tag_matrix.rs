//! Pin the policy-decision serde tag matrix across JSON and CBOR
//! (flywheel_connectors-qyq9l).
//!
//! Bead asks for "PolicyDecision serde tag matrix (allow/deny/skip)".
//! `PolicyDecision` itself is NOT a serde-derived enum — it's a
//! struct (policy.rs:2173) without Serialize/Deserialize. The two
//! decision-shaped enums in fcp-core that DO derive serde are:
//!
//! 1. `enforcement::CheckOutcome` (the Allow/Deny/Skip enum the bead
//!    describes) — internally-tagged by `outcome` field, `rename_all
//!    = "snake_case"` (enforcement.rs:144). Three variants:
//!    - `Allow`              → `{"outcome":"allow"}`
//!    - `Deny{reason_code, explanation}`
//!                           → `{"outcome":"deny","reason_code":...,"explanation":...}`
//!    - `Skip{reason}`       → `{"outcome":"skip","reason":...}`
//!
//! 2. `audit::Decision` (allow/deny only — no Skip) —
//!    `rename_all = "lowercase"` (audit.rs:234). Two variants:
//!    - `Allow` → `"allow"`
//!    - `Deny`  → `"deny"`
//!
//! Tests pin both: the three-variant CheckOutcome (which matches the
//! bead's allow/deny/skip framing) AND the two-variant Decision (since
//! it's literally called "Decision"). Both go through JSON + CBOR
//! round-trip.

use ciborium::value::Value as CborValue;
use fcp_core::{CheckOutcome, Decision};

// ─────────────────────────────────────────────────────────────────────────────
// CheckOutcome: tag = "outcome", snake_case, three variants
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn check_outcome_allow_json_form_pinned() {
    let v = CheckOutcome::Allow;
    let json = serde_json::to_string(&v).expect("serialize");
    assert_eq!(
        json, r#"{"outcome":"allow"}"#,
        "FORMAT REGRESSION: CheckOutcome::Allow JSON drift"
    );
    let back: CheckOutcome = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, v);
    assert!(back.is_allow());
    assert!(!back.is_deny());
    assert!(!back.is_skip());
}

#[test]
fn check_outcome_deny_json_form_pinned() {
    let v = CheckOutcome::Deny {
        reason_code: "zone_violation".to_string(),
        explanation: "principal not in zone".to_string(),
    };
    let json = serde_json::to_string(&v).expect("serialize");
    // Internally-tagged form puts `outcome` first, then the variant
    // fields. Pin the field-presence + values; field-order is a
    // serde implementation detail.
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
    assert_eq!(parsed["outcome"], "deny", "tag MUST be `deny`");
    assert_eq!(parsed["reason_code"], "zone_violation");
    assert_eq!(parsed["explanation"], "principal not in zone");
    // And the full value must round-trip.
    let back: CheckOutcome = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, v);
    assert!(back.is_deny());
    assert!(!back.is_allow());
    assert!(!back.is_skip());
}

#[test]
fn check_outcome_skip_json_form_pinned() {
    let v = CheckOutcome::Skip {
        reason: "not applicable".to_string(),
    };
    let json = serde_json::to_string(&v).expect("serialize");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
    assert_eq!(parsed["outcome"], "skip", "tag MUST be `skip`");
    assert_eq!(parsed["reason"], "not applicable");
    let back: CheckOutcome = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, v);
    assert!(back.is_skip());
    assert!(!back.is_allow());
    assert!(!back.is_deny());
}

#[test]
fn check_outcome_json_roundtrip_for_all_three_variants() {
    let cases = [
        CheckOutcome::Allow,
        CheckOutcome::Deny {
            reason_code: "FCP-3003".to_string(),
            explanation: "capability id mismatch".to_string(),
        },
        CheckOutcome::Skip {
            reason: "not applicable for read-only request".to_string(),
        },
    ];
    for original in cases {
        let json = serde_json::to_string(&original).expect("serialize");
        let back: CheckOutcome = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, original, "JSON round-trip lost variant: {original:?}");
    }
}

#[test]
fn check_outcome_cbor_roundtrip_for_all_three_variants() {
    let cases = [
        CheckOutcome::Allow,
        CheckOutcome::Deny {
            reason_code: "FCP-3001".to_string(),
            explanation: "policy ceiling exceeded".to_string(),
        },
        CheckOutcome::Skip {
            reason: "no token bound to instance".to_string(),
        },
    ];
    for original in cases {
        let mut buf = Vec::new();
        ciborium::into_writer(&original, &mut buf).expect("serialize cbor");
        let back: CheckOutcome = ciborium::from_reader(&buf[..]).expect("deserialize cbor");
        assert_eq!(back, original, "CBOR round-trip lost variant: {original:?}");
    }
}

#[test]
fn check_outcome_cbor_form_carries_tag_field() {
    // CBOR follows the same internally-tagged structure as JSON. Pin
    // that the encoded CBOR is a Map whose `outcome` entry holds the
    // expected snake_case label.
    let cases: &[(CheckOutcome, &str)] = &[
        (CheckOutcome::Allow, "allow"),
        (
            CheckOutcome::Deny {
                reason_code: "x".to_string(),
                explanation: "y".to_string(),
            },
            "deny",
        ),
        (
            CheckOutcome::Skip {
                reason: "z".to_string(),
            },
            "skip",
        ),
    ];
    for (variant, expected_tag) in cases {
        let mut buf = Vec::new();
        ciborium::into_writer(variant, &mut buf).expect("serialize cbor");
        let value: CborValue = ciborium::from_reader(&buf[..]).expect("decode as Value");
        let CborValue::Map(entries) = value else {
            panic!("CheckOutcome MUST encode as a CBOR Map; got {value:?}");
        };
        let outcome_value = entries
            .iter()
            .find_map(|(k, v)| match k {
                CborValue::Text(s) if s == "outcome" => Some(v),
                _ => None,
            })
            .unwrap_or_else(|| panic!("CBOR Map MUST contain `outcome` key for {variant:?}"));
        assert_eq!(
            outcome_value,
            &CborValue::Text((*expected_tag).to_string()),
            "tag value MUST be {expected_tag} for {variant:?}"
        );
    }
}

#[test]
fn check_outcome_predicate_truth_table_per_variant() {
    let allow = CheckOutcome::Allow;
    assert!(allow.is_allow() && !allow.is_deny() && !allow.is_skip());

    let deny = CheckOutcome::Deny {
        reason_code: "x".into(),
        explanation: "y".into(),
    };
    assert!(!deny.is_allow() && deny.is_deny() && !deny.is_skip());

    let skip = CheckOutcome::Skip { reason: "z".into() };
    assert!(!skip.is_allow() && !skip.is_deny() && skip.is_skip());
}

#[test]
fn check_outcome_pascalcase_tag_rejected() {
    // The serde tag is snake_case; the PascalCase variant name must
    // NOT be accepted.
    let bad = serde_json::from_str::<CheckOutcome>(r#"{"outcome":"Allow"}"#);
    assert!(bad.is_err(), "PascalCase outcome value MUST be rejected");

    // Wrong tag key.
    let bad_key =
        serde_json::from_str::<CheckOutcome>(r#"{"type":"allow"}"#);
    assert!(bad_key.is_err(), "tag key MUST be `outcome`, not `type`");

    // Unknown variant.
    let bad_unknown = serde_json::from_str::<CheckOutcome>(r#"{"outcome":"unknown"}"#);
    assert!(bad_unknown.is_err(), "unknown variant MUST be rejected");
}

// ─────────────────────────────────────────────────────────────────────────────
// audit::Decision: rename_all = "lowercase", two variants
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn decision_json_form_pinned() {
    let allow = Decision::Allow;
    let deny = Decision::Deny;
    assert_eq!(serde_json::to_string(&allow).unwrap(), "\"allow\"");
    assert_eq!(serde_json::to_string(&deny).unwrap(), "\"deny\"");
}

#[test]
fn decision_json_roundtrip() {
    for original in [Decision::Allow, Decision::Deny] {
        let json = serde_json::to_string(&original).expect("serialize");
        let back: Decision = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, original);
    }
}

#[test]
fn decision_cbor_roundtrip() {
    for original in [Decision::Allow, Decision::Deny] {
        let mut buf = Vec::new();
        ciborium::into_writer(&original, &mut buf).expect("serialize cbor");
        let back: Decision = ciborium::from_reader(&buf[..]).expect("deserialize cbor");
        assert_eq!(back, original);
    }
}

#[test]
fn decision_cbor_form_is_lowercase_text() {
    let allow_cbor = {
        let mut buf = Vec::new();
        ciborium::into_writer(&Decision::Allow, &mut buf).unwrap();
        buf
    };
    let allow_value: CborValue = ciborium::from_reader(&allow_cbor[..]).unwrap();
    assert_eq!(allow_value, CborValue::Text("allow".to_string()));

    let deny_cbor = {
        let mut buf = Vec::new();
        ciborium::into_writer(&Decision::Deny, &mut buf).unwrap();
        buf
    };
    let deny_value: CborValue = ciborium::from_reader(&deny_cbor[..]).unwrap();
    assert_eq!(deny_value, CborValue::Text("deny".to_string()));
}

#[test]
fn decision_pascalcase_tag_rejected() {
    let bad_allow = serde_json::from_str::<Decision>("\"Allow\"");
    assert!(bad_allow.is_err(), "PascalCase Decision MUST be rejected");
    let bad_deny = serde_json::from_str::<Decision>("\"Deny\"");
    assert!(bad_deny.is_err());
    let bad_skip = serde_json::from_str::<Decision>("\"skip\"");
    assert!(bad_skip.is_err(), "Decision has no `skip` variant — MUST reject");
}

#[test]
fn decision_distinct_from_check_outcome_on_wire() {
    // Important: Decision and CheckOutcome use DIFFERENT JSON shapes.
    // Decision is a bare string (`"allow"`), CheckOutcome is a tagged
    // object (`{"outcome":"allow"}`). Pin that they don't accidentally
    // accept each other's serialized form.
    let decision_json = serde_json::to_string(&Decision::Allow).unwrap();
    assert!(serde_json::from_str::<CheckOutcome>(&decision_json).is_err(),
        "CheckOutcome MUST NOT accept Decision's bare-string JSON");

    let outcome_json = serde_json::to_string(&CheckOutcome::Allow).unwrap();
    assert!(serde_json::from_str::<Decision>(&outcome_json).is_err(),
        "Decision MUST NOT accept CheckOutcome's tagged-object JSON");
}

// ─────────────────────────────────────────────────────────────────────────────
// Cross-format consistency (JSON ↔ CBOR Eq)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn check_outcome_json_and_cbor_decode_to_same_value() {
    let original = CheckOutcome::Deny {
        reason_code: "FCP-3003".to_string(),
        explanation: "capability mismatch".to_string(),
    };

    let json = serde_json::to_string(&original).expect("json");
    let from_json: CheckOutcome = serde_json::from_str(&json).expect("json deser");

    let mut cbor = Vec::new();
    ciborium::into_writer(&original, &mut cbor).expect("cbor");
    let from_cbor: CheckOutcome =
        ciborium::from_reader(&cbor[..]).expect("cbor deser");

    assert_eq!(from_json, from_cbor);
    assert_eq!(from_json, original);
}

#[test]
fn decision_json_and_cbor_decode_to_same_value() {
    for original in [Decision::Allow, Decision::Deny] {
        let json = serde_json::to_string(&original).unwrap();
        let from_json: Decision = serde_json::from_str(&json).unwrap();

        let mut cbor = Vec::new();
        ciborium::into_writer(&original, &mut cbor).unwrap();
        let from_cbor: Decision = ciborium::from_reader(&cbor[..]).unwrap();

        assert_eq!(from_json, from_cbor);
        assert_eq!(from_json, original);
    }
}
