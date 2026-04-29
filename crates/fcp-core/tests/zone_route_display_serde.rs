//! Pin `TransportMode` + `ZoneTransportPolicy` serde shape + the
//! zone-to-zone transport truth table (flywheel_connectors-cfwab).
//!
//! Bead asks for `ZoneRoute Display formatting + serde tag`. No type
//! literally named `ZoneRoute` exists in fcp-core. The zone-to-zone
//! transport surface — i.e., the routing question "how does a
//! request reach this zone?" — is split across two types in
//! `policy.rs`:
//!
//!  - `TransportMode` (policy.rs:31) — the 3-variant snake_case
//!    classifier (Lan / Derp / Funnel) that policy decisions and
//!    audit logs dispatch on.
//!  - `ZoneTransportPolicy` (policy.rs:42) — the per-zone struct
//!    holding three booleans (allow_lan / allow_derp / allow_funnel)
//!    that gate which transports are permitted.
//!
//! Neither type implements `Display`, so the bead's "Display
//! formatting" ask has no direct analogue — pinning targets the
//! serde wire form (consumed by audit logs / dashboards) and the
//! `allows()` truth table that operators reason about.
//!
//! Targets:
//!
//!   1. **`TransportMode` per-variant JSON tag form** — snake_case
//!      `lan` / `derp` / `funnel`.
//!   2. **JSON + CBOR round-trip** preserves variant identity for
//!      every variant.
//!   3. **PascalCase + unknown variants rejected** — drift sentinel.
//!   4. **3-variant count + pairwise distinctness**.
//!   5. **`ZoneTransportPolicy::allows()` truth table** for every
//!      (policy × mode) combination — 8 policies × 3 modes = 24 cases.
//!   6. **Default policy values** pinned (allow_lan=true,
//!      allow_derp=false, allow_funnel=false) — the "LAN-only by
//!      default" posture is operator-visible.
//!   7. **`ZoneTransportPolicy` JSON shape** — 3-field object with
//!      explicit booleans.
//!   8. **`ZoneTransportPolicy` JSON + CBOR round-trip** preserves
//!      every flag.

use fcp_core::{TransportMode, ZoneTransportPolicy};

const TRANSPORT_MODE_CASES: &[(TransportMode, &str)] = &[
    (TransportMode::Lan, "lan"),
    (TransportMode::Derp, "derp"),
    (TransportMode::Funnel, "funnel"),
];

// ─────────────────────────────────────────────────────────────────────────────
// 1. TransportMode JSON tag form per variant
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn transport_mode_json_tag_pinned_per_variant() {
    for (variant, expected) in TRANSPORT_MODE_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        assert_eq!(
            json,
            format!("\"{expected}\""),
            "ZONE-ROUTE REGRESSION: TransportMode JSON tag drift on {variant:?} — \
             policy audit logs filter on this exact token"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. JSON + CBOR round-trip per variant
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn transport_mode_json_roundtrip_per_variant() {
    for (variant, _) in TRANSPORT_MODE_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        let back: TransportMode = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, back, "JSON round-trip lost {variant:?}");
    }
}

#[test]
fn transport_mode_cbor_roundtrip_per_variant() {
    for (variant, _) in TRANSPORT_MODE_CASES {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("encode");
        let back: TransportMode = ciborium::de::from_reader(buf.as_slice()).expect("decode");
        assert_eq!(*variant, back, "CBOR round-trip lost {variant:?}");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. PascalCase + unknown rejected
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn transport_mode_rejects_pascal_case_and_unknown() {
    for bad in [r#""Lan""#, r#""DERP""#, r#""Funnel""#, r#""ipv6""#, r#""""#] {
        let parsed = serde_json::from_str::<TransportMode>(bad);
        assert!(
            parsed.is_err(),
            "{bad} MUST be rejected — only documented snake_case is canonical"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Variant count + pairwise distinctness
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn transport_mode_has_three_documented_variants() {
    assert_eq!(
        TRANSPORT_MODE_CASES.len(),
        3,
        "TransportMode has 3 documented variants (Lan/Derp/Funnel) — count drifted"
    );
}

#[test]
fn transport_mode_variants_pairwise_distinct() {
    let mut seen_tokens = std::collections::HashSet::new();
    for (_, token) in TRANSPORT_MODE_CASES {
        assert!(seen_tokens.insert(*token), "duplicate token {token}");
    }
    assert_eq!(seen_tokens.len(), 3);

    for i in 0..TRANSPORT_MODE_CASES.len() {
        for j in (i + 1)..TRANSPORT_MODE_CASES.len() {
            assert_ne!(
                TRANSPORT_MODE_CASES[i].0, TRANSPORT_MODE_CASES[j].0,
                "{:?} and {:?} MUST be distinct",
                TRANSPORT_MODE_CASES[i].0, TRANSPORT_MODE_CASES[j].0
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. ZoneTransportPolicy::allows() truth table
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn zone_transport_policy_allows_truth_table_for_every_policy_mode_pair() {
    // 8 distinct policies (each of the 3 booleans toggled
    // independently) × 3 transport modes = 24 (policy, mode) cases.
    // Pin the truth table so any future change to the dispatch
    // logic (e.g., adding a denylist override) surfaces here.
    let policies = [
        // (lan, derp, funnel)
        (false, false, false),
        (false, false, true),
        (false, true, false),
        (false, true, true),
        (true, false, false),
        (true, false, true),
        (true, true, false),
        (true, true, true),
    ];
    let modes = [
        TransportMode::Lan,
        TransportMode::Derp,
        TransportMode::Funnel,
    ];
    for (allow_lan, allow_derp, allow_funnel) in policies {
        let policy = ZoneTransportPolicy {
            allow_lan,
            allow_derp,
            allow_funnel,
        };
        for mode in modes {
            let expected = match mode {
                TransportMode::Lan => allow_lan,
                TransportMode::Derp => allow_derp,
                TransportMode::Funnel => allow_funnel,
            };
            assert_eq!(
                policy.allows(mode),
                expected,
                "ZoneTransportPolicy::allows drift: policy=(lan={allow_lan},derp={allow_derp},\
                 funnel={allow_funnel}) mode={mode:?} expected={expected}"
            );
        }
    }
}

#[test]
fn zone_transport_policy_allows_only_explicitly_enabled_mode_in_isolation() {
    // Sanity check: exactly-one-enabled policies allow exactly that mode.
    let lan_only = ZoneTransportPolicy {
        allow_lan: true,
        allow_derp: false,
        allow_funnel: false,
    };
    assert!(lan_only.allows(TransportMode::Lan));
    assert!(!lan_only.allows(TransportMode::Derp));
    assert!(!lan_only.allows(TransportMode::Funnel));

    let derp_only = ZoneTransportPolicy {
        allow_lan: false,
        allow_derp: true,
        allow_funnel: false,
    };
    assert!(!derp_only.allows(TransportMode::Lan));
    assert!(derp_only.allows(TransportMode::Derp));
    assert!(!derp_only.allows(TransportMode::Funnel));

    let funnel_only = ZoneTransportPolicy {
        allow_lan: false,
        allow_derp: false,
        allow_funnel: true,
    };
    assert!(!funnel_only.allows(TransportMode::Lan));
    assert!(!funnel_only.allows(TransportMode::Derp));
    assert!(funnel_only.allows(TransportMode::Funnel));
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Default policy values
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn zone_transport_policy_default_is_lan_only() {
    // The documented default posture: LAN allowed, DERP and Funnel
    // denied. Operators rely on this default — pin it loudly.
    let default_policy = ZoneTransportPolicy::default();
    assert!(
        default_policy.allow_lan,
        "DEFAULT-POSTURE REGRESSION: default ZoneTransportPolicy MUST allow LAN"
    );
    assert!(
        !default_policy.allow_derp,
        "DEFAULT-POSTURE REGRESSION: default ZoneTransportPolicy MUST NOT allow DERP"
    );
    assert!(
        !default_policy.allow_funnel,
        "DEFAULT-POSTURE REGRESSION: default ZoneTransportPolicy MUST NOT allow Funnel"
    );

    // And the allows() method agrees with the field values.
    assert!(default_policy.allows(TransportMode::Lan));
    assert!(!default_policy.allows(TransportMode::Derp));
    assert!(!default_policy.allows(TransportMode::Funnel));
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. ZoneTransportPolicy JSON shape
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn zone_transport_policy_json_shape_pinned() {
    // 3-field object with explicit boolean fields. Pin the field
    // names since downstream tooling reads them positionally.
    let policy = ZoneTransportPolicy {
        allow_lan: true,
        allow_derp: false,
        allow_funnel: true,
    };
    let value = serde_json::to_value(&policy).expect("serialize");
    assert_eq!(
        value,
        serde_json::json!({
            "allow_lan": true,
            "allow_derp": false,
            "allow_funnel": true,
        }),
        "ZoneTransportPolicy JSON shape drift — field names are part of the wire contract"
    );
}

#[test]
fn zone_transport_policy_json_field_names_use_snake_case() {
    // Confirm none of the field names accidentally drift to
    // PascalCase or camelCase.
    let policy = ZoneTransportPolicy::default();
    let json = serde_json::to_string(&policy).expect("serialize");
    for field in ["allow_lan", "allow_derp", "allow_funnel"] {
        assert!(
            json.contains(field),
            "JSON MUST contain snake_case field {field:?}; got {json}"
        );
    }
    for bad in ["allowLan", "AllowDerp", "allow-funnel"] {
        assert!(
            !json.contains(bad),
            "JSON MUST NOT contain non-snake_case form {bad:?}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. ZoneTransportPolicy round-trip preserves every flag
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn zone_transport_policy_json_and_cbor_roundtrip_for_every_combination() {
    for allow_lan in [false, true] {
        for allow_derp in [false, true] {
            for allow_funnel in [false, true] {
                let original = ZoneTransportPolicy {
                    allow_lan,
                    allow_derp,
                    allow_funnel,
                };

                // JSON
                let json = serde_json::to_string(&original).expect("JSON serialize");
                let from_json: ZoneTransportPolicy =
                    serde_json::from_str(&json).expect("JSON deserialize");
                assert_eq!(from_json.allow_lan, allow_lan);
                assert_eq!(from_json.allow_derp, allow_derp);
                assert_eq!(from_json.allow_funnel, allow_funnel);

                // CBOR
                let mut buf = Vec::new();
                ciborium::ser::into_writer(&original, &mut buf).expect("CBOR encode");
                let from_cbor: ZoneTransportPolicy =
                    ciborium::de::from_reader(buf.as_slice()).expect("CBOR decode");
                assert_eq!(from_cbor.allow_lan, allow_lan);
                assert_eq!(from_cbor.allow_derp, allow_derp);
                assert_eq!(from_cbor.allow_funnel, allow_funnel);

                // And allows() agrees post-roundtrip.
                for mode in [
                    TransportMode::Lan,
                    TransportMode::Derp,
                    TransportMode::Funnel,
                ] {
                    assert_eq!(
                        from_json.allows(mode),
                        original.allows(mode),
                        "JSON round-trip lost allows({mode:?})"
                    );
                    assert_eq!(
                        from_cbor.allows(mode),
                        original.allows(mode),
                        "CBOR round-trip lost allows({mode:?})"
                    );
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. Cross-format consistency on ZoneTransportPolicy
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn zone_transport_policy_json_and_cbor_decode_to_same_policy() {
    let original = ZoneTransportPolicy {
        allow_lan: true,
        allow_derp: true,
        allow_funnel: false,
    };

    let json = serde_json::to_string(&original).expect("JSON serialize");
    let from_json: ZoneTransportPolicy = serde_json::from_str(&json).expect("JSON deserialize");

    let mut buf = Vec::new();
    ciborium::ser::into_writer(&original, &mut buf).expect("CBOR encode");
    let from_cbor: ZoneTransportPolicy =
        ciborium::de::from_reader(buf.as_slice()).expect("CBOR decode");

    assert_eq!(from_json.allow_lan, from_cbor.allow_lan);
    assert_eq!(from_json.allow_derp, from_cbor.allow_derp);
    assert_eq!(from_json.allow_funnel, from_cbor.allow_funnel);
}
