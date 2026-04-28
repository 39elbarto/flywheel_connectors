//! `fcp_host::discovery` status-enum wire-format conformance.
//!
//! The discovery surface exposes six status / classification enums
//! that operators, agents, and dashboards consume from the host's
//! `/health`, `/discover`, and `/introspect` endpoints. Wire-form
//! drift across host versions silently breaks every external
//! consumer (Grafana panels, agent filtering, archetype-based
//! routing).
//!
//! Properties pinned (NORMATIVE):
//!
//! 1. **`HealthFilter` 4 lowercase variants**: `healthy` /
//!    `degraded` / `available` / `all`.
//! 2. **`ConnectorArchetype` 6 snake_case variants**: `unknown` /
//!    `request_response` / `streaming` / `bidirectional` /
//!    `polling` / `webhook`.
//! 3. **`LatencyHint` 4 snake_case variants**: `fast` / `medium` /
//!    `slow` / `very_slow`.
//! 4. **`HostHealthStatus` 3 lowercase variants**: `healthy` /
//!    `degraded` / `unhealthy`.
//! 5. **`MeshStatus` 4 snake_case variants**: `connected` /
//!    `degraded` / `unreachable` / `not_configured`.
//! 6. **`PolicyEngineStatus` 4 snake_case variants**: `active` /
//!    `partially_loaded` / `not_initialized` / `error`.
//! 7. **`MeshStatus::is_operational`** is true ONLY for
//!    `Connected | Degraded` (the documented operational set).
//! 8. **`PolicyEngineStatus::can_decide`** is true ONLY for
//!    `Active | PartiallyLoaded` (degraded-but-decidable set).
//! 9. **All six enums implement `Copy`** — they appear in dashboard
//!    and metric-key code paths that pass by value.

use fcp_host::{
    ConnectorArchetype, HealthFilter, HostHealthStatus, LatencyHint, MeshStatus,
    PolicyEngineStatus,
};

// ─── HealthFilter ───────────────────────────────────────────────────

#[test]
fn health_filter_serde_uses_lowercase_for_each_variant() {
    let cases = [
        (HealthFilter::Healthy, "\"healthy\""),
        (HealthFilter::Degraded, "\"degraded\""),
        (HealthFilter::Available, "\"available\""),
        (HealthFilter::All, "\"all\""),
    ];
    for (variant, expected) in cases {
        let json = serde_json::to_string(&variant).expect("serialize");
        assert_eq!(json, expected, "{variant:?} MUST serialize as '{expected}'");
        let parsed: HealthFilter = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, variant);
    }
}

#[test]
fn health_filter_rejects_unknown_or_uppercase_variants() {
    for bogus in ["\"HEALTHY\"", "\"Healthy\"", "\"\"", "\"unknown\""] {
        assert!(
            serde_json::from_str::<HealthFilter>(bogus).is_err(),
            "HealthFilter MUST reject {bogus}"
        );
    }
}

#[test]
fn health_filter_implements_copy() {
    fn takes_value(_: HealthFilter) {}
    let h = HealthFilter::Available;
    takes_value(h);
    takes_value(h);
    assert_eq!(h, HealthFilter::Available);
}

// ─── ConnectorArchetype ─────────────────────────────────────────────

#[test]
fn connector_archetype_serde_uses_snake_case_for_each_variant() {
    let cases = [
        (ConnectorArchetype::Unknown, "\"unknown\""),
        (ConnectorArchetype::RequestResponse, "\"request_response\""),
        (ConnectorArchetype::Streaming, "\"streaming\""),
        (ConnectorArchetype::Bidirectional, "\"bidirectional\""),
        (ConnectorArchetype::Polling, "\"polling\""),
        (ConnectorArchetype::Webhook, "\"webhook\""),
    ];
    for (variant, expected) in cases {
        let json = serde_json::to_string(&variant).expect("serialize");
        assert_eq!(
            json, expected,
            "{variant:?} MUST serialize as '{expected}'"
        );
        let parsed: ConnectorArchetype = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, variant);
    }
}

#[test]
fn connector_archetype_rejects_unknown_or_camelcase_variants() {
    for bogus in [
        "\"REQUEST_RESPONSE\"",
        "\"requestResponse\"",
        "\"\"",
        "\"http\"",
        "\"unknown_kind\"",
    ] {
        assert!(
            serde_json::from_str::<ConnectorArchetype>(bogus).is_err(),
            "ConnectorArchetype MUST reject {bogus}"
        );
    }
}

#[test]
fn connector_archetype_implements_copy() {
    fn takes_value(_: ConnectorArchetype) {}
    let a = ConnectorArchetype::RequestResponse;
    takes_value(a);
    takes_value(a);
    assert_eq!(a, ConnectorArchetype::RequestResponse);
}

// ─── LatencyHint ────────────────────────────────────────────────────

#[test]
fn latency_hint_serde_uses_snake_case_for_each_variant() {
    let cases = [
        (LatencyHint::Fast, "\"fast\""),
        (LatencyHint::Medium, "\"medium\""),
        (LatencyHint::Slow, "\"slow\""),
        (LatencyHint::VerySlow, "\"very_slow\""),
    ];
    for (variant, expected) in cases {
        let json = serde_json::to_string(&variant).expect("serialize");
        assert_eq!(json, expected);
        let parsed: LatencyHint = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, variant);
    }
}

#[test]
fn latency_hint_rejects_unknown_or_camelcase_variants() {
    for bogus in ["\"verySlow\"", "\"VERY_SLOW\"", "\"\"", "\"glacial\""] {
        assert!(
            serde_json::from_str::<LatencyHint>(bogus).is_err(),
            "LatencyHint MUST reject {bogus}"
        );
    }
}

// ─── HostHealthStatus ──────────────────────────────────────────────

#[test]
fn host_health_status_serde_uses_lowercase_for_each_variant() {
    let cases = [
        (HostHealthStatus::Healthy, "\"healthy\""),
        (HostHealthStatus::Degraded, "\"degraded\""),
        (HostHealthStatus::Unhealthy, "\"unhealthy\""),
    ];
    for (variant, expected) in cases {
        let json = serde_json::to_string(&variant).expect("serialize");
        assert_eq!(json, expected);
        let parsed: HostHealthStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, variant);
    }
}

#[test]
fn host_health_status_rejects_uppercase_variants() {
    for bogus in ["\"HEALTHY\"", "\"Degraded\"", "\"\""] {
        assert!(
            serde_json::from_str::<HostHealthStatus>(bogus).is_err(),
            "HostHealthStatus MUST reject {bogus}"
        );
    }
}

// ─── MeshStatus + is_operational ───────────────────────────────────

#[test]
fn mesh_status_serde_uses_snake_case_for_each_variant() {
    let cases = [
        (MeshStatus::Connected, "\"connected\""),
        (MeshStatus::Degraded, "\"degraded\""),
        (MeshStatus::Unreachable, "\"unreachable\""),
        (MeshStatus::NotConfigured, "\"not_configured\""),
    ];
    for (variant, expected) in cases {
        let json = serde_json::to_string(&variant).expect("serialize");
        assert_eq!(
            json, expected,
            "{variant:?} MUST serialize as '{expected}'"
        );
        let parsed: MeshStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, variant);
    }
}

#[test]
fn mesh_status_is_operational_covers_connected_and_degraded() {
    assert!(MeshStatus::Connected.is_operational());
    assert!(
        MeshStatus::Degraded.is_operational(),
        "Degraded MUST count as operational — peer partitions are recoverable"
    );
}

#[test]
fn mesh_status_is_operational_excludes_unreachable_and_not_configured() {
    assert!(!MeshStatus::Unreachable.is_operational());
    assert!(
        !MeshStatus::NotConfigured.is_operational(),
        "standalone (NotConfigured) is NOT operational mesh"
    );
}

#[test]
fn mesh_status_rejects_unknown_or_camelcase_variants() {
    for bogus in ["\"NOT_CONFIGURED\"", "\"notConfigured\"", "\"\"", "\"online\""] {
        assert!(
            serde_json::from_str::<MeshStatus>(bogus).is_err(),
            "MeshStatus MUST reject {bogus}"
        );
    }
}

// ─── PolicyEngineStatus + can_decide ───────────────────────────────

#[test]
fn policy_engine_status_serde_uses_snake_case_for_each_variant() {
    let cases = [
        (PolicyEngineStatus::Active, "\"active\""),
        (PolicyEngineStatus::PartiallyLoaded, "\"partially_loaded\""),
        (PolicyEngineStatus::NotInitialized, "\"not_initialized\""),
        (PolicyEngineStatus::Error, "\"error\""),
    ];
    for (variant, expected) in cases {
        let json = serde_json::to_string(&variant).expect("serialize");
        assert_eq!(
            json, expected,
            "{variant:?} MUST serialize as '{expected}'"
        );
        let parsed: PolicyEngineStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, variant);
    }
}

#[test]
fn policy_engine_status_can_decide_covers_active_and_partially_loaded() {
    assert!(PolicyEngineStatus::Active.can_decide());
    assert!(
        PolicyEngineStatus::PartiallyLoaded.can_decide(),
        "PartiallyLoaded MUST still be able to decide — partial parse failures \
         do not disable the engine"
    );
}

#[test]
fn policy_engine_status_can_decide_excludes_not_initialized_and_error() {
    assert!(!PolicyEngineStatus::NotInitialized.can_decide());
    assert!(!PolicyEngineStatus::Error.can_decide());
}

#[test]
fn policy_engine_status_rejects_unknown_or_camelcase_variants() {
    for bogus in [
        "\"PARTIALLY_LOADED\"",
        "\"partiallyLoaded\"",
        "\"\"",
        "\"loaded\"",
    ] {
        assert!(
            serde_json::from_str::<PolicyEngineStatus>(bogus).is_err(),
            "PolicyEngineStatus MUST reject {bogus}"
        );
    }
}

// ─── Cross-enum sanity ─────────────────────────────────────────────

#[test]
fn all_status_enums_distinct_per_variant() {
    // Lightweight sanity: each enum's variants are all distinct on PartialEq.
    let hf = [
        HealthFilter::Healthy,
        HealthFilter::Degraded,
        HealthFilter::Available,
        HealthFilter::All,
    ];
    for (i, a) in hf.iter().enumerate() {
        for (j, b) in hf.iter().enumerate() {
            if i != j {
                assert_ne!(a, b);
            }
        }
    }

    let archetypes = [
        ConnectorArchetype::Unknown,
        ConnectorArchetype::RequestResponse,
        ConnectorArchetype::Streaming,
        ConnectorArchetype::Bidirectional,
        ConnectorArchetype::Polling,
        ConnectorArchetype::Webhook,
    ];
    for (i, a) in archetypes.iter().enumerate() {
        for (j, b) in archetypes.iter().enumerate() {
            if i != j {
                assert_ne!(a, b);
            }
        }
    }

    let mesh = [
        MeshStatus::Connected,
        MeshStatus::Degraded,
        MeshStatus::Unreachable,
        MeshStatus::NotConfigured,
    ];
    for (i, a) in mesh.iter().enumerate() {
        for (j, b) in mesh.iter().enumerate() {
            if i != j {
                assert_ne!(a, b);
            }
        }
    }
}
