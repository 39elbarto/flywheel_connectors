//! `fcp_host::admin_state` operator-facing enums wire-format
//! conformance.
//!
//! The host's admin RPC surface exposes 5 status / classification
//! enums that operator dashboards, alerting rules, and audit
//! pipelines consume from `/admin/*` endpoints. Wire-form drift
//! across host versions silently breaks every external consumer.
//!
//! Properties pinned (NORMATIVE):
//!
//! 1. **`ConnectorInventoryMutationKind`** — 2 snake_case variants
//!    (`install` / `update`).
//! 2. **`LifecycleAction`** — 6 snake_case variants (`enable` /
//!    `disable` / `restart` / `reload` / `uninstall` / `promote`).
//!    These ARE the operator verbs; renaming any one breaks
//!    automation scripts.
//! 3. **`LogSeverity`** — 4 snake_case variants
//!    (`debug` / `info` / `warn` / `error`). Standard syslog-style
//!    levels; operator alerting filters depend on these strings.
//! 4. **`HostEventKind`** — 7 snake_case variants
//!    (`lifecycle_transition` / `health_check` / `config_revision` /
//!    `rollout_decision` / `supply_chain_verification` /
//!    `drift_detected` / `connector_state_change`).
//! 5. **`SimulatePhase`** — 4 snake_case variants
//!    (`preflight_only` / `connector_reached` /
//!    `connector_unsupported` / `timed_out`). Drives operator
//!    visibility into how far simulation got.
//! 6. Each enum rejects mixed-case / camelCase / unknown / empty
//!    JSON values.
//! 7. Each enum implements `Copy` (tracker code paths pass by value).

use fcp_host::{
    ConnectorInventoryMutationKind, HostEventKind, LifecycleAction, LogSeverity, SimulatePhase,
};

// ─── ConnectorInventoryMutationKind ───────────────────────────────

#[test]
fn connector_inventory_mutation_kind_serde_uses_snake_case_for_each_variant() {
    let cases = [
        (ConnectorInventoryMutationKind::Install, "\"install\""),
        (ConnectorInventoryMutationKind::Update, "\"update\""),
    ];
    for (variant, expected) in cases {
        let json = serde_json::to_string(&variant).expect("serialize");
        assert_eq!(json, expected, "{variant:?} MUST serialize as '{expected}'");
        let parsed: ConnectorInventoryMutationKind =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, variant);
    }
}

#[test]
fn connector_inventory_mutation_kind_rejects_unknown_or_uppercase() {
    for bogus in ["\"INSTALL\"", "\"Install\"", "\"\"", "\"replace\""] {
        assert!(
            serde_json::from_str::<ConnectorInventoryMutationKind>(bogus).is_err(),
            "MUST reject {bogus}"
        );
    }
}

#[test]
fn connector_inventory_mutation_kind_implements_copy() {
    fn takes_value(_: ConnectorInventoryMutationKind) {}
    let k = ConnectorInventoryMutationKind::Install;
    takes_value(k);
    takes_value(k);
}

#[test]
fn connector_inventory_mutation_kind_two_variants_are_distinct() {
    assert_ne!(
        ConnectorInventoryMutationKind::Install,
        ConnectorInventoryMutationKind::Update
    );
}

// ─── LifecycleAction ───────────────────────────────────────────────

#[test]
fn lifecycle_action_serde_uses_snake_case_for_each_variant() {
    let cases = [
        (LifecycleAction::Enable, "\"enable\""),
        (LifecycleAction::Disable, "\"disable\""),
        (LifecycleAction::Restart, "\"restart\""),
        (LifecycleAction::Reload, "\"reload\""),
        (LifecycleAction::Uninstall, "\"uninstall\""),
        (LifecycleAction::Promote, "\"promote\""),
    ];
    for (variant, expected) in cases {
        let json = serde_json::to_string(&variant).expect("serialize");
        assert_eq!(json, expected, "{variant:?} MUST serialize as '{expected}'");
        let parsed: LifecycleAction = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, variant);
    }
}

#[test]
fn lifecycle_action_rejects_unknown_or_uppercase() {
    for bogus in [
        "\"ENABLE\"",
        "\"Enable\"",
        "\"\"",
        "\"start\"",
        "\"stop\"",
    ] {
        assert!(
            serde_json::from_str::<LifecycleAction>(bogus).is_err(),
            "LifecycleAction MUST reject {bogus}"
        );
    }
}

#[test]
fn lifecycle_action_implements_copy() {
    fn takes_value(_: LifecycleAction) {}
    let a = LifecycleAction::Restart;
    takes_value(a);
    takes_value(a);
}

#[test]
fn lifecycle_action_six_variants_are_distinct() {
    let all = [
        LifecycleAction::Enable,
        LifecycleAction::Disable,
        LifecycleAction::Restart,
        LifecycleAction::Reload,
        LifecycleAction::Uninstall,
        LifecycleAction::Promote,
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j {
                assert_ne!(a, b);
            }
        }
    }
}

// ─── LogSeverity ───────────────────────────────────────────────────

#[test]
fn log_severity_serde_uses_snake_case_for_each_variant() {
    let cases = [
        (LogSeverity::Debug, "\"debug\""),
        (LogSeverity::Info, "\"info\""),
        (LogSeverity::Warn, "\"warn\""),
        (LogSeverity::Error, "\"error\""),
    ];
    for (variant, expected) in cases {
        let json = serde_json::to_string(&variant).expect("serialize");
        assert_eq!(json, expected, "{variant:?} MUST serialize as '{expected}'");
        let parsed: LogSeverity = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, variant);
    }
}

#[test]
fn log_severity_rejects_uppercase_or_alternate_names() {
    for bogus in [
        "\"DEBUG\"",
        "\"Info\"",
        "\"\"",
        "\"warning\"",
        "\"err\"",
        "\"trace\"",
    ] {
        assert!(
            serde_json::from_str::<LogSeverity>(bogus).is_err(),
            "LogSeverity MUST reject {bogus}"
        );
    }
}

#[test]
fn log_severity_four_variants_are_distinct() {
    let all = [
        LogSeverity::Debug,
        LogSeverity::Info,
        LogSeverity::Warn,
        LogSeverity::Error,
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j {
                assert_ne!(a, b);
            }
        }
    }
}

#[test]
fn log_severity_implements_copy() {
    fn takes_value(_: LogSeverity) {}
    let s = LogSeverity::Warn;
    takes_value(s);
    takes_value(s);
}

// ─── HostEventKind ─────────────────────────────────────────────────

#[test]
fn host_event_kind_serde_uses_snake_case_for_each_variant() {
    let cases = [
        (HostEventKind::LifecycleTransition, "\"lifecycle_transition\""),
        (HostEventKind::HealthCheck, "\"health_check\""),
        (HostEventKind::ConfigRevision, "\"config_revision\""),
        (HostEventKind::RolloutDecision, "\"rollout_decision\""),
        (
            HostEventKind::SupplyChainVerification,
            "\"supply_chain_verification\"",
        ),
        (HostEventKind::DriftDetected, "\"drift_detected\""),
        (
            HostEventKind::ConnectorStateChange,
            "\"connector_state_change\"",
        ),
    ];
    for (variant, expected) in cases {
        let json = serde_json::to_string(&variant).expect("serialize");
        assert_eq!(json, expected, "{variant:?} MUST serialize as '{expected}'");
        let parsed: HostEventKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, variant);
    }
}

#[test]
fn host_event_kind_rejects_unknown_or_camelcase() {
    for bogus in [
        "\"LIFECYCLE_TRANSITION\"",
        "\"lifecycleTransition\"",
        "\"\"",
        "\"unknown_event\"",
        "\"health\"",
    ] {
        assert!(
            serde_json::from_str::<HostEventKind>(bogus).is_err(),
            "HostEventKind MUST reject {bogus}"
        );
    }
}

#[test]
fn host_event_kind_seven_variants_are_distinct() {
    let all = [
        HostEventKind::LifecycleTransition,
        HostEventKind::HealthCheck,
        HostEventKind::ConfigRevision,
        HostEventKind::RolloutDecision,
        HostEventKind::SupplyChainVerification,
        HostEventKind::DriftDetected,
        HostEventKind::ConnectorStateChange,
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j {
                assert_ne!(a, b);
            }
        }
    }
}

#[test]
fn host_event_kind_implements_copy() {
    fn takes_value(_: HostEventKind) {}
    let e = HostEventKind::HealthCheck;
    takes_value(e);
    takes_value(e);
}

// ─── SimulatePhase ─────────────────────────────────────────────────

#[test]
fn simulate_phase_serde_uses_snake_case_for_each_variant() {
    let cases = [
        (SimulatePhase::PreflightOnly, "\"preflight_only\""),
        (SimulatePhase::ConnectorReached, "\"connector_reached\""),
        (
            SimulatePhase::ConnectorUnsupported,
            "\"connector_unsupported\"",
        ),
        (SimulatePhase::TimedOut, "\"timed_out\""),
    ];
    for (variant, expected) in cases {
        let json = serde_json::to_string(&variant).expect("serialize");
        assert_eq!(json, expected, "{variant:?} MUST serialize as '{expected}'");
        let parsed: SimulatePhase = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, variant);
    }
}

#[test]
fn simulate_phase_rejects_unknown_or_camelcase() {
    for bogus in [
        "\"PREFLIGHT_ONLY\"",
        "\"preflightOnly\"",
        "\"\"",
        "\"timeout\"",
        "\"reached\"",
    ] {
        assert!(
            serde_json::from_str::<SimulatePhase>(bogus).is_err(),
            "SimulatePhase MUST reject {bogus}"
        );
    }
}

#[test]
fn simulate_phase_four_variants_are_distinct() {
    let all = [
        SimulatePhase::PreflightOnly,
        SimulatePhase::ConnectorReached,
        SimulatePhase::ConnectorUnsupported,
        SimulatePhase::TimedOut,
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j {
                assert_ne!(a, b);
            }
        }
    }
}

#[test]
fn simulate_phase_implements_copy() {
    fn takes_value(_: SimulatePhase) {}
    let p = SimulatePhase::ConnectorReached;
    takes_value(p);
    takes_value(p);
}
