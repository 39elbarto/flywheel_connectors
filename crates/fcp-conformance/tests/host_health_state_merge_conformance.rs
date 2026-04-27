//! `HealthState` lifecycle + `ConnectorHealth` mapping conformance.
//!
//! `fcp_core::HealthState` is the connector lifecycle enum (Starting,
//! Ready, Degraded, Error, Stopping). `fcp_core::ConnectorHealth` is
//! the external-facing health classification (Healthy, Degraded,
//! Unavailable) used in discovery responses, the health API, and CLI.
//! The two types are bridged by `impl From<&HealthState> for
//! ConnectorHealth`, and that mapping is the cross-crate contract
//! every external observer of connector health depends on.
//!
//! NORMATIVE properties pinned:
//!
//! 1. **`HealthState::as_str` snake_case mapping** for all 5 variants.
//! 2. **`ConnectorHealth` constructors** produce the right variant.
//! 3. **`is_healthy` only on `Healthy`**; `is_available` covers
//!    `Healthy + Degraded` (the documented "operational" set) but
//!    NOT `Unavailable`.
//! 4. **`From<&HealthState>` mapping**:
//!    - `Ready` → `Healthy`
//!    - `Degraded { reason }` → `Degraded { reason }` (reason
//!      preserved verbatim)
//!    - `Starting` → `Unavailable` with reason "Connector is starting"
//!    - `Stopping` → `Unavailable` with reason "Connector is stopping"
//!    - `Error { reason }` → `Unavailable { reason }`
//! 5. **JSON serde** uses the documented internal-tag format.

use fcp_core::{ConnectorHealth, HealthState};

#[test]
fn health_state_as_str_matches_snake_case_for_each_variant() {
    assert_eq!(HealthState::Starting.as_str(), "starting");
    assert_eq!(HealthState::Ready.as_str(), "ready");
    assert_eq!(
        HealthState::Degraded {
            reason: "x".into()
        }
        .as_str(),
        "degraded"
    );
    assert_eq!(
        HealthState::Error {
            reason: "boom".into()
        }
        .as_str(),
        "error"
    );
    assert_eq!(HealthState::Stopping.as_str(), "stopping");
}

#[test]
fn connector_health_healthy_constructor_yields_healthy_variant() {
    let h = ConnectorHealth::healthy();
    assert!(h.is_healthy());
    assert!(h.is_available());
    assert!(matches!(h, ConnectorHealth::Healthy));
}

#[test]
fn connector_health_degraded_constructor_preserves_reason() {
    let d = ConnectorHealth::degraded("disk pressure");
    assert!(!d.is_healthy());
    assert!(
        d.is_available(),
        "Degraded MUST be reported as available — the connector is still serving traffic"
    );
    match d {
        ConnectorHealth::Degraded { reason } => {
            assert_eq!(reason, "disk pressure");
        }
        other => panic!("expected Degraded, got {other:?}"),
    }
}

#[test]
fn connector_health_unavailable_constructor_records_now_timestamp() {
    let before = chrono::Utc::now();
    let u = ConnectorHealth::unavailable("api down");
    let after = chrono::Utc::now();

    assert!(!u.is_healthy());
    assert!(
        !u.is_available(),
        "Unavailable MUST report is_available=false"
    );
    match u {
        ConnectorHealth::Unavailable { reason, since } => {
            assert_eq!(reason, "api down");
            assert!(
                since >= before && since <= after,
                "ConnectorHealth::unavailable MUST stamp `since` with the current time; \
                 got {since}, expected in [{before}, {after}]"
            );
        }
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

#[test]
fn from_ready_health_state_yields_healthy_connector_health() {
    let mapped: ConnectorHealth = (&HealthState::Ready).into();
    assert!(matches!(mapped, ConnectorHealth::Healthy));
}

#[test]
fn from_degraded_health_state_preserves_reason_verbatim() {
    let state = HealthState::Degraded {
        reason: "memory pressure detected".into(),
    };
    let mapped: ConnectorHealth = (&state).into();
    match mapped {
        ConnectorHealth::Degraded { reason } => {
            assert_eq!(
                reason, "memory pressure detected",
                "From<&HealthState> MUST preserve the Degraded reason verbatim"
            );
        }
        other => panic!("expected Degraded, got {other:?}"),
    }
}

#[test]
fn from_starting_health_state_yields_unavailable_with_starting_reason() {
    let mapped: ConnectorHealth = (&HealthState::Starting).into();
    match mapped {
        ConnectorHealth::Unavailable { reason, since: _ } => {
            assert_eq!(
                reason, "Connector is starting",
                "Starting MUST map to a documented 'Connector is starting' reason"
            );
        }
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

#[test]
fn from_stopping_health_state_yields_unavailable_with_stopping_reason() {
    let mapped: ConnectorHealth = (&HealthState::Stopping).into();
    match mapped {
        ConnectorHealth::Unavailable { reason, since: _ } => {
            assert_eq!(
                reason, "Connector is stopping",
                "Stopping MUST map to a documented 'Connector is stopping' reason"
            );
        }
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

#[test]
fn from_error_health_state_propagates_reason_to_unavailable() {
    let state = HealthState::Error {
        reason: "panic during init".into(),
    };
    let mapped: ConnectorHealth = (&state).into();
    match mapped {
        ConnectorHealth::Unavailable { reason, since: _ } => {
            assert_eq!(
                reason, "panic during init",
                "Error reason MUST propagate to Unavailable verbatim — operators need the cause"
            );
        }
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

#[test]
fn from_health_state_unavailable_records_a_recent_timestamp() {
    // The mapping for non-Ready states stamps `since` with
    // chrono::Utc::now(). Pin that the timestamp is not stale.
    let before = chrono::Utc::now();
    let mapped: ConnectorHealth = (&HealthState::Starting).into();
    let after = chrono::Utc::now();
    if let ConnectorHealth::Unavailable { since, .. } = mapped {
        assert!(
            since >= before && since <= after,
            "From<&HealthState>::Starting MUST stamp `since` with current time; \
             got {since}, expected in [{before}, {after}]"
        );
    }
}

#[test]
fn json_serde_health_state_uses_state_tag_with_lowercase_variant() {
    let starting_json =
        serde_json::to_string(&HealthState::Starting).expect("serialize Starting");
    assert!(
        starting_json.contains("\"state\":\"starting\""),
        "HealthState JSON MUST use {{\"state\":\"<variant>\"}} tag with lowercase rename; \
         got {starting_json}"
    );

    let parsed: HealthState =
        serde_json::from_str(&starting_json).expect("deserialize Starting");
    assert!(matches!(parsed, HealthState::Starting));
}

#[test]
fn json_serde_connector_health_uses_status_tag() {
    let healthy_json =
        serde_json::to_string(&ConnectorHealth::Healthy).expect("serialize Healthy");
    assert!(
        healthy_json.contains("\"status\":\"healthy\""),
        "ConnectorHealth JSON MUST use {{\"status\":\"<variant>\"}} tag with lowercase \
         rename; got {healthy_json}"
    );

    let parsed: ConnectorHealth =
        serde_json::from_str(&healthy_json).expect("deserialize Healthy");
    assert!(matches!(parsed, ConnectorHealth::Healthy));
}

#[test]
fn is_available_excludes_unavailable() {
    // The is_available predicate is what callers use to decide
    // whether to send traffic. It MUST exclude Unavailable.
    let unavailable = ConnectorHealth::unavailable("down");
    assert!(
        !unavailable.is_available(),
        "Unavailable MUST report is_available=false — otherwise traffic is routed to a \
         dead connector"
    );
}

#[test]
fn from_health_state_round_trips_for_all_variants_without_panic() {
    // Sanity sweep: the From mapping must produce a valid
    // ConnectorHealth for every HealthState variant — no panic, no
    // wedge state.
    let states = [
        HealthState::Starting,
        HealthState::Ready,
        HealthState::Degraded {
            reason: "r".into(),
        },
        HealthState::Error {
            reason: "e".into(),
        },
        HealthState::Stopping,
    ];
    for state in &states {
        let _: ConnectorHealth = state.into();
    }
}
