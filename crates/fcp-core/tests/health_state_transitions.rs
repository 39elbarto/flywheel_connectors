use fcp_core::{
    AggregateHealthState, ComponentHealthEntry, CompositeHealthSnapshot, HealthAggregationConfig,
};

fn component(state: AggregateHealthState) -> ComponentHealthEntry {
    ComponentHealthEntry {
        name: "connector:example".to_string(),
        state,
        consecutive_failures: 0,
    }
}

fn aggregate_status(state: AggregateHealthState) -> AggregateHealthState {
    CompositeHealthSnapshot::from_components(
        "test-runtime".to_string(),
        42,
        vec![component(state)],
        &HealthAggregationConfig::default(),
    )
    .status
}

#[test]
fn aggregate_health_state_degrades_through_documented_ladder() {
    let healthy = aggregate_status(AggregateHealthState::Healthy);
    let degraded = aggregate_status(AggregateHealthState::Degraded {
        reasons: vec!["latency".to_string()],
    });
    let unhealthy = aggregate_status(AggregateHealthState::Unhealthy {
        reasons: vec!["crash_loop".to_string()],
    });

    assert!(healthy.is_healthy());
    assert_eq!(
        degraded,
        AggregateHealthState::Degraded {
            reasons: vec!["connector:example".to_string()],
        }
    );
    assert_eq!(
        unhealthy,
        AggregateHealthState::Unhealthy {
            reasons: vec!["connector:example".to_string()],
        }
    );

    assert_eq!(healthy.severity(), 0);
    assert_eq!(degraded.severity(), 1);
    assert_eq!(unhealthy.severity(), 2);
    assert_eq!(healthy.to_string(), "healthy");
    assert_eq!(degraded.to_string(), "degraded: connector:example");
    assert_eq!(unhealthy.to_string(), "unhealthy: connector:example");
}

#[test]
fn aggregate_health_state_recovers_through_documented_ladder() {
    let observed = [
        aggregate_status(AggregateHealthState::Unhealthy {
            reasons: vec!["dependency_down".to_string()],
        }),
        aggregate_status(AggregateHealthState::Degraded {
            reasons: vec!["dependency_recovering".to_string()],
        }),
        aggregate_status(AggregateHealthState::Healthy),
    ];

    assert!(observed[0].is_unhealthy());
    assert!(observed[1].is_degraded());
    assert!(observed[2].is_healthy());
    assert_eq!(
        observed
            .iter()
            .map(AggregateHealthState::severity)
            .collect::<Vec<_>>(),
        vec![2, 1, 0]
    );
}

#[test]
fn aggregate_health_state_roundtrips_documented_transition_path() {
    let observed = [
        aggregate_status(AggregateHealthState::Healthy),
        aggregate_status(AggregateHealthState::Degraded {
            reasons: vec!["latency_spike".to_string()],
        }),
        aggregate_status(AggregateHealthState::Unhealthy {
            reasons: vec!["dependency_down".to_string()],
        }),
        aggregate_status(AggregateHealthState::Degraded {
            reasons: vec!["dependency_recovering".to_string()],
        }),
        aggregate_status(AggregateHealthState::Healthy),
    ];

    assert!(observed[0].is_healthy());
    assert!(observed[1].is_degraded());
    assert!(observed[2].is_unhealthy());
    assert!(observed[3].is_degraded());
    assert!(observed[4].is_healthy());
    assert_eq!(
        observed
            .iter()
            .map(AggregateHealthState::severity)
            .collect::<Vec<_>>(),
        vec![0, 1, 2, 1, 0]
    );
    assert_eq!(
        observed
            .windows(2)
            .map(|states| i16::from(states[1].severity()) - i16::from(states[0].severity()))
            .collect::<Vec<_>>(),
        vec![1, 1, -1, -1]
    );
    assert_eq!(
        observed.iter().map(ToString::to_string).collect::<Vec<_>>(),
        vec![
            "healthy",
            "degraded: connector:example",
            "unhealthy: connector:example",
            "degraded: connector:example",
            "healthy",
        ]
    );
}

#[test]
fn aggregate_health_state_roundtrip_preserves_transition_states() -> Result<(), serde_json::Error> {
    for state in [
        AggregateHealthState::Healthy,
        AggregateHealthState::Degraded {
            reasons: vec!["slow".to_string()],
        },
        AggregateHealthState::Unhealthy {
            reasons: vec!["down".to_string()],
        },
    ] {
        let encoded = serde_json::to_string(&state)?;
        let decoded: AggregateHealthState = serde_json::from_str(&encoded)?;

        assert_eq!(decoded, state);
        assert_eq!(decoded.severity(), state.severity());
    }

    Ok(())
}
