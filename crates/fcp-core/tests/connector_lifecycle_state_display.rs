use std::str::FromStr;

use fcp_core::ConnectorLifecycleState;

const CASES: &[(ConnectorLifecycleState, &str)] = &[
    (ConnectorLifecycleState::Loaded, "loaded"),
    (ConnectorLifecycleState::Activated, "activated"),
    (ConnectorLifecycleState::Running, "running"),
    (ConnectorLifecycleState::Suspended, "suspended"),
    (ConnectorLifecycleState::Terminated, "terminated"),
];

#[test]
fn connector_lifecycle_states_display_canonical_strings() {
    for (state, expected) in CASES {
        assert_eq!(state.to_string(), *expected);
    }
}

#[test]
fn connector_lifecycle_states_roundtrip_from_display() {
    for (state, expected) in CASES {
        let parsed = ConnectorLifecycleState::from_str(expected)
            .expect("canonical connector lifecycle state should parse");

        assert_eq!(parsed, *state);
        assert_eq!(parsed.to_string(), *expected);
    }
}
