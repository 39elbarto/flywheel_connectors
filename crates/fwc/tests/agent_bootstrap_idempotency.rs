use chrono::{TimeZone, Utc};
use fwc::agent_bootstrap::{
    AgentBootstrapError, AgentMailStatus, BootstrapMode, BootstrapOpts, BootstrapState, ReadyBead,
    run_with_state,
};

fn opts(name: &str) -> BootstrapOpts {
    BootstrapOpts {
        agent_name_prefix: Some(name.to_owned()),
        ready_beads: vec![ReadyBead {
            id: "flywheel_connectors-angoc.6.2.1".to_owned(),
            title: "[Phase L.2.1] Deferred Rust impl for fwc agent-bootstrap".to_owned(),
            priority: 3,
            score: Some(0.42),
        }],
        now: Utc
            .with_ymd_and_hms(2026, 5, 14, 3, 0, 0)
            .single()
            .expect("test timestamp should be valid"),
        ..BootstrapOpts::default()
    }
}

#[test]
fn test_bootstrap_idempotent_same_name() {
    let mut state = BootstrapState::default();

    let first = run_with_state("TestAgent", &opts("TestAgent"), &mut state)
        .expect("first bootstrap should succeed");
    let second = run_with_state("TestAgent", &opts("TestAgent"), &mut state)
        .expect("second bootstrap should converge");

    assert_eq!(first.mode, BootstrapMode::Fresh);
    assert!(first.identity.created);
    assert_eq!(
        first.identity.agent_mail_status,
        AgentMailStatus::Registered
    );
    assert!(!first.reservation.extended);

    assert_eq!(second.mode, BootstrapMode::Rebootstrap);
    assert!(!second.identity.created);
    assert_eq!(
        second.identity.agent_mail_status,
        AgentMailStatus::AlreadyPresent
    );
    assert!(second.reservation.extended);
    assert_eq!(second.ready_beads, first.ready_beads);
    assert_eq!(second.identity.identity_id, first.identity.identity_id);
    assert_eq!(state.identities.len(), 1);
    assert_eq!(state.reservations.len(), 1);
}

#[test]
fn test_bootstrap_fails_on_existing_different_owner() {
    let mut state = BootstrapState::default();
    let first_opts = BootstrapOpts {
        owner_email: Some("owner-a@example.dev".to_owned()),
        ..opts("TestAgent")
    };
    run_with_state("TestAgent", &first_opts, &mut state).expect("initial owner should register");

    let second_opts = BootstrapOpts {
        owner_email: Some("owner-b@example.dev".to_owned()),
        ..opts("TestAgent")
    };
    let error = run_with_state("TestAgent", &second_opts, &mut state)
        .expect_err("different owner should be rejected");

    match error {
        AgentBootstrapError::IdentityConflict {
            name,
            existing_owner,
            requested_owner,
        } => {
            assert_eq!(name, "TestAgent");
            assert_eq!(existing_owner, "owner-a@example.dev");
            assert_eq!(requested_owner, "owner-b@example.dev");
        }
        other => panic!("expected identity conflict, got {other:?}"),
    }
}
