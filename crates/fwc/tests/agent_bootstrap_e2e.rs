use chrono::{TimeZone, Utc};
use fwc::agent_bootstrap::{
    AgentMailStatus, BootstrapMode, BootstrapOpts, BootstrapState, ProbeVerdict, ReadyBead,
    run_with_state,
};

fn base_opts(name: &str) -> BootstrapOpts {
    BootstrapOpts {
        agent_name_prefix: Some(name.to_owned()),
        ready_beads: vec![ReadyBead {
            id: "flywheel_connectors-angoc.7.2.1".to_owned(),
            title: "[Phase M.5.1] Deferred Rust impl for audit-chain OTLP parity export".to_owned(),
            priority: 3,
            score: Some(0.18),
        }],
        now: Utc
            .with_ymd_and_hms(2026, 5, 14, 3, 0, 0)
            .single()
            .expect("test timestamp should be valid"),
        ..BootstrapOpts::default()
    }
}

#[test]
fn test_fresh_env_full_bootstrap() {
    let mut state = BootstrapState::default();
    let report = run_with_state("TestAgent", &base_opts("TestAgent"), &mut state)
        .expect("fresh bootstrap should succeed");

    assert_eq!(report.mode, BootstrapMode::Fresh);
    assert_eq!(report.exit_code, 0);
    assert!(report.identity.created);
    assert_eq!(
        report.identity.agent_mail_status,
        AgentMailStatus::Registered
    );
    assert_eq!(report.reservation.scope, "src/**");
    assert!(!report.reservation.extended);
    assert_eq!(report.ready_beads.len(), 1);
    assert!(report.commit_template.written);
    assert_eq!(report.doctor.failed, 0);
    assert_eq!(
        report.doctor.by_probe.get("agent_name_prefix"),
        Some(&ProbeVerdict::Pass)
    );
    assert!(state.identities.contains_key("TestAgent"));
    assert_eq!(state.reservations.len(), 1);
}

#[test]
fn test_bootstrap_degraded_when_am_unreachable() {
    let mut state = BootstrapState::default();
    let opts = BootstrapOpts {
        agent_mail_reachable: false,
        ..base_opts("TestAgent")
    };
    let report = run_with_state("TestAgent", &opts, &mut state)
        .expect("degraded bootstrap should still return a report");

    assert_eq!(report.mode, BootstrapMode::Degraded);
    assert_eq!(report.exit_code, 4);
    assert!(!report.identity.created);
    assert_eq!(
        report.identity.agent_mail_status,
        AgentMailStatus::Unreachable
    );
    assert_eq!(report.reservation.ttl_seconds, 0);
    assert!(!report.commit_template.written);
    assert_eq!(
        report.doctor.by_probe.get("agent_mail_health"),
        Some(&ProbeVerdict::Fail)
    );
    assert!(state.identities.is_empty());
    assert!(state.reservations.is_empty());
}
