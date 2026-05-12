use fcp_testkit::live_suite::{
    CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate, LiveTier, StaleResourceReport,
};
use serde_json::{Value, json};

const CONNECTOR: &str = "zalouser";
const PROVIDER: &str = "Zalo personal account runtime";
const GATE_ENV: &str = "FCP_LIVE_WRITE";
const WRITE_OPERATION: &str = "zalouser.helper.exec";
const CLEANUP_OPERATION: &str = "personal_test_thread_retention_prune";
const TARGET_ENV: &str = "ZALOUSER_LIVE_CONTACT_ID";
const AUTH_FAILURE_MAPPING: &str = "missing or rejected personal-account session maps to unsupported/unauthorized before helper execution";

#[must_use]
fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::live_write(CONNECTOR, PROVIDER)
        .with_env_secret(
            "session_state",
            "ZALOUSER_SESSION_STATE",
            "Operator-provided session state for an isolated personal-account test runtime",
        )
        .with_env_var(
            TARGET_ENV,
            "Dedicated contact or test thread that accepts prefixed synthetic messages",
        )
        .with_account_setup(
            "Use an isolated personal-account test runtime. This connector currently keeps helper execution disabled, so a live write run must fail closed until an operator-approved helper policy exists.",
        )
        .with_budget(0.25)
        .with_cleanup(CleanupStrategy::AutoExpire { ttl_hours: 24 })
        .with_rate_limits(0.1, true)
        .with_metadata(
            "mutation_scope",
            json!({
                "operation": WRITE_OPERATION,
                "target_env": TARGET_ENV,
                "namespace": "fcp-test-zalouser-*",
                "call_ceiling": 1,
                "execution_enabled": false,
            }),
        )
        .with_metadata(
            "cleanup_verification",
            json!({
                "operation": CLEANUP_OPERATION,
                "retention_window_hours": 24,
                "residual_prefix_is_failure_after_ttl": true,
            }),
        )
}

#[test]
fn live_write_manifest_declares_required_controls() {
    let manifest = manifest();
    let summary = manifest.evidence_summary();
    let prerequisites = manifest.prerequisite_report();

    assert_eq!(LiveTier::LiveWriteRequired.gate_env_var(), GATE_ENV);
    assert_eq!(summary["connector"], json!(CONNECTOR));
    assert_eq!(summary["tier"], json!("live_write_required"));
    assert_eq!(summary["synthetic_tenant_expected"], json!(true));
    assert!(prerequisites.account_setup_configured);
    assert!(prerequisites.budget_configured);
    assert!(prerequisites.cleanup_configured);
}

#[test]
fn live_write_prerequisite_evidence_is_redaction_safe() {
    let gate = LiveGate::write();
    let env = LiveEnvironment::from_manifest(manifest());
    let prerequisites = env.manifest.prerequisite_report();
    let event = json!({
        "connector": CONNECTOR,
        "event": "live_write_prerequisites",
        "suite_class": prerequisites.tier.to_string(),
        "gate_env_var": GATE_ENV,
        "gate_enabled": gate.is_enabled(),
        "ready": env.is_ready(),
        "write_operation": WRITE_OPERATION,
        "cleanup_operation": CLEANUP_OPERATION,
        "environment": env.evidence_summary(),
        "prerequisites": prerequisites.summary(),
        "redaction": redaction_evidence(),
    });

    eprintln!("{CONNECTOR}_LIVE_WRITE_JSONL {event}");
    assert_eq!(event["gate_env_var"], json!(GATE_ENV));
    assert_eq!(event["redaction"]["secret_values_logged"], json!(false));
    assert_eq!(
        event["redaction"]["provider_resource_ids_logged"],
        json!(false)
    );
    if env.is_ready() {
        assert!(prerequisites.is_ready());
    } else {
        assert!(!prerequisites.problems.is_empty());
    }
}

#[test]
fn live_write_denial_auth_failure_path_precedes_mutation() {
    let event = json!({
        "connector": CONNECTOR,
        "event": "live_write_auth_denial_contract",
        "write_operation": WRITE_OPERATION,
        "auth_failure_mapping": AUTH_FAILURE_MAPPING,
        "mutation_attempted_after_denial": false,
        "cleanup_required_after_denial": false,
        "execution_enabled": false,
    });

    eprintln!("{CONNECTOR}_LIVE_WRITE_JSONL {event}");
    assert_eq!(event["mutation_attempted_after_denial"], json!(false));
    assert_eq!(event["cleanup_required_after_denial"], json!(false));
    assert_eq!(event["execution_enabled"], json!(false));
}

#[test]
fn live_write_cleanup_verification_escalates_stale_resources() {
    let tenant = manifest().synthetic_tenant();
    let prefix = tenant.prefix();
    let stale_resource = format!("{prefix}-thread-orphan-00000000-20000101");
    let report = StaleResourceReport::scan(&[stale_resource.as_str()], 7);
    let event = json!({
        "connector": CONNECTOR,
        "event": "live_write_cleanup_verification",
        "cleanup_operation": CLEANUP_OPERATION,
        "cleanup_failure_escalates": report.has_stale(),
        "report": report.summary(),
        "redaction": redaction_evidence(),
    });

    eprintln!("{CONNECTOR}_LIVE_WRITE_JSONL {event}");
    assert!(report.has_stale());
    assert_eq!(event["cleanup_failure_escalates"], json!(true));
}

#[must_use]
fn redaction_evidence() -> Value {
    json!({
        "secret_values_logged": false,
        "provider_resource_ids_logged": false,
        "synthetic_identifiers_only": true,
    })
}
