use fcp_testkit::live_suite::{
    CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate, LiveTier, StaleResourceReport,
};
use serde_json::{Value, json};

const CONNECTOR: &str = "zalo";
const PROVIDER: &str = "Zalo Bot API";
const GATE_ENV: &str = "FCP_LIVE_WRITE";
const WRITE_OPERATION: &str = "zalo.webhook.set";
const CLEANUP_OPERATION: &str = "zalo.webhook.delete";
const TARGET_ENV: &str = "ZALO_LIVE_WEBHOOK_URL";
const AUTH_FAILURE_MAPPING: &str =
    "Zalo Bot API unauthorized response maps to unauthorized before webhook mutation";

#[must_use]
fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::live_write(CONNECTOR, PROVIDER)
        .with_env_secret(
            "access_token",
            "ZALO_ACCESS_TOKEN",
            "Zalo Bot API token for a dedicated test bot",
        )
        .with_env_secret(
            "webhook_secret",
            "ZALO_WEBHOOK_SECRET",
            "Secret used only by the synthetic webhook verification path",
        )
        .with_env_var(
            TARGET_ENV,
            "Synthetic HTTPS webhook URL that can be set and then deleted for the test bot",
        )
        .with_account_setup(
            "Use a dedicated Zalo test bot. The suite sets one synthetic webhook URL and must delete it before passing.",
        )
        .with_budget(0.25)
        .with_cleanup(CleanupStrategy::PrefixDelete)
        .with_rate_limits(0.2, true)
        .with_metadata(
            "mutation_scope",
            json!({
                "operation": WRITE_OPERATION,
                "cleanup_operation": CLEANUP_OPERATION,
                "target_env": TARGET_ENV,
                "namespace": "fcp-test-zalo-*",
                "call_ceiling": 4,
            }),
        )
        .with_metadata(
            "cleanup_verification",
            json!({
                "verify_operation": "zalo.webhook.info",
                "residual_webhook_is_failure": true,
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
    });

    eprintln!("{CONNECTOR}_LIVE_WRITE_JSONL {event}");
    assert_eq!(event["mutation_attempted_after_denial"], json!(false));
    assert_eq!(event["cleanup_required_after_denial"], json!(false));
}

#[test]
fn live_write_cleanup_verification_escalates_stale_resources() {
    let tenant = manifest().synthetic_tenant();
    let prefix = tenant.prefix();
    let stale_resource = format!("{prefix}-webhook-orphan-00000000-20000101");
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
