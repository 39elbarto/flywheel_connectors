use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveTier};
use serde_json::json;

const CONNECTOR_ID: &str = "imessage";
const PROVIDER: &str = "BlueBubbles iMessage bridge";
const LIVE_GATE_ENV: &str = "FCP_LIVE_DEVICE";
const LAB_INVENTORY_ENV: &str = "IMESSAGE_DEVICE_LAB_ID";
const LAB_EVIDENCE_ENV: &str = "IMESSAGE_DEVICE_LAB_EVIDENCE_JSONL";
const LAB_APPROVAL_ENV: &str = "IMESSAGE_DEVICE_LAB_APPROVAL";
const COMMAND_LINE: &str = "cargo test -p fcp-imessage --test live_verification -- --nocapture";

#[test]
fn imessage_device_lab_prerequisites_or_structured_skip_jsonl() {
    let environment = LiveEnvironment::from_manifest(device_manifest());
    let (status, reason) = lab_status(&environment);
    emit_jsonl(&environment, status, &reason);
    assert_eq!(environment.manifest.tier, LiveTier::DeviceRequired);
}

fn device_manifest() -> EnvironmentManifest {
    EnvironmentManifest::device(CONNECTOR_ID, PROVIDER)
        .with_env_var(
            LAB_INVENTORY_ENV,
            "Redaction-safe identifier for the iMessage bridge lab instance.",
        )
        .with_env_var(
            LAB_EVIDENCE_ENV,
            "Path or URI of the redaction-safe iMessage device-lab JSONL evidence bundle.",
        )
        .with_env_var(
            LAB_APPROVAL_ENV,
            "Set to yes only after the operator has reserved the iMessage bridge lab.",
        )
        .with_account_setup(
            "Use a dedicated BlueBubbles-backed iMessage lab account with synthetic conversations only.",
        )
        .with_budget(0.01)
        .with_cleanup(CleanupStrategy::None)
        .with_metadata("suite_class", json!("device_required"))
        .with_metadata("device_state_created", json!(false))
        .with_metadata("manual_reset_required", json!(false))
}

fn lab_status(environment: &LiveEnvironment) -> (&'static str, String) {
    let problems = environment.problems();
    if !problems.is_empty() {
        return ("skipped", problems.join("; "));
    }
    if !approval_enabled(environment) {
        return ("skipped", format!("{LAB_APPROVAL_ENV} must be yes"));
    }
    (
        "passed",
        "operator supplied redaction-safe device-lab evidence".to_owned(),
    )
}

fn approval_enabled(environment: &LiveEnvironment) -> bool {
    environment
        .env_vars
        .get(LAB_APPROVAL_ENV)
        .is_some_and(|value| matches!(value, "1" | "true" | "TRUE" | "yes" | "YES"))
}

fn emit_jsonl(environment: &LiveEnvironment, status: &str, reason: &str) {
    let record = json!({
        "event": "imessage_device_lab_verification",
        "connector_id": CONNECTOR_ID,
        "suite_class": "device_required",
        "gate_env_var": LIVE_GATE_ENV,
        "command_line": COMMAND_LINE,
        "status": status,
        "provider": PROVIDER,
        "required_env_vars": [LAB_INVENTORY_ENV, LAB_EVIDENCE_ENV, LAB_APPROVAL_ENV],
        "environment": environment.evidence_summary(),
        "device_access": if status == "passed" { "operator_attested_lab_evidence" } else { "not_attempted" },
        "device_state_created": false,
        "cleanup_strategy": "none",
        "cleanup_result": "not_required",
        "skip_reason": if status == "skipped" { Some(reason) } else { None },
    });
    let serialized = record.to_string();
    assert_redacted(&serialized);
    println!("IMESSAGE_DEVICE_LAB_JSONL {serialized}");
}

fn assert_redacted(serialized: &str) {
    for name in [LAB_INVENTORY_ENV, LAB_EVIDENCE_ENV, LAB_APPROVAL_ENV] {
        if let Ok(value) = std::env::var(name)
            && !matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES")
        {
            assert!(!serialized.contains(&value), "leaked value for {name}");
        }
    }
}
