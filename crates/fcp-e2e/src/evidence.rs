//! E2E scenario script format and evidence bundle types.
//!
//! This module defines the structured types for describing end-to-end test
//! scenarios, individual steps with assertions, and evidence bundles for
//! archival and replay.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Shared verification bundle schema version used across replayable evidence.
pub const VERIFICATION_BUNDLE_SCHEMA_VERSION: &str = "fcp-verification-bundle/v1";

// ── Scenario metadata ───────────────────────────────────────────────────

/// Metadata describing an E2E scenario.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioMeta {
    /// Human-readable scenario name.
    pub name: String,
    /// Longer description of what the scenario verifies.
    pub description: String,
    /// Free-form tags for filtering/grouping.
    pub tags: Vec<String>,
    /// Execution environment.
    pub environment: ScenarioEnvironment,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
    /// Author identifier.
    pub author: String,
}

/// Execution environment for an E2E scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioEnvironment {
    /// Local in-process execution.
    Local,
    /// WASI sandbox execution.
    Wasi,
    /// Remote (network) execution.
    Remote,
    /// Mesh-based multi-node execution.
    Mesh,
}

/// Validation tier that produced an evidence bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceLayer {
    Unit,
    Integration,
    E2e,
    Snapshot,
    Benchmark,
    Live,
}

impl EvidenceLayer {
    /// Short machine-readable label for this layer.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unit => "unit",
            Self::Integration => "integration",
            Self::E2e => "e2e",
            Self::Snapshot => "snapshot",
            Self::Benchmark => "benchmark",
            Self::Live => "live",
        }
    }
}

/// Stable command slots carried by replayable evidence.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationCommands {
    /// Preferred local rerun command.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub local: String,
    /// Preferred CI or remote-offloaded rerun command.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ci: String,
    /// Bundle validation command.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub validate: String,
}

// ── Step taxonomy ───────────────────────────────────────────────────────

/// Classification of an E2E step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepKind {
    /// Precondition establishment.
    Setup,
    /// Primary operation under test.
    Action,
    /// Verification point.
    Assert,
    /// Cleanup.
    Teardown,
    /// Intermediate state capture.
    Checkpoint,
    /// Failure recovery path.
    Recovery,
    /// Expected failure scenario.
    Negative,
}

// ── Scenario step ───────────────────────────────────────────────────────

/// A single step in an E2E scenario.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioStep {
    /// Zero-based step index.
    pub index: u32,
    /// Step classification.
    pub kind: StepKind,
    /// Human-readable description.
    pub description: String,
    /// Correlation ID linking related operations.
    pub correlation_id: String,
    /// ISO 8601 timestamp of step execution.
    pub timestamp: String,
    /// Duration in milliseconds (None if not yet executed).
    pub duration_ms: Option<u64>,
    /// Assertions evaluated during this step.
    pub assertions: Vec<StepAssertion>,
    /// Evidence collected during this step.
    pub evidence: Vec<EvidenceItem>,
}

/// A single assertion within a step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepAssertion {
    /// What was being asserted.
    pub description: String,
    /// Whether the assertion passed.
    pub passed: bool,
    /// Expected value (stringified).
    pub expected: String,
    /// Actual value (stringified).
    pub actual: String,
}

// ── Evidence items ──────────────────────────────────────────────────────

/// An evidence item collected during a step.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EvidenceItem {
    /// Captured log lines.
    Log {
        /// Raw log lines.
        lines: Vec<String>,
    },
    /// Cryptographic receipt evidence.
    Receipt {
        /// Digest (hash) of the receipt.
        digest: String,
        /// Short summary of the receipt payload.
        payload_summary: String,
    },
    /// Snapshot of component health at a point in time.
    HealthSnapshot {
        /// Component name.
        component: String,
        /// Health state (e.g. "healthy", "degraded").
        state: String,
    },
    /// A single metric observation.
    Metric {
        /// Metric name.
        name: String,
        /// Observed value.
        value: f64,
        /// Unit of measurement.
        unit: String,
    },
}

// ── Scenario script ─────────────────────────────────────────────────────

/// A complete E2E scenario script.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioScript {
    /// Scenario metadata.
    pub meta: ScenarioMeta,
    /// Ordered list of steps.
    pub steps: Vec<ScenarioStep>,
    /// Overall scenario outcome.
    pub outcome: ScenarioOutcome,
}

/// Outcome of an E2E scenario execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ScenarioOutcome {
    /// All assertions passed.
    Pass,
    /// A step failed.
    Fail {
        /// Index of the failing step.
        step_index: u32,
        /// Reason for failure.
        reason: String,
    },
    /// The scenario was skipped.
    Skip {
        /// Reason for skipping.
        reason: String,
    },
    /// Mixed results.
    Degraded {
        /// Number of passing assertions.
        passed: u32,
        /// Number of failing assertions.
        failed: u32,
        /// Human-readable detail.
        details: String,
    },
}

// ── Evidence bundle ─────────────────────────────────────────────────────

/// Evidence bundle for archival and replay of a scenario execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBundle {
    /// Shared verification-bundle schema version.
    #[serde(default = "default_bundle_schema_version")]
    pub schema_version: String,
    /// Stable scenario identifier for downstream tooling.
    pub scenario_id: String,
    /// Optional run identifier when a harness minted one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    /// Optional connector identifier when the bundle is connector-scoped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connector_id: Option<String>,
    /// Validation tier that produced this bundle.
    #[serde(default = "default_evidence_layer")]
    pub layer: EvidenceLayer,
    /// Canonical artifact labels mapped to relative bundle paths.
    #[serde(
        default = "canonical_e2e_artifact_paths",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub artifact_paths: BTreeMap<String, String>,
    /// The scenario script with results.
    pub script: ScenarioScript,
    /// Field paths that were redacted before archival.
    pub redacted_fields: Vec<String>,
    /// Instructions for replaying this scenario.
    pub replay_instructions: String,
    /// Structured rerun and validation commands.
    #[serde(default)]
    pub commands: VerificationCommands,
    /// Number of days to retain this bundle.
    pub retention_days: u32,
}

// ── Constructor & helpers ───────────────────────────────────────────────

/// Default retention period for evidence bundles (in days).
const DEFAULT_RETENTION_DAYS: u32 = 90;

fn default_bundle_schema_version() -> String {
    VERIFICATION_BUNDLE_SCHEMA_VERSION.to_string()
}

const fn default_evidence_layer() -> EvidenceLayer {
    EvidenceLayer::E2e
}

/// Canonical relative artifact paths expected from an E2E verification bundle.
#[must_use]
pub fn canonical_e2e_artifact_paths() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("logs_jsonl".to_string(), "logs.jsonl".to_string()),
        ("report_json".to_string(), "report.json".to_string()),
        ("summary_txt".to_string(), "summary.txt".to_string()),
        (
            "environment_json".to_string(),
            "environment.json".to_string(),
        ),
        (
            "session_transcript_json".to_string(),
            "session_transcript.json".to_string(),
        ),
        ("replay_sh".to_string(), "replay.sh".to_string()),
    ])
}

/// Canonical validator command for a materialized verification bundle.
#[must_use]
pub fn default_e2e_validation_command() -> String {
    "bash scripts/ci/validate_e2e_artifacts.sh --bundle-dir <bundle-dir>".to_string()
}

/// Create a new scenario script with sensible defaults.
#[must_use]
pub fn new_scenario(name: &str, env: ScenarioEnvironment) -> ScenarioScript {
    ScenarioScript {
        meta: ScenarioMeta {
            name: name.to_string(),
            description: String::new(),
            tags: Vec::new(),
            environment: env,
            created_at: String::new(),
            author: String::new(),
        },
        steps: Vec::new(),
        outcome: ScenarioOutcome::Pass,
    }
}

/// Append a new step to the scenario script and return a mutable reference
/// to it. The step index is assigned automatically.
///
/// # Panics
///
/// Panics if the internal push to the step vector somehow fails to insert
/// (should never happen in practice).
pub fn add_step<'a>(
    script: &'a mut ScenarioScript,
    kind: StepKind,
    description: &str,
) -> &'a mut ScenarioStep {
    let index = u32::try_from(script.steps.len()).unwrap_or(u32::MAX);
    script.steps.push(ScenarioStep {
        index,
        kind,
        description: description.to_string(),
        correlation_id: String::new(),
        timestamp: String::new(),
        duration_ms: None,
        assertions: Vec::new(),
        evidence: Vec::new(),
    });
    script.steps.last_mut().expect("just pushed a step")
}

/// Finalize the scenario outcome based on step assertion results.
///
/// - If every assertion passed: `Pass`.
/// - If any assertion failed but some passed: `Degraded`.
/// - If any assertion failed and none passed: `Fail` (pointing at the first
///   failing step).
pub fn finalize_scenario(script: &mut ScenarioScript) {
    let mut total_passed: u32 = 0;
    let mut total_failed: u32 = 0;
    let mut first_fail_index: Option<u32> = None;
    let mut first_fail_reason: Option<String> = None;

    for step in &script.steps {
        for assertion in &step.assertions {
            if assertion.passed {
                total_passed += 1;
            } else {
                total_failed += 1;
                if first_fail_index.is_none() {
                    first_fail_index = Some(step.index);
                    first_fail_reason = Some(assertion.description.clone());
                }
            }
        }
    }

    script.outcome = if total_failed == 0 {
        ScenarioOutcome::Pass
    } else if total_passed == 0 {
        ScenarioOutcome::Fail {
            step_index: first_fail_index.unwrap_or(0),
            reason: first_fail_reason.unwrap_or_default(),
        }
    } else {
        ScenarioOutcome::Degraded {
            passed: total_passed,
            failed: total_failed,
            details: format!(
                "{total_passed} passed, {total_failed} failed; first failure at step {}",
                first_fail_index.unwrap_or(0),
            ),
        }
    };
}

/// Bundle a completed scenario script into an evidence bundle.
///
/// Fields listed in `redact` are recorded so consumers know what was
/// stripped before archival.
#[must_use]
pub fn bundle_evidence(script: ScenarioScript, redact: &[&str]) -> EvidenceBundle {
    EvidenceBundle {
        schema_version: default_bundle_schema_version(),
        scenario_id: script.meta.name.clone(),
        run_id: None,
        connector_id: None,
        layer: default_evidence_layer(),
        artifact_paths: canonical_e2e_artifact_paths(),
        script,
        redacted_fields: redact.iter().map(|s| (*s).to_string()).collect(),
        replay_instructions: String::new(),
        commands: VerificationCommands {
            validate: default_e2e_validation_command(),
            ..VerificationCommands::default()
        },
        retention_days: DEFAULT_RETENTION_DAYS,
    }
}

/// Validate a scenario script and return a list of problems.
///
/// A valid script must contain at least one `Setup`, one `Action`, and one
/// `Assert` step.
#[must_use]
pub fn validate_script(script: &ScenarioScript) -> Vec<String> {
    let mut errors = Vec::new();

    let has_setup = script.steps.iter().any(|s| s.kind == StepKind::Setup);
    let has_action = script.steps.iter().any(|s| s.kind == StepKind::Action);
    let has_assert = script.steps.iter().any(|s| s.kind == StepKind::Assert);

    if !has_setup {
        errors.push("missing required step kind: Setup".to_string());
    }
    if !has_action {
        errors.push("missing required step kind: Action".to_string());
    }
    if !has_assert {
        errors.push("missing required step kind: Assert".to_string());
    }

    errors
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_scenario_creates_with_correct_defaults() {
        let script = new_scenario("smoke_test", ScenarioEnvironment::Local);
        assert_eq!(script.meta.name, "smoke_test");
        assert_eq!(script.meta.environment, ScenarioEnvironment::Local);
        assert!(script.meta.description.is_empty());
        assert!(script.meta.tags.is_empty());
        assert!(script.steps.is_empty());
        assert_eq!(script.outcome, ScenarioOutcome::Pass);
    }

    #[test]
    fn add_step_increments_index_correctly() {
        let mut script = new_scenario("idx_test", ScenarioEnvironment::Local);
        add_step(&mut script, StepKind::Setup, "first");
        add_step(&mut script, StepKind::Action, "second");
        add_step(&mut script, StepKind::Assert, "third");
        assert_eq!(script.steps[0].index, 0);
        assert_eq!(script.steps[1].index, 1);
        assert_eq!(script.steps[2].index, 2);
    }

    #[test]
    fn setup_is_first_in_valid_scripts() {
        let mut script = new_scenario("order_test", ScenarioEnvironment::Local);
        add_step(&mut script, StepKind::Setup, "init env");
        add_step(&mut script, StepKind::Action, "invoke op");
        add_step(&mut script, StepKind::Assert, "check result");
        assert_eq!(script.steps[0].kind, StepKind::Setup);
    }

    #[test]
    fn scenario_with_no_assert_step_fails_validation() {
        let mut script = new_scenario("no_assert", ScenarioEnvironment::Local);
        add_step(&mut script, StepKind::Setup, "init");
        add_step(&mut script, StepKind::Action, "act");
        let errors = validate_script(&script);
        assert!(errors.iter().any(|e| e.contains("Assert")));
    }

    #[test]
    fn scenario_with_no_action_step_fails_validation() {
        let mut script = new_scenario("no_action", ScenarioEnvironment::Local);
        add_step(&mut script, StepKind::Setup, "init");
        add_step(&mut script, StepKind::Assert, "check");
        let errors = validate_script(&script);
        assert!(errors.iter().any(|e| e.contains("Action")));
    }

    #[test]
    fn complete_valid_scenario_passes_validation() {
        let mut script = new_scenario("valid", ScenarioEnvironment::Wasi);
        add_step(&mut script, StepKind::Setup, "init");
        add_step(&mut script, StepKind::Action, "do");
        add_step(&mut script, StepKind::Assert, "verify");
        let errors = validate_script(&script);
        assert!(errors.is_empty(), "expected no errors, got: {errors:?}");
    }

    #[test]
    fn finalize_scenario_sets_pass_for_all_passing_assertions() {
        let mut script = new_scenario("all_pass", ScenarioEnvironment::Local);
        let step = add_step(&mut script, StepKind::Assert, "check");
        step.assertions.push(StepAssertion {
            description: "value matches".to_string(),
            passed: true,
            expected: "42".to_string(),
            actual: "42".to_string(),
        });
        finalize_scenario(&mut script);
        assert_eq!(script.outcome, ScenarioOutcome::Pass);
    }

    #[test]
    fn finalize_scenario_sets_fail_for_failing_assertion() {
        let mut script = new_scenario("one_fail", ScenarioEnvironment::Local);
        let step = add_step(&mut script, StepKind::Assert, "check");
        step.assertions.push(StepAssertion {
            description: "mismatch".to_string(),
            passed: false,
            expected: "42".to_string(),
            actual: "99".to_string(),
        });
        finalize_scenario(&mut script);
        assert!(
            matches!(script.outcome, ScenarioOutcome::Fail { .. }),
            "expected Fail, got {:?}",
            script.outcome
        );
    }

    #[test]
    fn evidence_bundle_includes_redaction_list() {
        let script = new_scenario("redact_test", ScenarioEnvironment::Local);
        let bundle = bundle_evidence(script, &["access_token", "secret_key"]);
        assert_eq!(bundle.schema_version, VERIFICATION_BUNDLE_SCHEMA_VERSION);
        assert_eq!(bundle.scenario_id, "redact_test");
        assert_eq!(bundle.layer, EvidenceLayer::E2e);
        assert_eq!(bundle.redacted_fields.len(), 2);
        assert!(bundle.redacted_fields.contains(&"access_token".to_string()));
        assert!(bundle.redacted_fields.contains(&"secret_key".to_string()));
        assert_eq!(
            bundle.commands.validate,
            "bash scripts/ci/validate_e2e_artifacts.sh --bundle-dir <bundle-dir>"
        );
    }

    #[test]
    fn evidence_item_log_serialization_roundtrip() {
        let item = EvidenceItem::Log {
            lines: vec!["line1".to_string(), "line2".to_string()],
        };
        let json = serde_json::to_string(&item).expect("serialize");
        let back: EvidenceItem = serde_json::from_str(&json).expect("deserialize");
        match back {
            EvidenceItem::Log { lines } => {
                assert_eq!(lines.len(), 2);
                assert_eq!(lines[0], "line1");
            }
            other => panic!("expected Log variant, got {other:?}"),
        }
    }

    #[test]
    fn evidence_item_receipt_contains_digest() {
        let item = EvidenceItem::Receipt {
            digest: "sha256:abc123".to_string(),
            payload_summary: "invoke result".to_string(),
        };
        match &item {
            EvidenceItem::Receipt { digest, .. } => {
                assert_eq!(digest, "sha256:abc123");
            }
            other => panic!("expected Receipt, got {other:?}"),
        }
    }

    #[test]
    fn scenario_outcome_degraded_tracks_both_counts() {
        let outcome = ScenarioOutcome::Degraded {
            passed: 7,
            failed: 3,
            details: "mixed results".to_string(),
        };
        match outcome {
            ScenarioOutcome::Degraded {
                passed,
                failed,
                details,
            } => {
                assert_eq!(passed, 7);
                assert_eq!(failed, 3);
                assert_eq!(details, "mixed results");
            }
            other => panic!("expected Degraded, got {other:?}"),
        }
    }

    #[test]
    fn scenario_environment_serialization_covers_all_variants() {
        let variants = [
            (ScenarioEnvironment::Local, "\"local\""),
            (ScenarioEnvironment::Wasi, "\"wasi\""),
            (ScenarioEnvironment::Remote, "\"remote\""),
            (ScenarioEnvironment::Mesh, "\"mesh\""),
        ];
        for (env, expected_json) in variants {
            let json = serde_json::to_string(&env).expect("serialize");
            assert_eq!(json, expected_json, "variant {env:?}");
            let back: ScenarioEnvironment = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, env);
        }
    }

    #[test]
    fn step_assertion_tracks_expected_vs_actual() {
        let assertion = StepAssertion {
            description: "status code check".to_string(),
            passed: false,
            expected: "200".to_string(),
            actual: "500".to_string(),
        };
        assert!(!assertion.passed);
        assert_eq!(assertion.expected, "200");
        assert_eq!(assertion.actual, "500");
        assert_eq!(assertion.description, "status code check");
    }

    #[test]
    fn bundle_evidence_sets_default_retention_days() {
        let script = new_scenario("retention_test", ScenarioEnvironment::Local);
        let bundle = bundle_evidence(script, &[]);
        assert_eq!(bundle.retention_days, DEFAULT_RETENTION_DAYS);
        assert_eq!(bundle.retention_days, 90);
    }

    // ── Additional coverage ─────────────────────────────────────────────

    #[test]
    fn finalize_scenario_degraded_with_mixed_results() {
        let mut script = new_scenario("mixed", ScenarioEnvironment::Remote);
        let step = add_step(&mut script, StepKind::Assert, "check both");
        step.assertions.push(StepAssertion {
            description: "first passes".to_string(),
            passed: true,
            expected: "ok".to_string(),
            actual: "ok".to_string(),
        });
        step.assertions.push(StepAssertion {
            description: "second fails".to_string(),
            passed: false,
            expected: "ok".to_string(),
            actual: "err".to_string(),
        });
        finalize_scenario(&mut script);
        match &script.outcome {
            ScenarioOutcome::Degraded { passed, failed, .. } => {
                assert_eq!(*passed, 1);
                assert_eq!(*failed, 1);
            }
            other => panic!("expected Degraded, got {other:?}"),
        }
    }

    #[test]
    fn validate_script_empty_scenario_fails_all_three() {
        let script = new_scenario("empty", ScenarioEnvironment::Local);
        let errors = validate_script(&script);
        assert_eq!(errors.len(), 3);
        assert!(errors.iter().any(|e| e.contains("Setup")));
        assert!(errors.iter().any(|e| e.contains("Action")));
        assert!(errors.iter().any(|e| e.contains("Assert")));
    }

    #[test]
    fn scenario_script_serde_roundtrip() {
        let mut script = new_scenario("roundtrip", ScenarioEnvironment::Mesh);
        add_step(&mut script, StepKind::Setup, "init");
        add_step(&mut script, StepKind::Action, "act");
        let step = add_step(&mut script, StepKind::Assert, "verify");
        step.assertions.push(StepAssertion {
            description: "check".to_string(),
            passed: true,
            expected: "1".to_string(),
            actual: "1".to_string(),
        });
        step.evidence.push(EvidenceItem::Metric {
            name: "latency_ms".to_string(),
            value: 12.5,
            unit: "ms".to_string(),
        });
        finalize_scenario(&mut script);

        let json = serde_json::to_string(&script).expect("serialize");
        let back: ScenarioScript = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.meta.name, "roundtrip");
        assert_eq!(back.steps.len(), 3);
        assert_eq!(back.outcome, ScenarioOutcome::Pass);
    }

    #[test]
    fn evidence_bundle_serde_roundtrip() {
        let script = new_scenario("bundle_rt", ScenarioEnvironment::Wasi);
        let bundle = bundle_evidence(script, &["token"]);
        let json = serde_json::to_string(&bundle).expect("serialize");
        let back: EvidenceBundle = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.schema_version, VERIFICATION_BUNDLE_SCHEMA_VERSION);
        assert_eq!(back.scenario_id, "bundle_rt");
        assert_eq!(
            back.artifact_paths.get("report_json").map(String::as_str),
            Some("report.json")
        );
        assert_eq!(back.redacted_fields, vec!["token"]);
        assert_eq!(back.retention_days, 90);
    }

    #[test]
    fn evidence_item_health_snapshot_fields() {
        let item = EvidenceItem::HealthSnapshot {
            component: "connector-a".to_string(),
            state: "healthy".to_string(),
        };
        let json = serde_json::to_string(&item).expect("serialize");
        let back: EvidenceItem = serde_json::from_str(&json).expect("deserialize");
        match back {
            EvidenceItem::HealthSnapshot { component, state } => {
                assert_eq!(component, "connector-a");
                assert_eq!(state, "healthy");
            }
            other => panic!("expected HealthSnapshot, got {other:?}"),
        }
    }

    #[test]
    fn evidence_item_metric_value_preserved() {
        let item = EvidenceItem::Metric {
            name: "throughput".to_string(),
            value: 1234.5,
            unit: "req/s".to_string(),
        };
        let json = serde_json::to_string(&item).expect("serialize");
        let back: EvidenceItem = serde_json::from_str(&json).expect("deserialize");
        match back {
            EvidenceItem::Metric { name, value, unit } => {
                assert_eq!(name, "throughput");
                assert!((value - 1234.5).abs() < f64::EPSILON);
                assert_eq!(unit, "req/s");
            }
            other => panic!("expected Metric, got {other:?}"),
        }
    }

    #[test]
    fn add_step_sets_empty_defaults() {
        let mut script = new_scenario("defaults", ScenarioEnvironment::Local);
        add_step(&mut script, StepKind::Checkpoint, "snap");
        let step = &script.steps[0];
        assert!(step.correlation_id.is_empty());
        assert!(step.timestamp.is_empty());
        assert!(step.duration_ms.is_none());
        assert!(step.assertions.is_empty());
        assert!(step.evidence.is_empty());
    }

    #[test]
    fn step_kind_all_variants_distinct() {
        let kinds = [
            StepKind::Setup,
            StepKind::Action,
            StepKind::Assert,
            StepKind::Teardown,
            StepKind::Checkpoint,
            StepKind::Recovery,
            StepKind::Negative,
        ];
        for (i, a) in kinds.iter().enumerate() {
            for (j, b) in kinds.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn scenario_outcome_skip_variant() {
        let outcome = ScenarioOutcome::Skip {
            reason: "missing credentials".to_string(),
        };
        let json = serde_json::to_string(&outcome).expect("serialize");
        let back: ScenarioOutcome = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, outcome);
    }

    #[test]
    fn finalize_scenario_no_assertions_yields_pass() {
        let mut script = new_scenario("empty_steps", ScenarioEnvironment::Local);
        add_step(&mut script, StepKind::Setup, "init");
        finalize_scenario(&mut script);
        assert_eq!(script.outcome, ScenarioOutcome::Pass);
    }
}
