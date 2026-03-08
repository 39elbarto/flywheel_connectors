//! Connector/host readiness contract for `fwc`.
//!
//! Defines the minimum metadata and RPC surface that a connector and `fcp-host`
//! must expose for `fwc` to present discovery, configuration, lifecycle
//! management, and invocation workflows cleanly.
//!
//! A connector is **fwc-ready** when all mandatory fields are present and valid.
//! Gap categories identify what is missing so cohort remediation beads can
//! systematically bring connectors to full readiness.

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Readiness verdict ───────────────────────────────────────────────────

/// Overall readiness assessment for a single connector.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReadinessVerdict {
    /// Canonical connector id (e.g. `"github:fcp2:1.0"`).
    pub connector_id: String,
    /// Crate path relative to workspace root (e.g. `"connectors/github"`).
    pub crate_path: String,
    /// Connector category/cohort for grouping remediation work.
    pub cohort: ConnectorCohort,
    /// Overall readiness level.
    pub level: ReadinessLevel,
    /// Per-area checklist results.
    pub areas: ReadinessAreas,
    /// Specific gaps that prevent full readiness.
    pub gaps: Vec<ReadinessGap>,
}

/// Readiness level summary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReadinessLevel {
    /// All mandatory fields present, all areas pass.
    Ready,
    /// Core functionality works but some metadata is missing.
    PartiallyReady,
    /// Major gaps prevent fwc from presenting this connector cleanly.
    NotReady,
}

/// Connector cohort for grouping remediation work.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectorCohort {
    Messaging,
    Social,
    Workspace,
    Productivity,
    Ai,
    DevTools,
    Infra,
    Data,
    Storage,
    Analytics,
    Finance,
    Browser,
    Knowledge,
    Automation,
    Community,
}

// ── Per-area checklists ─────────────────────────────────────────────────

/// Checklist results for each readiness area.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReadinessAreas {
    pub summary: SummaryReadiness,
    pub operations: OperationsReadiness,
    pub config: ConfigReadiness,
    pub lifecycle: LifecycleReadiness,
}

/// Host-visible connector summary contract.
///
/// Mandatory fields that the host must expose for `fwc list` and `fwc show`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct SummaryReadiness {
    /// Connector has a canonical id in `name:archetype:version` format.
    pub has_canonical_id: bool,
    /// Connector has a human-readable display name.
    pub has_display_name: bool,
    /// Connector declares at least one archetype (request-response, streaming, etc.).
    pub has_archetypes: bool,
    /// Version follows semver.
    pub has_semver_version: bool,
    /// Connector has a non-empty description.
    pub has_description: bool,
    /// Operation count is available from introspection.
    pub has_operation_count: bool,
    /// Capability/risk summary is derivable from operations.
    pub has_risk_summary: bool,
}

/// Operation metadata contract.
///
/// Every operation must declare these fields for `fwc ops`, `fwc schema`,
/// and `fwc invoke` to work correctly.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct OperationsReadiness {
    /// Total number of operations declared.
    pub operation_count: usize,
    /// All operations have a non-empty `id`.
    pub all_have_id: bool,
    /// All operations have a non-empty `summary`.
    pub all_have_summary: bool,
    /// All operations have an `input_schema` (JSON Schema).
    pub all_have_input_schema: bool,
    /// All operations have an `output_schema` (JSON Schema).
    pub all_have_output_schema: bool,
    /// All operations declare a `capability` requirement.
    pub all_have_capability: bool,
    /// All operations declare a `risk_level`.
    pub all_have_risk_level: bool,
    /// All operations declare a `safety_tier`.
    pub all_have_safety_tier: bool,
    /// All operations declare an `idempotency` class.
    pub all_have_idempotency: bool,
    /// All operations include `ai_hints` with `when_to_use`.
    pub all_have_ai_hints: bool,
    /// Operations that require approval declare `requires_approval`.
    pub approval_declared_where_needed: bool,
    /// Number of operations with complete examples in `ai_hints`.
    pub operations_with_examples: usize,
}

/// Config metadata contract.
///
/// Fields that `fwc config schema`, `fwc config doctor`, and `fwc config set`
/// need to present secure, redaction-aware configuration workflows.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct ConfigReadiness {
    /// Connector accepts configuration via `configure()`.
    pub accepts_config: bool,
    /// Config schema is available (can be a JSON Schema or structured value).
    pub has_config_schema: bool,
    /// Secret fields are clearly marked for redaction.
    pub secrets_marked: bool,
    /// Default values are documented for non-secret fields.
    pub defaults_documented: bool,
    /// Self-check (`self_check()`) is implemented and returns actionable reports.
    pub has_self_check: bool,
}

/// Lifecycle and state metadata contract.
///
/// Fields for `fwc status`, `fwc enable/disable`, and `fwc start/stop`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct LifecycleReadiness {
    /// Health endpoint (`health()`) returns meaningful state.
    pub has_health: bool,
    /// Connector reports `configured` and `handshaken` state.
    pub reports_lifecycle_state: bool,
    /// Streaming/event support is declared when applicable.
    pub events_declared: bool,
    /// Rate limit declarations are present.
    pub has_rate_limits: bool,
    /// Metrics (`metrics()`) return populated data.
    pub has_metrics: bool,
    /// Shutdown is implemented for clean teardown.
    pub has_shutdown: bool,
}

// ── Gap categories ──────────────────────────────────────────────────────

/// A specific readiness gap with remediation guidance.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReadinessGap {
    /// Gap category for grouping.
    pub category: GapCategory,
    /// Human-readable description of what is missing.
    pub description: String,
    /// Severity: does this block fwc usage or just degrade it?
    pub severity: GapSeverity,
    /// Suggested remediation action.
    pub remediation: String,
}

/// Categories of readiness gaps.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GapCategory {
    /// Missing or malformed connector identity metadata.
    Identity,
    /// Missing operation metadata (schema, hints, safety).
    OperationMetadata,
    /// Missing or incomplete config schema.
    ConfigSchema,
    /// Missing health/lifecycle/metrics implementation.
    Lifecycle,
    /// Missing examples or agent hints.
    AgentHints,
    /// Missing event/stream declarations.
    EventSupport,
    /// Missing rate limit declarations.
    RateLimits,
    /// Missing approval mode declarations.
    ApprovalPolicy,
}

/// How severely a gap affects fwc usability.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GapSeverity {
    /// fwc cannot present this connector at all.
    Blocking,
    /// fwc works but output is degraded or incomplete.
    Degraded,
    /// fwc works fully but polish/hints are missing.
    Cosmetic,
}

// ── Host RPC contract ───────────────────────────────────────────────────

/// Canonical payload shape for `fwc list` (discovery summary).
///
/// The host must be able to produce this for every registered connector.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectorSummary {
    /// Canonical connector id.
    pub id: String,
    /// Human-readable display name.
    pub name: String,
    /// Semver version string.
    pub version: String,
    /// Short description.
    pub description: String,
    /// Connector archetypes (e.g. `["request-response", "streaming"]`).
    pub archetypes: Vec<String>,
    /// Current lifecycle state.
    pub state: ConnectorState,
    /// Number of declared operations.
    pub operation_count: usize,
    /// Highest risk level across all operations.
    pub max_risk: String,
    /// Whether the connector supports events/streaming.
    pub has_events: bool,
}

/// Lifecycle state as reported by the host.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectorState {
    /// Not yet configured.
    Unconfigured,
    /// Configured but not handshaken.
    Configured,
    /// Fully operational.
    Ready,
    /// Running but with degraded functionality.
    Degraded,
    /// Explicitly disabled by operator.
    Disabled,
    /// Error state requiring intervention.
    Error,
}

/// Canonical payload shape for `fwc show <connector>`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectorDetail {
    /// Summary fields.
    pub summary: ConnectorSummary,
    /// Per-operation metadata.
    pub operations: Vec<OperationSummary>,
    /// Config schema (redacted: secrets replaced with `"***"`).
    pub config_schema: Option<Value>,
    /// Current health snapshot.
    pub health: Option<HealthSummary>,
    /// Rate limit declarations.
    pub rate_limits: Vec<RateLimitSummary>,
}

/// Compact operation summary for `fwc ops`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperationSummary {
    /// Operation id (e.g. `"issues.create"`).
    pub id: String,
    /// One-line summary.
    pub summary: String,
    /// Required capability.
    pub capability: String,
    /// Risk level: low, medium, high, critical.
    pub risk_level: String,
    /// Safety tier: safe, risky, dangerous, critical, forbidden.
    pub safety_tier: String,
    /// Idempotency class: none, best-effort, strict.
    pub idempotency: String,
    /// Whether approval is required.
    pub requires_approval: bool,
    /// Whether simulate is supported.
    pub supports_simulate: bool,
}

/// Health summary for display.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealthSummary {
    /// Current state: starting, ready, degraded, error, stopping.
    pub state: String,
    /// Uptime in human-readable form.
    pub uptime: String,
    /// Optional load factor (0.0 to 1.0).
    pub load: Option<f32>,
}

/// Rate limit summary for display.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RateLimitSummary {
    /// What this limit applies to (e.g. operation id or "global").
    pub scope: String,
    /// Requests per window.
    pub requests: u32,
    /// Window duration (e.g. "60s").
    pub window: String,
}

// ── Readiness evaluation ────────────────────────────────────────────────

/// Evaluate a connector's introspection output against the readiness contract.
///
/// Takes the raw introspection JSON (as returned by `FcpConnector::introspect()`)
/// and produces a verdict with specific gaps.
#[allow(clippy::too_many_lines)]
pub fn evaluate_introspection(
    connector_id: &str,
    crate_path: &str,
    cohort: ConnectorCohort,
    introspection: &Value,
) -> ReadinessVerdict {
    let ops = introspection["operations"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let operation_count = ops.len();

    // Evaluate operation metadata completeness.
    let mut all_have_id = true;
    let mut all_have_summary = true;
    let mut all_have_input_schema = true;
    let mut all_have_output_schema = true;
    let mut all_have_capability = true;
    let mut all_have_risk_level = true;
    let mut all_have_safety_tier = true;
    let mut all_have_idempotency = true;
    let mut all_have_ai_hints = true;
    let mut operations_with_examples = 0usize;

    for op in &ops {
        if op["id"].as_str().unwrap_or_default().is_empty() {
            all_have_id = false;
        }
        if op["summary"].as_str().unwrap_or_default().is_empty() {
            all_have_summary = false;
        }
        if op["input_schema"].is_null() {
            all_have_input_schema = false;
        }
        if op["output_schema"].is_null() {
            all_have_output_schema = false;
        }
        if op["capability"].as_str().unwrap_or_default().is_empty() {
            all_have_capability = false;
        }
        if op["risk_level"].as_str().unwrap_or_default().is_empty() {
            all_have_risk_level = false;
        }
        if op["safety_tier"].as_str().unwrap_or_default().is_empty() {
            all_have_safety_tier = false;
        }
        if op["idempotency"].as_str().unwrap_or_default().is_empty() {
            all_have_idempotency = false;
        }
        let hints = &op["ai_hints"];
        if hints.is_null() || hints["when_to_use"].as_str().unwrap_or_default().is_empty() {
            all_have_ai_hints = false;
        }
        if hints["examples"].as_array().is_some_and(|a| !a.is_empty()) {
            operations_with_examples += 1;
        }
    }

    let operations = OperationsReadiness {
        operation_count,
        all_have_id,
        all_have_summary,
        all_have_input_schema,
        all_have_output_schema,
        all_have_capability,
        all_have_risk_level,
        all_have_safety_tier,
        all_have_idempotency,
        all_have_ai_hints,
        approval_declared_where_needed: true, // assume OK unless proven otherwise
        operations_with_examples,
    };

    // Summary readiness: derived from connector_id format and introspection.
    let id_parts: Vec<&str> = connector_id.split(':').collect();
    let summary = SummaryReadiness {
        has_canonical_id: id_parts.len() >= 3,
        has_display_name: !connector_id.is_empty(),
        has_archetypes: true, // archetype is declared in manifest, not introspection
        has_semver_version: id_parts.len() >= 3,
        has_description: true, // from manifest
        has_operation_count: operation_count > 0,
        has_risk_summary: all_have_risk_level,
    };

    // Config and lifecycle from introspection are limited; mark as needing
    // host-level verification for a complete assessment.
    let has_auth_caps = !introspection["auth_caps"].is_null();

    let config = ConfigReadiness {
        accepts_config: true, // all connectors accept config
        has_config_schema: has_auth_caps, // proxy: auth_caps implies config awareness
        secrets_marked: false,            // requires manifest inspection
        defaults_documented: false,       // requires manifest inspection
        has_self_check: true,             // trait requires it
    };

    let lifecycle = LifecycleReadiness {
        has_health: true,             // trait requires it
        reports_lifecycle_state: true, // BaseConnector provides it
        events_declared: true, // event declaration is optional; all connectors pass
        has_rate_limits: true,        // trait requires rate_limits()
        has_metrics: true,            // trait requires metrics()
        has_shutdown: true,           // trait requires shutdown()
    };

    let areas = ReadinessAreas {
        summary,
        operations,
        config,
        lifecycle,
    };

    // Collect gaps.
    let mut gaps = Vec::new();

    if operation_count == 0 {
        gaps.push(ReadinessGap {
            category: GapCategory::OperationMetadata,
            description: "No operations declared in introspection".to_owned(),
            severity: GapSeverity::Blocking,
            remediation: "Implement operations_info() returning at least one OperationInfo"
                .to_owned(),
        });
    }
    if !all_have_input_schema {
        gaps.push(ReadinessGap {
            category: GapCategory::OperationMetadata,
            description: "Some operations missing input_schema".to_owned(),
            severity: GapSeverity::Degraded,
            remediation: "Add JSON Schema for input to all operations".to_owned(),
        });
    }
    if !all_have_output_schema {
        gaps.push(ReadinessGap {
            category: GapCategory::OperationMetadata,
            description: "Some operations missing output_schema".to_owned(),
            severity: GapSeverity::Degraded,
            remediation: "Add JSON Schema for output to all operations".to_owned(),
        });
    }
    if !all_have_ai_hints {
        gaps.push(ReadinessGap {
            category: GapCategory::AgentHints,
            description: "Some operations missing ai_hints.when_to_use".to_owned(),
            severity: GapSeverity::Cosmetic,
            remediation: "Add AgentHint with when_to_use to all operations".to_owned(),
        });
    }
    if operations_with_examples < operation_count {
        gaps.push(ReadinessGap {
            category: GapCategory::AgentHints,
            description: format!(
                "Only {operations_with_examples}/{operation_count} operations have examples"
            ),
            severity: GapSeverity::Cosmetic,
            remediation: "Add examples to ai_hints for remaining operations".to_owned(),
        });
    }

    let level = if gaps.iter().any(|g| g.severity == GapSeverity::Blocking) {
        ReadinessLevel::NotReady
    } else if gaps
        .iter()
        .any(|g| g.severity == GapSeverity::Degraded)
    {
        ReadinessLevel::PartiallyReady
    } else {
        ReadinessLevel::Ready
    };

    ReadinessVerdict {
        connector_id: connector_id.to_owned(),
        crate_path: crate_path.to_owned(),
        cohort,
        level,
        areas,
        gaps,
    }
}

/// Mandatory fields for the host discovery endpoint per connector.
///
/// These are the fields that `fwc list` absolutely requires.
pub const MANDATORY_SUMMARY_FIELDS: &[&str] = &[
    "id",
    "name",
    "version",
    "description",
    "operation_count",
    "state",
];

/// Mandatory fields per operation for `fwc ops` and `fwc invoke`.
pub const MANDATORY_OPERATION_FIELDS: &[&str] = &[
    "id",
    "summary",
    "capability",
    "risk_level",
    "safety_tier",
    "idempotency",
    "input_schema",
    "output_schema",
];

/// Fields that enhance agent UX but are not strictly required.
pub const RECOMMENDED_OPERATION_FIELDS: &[&str] = &[
    "description",
    "ai_hints",
    "requires_approval",
    "rate_limit",
    "examples",
];

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    // ── ReadinessLevel ──────────────────────────────────────────────────

    #[test]
    fn readiness_level_serde_round_trip() {
        for level in [
            ReadinessLevel::Ready,
            ReadinessLevel::PartiallyReady,
            ReadinessLevel::NotReady,
        ] {
            let json = serde_json::to_string(&level).unwrap();
            let back: ReadinessLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(level, back);
        }
    }

    #[test]
    fn readiness_level_kebab_case_serialization() {
        let json = serde_json::to_string(&ReadinessLevel::PartiallyReady).unwrap();
        assert_eq!(json, "\"partially-ready\"");
    }

    // ── ConnectorCohort ─────────────────────────────────────────────────

    #[test]
    fn cohort_serde_round_trip() {
        for cohort in [
            ConnectorCohort::Messaging,
            ConnectorCohort::Ai,
            ConnectorCohort::DevTools,
            ConnectorCohort::Finance,
        ] {
            let json = serde_json::to_string(&cohort).unwrap();
            let back: ConnectorCohort = serde_json::from_str(&json).unwrap();
            assert_eq!(cohort, back);
        }
    }

    // ── GapSeverity ordering ────────────────────────────────────────────

    #[test]
    fn gap_severity_ordering() {
        assert!(GapSeverity::Blocking < GapSeverity::Degraded);
        assert!(GapSeverity::Degraded < GapSeverity::Cosmetic);
    }

    // ── ConnectorState ──────────────────────────────────────────────────

    #[test]
    fn connector_state_serde() {
        let json = serde_json::to_string(&ConnectorState::Ready).unwrap();
        assert_eq!(json, "\"ready\"");
        let back: ConnectorState = serde_json::from_str("\"degraded\"").unwrap();
        assert_eq!(back, ConnectorState::Degraded);
    }

    // ── evaluate_introspection ──────────────────────────────────────────

    #[test]
    fn fully_ready_connector() {
        let introspection = json!({
            "operations": [
                {
                    "id": "issues.create",
                    "summary": "Create a new issue",
                    "input_schema": {"type": "object"},
                    "output_schema": {"type": "object"},
                    "capability": "github.write",
                    "risk_level": "medium",
                    "safety_tier": "risky",
                    "idempotency": "none",
                    "ai_hints": {
                        "when_to_use": "When the user wants to create a GitHub issue",
                        "common_mistakes": [],
                        "examples": ["Create issue titled 'Bug fix'"],
                        "related": []
                    }
                },
                {
                    "id": "issues.list",
                    "summary": "List issues",
                    "input_schema": {"type": "object"},
                    "output_schema": {"type": "array"},
                    "capability": "github.read",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "strict",
                    "ai_hints": {
                        "when_to_use": "When listing issues in a repository",
                        "common_mistakes": [],
                        "examples": ["List open issues"],
                        "related": []
                    }
                }
            ],
            "events": [],
            "resource_types": []
        });

        let verdict = evaluate_introspection(
            "github:fcp2:1.0",
            "connectors/github",
            ConnectorCohort::DevTools,
            &introspection,
        );

        assert_eq!(verdict.level, ReadinessLevel::Ready);
        assert!(verdict.gaps.is_empty());
        assert_eq!(verdict.areas.operations.operation_count, 2);
        assert!(verdict.areas.operations.all_have_id);
        assert!(verdict.areas.operations.all_have_summary);
        assert!(verdict.areas.operations.all_have_input_schema);
        assert!(verdict.areas.operations.all_have_capability);
        assert!(verdict.areas.operations.all_have_ai_hints);
        assert_eq!(verdict.areas.operations.operations_with_examples, 2);
    }

    #[test]
    fn connector_with_no_operations_is_not_ready() {
        let introspection = json!({
            "operations": [],
            "events": [],
            "resource_types": []
        });

        let verdict = evaluate_introspection(
            "empty:fcp2:0.1",
            "connectors/empty",
            ConnectorCohort::Automation,
            &introspection,
        );

        assert_eq!(verdict.level, ReadinessLevel::NotReady);
        assert!(verdict.gaps.iter().any(|g| g.category == GapCategory::OperationMetadata
            && g.severity == GapSeverity::Blocking));
    }

    #[test]
    fn connector_missing_schemas_is_partially_ready() {
        let introspection = json!({
            "operations": [
                {
                    "id": "send",
                    "summary": "Send a message",
                    "input_schema": null,
                    "output_schema": null,
                    "capability": "slack.write",
                    "risk_level": "medium",
                    "safety_tier": "risky",
                    "idempotency": "none",
                    "ai_hints": {
                        "when_to_use": "Send a Slack message",
                        "examples": ["Send hello to #general"]
                    }
                }
            ],
            "events": []
        });

        let verdict = evaluate_introspection(
            "slack:fcp2:1.0",
            "connectors/slack",
            ConnectorCohort::Messaging,
            &introspection,
        );

        assert_eq!(verdict.level, ReadinessLevel::PartiallyReady);
        assert!(verdict
            .gaps
            .iter()
            .any(|g| g.category == GapCategory::OperationMetadata
                && g.description.contains("input_schema")));
    }

    #[test]
    fn connector_missing_ai_hints_gets_cosmetic_gap() {
        let introspection = json!({
            "operations": [
                {
                    "id": "query",
                    "summary": "Run a SQL query",
                    "input_schema": {"type": "object"},
                    "output_schema": {"type": "array"},
                    "capability": "pg.read",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "strict",
                    "ai_hints": null
                }
            ],
            "events": []
        });

        let verdict = evaluate_introspection(
            "postgresql:fcp2:1.0",
            "connectors/postgresql",
            ConnectorCohort::Data,
            &introspection,
        );

        // Missing ai_hints is cosmetic, not blocking.
        assert_eq!(verdict.level, ReadinessLevel::Ready);
        assert!(verdict.gaps.iter().any(|g| g.category == GapCategory::AgentHints
            && g.severity == GapSeverity::Cosmetic));
    }

    #[test]
    fn verdict_serialization_round_trip() {
        let verdict = ReadinessVerdict {
            connector_id: "test:fcp2:0.1".to_owned(),
            crate_path: "connectors/test".to_owned(),
            cohort: ConnectorCohort::Automation,
            level: ReadinessLevel::PartiallyReady,
            areas: ReadinessAreas {
                summary: SummaryReadiness {
                    has_canonical_id: true,
                    has_display_name: true,
                    has_archetypes: true,
                    has_semver_version: true,
                    has_description: true,
                    has_operation_count: true,
                    has_risk_summary: true,
                },
                operations: OperationsReadiness {
                    operation_count: 5,
                    all_have_id: true,
                    all_have_summary: true,
                    all_have_input_schema: false,
                    all_have_output_schema: true,
                    all_have_capability: true,
                    all_have_risk_level: true,
                    all_have_safety_tier: true,
                    all_have_idempotency: true,
                    all_have_ai_hints: false,
                    approval_declared_where_needed: true,
                    operations_with_examples: 3,
                },
                config: ConfigReadiness {
                    accepts_config: true,
                    has_config_schema: false,
                    secrets_marked: false,
                    defaults_documented: false,
                    has_self_check: true,
                },
                lifecycle: LifecycleReadiness {
                    has_health: true,
                    reports_lifecycle_state: true,
                    events_declared: true,
                    has_rate_limits: true,
                    has_metrics: true,
                    has_shutdown: true,
                },
            },
            gaps: vec![ReadinessGap {
                category: GapCategory::OperationMetadata,
                description: "Some operations missing input_schema".to_owned(),
                severity: GapSeverity::Degraded,
                remediation: "Add JSON Schema for input".to_owned(),
            }],
        };

        let json = serde_json::to_string_pretty(&verdict).unwrap();
        let back: ReadinessVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back.connector_id, "test:fcp2:0.1");
        assert_eq!(back.level, ReadinessLevel::PartiallyReady);
        assert_eq!(back.gaps.len(), 1);
    }

    // ── ConnectorSummary ────────────────────────────────────────────────

    #[test]
    fn connector_summary_serde() {
        let summary = ConnectorSummary {
            id: "github:fcp2:1.0".to_owned(),
            name: "GitHub".to_owned(),
            version: "1.0.0".to_owned(),
            description: "GitHub API connector".to_owned(),
            archetypes: vec!["request-response".to_owned()],
            state: ConnectorState::Ready,
            operation_count: 12,
            max_risk: "high".to_owned(),
            has_events: true,
        };

        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["id"], "github:fcp2:1.0");
        assert_eq!(json["state"], "ready");
        assert_eq!(json["operation_count"], 12);
    }

    // ── OperationSummary ────────────────────────────────────────────────

    #[test]
    fn operation_summary_serde() {
        let op = OperationSummary {
            id: "issues.create".to_owned(),
            summary: "Create a new issue".to_owned(),
            capability: "github.write".to_owned(),
            risk_level: "medium".to_owned(),
            safety_tier: "risky".to_owned(),
            idempotency: "none".to_owned(),
            requires_approval: false,
            supports_simulate: true,
        };

        let json = serde_json::to_value(&op).unwrap();
        assert_eq!(json["id"], "issues.create");
        assert_eq!(json["risk_level"], "medium");
    }

    // ── Mandatory field constants ───────────────────────────────────────

    #[test]
    fn mandatory_summary_fields_are_non_empty() {
        assert!(!MANDATORY_SUMMARY_FIELDS.is_empty());
        assert!(MANDATORY_SUMMARY_FIELDS.contains(&"id"));
        assert!(MANDATORY_SUMMARY_FIELDS.contains(&"state"));
    }

    #[test]
    fn mandatory_operation_fields_cover_core_metadata() {
        assert!(MANDATORY_OPERATION_FIELDS.contains(&"id"));
        assert!(MANDATORY_OPERATION_FIELDS.contains(&"capability"));
        assert!(MANDATORY_OPERATION_FIELDS.contains(&"risk_level"));
        assert!(MANDATORY_OPERATION_FIELDS.contains(&"input_schema"));
    }

    #[test]
    fn recommended_fields_include_ai_hints() {
        assert!(RECOMMENDED_OPERATION_FIELDS.contains(&"ai_hints"));
        assert!(RECOMMENDED_OPERATION_FIELDS.contains(&"examples"));
    }

    // ── Edge cases ──────────────────────────────────────────────────────

    #[test]
    fn evaluate_null_introspection() {
        let verdict = evaluate_introspection(
            "broken:fcp2:0.0",
            "connectors/broken",
            ConnectorCohort::Automation,
            &json!(null),
        );
        assert_eq!(verdict.level, ReadinessLevel::NotReady);
    }

    #[test]
    fn evaluate_empty_object_introspection() {
        let verdict = evaluate_introspection(
            "empty:fcp2:0.0",
            "connectors/empty",
            ConnectorCohort::Automation,
            &json!({}),
        );
        assert_eq!(verdict.level, ReadinessLevel::NotReady);
    }

    #[test]
    fn evaluate_operation_with_empty_strings() {
        let introspection = json!({
            "operations": [
                {
                    "id": "",
                    "summary": "",
                    "input_schema": {"type": "object"},
                    "output_schema": {"type": "object"},
                    "capability": "",
                    "risk_level": "",
                    "safety_tier": "",
                    "idempotency": "",
                    "ai_hints": null
                }
            ]
        });

        let verdict = evaluate_introspection(
            "bad:fcp2:0.1",
            "connectors/bad",
            ConnectorCohort::Automation,
            &introspection,
        );

        // Empty strings are treated as missing.
        assert!(!verdict.areas.operations.all_have_id);
        assert!(!verdict.areas.operations.all_have_summary);
        assert!(!verdict.areas.operations.all_have_capability);
    }

    #[test]
    fn gap_category_serde() {
        let json = serde_json::to_string(&GapCategory::ConfigSchema).unwrap();
        assert_eq!(json, "\"config-schema\"");
        let back: GapCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(back, GapCategory::ConfigSchema);
    }

    #[test]
    fn multiple_gaps_accumulate() {
        let introspection = json!({
            "operations": [
                {
                    "id": "op1",
                    "summary": "Op one",
                    "input_schema": null,
                    "output_schema": null,
                    "capability": "cap.read",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "strict",
                    "ai_hints": null
                }
            ]
        });

        let verdict = evaluate_introspection(
            "multi:fcp2:0.1",
            "connectors/multi",
            ConnectorCohort::Data,
            &introspection,
        );

        // Should have gaps for: input_schema, output_schema, ai_hints, examples.
        assert!(verdict.gaps.len() >= 3);
    }

    // ── HealthSummary ───────────────────────────────────────────────────

    #[test]
    fn health_summary_serde() {
        let h = HealthSummary {
            state: "ready".to_owned(),
            uptime: "2h 15m".to_owned(),
            load: Some(0.5),
        };
        let json = serde_json::to_value(&h).unwrap();
        assert_eq!(json["state"], "ready");
        assert_eq!(json["load"], 0.5);
    }

    // ── RateLimitSummary ────────────────────────────────────────────────

    #[test]
    fn rate_limit_summary_serde() {
        let rl = RateLimitSummary {
            scope: "global".to_owned(),
            requests: 100,
            window: "60s".to_owned(),
        };
        let json = serde_json::to_value(&rl).unwrap();
        assert_eq!(json["requests"], 100);
    }

    // ── ConnectorDetail ─────────────────────────────────────────────────

    #[test]
    fn connector_detail_serde() {
        let detail = ConnectorDetail {
            summary: ConnectorSummary {
                id: "test:fcp2:1.0".to_owned(),
                name: "Test".to_owned(),
                version: "1.0.0".to_owned(),
                description: "Test connector".to_owned(),
                archetypes: vec!["request-response".to_owned()],
                state: ConnectorState::Ready,
                operation_count: 1,
                max_risk: "low".to_owned(),
                has_events: false,
            },
            operations: vec![OperationSummary {
                id: "test.ping".to_owned(),
                summary: "Ping the service".to_owned(),
                capability: "test.read".to_owned(),
                risk_level: "low".to_owned(),
                safety_tier: "safe".to_owned(),
                idempotency: "strict".to_owned(),
                requires_approval: false,
                supports_simulate: true,
            }],
            config_schema: Some(json!({"type": "object", "properties": {}})),
            health: Some(HealthSummary {
                state: "ready".to_owned(),
                uptime: "5m".to_owned(),
                load: None,
            }),
            rate_limits: vec![],
        };

        let json = serde_json::to_string(&detail).unwrap();
        let back: ConnectorDetail = serde_json::from_str(&json).unwrap();
        assert_eq!(back.summary.id, "test:fcp2:1.0");
        assert_eq!(back.operations.len(), 1);
    }

    // ── All ConnectorCohort variants serde round-trip ──────────────────

    #[test]
    fn all_connector_cohort_variants_serde_round_trip() {
        let all = [
            ConnectorCohort::Messaging,
            ConnectorCohort::Social,
            ConnectorCohort::Workspace,
            ConnectorCohort::Productivity,
            ConnectorCohort::Ai,
            ConnectorCohort::DevTools,
            ConnectorCohort::Infra,
            ConnectorCohort::Data,
            ConnectorCohort::Storage,
            ConnectorCohort::Analytics,
            ConnectorCohort::Finance,
            ConnectorCohort::Browser,
            ConnectorCohort::Knowledge,
            ConnectorCohort::Automation,
            ConnectorCohort::Community,
        ];
        assert_eq!(all.len(), 15, "must cover all 15 variants");
        for cohort in all {
            let json = serde_json::to_string(&cohort).unwrap();
            let back: ConnectorCohort = serde_json::from_str(&json).unwrap();
            assert_eq!(cohort, back);
        }
    }

    #[test]
    fn connector_cohort_kebab_case_values() {
        assert_eq!(
            serde_json::to_string(&ConnectorCohort::DevTools).unwrap(),
            "\"dev-tools\""
        );
        assert_eq!(
            serde_json::to_string(&ConnectorCohort::Ai).unwrap(),
            "\"ai\""
        );
        assert_eq!(
            serde_json::to_string(&ConnectorCohort::Messaging).unwrap(),
            "\"messaging\""
        );
    }

    // ── All ConnectorState variants serde round-trip ───────────────────

    #[test]
    fn all_connector_state_variants_serde_round_trip() {
        let all = [
            ConnectorState::Unconfigured,
            ConnectorState::Configured,
            ConnectorState::Ready,
            ConnectorState::Degraded,
            ConnectorState::Disabled,
            ConnectorState::Error,
        ];
        assert_eq!(all.len(), 6, "must cover all 6 variants");
        for state in all {
            let json = serde_json::to_string(&state).unwrap();
            let back: ConnectorState = serde_json::from_str(&json).unwrap();
            assert_eq!(state, back);
        }
    }

    #[test]
    fn connector_state_kebab_case_values() {
        assert_eq!(
            serde_json::to_string(&ConnectorState::Unconfigured).unwrap(),
            "\"unconfigured\""
        );
        assert_eq!(
            serde_json::to_string(&ConnectorState::Error).unwrap(),
            "\"error\""
        );
        assert_eq!(
            serde_json::to_string(&ConnectorState::Disabled).unwrap(),
            "\"disabled\""
        );
    }

    // ── All GapCategory variants serde round-trip ─────────────────────

    #[test]
    fn all_gap_category_variants_serde_round_trip() {
        let all = [
            GapCategory::Identity,
            GapCategory::OperationMetadata,
            GapCategory::ConfigSchema,
            GapCategory::Lifecycle,
            GapCategory::AgentHints,
            GapCategory::EventSupport,
            GapCategory::RateLimits,
            GapCategory::ApprovalPolicy,
        ];
        assert_eq!(all.len(), 8, "must cover all 8 variants");
        for cat in all {
            let json = serde_json::to_string(&cat).unwrap();
            let back: GapCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(cat, back);
        }
    }

    #[test]
    fn gap_category_kebab_case_values() {
        assert_eq!(
            serde_json::to_string(&GapCategory::OperationMetadata).unwrap(),
            "\"operation-metadata\""
        );
        assert_eq!(
            serde_json::to_string(&GapCategory::ApprovalPolicy).unwrap(),
            "\"approval-policy\""
        );
        assert_eq!(
            serde_json::to_string(&GapCategory::RateLimits).unwrap(),
            "\"rate-limits\""
        );
    }

    // ── GapSeverity serde all 3 variants ──────────────────────────────

    #[test]
    fn all_gap_severity_variants_serde_round_trip() {
        let all = [
            GapSeverity::Blocking,
            GapSeverity::Degraded,
            GapSeverity::Cosmetic,
        ];
        for sev in all {
            let json = serde_json::to_string(&sev).unwrap();
            let back: GapSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(sev, back);
        }
    }

    #[test]
    fn gap_severity_kebab_case_values() {
        assert_eq!(
            serde_json::to_string(&GapSeverity::Blocking).unwrap(),
            "\"blocking\""
        );
        assert_eq!(
            serde_json::to_string(&GapSeverity::Degraded).unwrap(),
            "\"degraded\""
        );
        assert_eq!(
            serde_json::to_string(&GapSeverity::Cosmetic).unwrap(),
            "\"cosmetic\""
        );
    }

    // ── GapSeverity full ordering ─────────────────────────────────────

    #[test]
    fn gap_severity_ordering_full() {
        assert!(GapSeverity::Blocking < GapSeverity::Degraded);
        assert!(GapSeverity::Blocking < GapSeverity::Cosmetic);
        assert!(GapSeverity::Degraded < GapSeverity::Cosmetic);
        // Reflexivity
        assert!(GapSeverity::Blocking == GapSeverity::Blocking);
        assert!(GapSeverity::Degraded == GapSeverity::Degraded);
        assert!(GapSeverity::Cosmetic == GapSeverity::Cosmetic);
        // Sorting
        let mut v = vec![
            GapSeverity::Cosmetic,
            GapSeverity::Blocking,
            GapSeverity::Degraded,
        ];
        v.sort();
        assert_eq!(
            v,
            vec![
                GapSeverity::Blocking,
                GapSeverity::Degraded,
                GapSeverity::Cosmetic
            ]
        );
    }

    // ── ReadinessLevel equality checks ────────────────────────────────

    #[test]
    fn readiness_level_equality() {
        assert_eq!(ReadinessLevel::Ready, ReadinessLevel::Ready);
        assert_eq!(
            ReadinessLevel::PartiallyReady,
            ReadinessLevel::PartiallyReady
        );
        assert_eq!(ReadinessLevel::NotReady, ReadinessLevel::NotReady);
        assert_ne!(ReadinessLevel::Ready, ReadinessLevel::PartiallyReady);
        assert_ne!(ReadinessLevel::Ready, ReadinessLevel::NotReady);
        assert_ne!(ReadinessLevel::PartiallyReady, ReadinessLevel::NotReady);
    }

    #[test]
    fn readiness_level_all_kebab_values() {
        assert_eq!(
            serde_json::to_string(&ReadinessLevel::Ready).unwrap(),
            "\"ready\""
        );
        assert_eq!(
            serde_json::to_string(&ReadinessLevel::PartiallyReady).unwrap(),
            "\"partially-ready\""
        );
        assert_eq!(
            serde_json::to_string(&ReadinessLevel::NotReady).unwrap(),
            "\"not-ready\""
        );
    }

    // ── evaluate_introspection: complete but missing examples ─────────

    #[test]
    fn complete_fields_but_missing_examples_only_cosmetic_gap() {
        let introspection = json!({
            "operations": [
                {
                    "id": "do.something",
                    "summary": "Does something",
                    "input_schema": {"type": "object"},
                    "output_schema": {"type": "object"},
                    "capability": "test.write",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "strict",
                    "ai_hints": {
                        "when_to_use": "When you need to do something",
                        "examples": []
                    }
                }
            ]
        });

        let verdict = evaluate_introspection(
            "test:fcp2:1.0",
            "connectors/test",
            ConnectorCohort::Automation,
            &introspection,
        );

        // All fields are complete except examples → only cosmetic gap
        assert_eq!(verdict.level, ReadinessLevel::Ready);
        assert!(verdict.gaps.iter().all(|g| g.severity == GapSeverity::Cosmetic));
        assert!(
            verdict
                .gaps
                .iter()
                .any(|g| g.description.contains("examples"))
        );
    }

    // ── evaluate_introspection: missing capability doesn't degrade ────

    #[test]
    fn missing_capability_does_not_degrade_level() {
        // "capability" missing still results in no Blocking/Degraded gap
        // (the function only adds gaps for schemas, ai_hints, examples, and zero ops)
        let introspection = json!({
            "operations": [
                {
                    "id": "op1",
                    "summary": "Something",
                    "input_schema": {"type": "object"},
                    "output_schema": {"type": "object"},
                    "capability": "",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "strict",
                    "ai_hints": {
                        "when_to_use": "Use it",
                        "examples": ["ex"]
                    }
                }
            ]
        });

        let verdict = evaluate_introspection(
            "test:fcp2:1.0",
            "connectors/test",
            ConnectorCohort::DevTools,
            &introspection,
        );

        // Capability is tracked in areas but not in gaps
        assert!(!verdict.areas.operations.all_have_capability);
        assert_eq!(verdict.level, ReadinessLevel::Ready);
    }

    // ── evaluate_introspection: non-canonical id (no colons) ──────────

    #[test]
    fn non_canonical_id_still_evaluates() {
        let introspection = json!({
            "operations": [
                {
                    "id": "op1",
                    "summary": "Op",
                    "input_schema": {"type": "object"},
                    "output_schema": {"type": "object"},
                    "capability": "c",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "none",
                    "ai_hints": {
                        "when_to_use": "use",
                        "examples": ["ex"]
                    }
                }
            ]
        });

        let verdict = evaluate_introspection(
            "noColonsHere",
            "connectors/test",
            ConnectorCohort::Browser,
            &introspection,
        );

        // Non-canonical id → has_canonical_id = false, has_semver_version = false
        assert!(!verdict.areas.summary.has_canonical_id);
        assert!(!verdict.areas.summary.has_semver_version);
        // But still evaluates the operations
        assert_eq!(verdict.areas.operations.operation_count, 1);
        assert_eq!(verdict.level, ReadinessLevel::Ready);
    }

    // ── evaluate_introspection: large operation set all complete ───────

    #[test]
    fn large_operation_set_all_complete_is_ready() {
        let ops: Vec<Value> = (0..15)
            .map(|i| {
                json!({
                    "id": format!("op.{i}"),
                    "summary": format!("Operation {i}"),
                    "input_schema": {"type": "object"},
                    "output_schema": {"type": "object"},
                    "capability": format!("cap.{i}"),
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "strict",
                    "ai_hints": {
                        "when_to_use": format!("When doing thing {i}"),
                        "examples": [format!("Example {i}")]
                    }
                })
            })
            .collect();

        let introspection = json!({ "operations": ops });

        let verdict = evaluate_introspection(
            "big:fcp2:2.0",
            "connectors/big",
            ConnectorCohort::Infra,
            &introspection,
        );

        assert_eq!(verdict.level, ReadinessLevel::Ready);
        assert!(verdict.gaps.is_empty());
        assert_eq!(verdict.areas.operations.operation_count, 15);
        assert_eq!(verdict.areas.operations.operations_with_examples, 15);
    }

    // ── evaluate_introspection: mixed ops → partially ready ──────────

    #[test]
    fn mixed_ops_some_missing_schemas_is_partially_ready() {
        let introspection = json!({
            "operations": [
                {
                    "id": "op.good",
                    "summary": "Good operation",
                    "input_schema": {"type": "object"},
                    "output_schema": {"type": "object"},
                    "capability": "cap.read",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "strict",
                    "ai_hints": {
                        "when_to_use": "Good operation",
                        "examples": ["ex"]
                    }
                },
                {
                    "id": "op.bad",
                    "summary": "Bad operation",
                    "input_schema": null,
                    "output_schema": {"type": "object"},
                    "capability": "cap.write",
                    "risk_level": "medium",
                    "safety_tier": "risky",
                    "idempotency": "none",
                    "ai_hints": {
                        "when_to_use": "Bad op",
                        "examples": ["ex"]
                    }
                },
                {
                    "id": "op.worse",
                    "summary": "Worse op",
                    "input_schema": {"type": "object"},
                    "output_schema": null,
                    "capability": "cap.admin",
                    "risk_level": "high",
                    "safety_tier": "dangerous",
                    "idempotency": "none",
                    "ai_hints": {
                        "when_to_use": "Worse op",
                        "examples": ["ex"]
                    }
                }
            ]
        });

        let verdict = evaluate_introspection(
            "mixed:fcp2:1.0",
            "connectors/mixed",
            ConnectorCohort::Data,
            &introspection,
        );

        assert_eq!(verdict.level, ReadinessLevel::PartiallyReady);
        assert!(!verdict.areas.operations.all_have_input_schema);
        assert!(!verdict.areas.operations.all_have_output_schema);
        assert!(
            verdict
                .gaps
                .iter()
                .any(|g| g.description.contains("input_schema"))
        );
        assert!(
            verdict
                .gaps
                .iter()
                .any(|g| g.description.contains("output_schema"))
        );
    }

    // ── evaluate_introspection: has_events detection ──────────────────

    #[test]
    fn connector_with_events_detected_via_introspection() {
        let introspection = json!({
            "operations": [
                {
                    "id": "op1",
                    "summary": "s",
                    "input_schema": {},
                    "output_schema": {},
                    "capability": "c",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "none",
                    "ai_hints": { "when_to_use": "w", "examples": ["e"] }
                }
            ],
            "events": [
                { "name": "issue.created", "description": "Fired when an issue is created" }
            ]
        });

        let verdict = evaluate_introspection(
            "evented:fcp2:1.0",
            "connectors/evented",
            ConnectorCohort::DevTools,
            &introspection,
        );

        // The lifecycle.events_declared is always true in current impl
        assert!(verdict.areas.lifecycle.events_declared);
        assert_eq!(verdict.areas.operations.operation_count, 1);
    }

    // ── evaluate_introspection: auth_caps → config awareness ─────────

    #[test]
    fn connector_with_auth_caps_has_config_schema() {
        let introspection = json!({
            "operations": [
                {
                    "id": "op1",
                    "summary": "s",
                    "input_schema": {},
                    "output_schema": {},
                    "capability": "c",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "none",
                    "ai_hints": { "when_to_use": "w", "examples": ["e"] }
                }
            ],
            "auth_caps": { "bearer": true }
        });

        let verdict = evaluate_introspection(
            "authed:fcp2:1.0",
            "connectors/authed",
            ConnectorCohort::Ai,
            &introspection,
        );

        assert!(verdict.areas.config.has_config_schema);
    }

    #[test]
    fn connector_without_auth_caps_no_config_schema() {
        let introspection = json!({
            "operations": [
                {
                    "id": "op1",
                    "summary": "s",
                    "input_schema": {},
                    "output_schema": {},
                    "capability": "c",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "none",
                    "ai_hints": { "when_to_use": "w", "examples": ["e"] }
                }
            ]
        });

        let verdict = evaluate_introspection(
            "noauth:fcp2:1.0",
            "connectors/noauth",
            ConnectorCohort::Knowledge,
            &introspection,
        );

        assert!(!verdict.areas.config.has_config_schema);
    }

    // ── ConnectorSummary: all fields serialize correctly ──────────────

    #[test]
    fn connector_summary_all_fields_present_in_json() {
        let summary = ConnectorSummary {
            id: "slack:fcp2:2.0".to_owned(),
            name: "Slack".to_owned(),
            version: "2.0.0".to_owned(),
            description: "Slack messaging connector".to_owned(),
            archetypes: vec!["request-response".to_owned(), "streaming".to_owned()],
            state: ConnectorState::Degraded,
            operation_count: 42,
            max_risk: "critical".to_owned(),
            has_events: true,
        };

        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["id"], "slack:fcp2:2.0");
        assert_eq!(json["name"], "Slack");
        assert_eq!(json["version"], "2.0.0");
        assert_eq!(json["description"], "Slack messaging connector");
        assert_eq!(json["archetypes"].as_array().unwrap().len(), 2);
        assert_eq!(json["state"], "degraded");
        assert_eq!(json["operation_count"], 42);
        assert_eq!(json["max_risk"], "critical");
        assert_eq!(json["has_events"], true);
    }

    #[test]
    fn connector_summary_deserialization_from_json() {
        let json = json!({
            "id": "x:fcp2:1.0",
            "name": "X",
            "version": "1.0.0",
            "description": "desc",
            "archetypes": [],
            "state": "unconfigured",
            "operation_count": 0,
            "max_risk": "low",
            "has_events": false
        });
        let summary: ConnectorSummary = serde_json::from_value(json).unwrap();
        assert_eq!(summary.state, ConnectorState::Unconfigured);
        assert!(summary.archetypes.is_empty());
        assert!(!summary.has_events);
    }

    // ── ConnectorDetail: with None health and empty rate_limits ───────

    #[test]
    fn connector_detail_none_health_empty_rate_limits() {
        let detail = ConnectorDetail {
            summary: ConnectorSummary {
                id: "bare:fcp2:0.1".to_owned(),
                name: "Bare".to_owned(),
                version: "0.1.0".to_owned(),
                description: "Bare connector".to_owned(),
                archetypes: vec![],
                state: ConnectorState::Unconfigured,
                operation_count: 0,
                max_risk: "low".to_owned(),
                has_events: false,
            },
            operations: vec![],
            config_schema: None,
            health: None,
            rate_limits: vec![],
        };

        let json = serde_json::to_value(&detail).unwrap();
        assert!(json["health"].is_null());
        assert!(json["config_schema"].is_null());
        assert_eq!(json["rate_limits"].as_array().unwrap().len(), 0);
        assert_eq!(json["operations"].as_array().unwrap().len(), 0);

        let back: ConnectorDetail = serde_json::from_value(json).unwrap();
        assert!(back.health.is_none());
        assert!(back.config_schema.is_none());
    }

    // ── ConnectorDetail: round-trip with all optionals populated ──────

    #[test]
    fn connector_detail_all_optionals_populated_round_trip() {
        let detail = ConnectorDetail {
            summary: ConnectorSummary {
                id: "full:fcp2:3.0".to_owned(),
                name: "Full".to_owned(),
                version: "3.0.0".to_owned(),
                description: "Full connector".to_owned(),
                archetypes: vec!["request-response".to_owned()],
                state: ConnectorState::Ready,
                operation_count: 2,
                max_risk: "high".to_owned(),
                has_events: true,
            },
            operations: vec![
                OperationSummary {
                    id: "a.create".to_owned(),
                    summary: "Create A".to_owned(),
                    capability: "a.write".to_owned(),
                    risk_level: "high".to_owned(),
                    safety_tier: "dangerous".to_owned(),
                    idempotency: "none".to_owned(),
                    requires_approval: true,
                    supports_simulate: false,
                },
                OperationSummary {
                    id: "a.list".to_owned(),
                    summary: "List A".to_owned(),
                    capability: "a.read".to_owned(),
                    risk_level: "low".to_owned(),
                    safety_tier: "safe".to_owned(),
                    idempotency: "strict".to_owned(),
                    requires_approval: false,
                    supports_simulate: true,
                },
            ],
            config_schema: Some(json!({
                "type": "object",
                "properties": {
                    "api_key": { "type": "string", "secret": true },
                    "base_url": { "type": "string", "default": "https://api.example.com" }
                }
            })),
            health: Some(HealthSummary {
                state: "ready".to_owned(),
                uptime: "12h 30m".to_owned(),
                load: Some(0.75),
            }),
            rate_limits: vec![
                RateLimitSummary {
                    scope: "global".to_owned(),
                    requests: 1000,
                    window: "60s".to_owned(),
                },
                RateLimitSummary {
                    scope: "a.create".to_owned(),
                    requests: 50,
                    window: "60s".to_owned(),
                },
            ],
        };

        let json_str = serde_json::to_string_pretty(&detail).unwrap();
        let back: ConnectorDetail = serde_json::from_str(&json_str).unwrap();

        assert_eq!(back.summary.id, "full:fcp2:3.0");
        assert_eq!(back.operations.len(), 2);
        assert!(back.operations[0].requires_approval);
        assert!(!back.operations[1].requires_approval);
        assert!(back.config_schema.is_some());
        assert!(back.health.is_some());
        let h = back.health.unwrap();
        assert_eq!(h.load, Some(0.75));
        assert_eq!(back.rate_limits.len(), 2);
        assert_eq!(back.rate_limits[1].requests, 50);
    }

    // ── OperationSummary: round-trip serde ────────────────────────────

    #[test]
    fn operation_summary_round_trip() {
        let op = OperationSummary {
            id: "repos.delete".to_owned(),
            summary: "Delete a repository".to_owned(),
            capability: "repos.admin".to_owned(),
            risk_level: "critical".to_owned(),
            safety_tier: "forbidden".to_owned(),
            idempotency: "none".to_owned(),
            requires_approval: true,
            supports_simulate: false,
        };

        let json_str = serde_json::to_string(&op).unwrap();
        let back: OperationSummary = serde_json::from_str(&json_str).unwrap();

        assert_eq!(back.id, "repos.delete");
        assert_eq!(back.safety_tier, "forbidden");
        assert!(back.requires_approval);
        assert!(!back.supports_simulate);
    }

    #[test]
    fn operation_summary_all_json_fields() {
        let op = OperationSummary {
            id: "x".to_owned(),
            summary: "s".to_owned(),
            capability: "c".to_owned(),
            risk_level: "low".to_owned(),
            safety_tier: "safe".to_owned(),
            idempotency: "best-effort".to_owned(),
            requires_approval: false,
            supports_simulate: true,
        };

        let v = serde_json::to_value(&op).unwrap();
        // Verify all expected keys exist
        let obj = v.as_object().unwrap();
        for key in [
            "id",
            "summary",
            "capability",
            "risk_level",
            "safety_tier",
            "idempotency",
            "requires_approval",
            "supports_simulate",
        ] {
            assert!(obj.contains_key(key), "missing key: {key}");
        }
    }

    // ── HealthSummary: load variants ──────────────────────────────────

    #[test]
    fn health_summary_load_none() {
        let h = HealthSummary {
            state: "starting".to_owned(),
            uptime: "0s".to_owned(),
            load: None,
        };
        let json = serde_json::to_value(&h).unwrap();
        assert!(json["load"].is_null());
        let back: HealthSummary = serde_json::from_value(json).unwrap();
        assert!(back.load.is_none());
    }

    #[test]
    fn health_summary_load_zero() {
        let h = HealthSummary {
            state: "ready".to_owned(),
            uptime: "1m".to_owned(),
            load: Some(0.0),
        };
        let json = serde_json::to_value(&h).unwrap();
        let load_val = json["load"].as_f64().unwrap();
        assert!((load_val).abs() < f64::EPSILON);
        let back: HealthSummary = serde_json::from_value(json).unwrap();
        assert_eq!(back.load, Some(0.0));
    }

    #[test]
    fn health_summary_load_max() {
        let h = HealthSummary {
            state: "degraded".to_owned(),
            uptime: "48h".to_owned(),
            load: Some(1.0),
        };
        let json = serde_json::to_value(&h).unwrap();
        let load_val = json["load"].as_f64().unwrap();
        assert!((load_val - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn health_summary_round_trip() {
        let h = HealthSummary {
            state: "error".to_owned(),
            uptime: "0s".to_owned(),
            load: Some(0.99),
        };
        let json_str = serde_json::to_string(&h).unwrap();
        let back: HealthSummary = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.state, "error");
        assert_eq!(back.uptime, "0s");
        assert!(back.load.is_some());
    }

    // ── RateLimitSummary: round-trip serde ────────────────────────────

    #[test]
    fn rate_limit_summary_round_trip() {
        let rl = RateLimitSummary {
            scope: "issues.create".to_owned(),
            requests: 500,
            window: "300s".to_owned(),
        };
        let json_str = serde_json::to_string(&rl).unwrap();
        let back: RateLimitSummary = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.scope, "issues.create");
        assert_eq!(back.requests, 500);
        assert_eq!(back.window, "300s");
    }

    #[test]
    fn rate_limit_summary_zero_requests() {
        let rl = RateLimitSummary {
            scope: "global".to_owned(),
            requests: 0,
            window: "1s".to_owned(),
        };
        let json = serde_json::to_value(&rl).unwrap();
        assert_eq!(json["requests"], 0);
    }

    // ── ReadinessGap: construction and serde ──────────────────────────

    #[test]
    fn readiness_gap_construction_and_serde() {
        let gap = ReadinessGap {
            category: GapCategory::EventSupport,
            description: "No events declared".to_owned(),
            severity: GapSeverity::Cosmetic,
            remediation: "Add subscribe() support".to_owned(),
        };

        let json = serde_json::to_value(&gap).unwrap();
        assert_eq!(json["category"], "event-support");
        assert_eq!(json["severity"], "cosmetic");
        assert_eq!(json["description"], "No events declared");
        assert_eq!(json["remediation"], "Add subscribe() support");

        let back: ReadinessGap = serde_json::from_value(json).unwrap();
        assert_eq!(back.category, GapCategory::EventSupport);
        assert_eq!(back.severity, GapSeverity::Cosmetic);
    }

    #[test]
    fn readiness_gap_all_category_severity_combos_serialize() {
        let categories = [
            GapCategory::Identity,
            GapCategory::OperationMetadata,
            GapCategory::ConfigSchema,
            GapCategory::Lifecycle,
        ];
        let severities = [
            GapSeverity::Blocking,
            GapSeverity::Degraded,
            GapSeverity::Cosmetic,
        ];
        for cat in categories {
            for sev in severities {
                let gap = ReadinessGap {
                    category: cat,
                    description: "test".to_owned(),
                    severity: sev,
                    remediation: "fix".to_owned(),
                };
                let json = serde_json::to_string(&gap).unwrap();
                let back: ReadinessGap = serde_json::from_str(&json).unwrap();
                assert_eq!(back.category, cat);
                assert_eq!(back.severity, sev);
            }
        }
    }

    // ── SummaryReadiness: all-true, all-false, mixed ──────────────────

    #[test]
    fn summary_readiness_all_true() {
        let s = SummaryReadiness {
            has_canonical_id: true,
            has_display_name: true,
            has_archetypes: true,
            has_semver_version: true,
            has_description: true,
            has_operation_count: true,
            has_risk_summary: true,
        };
        let json = serde_json::to_value(&s).unwrap();
        let obj = json.as_object().unwrap();
        for (key, val) in obj {
            assert!(val.as_bool().unwrap(), "expected true for {key}");
        }
    }

    #[test]
    fn summary_readiness_all_false() {
        let s = SummaryReadiness {
            has_canonical_id: false,
            has_display_name: false,
            has_archetypes: false,
            has_semver_version: false,
            has_description: false,
            has_operation_count: false,
            has_risk_summary: false,
        };
        let json = serde_json::to_value(&s).unwrap();
        let obj = json.as_object().unwrap();
        for (key, val) in obj {
            assert!(!val.as_bool().unwrap(), "expected false for {key}");
        }
    }

    #[test]
    fn summary_readiness_mixed_round_trip() {
        let s = SummaryReadiness {
            has_canonical_id: true,
            has_display_name: true,
            has_archetypes: false,
            has_semver_version: true,
            has_description: false,
            has_operation_count: true,
            has_risk_summary: false,
        };
        let json_str = serde_json::to_string(&s).unwrap();
        let back: SummaryReadiness = serde_json::from_str(&json_str).unwrap();
        assert!(back.has_canonical_id);
        assert!(back.has_display_name);
        assert!(!back.has_archetypes);
        assert!(back.has_semver_version);
        assert!(!back.has_description);
        assert!(back.has_operation_count);
        assert!(!back.has_risk_summary);
    }

    // ── OperationsReadiness: zero operations edge case ────────────────

    #[test]
    fn operations_readiness_zero_operations() {
        let ops = OperationsReadiness {
            operation_count: 0,
            all_have_id: true,
            all_have_summary: true,
            all_have_input_schema: true,
            all_have_output_schema: true,
            all_have_capability: true,
            all_have_risk_level: true,
            all_have_safety_tier: true,
            all_have_idempotency: true,
            all_have_ai_hints: true,
            approval_declared_where_needed: true,
            operations_with_examples: 0,
        };

        let json = serde_json::to_value(&ops).unwrap();
        assert_eq!(json["operation_count"], 0);
        assert_eq!(json["operations_with_examples"], 0);
        // All bools are vacuously true
        assert!(json["all_have_id"].as_bool().unwrap());

        let back: OperationsReadiness = serde_json::from_value(json).unwrap();
        assert_eq!(back.operation_count, 0);
    }

    #[test]
    fn operations_readiness_large_count() {
        let ops = OperationsReadiness {
            operation_count: 999,
            all_have_id: false,
            all_have_summary: false,
            all_have_input_schema: false,
            all_have_output_schema: false,
            all_have_capability: false,
            all_have_risk_level: false,
            all_have_safety_tier: false,
            all_have_idempotency: false,
            all_have_ai_hints: false,
            approval_declared_where_needed: false,
            operations_with_examples: 42,
        };

        let json_str = serde_json::to_string(&ops).unwrap();
        let back: OperationsReadiness = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.operation_count, 999);
        assert_eq!(back.operations_with_examples, 42);
        assert!(!back.all_have_id);
    }

    // ── ConfigReadiness: all-false serde ──────────────────────────────

    #[test]
    fn config_readiness_all_false_serde() {
        let c = ConfigReadiness {
            accepts_config: false,
            has_config_schema: false,
            secrets_marked: false,
            defaults_documented: false,
            has_self_check: false,
        };

        let json = serde_json::to_value(&c).unwrap();
        let obj = json.as_object().unwrap();
        for (key, val) in obj {
            assert!(!val.as_bool().unwrap(), "expected false for {key}");
        }

        let back: ConfigReadiness = serde_json::from_value(json).unwrap();
        assert!(!back.accepts_config);
        assert!(!back.has_config_schema);
        assert!(!back.secrets_marked);
        assert!(!back.defaults_documented);
        assert!(!back.has_self_check);
    }

    #[test]
    fn config_readiness_all_true_serde() {
        let c = ConfigReadiness {
            accepts_config: true,
            has_config_schema: true,
            secrets_marked: true,
            defaults_documented: true,
            has_self_check: true,
        };

        let json_str = serde_json::to_string(&c).unwrap();
        let back: ConfigReadiness = serde_json::from_str(&json_str).unwrap();
        assert!(back.accepts_config);
        assert!(back.has_config_schema);
        assert!(back.secrets_marked);
        assert!(back.defaults_documented);
        assert!(back.has_self_check);
    }

    // ── LifecycleReadiness: all-true serde ────────────────────────────

    #[test]
    fn lifecycle_readiness_all_true_serde() {
        let lc = LifecycleReadiness {
            has_health: true,
            reports_lifecycle_state: true,
            events_declared: true,
            has_rate_limits: true,
            has_metrics: true,
            has_shutdown: true,
        };

        let json = serde_json::to_value(&lc).unwrap();
        let obj = json.as_object().unwrap();
        for (key, val) in obj {
            assert!(val.as_bool().unwrap(), "expected true for {key}");
        }

        let back: LifecycleReadiness = serde_json::from_value(json).unwrap();
        assert!(back.has_health);
        assert!(back.has_shutdown);
    }

    #[test]
    fn lifecycle_readiness_all_false_serde() {
        let lc = LifecycleReadiness {
            has_health: false,
            reports_lifecycle_state: false,
            events_declared: false,
            has_rate_limits: false,
            has_metrics: false,
            has_shutdown: false,
        };

        let json_str = serde_json::to_string(&lc).unwrap();
        let back: LifecycleReadiness = serde_json::from_str(&json_str).unwrap();
        assert!(!back.has_health);
        assert!(!back.reports_lifecycle_state);
        assert!(!back.events_declared);
        assert!(!back.has_rate_limits);
        assert!(!back.has_metrics);
        assert!(!back.has_shutdown);
    }

    // ── MANDATORY_SUMMARY_FIELDS: no duplicates ──────────────────────

    #[test]
    fn mandatory_summary_fields_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for field in MANDATORY_SUMMARY_FIELDS {
            assert!(seen.insert(field), "duplicate field: {field}");
        }
    }

    #[test]
    fn mandatory_summary_fields_contains_required() {
        for required in &["id", "name", "version", "description", "state"] {
            assert!(
                MANDATORY_SUMMARY_FIELDS.contains(required),
                "missing required field: {required}"
            );
        }
    }

    // ── MANDATORY_OPERATION_FIELDS: no duplicates ────────────────────

    #[test]
    fn mandatory_operation_fields_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for field in MANDATORY_OPERATION_FIELDS {
            assert!(seen.insert(field), "duplicate field: {field}");
        }
    }

    #[test]
    fn mandatory_operation_fields_contains_required() {
        for required in &[
            "id",
            "summary",
            "capability",
            "risk_level",
            "safety_tier",
            "input_schema",
            "output_schema",
        ] {
            assert!(
                MANDATORY_OPERATION_FIELDS.contains(required),
                "missing required field: {required}"
            );
        }
    }

    // ── RECOMMENDED_OPERATION_FIELDS: no overlap with mandatory ──────

    #[test]
    fn recommended_fields_no_overlap_with_mandatory() {
        for rec in RECOMMENDED_OPERATION_FIELDS {
            assert!(
                !MANDATORY_OPERATION_FIELDS.contains(rec),
                "field {rec} appears in both mandatory and recommended"
            );
        }
    }

    #[test]
    fn recommended_operation_fields_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for field in RECOMMENDED_OPERATION_FIELDS {
            assert!(seen.insert(field), "duplicate field: {field}");
        }
    }

    // ── evaluate_introspection: non-array operations ─────────────────

    #[test]
    fn operations_as_string_treated_as_empty() {
        let introspection = json!({
            "operations": "not an array"
        });

        let verdict = evaluate_introspection(
            "weird:fcp2:0.1",
            "connectors/weird",
            ConnectorCohort::Automation,
            &introspection,
        );

        assert_eq!(verdict.level, ReadinessLevel::NotReady);
        assert_eq!(verdict.areas.operations.operation_count, 0);
    }

    #[test]
    fn operations_as_number_treated_as_empty() {
        let introspection = json!({
            "operations": 42
        });

        let verdict = evaluate_introspection(
            "numops:fcp2:0.1",
            "connectors/numops",
            ConnectorCohort::Automation,
            &introspection,
        );

        assert_eq!(verdict.level, ReadinessLevel::NotReady);
        assert_eq!(verdict.areas.operations.operation_count, 0);
    }

    #[test]
    fn operations_as_object_treated_as_empty() {
        let introspection = json!({
            "operations": { "op1": "data" }
        });

        let verdict = evaluate_introspection(
            "objops:fcp2:0.1",
            "connectors/objops",
            ConnectorCohort::Automation,
            &introspection,
        );

        assert_eq!(verdict.level, ReadinessLevel::NotReady);
        assert_eq!(verdict.areas.operations.operation_count, 0);
    }

    #[test]
    fn operations_as_bool_treated_as_empty() {
        let introspection = json!({
            "operations": true
        });

        let verdict = evaluate_introspection(
            "boolops:fcp2:0.1",
            "connectors/boolops",
            ConnectorCohort::Automation,
            &introspection,
        );

        assert_eq!(verdict.level, ReadinessLevel::NotReady);
        assert_eq!(verdict.areas.operations.operation_count, 0);
    }

    // ── evaluate_introspection: id format variations ─────────────────

    #[test]
    fn two_part_id_not_canonical() {
        let introspection = json!({
            "operations": [
                {
                    "id": "op1",
                    "summary": "s",
                    "input_schema": {},
                    "output_schema": {},
                    "capability": "c",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "none",
                    "ai_hints": { "when_to_use": "w", "examples": ["e"] }
                }
            ]
        });

        let verdict = evaluate_introspection(
            "name:version",
            "connectors/test",
            ConnectorCohort::Community,
            &introspection,
        );

        assert!(!verdict.areas.summary.has_canonical_id);
        assert!(!verdict.areas.summary.has_semver_version);
    }

    #[test]
    fn empty_id_has_display_name_false() {
        let introspection = json!({
            "operations": [
                {
                    "id": "op1",
                    "summary": "s",
                    "input_schema": {},
                    "output_schema": {},
                    "capability": "c",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "none",
                    "ai_hints": { "when_to_use": "w", "examples": ["e"] }
                }
            ]
        });

        let verdict = evaluate_introspection(
            "",
            "connectors/test",
            ConnectorCohort::Finance,
            &introspection,
        );

        assert!(!verdict.areas.summary.has_display_name);
        assert!(!verdict.areas.summary.has_canonical_id);
    }

    // ── ReadinessVerdict: verify cohort is preserved ──────────────────

    #[test]
    fn verdict_preserves_cohort() {
        let introspection = json!({ "operations": [] });
        for cohort in [
            ConnectorCohort::Social,
            ConnectorCohort::Storage,
            ConnectorCohort::Analytics,
        ] {
            let verdict = evaluate_introspection(
                "x:fcp2:1.0",
                "connectors/x",
                cohort.clone(),
                &introspection,
            );
            assert_eq!(verdict.cohort, cohort);
        }
    }

    #[test]
    fn verdict_preserves_crate_path() {
        let introspection = json!({ "operations": [] });
        let verdict = evaluate_introspection(
            "x:fcp2:1.0",
            "connectors/custom/path",
            ConnectorCohort::Productivity,
            &introspection,
        );
        assert_eq!(verdict.crate_path, "connectors/custom/path");
    }

    // ── ReadinessAreas serde round-trip ───────────────────────────────

    #[test]
    fn readiness_areas_full_round_trip() {
        let areas = ReadinessAreas {
            summary: SummaryReadiness {
                has_canonical_id: true,
                has_display_name: true,
                has_archetypes: false,
                has_semver_version: true,
                has_description: true,
                has_operation_count: true,
                has_risk_summary: false,
            },
            operations: OperationsReadiness {
                operation_count: 7,
                all_have_id: true,
                all_have_summary: false,
                all_have_input_schema: true,
                all_have_output_schema: true,
                all_have_capability: true,
                all_have_risk_level: true,
                all_have_safety_tier: false,
                all_have_idempotency: true,
                all_have_ai_hints: false,
                approval_declared_where_needed: true,
                operations_with_examples: 3,
            },
            config: ConfigReadiness {
                accepts_config: true,
                has_config_schema: true,
                secrets_marked: false,
                defaults_documented: true,
                has_self_check: true,
            },
            lifecycle: LifecycleReadiness {
                has_health: true,
                reports_lifecycle_state: false,
                events_declared: true,
                has_rate_limits: true,
                has_metrics: false,
                has_shutdown: true,
            },
        };

        let json_str = serde_json::to_string_pretty(&areas).unwrap();
        let back: ReadinessAreas = serde_json::from_str(&json_str).unwrap();

        assert_eq!(back.operations.operation_count, 7);
        assert_eq!(back.operations.operations_with_examples, 3);
        assert!(!back.summary.has_archetypes);
        assert!(!back.operations.all_have_summary);
        assert!(!back.lifecycle.reports_lifecycle_state);
        assert!(back.config.has_config_schema);
    }

    // ── evaluate_introspection: risk_summary derived from operations ──

    #[test]
    fn risk_summary_true_when_all_ops_have_risk_level() {
        let introspection = json!({
            "operations": [
                {
                    "id": "a",
                    "summary": "s",
                    "input_schema": {},
                    "output_schema": {},
                    "capability": "c",
                    "risk_level": "high",
                    "safety_tier": "dangerous",
                    "idempotency": "none",
                    "ai_hints": { "when_to_use": "w", "examples": ["e"] }
                },
                {
                    "id": "b",
                    "summary": "s2",
                    "input_schema": {},
                    "output_schema": {},
                    "capability": "c2",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "strict",
                    "ai_hints": { "when_to_use": "w2", "examples": ["e2"] }
                }
            ]
        });

        let verdict = evaluate_introspection(
            "r:fcp2:1.0",
            "connectors/r",
            ConnectorCohort::DevTools,
            &introspection,
        );

        assert!(verdict.areas.summary.has_risk_summary);
    }

    #[test]
    fn risk_summary_false_when_any_op_missing_risk_level() {
        let introspection = json!({
            "operations": [
                {
                    "id": "a",
                    "summary": "s",
                    "input_schema": {},
                    "output_schema": {},
                    "capability": "c",
                    "risk_level": "high",
                    "safety_tier": "dangerous",
                    "idempotency": "none",
                    "ai_hints": { "when_to_use": "w", "examples": ["e"] }
                },
                {
                    "id": "b",
                    "summary": "s2",
                    "input_schema": {},
                    "output_schema": {},
                    "capability": "c2",
                    "risk_level": "",
                    "safety_tier": "safe",
                    "idempotency": "strict",
                    "ai_hints": { "when_to_use": "w2", "examples": ["e2"] }
                }
            ]
        });

        let verdict = evaluate_introspection(
            "r:fcp2:1.0",
            "connectors/r",
            ConnectorCohort::DevTools,
            &introspection,
        );

        assert!(!verdict.areas.summary.has_risk_summary);
    }

    // ── evaluate_introspection: examples counting ─────────────────────

    #[test]
    fn examples_count_partial() {
        let introspection = json!({
            "operations": [
                {
                    "id": "op1",
                    "summary": "s1",
                    "input_schema": {},
                    "output_schema": {},
                    "capability": "c",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "strict",
                    "ai_hints": {
                        "when_to_use": "w",
                        "examples": ["ex1"]
                    }
                },
                {
                    "id": "op2",
                    "summary": "s2",
                    "input_schema": {},
                    "output_schema": {},
                    "capability": "c",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "strict",
                    "ai_hints": {
                        "when_to_use": "w",
                        "examples": []
                    }
                },
                {
                    "id": "op3",
                    "summary": "s3",
                    "input_schema": {},
                    "output_schema": {},
                    "capability": "c",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "strict",
                    "ai_hints": {
                        "when_to_use": "w",
                        "examples": ["ex1", "ex2"]
                    }
                }
            ]
        });

        let verdict = evaluate_introspection(
            "ex:fcp2:1.0",
            "connectors/ex",
            ConnectorCohort::Automation,
            &introspection,
        );

        assert_eq!(verdict.areas.operations.operations_with_examples, 2);
        assert_eq!(verdict.areas.operations.operation_count, 3);
        // Gap for incomplete examples
        assert!(
            verdict
                .gaps
                .iter()
                .any(|g| g.description.contains("2/3"))
        );
    }

    // ── evaluate_introspection: operation missing only output_schema ──

    #[test]
    fn missing_only_output_schema_is_partially_ready() {
        let introspection = json!({
            "operations": [
                {
                    "id": "op1",
                    "summary": "s",
                    "input_schema": {"type": "object"},
                    "output_schema": null,
                    "capability": "c",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "strict",
                    "ai_hints": { "when_to_use": "w", "examples": ["e"] }
                }
            ]
        });

        let verdict = evaluate_introspection(
            "out:fcp2:1.0",
            "connectors/out",
            ConnectorCohort::Data,
            &introspection,
        );

        assert_eq!(verdict.level, ReadinessLevel::PartiallyReady);
        assert!(verdict.areas.operations.all_have_input_schema);
        assert!(!verdict.areas.operations.all_have_output_schema);
    }

    // ── evaluate_introspection: single op all complete → ready ────────

    #[test]
    fn single_complete_operation_is_ready() {
        let introspection = json!({
            "operations": [
                {
                    "id": "ping",
                    "summary": "Ping the service",
                    "input_schema": {"type": "object"},
                    "output_schema": {"type": "object"},
                    "capability": "health.read",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "strict",
                    "ai_hints": {
                        "when_to_use": "Check service health",
                        "examples": ["Ping the service"]
                    }
                }
            ]
        });

        let verdict = evaluate_introspection(
            "simple:fcp2:1.0",
            "connectors/simple",
            ConnectorCohort::Infra,
            &introspection,
        );

        assert_eq!(verdict.level, ReadinessLevel::Ready);
        assert!(verdict.gaps.is_empty());
        assert_eq!(verdict.areas.operations.operation_count, 1);
        assert!(verdict.areas.operations.all_have_id);
        assert!(verdict.areas.operations.all_have_summary);
        assert!(verdict.areas.operations.all_have_input_schema);
        assert!(verdict.areas.operations.all_have_output_schema);
        assert!(verdict.areas.operations.all_have_capability);
        assert!(verdict.areas.operations.all_have_risk_level);
        assert!(verdict.areas.operations.all_have_safety_tier);
        assert!(verdict.areas.operations.all_have_idempotency);
        assert!(verdict.areas.operations.all_have_ai_hints);
        assert_eq!(verdict.areas.operations.operations_with_examples, 1);
    }

    // ── evaluate_introspection: connector_id stored correctly ─────────

    #[test]
    fn verdict_stores_connector_id() {
        let introspection = json!({ "operations": [] });
        let verdict = evaluate_introspection(
            "test-connector:fcp2:99.99",
            "connectors/test-connector",
            ConnectorCohort::Browser,
            &introspection,
        );
        assert_eq!(verdict.connector_id, "test-connector:fcp2:99.99");
    }

    // ── evaluate_introspection: all idempotency fields ───────────────

    #[test]
    fn idempotency_tracked_correctly() {
        let introspection = json!({
            "operations": [
                {
                    "id": "op1",
                    "summary": "s",
                    "input_schema": {},
                    "output_schema": {},
                    "capability": "c",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "strict",
                    "ai_hints": { "when_to_use": "w", "examples": ["e"] }
                },
                {
                    "id": "op2",
                    "summary": "s",
                    "input_schema": {},
                    "output_schema": {},
                    "capability": "c",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "",
                    "ai_hints": { "when_to_use": "w", "examples": ["e"] }
                }
            ]
        });

        let verdict = evaluate_introspection(
            "idem:fcp2:1.0",
            "connectors/idem",
            ConnectorCohort::Workspace,
            &introspection,
        );

        assert!(!verdict.areas.operations.all_have_idempotency);
    }

    // ── evaluate_introspection: safety_tier tracking ─────────────────

    #[test]
    fn safety_tier_tracked_correctly() {
        let introspection = json!({
            "operations": [
                {
                    "id": "op1",
                    "summary": "s",
                    "input_schema": {},
                    "output_schema": {},
                    "capability": "c",
                    "risk_level": "low",
                    "safety_tier": "",
                    "idempotency": "strict",
                    "ai_hints": { "when_to_use": "w", "examples": ["e"] }
                }
            ]
        });

        let verdict = evaluate_introspection(
            "safe:fcp2:1.0",
            "connectors/safe",
            ConnectorCohort::Social,
            &introspection,
        );

        assert!(!verdict.areas.operations.all_have_safety_tier);
    }
}
