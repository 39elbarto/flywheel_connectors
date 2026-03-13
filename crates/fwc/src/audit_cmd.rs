//! Audit command family wiring for connector compliance.
//!
//! Provides the `fwc audit` command family: per-connector and fleet-wide
//! compliance auditing, gap detection with severity filtering, and compliance
//! checks against FCP standards. All output functions produce TOON-formatted
//! `Vec<String>` for consistent CLI rendering.

use serde::{Deserialize, Serialize};

use crate::audit::{AuditMatrix, ConnectorAudit};
use crate::readiness::GapSeverity;

// ── Argument types ──────────────────────────────────────────────────────

/// Arguments for `fwc audit`.
#[derive(Clone, Debug)]
pub struct AuditArgs {
    /// Filter to a specific connector (by name or ID).
    pub connector: Option<String>,
    /// Only show connectors with gaps.
    pub gaps_only: bool,
    /// Show verbose detail.
    pub verbose: bool,
    /// Output format: "text" or "json".
    pub format: OutputFormat,
}

/// Arguments for `fwc audit gaps`.
#[derive(Clone, Debug)]
pub struct AuditGapsArgs {
    /// Filter to a specific connector (by name or ID).
    pub connector: Option<String>,
    /// Minimum severity to include (blocking, degraded, cosmetic).
    pub severity_threshold: SeverityThreshold,
    /// Include gaps that are marked as planned remediation.
    pub include_planned: bool,
}

/// Arguments for `fwc audit compliance`.
#[derive(Clone, Debug)]
pub struct AuditComplianceArgs {
    /// Connector to check.
    pub connector: String,
    /// Standard to check against (e.g., "fcp2", "fcp3").
    pub standard: String,
    /// Level of detail: "summary", "detailed", "full".
    pub detail_level: DetailLevel,
}

/// Output format selection.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
}

/// Severity threshold for gap filtering.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeverityThreshold {
    /// Show all gaps.
    #[default]
    All,
    /// Show only degraded and blocking.
    Degraded,
    /// Show only blocking.
    Blocking,
}

/// Detail level for compliance output.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetailLevel {
    #[default]
    Summary,
    Detailed,
    Full,
}

// ── Result types ────────────────────────────────────────────────────────

/// Full audit result for a connector.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditResult {
    /// Connector name.
    pub connector: String,
    /// Matrix entry keys (capability area names).
    pub matrix_entries: Vec<MatrixEntry>,
    /// Compliance score (0.0 - 1.0).
    pub compliance_score: f64,
    /// Gaps found during audit.
    pub gaps: Vec<GapEntry>,
    /// Actionable recommendations.
    pub recommendations: Vec<String>,
}

/// A single capability area in the audit matrix.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MatrixEntry {
    /// Capability area name (e.g. "operations", "`agent_hints`", "network").
    pub area: String,
    /// Coverage ratio (0.0 - 1.0).
    pub coverage: f64,
    /// Whether this area passes the threshold.
    pub passing: bool,
}

/// A single gap entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GapEntry {
    /// Connector where the gap was found.
    pub connector: String,
    /// Capability that is missing or incomplete.
    pub capability: String,
    /// Gap severity.
    pub severity: GapEntrySeverity,
    /// Suggested remediation.
    pub remediation: String,
    /// Whether a fix is planned.
    pub planned: bool,
}

/// Severity levels for gap entries (mirrors `GapSeverity` but is self-contained).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapEntrySeverity {
    Blocking,
    Degraded,
    Cosmetic,
}

impl GapEntrySeverity {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Blocking => "BLOCKING",
            Self::Degraded => "DEGRADED",
            Self::Cosmetic => "COSMETIC",
        }
    }

    /// Convert from the readiness module's severity.
    pub const fn from_gap_severity(sev: GapSeverity) -> Self {
        match sev {
            GapSeverity::Blocking => Self::Blocking,
            GapSeverity::Degraded => Self::Degraded,
            GapSeverity::Cosmetic => Self::Cosmetic,
        }
    }
}

/// Compliance check entry for a single requirement.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComplianceEntry {
    /// Standard being checked (e.g., "fcp2").
    pub standard: String,
    /// Requirement identifier (e.g., "FCP2-OPS-001").
    pub requirement: String,
    /// Human-readable requirement description.
    pub description: String,
    /// Pass/fail/partial/NA status.
    pub status: ComplianceStatus,
    /// Evidence supporting the status determination.
    pub evidence: String,
}

/// Compliance status for a requirement check.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceStatus {
    Pass,
    Fail,
    Partial,
    NotApplicable,
}

impl ComplianceStatus {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Partial => "PARTIAL",
            Self::NotApplicable => "N/A",
        }
    }

    pub const fn symbol(self) -> &'static str {
        match self {
            Self::Pass => "[+]",
            Self::Fail => "[-]",
            Self::Partial => "[~]",
            Self::NotApplicable => "[.]",
        }
    }
}

/// Aggregate audit summary across the fleet.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AuditSummary {
    /// Total connectors in the workspace.
    pub total_connectors: usize,
    /// Number of connectors audited.
    pub audited: usize,
    /// Number that pass compliance.
    pub passed: usize,
    /// Number that fail compliance.
    pub failed: usize,
    /// Total gaps found across all connectors.
    pub gap_count: usize,
}

/// Full compliance report for a connector against a standard.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComplianceReport {
    /// Connector being checked.
    pub connector: String,
    /// Standard checked against.
    pub standard: String,
    /// Individual requirement entries.
    pub entries: Vec<ComplianceEntry>,
    /// Overall pass rate (0.0 - 1.0).
    pub pass_rate: f64,
    /// Overall verdict.
    pub verdict: ComplianceStatus,
}

// ── Known standards ─────────────────────────────────────────────────────

/// FCP compliance standard definitions.
struct StandardDef {
    id: &'static str,
    requirements: &'static [RequirementDef],
}

struct RequirementDef {
    id: &'static str,
    description: &'static str,
    check: fn(&ConnectorAudit) -> ComplianceStatus,
    evidence: fn(&ConnectorAudit) -> String,
}

const FCP2_REQUIREMENTS: &[RequirementDef] = &[
    RequirementDef {
        id: "FCP2-OPS-001",
        description: "All operations must have descriptions",
        check: |a| {
            if a.operations.count == 0 {
                ComplianceStatus::NotApplicable
            } else if a.operations.with_description == a.operations.count {
                ComplianceStatus::Pass
            } else if a.operations.with_description > 0 {
                ComplianceStatus::Partial
            } else {
                ComplianceStatus::Fail
            }
        },
        evidence: |a| {
            format!(
                "{}/{} operations have descriptions",
                a.operations.with_description, a.operations.count
            )
        },
    },
    RequirementDef {
        id: "FCP2-OPS-002",
        description: "All operations must declare capabilities",
        check: |a| {
            if a.operations.count == 0 {
                ComplianceStatus::NotApplicable
            } else if a.operations.with_capability == a.operations.count {
                ComplianceStatus::Pass
            } else if a.operations.with_capability > 0 {
                ComplianceStatus::Partial
            } else {
                ComplianceStatus::Fail
            }
        },
        evidence: |a| {
            format!(
                "{}/{} operations declare capability",
                a.operations.with_capability, a.operations.count
            )
        },
    },
    RequirementDef {
        id: "FCP2-OPS-003",
        description: "Operations must have input schema properties",
        check: |a| {
            if a.operations.count == 0 {
                ComplianceStatus::NotApplicable
            } else if a.operations.with_input_properties == a.operations.count {
                ComplianceStatus::Pass
            } else if a.operations.with_input_properties > 0 {
                ComplianceStatus::Partial
            } else {
                ComplianceStatus::Fail
            }
        },
        evidence: |a| {
            format!(
                "{}/{} operations have input schema",
                a.operations.with_input_properties, a.operations.count
            )
        },
    },
    RequirementDef {
        id: "FCP2-SAFETY-001",
        description: "Operations must declare risk_level",
        check: |a| {
            if a.operations.count == 0 {
                ComplianceStatus::NotApplicable
            } else if a.operations.with_risk_level == a.operations.count {
                ComplianceStatus::Pass
            } else if a.operations.with_risk_level > 0 {
                ComplianceStatus::Partial
            } else {
                ComplianceStatus::Fail
            }
        },
        evidence: |a| {
            format!(
                "{}/{} operations declare risk_level",
                a.operations.with_risk_level, a.operations.count
            )
        },
    },
    RequirementDef {
        id: "FCP2-SAFETY-002",
        description: "Operations must declare safety_tier",
        check: |a| {
            if a.operations.count == 0 {
                ComplianceStatus::NotApplicable
            } else if a.operations.with_safety_tier == a.operations.count {
                ComplianceStatus::Pass
            } else if a.operations.with_safety_tier > 0 {
                ComplianceStatus::Partial
            } else {
                ComplianceStatus::Fail
            }
        },
        evidence: |a| {
            format!(
                "{}/{} operations declare safety_tier",
                a.operations.with_safety_tier, a.operations.count
            )
        },
    },
    RequirementDef {
        id: "FCP2-HINTS-001",
        description: "Agent hints coverage must exceed 80%",
        check: |a| {
            if a.operations.count == 0 {
                ComplianceStatus::NotApplicable
            } else if a.agent_hints.coverage >= 0.8 {
                ComplianceStatus::Pass
            } else if a.agent_hints.coverage >= 0.5 {
                ComplianceStatus::Partial
            } else {
                ComplianceStatus::Fail
            }
        },
        evidence: |a| format!("hint coverage: {:.0}%", a.agent_hints.coverage * 100.0),
    },
    RequirementDef {
        id: "FCP2-NET-001",
        description: "Network constraints should be declared",
        check: |a| {
            if a.operations.count == 0 {
                ComplianceStatus::NotApplicable
            } else if a.network.coverage >= 0.8 {
                ComplianceStatus::Pass
            } else if a.network.coverage >= 0.3 {
                ComplianceStatus::Partial
            } else {
                ComplianceStatus::Fail
            }
        },
        evidence: |a| {
            format!(
                "network constraint coverage: {:.0}%",
                a.network.coverage * 100.0
            )
        },
    },
    RequirementDef {
        id: "FCP2-ID-001",
        description: "Connector must have a manifest.toml",
        check: |a| {
            if a.has_manifest {
                ComplianceStatus::Pass
            } else {
                ComplianceStatus::Fail
            }
        },
        evidence: |a| {
            if a.has_manifest {
                "manifest.toml found".to_string()
            } else {
                "manifest.toml missing".to_string()
            }
        },
    },
];

const FCP3_REQUIREMENTS: &[RequirementDef] = &[
    RequirementDef {
        id: "FCP3-OPS-001",
        description: "All operations must have descriptions",
        check: |a| {
            if a.operations.count == 0 {
                ComplianceStatus::NotApplicable
            } else if a.operations.with_description == a.operations.count {
                ComplianceStatus::Pass
            } else {
                ComplianceStatus::Fail
            }
        },
        evidence: |a| {
            format!(
                "{}/{} operations have descriptions",
                a.operations.with_description, a.operations.count
            )
        },
    },
    RequirementDef {
        id: "FCP3-OPS-002",
        description: "All operations must declare capabilities",
        check: |a| {
            if a.operations.count == 0 {
                ComplianceStatus::NotApplicable
            } else if a.operations.with_capability == a.operations.count {
                ComplianceStatus::Pass
            } else {
                ComplianceStatus::Fail
            }
        },
        evidence: |a| {
            format!(
                "{}/{} operations declare capability",
                a.operations.with_capability, a.operations.count
            )
        },
    },
    RequirementDef {
        id: "FCP3-OPS-003",
        description: "All operations must have input and output schemas",
        check: |a| {
            if a.operations.count == 0 {
                ComplianceStatus::NotApplicable
            } else if a.operations.with_input_properties == a.operations.count
                && a.operations.with_output_schema == a.operations.count
            {
                ComplianceStatus::Pass
            } else if a.operations.with_input_properties > 0 || a.operations.with_output_schema > 0
            {
                ComplianceStatus::Partial
            } else {
                ComplianceStatus::Fail
            }
        },
        evidence: |a| {
            format!(
                "input: {}/{}, output: {}/{}",
                a.operations.with_input_properties,
                a.operations.count,
                a.operations.with_output_schema,
                a.operations.count
            )
        },
    },
    RequirementDef {
        id: "FCP3-SAFETY-001",
        description: "All operations must declare risk_level and safety_tier",
        check: |a| {
            if a.operations.count == 0 {
                ComplianceStatus::NotApplicable
            } else if a.operations.with_risk_level == a.operations.count
                && a.operations.with_safety_tier == a.operations.count
            {
                ComplianceStatus::Pass
            } else if a.operations.with_risk_level > 0 || a.operations.with_safety_tier > 0 {
                ComplianceStatus::Partial
            } else {
                ComplianceStatus::Fail
            }
        },
        evidence: |a| {
            format!(
                "risk: {}/{}, safety: {}/{}",
                a.operations.with_risk_level,
                a.operations.count,
                a.operations.with_safety_tier,
                a.operations.count
            )
        },
    },
    RequirementDef {
        id: "FCP3-SAFETY-002",
        description: "All operations must declare idempotency class",
        check: |a| {
            if a.operations.count == 0 {
                ComplianceStatus::NotApplicable
            } else if a.operations.with_idempotency == a.operations.count {
                ComplianceStatus::Pass
            } else if a.operations.with_idempotency > 0 {
                ComplianceStatus::Partial
            } else {
                ComplianceStatus::Fail
            }
        },
        evidence: |a| {
            format!(
                "{}/{} operations declare idempotency",
                a.operations.with_idempotency, a.operations.count
            )
        },
    },
    RequirementDef {
        id: "FCP3-HINTS-001",
        description: "Full agent hint coverage required (100%)",
        check: |a| {
            if a.operations.count == 0 {
                ComplianceStatus::NotApplicable
            } else if (a.agent_hints.coverage - 1.0).abs() < f64::EPSILON {
                ComplianceStatus::Pass
            } else if a.agent_hints.coverage >= 0.8 {
                ComplianceStatus::Partial
            } else {
                ComplianceStatus::Fail
            }
        },
        evidence: |a| format!("hint coverage: {:.0}%", a.agent_hints.coverage * 100.0),
    },
    RequirementDef {
        id: "FCP3-HINTS-002",
        description: "All hints must include when_to_use and examples",
        check: |a| {
            if a.operations.count == 0 {
                ComplianceStatus::NotApplicable
            } else if a.agent_hints.with_when_to_use == a.operations.count
                && a.agent_hints.with_examples == a.operations.count
            {
                ComplianceStatus::Pass
            } else if a.agent_hints.with_when_to_use > 0 || a.agent_hints.with_examples > 0 {
                ComplianceStatus::Partial
            } else {
                ComplianceStatus::Fail
            }
        },
        evidence: |a| {
            format!(
                "when_to_use: {}/{}, examples: {}/{}",
                a.agent_hints.with_when_to_use,
                a.operations.count,
                a.agent_hints.with_examples,
                a.operations.count
            )
        },
    },
    RequirementDef {
        id: "FCP3-NET-001",
        description: "All operations must have network constraints",
        check: |a| {
            if a.operations.count == 0 {
                ComplianceStatus::NotApplicable
            } else if (a.network.coverage - 1.0).abs() < f64::EPSILON {
                ComplianceStatus::Pass
            } else if a.network.coverage >= 0.5 {
                ComplianceStatus::Partial
            } else {
                ComplianceStatus::Fail
            }
        },
        evidence: |a| format!("network coverage: {:.0}%", a.network.coverage * 100.0),
    },
    RequirementDef {
        id: "FCP3-RATE-001",
        description: "Rate limit pools must be declared",
        check: |a| {
            if a.rate_limits.pool_count > 0 && a.rate_limits.has_operation_pools {
                ComplianceStatus::Pass
            } else if a.rate_limits.pool_count > 0 {
                ComplianceStatus::Partial
            } else {
                ComplianceStatus::Fail
            }
        },
        evidence: |a| {
            format!(
                "pools: {}, op_mappings: {}",
                a.rate_limits.pool_count, a.rate_limits.has_operation_pools
            )
        },
    },
    RequirementDef {
        id: "FCP3-ID-001",
        description: "Connector must have a valid connector_id",
        check: |a| {
            if a.connector_id.is_some() {
                ComplianceStatus::Pass
            } else if a.has_manifest {
                ComplianceStatus::Partial
            } else {
                ComplianceStatus::Fail
            }
        },
        evidence: |a| {
            a.connector_id.as_ref().map_or_else(
                || "connector_id missing".to_string(),
                |id| format!("connector_id: {id}"),
            )
        },
    },
];

const KNOWN_STANDARDS: &[StandardDef] = &[
    StandardDef {
        id: "fcp2",
        requirements: FCP2_REQUIREMENTS,
    },
    StandardDef {
        id: "fcp3",
        requirements: FCP3_REQUIREMENTS,
    },
];

fn find_standard(name: &str) -> Option<&'static StandardDef> {
    KNOWN_STANDARDS.iter().find(|s| s.id == name)
}

// ── Core functions ──────────────────────────────────────────────────────

/// Build an `AuditResult` from a `ConnectorAudit`.
pub fn audit_connector(connector_audit: &ConnectorAudit) -> AuditResult {
    let matrix_entries = build_matrix_entries(connector_audit);
    let gaps = build_gap_entries(connector_audit);
    let compliance_score = compute_compliance_score(connector_audit);
    let recommendations = build_recommendations(connector_audit);

    AuditResult {
        connector: connector_audit.name.clone(),
        matrix_entries,
        compliance_score,
        gaps,
        recommendations,
    }
}

/// Build audit results for all connectors in a matrix.
pub fn audit_all(matrix: &AuditMatrix) -> (Vec<AuditResult>, AuditSummary) {
    let mut results = Vec::new();
    let mut summary = AuditSummary {
        total_connectors: matrix.total_connectors,
        audited: 0,
        passed: 0,
        failed: 0,
        gap_count: 0,
    };

    for audit in matrix.connectors.values() {
        let result = audit_connector(audit);
        summary.audited += 1;
        summary.gap_count += result.gaps.len();
        if result.compliance_score >= 0.8 {
            summary.passed += 1;
        } else {
            summary.failed += 1;
        }
        results.push(result);
    }

    (results, summary)
}

/// Perform gap analysis with severity filtering.
pub fn audit_gaps(matrix: &AuditMatrix, args: &AuditGapsArgs) -> Vec<GapEntry> {
    let mut all_gaps = Vec::new();

    let connectors: Vec<&ConnectorAudit> = args.connector.as_ref().map_or_else(
        || matrix.connectors.values().collect(),
        |name| matrix.connectors.get(name).into_iter().collect(),
    );

    for audit in connectors {
        let entries = build_gap_entries(audit);
        for entry in entries {
            let dominated = match args.severity_threshold {
                SeverityThreshold::All => false,
                SeverityThreshold::Degraded => entry.severity == GapEntrySeverity::Cosmetic,
                SeverityThreshold::Blocking => entry.severity != GapEntrySeverity::Blocking,
            };
            if dominated {
                continue;
            }
            if !args.include_planned && entry.planned {
                continue;
            }
            all_gaps.push(entry);
        }
    }

    all_gaps
}

/// Check a connector against a compliance standard.
pub fn audit_compliance(
    connector_audit: &ConnectorAudit,
    args: &AuditComplianceArgs,
) -> Result<ComplianceReport, AuditError> {
    let standard = find_standard(&args.standard)
        .ok_or_else(|| AuditError::UnknownStandard(args.standard.clone()))?;

    let mut entries = Vec::new();
    let mut pass_count = 0_usize;
    let mut total_applicable = 0_usize;

    for req in standard.requirements {
        let status = (req.check)(connector_audit);
        let evidence = (req.evidence)(connector_audit);

        if status != ComplianceStatus::NotApplicable {
            total_applicable += 1;
            if status == ComplianceStatus::Pass {
                pass_count += 1;
            }
        }

        entries.push(ComplianceEntry {
            standard: args.standard.clone(),
            requirement: req.id.to_string(),
            description: req.description.to_string(),
            status,
            evidence,
        });
    }

    #[allow(clippy::cast_precision_loss)]
    let pass_rate = if total_applicable > 0 {
        pass_count as f64 / total_applicable as f64
    } else {
        1.0
    };

    let verdict = if pass_rate >= 1.0 {
        ComplianceStatus::Pass
    } else if pass_rate >= 0.5 {
        ComplianceStatus::Partial
    } else {
        ComplianceStatus::Fail
    };

    Ok(ComplianceReport {
        connector: connector_audit.name.clone(),
        standard: args.standard.clone(),
        entries,
        pass_rate,
        verdict,
    })
}

/// Errors that can occur during audit operations.
#[derive(Clone, Debug)]
pub enum AuditError {
    /// The specified standard name is not recognized.
    UnknownStandard(String),
    /// The specified connector name was not found.
    UnknownConnector(String),
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownStandard(s) => write!(f, "unknown compliance standard: {s}"),
            Self::UnknownConnector(c) => write!(f, "unknown connector: {c}"),
        }
    }
}

impl std::error::Error for AuditError {}

// ── Internal helpers ────────────────────────────────────────────────────

fn build_matrix_entries(audit: &ConnectorAudit) -> Vec<MatrixEntry> {
    let ops_count = audit.operations.count;

    let ops_coverage = audit.operations.completeness;
    let hints_coverage = audit.agent_hints.coverage;
    let net_coverage = audit.network.coverage;

    #[allow(clippy::cast_precision_loss)]
    let config_coverage = if audit.config.has_state_config && audit.config.has_migration_hint {
        1.0
    } else if audit.config.has_state_config || audit.config.has_migration_hint {
        0.5
    } else {
        0.0
    };

    #[allow(clippy::cast_precision_loss)]
    let events_coverage = if ops_count == 0 {
        0.0
    } else {
        let mut score = 0.0_f64;
        if audit.events.event_count > 0 {
            score += 0.4;
        }
        if audit.events.has_event_caps {
            score += 0.3;
        }
        if audit.events.has_streaming_archetype {
            score += 0.3;
        }
        score
    };

    #[allow(clippy::cast_precision_loss)]
    let rate_limit_coverage =
        if audit.rate_limits.pool_count > 0 && audit.rate_limits.has_operation_pools {
            1.0
        } else if audit.rate_limits.pool_count > 0 {
            0.5
        } else {
            0.0
        };

    vec![
        MatrixEntry {
            area: "operations".to_string(),
            coverage: ops_coverage,
            passing: ops_coverage >= 0.8,
        },
        MatrixEntry {
            area: "agent_hints".to_string(),
            coverage: hints_coverage,
            passing: hints_coverage >= 0.8,
        },
        MatrixEntry {
            area: "network".to_string(),
            coverage: net_coverage,
            passing: net_coverage >= 0.5,
        },
        MatrixEntry {
            area: "config".to_string(),
            coverage: config_coverage,
            passing: config_coverage >= 0.5,
        },
        MatrixEntry {
            area: "events".to_string(),
            coverage: events_coverage,
            passing: events_coverage >= 0.4,
        },
        MatrixEntry {
            area: "rate_limits".to_string(),
            coverage: rate_limit_coverage,
            passing: rate_limit_coverage >= 0.5,
        },
    ]
}

fn build_gap_entries(audit: &ConnectorAudit) -> Vec<GapEntry> {
    audit
        .gaps
        .iter()
        .map(|g| GapEntry {
            connector: audit.name.clone(),
            capability: format!("{:?}/{}", g.category, g.description),
            severity: GapEntrySeverity::from_gap_severity(g.severity),
            remediation: g.remediation.clone(),
            planned: false,
        })
        .collect()
}

#[allow(clippy::cast_precision_loss)]
fn compute_compliance_score(audit: &ConnectorAudit) -> f64 {
    // Weighted average of the matrix areas.
    let entries = build_matrix_entries(audit);
    if entries.is_empty() {
        return 0.0;
    }
    let weights: &[f64] = &[0.30, 0.20, 0.15, 0.10, 0.10, 0.15];
    let mut total_weight = 0.0_f64;
    let mut weighted_sum = 0.0_f64;
    for (entry, &w) in entries.iter().zip(weights.iter()) {
        weighted_sum += entry.coverage * w;
        total_weight += w;
    }
    if total_weight > 0.0 {
        weighted_sum / total_weight
    } else {
        0.0
    }
}

fn build_recommendations(audit: &ConnectorAudit) -> Vec<String> {
    let mut recs = Vec::new();

    if !audit.has_manifest {
        recs.push("Create a manifest.toml with connector identity and operations".to_string());
        return recs;
    }

    if audit.operations.count == 0 {
        recs.push("Add operation declarations to manifest.toml".to_string());
    }

    if audit.operations.completeness < 0.5 {
        recs.push(
            "Improve operation metadata completeness (descriptions, schemas, capabilities)"
                .to_string(),
        );
    } else if audit.operations.completeness < 0.9 {
        recs.push("Fill remaining operation metadata gaps for full readiness".to_string());
    }

    if audit.agent_hints.coverage < 0.5 {
        recs.push("Add ai_hints sections with when_to_use and examples".to_string());
    } else if audit.agent_hints.coverage < 0.8 {
        recs.push("Increase agent hint coverage to 80%+ for FCP2 compliance".to_string());
    }

    if audit.network.coverage < 0.3 {
        recs.push("Add network_constraints to operations for security compliance".to_string());
    }

    if audit.rate_limits.pool_count == 0 {
        recs.push("Declare rate limit pools for operational safety".to_string());
    }

    if !audit.config.has_state_config {
        recs.push("Add connector.state configuration section".to_string());
    }

    recs
}

// ── TOON formatters ─────────────────────────────────────────────────────

/// TOON output for a single audit result.
pub fn format_audit_toon(result: &AuditResult) -> Vec<String> {
    let mut lines = Vec::new();

    lines.push(format!("== Audit: {} ==", result.connector));
    lines.push(format!(
        "Compliance score: {:.0}%",
        result.compliance_score * 100.0
    ));
    lines.push(String::new());

    lines.push("Matrix:".to_string());
    for entry in &result.matrix_entries {
        let marker = if entry.passing { "[+]" } else { "[-]" };
        lines.push(format!(
            "  {marker} {}: {:.0}%",
            entry.area,
            entry.coverage * 100.0
        ));
    }
    lines.push(String::new());

    if result.gaps.is_empty() {
        lines.push("Gaps: none".to_string());
    } else {
        lines.push(format!("Gaps ({}):", result.gaps.len()));
        for gap in &result.gaps {
            lines.push(format!(
                "  [{}] {}: {}",
                gap.severity.label(),
                gap.capability,
                gap.remediation
            ));
        }
    }

    if !result.recommendations.is_empty() {
        lines.push(String::new());
        lines.push("Recommendations:".to_string());
        for (i, rec) in result.recommendations.iter().enumerate() {
            lines.push(format!("  {}. {rec}", i + 1));
        }
    }

    lines
}

/// TOON output for gap analysis.
pub fn format_gaps_toon(gaps: &[GapEntry]) -> Vec<String> {
    let mut lines = Vec::new();

    if gaps.is_empty() {
        lines.push("No gaps found.".to_string());
        return lines;
    }

    lines.push(format!("== Gap Analysis ({} gaps) ==", gaps.len()));
    lines.push(String::new());

    let blocking: Vec<_> = gaps
        .iter()
        .filter(|g| g.severity == GapEntrySeverity::Blocking)
        .collect();
    let degraded: Vec<_> = gaps
        .iter()
        .filter(|g| g.severity == GapEntrySeverity::Degraded)
        .collect();
    let cosmetic: Vec<_> = gaps
        .iter()
        .filter(|g| g.severity == GapEntrySeverity::Cosmetic)
        .collect();

    if !blocking.is_empty() {
        lines.push(format!("BLOCKING ({}):", blocking.len()));
        for g in &blocking {
            let planned_tag = if g.planned { " [planned]" } else { "" };
            lines.push(format!(
                "  - {}: {}{planned_tag}",
                g.connector, g.capability
            ));
            lines.push(format!("    fix: {}", g.remediation));
        }
        lines.push(String::new());
    }

    if !degraded.is_empty() {
        lines.push(format!("DEGRADED ({}):", degraded.len()));
        for g in &degraded {
            let planned_tag = if g.planned { " [planned]" } else { "" };
            lines.push(format!(
                "  - {}: {}{planned_tag}",
                g.connector, g.capability
            ));
            lines.push(format!("    fix: {}", g.remediation));
        }
        lines.push(String::new());
    }

    if !cosmetic.is_empty() {
        lines.push(format!("COSMETIC ({}):", cosmetic.len()));
        for g in &cosmetic {
            let planned_tag = if g.planned { " [planned]" } else { "" };
            lines.push(format!(
                "  - {}: {}{planned_tag}",
                g.connector, g.capability
            ));
            lines.push(format!("    fix: {}", g.remediation));
        }
    }

    lines
}

/// TOON output for a compliance check.
pub fn format_compliance_toon(report: &ComplianceReport) -> Vec<String> {
    let mut lines = Vec::new();

    lines.push(format!(
        "== Compliance: {} vs {} ==",
        report.connector, report.standard
    ));
    lines.push(format!(
        "Verdict: {} (pass rate: {:.0}%)",
        report.verdict.label(),
        report.pass_rate * 100.0
    ));
    lines.push(String::new());

    for entry in &report.entries {
        lines.push(format!(
            "  {} {} - {}",
            entry.status.symbol(),
            entry.requirement,
            entry.description
        ));
        lines.push(format!("       evidence: {}", entry.evidence));
    }

    lines
}

/// TOON output for the fleet-wide audit summary.
pub fn format_summary_toon(summary: &AuditSummary) -> Vec<String> {
    let mut lines = Vec::new();

    lines.push("== Audit Summary ==".to_string());
    lines.push(format!("Total connectors: {}", summary.total_connectors));
    lines.push(format!("Audited: {}", summary.audited));
    lines.push(format!(
        "Passed: {} | Failed: {}",
        summary.passed, summary.failed
    ));
    lines.push(format!("Total gaps: {}", summary.gap_count));

    lines
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::audit::{
        AgentHintAudit, ConfigAudit, EventAudit, NetworkAudit, OperationsAudit, RateLimitAudit,
    };
    use crate::readiness::{
        ConnectorCohort, GapCategory, GapSeverity, ReadinessGap, ReadinessLevel,
    };

    // ── Test fixtures ───────────────────────────────────────────────

    fn make_full_connector(name: &str) -> ConnectorAudit {
        ConnectorAudit {
            name: name.to_string(),
            crate_path: format!("connectors/{name}"),
            connector_id: Some(format!("fcp.{name}")),
            cohort: ConnectorCohort::DevTools,
            level: ReadinessLevel::Ready,
            has_manifest: true,
            operations: OperationsAudit {
                count: 5,
                with_description: 5,
                with_input_properties: 5,
                with_output_schema: 5,
                with_capability: 5,
                with_risk_level: 5,
                with_safety_tier: 5,
                with_idempotency: 5,
                with_approval: 5,
                completeness: 1.0,
            },
            config: ConfigAudit {
                has_state_config: true,
                has_migration_hint: true,
            },
            agent_hints: AgentHintAudit {
                with_hints: 5,
                with_when_to_use: 5,
                with_examples: 5,
                with_common_mistakes: 3,
                with_related: 4,
                coverage: 1.0,
            },
            events: EventAudit {
                event_count: 3,
                has_event_caps: true,
                has_streaming_archetype: true,
            },
            rate_limits: RateLimitAudit {
                pool_count: 2,
                has_operation_pools: true,
            },
            network: NetworkAudit {
                with_constraints: 5,
                with_host_allow: 5,
                with_port_allow: 3,
                coverage: 1.0,
            },
            gaps: vec![],
        }
    }

    fn make_partial_connector(name: &str) -> ConnectorAudit {
        ConnectorAudit {
            name: name.to_string(),
            crate_path: format!("connectors/{name}"),
            connector_id: Some(format!("fcp.{name}")),
            cohort: ConnectorCohort::Messaging,
            level: ReadinessLevel::PartiallyReady,
            has_manifest: true,
            operations: OperationsAudit {
                count: 4,
                with_description: 3,
                with_input_properties: 2,
                with_output_schema: 2,
                with_capability: 4,
                with_risk_level: 2,
                with_safety_tier: 2,
                with_idempotency: 1,
                with_approval: 0,
                completeness: 0.5,
            },
            config: ConfigAudit {
                has_state_config: true,
                has_migration_hint: false,
            },
            agent_hints: AgentHintAudit {
                with_hints: 2,
                with_when_to_use: 2,
                with_examples: 1,
                with_common_mistakes: 0,
                with_related: 0,
                coverage: 0.5,
            },
            events: EventAudit {
                event_count: 1,
                has_event_caps: false,
                has_streaming_archetype: false,
            },
            rate_limits: RateLimitAudit {
                pool_count: 1,
                has_operation_pools: false,
            },
            network: NetworkAudit {
                with_constraints: 1,
                with_host_allow: 1,
                with_port_allow: 0,
                coverage: 0.25,
            },
            gaps: vec![
                ReadinessGap {
                    category: GapCategory::OperationMetadata,
                    severity: GapSeverity::Blocking,
                    description: "op_send: missing description".to_string(),
                    remediation: "Add description".to_string(),
                },
                ReadinessGap {
                    category: GapCategory::AgentHints,
                    severity: GapSeverity::Degraded,
                    description: "op_list: missing ai_hints".to_string(),
                    remediation: "Add ai_hints section".to_string(),
                },
            ],
        }
    }

    fn make_empty_connector(name: &str) -> ConnectorAudit {
        ConnectorAudit {
            name: name.to_string(),
            crate_path: format!("connectors/{name}"),
            connector_id: None,
            cohort: ConnectorCohort::Other,
            level: ReadinessLevel::NotReady,
            has_manifest: false,
            operations: OperationsAudit::default(),
            config: ConfigAudit::default(),
            agent_hints: AgentHintAudit::default(),
            events: EventAudit::default(),
            rate_limits: RateLimitAudit::default(),
            network: NetworkAudit::default(),
            gaps: vec![ReadinessGap {
                category: GapCategory::Identity,
                severity: GapSeverity::Blocking,
                description: "No manifest.toml found".to_string(),
                remediation: "Create a manifest.toml".to_string(),
            }],
        }
    }

    fn make_cosmetic_only_connector(name: &str) -> ConnectorAudit {
        ConnectorAudit {
            name: name.to_string(),
            crate_path: format!("connectors/{name}"),
            connector_id: Some(format!("fcp.{name}")),
            cohort: ConnectorCohort::Productivity,
            level: ReadinessLevel::PartiallyReady,
            has_manifest: true,
            operations: OperationsAudit {
                count: 3,
                with_description: 3,
                with_input_properties: 3,
                with_output_schema: 3,
                with_capability: 3,
                with_risk_level: 3,
                with_safety_tier: 3,
                with_idempotency: 3,
                with_approval: 3,
                completeness: 1.0,
            },
            config: ConfigAudit {
                has_state_config: true,
                has_migration_hint: true,
            },
            agent_hints: AgentHintAudit {
                with_hints: 3,
                with_when_to_use: 3,
                with_examples: 3,
                with_common_mistakes: 2,
                with_related: 1,
                coverage: 1.0,
            },
            events: EventAudit {
                event_count: 0,
                has_event_caps: false,
                has_streaming_archetype: false,
            },
            rate_limits: RateLimitAudit {
                pool_count: 1,
                has_operation_pools: true,
            },
            network: NetworkAudit {
                with_constraints: 3,
                with_host_allow: 3,
                with_port_allow: 2,
                coverage: 1.0,
            },
            gaps: vec![ReadinessGap {
                category: GapCategory::EventSupport,
                severity: GapSeverity::Cosmetic,
                description: "No events declared".to_string(),
                remediation: "Add event declarations if applicable".to_string(),
            }],
        }
    }

    fn make_matrix(connectors: Vec<ConnectorAudit>) -> AuditMatrix {
        let mut map = BTreeMap::new();
        for c in &connectors {
            map.insert(c.name.clone(), c.clone());
        }
        AuditMatrix {
            generated_at: "2026-03-12T00:00:00Z".to_string(),
            total_connectors: connectors.len(),
            with_manifest: connectors.iter().filter(|c| c.has_manifest).count(),
            missing_manifest: connectors.iter().filter(|c| !c.has_manifest).count(),
            connectors: map,
            summary: crate::audit::AuditSummary::default(),
        }
    }

    // ── AuditArgs tests ─────────────────────────────────────────────

    #[test]
    fn audit_args_default_format() {
        let args = AuditArgs {
            connector: None,
            gaps_only: false,
            verbose: false,
            format: OutputFormat::default(),
        };
        assert_eq!(args.format, OutputFormat::Text);
        assert!(!args.gaps_only);
        assert!(!args.verbose);
    }

    #[test]
    fn audit_args_json_format() {
        let args = AuditArgs {
            connector: Some("github".to_string()),
            gaps_only: true,
            verbose: true,
            format: OutputFormat::Json,
        };
        assert_eq!(args.format, OutputFormat::Json);
        assert!(args.gaps_only);
        assert!(args.verbose);
        assert_eq!(args.connector.as_deref(), Some("github"));
    }

    // ── AuditGapsArgs tests ──────────────────────────────────────────

    #[test]
    fn gaps_args_default_threshold() {
        let args = AuditGapsArgs {
            connector: None,
            severity_threshold: SeverityThreshold::default(),
            include_planned: false,
        };
        assert_eq!(args.severity_threshold, SeverityThreshold::All);
    }

    #[test]
    fn gaps_args_blocking_threshold() {
        let args = AuditGapsArgs {
            connector: Some("slack".to_string()),
            severity_threshold: SeverityThreshold::Blocking,
            include_planned: true,
        };
        assert_eq!(args.severity_threshold, SeverityThreshold::Blocking);
        assert!(args.include_planned);
    }

    // ── AuditComplianceArgs tests ────────────────────────────────────

    #[test]
    fn compliance_args_detail_levels() {
        assert_eq!(DetailLevel::default(), DetailLevel::Summary);

        let args = AuditComplianceArgs {
            connector: "github".to_string(),
            standard: "fcp2".to_string(),
            detail_level: DetailLevel::Full,
        };
        assert_eq!(args.detail_level, DetailLevel::Full);
    }

    // ── audit_connector tests ────────────────────────────────────────

    #[test]
    fn audit_full_connector_high_score() {
        let c = make_full_connector("github");
        let result = audit_connector(&c);
        assert_eq!(result.connector, "github");
        assert!(result.compliance_score > 0.9);
        assert!(result.gaps.is_empty());
    }

    #[test]
    fn audit_full_connector_all_matrix_areas() {
        let c = make_full_connector("github");
        let result = audit_connector(&c);
        assert_eq!(result.matrix_entries.len(), 6);
        let areas: Vec<&str> = result
            .matrix_entries
            .iter()
            .map(|e| e.area.as_str())
            .collect();
        assert!(areas.contains(&"operations"));
        assert!(areas.contains(&"agent_hints"));
        assert!(areas.contains(&"network"));
        assert!(areas.contains(&"config"));
        assert!(areas.contains(&"events"));
        assert!(areas.contains(&"rate_limits"));
    }

    #[test]
    fn audit_full_connector_all_passing() {
        let c = make_full_connector("github");
        let result = audit_connector(&c);
        for entry in &result.matrix_entries {
            assert!(entry.passing, "area {} should pass", entry.area);
        }
    }

    #[test]
    fn audit_partial_connector_has_gaps() {
        let c = make_partial_connector("slack");
        let result = audit_connector(&c);
        assert!(!result.gaps.is_empty());
        assert!(result.compliance_score < 0.9);
    }

    #[test]
    fn audit_partial_connector_has_recommendations() {
        let c = make_partial_connector("slack");
        let result = audit_connector(&c);
        assert!(!result.recommendations.is_empty());
    }

    #[test]
    fn audit_empty_connector_low_score() {
        let c = make_empty_connector("unknown");
        let result = audit_connector(&c);
        assert!(result.compliance_score < 0.2);
        assert!(!result.gaps.is_empty());
    }

    #[test]
    fn audit_empty_connector_has_manifest_recommendation() {
        let c = make_empty_connector("unknown");
        let result = audit_connector(&c);
        assert!(
            result
                .recommendations
                .iter()
                .any(|r| r.contains("manifest.toml"))
        );
    }

    #[test]
    fn audit_connector_preserves_name() {
        let c = make_full_connector("sentry");
        let result = audit_connector(&c);
        assert_eq!(result.connector, "sentry");
    }

    #[test]
    fn audit_connector_score_is_bounded() {
        let c = make_full_connector("test");
        let result = audit_connector(&c);
        assert!(result.compliance_score >= 0.0);
        assert!(result.compliance_score <= 1.0);
    }

    #[test]
    fn audit_partial_score_between_bounds() {
        let c = make_partial_connector("test");
        let result = audit_connector(&c);
        assert!(result.compliance_score > 0.0);
        assert!(result.compliance_score < 1.0);
    }

    // ── audit_all tests ──────────────────────────────────────────────

    #[test]
    fn audit_all_single_connector() {
        let matrix = make_matrix(vec![make_full_connector("github")]);
        let (results, summary) = audit_all(&matrix);
        assert_eq!(results.len(), 1);
        assert_eq!(summary.audited, 1);
        assert_eq!(summary.total_connectors, 1);
    }

    #[test]
    fn audit_all_multiple_connectors() {
        let matrix = make_matrix(vec![
            make_full_connector("github"),
            make_partial_connector("slack"),
            make_empty_connector("unknown"),
        ]);
        let (results, summary) = audit_all(&matrix);
        assert_eq!(results.len(), 3);
        assert_eq!(summary.audited, 3);
    }

    #[test]
    fn audit_all_counts_passed_and_failed() {
        let matrix = make_matrix(vec![
            make_full_connector("github"),
            make_empty_connector("unknown"),
        ]);
        let (_, summary) = audit_all(&matrix);
        assert!(summary.passed >= 1);
        assert!(summary.failed >= 1);
    }

    #[test]
    fn audit_all_empty_matrix() {
        let matrix = make_matrix(vec![]);
        let (results, summary) = audit_all(&matrix);
        assert!(results.is_empty());
        assert_eq!(summary.audited, 0);
        assert_eq!(summary.passed, 0);
        assert_eq!(summary.failed, 0);
    }

    #[test]
    fn audit_all_gap_count_aggregates() {
        let matrix = make_matrix(vec![
            make_partial_connector("slack"),
            make_partial_connector("discord"),
        ]);
        let (_, summary) = audit_all(&matrix);
        assert!(summary.gap_count >= 4); // 2 gaps each
    }

    #[test]
    fn audit_all_all_passing() {
        let matrix = make_matrix(vec![make_full_connector("a"), make_full_connector("b")]);
        let (_, summary) = audit_all(&matrix);
        assert_eq!(summary.passed, 2);
        assert_eq!(summary.failed, 0);
    }

    #[test]
    fn audit_all_all_failing() {
        let matrix = make_matrix(vec![make_empty_connector("a"), make_empty_connector("b")]);
        let (_, summary) = audit_all(&matrix);
        assert_eq!(summary.passed, 0);
        assert_eq!(summary.failed, 2);
    }

    #[test]
    fn audit_all_preserves_total_connectors() {
        let matrix = make_matrix(vec![make_full_connector("a"), make_empty_connector("b")]);
        let (_, summary) = audit_all(&matrix);
        assert_eq!(summary.total_connectors, 2);
    }

    // ── audit_gaps tests ─────────────────────────────────────────────

    #[test]
    fn gaps_no_gaps_for_full_connector() {
        let matrix = make_matrix(vec![make_full_connector("github")]);
        let args = AuditGapsArgs {
            connector: Some("github".to_string()),
            severity_threshold: SeverityThreshold::All,
            include_planned: true,
        };
        let gaps = audit_gaps(&matrix, &args);
        assert!(gaps.is_empty());
    }

    #[test]
    fn gaps_returns_all_severities() {
        let matrix = make_matrix(vec![make_partial_connector("slack")]);
        let args = AuditGapsArgs {
            connector: None,
            severity_threshold: SeverityThreshold::All,
            include_planned: true,
        };
        let gaps = audit_gaps(&matrix, &args);
        assert!(!gaps.is_empty());
    }

    #[test]
    fn gaps_filter_blocking_only() {
        let matrix = make_matrix(vec![make_partial_connector("slack")]);
        let args = AuditGapsArgs {
            connector: None,
            severity_threshold: SeverityThreshold::Blocking,
            include_planned: true,
        };
        let gaps = audit_gaps(&matrix, &args);
        for g in &gaps {
            assert_eq!(g.severity, GapEntrySeverity::Blocking);
        }
    }

    #[test]
    fn gaps_filter_degraded_and_above() {
        let matrix = make_matrix(vec![make_partial_connector("slack")]);
        let args = AuditGapsArgs {
            connector: None,
            severity_threshold: SeverityThreshold::Degraded,
            include_planned: true,
        };
        let gaps = audit_gaps(&matrix, &args);
        for g in &gaps {
            assert_ne!(g.severity, GapEntrySeverity::Cosmetic);
        }
    }

    #[test]
    fn gaps_filter_by_connector_name() {
        let matrix = make_matrix(vec![
            make_partial_connector("slack"),
            make_partial_connector("discord"),
        ]);
        let args = AuditGapsArgs {
            connector: Some("slack".to_string()),
            severity_threshold: SeverityThreshold::All,
            include_planned: true,
        };
        let gaps = audit_gaps(&matrix, &args);
        for g in &gaps {
            assert_eq!(g.connector, "slack");
        }
    }

    #[test]
    fn gaps_unknown_connector_returns_empty() {
        let matrix = make_matrix(vec![make_partial_connector("slack")]);
        let args = AuditGapsArgs {
            connector: Some("nonexistent".to_string()),
            severity_threshold: SeverityThreshold::All,
            include_planned: true,
        };
        let gaps = audit_gaps(&matrix, &args);
        assert!(gaps.is_empty());
    }

    #[test]
    fn gaps_all_connectors_when_none_specified() {
        let matrix = make_matrix(vec![
            make_partial_connector("slack"),
            make_partial_connector("discord"),
        ]);
        let args = AuditGapsArgs {
            connector: None,
            severity_threshold: SeverityThreshold::All,
            include_planned: true,
        };
        let gaps = audit_gaps(&matrix, &args);
        let connectors: std::collections::BTreeSet<&str> =
            gaps.iter().map(|g| g.connector.as_str()).collect();
        assert!(connectors.contains("slack"));
        assert!(connectors.contains("discord"));
    }

    #[test]
    fn gaps_cosmetic_only_connector() {
        let matrix = make_matrix(vec![make_cosmetic_only_connector("todoist")]);
        let args = AuditGapsArgs {
            connector: None,
            severity_threshold: SeverityThreshold::All,
            include_planned: true,
        };
        let gaps = audit_gaps(&matrix, &args);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].severity, GapEntrySeverity::Cosmetic);
    }

    #[test]
    fn gaps_cosmetic_filtered_by_blocking() {
        let matrix = make_matrix(vec![make_cosmetic_only_connector("todoist")]);
        let args = AuditGapsArgs {
            connector: None,
            severity_threshold: SeverityThreshold::Blocking,
            include_planned: true,
        };
        let gaps = audit_gaps(&matrix, &args);
        assert!(gaps.is_empty());
    }

    #[test]
    fn gaps_cosmetic_filtered_by_degraded() {
        let matrix = make_matrix(vec![make_cosmetic_only_connector("todoist")]);
        let args = AuditGapsArgs {
            connector: None,
            severity_threshold: SeverityThreshold::Degraded,
            include_planned: true,
        };
        let gaps = audit_gaps(&matrix, &args);
        assert!(gaps.is_empty());
    }

    #[test]
    fn gaps_planned_exclusion() {
        // Gaps built from ReadinessGap have planned=false by default
        let matrix = make_matrix(vec![make_partial_connector("slack")]);
        let args = AuditGapsArgs {
            connector: None,
            severity_threshold: SeverityThreshold::All,
            include_planned: false,
        };
        let gaps = audit_gaps(&matrix, &args);
        // All gaps should be included since none are planned
        assert!(!gaps.is_empty());
        for g in &gaps {
            assert!(!g.planned);
        }
    }

    #[test]
    fn gaps_empty_matrix_returns_empty() {
        let matrix = make_matrix(vec![]);
        let args = AuditGapsArgs {
            connector: None,
            severity_threshold: SeverityThreshold::All,
            include_planned: true,
        };
        let gaps = audit_gaps(&matrix, &args);
        assert!(gaps.is_empty());
    }

    // ── audit_compliance tests ───────────────────────────────────────

    #[test]
    fn compliance_fcp2_full_connector_passes() {
        let c = make_full_connector("github");
        let args = AuditComplianceArgs {
            connector: "github".to_string(),
            standard: "fcp2".to_string(),
            detail_level: DetailLevel::Summary,
        };
        let report = audit_compliance(&c, &args).unwrap();
        assert_eq!(report.verdict, ComplianceStatus::Pass);
        assert!((report.pass_rate - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn compliance_fcp2_partial_connector() {
        let c = make_partial_connector("slack");
        let args = AuditComplianceArgs {
            connector: "slack".to_string(),
            standard: "fcp2".to_string(),
            detail_level: DetailLevel::Detailed,
        };
        let report = audit_compliance(&c, &args).unwrap();
        assert!(report.pass_rate < 1.0);
        // At least some requirements fail or are partial
        assert!(
            report
                .entries
                .iter()
                .any(|e| e.status != ComplianceStatus::Pass)
        );
    }

    #[test]
    fn compliance_fcp2_empty_connector() {
        let c = make_empty_connector("unknown");
        let args = AuditComplianceArgs {
            connector: "unknown".to_string(),
            standard: "fcp2".to_string(),
            detail_level: DetailLevel::Full,
        };
        let report = audit_compliance(&c, &args).unwrap();
        assert_eq!(report.verdict, ComplianceStatus::Fail);
    }

    #[test]
    fn compliance_fcp3_full_connector() {
        let c = make_full_connector("github");
        let args = AuditComplianceArgs {
            connector: "github".to_string(),
            standard: "fcp3".to_string(),
            detail_level: DetailLevel::Summary,
        };
        let report = audit_compliance(&c, &args).unwrap();
        // FCP3 is stricter, but full connector should still pass
        assert!(report.pass_rate > 0.5);
    }

    #[test]
    fn compliance_fcp3_empty_connector_fails() {
        let c = make_empty_connector("unknown");
        let args = AuditComplianceArgs {
            connector: "unknown".to_string(),
            standard: "fcp3".to_string(),
            detail_level: DetailLevel::Summary,
        };
        let report = audit_compliance(&c, &args).unwrap();
        assert_eq!(report.verdict, ComplianceStatus::Fail);
    }

    #[test]
    fn compliance_unknown_standard_returns_error() {
        let c = make_full_connector("github");
        let args = AuditComplianceArgs {
            connector: "github".to_string(),
            standard: "fcp99".to_string(),
            detail_level: DetailLevel::Summary,
        };
        let result = audit_compliance(&c, &args);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("fcp99"));
    }

    #[test]
    fn compliance_entries_have_evidence() {
        let c = make_full_connector("github");
        let args = AuditComplianceArgs {
            connector: "github".to_string(),
            standard: "fcp2".to_string(),
            detail_level: DetailLevel::Full,
        };
        let report = audit_compliance(&c, &args).unwrap();
        for entry in &report.entries {
            assert!(
                !entry.evidence.is_empty(),
                "entry {} lacks evidence",
                entry.requirement
            );
        }
    }

    #[test]
    fn compliance_entries_have_standard_field() {
        let c = make_full_connector("github");
        let args = AuditComplianceArgs {
            connector: "github".to_string(),
            standard: "fcp2".to_string(),
            detail_level: DetailLevel::Summary,
        };
        let report = audit_compliance(&c, &args).unwrap();
        for entry in &report.entries {
            assert_eq!(entry.standard, "fcp2");
        }
    }

    #[test]
    fn compliance_preserves_connector_name() {
        let c = make_full_connector("sentry");
        let args = AuditComplianceArgs {
            connector: "sentry".to_string(),
            standard: "fcp2".to_string(),
            detail_level: DetailLevel::Summary,
        };
        let report = audit_compliance(&c, &args).unwrap();
        assert_eq!(report.connector, "sentry");
    }

    #[test]
    fn compliance_fcp2_na_handling() {
        // Empty connector operations should produce N/A for operation-dependent requirements
        let c = ConnectorAudit {
            name: "bare".to_string(),
            crate_path: "connectors/bare".to_string(),
            connector_id: Some("fcp.bare".to_string()),
            cohort: ConnectorCohort::Other,
            level: ReadinessLevel::NotReady,
            has_manifest: true,
            operations: OperationsAudit {
                count: 0,
                ..Default::default()
            },
            config: ConfigAudit::default(),
            agent_hints: AgentHintAudit::default(),
            events: EventAudit::default(),
            rate_limits: RateLimitAudit::default(),
            network: NetworkAudit::default(),
            gaps: vec![],
        };
        let args = AuditComplianceArgs {
            connector: "bare".to_string(),
            standard: "fcp2".to_string(),
            detail_level: DetailLevel::Full,
        };
        let report = audit_compliance(&c, &args).unwrap();
        let na_count = report
            .entries
            .iter()
            .filter(|e| e.status == ComplianceStatus::NotApplicable)
            .count();
        // Most FCP2 requirements are operation-based, should be N/A
        assert!(na_count >= 5);
    }

    #[test]
    fn compliance_fcp3_stricter_than_fcp2() {
        let c = make_partial_connector("slack");
        let fcp2_args = AuditComplianceArgs {
            connector: "slack".to_string(),
            standard: "fcp2".to_string(),
            detail_level: DetailLevel::Summary,
        };
        let fcp3_args = AuditComplianceArgs {
            connector: "slack".to_string(),
            standard: "fcp3".to_string(),
            detail_level: DetailLevel::Summary,
        };
        let fcp2 = audit_compliance(&c, &fcp2_args).unwrap();
        let fcp3 = audit_compliance(&c, &fcp3_args).unwrap();
        assert!(fcp3.pass_rate <= fcp2.pass_rate);
    }

    // ── ComplianceStatus tests ───────────────────────────────────────

    #[test]
    fn compliance_status_labels() {
        assert_eq!(ComplianceStatus::Pass.label(), "PASS");
        assert_eq!(ComplianceStatus::Fail.label(), "FAIL");
        assert_eq!(ComplianceStatus::Partial.label(), "PARTIAL");
        assert_eq!(ComplianceStatus::NotApplicable.label(), "N/A");
    }

    #[test]
    fn compliance_status_symbols() {
        assert_eq!(ComplianceStatus::Pass.symbol(), "[+]");
        assert_eq!(ComplianceStatus::Fail.symbol(), "[-]");
        assert_eq!(ComplianceStatus::Partial.symbol(), "[~]");
        assert_eq!(ComplianceStatus::NotApplicable.symbol(), "[.]");
    }

    // ── GapEntrySeverity tests ───────────────────────────────────────

    #[test]
    fn gap_severity_labels() {
        assert_eq!(GapEntrySeverity::Blocking.label(), "BLOCKING");
        assert_eq!(GapEntrySeverity::Degraded.label(), "DEGRADED");
        assert_eq!(GapEntrySeverity::Cosmetic.label(), "COSMETIC");
    }

    #[test]
    fn gap_severity_from_gap_severity_blocking() {
        assert_eq!(
            GapEntrySeverity::from_gap_severity(GapSeverity::Blocking),
            GapEntrySeverity::Blocking
        );
    }

    #[test]
    fn gap_severity_from_gap_severity_degraded() {
        assert_eq!(
            GapEntrySeverity::from_gap_severity(GapSeverity::Degraded),
            GapEntrySeverity::Degraded
        );
    }

    #[test]
    fn gap_severity_from_gap_severity_cosmetic() {
        assert_eq!(
            GapEntrySeverity::from_gap_severity(GapSeverity::Cosmetic),
            GapEntrySeverity::Cosmetic
        );
    }

    // ── AuditSummary tests ───────────────────────────────────────────

    #[test]
    fn summary_empty_defaults() {
        let s = AuditSummary::default();
        assert_eq!(s.total_connectors, 0);
        assert_eq!(s.audited, 0);
        assert_eq!(s.passed, 0);
        assert_eq!(s.failed, 0);
        assert_eq!(s.gap_count, 0);
    }

    #[test]
    fn summary_some_pass() {
        let matrix = make_matrix(vec![make_full_connector("a"), make_empty_connector("b")]);
        let (_, summary) = audit_all(&matrix);
        assert_eq!(summary.passed, 1);
        assert_eq!(summary.failed, 1);
    }

    #[test]
    fn summary_all_fail() {
        let matrix = make_matrix(vec![
            make_empty_connector("a"),
            make_empty_connector("b"),
            make_empty_connector("c"),
        ]);
        let (_, summary) = audit_all(&matrix);
        assert_eq!(summary.passed, 0);
        assert_eq!(summary.failed, 3);
    }

    // ── format_audit_toon tests ──────────────────────────────────────

    #[test]
    fn toon_audit_contains_connector_name() {
        let c = make_full_connector("github");
        let result = audit_connector(&c);
        let lines = format_audit_toon(&result);
        assert!(lines.iter().any(|l| l.contains("github")));
    }

    #[test]
    fn toon_audit_contains_score() {
        let c = make_full_connector("github");
        let result = audit_connector(&c);
        let lines = format_audit_toon(&result);
        assert!(lines.iter().any(|l| l.contains("Compliance score")));
    }

    #[test]
    fn toon_audit_contains_matrix() {
        let c = make_full_connector("github");
        let result = audit_connector(&c);
        let lines = format_audit_toon(&result);
        assert!(lines.iter().any(|l| l.contains("Matrix")));
        assert!(lines.iter().any(|l| l.contains("operations")));
    }

    #[test]
    fn toon_audit_no_gaps_label() {
        let c = make_full_connector("github");
        let result = audit_connector(&c);
        let lines = format_audit_toon(&result);
        assert!(lines.iter().any(|l| l.contains("Gaps: none")));
    }

    #[test]
    fn toon_audit_with_gaps_shows_count() {
        let c = make_partial_connector("slack");
        let result = audit_connector(&c);
        let lines = format_audit_toon(&result);
        assert!(lines.iter().any(|l| l.contains("Gaps (")));
    }

    #[test]
    fn toon_audit_with_recommendations() {
        let c = make_partial_connector("slack");
        let result = audit_connector(&c);
        let lines = format_audit_toon(&result);
        assert!(lines.iter().any(|l| l.contains("Recommendations")));
    }

    #[test]
    fn toon_audit_markers_for_passing() {
        let c = make_full_connector("github");
        let result = audit_connector(&c);
        let lines = format_audit_toon(&result);
        let matrix_lines: Vec<_> = lines.iter().filter(|l| l.contains("[+]")).collect();
        assert!(!matrix_lines.is_empty());
    }

    #[test]
    fn toon_audit_markers_for_failing() {
        let c = make_partial_connector("slack");
        let result = audit_connector(&c);
        let lines = format_audit_toon(&result);
        let fail_lines: Vec<_> = lines.iter().filter(|l| l.contains("[-]")).collect();
        assert!(!fail_lines.is_empty());
    }

    #[test]
    fn toon_audit_not_empty() {
        let c = make_full_connector("github");
        let result = audit_connector(&c);
        let lines = format_audit_toon(&result);
        assert!(!lines.is_empty());
    }

    #[test]
    fn toon_audit_has_header() {
        let c = make_full_connector("github");
        let result = audit_connector(&c);
        let lines = format_audit_toon(&result);
        assert!(lines[0].starts_with("== Audit:"));
    }

    // ── format_gaps_toon tests ───────────────────────────────────────

    #[test]
    fn toon_gaps_empty() {
        let lines = format_gaps_toon(&[]);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("No gaps found"));
    }

    #[test]
    fn toon_gaps_blocking_section() {
        let gaps = vec![GapEntry {
            connector: "slack".to_string(),
            capability: "description".to_string(),
            severity: GapEntrySeverity::Blocking,
            remediation: "Add description".to_string(),
            planned: false,
        }];
        let lines = format_gaps_toon(&gaps);
        assert!(lines.iter().any(|l| l.contains("BLOCKING")));
    }

    #[test]
    fn toon_gaps_degraded_section() {
        let gaps = vec![GapEntry {
            connector: "slack".to_string(),
            capability: "ai_hints".to_string(),
            severity: GapEntrySeverity::Degraded,
            remediation: "Add hints".to_string(),
            planned: false,
        }];
        let lines = format_gaps_toon(&gaps);
        assert!(lines.iter().any(|l| l.contains("DEGRADED")));
    }

    #[test]
    fn toon_gaps_cosmetic_section() {
        let gaps = vec![GapEntry {
            connector: "slack".to_string(),
            capability: "events".to_string(),
            severity: GapEntrySeverity::Cosmetic,
            remediation: "Add events".to_string(),
            planned: false,
        }];
        let lines = format_gaps_toon(&gaps);
        assert!(lines.iter().any(|l| l.contains("COSMETIC")));
    }

    #[test]
    fn toon_gaps_mixed_severities() {
        let gaps = vec![
            GapEntry {
                connector: "slack".to_string(),
                capability: "desc".to_string(),
                severity: GapEntrySeverity::Blocking,
                remediation: "fix".to_string(),
                planned: false,
            },
            GapEntry {
                connector: "slack".to_string(),
                capability: "hints".to_string(),
                severity: GapEntrySeverity::Degraded,
                remediation: "fix".to_string(),
                planned: false,
            },
            GapEntry {
                connector: "slack".to_string(),
                capability: "events".to_string(),
                severity: GapEntrySeverity::Cosmetic,
                remediation: "fix".to_string(),
                planned: false,
            },
        ];
        let lines = format_gaps_toon(&gaps);
        assert!(lines.iter().any(|l| l.contains("BLOCKING")));
        assert!(lines.iter().any(|l| l.contains("DEGRADED")));
        assert!(lines.iter().any(|l| l.contains("COSMETIC")));
    }

    #[test]
    fn toon_gaps_planned_tag() {
        let gaps = vec![GapEntry {
            connector: "slack".to_string(),
            capability: "events".to_string(),
            severity: GapEntrySeverity::Degraded,
            remediation: "fix".to_string(),
            planned: true,
        }];
        let lines = format_gaps_toon(&gaps);
        assert!(lines.iter().any(|l| l.contains("[planned]")));
    }

    #[test]
    fn toon_gaps_unplanned_no_tag() {
        let gaps = vec![GapEntry {
            connector: "slack".to_string(),
            capability: "events".to_string(),
            severity: GapEntrySeverity::Degraded,
            remediation: "fix".to_string(),
            planned: false,
        }];
        let lines = format_gaps_toon(&gaps);
        assert!(!lines.iter().any(|l| l.contains("[planned]")));
    }

    #[test]
    fn toon_gaps_shows_remediation() {
        let gaps = vec![GapEntry {
            connector: "slack".to_string(),
            capability: "events".to_string(),
            severity: GapEntrySeverity::Degraded,
            remediation: "Add event declarations".to_string(),
            planned: false,
        }];
        let lines = format_gaps_toon(&gaps);
        assert!(lines.iter().any(|l| l.contains("Add event declarations")));
    }

    #[test]
    fn toon_gaps_shows_count_in_header() {
        let gaps = vec![
            GapEntry {
                connector: "a".to_string(),
                capability: "x".to_string(),
                severity: GapEntrySeverity::Blocking,
                remediation: "fix".to_string(),
                planned: false,
            },
            GapEntry {
                connector: "b".to_string(),
                capability: "y".to_string(),
                severity: GapEntrySeverity::Blocking,
                remediation: "fix".to_string(),
                planned: false,
            },
        ];
        let lines = format_gaps_toon(&gaps);
        assert!(lines[0].contains("2 gaps"));
    }

    // ── format_compliance_toon tests ─────────────────────────────────

    #[test]
    fn toon_compliance_header() {
        let c = make_full_connector("github");
        let args = AuditComplianceArgs {
            connector: "github".to_string(),
            standard: "fcp2".to_string(),
            detail_level: DetailLevel::Summary,
        };
        let report = audit_compliance(&c, &args).unwrap();
        let lines = format_compliance_toon(&report);
        assert!(lines[0].contains("github"));
        assert!(lines[0].contains("fcp2"));
    }

    #[test]
    fn toon_compliance_verdict() {
        let c = make_full_connector("github");
        let args = AuditComplianceArgs {
            connector: "github".to_string(),
            standard: "fcp2".to_string(),
            detail_level: DetailLevel::Summary,
        };
        let report = audit_compliance(&c, &args).unwrap();
        let lines = format_compliance_toon(&report);
        assert!(lines.iter().any(|l| l.contains("Verdict")));
    }

    #[test]
    fn toon_compliance_shows_pass_symbol() {
        let c = make_full_connector("github");
        let args = AuditComplianceArgs {
            connector: "github".to_string(),
            standard: "fcp2".to_string(),
            detail_level: DetailLevel::Summary,
        };
        let report = audit_compliance(&c, &args).unwrap();
        let lines = format_compliance_toon(&report);
        assert!(lines.iter().any(|l| l.contains("[+]")));
    }

    #[test]
    fn toon_compliance_shows_fail_symbol() {
        let c = make_empty_connector("unknown");
        let args = AuditComplianceArgs {
            connector: "unknown".to_string(),
            standard: "fcp2".to_string(),
            detail_level: DetailLevel::Summary,
        };
        let report = audit_compliance(&c, &args).unwrap();
        let lines = format_compliance_toon(&report);
        assert!(lines.iter().any(|l| l.contains("[-]")));
    }

    #[test]
    fn toon_compliance_shows_evidence() {
        let c = make_full_connector("github");
        let args = AuditComplianceArgs {
            connector: "github".to_string(),
            standard: "fcp2".to_string(),
            detail_level: DetailLevel::Full,
        };
        let report = audit_compliance(&c, &args).unwrap();
        let lines = format_compliance_toon(&report);
        assert!(lines.iter().any(|l| l.contains("evidence")));
    }

    #[test]
    fn toon_compliance_na_symbol() {
        let c = ConnectorAudit {
            name: "bare".to_string(),
            crate_path: "connectors/bare".to_string(),
            connector_id: Some("fcp.bare".to_string()),
            cohort: ConnectorCohort::Other,
            level: ReadinessLevel::NotReady,
            has_manifest: true,
            operations: OperationsAudit {
                count: 0,
                ..Default::default()
            },
            config: ConfigAudit::default(),
            agent_hints: AgentHintAudit::default(),
            events: EventAudit::default(),
            rate_limits: RateLimitAudit::default(),
            network: NetworkAudit::default(),
            gaps: vec![],
        };
        let args = AuditComplianceArgs {
            connector: "bare".to_string(),
            standard: "fcp2".to_string(),
            detail_level: DetailLevel::Full,
        };
        let report = audit_compliance(&c, &args).unwrap();
        let lines = format_compliance_toon(&report);
        assert!(lines.iter().any(|l| l.contains("[.]")));
    }

    #[test]
    fn toon_compliance_shows_pass_rate() {
        let c = make_full_connector("github");
        let args = AuditComplianceArgs {
            connector: "github".to_string(),
            standard: "fcp2".to_string(),
            detail_level: DetailLevel::Summary,
        };
        let report = audit_compliance(&c, &args).unwrap();
        let lines = format_compliance_toon(&report);
        assert!(lines.iter().any(|l| l.contains("pass rate")));
    }

    // ── format_summary_toon tests ────────────────────────────────────

    #[test]
    fn toon_summary_header() {
        let s = AuditSummary::default();
        let lines = format_summary_toon(&s);
        assert!(lines[0].contains("Audit Summary"));
    }

    #[test]
    fn toon_summary_total() {
        let s = AuditSummary {
            total_connectors: 42,
            ..Default::default()
        };
        let lines = format_summary_toon(&s);
        assert!(lines.iter().any(|l| l.contains("42")));
    }

    #[test]
    fn toon_summary_passed_failed() {
        let s = AuditSummary {
            passed: 10,
            failed: 5,
            ..Default::default()
        };
        let lines = format_summary_toon(&s);
        assert!(lines.iter().any(|l| l.contains("10") && l.contains("5")));
    }

    #[test]
    fn toon_summary_gap_count() {
        let s = AuditSummary {
            gap_count: 99,
            ..Default::default()
        };
        let lines = format_summary_toon(&s);
        assert!(lines.iter().any(|l| l.contains("99")));
    }

    #[test]
    fn toon_summary_zero_result() {
        let s = AuditSummary::default();
        let lines = format_summary_toon(&s);
        assert!(lines.iter().any(|l| l.contains("0")));
    }

    #[test]
    fn toon_summary_not_empty() {
        let s = AuditSummary::default();
        let lines = format_summary_toon(&s);
        assert!(!lines.is_empty());
    }

    // ── Matrix entry tests ───────────────────────────────────────────

    #[test]
    fn matrix_entries_full_connector_all_pass() {
        let c = make_full_connector("github");
        let entries = build_matrix_entries(&c);
        for entry in &entries {
            assert!(
                entry.passing,
                "area {} should pass on full connector",
                entry.area
            );
        }
    }

    #[test]
    fn matrix_entries_empty_connector_some_fail() {
        let c = make_empty_connector("unknown");
        let entries = build_matrix_entries(&c);
        assert!(entries.iter().any(|e| !e.passing));
    }

    #[test]
    fn matrix_entries_count() {
        let c = make_full_connector("github");
        let entries = build_matrix_entries(&c);
        assert_eq!(entries.len(), 6);
    }

    #[test]
    fn matrix_entry_coverage_bounded() {
        let c = make_partial_connector("slack");
        let entries = build_matrix_entries(&c);
        for entry in &entries {
            assert!(entry.coverage >= 0.0, "area {} coverage < 0", entry.area);
            assert!(entry.coverage <= 1.0, "area {} coverage > 1", entry.area);
        }
    }

    // ── Compliance score tests ───────────────────────────────────────

    #[test]
    fn score_full_connector_high() {
        let c = make_full_connector("github");
        let score = compute_compliance_score(&c);
        assert!(score > 0.9);
    }

    #[test]
    fn score_empty_connector_low() {
        let c = make_empty_connector("unknown");
        let score = compute_compliance_score(&c);
        assert!(score < 0.2);
    }

    #[test]
    fn score_partial_connector_middle() {
        let c = make_partial_connector("slack");
        let score = compute_compliance_score(&c);
        assert!(score > 0.1);
        assert!(score < 0.9);
    }

    #[test]
    fn score_bounded_0_1() {
        for c in [
            make_full_connector("a"),
            make_partial_connector("b"),
            make_empty_connector("c"),
        ] {
            let score = compute_compliance_score(&c);
            assert!(score >= 0.0);
            assert!(score <= 1.0);
        }
    }

    // ── Recommendations tests ────────────────────────────────────────

    #[test]
    fn recommendations_full_connector_minimal() {
        let c = make_full_connector("github");
        let recs = build_recommendations(&c);
        assert!(
            recs.is_empty(),
            "full connector should have no recommendations"
        );
    }

    #[test]
    fn recommendations_empty_connector_has_manifest_advice() {
        let c = make_empty_connector("unknown");
        let recs = build_recommendations(&c);
        assert!(!recs.is_empty());
        assert!(recs.iter().any(|r| r.contains("manifest.toml")));
    }

    #[test]
    fn recommendations_partial_connector_actionable() {
        let c = make_partial_connector("slack");
        let recs = build_recommendations(&c);
        assert!(!recs.is_empty());
    }

    // ── Serialization roundtrip tests ────────────────────────────────

    #[test]
    fn audit_result_json_roundtrip() {
        let c = make_full_connector("github");
        let result = audit_connector(&c);
        let json = serde_json::to_string(&result).unwrap();
        let parsed: AuditResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.connector, result.connector);
        assert!((parsed.compliance_score - result.compliance_score).abs() < f64::EPSILON);
    }

    #[test]
    fn gap_entry_json_roundtrip() {
        let gap = GapEntry {
            connector: "slack".to_string(),
            capability: "description".to_string(),
            severity: GapEntrySeverity::Blocking,
            remediation: "fix it".to_string(),
            planned: true,
        };
        let json = serde_json::to_string(&gap).unwrap();
        let parsed: GapEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.connector, "slack");
        assert_eq!(parsed.severity, GapEntrySeverity::Blocking);
        assert!(parsed.planned);
    }

    #[test]
    fn compliance_entry_json_roundtrip() {
        let entry = ComplianceEntry {
            standard: "fcp2".to_string(),
            requirement: "FCP2-OPS-001".to_string(),
            description: "test".to_string(),
            status: ComplianceStatus::Pass,
            evidence: "all good".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: ComplianceEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.status, ComplianceStatus::Pass);
        assert_eq!(parsed.requirement, "FCP2-OPS-001");
    }

    #[test]
    fn audit_summary_json_roundtrip() {
        let summary = AuditSummary {
            total_connectors: 10,
            audited: 8,
            passed: 6,
            failed: 2,
            gap_count: 15,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let parsed: AuditSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_connectors, 10);
        assert_eq!(parsed.gap_count, 15);
    }

    #[test]
    fn compliance_report_json_roundtrip() {
        let c = make_full_connector("github");
        let args = AuditComplianceArgs {
            connector: "github".to_string(),
            standard: "fcp2".to_string(),
            detail_level: DetailLevel::Summary,
        };
        let report = audit_compliance(&c, &args).unwrap();
        let json = serde_json::to_string(&report).unwrap();
        let parsed: ComplianceReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.connector, "github");
        assert_eq!(parsed.standard, "fcp2");
    }

    #[test]
    fn output_format_json_roundtrip() {
        let format = OutputFormat::Json;
        let json = serde_json::to_string(&format).unwrap();
        let parsed: OutputFormat = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, OutputFormat::Json);
    }

    #[test]
    fn severity_threshold_json_roundtrip() {
        for threshold in [
            SeverityThreshold::All,
            SeverityThreshold::Degraded,
            SeverityThreshold::Blocking,
        ] {
            let json = serde_json::to_string(&threshold).unwrap();
            let parsed: SeverityThreshold = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, threshold);
        }
    }

    #[test]
    fn detail_level_json_roundtrip() {
        for level in [
            DetailLevel::Summary,
            DetailLevel::Detailed,
            DetailLevel::Full,
        ] {
            let json = serde_json::to_string(&level).unwrap();
            let parsed: DetailLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, level);
        }
    }

    // ── AuditError tests ─────────────────────────────────────────────

    #[test]
    fn audit_error_unknown_standard_display() {
        let err = AuditError::UnknownStandard("fcp99".to_string());
        assert!(err.to_string().contains("fcp99"));
    }

    #[test]
    fn audit_error_unknown_connector_display() {
        let err = AuditError::UnknownConnector("nonexistent".to_string());
        assert!(err.to_string().contains("nonexistent"));
    }

    // ── Edge case tests ──────────────────────────────────────────────

    #[test]
    fn empty_connector_list_audit_all() {
        let matrix = make_matrix(vec![]);
        let (results, summary) = audit_all(&matrix);
        assert!(results.is_empty());
        assert_eq!(summary.total_connectors, 0);
        assert_eq!(summary.gap_count, 0);
    }

    #[test]
    fn connector_with_zero_ops_score() {
        let c = ConnectorAudit {
            name: "bare".to_string(),
            crate_path: "connectors/bare".to_string(),
            connector_id: None,
            cohort: ConnectorCohort::Other,
            level: ReadinessLevel::NotReady,
            has_manifest: true,
            operations: OperationsAudit {
                count: 0,
                ..Default::default()
            },
            config: ConfigAudit::default(),
            agent_hints: AgentHintAudit::default(),
            events: EventAudit::default(),
            rate_limits: RateLimitAudit::default(),
            network: NetworkAudit::default(),
            gaps: vec![],
        };
        let result = audit_connector(&c);
        assert!(result.compliance_score >= 0.0);
        assert!(result.compliance_score <= 1.0);
    }

    #[test]
    fn multiple_gaps_same_connector() {
        let c = make_partial_connector("slack");
        let result = audit_connector(&c);
        assert!(result.gaps.len() >= 2);
        for gap in &result.gaps {
            assert_eq!(gap.connector, "slack");
        }
    }

    #[test]
    fn toon_audit_large_score_value() {
        let mut c = make_full_connector("test");
        c.operations.completeness = 1.0;
        let result = audit_connector(&c);
        let lines = format_audit_toon(&result);
        // Should render without panic
        assert!(lines.iter().any(|l| l.contains("Compliance score")));
    }

    #[test]
    fn severity_ordering() {
        assert!(GapEntrySeverity::Blocking < GapEntrySeverity::Degraded);
        assert!(GapEntrySeverity::Degraded < GapEntrySeverity::Cosmetic);
    }

    #[test]
    fn compliance_partial_symbol_in_toon() {
        let c = make_partial_connector("slack");
        let args = AuditComplianceArgs {
            connector: "slack".to_string(),
            standard: "fcp2".to_string(),
            detail_level: DetailLevel::Summary,
        };
        let report = audit_compliance(&c, &args).unwrap();
        let lines = format_compliance_toon(&report);
        // Partial connector should have at least one partial or failing symbol
        assert!(lines.iter().any(|l| l.contains("[~]") || l.contains("[-]")));
    }

    #[test]
    fn gap_entry_planned_flag_preserved() {
        let gap = GapEntry {
            connector: "test".to_string(),
            capability: "cap".to_string(),
            severity: GapEntrySeverity::Blocking,
            remediation: "fix".to_string(),
            planned: true,
        };
        assert!(gap.planned);
    }

    #[test]
    fn gap_entry_unplanned_flag_preserved() {
        let gap = GapEntry {
            connector: "test".to_string(),
            capability: "cap".to_string(),
            severity: GapEntrySeverity::Blocking,
            remediation: "fix".to_string(),
            planned: false,
        };
        assert!(!gap.planned);
    }

    #[test]
    fn find_standard_fcp2() {
        assert!(find_standard("fcp2").is_some());
    }

    #[test]
    fn find_standard_fcp3() {
        assert!(find_standard("fcp3").is_some());
    }

    #[test]
    fn find_standard_unknown() {
        assert!(find_standard("fcp99").is_none());
    }

    #[test]
    fn find_standard_empty() {
        assert!(find_standard("").is_none());
    }

    #[test]
    fn compliance_report_verdict_pass() {
        let c = make_full_connector("github");
        let args = AuditComplianceArgs {
            connector: "github".to_string(),
            standard: "fcp2".to_string(),
            detail_level: DetailLevel::Summary,
        };
        let report = audit_compliance(&c, &args).unwrap();
        assert_eq!(report.verdict, ComplianceStatus::Pass);
    }

    #[test]
    fn compliance_report_verdict_fail() {
        let c = make_empty_connector("unknown");
        let args = AuditComplianceArgs {
            connector: "unknown".to_string(),
            standard: "fcp3".to_string(),
            detail_level: DetailLevel::Summary,
        };
        let report = audit_compliance(&c, &args).unwrap();
        assert_eq!(report.verdict, ComplianceStatus::Fail);
    }

    #[test]
    fn audit_result_gaps_match_connector() {
        let c = make_partial_connector("discord");
        let result = audit_connector(&c);
        for gap in &result.gaps {
            assert_eq!(gap.connector, "discord");
        }
    }

    #[test]
    fn audit_result_matrix_areas_coverage_range() {
        let c = make_partial_connector("slack");
        let result = audit_connector(&c);
        for entry in &result.matrix_entries {
            assert!(
                entry.coverage >= 0.0 && entry.coverage <= 1.0,
                "area {} has out-of-bounds coverage: {}",
                entry.area,
                entry.coverage
            );
        }
    }

    #[test]
    fn multiple_connectors_independent_audits() {
        let c1 = make_full_connector("github");
        let c2 = make_empty_connector("unknown");
        let r1 = audit_connector(&c1);
        let r2 = audit_connector(&c2);
        assert!(r1.compliance_score > r2.compliance_score);
    }

    #[test]
    fn toon_gaps_zero_result() {
        let lines = format_gaps_toon(&[]);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], "No gaps found.");
    }

    #[test]
    fn toon_summary_audited_field() {
        let s = AuditSummary {
            total_connectors: 50,
            audited: 45,
            passed: 30,
            failed: 15,
            gap_count: 100,
        };
        let lines = format_summary_toon(&s);
        assert!(lines.iter().any(|l| l.contains("45")));
    }
}
