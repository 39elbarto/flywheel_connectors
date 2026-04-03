//! Connector metadata gap audit and readiness matrix.
//!
//! Scans every connector crate's `manifest.toml` against the fwc readiness
//! contract and produces a deterministic, machine-readable matrix of metadata
//! completeness.  Later cohort beads reference this matrix to drive remediation.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::readiness::{ConnectorCohort, GapCategory, GapSeverity, ReadinessGap, ReadinessLevel};

// ── Audit matrix types ────────────────────────────────────────────────────

/// Full audit matrix across all connectors in the workspace.
#[derive(Clone, Debug, Serialize)]
pub struct AuditMatrix {
    /// Timestamp of the audit run (ISO-8601).
    pub generated_at: String,
    /// Number of connector directories scanned.
    pub total_connectors: usize,
    /// Number of connectors with a `manifest.toml`.
    pub with_manifest: usize,
    /// Number of connectors missing a `manifest.toml` entirely.
    pub missing_manifest: usize,
    /// Per-connector audit results, keyed by connector directory name.
    pub connectors: BTreeMap<String, ConnectorAudit>,
    /// Aggregate statistics across all connectors.
    pub summary: AuditSummary,
}

/// Audit result for a single connector.
#[derive(Clone, Debug, Serialize)]
pub struct ConnectorAudit {
    /// Connector directory name (e.g. `"github"`).
    pub name: String,
    /// Crate path relative to workspace root.
    pub crate_path: String,
    /// Connector id from manifest (e.g. `"fcp.github"`), if present.
    pub connector_id: Option<String>,
    /// Assigned cohort category.
    pub cohort: ConnectorCohort,
    /// Overall readiness level.
    pub level: ReadinessLevel,
    /// Whether a `manifest.toml` exists.
    pub has_manifest: bool,
    /// Operation metadata audit.
    pub operations: OperationsAudit,
    /// Config schema audit.
    pub config: ConfigAudit,
    /// Agent hint coverage.
    pub agent_hints: AgentHintAudit,
    /// Event/stream metadata audit.
    pub events: EventAudit,
    /// Rate limit declaration audit.
    pub rate_limits: RateLimitAudit,
    /// Network constraints audit.
    pub network: NetworkAudit,
    /// Specific gaps found.
    pub gaps: Vec<ReadinessGap>,
}

/// Operation metadata completeness for a connector.
#[derive(Clone, Debug, Default, Serialize)]
pub struct OperationsAudit {
    /// Total operations declared in manifest.
    pub count: usize,
    /// Operations with non-empty description.
    pub with_description: usize,
    /// Operations with `input_schema` containing properties.
    pub with_input_properties: usize,
    /// Operations with `output_schema` containing properties or required.
    pub with_output_schema: usize,
    /// Operations with `capability` declared.
    pub with_capability: usize,
    /// Operations with `risk_level` set.
    pub with_risk_level: usize,
    /// Operations with `safety_tier` set.
    pub with_safety_tier: usize,
    /// Operations with `idempotency` set.
    pub with_idempotency: usize,
    /// Operations with `requires_approval` set.
    pub with_approval: usize,
    /// Completeness ratio (0.0–1.0).
    pub completeness: f64,
}

/// Config schema completeness.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ConfigAudit {
    /// Whether `connector.state` section exists.
    pub has_state_config: bool,
    /// Whether `migration_hint` is non-trivial.
    pub has_migration_hint: bool,
}

/// Agent hint (`ai_hints`) coverage.
#[derive(Clone, Debug, Default, Serialize)]
pub struct AgentHintAudit {
    /// Operations with `ai_hints` section.
    pub with_hints: usize,
    /// Operations with non-empty `when_to_use`.
    pub with_when_to_use: usize,
    /// Operations with at least one example.
    pub with_examples: usize,
    /// Operations with at least one `common_mistake` entry.
    pub with_common_mistakes: usize,
    /// Operations with at least one related operation.
    pub with_related: usize,
    /// Coverage ratio: operations with hints / total operations.
    pub coverage: f64,
}

/// Event/stream metadata audit.
#[derive(Clone, Debug, Default, Serialize)]
pub struct EventAudit {
    /// Number of events declared.
    pub event_count: usize,
    /// Whether `event_caps` section exists.
    pub has_event_caps: bool,
    /// Archetypes that imply event support.
    pub has_streaming_archetype: bool,
}

/// Rate limit declaration audit.
#[derive(Clone, Debug, Default, Serialize)]
pub struct RateLimitAudit {
    /// Number of rate limit pools declared.
    pub pool_count: usize,
    /// Whether operation-to-pool mappings exist.
    pub has_operation_pools: bool,
}

/// Network constraint audit.
#[derive(Clone, Debug, Default, Serialize)]
pub struct NetworkAudit {
    /// Operations with `network_constraints` section.
    pub with_constraints: usize,
    /// Operations with non-empty `host_allow`.
    pub with_host_allow: usize,
    /// Operations with `port_allow`.
    pub with_port_allow: usize,
    /// Coverage ratio.
    pub coverage: f64,
}

/// Aggregate summary statistics.
#[derive(Clone, Debug, Default, Serialize)]
pub struct AuditSummary {
    /// Connectors at each readiness level.
    pub ready: usize,
    pub partially_ready: usize,
    pub not_ready: usize,
    /// Connectors by cohort.
    pub by_cohort: BTreeMap<String, usize>,
    /// Total operations across all connectors.
    pub total_operations: usize,
    /// Total gaps found.
    pub total_gaps: usize,
    /// Gaps by severity.
    pub blocking_gaps: usize,
    pub degraded_gaps: usize,
    pub cosmetic_gaps: usize,
    /// Mean operation metadata completeness (0.0–1.0).
    pub mean_operation_completeness: f64,
    /// Mean agent hint coverage (0.0–1.0).
    pub mean_hint_coverage: f64,
}

// ── Cohort assignment ─────────────────────────────────────────────────────

/// Assign a connector to its cohort based on directory name.
fn assign_cohort(name: &str) -> ConnectorCohort {
    match name {
        // Messaging & social
        "slack" | "discord" | "telegram" | "twilio" | "sendgrid" | "mailchimp" | "intercom" => {
            ConnectorCohort::Messaging
        }
        "twitter" | "reddit" | "linkedin" => ConnectorCohort::Social,

        // Developer tools
        "github" | "gitlab" | "bitbucket" | "sentry" | "grafana" | "datadog" => {
            ConnectorCohort::DevTools
        }

        // Productivity & workspace
        "notion" | "asana" | "trello" | "todoist" | "clickup" | "monday" | "figma" => {
            ConnectorCohort::Productivity
        }
        "jira" | "linear" => ConnectorCohort::Productivity,
        "microsoft365" | "google-calendar" | "gmail" => ConnectorCohort::Workspace,

        // Cloud storage
        "s3" | "dropbox" | "box" => ConnectorCohort::Storage,

        // Knowledge & research
        "arxiv" | "semanticscholar" | "logseq" | "roam" | "evernote" | "wikipedia" => {
            ConnectorCohort::Knowledge
        }

        // AI & LLM
        "openai" | "anthropic" | "google-ai" | "llm-router" | "whisper" => ConnectorCohort::Ai,

        // Data & analytics
        "elasticsearch" | "bigquery" | "snowflake" | "duckdb" | "mongodb" | "postgresql"
        | "redis" => ConnectorCohort::Data,
        "posthog" | "mixpanel" | "amplitude" | "segment" => ConnectorCohort::Analytics,

        // Security & identity
        "1password" | "bitwarden" => ConnectorCohort::Security,

        // Business & finance
        "stripe" | "plaid" | "salesforce" | "hubspot" | "docusign" | "pandadoc" => {
            ConnectorCohort::Business
        }

        // Infrastructure & automation
        "kubernetes" | "terraform" | "pulumi" => ConnectorCohort::Infra,
        "zapier" | "make" | "n8n" | "retool" | "metabase" | "cron" | "webhook-receiver"
        | "mcp-bridge" => ConnectorCohort::Automation,

        // Media & content
        "youtube" | "spotify" => ConnectorCohort::Media,

        // Browser & search
        "browser" | "algolia" | "annas-archive" => ConnectorCohort::Browser,

        // Vector databases
        "pinecone" | "qdrant" | "vectordb" => ConnectorCohort::Vectordb,

        // Home & IoT
        "homeassistant" => ConnectorCohort::Iot,

        // Fallback
        _ => ConnectorCohort::Other,
    }
}

// ── Manifest parsing and audit ────────────────────────────────────────────

/// Parse a manifest TOML and audit its metadata completeness.
#[allow(clippy::too_many_lines)]
fn audit_manifest(name: &str, manifest: &toml::Value) -> ConnectorAudit {
    let connector_id = manifest
        .get("connector")
        .and_then(|c| c.get("id"))
        .and_then(|v| v.as_str())
        .map(String::from);

    let cohort = assign_cohort(name);
    let mut gaps: Vec<ReadinessGap> = Vec::new();

    // ── Operations audit ──
    let ops_table = manifest
        .get("provides")
        .and_then(|p| p.get("operations"))
        .and_then(|o| o.as_table());

    let mut ops = OperationsAudit::default();
    let mut hints = AgentHintAudit::default();
    let mut network = NetworkAudit::default();

    if let Some(operations) = ops_table {
        ops.count = operations.len();

        for (op_id, op_val) in operations {
            // Description
            let desc = op_val
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if desc.is_empty() {
                gaps.push(ReadinessGap {
                    category: GapCategory::OperationMetadata,
                    severity: GapSeverity::Blocking,
                    description: format!("{op_id}: missing description"),
                    remediation: "Add a non-empty description to this operation".into(),
                });
            } else {
                ops.with_description += 1;
            }

            // Input schema properties
            let has_input_props = op_val
                .get("input_schema")
                .and_then(|s| s.get("properties"))
                .is_some_and(|p| p.as_table().is_some_and(|t| !t.is_empty()));
            if has_input_props {
                ops.with_input_properties += 1;
            }

            // Output schema
            let has_output = op_val
                .get("output_schema")
                .is_some_and(|s| s.get("properties").is_some() || s.get("required").is_some());
            if has_output {
                ops.with_output_schema += 1;
            }

            // Capability
            if op_val
                .get("capability")
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty())
            {
                ops.with_capability += 1;
            } else {
                gaps.push(ReadinessGap {
                    category: GapCategory::OperationMetadata,
                    severity: GapSeverity::Blocking,
                    description: format!("{op_id}: missing capability"),
                    remediation: "Add a capability declaration to this operation".into(),
                });
            }

            // Risk level
            if op_val.get("risk_level").is_some() {
                ops.with_risk_level += 1;
            }

            // Safety tier
            if op_val.get("safety_tier").is_some() {
                ops.with_safety_tier += 1;
            }

            // Idempotency
            if op_val.get("idempotency").is_some() {
                ops.with_idempotency += 1;
            }

            // Requires approval
            if op_val.get("requires_approval").is_some() {
                ops.with_approval += 1;
            }

            // AI hints
            if let Some(ai) = op_val.get("ai_hints") {
                hints.with_hints += 1;

                let wtu = ai.get("when_to_use").and_then(|v| v.as_str()).unwrap_or("");
                if !wtu.is_empty() {
                    hints.with_when_to_use += 1;
                }

                let examples = ai
                    .get("examples")
                    .and_then(|v| v.as_array())
                    .map_or(0, Vec::len);
                if examples > 0 {
                    hints.with_examples += 1;
                }

                let mistakes = ai
                    .get("common_mistakes")
                    .and_then(|v| v.as_array())
                    .map_or(0, Vec::len);
                if mistakes > 0 {
                    hints.with_common_mistakes += 1;
                }

                let related = ai
                    .get("related")
                    .and_then(|v| v.as_array())
                    .map_or(0, Vec::len);
                if related > 0 {
                    hints.with_related += 1;
                }
            } else {
                gaps.push(ReadinessGap {
                    category: GapCategory::AgentHints,
                    severity: GapSeverity::Degraded,
                    description: format!("{op_id}: missing ai_hints section"),
                    remediation: "Add ai_hints with when_to_use and examples".into(),
                });
            }

            // Network constraints
            if let Some(nc) = op_val.get("network_constraints") {
                network.with_constraints += 1;

                let host_allow = nc
                    .get("host_allow")
                    .and_then(|v| v.as_array())
                    .map_or(0, Vec::len);
                if host_allow > 0 {
                    network.with_host_allow += 1;
                }

                let port_allow = nc
                    .get("port_allow")
                    .and_then(|v| v.as_array())
                    .map_or(0, Vec::len);
                if port_allow > 0 {
                    network.with_port_allow += 1;
                }
            }
        }

        // Compute ratios
        if ops.count > 0 {
            #[allow(clippy::cast_precision_loss)]
            let total_checks = ops.count as f64 * 8.0; // 8 checked fields per op
            #[allow(clippy::cast_precision_loss)]
            let passed = (ops.with_description
                + ops.with_input_properties
                + ops.with_output_schema
                + ops.with_capability
                + ops.with_risk_level
                + ops.with_safety_tier
                + ops.with_idempotency
                + ops.with_approval) as f64;
            ops.completeness = passed / total_checks;

            #[allow(clippy::cast_precision_loss)]
            {
                hints.coverage = hints.with_hints as f64 / ops.count as f64;
                network.coverage = network.with_constraints as f64 / ops.count as f64;
            }
        }
    } else {
        gaps.push(ReadinessGap {
            category: GapCategory::OperationMetadata,
            severity: GapSeverity::Blocking,
            description: "No operations declared in manifest".into(),
            remediation: "Add [provides.operations.*] sections to manifest.toml".into(),
        });
    }

    // ── Config audit ──
    let config = ConfigAudit {
        has_state_config: manifest
            .get("connector")
            .and_then(|c| c.get("state"))
            .is_some(),
        has_migration_hint: manifest
            .get("connector")
            .and_then(|c| c.get("state"))
            .and_then(|s| s.get("migration_hint"))
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.is_empty() && s != "init"),
    };

    // ── Events audit ──
    let events_table = manifest
        .get("provides")
        .and_then(|p| p.get("events"))
        .and_then(|e| e.as_table());
    let archetypes = manifest
        .get("connector")
        .and_then(|c| c.get("archetypes"))
        .and_then(|a| a.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
        .unwrap_or_default();
    let has_streaming_archetype = archetypes
        .iter()
        .any(|a| *a == "streaming" || *a == "bidirectional" || *a == "webhook" || *a == "polling");

    let events = EventAudit {
        event_count: events_table.map_or(0, toml::map::Map::len),
        has_event_caps: manifest.get("event_caps").is_some(),
        has_streaming_archetype,
    };

    // ── Rate limits audit ──
    let pools = manifest
        .get("rate_limits")
        .and_then(|r| r.get("pools"))
        .and_then(|p| p.as_array())
        .map_or(0, Vec::len);
    let has_op_pools = manifest
        .get("rate_limits")
        .and_then(|r| r.get("operation_pools"))
        .is_some();
    let rate_limits = RateLimitAudit {
        pool_count: pools,
        has_operation_pools: has_op_pools,
    };

    // ── Determine overall level ──
    let has_blocking = gaps.iter().any(|g| g.severity == GapSeverity::Blocking);
    let has_degraded = gaps.iter().any(|g| g.severity == GapSeverity::Degraded);
    let level = if has_blocking {
        ReadinessLevel::NotReady
    } else if has_degraded || ops.completeness < 0.9 || hints.coverage < 0.8 {
        ReadinessLevel::PartiallyReady
    } else {
        ReadinessLevel::Ready
    };

    ConnectorAudit {
        name: name.to_string(),
        crate_path: format!("connectors/{name}"),
        connector_id,
        cohort,
        level,
        has_manifest: true,
        operations: ops,
        config,
        agent_hints: hints,
        events,
        rate_limits,
        network,
        gaps,
    }
}

/// Create an audit entry for a connector with no manifest.
fn audit_missing_manifest(name: &str) -> ConnectorAudit {
    let cohort = assign_cohort(name);
    ConnectorAudit {
        name: name.to_string(),
        crate_path: format!("connectors/{name}"),
        connector_id: None,
        cohort,
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
            description: "No manifest.toml found".into(),
            remediation: "Create a manifest.toml with connector identity and operations".into(),
        }],
    }
}

/// Compute aggregate summary from individual audits.
fn compute_summary(audits: &BTreeMap<String, ConnectorAudit>) -> AuditSummary {
    let mut summary = AuditSummary::default();
    let mut completeness_sum = 0.0_f64;
    let mut coverage_sum = 0.0_f64;

    for audit in audits.values() {
        match audit.level {
            ReadinessLevel::Ready => summary.ready += 1,
            ReadinessLevel::PartiallyReady => summary.partially_ready += 1,
            ReadinessLevel::NotReady => summary.not_ready += 1,
        }

        let cohort_key = format!("{:?}", audit.cohort).to_lowercase();
        *summary.by_cohort.entry(cohort_key).or_insert(0) += 1;

        summary.total_operations += audit.operations.count;
        summary.total_gaps += audit.gaps.len();
        summary.blocking_gaps += audit
            .gaps
            .iter()
            .filter(|g| g.severity == GapSeverity::Blocking)
            .count();
        summary.degraded_gaps += audit
            .gaps
            .iter()
            .filter(|g| g.severity == GapSeverity::Degraded)
            .count();
        summary.cosmetic_gaps += audit
            .gaps
            .iter()
            .filter(|g| g.severity == GapSeverity::Cosmetic)
            .count();

        completeness_sum += audit.operations.completeness;
        coverage_sum += audit.agent_hints.coverage;
    }

    #[allow(clippy::cast_precision_loss)]
    if !audits.is_empty() {
        let count = audits.len() as f64;
        summary.mean_operation_completeness = completeness_sum / count;
        summary.mean_hint_coverage = coverage_sum / count;
    }

    summary
}

/// Run the full audit across all connector directories under `connectors_root`.
///
/// # Errors
///
/// Returns an error if the connectors root directory cannot be read.
pub fn run_audit(connectors_root: &Path) -> anyhow::Result<AuditMatrix> {
    let mut connectors = BTreeMap::new();
    let mut total = 0_usize;
    let mut with_manifest = 0_usize;
    let mut missing_manifest = 0_usize;

    let mut entries: Vec<PathBuf> = std::fs::read_dir(connectors_root)?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    entries.sort();

    for dir in &entries {
        let Some(name) = dir.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        total += 1;

        let manifest_path = dir.join("manifest.toml");
        if manifest_path.exists() {
            with_manifest += 1;
            let content = std::fs::read_to_string(&manifest_path)?;
            let manifest: toml::Value = toml::from_str(&content)?;
            let audit = audit_manifest(name, &manifest);
            connectors.insert(name.to_string(), audit);
        } else {
            missing_manifest += 1;
            connectors.insert(name.to_string(), audit_missing_manifest(name));
        }
    }

    let summary = compute_summary(&connectors);

    Ok(AuditMatrix {
        generated_at: chrono::Utc::now().to_rfc3339(),
        total_connectors: total,
        with_manifest,
        missing_manifest,
        connectors,
        summary,
    })
}

// ── Production Placeholder Inventory ────────────────────────────────────

/// High-confidence runtime placeholder classification used by the placeholder
/// inventory and later scanner/gating beads.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PlaceholderFindingKind {
    RuntimeBlocker,
    StatusDrift,
    OperatorGap,
    ScaffoldGap,
    ApprovedException,
}

/// Narrow approved exception classes for placeholder-like markers that are
/// intentionally quarantined away from runtime paths.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ApprovedPlaceholderExceptionClass {
    /// Stable exception-class identifier.
    pub id: String,
    /// Why this class is allowed to carry placeholder/stub terminology.
    pub description: String,
    /// Narrow path globs the later scanner may treat as in-class.
    pub allowed_path_globs: Vec<String>,
    /// Condition that must stay true for the class to remain approved.
    pub closure_rule: String,
    /// Bead that owns continued enforcement for this class.
    pub owner_bead: String,
}

/// One machine-checkable anchor proving a placeholder finding still exists in
/// the current workspace.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PlaceholderFindingAnchor {
    /// Repository-relative text file path.
    pub path: String,
    /// Literal snippet that should exist at the anchored path.
    pub needle: String,
}

/// One audited placeholder finding, mapped to an owner bead and closure rule.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PlaceholderInventoryFinding {
    /// Stable finding identifier.
    pub id: String,
    /// Human-readable title.
    pub title: String,
    /// Category of the gap.
    pub classification: PlaceholderFindingKind,
    /// Whether this could eventually remain as a narrow, truthful scaffold-only
    /// surface once a later bead hardens the quarantine.
    pub allowed_scaffold_candidate: bool,
    /// Approved exception class when the finding is already intentionally
    /// quarantined and allowed.
    pub approved_exception_class: Option<String>,
    /// Bead responsible for closure or quarantine.
    pub owner_bead: String,
    /// Why the current surface is incomplete or misleading.
    pub rationale: String,
    /// Expected exit path for closing or quarantining the finding.
    pub exit_strategy: String,
    /// Expected verification proof for the owning bead.
    pub verification_expectation: String,
    /// Concrete anchors that should remain detectable until the owning bead
    /// resolves the gap.
    pub anchors: Vec<PlaceholderFindingAnchor>,
}

/// The committed production-placeholder inventory consumed by this bead's scan
/// artifact and by later scanner/gating work.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProductionPlaceholderInventory {
    /// Document version for future evolution.
    pub version: u32,
    /// Timestamp when this inventory snapshot was locked.
    pub generated_at: String,
    /// Short explanation of the artifact's purpose.
    pub purpose: String,
    /// Explicit exception classes that later scanners may allow.
    pub approved_exception_classes: Vec<ApprovedPlaceholderExceptionClass>,
    /// High-confidence findings that must not be lost by mere wording changes.
    pub findings: Vec<PlaceholderInventoryFinding>,
}

/// Human-facing reduction of the inventory disposition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlaceholderFindingDisposition {
    RuntimeBlocker,
    AllowedScaffoldCandidate,
    ApprovedException,
}

/// Enforcement policy for a placeholder finding during repo-wide scans.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlaceholderFindingGate {
    FailUntilCleared,
    AllowlistedException,
}

/// Repository-relative path of the committed placeholder inventory.
#[must_use]
pub fn placeholder_inventory_path(repo_root: &Path) -> PathBuf {
    repo_root.join("docs/testing/placeholder-inventory.json")
}

/// Classify a finding into the narrow disposition the initiative cares about:
/// runtime blocker, allowed scaffold candidate, or approved exception.
#[must_use]
pub fn placeholder_finding_disposition(
    finding: &PlaceholderInventoryFinding,
) -> PlaceholderFindingDisposition {
    if finding.approved_exception_class.is_some() {
        PlaceholderFindingDisposition::ApprovedException
    } else if finding.allowed_scaffold_candidate {
        PlaceholderFindingDisposition::AllowedScaffoldCandidate
    } else {
        PlaceholderFindingDisposition::RuntimeBlocker
    }
}

/// Determine whether a finding should still fail scans or is an explicitly
/// allowlisted exception class.
#[must_use]
pub fn placeholder_finding_gate(finding: &PlaceholderInventoryFinding) -> PlaceholderFindingGate {
    if finding.approved_exception_class.is_some() {
        PlaceholderFindingGate::AllowlistedException
    } else {
        PlaceholderFindingGate::FailUntilCleared
    }
}

fn placeholder_glob_matches(pattern: &str, text: &str) -> bool {
    placeholder_glob_match_bytes(pattern.as_bytes(), text.as_bytes())
}

fn placeholder_glob_match_bytes(pattern: &[u8], text: &[u8]) -> bool {
    match (pattern.first(), text.first()) {
        (None, None) => true,
        (Some(b'*'), _) => {
            placeholder_glob_match_bytes(&pattern[1..], text)
                || (!text.is_empty() && placeholder_glob_match_bytes(pattern, &text[1..]))
        }
        (Some(b'?'), Some(_)) => placeholder_glob_match_bytes(&pattern[1..], &text[1..]),
        (Some(&expected), Some(&actual)) if expected == actual => {
            placeholder_glob_match_bytes(&pattern[1..], &text[1..])
        }
        _ => false,
    }
}

/// Check whether a repo-relative path stays inside the approved exception class
/// attached to this finding.
#[must_use]
pub fn placeholder_path_is_allowlisted(
    inventory: &ProductionPlaceholderInventory,
    finding: &PlaceholderInventoryFinding,
    path: &str,
) -> bool {
    let Some(class_id) = finding.approved_exception_class.as_deref() else {
        return false;
    };
    inventory
        .approved_exception_classes
        .iter()
        .find(|class| class.id == class_id)
        .is_some_and(|class| {
            class
                .allowed_path_globs
                .iter()
                .any(|pattern| placeholder_glob_matches(pattern, path))
        })
}

/// Load and structurally validate the committed production-placeholder
/// inventory.
///
/// # Errors
///
/// Returns an error if the JSON cannot be parsed or if the document fails the
/// structural invariants expected by the scanner/gating workflow.
pub fn load_placeholder_inventory(
    repo_root: &Path,
) -> anyhow::Result<ProductionPlaceholderInventory> {
    let path = placeholder_inventory_path(repo_root);
    let raw = std::fs::read_to_string(&path).map_err(|error| {
        anyhow::anyhow!(
            "failed to read placeholder inventory `{}`: {error}",
            path.display()
        )
    })?;
    let inventory: ProductionPlaceholderInventory =
        serde_json::from_str(&raw).map_err(|error| {
            anyhow::anyhow!(
                "failed to parse placeholder inventory `{}`: {error}",
                path.display()
            )
        })?;
    validate_placeholder_inventory_structure(&inventory)?;
    Ok(inventory)
}

fn validate_non_empty(label: &str, value: &str) -> anyhow::Result<()> {
    if value.trim().is_empty() {
        anyhow::bail!("{label} must not be empty");
    }
    Ok(())
}

/// Validate the committed inventory against structural invariants.
///
/// # Errors
///
/// Returns an error if the inventory is malformed, too broad, or internally
/// inconsistent.
fn validate_placeholder_inventory_structure(
    inventory: &ProductionPlaceholderInventory,
) -> anyhow::Result<()> {
    if inventory.version != 1 {
        anyhow::bail!(
            "unsupported placeholder inventory version {}; expected 1",
            inventory.version
        );
    }
    validate_non_empty("inventory.generated_at", &inventory.generated_at)?;
    validate_non_empty("inventory.purpose", &inventory.purpose)?;
    if inventory.findings.is_empty() {
        anyhow::bail!("placeholder inventory must contain at least one finding");
    }
    if inventory.approved_exception_classes.len() > 5 {
        anyhow::bail!(
            "approved exception classes must stay intentionally narrow; found {}",
            inventory.approved_exception_classes.len()
        );
    }

    let mut exception_class_ids = BTreeSet::new();
    for class in &inventory.approved_exception_classes {
        validate_non_empty("approved_exception_classes.id", &class.id)?;
        validate_non_empty("approved_exception_classes.description", &class.description)?;
        validate_non_empty(
            "approved_exception_classes.closure_rule",
            &class.closure_rule,
        )?;
        validate_non_empty("approved_exception_classes.owner_bead", &class.owner_bead)?;
        if class.allowed_path_globs.is_empty() {
            anyhow::bail!(
                "approved exception class `{}` must declare at least one allowed path glob",
                class.id
            );
        }
        for glob in &class.allowed_path_globs {
            validate_non_empty("approved_exception_classes.allowed_path_globs", glob)?;
        }
        if !exception_class_ids.insert(class.id.clone()) {
            anyhow::bail!("duplicate approved exception class `{}`", class.id);
        }
    }

    let mut finding_ids = BTreeSet::new();
    let mut anchor_pairs = BTreeSet::new();

    for finding in &inventory.findings {
        validate_non_empty("findings.id", &finding.id)?;
        validate_non_empty("findings.title", &finding.title)?;
        validate_non_empty("findings.owner_bead", &finding.owner_bead)?;
        validate_non_empty("findings.rationale", &finding.rationale)?;
        validate_non_empty("findings.exit_strategy", &finding.exit_strategy)?;
        validate_non_empty(
            "findings.verification_expectation",
            &finding.verification_expectation,
        )?;
        if !finding.owner_bead.starts_with("flywheel_connectors-") {
            anyhow::bail!(
                "finding `{}` has unexpected owner bead `{}`",
                finding.id,
                finding.owner_bead
            );
        }
        if !finding_ids.insert(finding.id.clone()) {
            anyhow::bail!("duplicate placeholder finding `{}`", finding.id);
        }
        if finding.anchors.is_empty() {
            anyhow::bail!("finding `{}` must declare at least one anchor", finding.id);
        }
        if let Some(class_id) = &finding.approved_exception_class {
            if !finding.allowed_scaffold_candidate {
                anyhow::bail!(
                    "finding `{}` declares approved exception class `{class_id}` but is not marked as an allowed scaffold candidate",
                    finding.id
                );
            }
            if !exception_class_ids.contains(class_id) {
                anyhow::bail!(
                    "finding `{}` references unknown approved exception class `{class_id}`",
                    finding.id
                );
            }
        }

        for anchor in &finding.anchors {
            validate_non_empty("anchors.path", &anchor.path)?;
            validate_non_empty("anchors.needle", &anchor.needle)?;
            let key = format!("{}::{}", anchor.path, anchor.needle);
            if !anchor_pairs.insert(key) {
                anyhow::bail!(
                    "duplicate anchor path/needle pair for finding `{}` at `{}`",
                    finding.id,
                    anchor.path
                );
            }
        }
    }

    Ok(())
}

/// Validate the committed inventory against both structural and workspace-local
/// invariants.
///
/// # Errors
///
/// Returns an error if the inventory is malformed, too broad, or points at
/// anchors that no longer exist in the repository.
pub fn validate_placeholder_inventory(
    repo_root: &Path,
    inventory: &ProductionPlaceholderInventory,
) -> anyhow::Result<()> {
    validate_placeholder_inventory_structure(inventory)?;

    for finding in &inventory.findings {
        for anchor in &finding.anchors {
            let absolute_path = repo_root.join(&anchor.path);
            if !absolute_path.is_file() {
                anyhow::bail!(
                    "finding `{}` points at missing anchor path `{}`",
                    finding.id,
                    anchor.path
                );
            }
            let contents = std::fs::read_to_string(&absolute_path).map_err(|error| {
                anyhow::anyhow!(
                    "failed to read anchor `{}` for finding `{}`: {error}",
                    anchor.path,
                    finding.id
                )
            })?;
            if !contents.contains(&anchor.needle) {
                anyhow::bail!(
                    "finding `{}` anchor `{}` no longer contains expected needle `{}`",
                    finding.id,
                    anchor.path,
                    anchor.needle
                );
            }
        }
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Cohort assignment ──

    #[test]
    fn cohort_messaging() {
        assert_eq!(assign_cohort("slack"), ConnectorCohort::Messaging);
        assert_eq!(assign_cohort("discord"), ConnectorCohort::Messaging);
        assert_eq!(assign_cohort("telegram"), ConnectorCohort::Messaging);
        assert_eq!(assign_cohort("twilio"), ConnectorCohort::Messaging);
    }

    #[test]
    fn cohort_social() {
        assert_eq!(assign_cohort("twitter"), ConnectorCohort::Social);
        assert_eq!(assign_cohort("reddit"), ConnectorCohort::Social);
        assert_eq!(assign_cohort("linkedin"), ConnectorCohort::Social);
    }

    #[test]
    fn cohort_devtools() {
        assert_eq!(assign_cohort("github"), ConnectorCohort::DevTools);
        assert_eq!(assign_cohort("gitlab"), ConnectorCohort::DevTools);
        assert_eq!(assign_cohort("sentry"), ConnectorCohort::DevTools);
    }

    #[test]
    fn cohort_productivity() {
        assert_eq!(assign_cohort("notion"), ConnectorCohort::Productivity);
        assert_eq!(assign_cohort("jira"), ConnectorCohort::Productivity);
        assert_eq!(assign_cohort("todoist"), ConnectorCohort::Productivity);
    }

    #[test]
    fn cohort_ai() {
        assert_eq!(assign_cohort("openai"), ConnectorCohort::Ai);
        assert_eq!(assign_cohort("anthropic"), ConnectorCohort::Ai);
        assert_eq!(assign_cohort("whisper"), ConnectorCohort::Ai);
    }

    #[test]
    fn cohort_data() {
        assert_eq!(assign_cohort("elasticsearch"), ConnectorCohort::Data);
        assert_eq!(assign_cohort("redis"), ConnectorCohort::Data);
        assert_eq!(assign_cohort("postgresql"), ConnectorCohort::Data);
    }

    #[test]
    fn cohort_analytics() {
        assert_eq!(assign_cohort("amplitude"), ConnectorCohort::Analytics);
        assert_eq!(assign_cohort("mixpanel"), ConnectorCohort::Analytics);
    }

    #[test]
    fn cohort_infra() {
        assert_eq!(assign_cohort("kubernetes"), ConnectorCohort::Infra);
        assert_eq!(assign_cohort("terraform"), ConnectorCohort::Infra);
    }

    #[test]
    fn cohort_automation() {
        assert_eq!(assign_cohort("zapier"), ConnectorCohort::Automation);
        assert_eq!(assign_cohort("n8n"), ConnectorCohort::Automation);
        assert_eq!(assign_cohort("cron"), ConnectorCohort::Automation);
    }

    #[test]
    fn cohort_storage() {
        assert_eq!(assign_cohort("s3"), ConnectorCohort::Storage);
        assert_eq!(assign_cohort("dropbox"), ConnectorCohort::Storage);
    }

    #[test]
    fn cohort_security() {
        assert_eq!(assign_cohort("1password"), ConnectorCohort::Security);
        assert_eq!(assign_cohort("bitwarden"), ConnectorCohort::Security);
    }

    #[test]
    fn cohort_business() {
        assert_eq!(assign_cohort("stripe"), ConnectorCohort::Business);
        assert_eq!(assign_cohort("salesforce"), ConnectorCohort::Business);
    }

    #[test]
    fn cohort_unknown_is_other() {
        assert_eq!(assign_cohort("unknown-xyz"), ConnectorCohort::Other);
    }

    // ── Missing manifest ──

    #[test]
    fn missing_manifest_is_not_ready() {
        let audit = audit_missing_manifest("redis");
        assert_eq!(audit.level, ReadinessLevel::NotReady);
        assert!(!audit.has_manifest);
        assert_eq!(audit.gaps.len(), 1);
        assert_eq!(audit.gaps[0].severity, GapSeverity::Blocking);
        assert_eq!(audit.gaps[0].category, GapCategory::Identity);
    }

    #[test]
    fn missing_manifest_preserves_name_and_path() {
        let audit = audit_missing_manifest("postgresql");
        assert_eq!(audit.name, "postgresql");
        assert_eq!(audit.crate_path, "connectors/postgresql");
        assert!(audit.connector_id.is_none());
    }

    // ── Manifest parsing ──

    fn minimal_manifest() -> toml::Value {
        let s = r#"
[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"

[connector]
id = "fcp.test"
name = "Test Connector"
version = "0.1.0"
description = "A test connector"
archetypes = ["operational"]
format = "wasi"

[connector.state]
model = "singleton_writer"
state_schema_version = "1"
migration_hint = "init"

[zones]
home = "z:work"
allowed_sources = ["z:owner"]
allowed_targets = ["z:work"]
forbidden = []

[capabilities]
required = ["network.dns"]
optional = []
forbidden = []

[provides.operations."test.get_item"]
description = "Get an item"
capability = "test.read"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "strict"

[provides.operations."test.get_item".input_schema]
type = "object"
required = ["id"]
[provides.operations."test.get_item".input_schema.properties.id]
type = "string"

[provides.operations."test.get_item".output_schema]
type = "object"
required = ["item"]
[provides.operations."test.get_item".output_schema.properties.item]
type = "object"

[provides.operations."test.get_item".network_constraints]
host_allow = ["api.test.com"]
port_allow = [443]
deny_localhost = true
deny_private_ranges = true

[provides.operations."test.get_item".ai_hints]
when_to_use = "Get an item by ID."
common_mistakes = ["Using wrong ID format"]
examples = ['{"id": "abc123"}']
related = ["test.list_items"]
"#;
        toml::from_str(s).unwrap()
    }

    #[test]
    fn full_manifest_is_ready() {
        let manifest = minimal_manifest();
        let audit = audit_manifest("test", &manifest);
        assert_eq!(audit.level, ReadinessLevel::Ready);
        assert!(audit.has_manifest);
        assert_eq!(audit.connector_id.as_deref(), Some("fcp.test"));
    }

    #[test]
    fn operations_count_matches() {
        let manifest = minimal_manifest();
        let audit = audit_manifest("test", &manifest);
        assert_eq!(audit.operations.count, 1);
        assert_eq!(audit.operations.with_description, 1);
        assert_eq!(audit.operations.with_capability, 1);
        assert_eq!(audit.operations.with_risk_level, 1);
        assert_eq!(audit.operations.with_safety_tier, 1);
    }

    #[test]
    fn input_properties_detected() {
        let manifest = minimal_manifest();
        let audit = audit_manifest("test", &manifest);
        assert_eq!(audit.operations.with_input_properties, 1);
    }

    #[test]
    fn output_schema_detected() {
        let manifest = minimal_manifest();
        let audit = audit_manifest("test", &manifest);
        assert_eq!(audit.operations.with_output_schema, 1);
    }

    #[test]
    fn ai_hints_detected() {
        let manifest = minimal_manifest();
        let audit = audit_manifest("test", &manifest);
        assert_eq!(audit.agent_hints.with_hints, 1);
        assert_eq!(audit.agent_hints.with_when_to_use, 1);
        assert_eq!(audit.agent_hints.with_examples, 1);
        assert_eq!(audit.agent_hints.with_common_mistakes, 1);
        assert_eq!(audit.agent_hints.with_related, 1);
        assert!((audit.agent_hints.coverage - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn network_constraints_detected() {
        let manifest = minimal_manifest();
        let audit = audit_manifest("test", &manifest);
        assert_eq!(audit.network.with_constraints, 1);
        assert_eq!(audit.network.with_host_allow, 1);
        assert_eq!(audit.network.with_port_allow, 1);
    }

    #[test]
    fn config_state_detected() {
        let manifest = minimal_manifest();
        let audit = audit_manifest("test", &manifest);
        assert!(audit.config.has_state_config);
    }

    #[test]
    fn migration_hint_init_is_not_meaningful() {
        let manifest = minimal_manifest();
        let audit = audit_manifest("test", &manifest);
        // "init" is the default, not a real migration hint
        assert!(!audit.config.has_migration_hint);
    }

    // ── Gap detection ──

    fn manifest_missing_description() -> toml::Value {
        let s = r#"
[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"

[connector]
id = "fcp.bad"
name = "Bad"
version = "0.1.0"
description = "Bad connector"
archetypes = ["operational"]
format = "wasi"

[provides.operations."bad.op"]
description = ""
capability = "bad.read"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "strict"

[provides.operations."bad.op".input_schema]
type = "object"
[provides.operations."bad.op".output_schema]
type = "object"

[provides.operations."bad.op".network_constraints]
host_allow = ["api.bad.com"]
port_allow = [443]

[provides.operations."bad.op".ai_hints]
when_to_use = "Do bad things"
common_mistakes = []
examples = []
related = []
"#;
        toml::from_str(s).unwrap()
    }

    #[test]
    fn empty_description_creates_blocking_gap() {
        let manifest = manifest_missing_description();
        let audit = audit_manifest("bad", &manifest);
        assert_eq!(audit.operations.with_description, 0);
        let desc_gaps: Vec<_> = audit
            .gaps
            .iter()
            .filter(|g| g.description.contains("description"))
            .collect();
        assert_eq!(desc_gaps.len(), 1);
        assert_eq!(desc_gaps[0].severity, GapSeverity::Blocking);
    }

    fn manifest_no_hints() -> toml::Value {
        let s = r#"
[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"

[connector]
id = "fcp.nohints"
name = "NoHints"
version = "0.1.0"
description = "No hints connector"
archetypes = ["operational"]
format = "wasi"

[provides.operations."nohints.op"]
description = "An operation"
capability = "nohints.read"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "strict"

[provides.operations."nohints.op".input_schema]
type = "object"
required = ["id"]
[provides.operations."nohints.op".input_schema.properties.id]
type = "string"

[provides.operations."nohints.op".output_schema]
type = "object"
required = ["result"]

[provides.operations."nohints.op".network_constraints]
host_allow = ["api.nohints.com"]
port_allow = [443]
"#;
        toml::from_str(s).unwrap()
    }

    #[test]
    fn missing_ai_hints_creates_degraded_gap() {
        let manifest = manifest_no_hints();
        let audit = audit_manifest("nohints", &manifest);
        assert_eq!(audit.agent_hints.with_hints, 0);
        let hint_gaps: Vec<_> = audit
            .gaps
            .iter()
            .filter(|g| g.category == GapCategory::AgentHints)
            .collect();
        assert_eq!(hint_gaps.len(), 1);
        assert_eq!(hint_gaps[0].severity, GapSeverity::Degraded);
    }

    #[test]
    fn missing_hints_makes_partially_ready() {
        let manifest = manifest_no_hints();
        let audit = audit_manifest("nohints", &manifest);
        // Degraded gap → PartiallyReady
        assert_eq!(audit.level, ReadinessLevel::PartiallyReady);
    }

    fn manifest_no_ops() -> toml::Value {
        let s = r#"
[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"

[connector]
id = "fcp.empty"
name = "Empty"
version = "0.1.0"
description = "Empty connector"
archetypes = ["operational"]
format = "wasi"
"#;
        toml::from_str(s).unwrap()
    }

    #[test]
    fn no_operations_creates_blocking_gap() {
        let manifest = manifest_no_ops();
        let audit = audit_manifest("empty", &manifest);
        assert_eq!(audit.operations.count, 0);
        assert_eq!(audit.level, ReadinessLevel::NotReady);
        assert_eq!(
            audit
                .gaps
                .iter()
                .filter(|g| g.description.contains("No operations"))
                .count(),
            1
        );
    }

    fn manifest_missing_capability() -> toml::Value {
        let s = r#"
[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"

[connector]
id = "fcp.nocap"
name = "NoCap"
version = "0.1.0"
description = "No cap connector"
archetypes = ["operational"]
format = "wasi"

[provides.operations."nocap.op"]
description = "An operation"
risk_level = "low"
safety_tier = "safe"

[provides.operations."nocap.op".input_schema]
type = "object"
[provides.operations."nocap.op".output_schema]
type = "object"

[provides.operations."nocap.op".ai_hints]
when_to_use = "Do something"
common_mistakes = []
examples = ['{}']
related = []

[provides.operations."nocap.op".network_constraints]
host_allow = ["api.nocap.com"]
port_allow = [443]
"#;
        toml::from_str(s).unwrap()
    }

    #[test]
    fn missing_capability_creates_blocking_gap() {
        let manifest = manifest_missing_capability();
        let audit = audit_manifest("nocap", &manifest);
        assert_eq!(audit.operations.with_capability, 0);
        let cap_gaps: Vec<_> = audit
            .gaps
            .iter()
            .filter(|g| g.description.contains("capability"))
            .collect();
        assert_eq!(cap_gaps.len(), 1);
        assert_eq!(cap_gaps[0].severity, GapSeverity::Blocking);
    }

    // ── Completeness ratios ──

    #[test]
    fn full_manifest_completeness_is_one() {
        let manifest = minimal_manifest();
        let audit = audit_manifest("test", &manifest);
        assert!((audit.operations.completeness - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn hint_coverage_zero_when_no_hints() {
        let manifest = manifest_no_hints();
        let audit = audit_manifest("nohints", &manifest);
        assert!(audit.agent_hints.coverage.abs() < f64::EPSILON);
    }

    #[test]
    fn network_coverage_one_when_all_have_constraints() {
        let manifest = minimal_manifest();
        let audit = audit_manifest("test", &manifest);
        assert!((audit.network.coverage - 1.0).abs() < f64::EPSILON);
    }

    // ── Event detection ──

    fn manifest_with_streaming() -> toml::Value {
        let s = r#"
[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"

[connector]
id = "fcp.streamer"
name = "Streamer"
version = "0.1.0"
description = "Streaming connector"
archetypes = ["operational", "streaming"]
format = "wasi"

[event_caps]
streaming = true
replay = false

[provides.operations."streamer.listen"]
description = "Listen for events"
capability = "streamer.read"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "strict"

[provides.operations."streamer.listen".input_schema]
type = "object"
required = ["channel"]
[provides.operations."streamer.listen".input_schema.properties.channel]
type = "string"

[provides.operations."streamer.listen".output_schema]
type = "object"
required = ["events"]

[provides.operations."streamer.listen".network_constraints]
host_allow = ["api.streamer.com"]
port_allow = [443]

[provides.operations."streamer.listen".ai_hints]
when_to_use = "Listen for streaming events."
common_mistakes = []
examples = ['{"channel": "main"}']
related = []

[provides.events."streamer.message"]
description = "New message event"
streaming = true
replay = false
"#;
        toml::from_str(s).unwrap()
    }

    #[test]
    fn streaming_archetype_detected() {
        let manifest = manifest_with_streaming();
        let audit = audit_manifest("streamer", &manifest);
        assert!(audit.events.has_streaming_archetype);
        assert!(audit.events.has_event_caps);
        assert_eq!(audit.events.event_count, 1);
    }

    #[test]
    fn non_streaming_has_no_event_caps() {
        let manifest = minimal_manifest();
        let audit = audit_manifest("test", &manifest);
        assert!(!audit.events.has_streaming_archetype);
        assert!(!audit.events.has_event_caps);
        assert_eq!(audit.events.event_count, 0);
    }

    // ── Summary computation ──

    #[test]
    fn summary_counts_levels() {
        let mut map = BTreeMap::new();
        map.insert("a".into(), audit_manifest("a", &minimal_manifest()));
        map.insert("b".into(), audit_missing_manifest("b"));
        map.insert("c".into(), audit_manifest("c", &manifest_no_hints()));

        let summary = compute_summary(&map);
        assert_eq!(summary.ready, 1);
        assert_eq!(summary.partially_ready, 1);
        assert_eq!(summary.not_ready, 1);
    }

    #[test]
    fn summary_total_operations() {
        let mut map = BTreeMap::new();
        map.insert("a".into(), audit_manifest("a", &minimal_manifest()));
        map.insert("b".into(), audit_manifest("b", &minimal_manifest()));

        let summary = compute_summary(&map);
        assert_eq!(summary.total_operations, 2); // 1 op each
    }

    #[test]
    fn summary_gap_counts() {
        let mut map = BTreeMap::new();
        map.insert("a".into(), audit_missing_manifest("a")); // 1 blocking
        map.insert("b".into(), audit_manifest("b", &manifest_no_hints())); // 1 degraded

        let summary = compute_summary(&map);
        assert_eq!(summary.blocking_gaps, 1);
        assert_eq!(summary.degraded_gaps, 1);
    }

    #[test]
    fn summary_mean_completeness() {
        let mut map = BTreeMap::new();
        map.insert("a".into(), audit_manifest("a", &minimal_manifest()));
        map.insert("b".into(), audit_manifest("b", &minimal_manifest()));

        let summary = compute_summary(&map);
        assert!((summary.mean_operation_completeness - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn summary_by_cohort() {
        let mut map = BTreeMap::new();
        map.insert(
            "github".into(),
            audit_manifest("github", &minimal_manifest()),
        );
        map.insert(
            "gitlab".into(),
            audit_manifest("gitlab", &minimal_manifest()),
        );
        map.insert("slack".into(), audit_manifest("slack", &minimal_manifest()));

        let summary = compute_summary(&map);
        assert_eq!(summary.by_cohort.get("devtools"), Some(&2));
        assert_eq!(summary.by_cohort.get("messaging"), Some(&1));
    }

    // ── Filesystem audit ──

    #[test]
    fn run_audit_on_real_connectors() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../connectors");
        if !root.exists() {
            return; // Skip if not in workspace
        }

        let matrix = run_audit(&root).unwrap();
        // We have at least 80 connectors
        assert!(matrix.total_connectors >= 80);
        // At least 78 should have manifests
        assert!(matrix.with_manifest >= 78);
        // Every connector should appear in the map
        assert_eq!(matrix.connectors.len(), matrix.total_connectors);
        // Summary levels should sum to total
        assert_eq!(
            matrix.summary.ready + matrix.summary.partially_ready + matrix.summary.not_ready,
            matrix.total_connectors,
        );
    }

    #[test]
    fn run_audit_github_is_ready() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../connectors");
        if !root.exists() {
            return;
        }

        let matrix = run_audit(&root).unwrap();
        let github = matrix.connectors.get("github").expect("github not found");
        assert!(github.has_manifest);
        assert_eq!(github.connector_id.as_deref(), Some("fcp.github"));
        assert_eq!(github.cohort, ConnectorCohort::DevTools);
        assert!(github.operations.count >= 10);
    }

    #[test]
    fn run_audit_all_connectors_have_entries() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../connectors");
        if !root.exists() {
            return;
        }

        let matrix = run_audit(&root).unwrap();
        // Every connector dir appears in the matrix
        assert_eq!(matrix.connectors.len(), matrix.total_connectors);
        // Manifest counts add up
        assert_eq!(
            matrix.with_manifest + matrix.missing_manifest,
            matrix.total_connectors,
        );
        // Any connector without a manifest is NotReady
        for audit in matrix.connectors.values() {
            if !audit.has_manifest {
                assert_eq!(audit.level, ReadinessLevel::NotReady);
            }
        }
    }

    #[test]
    fn run_audit_nonexistent_dir() {
        let result = run_audit(Path::new("/nonexistent/path"));
        assert!(result.is_err());
    }

    // ── Serialization ──

    #[test]
    fn audit_matrix_serializes_to_json() {
        let mut connectors = BTreeMap::new();
        connectors.insert("test".into(), audit_manifest("test", &minimal_manifest()));

        let matrix = AuditMatrix {
            generated_at: "2026-03-08T00:00:00Z".into(),
            total_connectors: 1,
            with_manifest: 1,
            missing_manifest: 0,
            connectors,
            summary: AuditSummary::default(),
        };

        let json = serde_json::to_string_pretty(&matrix).unwrap();
        assert!(json.contains("test"));
        assert!(json.contains("generated_at"));
    }

    #[test]
    fn connector_audit_serializes_all_fields() {
        let audit = audit_manifest("test", &minimal_manifest());
        let json = serde_json::to_string(&audit).unwrap();
        assert!(json.contains("operations"));
        assert!(json.contains("agent_hints"));
        assert!(json.contains("network"));
        assert!(json.contains("rate_limits"));
        assert!(json.contains("config"));
        assert!(json.contains("events"));
        assert!(json.contains("gaps"));
    }

    // ── Multiple operations ──

    fn manifest_multi_ops() -> toml::Value {
        let s = r#"
[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"

[connector]
id = "fcp.multi"
name = "Multi"
version = "0.1.0"
description = "Multi-op connector"
archetypes = ["operational"]
format = "wasi"

[provides.operations."multi.read"]
description = "Read something"
capability = "multi.read"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "strict"

[provides.operations."multi.read".input_schema]
type = "object"
required = ["id"]
[provides.operations."multi.read".input_schema.properties.id]
type = "string"
[provides.operations."multi.read".output_schema]
type = "object"
required = ["data"]
[provides.operations."multi.read".network_constraints]
host_allow = ["api.multi.com"]
port_allow = [443]
[provides.operations."multi.read".ai_hints]
when_to_use = "Read a resource."
common_mistakes = []
examples = ['{"id": "123"}']
related = ["multi.write"]

[provides.operations."multi.write"]
description = "Write something"
capability = "multi.write"
risk_level = "medium"
safety_tier = "risky"
requires_approval = "policy"
idempotency = "none"

[provides.operations."multi.write".input_schema]
type = "object"
required = ["id", "data"]
[provides.operations."multi.write".input_schema.properties.id]
type = "string"
[provides.operations."multi.write".input_schema.properties.data]
type = "object"
[provides.operations."multi.write".output_schema]
type = "object"
required = ["result"]
[provides.operations."multi.write".network_constraints]
host_allow = ["api.multi.com"]
port_allow = [443]
[provides.operations."multi.write".ai_hints]
when_to_use = "Write a resource."
common_mistakes = ["Forgetting data field"]
examples = ['{"id": "123", "data": {"key": "value"}}']
related = ["multi.read"]

[provides.operations."multi.delete"]
description = "Delete something"
capability = "multi.write"
risk_level = "high"
safety_tier = "dangerous"
requires_approval = "interactive"
idempotency = "best_effort"

[provides.operations."multi.delete".input_schema]
type = "object"
required = ["id"]
[provides.operations."multi.delete".input_schema.properties.id]
type = "string"
[provides.operations."multi.delete".output_schema]
type = "object"
required = ["deleted"]
[provides.operations."multi.delete".network_constraints]
host_allow = ["api.multi.com"]
port_allow = [443]
[provides.operations."multi.delete".ai_hints]
when_to_use = "Delete a resource permanently."
common_mistakes = ["Not verifying the ID before deletion"]
examples = ['{"id": "123"}']
related = ["multi.read"]
"#;
        toml::from_str(s).unwrap()
    }

    #[test]
    fn multi_op_manifest_counts_correctly() {
        let manifest = manifest_multi_ops();
        let audit = audit_manifest("multi", &manifest);
        assert_eq!(audit.operations.count, 3);
        assert_eq!(audit.operations.with_description, 3);
        assert_eq!(audit.operations.with_capability, 3);
        assert_eq!(audit.operations.with_risk_level, 3);
        assert_eq!(audit.operations.with_safety_tier, 3);
        assert_eq!(audit.operations.with_idempotency, 3);
        assert_eq!(audit.operations.with_approval, 3);
    }

    #[test]
    fn multi_op_all_have_hints() {
        let manifest = manifest_multi_ops();
        let audit = audit_manifest("multi", &manifest);
        assert_eq!(audit.agent_hints.with_hints, 3);
        assert_eq!(audit.agent_hints.with_when_to_use, 3);
        assert_eq!(audit.agent_hints.with_examples, 3);
    }

    #[test]
    fn multi_op_completeness_is_one() {
        let manifest = manifest_multi_ops();
        let audit = audit_manifest("multi", &manifest);
        assert!((audit.operations.completeness - 1.0).abs() < f64::EPSILON);
        assert_eq!(audit.level, ReadinessLevel::Ready);
    }

    #[test]
    fn multi_op_all_have_network() {
        let manifest = manifest_multi_ops();
        let audit = audit_manifest("multi", &manifest);
        assert_eq!(audit.network.with_constraints, 3);
        assert!((audit.network.coverage - 1.0).abs() < f64::EPSILON);
    }

    // ── Rate limit detection ──

    fn manifest_with_rate_limits() -> toml::Value {
        let s = r#"
[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"

[connector]
id = "fcp.rated"
name = "Rated"
version = "0.1.0"
description = "Rate-limited connector"
archetypes = ["operational"]
format = "wasi"

[provides.operations."rated.op"]
description = "A rate-limited operation"
capability = "rated.read"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "strict"
[provides.operations."rated.op".input_schema]
type = "object"
[provides.operations."rated.op".output_schema]
type = "object"
[provides.operations."rated.op".network_constraints]
host_allow = ["api.rated.com"]
port_allow = [443]
[provides.operations."rated.op".ai_hints]
when_to_use = "A rated operation."
common_mistakes = []
examples = ['{}']
related = []

[[rate_limits.pools]]
id = "rated.read"
requests = 100
window_ms = 60000
burst = 10
scope = "instance"

[rate_limits.operation_pools]
"rated.op" = ["rated.read"]
"#;
        toml::from_str(s).unwrap()
    }

    #[test]
    fn rate_limits_detected() {
        let manifest = manifest_with_rate_limits();
        let audit = audit_manifest("rated", &manifest);
        assert_eq!(audit.rate_limits.pool_count, 1);
        assert!(audit.rate_limits.has_operation_pools);
    }

    #[test]
    fn no_rate_limits_is_zero() {
        let manifest = minimal_manifest();
        let audit = audit_manifest("test", &manifest);
        assert_eq!(audit.rate_limits.pool_count, 0);
        assert!(!audit.rate_limits.has_operation_pools);
    }

    // ── Additional cohort assignment tests ─────────────────────────

    #[test]
    fn cohort_workspace() {
        assert_eq!(assign_cohort("microsoft365"), ConnectorCohort::Workspace);
        assert_eq!(assign_cohort("google-calendar"), ConnectorCohort::Workspace);
        assert_eq!(assign_cohort("gmail"), ConnectorCohort::Workspace);
    }

    #[test]
    fn cohort_knowledge() {
        assert_eq!(assign_cohort("arxiv"), ConnectorCohort::Knowledge);
        assert_eq!(assign_cohort("semanticscholar"), ConnectorCohort::Knowledge);
        assert_eq!(assign_cohort("wikipedia"), ConnectorCohort::Knowledge);
        assert_eq!(assign_cohort("logseq"), ConnectorCohort::Knowledge);
    }

    #[test]
    fn cohort_media() {
        assert_eq!(assign_cohort("youtube"), ConnectorCohort::Media);
        assert_eq!(assign_cohort("spotify"), ConnectorCohort::Media);
    }

    #[test]
    fn cohort_browser() {
        assert_eq!(assign_cohort("browser"), ConnectorCohort::Browser);
        assert_eq!(assign_cohort("algolia"), ConnectorCohort::Browser);
        assert_eq!(assign_cohort("annas-archive"), ConnectorCohort::Browser);
    }

    #[test]
    fn cohort_vectordb() {
        assert_eq!(assign_cohort("pinecone"), ConnectorCohort::Vectordb);
        assert_eq!(assign_cohort("qdrant"), ConnectorCohort::Vectordb);
        assert_eq!(assign_cohort("vectordb"), ConnectorCohort::Vectordb);
    }

    #[test]
    fn cohort_iot() {
        assert_eq!(assign_cohort("homeassistant"), ConnectorCohort::Iot);
    }

    #[test]
    fn cohort_full_messaging_list() {
        for name in ["sendgrid", "mailchimp", "intercom"] {
            assert_eq!(
                assign_cohort(name),
                ConnectorCohort::Messaging,
                "failed for {name}"
            );
        }
    }

    #[test]
    fn cohort_full_devtools_list() {
        for name in [
            "github",
            "gitlab",
            "bitbucket",
            "sentry",
            "grafana",
            "datadog",
        ] {
            assert_eq!(
                assign_cohort(name),
                ConnectorCohort::DevTools,
                "failed for {name}"
            );
        }
    }

    #[test]
    fn cohort_full_productivity_list() {
        for name in [
            "notion", "asana", "trello", "todoist", "clickup", "monday", "figma", "jira", "linear",
        ] {
            assert_eq!(
                assign_cohort(name),
                ConnectorCohort::Productivity,
                "failed for {name}"
            );
        }
    }

    #[test]
    fn cohort_full_automation_list() {
        for name in [
            "zapier",
            "make",
            "n8n",
            "retool",
            "metabase",
            "cron",
            "webhook-receiver",
            "mcp-bridge",
        ] {
            assert_eq!(
                assign_cohort(name),
                ConnectorCohort::Automation,
                "failed for {name}"
            );
        }
    }

    #[test]
    fn cohort_full_data_list() {
        for name in [
            "elasticsearch",
            "bigquery",
            "snowflake",
            "duckdb",
            "mongodb",
            "postgresql",
            "redis",
        ] {
            assert_eq!(
                assign_cohort(name),
                ConnectorCohort::Data,
                "failed for {name}"
            );
        }
    }

    #[test]
    fn cohort_full_analytics_list() {
        for name in ["posthog", "mixpanel", "amplitude", "segment"] {
            assert_eq!(
                assign_cohort(name),
                ConnectorCohort::Analytics,
                "failed for {name}"
            );
        }
    }

    #[test]
    fn cohort_full_business_list() {
        for name in [
            "stripe",
            "plaid",
            "salesforce",
            "hubspot",
            "docusign",
            "pandadoc",
        ] {
            assert_eq!(
                assign_cohort(name),
                ConnectorCohort::Business,
                "failed for {name}"
            );
        }
    }

    #[test]
    fn cohort_full_infra_list() {
        for name in ["kubernetes", "terraform", "pulumi"] {
            assert_eq!(
                assign_cohort(name),
                ConnectorCohort::Infra,
                "failed for {name}"
            );
        }
    }

    #[test]
    fn cohort_full_ai_list() {
        for name in ["openai", "anthropic", "google-ai", "llm-router", "whisper"] {
            assert_eq!(
                assign_cohort(name),
                ConnectorCohort::Ai,
                "failed for {name}"
            );
        }
    }

    // ── Additional missing manifest tests ──────────────────────────

    #[test]
    fn missing_manifest_default_audit_fields() {
        let audit = audit_missing_manifest("test");
        assert_eq!(audit.operations.count, 0);
        assert!(!audit.config.has_state_config);
        assert!(!audit.config.has_migration_hint);
        assert_eq!(audit.events.event_count, 0);
        assert!(!audit.events.has_event_caps);
        assert_eq!(audit.rate_limits.pool_count, 0);
        assert!(!audit.rate_limits.has_operation_pools);
        assert_eq!(audit.agent_hints.with_hints, 0);
        assert_eq!(audit.network.with_constraints, 0);
    }

    #[test]
    fn missing_manifest_assigns_cohort() {
        let audit = audit_missing_manifest("github");
        assert_eq!(audit.cohort, ConnectorCohort::DevTools);
        let audit2 = audit_missing_manifest("slack");
        assert_eq!(audit2.cohort, ConnectorCohort::Messaging);
    }

    #[test]
    fn missing_manifest_gap_remediation() {
        let audit = audit_missing_manifest("x");
        assert!(audit.gaps[0].remediation.contains("manifest.toml"));
    }

    // ── Additional manifest audit edge cases ───────────────────────

    #[test]
    fn manifest_with_meaningful_migration_hint() {
        let s = r#"
[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"

[connector]
id = "fcp.test"
name = "Test"
version = "0.1.0"
description = "Test"
archetypes = ["operational"]
format = "wasi"

[connector.state]
model = "singleton_writer"
state_schema_version = "1"
migration_hint = "v2_token_format"

[provides.operations."test.op"]
description = "Op"
capability = "test.read"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "strict"
[provides.operations."test.op".input_schema]
type = "object"
required = ["id"]
[provides.operations."test.op".input_schema.properties.id]
type = "string"
[provides.operations."test.op".output_schema]
type = "object"
required = ["data"]
[provides.operations."test.op".network_constraints]
host_allow = ["api.test.com"]
port_allow = [443]
[provides.operations."test.op".ai_hints]
when_to_use = "Test"
common_mistakes = ["x"]
examples = ['{}']
related = ["test.other"]
"#;
        let manifest: toml::Value = toml::from_str(s).unwrap();
        let audit = audit_manifest("test", &manifest);
        assert!(audit.config.has_migration_hint);
    }

    #[test]
    fn manifest_no_state_section() {
        let manifest = manifest_no_ops();
        let audit = audit_manifest("empty", &manifest);
        assert!(!audit.config.has_state_config);
        assert!(!audit.config.has_migration_hint);
    }

    #[test]
    fn manifest_empty_capability_is_blocking() {
        let s = r#"
[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"

[connector]
id = "fcp.emptycap"
name = "EmptyCap"
version = "0.1.0"
description = "Empty cap"
archetypes = ["operational"]
format = "wasi"

[provides.operations."emptycap.op"]
description = "Op"
capability = ""
risk_level = "low"
safety_tier = "safe"
[provides.operations."emptycap.op".input_schema]
type = "object"
[provides.operations."emptycap.op".output_schema]
type = "object"
[provides.operations."emptycap.op".ai_hints]
when_to_use = "Test"
examples = ['{}']
related = []
"#;
        let manifest: toml::Value = toml::from_str(s).unwrap();
        let audit = audit_manifest("emptycap", &manifest);
        assert_eq!(audit.operations.with_capability, 0);
        assert!(
            audit
                .gaps
                .iter()
                .any(|g| g.description.contains("capability"))
        );
    }

    // ── Additional completeness / coverage tests ───────────────────

    #[test]
    fn zero_operations_completeness_is_zero() {
        let manifest = manifest_no_ops();
        let audit = audit_manifest("empty", &manifest);
        assert!(audit.operations.completeness.abs() < f64::EPSILON);
    }

    #[test]
    fn network_coverage_zero_when_no_constraints() {
        let s = r#"
[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"

[connector]
id = "fcp.nonet"
name = "NoNet"
version = "0.1.0"
description = "No network"
archetypes = ["operational"]
format = "wasi"

[provides.operations."nonet.op"]
description = "Op"
capability = "nonet.read"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "strict"
[provides.operations."nonet.op".input_schema]
type = "object"
required = ["id"]
[provides.operations."nonet.op".input_schema.properties.id]
type = "string"
[provides.operations."nonet.op".output_schema]
type = "object"
required = ["data"]
[provides.operations."nonet.op".ai_hints]
when_to_use = "Do stuff."
common_mistakes = ["x"]
examples = ['{}']
related = []
"#;
        let manifest: toml::Value = toml::from_str(s).unwrap();
        let audit = audit_manifest("nonet", &manifest);
        assert_eq!(audit.network.with_constraints, 0);
        assert!(audit.network.coverage.abs() < f64::EPSILON);
    }

    // ── Additional summary computation tests ───────────────────────

    #[test]
    fn summary_empty_map() {
        let map = BTreeMap::new();
        let summary = compute_summary(&map);
        assert_eq!(summary.ready, 0);
        assert_eq!(summary.partially_ready, 0);
        assert_eq!(summary.not_ready, 0);
        assert_eq!(summary.total_operations, 0);
        assert_eq!(summary.total_gaps, 0);
        assert!(summary.mean_operation_completeness.abs() < f64::EPSILON);
    }

    #[test]
    fn summary_all_not_ready() {
        let mut map = BTreeMap::new();
        map.insert("a".into(), audit_missing_manifest("a"));
        map.insert("b".into(), audit_missing_manifest("b"));
        let summary = compute_summary(&map);
        assert_eq!(summary.not_ready, 2);
        assert_eq!(summary.ready, 0);
    }

    #[test]
    fn summary_cosmetic_gaps_counted() {
        let mut map = BTreeMap::new();
        let mut audit = audit_manifest("test", &minimal_manifest());
        audit.gaps.push(ReadinessGap {
            category: GapCategory::OperationMetadata,
            severity: GapSeverity::Cosmetic,
            description: "Minor style issue".into(),
            remediation: "Fix formatting".into(),
        });
        map.insert("test".into(), audit);
        let summary = compute_summary(&map);
        assert_eq!(summary.cosmetic_gaps, 1);
    }

    #[test]
    fn summary_mean_hint_coverage() {
        let mut map = BTreeMap::new();
        map.insert("a".into(), audit_manifest("a", &minimal_manifest()));
        // minimal_manifest has 100% hint coverage
        let summary = compute_summary(&map);
        assert!((summary.mean_hint_coverage - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn summary_mean_hint_coverage_mixed() {
        let mut map = BTreeMap::new();
        map.insert("a".into(), audit_manifest("a", &minimal_manifest())); // 100% coverage
        map.insert("b".into(), audit_manifest("b", &manifest_no_hints())); // 0% coverage
        let summary = compute_summary(&map);
        assert!((summary.mean_hint_coverage - 0.5).abs() < f64::EPSILON);
    }

    // ── Serialization tests ────────────────────────────────────────

    #[test]
    fn operations_audit_serializes() {
        let ops = OperationsAudit {
            count: 5,
            with_description: 4,
            with_input_properties: 3,
            with_output_schema: 3,
            with_capability: 5,
            with_risk_level: 5,
            with_safety_tier: 4,
            with_idempotency: 3,
            with_approval: 2,
            completeness: 0.85,
        };
        let json = serde_json::to_value(&ops).unwrap();
        assert_eq!(json["count"], 5);
        assert_eq!(json["with_description"], 4);
    }

    #[test]
    fn config_audit_serializes() {
        let config = ConfigAudit {
            has_state_config: true,
            has_migration_hint: false,
        };
        let json = serde_json::to_value(&config).unwrap();
        assert_eq!(json["has_state_config"], true);
        assert_eq!(json["has_migration_hint"], false);
    }

    #[test]
    fn event_audit_serializes() {
        let events = EventAudit {
            event_count: 3,
            has_event_caps: true,
            has_streaming_archetype: true,
        };
        let json = serde_json::to_value(&events).unwrap();
        assert_eq!(json["event_count"], 3);
        assert_eq!(json["has_event_caps"], true);
    }

    #[test]
    fn rate_limit_audit_serializes() {
        let rl = RateLimitAudit {
            pool_count: 2,
            has_operation_pools: true,
        };
        let json = serde_json::to_value(&rl).unwrap();
        assert_eq!(json["pool_count"], 2);
        assert_eq!(json["has_operation_pools"], true);
    }

    #[test]
    fn network_audit_serializes() {
        let net = NetworkAudit {
            with_constraints: 4,
            with_host_allow: 3,
            with_port_allow: 2,
            coverage: 0.8,
        };
        let json = serde_json::to_value(&net).unwrap();
        assert_eq!(json["with_constraints"], 4);
        assert_eq!(json["coverage"], 0.8);
    }

    #[test]
    fn agent_hint_audit_serializes() {
        let hints = AgentHintAudit {
            with_hints: 5,
            with_when_to_use: 4,
            with_examples: 3,
            with_common_mistakes: 2,
            with_related: 1,
            coverage: 0.5,
        };
        let json = serde_json::to_value(&hints).unwrap();
        assert_eq!(json["with_hints"], 5);
        assert_eq!(json["coverage"], 0.5);
    }

    #[test]
    fn audit_summary_serializes() {
        let summary = AuditSummary {
            ready: 10,
            partially_ready: 5,
            not_ready: 2,
            total_operations: 150,
            total_gaps: 20,
            blocking_gaps: 3,
            degraded_gaps: 12,
            cosmetic_gaps: 5,
            mean_operation_completeness: 0.75,
            mean_hint_coverage: 0.6,
            ..AuditSummary::default()
        };
        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["ready"], 10);
        assert_eq!(json["blocking_gaps"], 3);
    }

    // ── Multi-op partial completeness ──────────────────────────────

    #[test]
    fn multi_op_with_some_missing_fields_partial_completeness() {
        let s = r#"
[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"

[connector]
id = "fcp.partial"
name = "Partial"
version = "0.1.0"
description = "Partial connector"
archetypes = ["operational"]
format = "wasi"

[provides.operations."partial.read"]
description = "Read"
capability = "partial.read"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "strict"
[provides.operations."partial.read".input_schema]
type = "object"
required = ["id"]
[provides.operations."partial.read".input_schema.properties.id]
type = "string"
[provides.operations."partial.read".output_schema]
type = "object"
required = ["data"]
[provides.operations."partial.read".network_constraints]
host_allow = ["api.partial.com"]
port_allow = [443]
[provides.operations."partial.read".ai_hints]
when_to_use = "Read"
common_mistakes = []
examples = ['{}']
related = []

[provides.operations."partial.write"]
description = "Write"
capability = "partial.write"
[provides.operations."partial.write".input_schema]
type = "object"
[provides.operations."partial.write".output_schema]
type = "object"
[provides.operations."partial.write".ai_hints]
when_to_use = "Write"
examples = ['{}']
related = []
"#;
        let manifest: toml::Value = toml::from_str(s).unwrap();
        let audit = audit_manifest("partial", &manifest);
        assert_eq!(audit.operations.count, 2);
        assert_eq!(audit.operations.with_description, 2);
        assert_eq!(audit.operations.with_capability, 2);
        // partial.write missing risk_level, safety_tier, idempotency, requires_approval
        assert_eq!(audit.operations.with_risk_level, 1);
        assert_eq!(audit.operations.with_safety_tier, 1);
        assert!(audit.operations.completeness < 1.0);
        assert!(audit.operations.completeness > 0.5);
    }

    // ── Default trait tests ────────────────────────────────────────

    #[test]
    fn operations_audit_default() {
        let ops = OperationsAudit::default();
        assert_eq!(ops.count, 0);
        assert!(ops.completeness.abs() < f64::EPSILON);
    }

    #[test]
    fn config_audit_default() {
        let config = ConfigAudit::default();
        assert!(!config.has_state_config);
        assert!(!config.has_migration_hint);
    }

    #[test]
    fn event_audit_default() {
        let events = EventAudit::default();
        assert_eq!(events.event_count, 0);
        assert!(!events.has_event_caps);
        assert!(!events.has_streaming_archetype);
    }

    #[test]
    fn network_audit_default() {
        let net = NetworkAudit::default();
        assert_eq!(net.with_constraints, 0);
        assert!(net.coverage.abs() < f64::EPSILON);
    }

    #[test]
    fn agent_hint_audit_default() {
        let hints = AgentHintAudit::default();
        assert_eq!(hints.with_hints, 0);
        assert!(hints.coverage.abs() < f64::EPSILON);
    }

    // ── Clone tests ────────────────────────────────────────────────

    #[test]
    fn connector_audit_clone() {
        let audit = audit_manifest("test", &minimal_manifest());
        let cloned = audit.clone();
        assert_eq!(audit.name, cloned.name);
        assert_eq!(audit.level, cloned.level);
        assert_eq!(audit.operations.count, cloned.operations.count);
        assert_eq!(audit.gaps.len(), cloned.gaps.len());
    }

    #[test]
    fn audit_matrix_clone() {
        let mut connectors = BTreeMap::new();
        connectors.insert("test".into(), audit_manifest("test", &minimal_manifest()));
        let matrix = AuditMatrix {
            generated_at: "2026-03-09T00:00:00Z".into(),
            total_connectors: 1,
            with_manifest: 1,
            missing_manifest: 0,
            connectors,
            summary: AuditSummary::default(),
        };
        let cloned = matrix.clone();
        assert_eq!(matrix.total_connectors, cloned.total_connectors);
    }

    // ── Additional cohort edge cases ─────────────────────────────────

    #[test]
    fn cohort_empty_string_is_other() {
        assert_eq!(assign_cohort(""), ConnectorCohort::Other);
    }

    #[test]
    fn cohort_case_sensitive() {
        // Cohort assignment is case-sensitive
        assert_eq!(assign_cohort("Slack"), ConnectorCohort::Other);
        assert_eq!(assign_cohort("GITHUB"), ConnectorCohort::Other);
        assert_eq!(assign_cohort("Redis"), ConnectorCohort::Other);
    }

    #[test]
    fn cohort_with_dashes_and_numbers() {
        assert_eq!(assign_cohort("1password"), ConnectorCohort::Security);
        assert_eq!(assign_cohort("annas-archive"), ConnectorCohort::Browser);
        assert_eq!(assign_cohort("google-calendar"), ConnectorCohort::Workspace);
        assert_eq!(assign_cohort("google-ai"), ConnectorCohort::Ai);
    }

    #[test]
    fn cohort_storage_complete() {
        assert_eq!(assign_cohort("s3"), ConnectorCohort::Storage);
        assert_eq!(assign_cohort("dropbox"), ConnectorCohort::Storage);
        assert_eq!(assign_cohort("box"), ConnectorCohort::Storage);
    }

    #[test]
    fn cohort_security_complete() {
        assert_eq!(assign_cohort("1password"), ConnectorCohort::Security);
        assert_eq!(assign_cohort("bitwarden"), ConnectorCohort::Security);
    }

    #[test]
    fn cohort_other_various_unknown() {
        for name in ["abc", "my-connector", "test-123", "zzz"] {
            assert_eq!(
                assign_cohort(name),
                ConnectorCohort::Other,
                "failed for {name}"
            );
        }
    }

    // ── Manifest parsing edge cases ──────────────────────────────────

    #[test]
    fn manifest_no_connector_id() {
        let s = r#"
[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"

[connector]
name = "NoId"
version = "0.1.0"
description = "No id"
archetypes = ["operational"]
format = "wasi"

[provides.operations."noid.op"]
description = "Op"
capability = "noid.read"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "strict"
[provides.operations."noid.op".input_schema]
type = "object"
required = ["id"]
[provides.operations."noid.op".input_schema.properties.id]
type = "string"
[provides.operations."noid.op".output_schema]
type = "object"
required = ["data"]
[provides.operations."noid.op".network_constraints]
host_allow = ["api.noid.com"]
port_allow = [443]
[provides.operations."noid.op".ai_hints]
when_to_use = "Do it"
common_mistakes = ["x"]
examples = ['{}']
related = ["noid.other"]
"#;
        let manifest: toml::Value = toml::from_str(s).unwrap();
        let audit = audit_manifest("noid", &manifest);
        assert!(audit.connector_id.is_none());
    }

    #[test]
    fn manifest_empty_input_properties_not_counted() {
        let s = r#"
[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"

[connector]
id = "fcp.emptyin"
name = "EmptyIn"
version = "0.1.0"
description = "Empty input props"
archetypes = ["operational"]
format = "wasi"

[provides.operations."emptyin.op"]
description = "Op"
capability = "emptyin.read"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "strict"
[provides.operations."emptyin.op".input_schema]
type = "object"
[provides.operations."emptyin.op".input_schema.properties]
[provides.operations."emptyin.op".output_schema]
type = "object"
required = ["data"]
[provides.operations."emptyin.op".ai_hints]
when_to_use = "Do it"
common_mistakes = ["x"]
examples = ['{}']
related = []
"#;
        let manifest: toml::Value = toml::from_str(s).unwrap();
        let audit = audit_manifest("emptyin", &manifest);
        // Empty properties table should NOT count
        assert_eq!(audit.operations.with_input_properties, 0);
    }

    #[test]
    fn manifest_output_with_only_required() {
        let s = r#"
[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"

[connector]
id = "fcp.outreq"
name = "OutReq"
version = "0.1.0"
description = "Output required only"
archetypes = ["operational"]
format = "wasi"

[provides.operations."outreq.op"]
description = "Op"
capability = "outreq.read"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "strict"
[provides.operations."outreq.op".input_schema]
type = "object"
required = ["id"]
[provides.operations."outreq.op".input_schema.properties.id]
type = "string"
[provides.operations."outreq.op".output_schema]
type = "object"
required = ["data"]
[provides.operations."outreq.op".ai_hints]
when_to_use = "Test"
common_mistakes = ["x"]
examples = ['{}']
related = []
"#;
        let manifest: toml::Value = toml::from_str(s).unwrap();
        let audit = audit_manifest("outreq", &manifest);
        // output_schema has required but no properties — still counts
        assert_eq!(audit.operations.with_output_schema, 1);
    }

    #[test]
    fn manifest_hints_partial_fields() {
        let s = r#"
[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"

[connector]
id = "fcp.phint"
name = "PartialHint"
version = "0.1.0"
description = "Partial hints"
archetypes = ["operational"]
format = "wasi"

[provides.operations."phint.op"]
description = "Op"
capability = "phint.read"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "strict"
[provides.operations."phint.op".input_schema]
type = "object"
required = ["id"]
[provides.operations."phint.op".input_schema.properties.id]
type = "string"
[provides.operations."phint.op".output_schema]
type = "object"
required = ["data"]
[provides.operations."phint.op".network_constraints]
host_allow = ["api.phint.com"]
port_allow = [443]
[provides.operations."phint.op".ai_hints]
when_to_use = "Use this for testing"
common_mistakes = []
examples = []
related = []
"#;
        let manifest: toml::Value = toml::from_str(s).unwrap();
        let audit = audit_manifest("phint", &manifest);
        assert_eq!(audit.agent_hints.with_hints, 1);
        assert_eq!(audit.agent_hints.with_when_to_use, 1);
        // empty examples, common_mistakes, related arrays → not counted
        assert_eq!(audit.agent_hints.with_examples, 0);
        assert_eq!(audit.agent_hints.with_common_mistakes, 0);
        assert_eq!(audit.agent_hints.with_related, 0);
    }

    #[test]
    fn manifest_empty_when_to_use_not_counted() {
        let s = r#"
[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"

[connector]
id = "fcp.ewtu"
name = "EmptyWTU"
version = "0.1.0"
description = "Empty when_to_use"
archetypes = ["operational"]
format = "wasi"

[provides.operations."ewtu.op"]
description = "Op"
capability = "ewtu.read"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "strict"
[provides.operations."ewtu.op".input_schema]
type = "object"
[provides.operations."ewtu.op".output_schema]
type = "object"
[provides.operations."ewtu.op".ai_hints]
when_to_use = ""
common_mistakes = ["x"]
examples = ['{}']
related = ["ewtu.other"]
"#;
        let manifest: toml::Value = toml::from_str(s).unwrap();
        let audit = audit_manifest("ewtu", &manifest);
        assert_eq!(audit.agent_hints.with_when_to_use, 0);
        assert_eq!(audit.agent_hints.with_common_mistakes, 1);
        assert_eq!(audit.agent_hints.with_examples, 1);
        assert_eq!(audit.agent_hints.with_related, 1);
    }

    #[test]
    fn manifest_network_host_allow_only() {
        let s = r#"
[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"

[connector]
id = "fcp.hostonly"
name = "HostOnly"
version = "0.1.0"
description = "Host allow only"
archetypes = ["operational"]
format = "wasi"

[provides.operations."hostonly.op"]
description = "Op"
capability = "hostonly.read"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "strict"
[provides.operations."hostonly.op".input_schema]
type = "object"
[provides.operations."hostonly.op".output_schema]
type = "object"
[provides.operations."hostonly.op".network_constraints]
host_allow = ["api.hostonly.com"]
port_allow = []
[provides.operations."hostonly.op".ai_hints]
when_to_use = "Test"
examples = ['{}']
related = []
"#;
        let manifest: toml::Value = toml::from_str(s).unwrap();
        let audit = audit_manifest("hostonly", &manifest);
        assert_eq!(audit.network.with_constraints, 1);
        assert_eq!(audit.network.with_host_allow, 1);
        assert_eq!(audit.network.with_port_allow, 0);
    }

    #[test]
    fn manifest_network_port_allow_only() {
        let s = r#"
[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"

[connector]
id = "fcp.portonly"
name = "PortOnly"
version = "0.1.0"
description = "Port allow only"
archetypes = ["operational"]
format = "wasi"

[provides.operations."portonly.op"]
description = "Op"
capability = "portonly.read"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "strict"
[provides.operations."portonly.op".input_schema]
type = "object"
[provides.operations."portonly.op".output_schema]
type = "object"
[provides.operations."portonly.op".network_constraints]
host_allow = []
port_allow = [443, 8080]
[provides.operations."portonly.op".ai_hints]
when_to_use = "Test"
examples = ['{}']
related = []
"#;
        let manifest: toml::Value = toml::from_str(s).unwrap();
        let audit = audit_manifest("portonly", &manifest);
        assert_eq!(audit.network.with_constraints, 1);
        assert_eq!(audit.network.with_host_allow, 0);
        assert_eq!(audit.network.with_port_allow, 1);
    }

    // ── Archetype detection edge cases ───────────────────────────────

    #[test]
    fn archetype_webhook_is_streaming() {
        let s = r#"
[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"

[connector]
id = "fcp.wh"
name = "Webhook"
version = "0.1.0"
description = "Webhook connector"
archetypes = ["operational", "webhook"]
format = "wasi"
"#;
        let manifest: toml::Value = toml::from_str(s).unwrap();
        let audit = audit_manifest("wh", &manifest);
        assert!(audit.events.has_streaming_archetype);
    }

    #[test]
    fn archetype_bidirectional_is_streaming() {
        let s = r#"
[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"

[connector]
id = "fcp.bidir"
name = "Bidirectional"
version = "0.1.0"
description = "Bidirectional connector"
archetypes = ["bidirectional"]
format = "wasi"
"#;
        let manifest: toml::Value = toml::from_str(s).unwrap();
        let audit = audit_manifest("bidir", &manifest);
        assert!(audit.events.has_streaming_archetype);
    }

    #[test]
    fn archetype_polling_is_streaming() {
        let s = r#"
[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"

[connector]
id = "fcp.poll"
name = "Polling"
version = "0.1.0"
description = "Polling connector"
archetypes = ["polling"]
format = "wasi"
"#;
        let manifest: toml::Value = toml::from_str(s).unwrap();
        let audit = audit_manifest("poll", &manifest);
        assert!(audit.events.has_streaming_archetype);
    }

    #[test]
    fn archetype_operational_only_not_streaming() {
        let s = r#"
[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"

[connector]
id = "fcp.oponly"
name = "OpOnly"
version = "0.1.0"
description = "Op only connector"
archetypes = ["operational"]
format = "wasi"
"#;
        let manifest: toml::Value = toml::from_str(s).unwrap();
        let audit = audit_manifest("oponly", &manifest);
        assert!(!audit.events.has_streaming_archetype);
    }

    #[test]
    fn archetype_no_archetypes_section() {
        let s = r#"
[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"

[connector]
id = "fcp.noarch"
name = "NoArch"
version = "0.1.0"
description = "No archetypes"
format = "wasi"
"#;
        let manifest: toml::Value = toml::from_str(s).unwrap();
        let audit = audit_manifest("noarch", &manifest);
        assert!(!audit.events.has_streaming_archetype);
    }

    // ── Readiness level determination ────────────────────────────────

    #[test]
    fn blocking_gap_makes_not_ready() {
        let manifest = manifest_missing_description();
        let audit = audit_manifest("bad", &manifest);
        assert_eq!(audit.level, ReadinessLevel::NotReady);
    }

    #[test]
    fn low_completeness_makes_partially_ready() {
        // A manifest with all descriptions but low completeness (<0.9)
        let s = r#"
[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"

[connector]
id = "fcp.lowcomp"
name = "LowComp"
version = "0.1.0"
description = "Low completeness"
archetypes = ["operational"]
format = "wasi"

[provides.operations."lowcomp.op"]
description = "Op"
capability = "lowcomp.read"
[provides.operations."lowcomp.op".input_schema]
type = "object"
[provides.operations."lowcomp.op".output_schema]
type = "object"
[provides.operations."lowcomp.op".ai_hints]
when_to_use = "Test"
examples = ['{}']
related = []
"#;
        let manifest: toml::Value = toml::from_str(s).unwrap();
        let audit = audit_manifest("lowcomp", &manifest);
        // Missing risk_level, safety_tier, idempotency, approval, input_properties
        // completeness < 0.9 → PartiallyReady
        assert_eq!(audit.level, ReadinessLevel::PartiallyReady);
    }

    #[test]
    fn low_hint_coverage_makes_partially_ready() {
        let manifest = manifest_no_hints();
        let audit = audit_manifest("nohints", &manifest);
        // 0% hint coverage < 0.8 threshold → PartiallyReady
        assert_eq!(audit.level, ReadinessLevel::PartiallyReady);
    }

    // ── Summary computation additional ───────────────────────────────

    #[test]
    fn summary_multiple_cohorts_counted() {
        let mut map = BTreeMap::new();
        map.insert("slack".into(), audit_manifest("slack", &minimal_manifest()));
        map.insert(
            "discord".into(),
            audit_manifest("discord", &minimal_manifest()),
        );
        map.insert(
            "github".into(),
            audit_manifest("github", &minimal_manifest()),
        );
        map.insert("s3".into(), audit_manifest("s3", &minimal_manifest()));
        let summary = compute_summary(&map);
        assert_eq!(summary.by_cohort.get("messaging"), Some(&2));
        assert_eq!(summary.by_cohort.get("devtools"), Some(&1));
        assert_eq!(summary.by_cohort.get("storage"), Some(&1));
    }

    #[test]
    fn summary_total_gaps_across_connectors() {
        let mut map = BTreeMap::new();
        map.insert("a".into(), audit_missing_manifest("a")); // 1 gap
        map.insert("b".into(), audit_missing_manifest("b")); // 1 gap
        map.insert("c".into(), audit_manifest("c", &manifest_no_hints())); // 1 gap
        let summary = compute_summary(&map);
        assert_eq!(summary.total_gaps, 3);
    }

    #[test]
    fn summary_all_ready() {
        let mut map = BTreeMap::new();
        map.insert("a".into(), audit_manifest("a", &minimal_manifest()));
        map.insert("b".into(), audit_manifest("b", &minimal_manifest()));
        map.insert("c".into(), audit_manifest("c", &minimal_manifest()));
        let summary = compute_summary(&map);
        assert_eq!(summary.ready, 3);
        assert_eq!(summary.partially_ready, 0);
        assert_eq!(summary.not_ready, 0);
    }

    #[test]
    fn summary_mean_completeness_mixed() {
        let mut map = BTreeMap::new();
        map.insert("a".into(), audit_manifest("a", &minimal_manifest())); // 1.0
        map.insert("b".into(), audit_missing_manifest("b")); // 0.0 (no ops)
        let summary = compute_summary(&map);
        assert!((summary.mean_operation_completeness - 0.5).abs() < f64::EPSILON);
    }

    // ── Serialization roundtrip tests ────────────────────────────────

    #[test]
    fn operations_audit_default_serializes() {
        let ops = OperationsAudit::default();
        let json = serde_json::to_string(&ops).unwrap();
        assert!(json.contains("\"count\":0"));
    }

    #[test]
    fn audit_summary_default_serializes() {
        let summary = AuditSummary::default();
        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["ready"], 0);
        assert_eq!(json["total_gaps"], 0);
        assert_eq!(json["mean_operation_completeness"], 0.0);
    }

    #[test]
    fn audit_matrix_full_serialization() {
        let mut connectors = BTreeMap::new();
        connectors.insert("test".into(), audit_manifest("test", &minimal_manifest()));
        connectors.insert("missing".into(), audit_missing_manifest("missing"));

        let summary = compute_summary(&connectors);
        let matrix = AuditMatrix {
            generated_at: "2026-03-12T00:00:00Z".into(),
            total_connectors: 2,
            with_manifest: 1,
            missing_manifest: 1,
            connectors,
            summary,
        };

        let json = serde_json::to_string_pretty(&matrix).unwrap();
        assert!(json.contains("\"total_connectors\": 2"));
        assert!(json.contains("\"with_manifest\": 1"));
        assert!(json.contains("\"missing_manifest\": 1"));
        assert!(json.contains("\"ready\": 1"));
        assert!(json.contains("\"not_ready\": 1"));
    }

    #[test]
    fn connector_audit_json_has_all_sub_objects() {
        let audit = audit_manifest("test", &minimal_manifest());
        let json = serde_json::to_value(&audit).unwrap();
        assert!(json.get("operations").is_some());
        assert!(json.get("config").is_some());
        assert!(json.get("agent_hints").is_some());
        assert!(json.get("events").is_some());
        assert!(json.get("rate_limits").is_some());
        assert!(json.get("network").is_some());
        assert!(json.get("gaps").is_some());
        assert!(json.get("name").is_some());
        assert!(json.get("crate_path").is_some());
        assert!(json.get("connector_id").is_some());
        assert!(json.get("cohort").is_some());
        assert!(json.get("level").is_some());
        assert!(json.get("has_manifest").is_some());
    }

    // ── Clone deep equality ──────────────────────────────────────────

    #[test]
    fn operations_audit_clone() {
        let ops = OperationsAudit {
            count: 5,
            with_description: 3,
            with_input_properties: 2,
            with_output_schema: 4,
            with_capability: 5,
            with_risk_level: 3,
            with_safety_tier: 2,
            with_idempotency: 4,
            with_approval: 1,
            completeness: 0.72,
        };
        let cloned = ops.clone();
        assert_eq!(ops.count, cloned.count);
        assert_eq!(ops.with_description, cloned.with_description);
        assert!((ops.completeness - cloned.completeness).abs() < f64::EPSILON);
    }

    #[test]
    fn config_audit_clone() {
        let config = ConfigAudit {
            has_state_config: true,
            has_migration_hint: true,
        };
        let cloned = config.clone();
        assert_eq!(config.has_state_config, cloned.has_state_config);
        assert_eq!(config.has_migration_hint, cloned.has_migration_hint);
    }

    #[test]
    fn event_audit_clone() {
        let events = EventAudit {
            event_count: 5,
            has_event_caps: true,
            has_streaming_archetype: true,
        };
        let cloned = events.clone();
        assert_eq!(events.event_count, cloned.event_count);
        assert_eq!(events.has_event_caps, cloned.has_event_caps);
    }

    #[test]
    fn rate_limit_audit_clone() {
        let rl = RateLimitAudit {
            pool_count: 3,
            has_operation_pools: true,
        };
        let cloned = rl.clone();
        assert_eq!(rl.pool_count, cloned.pool_count);
        assert_eq!(rl.has_operation_pools, cloned.has_operation_pools);
    }

    #[test]
    fn network_audit_clone() {
        let net = NetworkAudit {
            with_constraints: 4,
            with_host_allow: 3,
            with_port_allow: 2,
            coverage: 0.8,
        };
        let cloned = net.clone();
        assert_eq!(net.with_constraints, cloned.with_constraints);
        assert!((net.coverage - cloned.coverage).abs() < f64::EPSILON);
    }

    #[test]
    fn agent_hint_audit_clone() {
        let hints = AgentHintAudit {
            with_hints: 5,
            with_when_to_use: 4,
            with_examples: 3,
            with_common_mistakes: 2,
            with_related: 1,
            coverage: 0.5,
        };
        let cloned = hints.clone();
        assert_eq!(hints.with_hints, cloned.with_hints);
        assert!((hints.coverage - cloned.coverage).abs() < f64::EPSILON);
    }

    #[test]
    fn audit_summary_clone() {
        let summary = AuditSummary {
            ready: 10,
            partially_ready: 5,
            not_ready: 2,
            total_operations: 150,
            total_gaps: 20,
            blocking_gaps: 3,
            degraded_gaps: 12,
            cosmetic_gaps: 5,
            mean_operation_completeness: 0.75,
            mean_hint_coverage: 0.6,
            ..AuditSummary::default()
        };
        let cloned = summary.clone();
        assert_eq!(summary.ready, cloned.ready);
        assert_eq!(summary.total_gaps, cloned.total_gaps);
        assert!((summary.mean_hint_coverage - cloned.mean_hint_coverage).abs() < f64::EPSILON);
    }

    // ── Debug trait tests ────────────────────────────────────────────

    #[test]
    fn operations_audit_debug() {
        let ops = OperationsAudit::default();
        let debug = format!("{ops:?}");
        assert!(debug.contains("OperationsAudit"));
        assert!(debug.contains("count"));
    }

    #[test]
    fn config_audit_debug() {
        let config = ConfigAudit::default();
        let debug = format!("{config:?}");
        assert!(debug.contains("ConfigAudit"));
    }

    #[test]
    fn event_audit_debug() {
        let events = EventAudit::default();
        let debug = format!("{events:?}");
        assert!(debug.contains("EventAudit"));
    }

    #[test]
    fn rate_limit_audit_debug() {
        let rl = RateLimitAudit::default();
        let debug = format!("{rl:?}");
        assert!(debug.contains("RateLimitAudit"));
    }

    #[test]
    fn network_audit_debug() {
        let net = NetworkAudit::default();
        let debug = format!("{net:?}");
        assert!(debug.contains("NetworkAudit"));
    }

    #[test]
    fn agent_hint_audit_debug() {
        let hints = AgentHintAudit::default();
        let debug = format!("{hints:?}");
        assert!(debug.contains("AgentHintAudit"));
    }

    #[test]
    fn connector_audit_debug() {
        let audit = audit_missing_manifest("test");
        let debug = format!("{audit:?}");
        assert!(debug.contains("ConnectorAudit"));
        assert!(debug.contains("test"));
    }

    #[test]
    fn audit_matrix_debug() {
        let matrix = AuditMatrix {
            generated_at: "2026-03-12T00:00:00Z".into(),
            total_connectors: 0,
            with_manifest: 0,
            missing_manifest: 0,
            connectors: BTreeMap::new(),
            summary: AuditSummary::default(),
        };
        let debug = format!("{matrix:?}");
        assert!(debug.contains("AuditMatrix"));
    }

    #[test]
    fn audit_summary_debug() {
        let summary = AuditSummary::default();
        let debug = format!("{summary:?}");
        assert!(debug.contains("AuditSummary"));
    }

    // ── Crate path formatting ────────────────────────────────────────

    #[test]
    fn crate_path_format_for_manifest() {
        let audit = audit_manifest("github", &minimal_manifest());
        assert_eq!(audit.crate_path, "connectors/github");
    }

    #[test]
    fn crate_path_format_for_missing() {
        let audit = audit_missing_manifest("slack");
        assert_eq!(audit.crate_path, "connectors/slack");
    }

    #[test]
    fn crate_path_preserves_dashes() {
        let audit = audit_missing_manifest("annas-archive");
        assert_eq!(audit.crate_path, "connectors/annas-archive");
    }

    // ── Multi-op gap accumulation ────────────────────────────────────

    #[test]
    fn multiple_ops_missing_capability_accumulates_gaps() {
        let s = r#"
[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"

[connector]
id = "fcp.multigap"
name = "MultiGap"
version = "0.1.0"
description = "Multi gap connector"
archetypes = ["operational"]
format = "wasi"

[provides.operations."multigap.a"]
description = "Op A"
[provides.operations."multigap.a".input_schema]
type = "object"
[provides.operations."multigap.a".output_schema]
type = "object"

[provides.operations."multigap.b"]
description = "Op B"
[provides.operations."multigap.b".input_schema]
type = "object"
[provides.operations."multigap.b".output_schema]
type = "object"
"#;
        let manifest: toml::Value = toml::from_str(s).unwrap();
        let audit = audit_manifest("multigap", &manifest);
        // Each op missing capability → 1 blocking gap each
        // Each op missing ai_hints → 1 degraded gap each
        let cap_gaps = audit
            .gaps
            .iter()
            .filter(|g| g.description.contains("capability"))
            .count();
        assert_eq!(cap_gaps, 2);
        let hint_gaps = audit
            .gaps
            .iter()
            .filter(|g| g.category == GapCategory::AgentHints)
            .count();
        assert_eq!(hint_gaps, 2);
    }

    #[test]
    fn gap_remediation_messages_non_empty() {
        let audit = audit_missing_manifest("test");
        for gap in &audit.gaps {
            assert!(!gap.remediation.is_empty());
        }

        let manifest = manifest_missing_description();
        let audit2 = audit_manifest("bad", &manifest);
        for gap in &audit2.gaps {
            assert!(!gap.remediation.is_empty());
        }
    }

    // ── Rate limit edge cases ────────────────────────────────────────

    #[test]
    fn rate_limits_no_pools_section() {
        let s = r#"
[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"

[connector]
id = "fcp.norl"
name = "NoRL"
version = "0.1.0"
description = "No rate limits"
archetypes = ["operational"]
format = "wasi"

[rate_limits]
strategy = "token_bucket"
"#;
        let manifest: toml::Value = toml::from_str(s).unwrap();
        let audit = audit_manifest("norl", &manifest);
        assert_eq!(audit.rate_limits.pool_count, 0);
        assert!(!audit.rate_limits.has_operation_pools);
    }

    #[test]
    fn rate_limits_multiple_pools() {
        let s = r#"
[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"

[connector]
id = "fcp.multipool"
name = "MultiPool"
version = "0.1.0"
description = "Multi pool"
archetypes = ["operational"]
format = "wasi"

[[rate_limits.pools]]
id = "pool_a"
requests = 100
window_ms = 60000

[[rate_limits.pools]]
id = "pool_b"
requests = 50
window_ms = 30000

[[rate_limits.pools]]
id = "pool_c"
requests = 200
window_ms = 120000
"#;
        let manifest: toml::Value = toml::from_str(s).unwrap();
        let audit = audit_manifest("multipool", &manifest);
        assert_eq!(audit.rate_limits.pool_count, 3);
    }

    // ── Event count edge cases ───────────────────────────────────────

    #[test]
    fn multiple_events_counted() {
        let s = r#"
[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"

[connector]
id = "fcp.multievt"
name = "MultiEvt"
version = "0.1.0"
description = "Multi events"
archetypes = ["operational", "streaming"]
format = "wasi"

[event_caps]
streaming = true

[provides.events."evt.a"]
description = "Event A"
[provides.events."evt.b"]
description = "Event B"
[provides.events."evt.c"]
description = "Event C"
"#;
        let manifest: toml::Value = toml::from_str(s).unwrap();
        let audit = audit_manifest("multievt", &manifest);
        assert_eq!(audit.events.event_count, 3);
        assert!(audit.events.has_event_caps);
        assert!(audit.events.has_streaming_archetype);
    }

    // ── Completeness ratio precision ─────────────────────────────────

    #[test]
    fn completeness_ratio_calculated_correctly() {
        // 2 ops, each with 8 checks = 16 total checks
        // multi_ops manifest: all 8 fields present for all 3 ops → 24/24 = 1.0
        let manifest = manifest_multi_ops();
        let audit = audit_manifest("multi", &manifest);
        let expected = 24.0 / 24.0;
        assert!((audit.operations.completeness - expected).abs() < f64::EPSILON);
    }

    #[test]
    fn hint_coverage_ratio_partial() {
        // 3 ops, 2 with hints → coverage = 2/3
        let s = r#"
[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"

[connector]
id = "fcp.phcov"
name = "PartHintCov"
version = "0.1.0"
description = "Partial hint coverage"
archetypes = ["operational"]
format = "wasi"

[provides.operations."phcov.a"]
description = "A"
capability = "phcov.read"
[provides.operations."phcov.a".input_schema]
type = "object"
[provides.operations."phcov.a".output_schema]
type = "object"
[provides.operations."phcov.a".ai_hints]
when_to_use = "A"
examples = ['{}']
related = []

[provides.operations."phcov.b"]
description = "B"
capability = "phcov.read"
[provides.operations."phcov.b".input_schema]
type = "object"
[provides.operations."phcov.b".output_schema]
type = "object"
[provides.operations."phcov.b".ai_hints]
when_to_use = "B"
examples = ['{}']
related = []

[provides.operations."phcov.c"]
description = "C"
capability = "phcov.read"
[provides.operations."phcov.c".input_schema]
type = "object"
[provides.operations."phcov.c".output_schema]
type = "object"
"#;
        let manifest: toml::Value = toml::from_str(s).unwrap();
        let audit = audit_manifest("phcov", &manifest);
        let expected = 2.0 / 3.0;
        assert!((audit.agent_hints.coverage - expected).abs() < f64::EPSILON);
    }

    // ── Migration hint edge cases ────────────────────────────────────

    #[test]
    fn migration_hint_empty_string_not_meaningful() {
        let s = r#"
[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"

[connector]
id = "fcp.emptymig"
name = "EmptyMig"
version = "0.1.0"
description = "Empty migration hint"
archetypes = ["operational"]
format = "wasi"

[connector.state]
model = "singleton_writer"
state_schema_version = "1"
migration_hint = ""
"#;
        let manifest: toml::Value = toml::from_str(s).unwrap();
        let audit = audit_manifest("emptymig", &manifest);
        assert!(audit.config.has_state_config);
        assert!(!audit.config.has_migration_hint);
    }

    #[test]
    fn migration_hint_init_not_meaningful() {
        // Already tested but let's be explicit
        let manifest = minimal_manifest();
        let audit = audit_manifest("test", &manifest);
        assert!(!audit.config.has_migration_hint);
    }

    // ── Filesystem edge cases ────────────────────────────────────────

    #[test]
    fn run_audit_empty_directory() {
        let dir = std::env::temp_dir().join("fwc_audit_test_empty");
        let _ = std::fs::create_dir_all(&dir);
        let matrix = run_audit(&dir).unwrap();
        assert_eq!(matrix.total_connectors, 0);
        assert_eq!(matrix.with_manifest, 0);
        assert_eq!(matrix.missing_manifest, 0);
        assert!(matrix.connectors.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_audit_dir_with_files_only() {
        let dir = std::env::temp_dir().join("fwc_audit_test_files");
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(dir.join("not_a_dir.txt"), "hello").unwrap();
        let matrix = run_audit(&dir).unwrap();
        // Files are filtered out, only dirs
        assert_eq!(matrix.total_connectors, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_audit_dir_with_subdirs_no_manifest() {
        let dir = std::env::temp_dir().join("fwc_audit_test_subdirs");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("connector_a")).unwrap();
        std::fs::create_dir_all(dir.join("connector_b")).unwrap();
        let matrix = run_audit(&dir).unwrap();
        assert_eq!(matrix.total_connectors, 2);
        assert_eq!(matrix.missing_manifest, 2);
        assert_eq!(matrix.with_manifest, 0);
        for audit in matrix.connectors.values() {
            assert!(!audit.has_manifest);
            assert_eq!(audit.level, ReadinessLevel::NotReady);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── Summary by_cohort deduplication ──────────────────────────────

    #[test]
    fn summary_by_cohort_key_is_lowercase() {
        let mut map = BTreeMap::new();
        map.insert(
            "github".into(),
            audit_manifest("github", &minimal_manifest()),
        );
        let summary = compute_summary(&map);
        // Key should be lowercase debug repr of the enum
        assert!(summary.by_cohort.contains_key("devtools"));
        assert!(!summary.by_cohort.contains_key("DevTools"));
    }

    #[test]
    fn summary_by_cohort_accumulates() {
        let mut map = BTreeMap::new();
        for name in ["slack", "discord", "telegram", "twilio"] {
            map.insert(name.into(), audit_manifest(name, &minimal_manifest()));
        }
        let summary = compute_summary(&map);
        assert_eq!(summary.by_cohort.get("messaging"), Some(&4));
    }

    fn placeholder_inventory_repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn placeholder_inventory_fixture() -> PlaceholderInventoryFinding {
        PlaceholderInventoryFinding {
            id: "fixture".to_string(),
            title: "Fixture".to_string(),
            classification: PlaceholderFindingKind::RuntimeBlocker,
            allowed_scaffold_candidate: false,
            approved_exception_class: None,
            owner_bead: "flywheel_connectors-24llg.1.1".to_string(),
            rationale: "Fixture rationale".to_string(),
            exit_strategy: "Fixture exit".to_string(),
            verification_expectation: "Fixture verification".to_string(),
            anchors: vec![PlaceholderFindingAnchor {
                path: "crates/fwc/src/audit.rs".to_string(),
                needle: "PlaceholderFindingKind".to_string(),
            }],
        }
    }

    fn placeholder_inventory_temp_root(label: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "fwc_placeholder_inventory_{label}_{}_{}",
            std::process::id(),
            unique
        ))
    }

    #[test]
    fn placeholder_inventory_document_is_well_formed() {
        let root = placeholder_inventory_repo_root();
        let inventory = load_placeholder_inventory(&root).unwrap();
        assert!(inventory.findings.len() >= 10);
        assert!(!inventory.approved_exception_classes.is_empty());
    }

    #[test]
    fn placeholder_inventory_approved_exception_classes_stay_narrow() {
        let root = placeholder_inventory_repo_root();
        let inventory = load_placeholder_inventory(&root).unwrap();
        assert!(inventory.approved_exception_classes.len() <= 5);

        let class_ids = inventory
            .approved_exception_classes
            .iter()
            .map(|class| class.id.as_str())
            .collect::<BTreeSet<_>>();
        assert!(class_ids.contains("test_only"));
        assert!(class_ids.contains("mock_infrastructure"));
        assert!(class_ids.contains("offline_template_generation"));
    }

    #[test]
    fn placeholder_inventory_anchor_validation_accepts_matching_fixture() {
        let temp_root = placeholder_inventory_temp_root("anchor_match");
        let _ = std::fs::remove_dir_all(&temp_root);
        std::fs::create_dir_all(temp_root.join("fixtures")).unwrap();
        std::fs::write(
            temp_root.join("fixtures/present.txt"),
            "placeholder anchor fixture\n",
        )
        .unwrap();

        let inventory = ProductionPlaceholderInventory {
            version: 1,
            generated_at: "2026-04-03T00:00:00Z".to_string(),
            purpose: "Synthetic anchor validation fixture".to_string(),
            approved_exception_classes: vec![],
            findings: vec![PlaceholderInventoryFinding {
                anchors: vec![PlaceholderFindingAnchor {
                    path: "fixtures/present.txt".to_string(),
                    needle: "placeholder anchor fixture".to_string(),
                }],
                ..placeholder_inventory_fixture()
            }],
        };

        validate_placeholder_inventory(&temp_root, &inventory).unwrap();
        let _ = std::fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn placeholder_inventory_anchor_validation_reports_missing_needle() {
        let temp_root = placeholder_inventory_temp_root("anchor_missing");
        let _ = std::fs::remove_dir_all(&temp_root);
        std::fs::create_dir_all(temp_root.join("fixtures")).unwrap();
        std::fs::write(
            temp_root.join("fixtures/present.txt"),
            "truthful runtime code\n",
        )
        .unwrap();

        let inventory = ProductionPlaceholderInventory {
            version: 1,
            generated_at: "2026-04-03T00:00:00Z".to_string(),
            purpose: "Synthetic anchor validation fixture".to_string(),
            approved_exception_classes: vec![],
            findings: vec![PlaceholderInventoryFinding {
                id: "missing-anchor".to_string(),
                title: "Missing anchor".to_string(),
                classification: PlaceholderFindingKind::RuntimeBlocker,
                allowed_scaffold_candidate: false,
                approved_exception_class: None,
                owner_bead: "flywheel_connectors-24llg.1.2".to_string(),
                rationale: "Synthetic missing-anchor fixture".to_string(),
                exit_strategy: "Update the anchor or remove the finding".to_string(),
                verification_expectation: "Validator must report the missing needle".to_string(),
                anchors: vec![PlaceholderFindingAnchor {
                    path: "fixtures/present.txt".to_string(),
                    needle: "placeholder anchor fixture".to_string(),
                }],
            }],
        };

        let error = validate_placeholder_inventory(&temp_root, &inventory).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("no longer contains expected needle"),
            "unexpected error: {error}"
        );
        let _ = std::fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn placeholder_finding_disposition_classifies_candidates_and_exceptions() {
        let mut finding = placeholder_inventory_fixture();
        assert_eq!(
            placeholder_finding_disposition(&finding),
            PlaceholderFindingDisposition::RuntimeBlocker
        );

        finding.allowed_scaffold_candidate = true;
        assert_eq!(
            placeholder_finding_disposition(&finding),
            PlaceholderFindingDisposition::AllowedScaffoldCandidate
        );

        finding.approved_exception_class = Some("test_only".to_string());
        assert_eq!(
            placeholder_finding_disposition(&finding),
            PlaceholderFindingDisposition::ApprovedException
        );
    }

    #[test]
    fn placeholder_finding_gate_requires_closure_until_exception_is_approved() {
        let mut finding = placeholder_inventory_fixture();
        finding.allowed_scaffold_candidate = true;
        assert_eq!(
            placeholder_finding_gate(&finding),
            PlaceholderFindingGate::FailUntilCleared
        );

        finding.approved_exception_class = Some("offline_template_generation".to_string());
        assert_eq!(
            placeholder_finding_gate(&finding),
            PlaceholderFindingGate::AllowlistedException
        );
    }

    #[test]
    fn placeholder_path_is_allowlisted_checks_exception_globs() {
        let mut finding = placeholder_inventory_fixture();
        finding.allowed_scaffold_candidate = true;
        finding.approved_exception_class = Some("offline_template_generation".to_string());

        let inventory = ProductionPlaceholderInventory {
            version: 1,
            generated_at: "2026-04-03T00:00:00Z".to_string(),
            purpose: "fixture".to_string(),
            approved_exception_classes: vec![ApprovedPlaceholderExceptionClass {
                id: "offline_template_generation".to_string(),
                description: "Fixture".to_string(),
                allowed_path_globs: vec![
                    "crates/fcp-google-discovery/src/generated/*.rs".to_string(),
                    "crates/fwc/src/new_cmd.rs".to_string(),
                ],
                closure_rule: "fixture".to_string(),
                owner_bead: "flywheel_connectors-24llg.7.3".to_string(),
            }],
            findings: vec![finding.clone()],
        };

        assert!(placeholder_path_is_allowlisted(
            &inventory,
            &finding,
            "crates/fcp-google-discovery/src/generated/gmail.rs"
        ));
        assert!(placeholder_path_is_allowlisted(
            &inventory,
            &finding,
            "crates/fwc/src/new_cmd.rs"
        ));
        assert!(!placeholder_path_is_allowlisted(
            &inventory,
            &finding,
            "connectors/tlon/src/connector.rs"
        ));
    }
}
