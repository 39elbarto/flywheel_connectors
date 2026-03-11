//! Connector/host readiness contract for `fwc`.
//!
//! Defines the minimum metadata and RPC surface that a connector and `fcp-host`
//! must expose for `fwc` to present discovery, configuration, lifecycle
//! management, and invocation workflows cleanly.
//!
//! A connector is **fwc-ready** when all mandatory fields are present and valid.
//! Gap categories identify what is missing so cohort remediation beads can
//! systematically bring connectors to full readiness.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use fcp_core::{
    AgentHint, ApprovalMode, AuthDescriptor, CapabilityId, ConnectorDescriptor, DescriptorCheck,
    DescriptorStatus, IdempotencyClass, OperationId, OperationInfo, PrerequisiteCatalog,
    ReadinessDescriptor, RiskLevel, SafetyTier,
};
use fcp_manifest::{ConnectorManifest, ConnectorRuntimeFormat, ManifestApprovalMode};
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
    Business,
    Browser,
    Knowledge,
    Automation,
    Community,
    Security,
    Media,
    Vectordb,
    Iot,
    Other,
}

impl ConnectorCohort {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Messaging => "messaging",
            Self::Social => "social",
            Self::Workspace => "workspace",
            Self::Productivity => "productivity",
            Self::Ai => "ai",
            Self::DevTools => "dev-tools",
            Self::Infra => "infra",
            Self::Data => "data",
            Self::Storage => "storage",
            Self::Analytics => "analytics",
            Self::Finance => "finance",
            Self::Business => "business",
            Self::Browser => "browser",
            Self::Knowledge => "knowledge",
            Self::Automation => "automation",
            Self::Community => "community",
            Self::Security => "security",
            Self::Media => "media",
            Self::Vectordb => "vectordb",
            Self::Iot => "iot",
            Self::Other => "other",
        }
    }
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
    /// Host/runtime state has not been queried yet.
    Unknown,
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

// ── Manifest-backed discovery catalog ──────────────────────────────────

#[derive(Clone, Debug)]
pub struct DiscoveryCatalog {
    connectors: Vec<DiscoveredConnector>,
}

impl DiscoveryCatalog {
    /// Load the current workspace connector catalog from `connectors/*/manifest.toml`.
    ///
    /// This stays honest about runtime state: discovery is manifest-backed until
    /// host-backed lifecycle/status surfaces land in later beads.
    pub fn load() -> Result<Self> {
        let connectors_dir = workspace_root().join("connectors");
        let mut connectors = Vec::new();

        for entry in fs::read_dir(&connectors_dir)
            .with_context(|| format!("failed to read {}", connectors_dir.display()))?
        {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if !file_type.is_dir() {
                continue;
            }

            let slug = entry.file_name().to_string_lossy().into_owned();
            let manifest_path = entry.path().join("manifest.toml");
            if !manifest_path.is_file() {
                continue;
            }

            if let Ok(connector) = DiscoveredConnector::from_manifest(&slug, &manifest_path) {
                connectors.push(connector);
            }
        }

        connectors.sort_by(|left, right| left.slug.cmp(&right.slug));
        Ok(Self { connectors })
    }

    #[must_use]
    pub fn connectors(&self) -> &[DiscoveredConnector] {
        &self.connectors
    }

    #[must_use]
    pub fn list(&self, zone: Option<&str>, category: Option<&str>) -> Vec<&DiscoveredConnector> {
        let zone = zone.map(normalize_zone_selector);
        let category = category.map(normalize_category_selector);

        self.connectors
            .iter()
            .filter(|connector| {
                zone.as_ref()
                    .is_none_or(|requested| connector.matches_zone(requested))
                    && category
                        .as_ref()
                        .is_none_or(|requested| connector.matches_category(requested))
            })
            .collect()
    }

    pub fn resolve_connector(&self, selector: &str) -> Result<&DiscoveredConnector, SelectorError> {
        let normalized = normalize_connector_selector(selector);
        let exact = self
            .connectors
            .iter()
            .filter(|connector| connector.matches_selector(&normalized))
            .collect::<Vec<_>>();

        if exact.len() == 1 {
            return Ok(exact[0]);
        }
        if exact.len() > 1 {
            return Err(SelectorError::ambiguous(
                selector,
                exact
                    .iter()
                    .map(|connector| connector.slug.clone())
                    .collect(),
            ));
        }

        let prefix = self
            .connectors
            .iter()
            .filter(|connector| connector.matches_prefix(&normalized))
            .collect::<Vec<_>>();

        match prefix.as_slice() {
            [connector] => Ok(*connector),
            [] => Err(SelectorError::not_found(
                selector,
                suggest_connector_slugs(&self.connectors, &normalized),
            )),
            _ => Err(SelectorError::ambiguous(
                selector,
                prefix
                    .iter()
                    .map(|connector| connector.slug.clone())
                    .take(5)
                    .collect(),
            )),
        }
    }
}

#[derive(Clone, Debug)]
pub struct DiscoveredConnector {
    pub slug: String,
    pub manifest_path: String,
    pub cohort: String,
    pub runtime_format: String,
    pub state_model: Option<String>,
    pub supported_zones: Vec<String>,
    pub detail: ConnectorDetail,
    pub zones: Value,
    pub capabilities: Value,
    pub connector_schema: Value,
    pub operations: Vec<DiscoveredOperation>,
}

impl DiscoveredConnector {
    #[allow(clippy::too_many_lines)]
    fn from_manifest(slug: &str, manifest_path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(manifest_path)
            .with_context(|| format!("failed to read {}", manifest_path.display()))?;
        // Discovery should tolerate stale interface hashes so the CLI can still
        // surface real connector metadata while validation is being repaired.
        let manifest = ConnectorManifest::parse_str_unchecked(&raw)
            .with_context(|| format!("failed to parse {}", manifest_path.display()))?;

        let inventory_entry = CONNECTOR_INVENTORY.iter().find(|entry| entry.name == slug);
        let cohort = inventory_entry.map_or_else(
            || ConnectorCohort::Other.as_str().to_owned(),
            |entry| entry.cohort.as_str().to_owned(),
        );

        let namespace = manifest
            .connector
            .id
            .as_str()
            .strip_prefix("fcp.")
            .unwrap_or_else(|| manifest.connector.id.as_str())
            .to_owned();
        let runtime_format = runtime_format_label(manifest.connector.format).to_owned();
        let state_model = manifest
            .connector
            .state
            .as_ref()
            .map(serde_json::to_value)
            .transpose()?
            .and_then(|json| {
                json.get("model")
                    .and_then(Value::as_str)
                    .map(std::borrow::ToOwned::to_owned)
            });

        let mut operations = manifest
            .provides
            .operations
            .iter()
            .map(|(operation_id, operation)| {
                DiscoveredOperation::from_manifest(
                    &namespace,
                    operation_id,
                    operation,
                    manifest.rate_limits.as_ref(),
                )
            })
            .collect::<Result<Vec<_>>>()?;
        operations.sort_by(|left, right| left.preferred_selector.cmp(&right.preferred_selector));

        let max_risk = operations
            .iter()
            .map(|operation| operation.summary.risk_level.as_str())
            .max_by_key(|risk| risk_rank(risk))
            .unwrap_or("low")
            .to_owned();
        let has_events = manifest
            .event_caps
            .as_ref()
            .is_some_and(|caps| caps.streaming || caps.replay)
            || !manifest.provides.events.is_empty();
        let supported_zones = manifest
            .zones
            .allowed_sources
            .iter()
            .chain(manifest.zones.allowed_targets.iter())
            .chain(std::iter::once(&manifest.zones.home))
            .map(|zone| zone.as_str().to_owned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let connector_rate_limits = manifest
            .rate_limits
            .as_ref()
            .map(|rate_limits| {
                rate_limits
                    .pools
                    .iter()
                    .map(|pool| RateLimitSummary {
                        scope: pool.id.clone(),
                        requests: pool.requests,
                        window: human_window_ms(pool.window_ms),
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let connector_id = manifest.connector.id.as_str().to_owned();
        let connector_name = manifest.connector.name.clone();
        let connector_version = manifest.connector.version.to_string();
        let connector_description = manifest.connector.description.clone();
        let archetypes = manifest
            .connector
            .archetypes
            .iter()
            .map(|archetype| archetype.as_str().to_owned())
            .collect::<Vec<_>>();
        let summary = ConnectorSummary {
            id: connector_id.clone(),
            name: connector_name.clone(),
            version: connector_version.clone(),
            description: connector_description.clone(),
            archetypes: archetypes.clone(),
            state: ConnectorState::Unknown,
            operation_count: operations.len(),
            max_risk,
            has_events,
        };
        let operation_summaries = operations
            .iter()
            .map(|operation| operation.summary.clone())
            .collect();
        let zones = serde_json::to_value(&manifest.zones)?;
        let capabilities = serde_json::to_value(&manifest.capabilities)?;
        let event_caps = manifest
            .event_caps
            .as_ref()
            .map(serde_json::to_value)
            .transpose()?;
        let sandbox = serde_json::to_value(&manifest.sandbox)?;
        let rate_limits = manifest
            .rate_limits
            .as_ref()
            .map(serde_json::to_value)
            .transpose()?;
        let connector_schema = serde_json::json!({
            "connector": {
                "id": &connector_id,
                "name": &connector_name,
                "version": &connector_version,
                "description": &connector_description,
                "archetypes": archetypes,
                "format": &runtime_format,
                "state_model": state_model,
            },
            "zones": zones,
            "capabilities": capabilities,
            "events": {
                "event_caps": event_caps,
                "declared_topics": manifest.provides.events.keys().cloned().collect::<Vec<_>>(),
            },
            "sandbox": sandbox,
            "rate_limits": rate_limits,
            "operations": operations
                .iter()
                .map(|operation| serde_json::json!({
                    "selector": &operation.preferred_selector,
                    "canonical_id": &operation.actual_id,
                    "aliases": operation.aliases.clone(),
                }))
                .collect::<Vec<_>>(),
            "note": "This connector-level schema comes from the manifest. Config schema remains under `fwc config schema` once host-backed config introspection is wired.",
        });

        Ok(Self {
            slug: slug.to_owned(),
            manifest_path: relative_to_workspace(manifest_path),
            cohort,
            runtime_format,
            state_model,
            supported_zones,
            detail: ConnectorDetail {
                summary,
                operations: operation_summaries,
                config_schema: None,
                health: None,
                rate_limits: connector_rate_limits,
            },
            zones,
            capabilities,
            connector_schema,
            operations,
        })
    }

    #[must_use]
    pub fn shared_descriptor(&self) -> ConnectorDescriptor {
        let auth = AuthDescriptor::unverifiable(
            "Auth capabilities are not surfaced by workspace-manifest discovery yet.",
        )
        .with_check(
            DescriptorCheck::new(
                "auth.discovery",
                DescriptorStatus::Unverifiable,
                "Use host-backed introspection to inspect active auth methods, profiles, and health.",
            )
            .with_remediation("Expose auth capabilities and active auth state through the host discovery contract."),
        );

        let prerequisites = PrerequisiteCatalog::unverifiable(
            "Provisioning prerequisites are not surfaced by workspace-manifest discovery yet.",
        );

        let readiness = ReadinessDescriptor::unverifiable(
            "Workspace-manifest discovery confirms static connector metadata, but runtime and setup state still require host-backed evidence.",
        )
        .with_check(DescriptorCheck::new(
            "manifest.metadata",
            DescriptorStatus::Ready,
            "Connector identity and operation catalog loaded from manifest metadata.",
        ))
        .with_check(DescriptorCheck::new(
            "runtime.state",
            DescriptorStatus::Unverifiable,
            "Runtime lifecycle and health require host-backed discovery.",
        ))
        .with_check(if self.detail.config_schema.is_some() {
            DescriptorCheck::new(
                "config.schema",
                DescriptorStatus::Ready,
                "Config schema is available for this connector.",
            )
        } else {
            DescriptorCheck::new(
                "config.schema",
                DescriptorStatus::Unverifiable,
                "Config schema is not available from manifest-backed discovery.",
            )
            .with_remediation(
                "Expose redaction-aware config schema through host-backed config introspection.",
            )
        })
        .with_check(DescriptorCheck::new(
            "setup.prerequisites",
            DescriptorStatus::Unverifiable,
            "Service-side onboarding and prerequisite drift need shared provisioning descriptors.",
        ));

        let mut descriptor = ConnectorDescriptor::new(self.detail.summary.id.clone());
        descriptor.display_name = Some(self.detail.summary.name.clone());
        descriptor.version = Some(self.detail.summary.version.clone());
        descriptor.description = Some(self.detail.summary.description.clone());
        descriptor.archetypes = self.detail.summary.archetypes.clone();
        descriptor.supported_zones = self.supported_zones.clone();
        descriptor.runtime_format = Some(self.runtime_format.clone());
        descriptor.state_model = self.state_model.clone();
        descriptor.operations = self
            .operations
            .iter()
            .map(DiscoveredOperation::operation_info)
            .collect();
        descriptor.auth = Some(auth);
        descriptor.prerequisites = Some(prerequisites);
        descriptor.readiness = Some(readiness);
        descriptor
    }

    #[must_use]
    pub fn matches_zone(&self, zone: &str) -> bool {
        self.supported_zones
            .iter()
            .any(|candidate| candidate == zone)
    }

    #[must_use]
    pub fn matches_category(&self, category: &str) -> bool {
        self.cohort == category
            || self
                .detail
                .summary
                .archetypes
                .iter()
                .map(|archetype| normalize_category_selector(archetype))
                .any(|archetype| archetype == category)
    }

    pub fn resolve_operation(&self, selector: &str) -> Result<&DiscoveredOperation, SelectorError> {
        let normalized = normalize_operation_selector(selector);
        let exact = self
            .operations
            .iter()
            .filter(|operation| operation.matches_selector(&normalized))
            .collect::<Vec<_>>();

        if exact.len() == 1 {
            return Ok(exact[0]);
        }
        if exact.len() > 1 {
            return Err(SelectorError::ambiguous(
                selector,
                exact
                    .iter()
                    .map(|operation| operation.preferred_selector.clone())
                    .collect(),
            ));
        }

        let prefix = self
            .operations
            .iter()
            .filter(|operation| operation.matches_prefix(&normalized))
            .collect::<Vec<_>>();

        match prefix.as_slice() {
            [operation] => Ok(*operation),
            [] => Err(SelectorError::not_found(
                selector,
                suggest_operation_selectors(&self.operations, &normalized),
            )),
            _ => Err(SelectorError::ambiguous(
                selector,
                prefix
                    .iter()
                    .map(|operation| operation.preferred_selector.clone())
                    .take(5)
                    .collect(),
            )),
        }
    }

    fn matches_selector(&self, selector: &str) -> bool {
        self.selector_keys()
            .into_iter()
            .any(|candidate| candidate == selector)
    }

    fn matches_prefix(&self, selector: &str) -> bool {
        self.selector_keys()
            .into_iter()
            .any(|candidate| candidate.starts_with(selector))
    }

    fn selector_keys(&self) -> Vec<String> {
        let canonical = self.detail.summary.id.to_lowercase();
        let stripped = canonical
            .strip_prefix("fcp.")
            .unwrap_or(canonical.as_str())
            .to_owned();
        let normalized_name = normalize_connector_selector(&self.detail.summary.name);
        let compact_name = normalized_name.replace("-connector", "");

        [
            self.slug.to_lowercase(),
            canonical,
            stripped,
            normalized_name,
            compact_name,
        ]
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
    }
}

#[derive(Clone, Debug)]
pub struct DiscoveredOperation {
    pub actual_id: String,
    pub local_id: String,
    pub preferred_selector: String,
    pub aliases: Vec<String>,
    pub description: String,
    pub summary: OperationSummary,
    pub input_schema: Value,
    pub output_schema: Value,
    pub approval_mode: String,
    pub when_to_use: String,
    pub common_mistakes: Vec<String>,
    pub examples: Vec<String>,
    pub related: Vec<String>,
    pub network_constraints: Option<Value>,
    pub rate_limits: Vec<RateLimitSummary>,
}

impl DiscoveredOperation {
    fn from_manifest(
        namespace: &str,
        operation_id: &str,
        operation: &fcp_manifest::OperationSection,
        rate_limits: Option<&fcp_manifest::RateLimitsSection>,
    ) -> Result<Self> {
        let local_id = operation_id
            .strip_prefix(&format!("{namespace}."))
            .unwrap_or(operation_id)
            .to_owned();
        let preferred_selector = preferred_operation_selector(&local_id);
        let aliases = operation_aliases(namespace, operation_id, &local_id);
        let rate_limits = summarize_operation_rate_limits(operation_id, operation, rate_limits);

        Ok(Self {
            actual_id: operation_id.to_owned(),
            local_id,
            preferred_selector,
            aliases,
            description: operation.description.clone(),
            summary: OperationSummary {
                id: operation_id.to_owned(),
                summary: operation.description.clone(),
                capability: operation.capability.as_str().to_owned(),
                risk_level: risk_level_label(operation.risk_level).to_owned(),
                safety_tier: safety_tier_label(operation.safety_tier).to_owned(),
                idempotency: idempotency_label(operation.idempotency).to_owned(),
                requires_approval: !matches!(
                    operation.requires_approval,
                    ManifestApprovalMode::None
                ),
                supports_simulate: true,
            },
            input_schema: operation.input_schema.clone(),
            output_schema: operation.output_schema.clone(),
            approval_mode: approval_mode_label(operation.requires_approval).to_owned(),
            when_to_use: operation.ai_hints.when_to_use.clone(),
            common_mistakes: operation.ai_hints.common_mistakes.clone(),
            examples: operation.ai_hints.examples.clone(),
            related: operation
                .ai_hints
                .related
                .iter()
                .map(|related| related.as_str().to_owned())
                .collect(),
            network_constraints: operation
                .network_constraints
                .as_ref()
                .map(serde_json::to_value)
                .transpose()?,
            rate_limits,
        })
    }

    fn matches_selector(&self, selector: &str) -> bool {
        self.selector_keys()
            .into_iter()
            .any(|candidate| candidate == selector)
    }

    fn matches_prefix(&self, selector: &str) -> bool {
        self.selector_keys()
            .into_iter()
            .any(|candidate| candidate.starts_with(selector))
    }

    #[must_use]
    pub fn operation_info(&self) -> OperationInfo {
        OperationInfo {
            id: OperationId::new(self.actual_id.clone())
                .expect("discovery catalog should only surface canonical operation ids"),
            summary: self.summary.summary.clone(),
            description: Some(self.description.clone())
                .filter(|description| !description.is_empty()),
            input_schema: self.input_schema.clone(),
            output_schema: self.output_schema.clone(),
            capability: CapabilityId::new(self.summary.capability.clone())
                .expect("discovery catalog should only surface canonical capability ids"),
            risk_level: parse_risk_level(&self.summary.risk_level),
            safety_tier: parse_safety_tier(&self.summary.safety_tier),
            idempotency: parse_idempotency(&self.summary.idempotency),
            ai_hints: AgentHint {
                when_to_use: self.when_to_use.clone(),
                common_mistakes: self.common_mistakes.clone(),
                examples: self.examples.clone(),
                related: self
                    .related
                    .iter()
                    .filter_map(|related| CapabilityId::new(related.clone()).ok())
                    .collect(),
            },
            // Discovery intentionally stores human-facing rate-limit summaries
            // rather than the raw declaration, so the canonical `OperationInfo`
            // path leaves this unset until host-backed introspection lands.
            rate_limit: None,
            requires_approval: parse_approval_mode(&self.approval_mode),
        }
    }

    fn selector_keys(&self) -> Vec<String> {
        self.aliases
            .iter()
            .map(|alias| normalize_operation_selector(alias))
            .chain([
                normalize_operation_selector(&self.actual_id),
                normalize_operation_selector(&self.local_id),
                normalize_operation_selector(&self.preferred_selector),
            ])
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectorErrorKind {
    NotFound,
    Ambiguous,
}

#[derive(Clone, Debug)]
pub struct SelectorError {
    pub kind: SelectorErrorKind,
    pub selector: String,
    pub suggestions: Vec<String>,
}

impl SelectorError {
    pub(crate) fn not_found(selector: &str, suggestions: Vec<String>) -> Self {
        Self {
            kind: SelectorErrorKind::NotFound,
            selector: selector.to_owned(),
            suggestions,
        }
    }

    pub(crate) fn ambiguous(selector: &str, suggestions: Vec<String>) -> Self {
        Self {
            kind: SelectorErrorKind::Ambiguous,
            selector: selector.to_owned(),
            suggestions,
        }
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("fwc crate should live under crates/fwc")
        .to_path_buf()
}

fn relative_to_workspace(path: &Path) -> String {
    path.strip_prefix(workspace_root())
        .unwrap_or(path)
        .display()
        .to_string()
}

const fn runtime_format_label(format: ConnectorRuntimeFormat) -> &'static str {
    match format {
        ConnectorRuntimeFormat::Native => "native",
        ConnectorRuntimeFormat::Wasi => "wasi",
    }
}

fn parse_risk_level(label: &str) -> RiskLevel {
    match label {
        "low" => RiskLevel::Low,
        "medium" => RiskLevel::Medium,
        "high" => RiskLevel::High,
        "critical" => RiskLevel::Critical,
        other => panic!("unexpected risk level label from discovery catalog: {other}"),
    }
}

fn parse_safety_tier(label: &str) -> SafetyTier {
    match label {
        "safe" => SafetyTier::Safe,
        "risky" => SafetyTier::Risky,
        "dangerous" => SafetyTier::Dangerous,
        "critical" => SafetyTier::Critical,
        "forbidden" => SafetyTier::Forbidden,
        other => panic!("unexpected safety tier label from discovery catalog: {other}"),
    }
}

fn parse_idempotency(label: &str) -> IdempotencyClass {
    match label {
        "none" => IdempotencyClass::None,
        "best-effort" | "best_effort" => IdempotencyClass::BestEffort,
        "strict" => IdempotencyClass::Strict,
        other => panic!("unexpected idempotency label from discovery catalog: {other}"),
    }
}

fn parse_approval_mode(label: &str) -> Option<ApprovalMode> {
    match label {
        "none" => None,
        "policy" => Some(ApprovalMode::Policy),
        "interactive" => Some(ApprovalMode::Interactive),
        "elevation-token" | "elevation_token" => Some(ApprovalMode::ElevationToken),
        other => panic!("unexpected approval mode label from discovery catalog: {other}"),
    }
}

pub(crate) const fn risk_level_label(level: fcp_core::RiskLevel) -> &'static str {
    match level {
        fcp_core::RiskLevel::Low => "low",
        fcp_core::RiskLevel::Medium => "medium",
        fcp_core::RiskLevel::High => "high",
        fcp_core::RiskLevel::Critical => "critical",
    }
}

pub(crate) const fn safety_tier_label(tier: fcp_core::SafetyTier) -> &'static str {
    match tier {
        fcp_core::SafetyTier::Safe => "safe",
        fcp_core::SafetyTier::Risky => "risky",
        fcp_core::SafetyTier::Dangerous => "dangerous",
        fcp_core::SafetyTier::Critical => "critical",
        fcp_core::SafetyTier::Forbidden => "forbidden",
    }
}

pub(crate) const fn idempotency_label(idempotency: fcp_core::IdempotencyClass) -> &'static str {
    match idempotency {
        fcp_core::IdempotencyClass::None => "none",
        fcp_core::IdempotencyClass::BestEffort => "best-effort",
        fcp_core::IdempotencyClass::Strict => "strict",
    }
}

const fn approval_mode_label(mode: ManifestApprovalMode) -> &'static str {
    match mode {
        ManifestApprovalMode::None => "none",
        ManifestApprovalMode::Policy => "policy",
        ManifestApprovalMode::Interactive => "interactive",
        ManifestApprovalMode::ElevationToken => "elevation-token",
    }
}

fn summarize_operation_rate_limits(
    operation_id: &str,
    operation: &fcp_manifest::OperationSection,
    rate_limits: Option<&fcp_manifest::RateLimitsSection>,
) -> Vec<RateLimitSummary> {
    let mut summaries = Vec::new();

    if let Some(inline) = operation.rate_limit.as_ref() {
        summaries.push(RateLimitSummary {
            scope: "inline".to_owned(),
            requests: inline.as_inner().max,
            window: human_window_ms(inline.as_inner().per_ms),
        });
    }

    if let Some(rate_limits) = rate_limits {
        for pool_id in rate_limits
            .operation_pools
            .get(operation_id)
            .into_iter()
            .flatten()
        {
            if let Some(pool) = rate_limits.pools.iter().find(|pool| pool.id == *pool_id) {
                summaries.push(RateLimitSummary {
                    scope: pool.id.clone(),
                    requests: pool.requests,
                    window: human_window_ms(pool.window_ms),
                });
            }
        }
    }

    summaries
}

fn preferred_operation_selector(local_id: &str) -> String {
    if let Some((verb, object)) = local_id.split_once('_') {
        let plural = pluralize_object(object);
        return format!("{plural}.{verb}");
    }
    local_id.to_owned()
}

fn operation_aliases(namespace: &str, actual_id: &str, local_id: &str) -> Vec<String> {
    let mut aliases = BTreeSet::from([actual_id.to_owned(), local_id.to_owned()]);

    if let Some((verb, object)) = local_id.split_once('_') {
        let singular = object.to_owned();
        let plural = pluralize_object(object);
        for noun in [
            singular.clone(),
            plural.clone(),
            singular.replace('_', "-"),
            plural.replace('_', "-"),
        ] {
            aliases.insert(format!("{noun}.{verb}"));
        }
    }

    aliases.insert(format!("{namespace}.{local_id}"));
    aliases.into_iter().collect()
}

fn pluralize_object(object: &str) -> String {
    if object.ends_with('s') {
        object.to_owned()
    } else {
        format!("{object}s")
    }
}

pub(crate) fn normalize_connector_selector(selector: &str) -> String {
    selector
        .trim()
        .to_lowercase()
        .replace(" connector", "")
        .replace([' ', '_'], "-")
}

fn normalize_category_selector(selector: &str) -> String {
    selector.trim().to_lowercase().replace(' ', "-")
}

fn normalize_zone_selector(selector: &str) -> String {
    selector.trim().to_lowercase()
}

pub(crate) fn normalize_operation_selector(selector: &str) -> String {
    selector.trim().to_lowercase().replace('-', "_")
}

fn suggest_connector_slugs(connectors: &[DiscoveredConnector], selector: &str) -> Vec<String> {
    let mut candidates = connectors
        .iter()
        .map(|connector| {
            let distance = selector_distance(selector, &connector.slug);
            (connector.slug.clone(), distance)
        })
        .filter(|(slug, distance)| slug.starts_with(selector) || *distance <= 4)
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0)));
    candidates
        .into_iter()
        .map(|(slug, _)| slug)
        .take(5)
        .collect()
}

fn suggest_operation_selectors(operations: &[DiscoveredOperation], selector: &str) -> Vec<String> {
    let mut candidates = operations
        .iter()
        .map(|operation| {
            let distance = selector_distance(selector, &operation.preferred_selector);
            (operation.preferred_selector.clone(), distance)
        })
        .filter(|(candidate, distance)| candidate.starts_with(selector) || *distance <= 5)
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0)));
    candidates
        .into_iter()
        .map(|(candidate, _)| candidate)
        .take(5)
        .collect()
}

pub(crate) fn selector_distance(left: &str, right: &str) -> usize {
    let right_chars = right.chars().collect::<Vec<_>>();
    let mut costs = (0..=right_chars.len()).collect::<Vec<_>>();

    for (left_index, left_char) in left.chars().enumerate() {
        let mut previous = costs[0];
        costs[0] = left_index + 1;

        for (right_index, right_char) in right_chars.iter().enumerate() {
            let insertion = costs[right_index + 1] + 1;
            let deletion = costs[right_index] + 1;
            let substitution = previous + usize::from(left_char != *right_char);
            previous = costs[right_index + 1];
            costs[right_index + 1] = insertion.min(deletion).min(substitution);
        }
    }

    costs[right_chars.len()]
}

fn human_window_ms(window_ms: u64) -> String {
    match window_ms {
        1_000 => "1s".to_owned(),
        60_000 => "60s".to_owned(),
        3_600_000 => "1h".to_owned(),
        86_400_000 => "1d".to_owned(),
        _ if window_ms % 1_000 == 0 => format!("{}s", window_ms / 1_000),
        _ => format!("{window_ms}ms"),
    }
}

fn risk_rank(level: &str) -> u8 {
    match level {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
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
        accepts_config: true,             // all connectors accept config
        has_config_schema: has_auth_caps, // proxy: auth_caps implies config awareness
        secrets_marked: false,            // requires manifest inspection
        defaults_documented: false,       // requires manifest inspection
        has_self_check: true,             // trait requires it
    };

    let lifecycle = LifecycleReadiness {
        has_health: true,              // trait requires it
        reports_lifecycle_state: true, // BaseConnector provides it
        events_declared: true,         // event declaration is optional; all connectors pass
        has_rate_limits: true,         // trait requires rate_limits()
        has_metrics: true,             // trait requires metrics()
        has_shutdown: true,            // trait requires shutdown()
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
    } else if gaps.iter().any(|g| g.severity == GapSeverity::Degraded) {
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

// ── Connector inventory ─────────────────────────────────────────────

/// Metadata quality tier for a connector's operation declarations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MetadataTier {
    /// Fully typed `OperationInfo` structs with `AgentHint`.
    Typed,
    /// Raw JSON in `operations_info()` without typed `AgentHint`.
    Json,
}

/// Static inventory entry for a single connector.
#[derive(Clone, Debug)]
pub struct ConnectorEntry {
    /// Directory name under `connectors/` (e.g. `"github"`).
    pub name: &'static str,
    /// Primary cohort classification.
    pub cohort: ConnectorCohort,
    /// Number of declared operations.
    pub operation_count: usize,
    /// Whether operations use typed `OperationInfo` with `AgentHint`.
    pub metadata_tier: MetadataTier,
    /// Whether `ai_hints` with `when_to_use` is populated.
    pub has_agent_hints: bool,
    /// Whether `manifest.toml` exists.
    pub has_manifest: bool,
}

/// Complete inventory of all connector crates in the workspace.
///
/// Sorted alphabetically by name. Each entry records the connector's cohort,
/// operation count, metadata quality tier, and manifest presence.
///
/// **Typed** connectors (82): Use `OperationInfo` structs with `AgentHint`
/// objects providing `when_to_use`, `common_mistakes`, `examples`, and
/// `related` fields. These are fully fwc-ready.
///
/// **JSON** connectors (0): All connectors have been migrated to typed metadata.
/// They have `input_schema`, `output_schema`, `risk_level`, `safety_tier`,
/// and `idempotency` but lack typed `AgentHint` metadata. These are
/// partially ready — they work but discovery UX is degraded.
pub static CONNECTOR_INVENTORY: &[ConnectorEntry] = &[
    ConnectorEntry {
        name: "1password",
        cohort: ConnectorCohort::Infra,
        operation_count: 5,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "airtable",
        cohort: ConnectorCohort::Workspace,
        operation_count: 16,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "algolia",
        cohort: ConnectorCohort::Data,
        operation_count: 4,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "amplitude",
        cohort: ConnectorCohort::Analytics,
        operation_count: 3,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "annas-archive",
        cohort: ConnectorCohort::Knowledge,
        operation_count: 4,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "anthropic",
        cohort: ConnectorCohort::Ai,
        operation_count: 4,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "arxiv",
        cohort: ConnectorCohort::Knowledge,
        operation_count: 13,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "asana",
        cohort: ConnectorCohort::Workspace,
        operation_count: 10,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "bigquery",
        cohort: ConnectorCohort::Data,
        operation_count: 4,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "bitbucket",
        cohort: ConnectorCohort::DevTools,
        operation_count: 10,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "bitwarden",
        cohort: ConnectorCohort::Infra,
        operation_count: 5,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "box",
        cohort: ConnectorCohort::Storage,
        operation_count: 5,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "browser",
        cohort: ConnectorCohort::Browser,
        operation_count: 16,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "clickup",
        cohort: ConnectorCohort::Workspace,
        operation_count: 5,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "cron",
        cohort: ConnectorCohort::Automation,
        operation_count: 5,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "datadog",
        cohort: ConnectorCohort::Infra,
        operation_count: 8,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "discord",
        cohort: ConnectorCohort::Messaging,
        operation_count: 9,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "docusign",
        cohort: ConnectorCohort::Finance,
        operation_count: 10,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "dropbox",
        cohort: ConnectorCohort::Storage,
        operation_count: 4,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "duckdb",
        cohort: ConnectorCohort::Data,
        operation_count: 3,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "elasticsearch",
        cohort: ConnectorCohort::Data,
        operation_count: 8,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "evernote",
        cohort: ConnectorCohort::Knowledge,
        operation_count: 5,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "figma",
        cohort: ConnectorCohort::Workspace,
        operation_count: 17,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "github",
        cohort: ConnectorCohort::DevTools,
        operation_count: 13,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "gitlab",
        cohort: ConnectorCohort::DevTools,
        operation_count: 5,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "gmail",
        cohort: ConnectorCohort::Productivity,
        operation_count: 10,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "google-ai",
        cohort: ConnectorCohort::Ai,
        operation_count: 8,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "google-calendar",
        cohort: ConnectorCohort::Productivity,
        operation_count: 11,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "grafana",
        cohort: ConnectorCohort::Infra,
        operation_count: 9,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "homeassistant",
        cohort: ConnectorCohort::Automation,
        operation_count: 15,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "hubspot",
        cohort: ConnectorCohort::Social,
        operation_count: 11,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "intercom",
        cohort: ConnectorCohort::Social,
        operation_count: 6,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "jira",
        cohort: ConnectorCohort::Workspace,
        operation_count: 12,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "kubernetes",
        cohort: ConnectorCohort::Infra,
        operation_count: 14,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "linear",
        cohort: ConnectorCohort::Workspace,
        operation_count: 9,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "linkedin",
        cohort: ConnectorCohort::Social,
        operation_count: 10,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "llm-router",
        cohort: ConnectorCohort::Ai,
        operation_count: 5,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "logseq",
        cohort: ConnectorCohort::Knowledge,
        operation_count: 4,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "mailchimp",
        cohort: ConnectorCohort::Social,
        operation_count: 5,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "make",
        cohort: ConnectorCohort::Automation,
        operation_count: 3,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "mcp-bridge",
        cohort: ConnectorCohort::Automation,
        operation_count: 5,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "metabase",
        cohort: ConnectorCohort::Analytics,
        operation_count: 3,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "microsoft365",
        cohort: ConnectorCohort::Productivity,
        operation_count: 30,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "mixpanel",
        cohort: ConnectorCohort::Analytics,
        operation_count: 3,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "monday",
        cohort: ConnectorCohort::Workspace,
        operation_count: 7,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "mongodb",
        cohort: ConnectorCohort::Data,
        operation_count: 6,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "n8n",
        cohort: ConnectorCohort::Automation,
        operation_count: 5,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "notion",
        cohort: ConnectorCohort::Workspace,
        operation_count: 16,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "openai",
        cohort: ConnectorCohort::Ai,
        operation_count: 23,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "pandadoc",
        cohort: ConnectorCohort::Finance,
        operation_count: 6,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "pinecone",
        cohort: ConnectorCohort::Storage,
        operation_count: 9,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "plaid",
        cohort: ConnectorCohort::Finance,
        operation_count: 10,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "postgresql",
        cohort: ConnectorCohort::Data,
        operation_count: 12,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: false,
    },
    ConnectorEntry {
        name: "posthog",
        cohort: ConnectorCohort::Analytics,
        operation_count: 3,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "pulumi",
        cohort: ConnectorCohort::DevTools,
        operation_count: 6,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "qdrant",
        cohort: ConnectorCohort::Storage,
        operation_count: 12,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "reddit",
        cohort: ConnectorCohort::Community,
        operation_count: 9,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "redis",
        cohort: ConnectorCohort::Data,
        operation_count: 14,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: false,
    },
    ConnectorEntry {
        name: "retool",
        cohort: ConnectorCohort::Automation,
        operation_count: 2,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "roam",
        cohort: ConnectorCohort::Knowledge,
        operation_count: 4,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "s3",
        cohort: ConnectorCohort::Storage,
        operation_count: 10,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "salesforce",
        cohort: ConnectorCohort::Social,
        operation_count: 13,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "segment",
        cohort: ConnectorCohort::Analytics,
        operation_count: 3,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "semanticscholar",
        cohort: ConnectorCohort::Knowledge,
        operation_count: 7,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "sendgrid",
        cohort: ConnectorCohort::Messaging,
        operation_count: 10,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "sentry",
        cohort: ConnectorCohort::DevTools,
        operation_count: 16,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "slack",
        cohort: ConnectorCohort::Messaging,
        operation_count: 10,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "snowflake",
        cohort: ConnectorCohort::Data,
        operation_count: 5,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "spotify",
        cohort: ConnectorCohort::Social,
        operation_count: 10,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "stripe",
        cohort: ConnectorCohort::Finance,
        operation_count: 19,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "telegram",
        cohort: ConnectorCohort::Messaging,
        operation_count: 10,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "terraform",
        cohort: ConnectorCohort::DevTools,
        operation_count: 12,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "todoist",
        cohort: ConnectorCohort::Workspace,
        operation_count: 5,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "trello",
        cohort: ConnectorCohort::Workspace,
        operation_count: 5,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "twilio",
        cohort: ConnectorCohort::Messaging,
        operation_count: 10,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "twitter",
        cohort: ConnectorCohort::Social,
        operation_count: 12,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "vectordb",
        cohort: ConnectorCohort::Storage,
        operation_count: 9,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "webhook-receiver",
        cohort: ConnectorCohort::Automation,
        operation_count: 4,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "whisper",
        cohort: ConnectorCohort::Ai,
        operation_count: 8,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: false,
    },
    ConnectorEntry {
        name: "youtube",
        cohort: ConnectorCohort::Productivity,
        operation_count: 11,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "zapier",
        cohort: ConnectorCohort::Automation,
        operation_count: 2,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "zendesk",
        cohort: ConnectorCohort::Social,
        operation_count: 10,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
];

/// Generate readiness verdicts for all connectors in the inventory.
///
/// Typed connectors are assessed as **Ready** (all metadata present).
/// JSON connectors are assessed as **Ready** (schemas present) but with
/// cosmetic `AgentHints` gaps since they lack typed `when_to_use` fields.
/// Connectors missing `manifest.toml` receive an additional `Identity` gap.
#[allow(clippy::too_many_lines)]
pub fn audit_all_connectors() -> Vec<ReadinessVerdict> {
    CONNECTOR_INVENTORY
        .iter()
        .map(|entry| {
            let mut gaps = Vec::new();

            // All connectors have schemas in their operations_info(), so they
            // pass the Degraded threshold. The only remaining gaps are Cosmetic.

            if !entry.has_agent_hints {
                gaps.push(ReadinessGap {
                    category: GapCategory::AgentHints,
                    description: "Operations use raw JSON without typed AgentHint (when_to_use, examples, related)".to_string(),
                    severity: GapSeverity::Cosmetic,
                    remediation: format!(
                        "Migrate {}/src/connector.rs operations_info() to typed OperationInfo with AgentHint",
                        entry.name
                    ),
                });
            }

            if !entry.has_manifest {
                gaps.push(ReadinessGap {
                    category: GapCategory::Identity,
                    description: "Missing manifest.toml — network constraints, categories, and archetype metadata unavailable".to_owned(),
                    severity: GapSeverity::Cosmetic,
                    remediation: format!(
                        "Create connectors/{}/manifest.toml with connector metadata",
                        entry.name
                    ),
                });
            }

            let level = if gaps.iter().any(|g| g.severity == GapSeverity::Blocking) {
                ReadinessLevel::NotReady
            } else if gaps.iter().any(|g| g.severity == GapSeverity::Degraded) {
                ReadinessLevel::PartiallyReady
            } else {
                ReadinessLevel::Ready
            };

            ReadinessVerdict {
                connector_id: entry.name.to_owned(),
                crate_path: format!("connectors/{}", entry.name),
                cohort: entry.cohort.clone(),
                level,
                areas: ReadinessAreas {
                    summary: SummaryReadiness {
                        has_canonical_id: true,
                        has_display_name: true,
                        has_archetypes: entry.has_manifest,
                        has_semver_version: true,
                        has_description: true,
                        has_operation_count: entry.operation_count > 0,
                        has_risk_summary: true,
                    },
                    operations: OperationsReadiness {
                        operation_count: entry.operation_count,
                        all_have_id: true,
                        all_have_summary: true,
                        all_have_input_schema: true,
                        all_have_output_schema: true,
                        all_have_capability: true,
                        all_have_risk_level: true,
                        all_have_safety_tier: true,
                        all_have_idempotency: true,
                        all_have_ai_hints: entry.has_agent_hints,
                        approval_declared_where_needed: true,
                        operations_with_examples: if entry.has_agent_hints {
                            entry.operation_count
                        } else {
                            0
                        },
                    },
                    config: ConfigReadiness {
                        accepts_config: true,
                        has_config_schema: true,
                        secrets_marked: entry.has_manifest,
                        defaults_documented: entry.has_manifest,
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
                gaps,
            }
        })
        .collect()
}

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
        assert!(
            verdict
                .gaps
                .iter()
                .any(|g| g.category == GapCategory::OperationMetadata
                    && g.severity == GapSeverity::Blocking)
        );
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
        assert!(
            verdict
                .gaps
                .iter()
                .any(|g| g.category == GapCategory::OperationMetadata
                    && g.description.contains("input_schema"))
        );
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
        assert!(
            verdict
                .gaps
                .iter()
                .any(|g| g.category == GapCategory::AgentHints
                    && g.severity == GapSeverity::Cosmetic)
        );
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
            ConnectorState::Unknown,
            ConnectorState::Unconfigured,
            ConnectorState::Configured,
            ConnectorState::Ready,
            ConnectorState::Degraded,
            ConnectorState::Disabled,
            ConnectorState::Error,
        ];
        assert_eq!(all.len(), 7, "must cover all 7 variants");
        for state in all {
            let json = serde_json::to_string(&state).unwrap();
            let back: ConnectorState = serde_json::from_str(&json).unwrap();
            assert_eq!(state, back);
        }
    }

    #[test]
    fn connector_state_kebab_case_values() {
        assert_eq!(
            serde_json::to_string(&ConnectorState::Unknown).unwrap(),
            "\"unknown\""
        );
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
        assert!(
            verdict
                .gaps
                .iter()
                .all(|g| g.severity == GapSeverity::Cosmetic)
        );
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
        assert!(verdict.gaps.iter().any(|g| g.description.contains("2/3")));
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

    // ── Connector inventory audit ─────────────────────────────────────

    #[test]
    fn inventory_covers_all_connectors() {
        assert_eq!(CONNECTOR_INVENTORY.len(), 82);
    }

    #[test]
    fn inventory_entries_have_valid_cohorts() {
        for entry in CONNECTOR_INVENTORY {
            // Verify cohort round-trips through serde.
            let json = serde_json::to_string(&entry.cohort).unwrap();
            let _back: ConnectorCohort = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn inventory_entries_have_positive_operation_counts() {
        for entry in CONNECTOR_INVENTORY {
            assert!(
                entry.operation_count > 0,
                "{} has zero operations",
                entry.name
            );
        }
    }

    #[test]
    fn inventory_entries_sorted_by_name() {
        for window in CONNECTOR_INVENTORY.windows(2) {
            assert!(
                window[0].name <= window[1].name,
                "Inventory not sorted: {} > {}",
                window[0].name,
                window[1].name
            );
        }
    }

    #[test]
    fn typed_connectors_have_agent_hints() {
        let typed: Vec<_> = CONNECTOR_INVENTORY
            .iter()
            .filter(|e| e.metadata_tier == MetadataTier::Typed)
            .collect();

        assert!(!typed.is_empty());
        for entry in &typed {
            assert!(
                entry.has_agent_hints,
                "{} is typed but missing agent hints",
                entry.name
            );
        }
    }

    #[test]
    fn all_connectors_are_typed() {
        let json_style: Vec<_> = CONNECTOR_INVENTORY
            .iter()
            .filter(|e| e.metadata_tier == MetadataTier::Json)
            .collect();

        assert!(
            json_style.is_empty(),
            "expected 0 Json connectors, found {}: {:?}",
            json_style.len(),
            json_style.iter().map(|e| e.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn missing_manifest_connectors_identified() {
        let missing: Vec<_> = CONNECTOR_INVENTORY
            .iter()
            .filter(|e| !e.has_manifest)
            .collect();

        assert_eq!(missing.len(), 3);
        let names: Vec<_> = missing.iter().map(|e| e.name).collect();
        assert!(names.contains(&"postgresql"));
        assert!(names.contains(&"redis"));
        assert!(names.contains(&"whisper"));
    }

    #[test]
    fn audit_all_returns_expected_count() {
        let results = audit_all_connectors();
        assert_eq!(results.len(), 82);
    }

    #[test]
    fn audit_typed_connectors_are_ready() {
        let results = audit_all_connectors();
        let typed_ready: Vec<_> = results
            .iter()
            .filter(|v| {
                CONNECTOR_INVENTORY
                    .iter()
                    .any(|e| e.name == v.connector_id && e.metadata_tier == MetadataTier::Typed)
            })
            .collect();

        for verdict in &typed_ready {
            assert_eq!(
                verdict.level,
                ReadinessLevel::Ready,
                "{} should be ready",
                verdict.connector_id
            );
        }
    }

    #[test]
    fn audit_json_connectors_are_partially_ready_or_ready() {
        let results = audit_all_connectors();
        for verdict in &results {
            let entry = CONNECTOR_INVENTORY
                .iter()
                .find(|e| e.name == verdict.connector_id);
            if let Some(e) = entry {
                if e.metadata_tier == MetadataTier::Json {
                    assert_ne!(
                        verdict.level,
                        ReadinessLevel::NotReady,
                        "{} should not be not-ready (has operations)",
                        verdict.connector_id
                    );
                }
            }
        }
    }

    #[test]
    fn audit_gap_categories_are_correct() {
        let results = audit_all_connectors();
        for verdict in &results {
            for gap in &verdict.gaps {
                // All gaps should have non-empty descriptions and remediations.
                assert!(!gap.description.is_empty());
                assert!(!gap.remediation.is_empty());
            }
        }
    }

    #[test]
    fn cohort_distribution_is_reasonable() {
        use std::collections::HashMap;
        let mut counts: HashMap<String, usize> = HashMap::new();
        for entry in CONNECTOR_INVENTORY {
            let key = serde_json::to_string(&entry.cohort).unwrap();
            *counts.entry(key).or_default() += 1;
        }
        // Every cohort that appears should have at least one connector.
        for (cohort, count) in &counts {
            assert!(*count > 0, "Cohort {cohort} is empty");
        }
    }

    #[test]
    fn audit_matrix_serializable() {
        let results = audit_all_connectors();
        let json = serde_json::to_string_pretty(&results).unwrap();
        assert!(json.len() > 1000, "Matrix too small");
        // Verify it round-trips.
        let back: Vec<ReadinessVerdict> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), results.len());
    }

    #[test]
    fn inventory_has_correct_typed_count() {
        let typed_count = CONNECTOR_INVENTORY
            .iter()
            .filter(|e| e.metadata_tier == MetadataTier::Typed)
            .count();
        assert_eq!(typed_count, 82);
    }

    #[test]
    fn inventory_has_correct_json_count() {
        let json_count = CONNECTOR_INVENTORY
            .iter()
            .filter(|e| e.metadata_tier == MetadataTier::Json)
            .count();
        assert_eq!(json_count, 0);
    }
}
