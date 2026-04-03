//! Test observability contract: logging, artifact, redaction, and replay for fwc validation.
//!
//! Defines the structured contract that all fwc test layers (unit, integration, E2E,
//! snapshot, benchmark) use for:
//!
//! - **Scenario identification**: Structured `{layer}:{suite}:{case}` naming.
//! - **Structured logging**: Typed trace entries with categories and levels.
//! - **Artifact bundles**: Deterministic directory layout for test outputs.
//! - **Redaction**: Automatic secret scrubbing with correlation digests.
//! - **Replay**: Captures everything needed to reproduce a scenario run.

use crate::readiness::CommandAvailability;
use fcp_testkit::{LogRedactionScanner, LogScanReport};

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write as _};
use std::path::PathBuf;
use std::time::SystemTime;

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, Visitor},
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

// ── 1. Scenario ID Schema ──────────────────────────────────────────────────

/// Scenario layer — the validation tier that produced this observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ScenarioLayer {
    Unit,
    Integration,
    E2E,
    Snapshot,
    Benchmark,
}

impl ScenarioLayer {
    /// Short lowercase label for directory names.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unit => "unit",
            Self::Integration => "integration",
            Self::E2E => "e2e",
            Self::Snapshot => "snapshot",
            Self::Benchmark => "benchmark",
        }
    }

    #[must_use]
    pub fn parse_label(value: &str) -> Option<Self> {
        match value {
            "unit" => Some(Self::Unit),
            "integration" => Some(Self::Integration),
            "e2e" => Some(Self::E2E),
            "snapshot" => Some(Self::Snapshot),
            "benchmark" => Some(Self::Benchmark),
            _ => None,
        }
    }
}

impl fmt::Display for ScenarioLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for ScenarioLayer {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ScenarioLayer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ScenarioLayerVisitor;

        impl Visitor<'_> for ScenarioLayerVisitor {
            type Value = ScenarioLayer;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("one of: unit, integration, e2e, snapshot, benchmark")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                ScenarioLayer::parse_label(value).ok_or_else(|| {
                    E::unknown_variant(
                        value,
                        &["unit", "integration", "e2e", "snapshot", "benchmark"],
                    )
                })
            }
        }

        deserializer.deserialize_str(ScenarioLayerVisitor)
    }
}

/// Structured scenario identifier: `{layer}:{suite}:{case}`.
///
/// Examples: `unit:routing:ambiguous_alias`, `e2e:lifecycle:install_verify_invoke`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ScenarioId {
    pub layer: ScenarioLayer,
    pub suite: String,
    pub case: String,
}

impl ScenarioId {
    /// Create a new scenario ID from its components.
    #[must_use]
    pub fn new(layer: ScenarioLayer, suite: impl Into<String>, case: impl Into<String>) -> Self {
        let suite = suite.into();
        let case = case.into();
        assert!(
            is_valid_scenario_component(&suite) && is_valid_scenario_component(&case),
            "scenario suite/case must be non-empty path-safe components"
        );
        Self { layer, suite, case }
    }

    /// Parse a colon-delimited string: `"unit:routing:ambiguous_alias"`.
    ///
    /// Returns `None` if the format is invalid.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.splitn(3, ':').collect();
        if parts.len() != 3 {
            return None;
        }
        let layer = ScenarioLayer::parse_label(parts[0])?;
        if !is_valid_scenario_component(parts[1]) || !is_valid_scenario_component(parts[2]) {
            return None;
        }
        Some(Self {
            layer,
            suite: parts[1].to_string(),
            case: parts[2].to_string(),
        })
    }

    /// The canonical colon-delimited string form.
    #[must_use]
    pub fn to_string_id(&self) -> String {
        format!("{}:{}:{}", self.layer, self.suite, self.case)
    }
}

fn is_valid_scenario_component(value: &str) -> bool {
    !value.is_empty() && value != "." && value != ".." && !value.contains(['/', '\\'])
}

impl fmt::Display for ScenarioId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.layer, self.suite, self.case)
    }
}

/// UUID-based trace correlation ID.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TraceId(String);

impl TraceId {
    /// Generate a new random trace ID.
    #[must_use]
    pub fn generate() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    /// Create from an existing UUID string.
    #[must_use]
    pub fn from_string(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// The UUID string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TraceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Metadata attached to every scenario run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScenarioContext {
    pub scenario_id: ScenarioId,
    pub trace_id: TraceId,
    pub layer: ScenarioLayer,
    pub started_at: SystemTime,
    pub tags: Vec<String>,
    pub environment: BTreeMap<String, String>,
}

impl ScenarioContext {
    /// Create a new context for the given scenario.
    #[must_use]
    pub fn new(scenario_id: ScenarioId) -> Self {
        let layer = scenario_id.layer;
        Self {
            scenario_id,
            trace_id: TraceId::generate(),
            layer,
            started_at: SystemTime::now(),
            tags: Vec::new(),
            environment: BTreeMap::new(),
        }
    }

    /// Add a tag.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Add an environment key-value pair.
    #[must_use]
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.environment.insert(key.into(), value.into());
        self
    }

    /// Set the trace ID explicitly (useful for replay correlation).
    #[must_use]
    pub fn with_trace_id(mut self, trace_id: TraceId) -> Self {
        self.trace_id = trace_id;
        self
    }
}

// ── 2. Structured Log Envelope ──────────────────────────────────────────────

/// Log severity level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl TraceLevel {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

impl fmt::Display for TraceLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Semantic category of a trace entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceCategory {
    /// A step in the CLI command pipeline.
    CliStep,
    /// An outbound request to the host.
    HostRequest,
    /// A receipt returned from the host.
    HostReceipt,
    /// An approval/denial decision.
    Approval,
    /// Token-count observation.
    TokenCount,
    /// A replay-related event.
    Replay,
    /// An assertion outcome.
    Assertion,
    /// Test setup/fixture activity.
    Setup,
    /// Test teardown/cleanup activity.
    Teardown,
}

impl TraceCategory {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CliStep => "cli_step",
            Self::HostRequest => "host_request",
            Self::HostReceipt => "host_receipt",
            Self::Approval => "approval",
            Self::TokenCount => "token_count",
            Self::Replay => "replay",
            Self::Assertion => "assertion",
            Self::Setup => "setup",
            Self::Teardown => "teardown",
        }
    }
}

impl fmt::Display for TraceCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Canonical phase marker for truthfulness scenarios.
///
/// These markers let replayable evidence distinguish offline preparation,
/// host-backed discovery, preflight, real invocation, reconnect, and
/// cancellation paths instead of collapsing everything into a generic
/// "command ran" story.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TruthPhase {
    Setup,
    OfflineArtifact,
    HostDiscovery,
    Preflight,
    Simulate,
    Invoke,
    HostReceipt,
    Reconnect,
    Cancellation,
    Teardown,
}

impl TruthPhase {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Setup => "setup",
            Self::OfflineArtifact => "offline-artifact",
            Self::HostDiscovery => "host-discovery",
            Self::Preflight => "preflight",
            Self::Simulate => "simulate",
            Self::Invoke => "invoke",
            Self::HostReceipt => "host-receipt",
            Self::Reconnect => "reconnect",
            Self::Cancellation => "cancellation",
            Self::Teardown => "teardown",
        }
    }
}

impl fmt::Display for TruthPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Explicit reconnect marker for long-lived live-runtime scenarios.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReconnectEvent {
    Attempted,
    Succeeded,
    Failed,
}

impl ReconnectEvent {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Attempted => "attempted",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }
}

/// Explicit cancellation marker for live operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CancellationEvent {
    Requested,
    Acknowledged,
    Completed,
    Rejected,
}

impl CancellationEvent {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Acknowledged => "acknowledged",
            Self::Completed => "completed",
            Self::Rejected => "rejected",
        }
    }
}

/// Truthfulness evidence attached to a trace entry.
///
/// This is the structured payload that makes `trace.jsonl`, `summary.json`,
/// and `replay.sh` mechanically useful for the host-first migration: it
/// records which truth surface a step used, where the data came from, which
/// phase of the request path ran, and which host/request identifiers allow
/// replay and auditing.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TruthContext {
    /// Machine-readable availability verdict for the command output.
    #[serde(
        default,
        alias = "command_mode",
        skip_serializing_if = "Option::is_none"
    )]
    pub command_availability: Option<CommandAvailability>,
    /// One or more provenance/source markers (for example
    /// `live-host-introspection` or `workspace-manifest`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance_markers: Vec<String>,
    /// Which phase of the truthfulness path this entry belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<TruthPhase>,
    /// Host request correlation identifier, if the step crossed into the live
    /// control plane.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_request_id: Option<String>,
    /// Host response identifier, if the host produced a distinct response id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_response_id: Option<String>,
    /// Receipt identifier associated with the step, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    /// Reconnect marker for long-lived streams or MCP sessions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconnect_event: Option<ReconnectEvent>,
    /// Cancellation marker for stop/cancel flows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancellation_event: Option<CancellationEvent>,
}

impl TruthContext {
    /// Create a new truth context anchored to a command availability verdict.
    #[must_use]
    pub fn new(command_availability: CommandAvailability) -> Self {
        Self {
            command_availability: Some(command_availability),
            ..Self::default()
        }
    }

    /// Add a provenance/source marker.
    #[must_use]
    pub fn with_provenance_marker(mut self, marker: impl Into<String>) -> Self {
        self.provenance_markers.push(marker.into());
        self
    }

    /// Set the phase marker.
    #[must_use]
    pub fn with_phase(mut self, phase: TruthPhase) -> Self {
        self.phase = Some(phase);
        self
    }

    /// Set the host request correlation identifier.
    #[must_use]
    pub fn with_host_request_id(mut self, id: impl Into<String>) -> Self {
        self.host_request_id = Some(id.into());
        self
    }

    /// Set the host response identifier.
    #[must_use]
    pub fn with_host_response_id(mut self, id: impl Into<String>) -> Self {
        self.host_response_id = Some(id.into());
        self
    }

    /// Set the receipt identifier.
    #[must_use]
    pub fn with_receipt_id(mut self, id: impl Into<String>) -> Self {
        self.receipt_id = Some(id.into());
        self
    }

    /// Mark the step as part of a reconnect sequence.
    #[must_use]
    pub fn with_reconnect_event(mut self, event: ReconnectEvent) -> Self {
        self.reconnect_event = Some(event);
        self
    }

    /// Mark the step as part of a cancellation sequence.
    #[must_use]
    pub fn with_cancellation_event(mut self, event: CancellationEvent) -> Self {
        self.cancellation_event = Some(event);
        self
    }
}

/// Reusable fixture metadata that can be projected into truth-context markers.
///
/// Host-backed integration matrices use this profile to keep trace evidence
/// aligned with the same fixture vocabulary across integration and E2E layers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostIntegrationTruthProfile {
    pub fixture_id: String,
    pub archetype: String,
    pub coverage_mode: String,
    pub risk_level: String,
    pub readiness: CommandAvailability,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance_markers: Vec<String>,
}

impl HostIntegrationTruthProfile {
    /// Create a truth profile for a named host-integration fixture.
    #[must_use]
    pub fn new(
        fixture_id: impl Into<String>,
        archetype: impl Into<String>,
        coverage_mode: impl Into<String>,
        risk_level: impl Into<String>,
        readiness: CommandAvailability,
    ) -> Self {
        Self {
            fixture_id: fixture_id.into(),
            archetype: archetype.into(),
            coverage_mode: coverage_mode.into(),
            risk_level: risk_level.into(),
            readiness,
            provenance_markers: Vec::new(),
        }
    }

    /// Add a provenance marker inherited from the fixture catalog.
    #[must_use]
    pub fn with_provenance_marker(mut self, marker: impl Into<String>) -> Self {
        self.provenance_markers.push(marker.into());
        self
    }

    fn fixture_markers(&self) -> [String; 4] {
        [
            format!("fixture:{}", self.fixture_id),
            format!("archetype:{}", self.archetype),
            format!("coverage-mode:{}", self.coverage_mode),
            format!("risk-level:{}", self.risk_level),
        ]
    }

    /// Build a new truth context seeded from this profile.
    #[must_use]
    pub fn truth_context(&self) -> TruthContext {
        self.apply_to_truth_context(TruthContext::new(self.readiness))
    }

    /// Enrich an existing truth context with fixture-derived markers.
    #[must_use]
    pub fn apply_to_truth_context(&self, mut truth: TruthContext) -> TruthContext {
        if truth.command_availability.is_none() {
            truth.command_availability = Some(self.readiness);
        }
        for marker in self.fixture_markers() {
            truth = truth.with_provenance_marker(marker);
        }
        for marker in &self.provenance_markers {
            truth = truth.with_provenance_marker(marker.clone());
        }
        truth
    }
}

/// A single structured log entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceEntry {
    pub timestamp: SystemTime,
    pub trace_id: TraceId,
    pub scenario_id: ScenarioId,
    pub level: TraceLevel,
    pub category: TraceCategory,
    pub message: String,
    pub fields: BTreeMap<String, serde_json::Value>,
    pub duration_ms: Option<u64>,
    pub redacted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub truth: Option<TruthContext>,
}

impl TraceEntry {
    /// Create a new trace entry with the minimum required fields.
    #[must_use]
    pub fn new(
        trace_id: &TraceId,
        scenario_id: &ScenarioId,
        level: TraceLevel,
        category: TraceCategory,
        message: impl Into<String>,
    ) -> Self {
        Self {
            timestamp: SystemTime::now(),
            trace_id: trace_id.clone(),
            scenario_id: scenario_id.clone(),
            level,
            category,
            message: message.into(),
            fields: BTreeMap::new(),
            duration_ms: None,
            redacted: false,
            truth: None,
        }
    }

    /// Add a key-value field.
    #[must_use]
    pub fn with_field(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.fields.insert(key.into(), value);
        self
    }

    /// Set the duration in milliseconds.
    #[must_use]
    pub const fn with_duration_ms(mut self, ms: u64) -> Self {
        self.duration_ms = Some(ms);
        self
    }

    /// Mark this entry as redacted.
    #[must_use]
    pub const fn mark_redacted(mut self) -> Self {
        self.redacted = true;
        self
    }

    /// Attach structured truthfulness evidence to this entry.
    #[must_use]
    pub fn with_truth_context(mut self, truth: TruthContext) -> Self {
        self.truth = Some(truth);
        self
    }
}

/// Ordered collection of trace entries with query helpers.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TraceLog {
    entries: Vec<TraceEntry>,
}

/// Summary statistics from a trace log.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TraceLogSummary {
    pub total_entries: usize,
    pub debug_count: usize,
    pub info_count: usize,
    pub warn_count: usize,
    pub error_count: usize,
    pub categories: BTreeMap<String, usize>,
    pub redacted_count: usize,
}

/// Aggregated truthfulness evidence extracted from a trace log.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TruthfulnessSummary {
    /// Count of entries by availability tag.
    #[serde(
        default,
        alias = "command_modes",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub command_availabilities: BTreeMap<String, usize>,
    /// Distinct provenance/source markers emitted during the run.
    pub provenance_markers: Vec<String>,
    /// Distinct phase markers emitted during the run.
    pub phases: Vec<String>,
    /// Distinct host request identifiers observed in the run.
    pub host_request_ids: Vec<String>,
    /// Distinct host response identifiers observed in the run.
    pub host_response_ids: Vec<String>,
    /// Distinct receipt identifiers observed in the run.
    pub receipt_ids: Vec<String>,
    /// Distinct reconnect events observed in the run.
    pub reconnect_events: Vec<String>,
    /// Distinct cancellation events observed in the run.
    pub cancellation_events: Vec<String>,
    /// Number of entries that explicitly used live runtime truth.
    pub live_entry_count: usize,
    /// Number of entries that explicitly used offline artifact truth.
    pub offline_entry_count: usize,
}

impl TruthfulnessSummary {
    /// Build a summary from the trace log's per-entry truth context.
    #[must_use]
    pub fn from_trace_log(log: &TraceLog) -> Self {
        let mut summary = Self::default();
        let mut provenance_markers = BTreeSet::new();
        let mut phases = BTreeSet::new();
        let mut host_request_ids = BTreeSet::new();
        let mut host_response_ids = BTreeSet::new();
        let mut receipt_ids = BTreeSet::new();
        let mut reconnect_events = BTreeSet::new();
        let mut cancellation_events = BTreeSet::new();

        for entry in log.entries() {
            let Some(truth) = &entry.truth else {
                continue;
            };

            if let Some(availability) = truth.command_availability {
                *summary
                    .command_availabilities
                    .entry(availability.tag().to_owned())
                    .or_insert(0) += 1;
                match availability {
                    CommandAvailability::LiveRuntime => summary.live_entry_count += 1,
                    CommandAvailability::OfflineArtifact => summary.offline_entry_count += 1,
                    CommandAvailability::Unsupported
                    | CommandAvailability::Planned
                    | CommandAvailability::Unavailable
                    | CommandAvailability::Denied
                    | CommandAvailability::Unknown => {}
                }
            }

            provenance_markers.extend(truth.provenance_markers.iter().cloned());

            if let Some(phase) = truth.phase {
                phases.insert(phase.as_str().to_owned());
            }
            if let Some(id) = &truth.host_request_id {
                host_request_ids.insert(id.clone());
            }
            if let Some(id) = &truth.host_response_id {
                host_response_ids.insert(id.clone());
            }
            if let Some(id) = &truth.receipt_id {
                receipt_ids.insert(id.clone());
            }
            if let Some(event) = truth.reconnect_event {
                reconnect_events.insert(event.as_str().to_owned());
            }
            if let Some(event) = truth.cancellation_event {
                cancellation_events.insert(event.as_str().to_owned());
            }
        }

        summary.provenance_markers = provenance_markers.into_iter().collect();
        summary.phases = phases.into_iter().collect();
        summary.host_request_ids = host_request_ids.into_iter().collect();
        summary.host_response_ids = host_response_ids.into_iter().collect();
        summary.receipt_ids = receipt_ids.into_iter().collect();
        summary.reconnect_events = reconnect_events.into_iter().collect();
        summary.cancellation_events = cancellation_events.into_iter().collect();
        summary
    }
}

impl TraceLog {
    /// Create an empty trace log.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Append an entry.
    pub fn append(&mut self, entry: TraceEntry) {
        self.entries.push(entry);
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the log is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// All entries (immutable slice).
    #[must_use]
    pub fn entries(&self) -> &[TraceEntry] {
        &self.entries
    }

    /// Filter entries by category.
    #[must_use]
    pub fn filter_by_category(&self, category: TraceCategory) -> Vec<&TraceEntry> {
        self.entries
            .iter()
            .filter(|e| e.category == category)
            .collect()
    }

    /// Filter entries by level.
    #[must_use]
    pub fn filter_by_level(&self, level: TraceLevel) -> Vec<&TraceEntry> {
        self.entries.iter().filter(|e| e.level == level).collect()
    }

    /// Compute summary statistics.
    #[must_use]
    pub fn summary(&self) -> TraceLogSummary {
        let mut s = TraceLogSummary {
            total_entries: self.entries.len(),
            ..TraceLogSummary::default()
        };
        for e in &self.entries {
            match e.level {
                TraceLevel::Debug => s.debug_count += 1,
                TraceLevel::Info => s.info_count += 1,
                TraceLevel::Warn => s.warn_count += 1,
                TraceLevel::Error => s.error_count += 1,
            }
            *s.categories
                .entry(e.category.as_str().to_string())
                .or_insert(0) += 1;
            if e.redacted {
                s.redacted_count += 1;
            }
        }
        s
    }

    /// Extract the truthfulness evidence summary for this log.
    #[must_use]
    pub fn truthfulness_summary(&self) -> TruthfulnessSummary {
        TruthfulnessSummary::from_trace_log(self)
    }

    /// Serialize all entries as newline-delimited JSON (JSONL).
    ///
    /// # Errors
    ///
    /// Returns an error if any entry fails to serialize.
    pub fn to_jsonl(&self) -> Result<String, serde_json::Error> {
        let mut buf = String::new();
        for entry in &self.entries {
            let line = serde_json::to_string(entry)?;
            buf.push_str(&line);
            buf.push('\n');
        }
        Ok(buf)
    }
}

/// Scan a trace log's JSONL payload using the shared E2E secret scanner.
///
/// # Errors
/// Returns a serialization error if the trace log cannot be encoded as JSONL.
pub fn scan_trace_log(log: &TraceLog) -> Result<LogScanReport, serde_json::Error> {
    let payload = log.to_jsonl()?;
    Ok(LogRedactionScanner::new().scan_report(&payload))
}

// ── 3. Artifact Bundle Layout ───────────────────────────────────────────────

/// Outcome of a scenario run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum BundleOutcome {
    Pass,
    Fail { reason: String },
    Skip { reason: String },
    Error { reason: String },
}

impl BundleOutcome {
    /// Whether the outcome is a pass.
    #[must_use]
    pub const fn is_pass(&self) -> bool {
        matches!(self, Self::Pass)
    }

    /// Whether the outcome is a failure.
    #[must_use]
    pub const fn is_fail(&self) -> bool {
        matches!(self, Self::Fail { .. })
    }
}

impl fmt::Display for BundleOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => f.write_str("pass"),
            Self::Fail { reason } => write!(f, "fail: {reason}"),
            Self::Skip { reason } => write!(f, "skip: {reason}"),
            Self::Error { reason } => write!(f, "error: {reason}"),
        }
    }
}

/// The directory structure for a scenario run's artifact output.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArtifactBundle {
    /// Deterministic bundle ID: `{scenario_string_id}@{timestamp_millis}`.
    pub bundle_id: String,
    /// Root directory path for the bundle.
    pub root: PathBuf,
    /// The scenario that produced this bundle.
    pub scenario_id: ScenarioId,
    /// Trace correlation ID.
    pub trace_id: TraceId,
    /// When the bundle was created.
    pub created_at: SystemTime,
}

impl ArtifactBundle {
    /// Create a new bundle with deterministic ID and path layout.
    ///
    /// Path pattern: `{base}/artifacts/{layer}/{suite}/{case}/{timestamp_millis}/`
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn new(base: &std::path::Path, scenario_id: &ScenarioId, trace_id: &TraceId) -> Self {
        assert!(
            is_valid_scenario_component(&scenario_id.suite)
                && is_valid_scenario_component(&scenario_id.case),
            "artifact bundles require non-empty path-safe scenario suite/case"
        );
        let now = SystemTime::now();
        let millis = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let bundle_id = format!("{}@{millis}", scenario_id.to_string_id());
        let root = base
            .join("artifacts")
            .join(scenario_id.layer.as_str())
            .join(&scenario_id.suite)
            .join(&scenario_id.case)
            .join(millis.to_string());

        Self {
            bundle_id,
            root,
            scenario_id: scenario_id.clone(),
            trace_id: trace_id.clone(),
            created_at: now,
        }
    }

    /// Path to `trace.jsonl` within the bundle.
    #[must_use]
    pub fn trace_path(&self) -> PathBuf {
        self.root.join("trace.jsonl")
    }

    /// Path to `summary.json` within the bundle.
    #[must_use]
    pub fn summary_path(&self) -> PathBuf {
        self.root.join("summary.json")
    }

    /// Path to `environment.json` within the bundle.
    #[must_use]
    pub fn environment_path(&self) -> PathBuf {
        self.root.join("environment.json")
    }

    /// Path to `session_transcript.json` within the bundle.
    #[must_use]
    pub fn session_transcript_path(&self) -> PathBuf {
        self.root.join("session_transcript.json")
    }

    /// Path to `replay.sh` within the bundle.
    #[must_use]
    pub fn replay_script_path(&self) -> PathBuf {
        self.root.join("replay.sh")
    }

    /// Path to `golden_snapshot` (optional) within the bundle.
    #[must_use]
    pub fn golden_snapshot_path(&self) -> PathBuf {
        self.root.join("golden_snapshot")
    }

    /// List all expected file names in a bundle.
    #[must_use]
    pub fn expected_files(&self) -> Vec<PathBuf> {
        vec![
            self.trace_path(),
            self.summary_path(),
            self.environment_path(),
            self.session_transcript_path(),
            self.replay_script_path(),
        ]
    }

    /// Return the canonical report artifacts keyed by stable label.
    #[must_use]
    pub fn report_artifact_paths(&self) -> BTreeMap<String, PathBuf> {
        BTreeMap::from([
            ("trace_jsonl".to_string(), self.trace_path()),
            ("summary_json".to_string(), self.summary_path()),
            ("environment_json".to_string(), self.environment_path()),
            (
                "session_transcript_json".to_string(),
                self.session_transcript_path(),
            ),
            ("replay_sh".to_string(), self.replay_script_path()),
        ])
    }
}

/// Shared verification bundle schema version used by replayable test artifacts.
pub const VERIFICATION_BUNDLE_SCHEMA_VERSION: &str = "fcp-verification-bundle/v1";

fn default_verification_bundle_schema_version() -> String {
    VERIFICATION_BUNDLE_SCHEMA_VERSION.to_string()
}

/// Metadata manifest for an artifact bundle.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArtifactManifest {
    #[serde(default = "default_verification_bundle_schema_version")]
    pub schema_version: String,
    pub scenario_id: ScenarioId,
    pub trace_id: TraceId,
    pub created_at: SystemTime,
    pub layer: ScenarioLayer,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub bundle_root: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub artifact_paths: BTreeMap<String, String>,
    pub file_count: usize,
    pub total_bytes: u64,
    pub outcome: BundleOutcome,
    #[serde(default)]
    pub log_summary: TraceLogSummary,
    #[serde(default)]
    pub truthfulness: TruthfulnessSummary,
}

impl ArtifactManifest {
    /// Create a manifest for a completed bundle.
    #[must_use]
    pub fn new(
        scenario_id: ScenarioId,
        trace_id: TraceId,
        file_count: usize,
        total_bytes: u64,
        outcome: BundleOutcome,
    ) -> Self {
        Self {
            schema_version: default_verification_bundle_schema_version(),
            layer: scenario_id.layer,
            scenario_id,
            trace_id,
            created_at: SystemTime::now(),
            bundle_root: String::new(),
            artifact_paths: BTreeMap::new(),
            file_count,
            total_bytes,
            outcome,
            log_summary: TraceLogSummary::default(),
            truthfulness: TruthfulnessSummary::default(),
        }
    }

    /// Attach bundle-path metadata so downstream tooling can locate canonical artifacts.
    #[must_use]
    pub fn with_bundle(mut self, bundle: &ArtifactBundle) -> Self {
        self.bundle_root = bundle.root.display().to_string();
        self.artifact_paths = bundle
            .report_artifact_paths()
            .into_iter()
            .map(|(label, path)| (label, path.display().to_string()))
            .collect();
        self
    }

    /// Attach trace-derived summaries to the manifest.
    #[must_use]
    pub fn with_trace_log(mut self, log: &TraceLog) -> Self {
        self.log_summary = log.summary();
        self.truthfulness = log.truthfulness_summary();
        self
    }

    /// Render a human-readable summary aligned with the shared E2E reporting vocabulary.
    #[must_use]
    pub fn render_e2e_summary(&self, bundle: &ArtifactBundle) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "Bundle: {}", bundle.bundle_id);
        let _ = writeln!(out, "Scenario: {}", self.scenario_id);
        let _ = writeln!(out, "Trace: {}", self.trace_id);
        let _ = writeln!(out, "Outcome: {}", self.outcome);
        let _ = writeln!(
            out,
            "Files: {} ({})",
            self.file_count,
            bundle.root.display()
        );
        let _ = writeln!(
            out,
            "Trace Summary: {} entries, {} errors, {} warnings, {} redacted",
            self.log_summary.total_entries,
            self.log_summary.error_count,
            self.log_summary.warn_count,
            self.log_summary.redacted_count
        );
        if !self.truthfulness.provenance_markers.is_empty() {
            let _ = writeln!(
                out,
                "Provenance: {}",
                self.truthfulness.provenance_markers.join(", ")
            );
        }
        if !self.truthfulness.phases.is_empty() {
            let _ = writeln!(out, "Phases: {}", self.truthfulness.phases.join(", "));
        }
        if !self.truthfulness.command_availabilities.is_empty() {
            let availability = self
                .truthfulness
                .command_availabilities
                .iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(out, "Availability: {availability}");
        }
        let _ = writeln!(out, "Artifacts:");
        for (label, path) in bundle.report_artifact_paths() {
            let _ = writeln!(out, "  {label}: {}", path.display());
        }
        out
    }
}

// ── 4. Redaction Rules ──────────────────────────────────────────────────────

/// A pattern-based redaction rule.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RedactionRule {
    /// Human-readable name for this rule.
    pub name: String,
    /// Field name patterns to match (case-insensitive substring).
    pub field_patterns: Vec<String>,
    /// Value prefix patterns to match.
    pub value_patterns: Vec<String>,
}

impl RedactionRule {
    /// Create a rule with field name patterns only.
    #[must_use]
    pub fn field_based(name: impl Into<String>, patterns: Vec<String>) -> Self {
        Self {
            name: name.into(),
            field_patterns: patterns,
            value_patterns: Vec::new(),
        }
    }

    /// Create a rule with value prefix patterns only.
    #[must_use]
    pub fn value_based(name: impl Into<String>, patterns: Vec<String>) -> Self {
        Self {
            name: name.into(),
            field_patterns: Vec::new(),
            value_patterns: patterns,
        }
    }

    /// Whether a field name matches any field pattern (case-insensitive).
    #[must_use]
    pub fn matches_field(&self, field_name: &str) -> bool {
        let lower = field_name.to_lowercase();
        self.field_patterns
            .iter()
            .any(|p| lower.contains(&p.to_lowercase()))
    }

    /// Whether a string value matches any value prefix pattern.
    #[must_use]
    pub fn matches_value(&self, value: &str) -> bool {
        self.value_patterns.iter().any(|p| value.starts_with(p))
    }
}

/// A redacted value placeholder with correlation digest.
///
/// Format: `"[REDACTED:sha256:<first8hex>]"`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactedValue {
    pub placeholder: String,
    pub digest: String,
}

impl RedactedValue {
    /// Create a redacted value from the original string.
    #[must_use]
    pub fn from_original(original: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(original.as_bytes());
        let hash = hasher.finalize();
        let digest = hex::encode(hash);
        let first8 = &digest[..8];
        Self {
            placeholder: format!("[REDACTED:sha256:{first8}]"),
            digest,
        }
    }

    /// The full SHA-256 hex digest of the original value.
    #[must_use]
    pub fn full_digest(&self) -> &str {
        &self.digest
    }

    /// The first 8 hex characters of the digest.
    #[must_use]
    pub fn short_digest(&self) -> &str {
        if self.digest.len() >= 8 {
            &self.digest[..8]
        } else {
            &self.digest
        }
    }
}

impl fmt::Display for RedactedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.placeholder)
    }
}

/// Engine that applies redaction rules to trace entries.
#[derive(Clone, Debug)]
pub struct RedactionEngine {
    rules: Vec<RedactionRule>,
}

impl RedactionEngine {
    /// Create a new engine with the given rules.
    #[must_use]
    pub const fn new(rules: Vec<RedactionRule>) -> Self {
        Self { rules }
    }

    /// Create an engine with the default rule set covering common secret patterns.
    #[must_use]
    pub fn default_rules() -> Self {
        Self {
            rules: vec![
                RedactionRule::field_based(
                    "sensitive_fields",
                    vec![
                        "token".to_string(),
                        "secret".to_string(),
                        "password".to_string(),
                        "api_key".to_string(),
                        "credential".to_string(),
                        "authorization".to_string(),
                    ],
                ),
                RedactionRule::value_based(
                    "sensitive_prefixes",
                    vec![
                        "Bearer ".to_string(),
                        "sk-".to_string(),
                        "ghp_".to_string(),
                        "xoxb-".to_string(),
                    ],
                ),
            ],
        }
    }

    /// The configured rules.
    #[must_use]
    pub fn rules(&self) -> &[RedactionRule] {
        &self.rules
    }

    /// Redact a single string value if it matches any value-based rule.
    #[must_use]
    pub fn redact_value(&self, value: &str) -> Option<RedactedValue> {
        for rule in &self.rules {
            if rule.matches_value(value) {
                return Some(RedactedValue::from_original(value));
            }
        }
        None
    }

    /// Check if a field name matches any field-based rule.
    #[must_use]
    pub fn should_redact_field(&self, field_name: &str) -> bool {
        self.rules.iter().any(|r| r.matches_field(field_name))
    }

    /// Apply redaction to a trace entry's fields, returning a redacted copy.
    #[must_use]
    pub fn redact_entry(&self, entry: &TraceEntry) -> TraceEntry {
        let mut redacted = entry.clone();
        let mut any_redacted = false;

        let mut new_fields = BTreeMap::new();
        for (key, value) in &entry.fields {
            if self.should_redact_field(key) {
                let original_str = match value {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                let rv = RedactedValue::from_original(&original_str);
                new_fields.insert(key.clone(), serde_json::Value::String(rv.placeholder));
                any_redacted = true;
            } else if let serde_json::Value::String(s) = value {
                if let Some(rv) = self.redact_value(s) {
                    new_fields.insert(key.clone(), serde_json::Value::String(rv.placeholder));
                    any_redacted = true;
                } else {
                    new_fields.insert(key.clone(), value.clone());
                }
            } else {
                new_fields.insert(key.clone(), value.clone());
            }
        }

        // Also check the message text for value-pattern matches
        let mut msg = entry.message.clone();
        for rule in &self.rules {
            for pattern in &rule.value_patterns {
                while let Some(start) = msg.find(pattern) {
                    // Skip past the pattern prefix to find the value portion,
                    // then extend to the next whitespace or end of string.
                    let after_prefix = start + pattern.len();
                    let rest = &msg[after_prefix..];
                    let value_end = rest.find(char::is_whitespace).unwrap_or(rest.len());
                    let token_end = after_prefix + value_end;
                    let rv = RedactedValue::from_original(&msg[start..token_end]);
                    msg.replace_range(start..token_end, &rv.placeholder);
                    any_redacted = true;
                }
            }
        }

        redacted.fields = new_fields;
        redacted.message = msg;
        if any_redacted {
            redacted.redacted = true;
        }
        redacted
    }

    /// Redact all entries in a trace log, returning a new redacted log.
    #[must_use]
    pub fn redact_log(&self, log: &TraceLog) -> TraceLog {
        let mut redacted = TraceLog::new();
        for entry in log.entries() {
            redacted.append(self.redact_entry(entry));
        }
        redacted
    }
}

// ── 5. Replay Contract ──────────────────────────────────────────────────────

/// Everything needed to replay a scenario.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplayEnvelope {
    /// Scenario that was run.
    pub scenario_id: ScenarioId,
    /// Correlation ID from the original run.
    pub trace_id: TraceId,
    /// Timestamp of the original run.
    pub timestamp: SystemTime,
    /// Command line invocation.
    pub command_line: String,
    /// Working directory.
    pub working_directory: String,
    /// Environment variables (redacted).
    pub environment: BTreeMap<String, String>,
    /// Git SHA at the time of the run (if available).
    pub git_sha: Option<String>,
    /// Rust toolchain version.
    pub rust_version: Option<String>,
    /// Optional command runner prefix. Cargo-backed replay defaults to
    /// `rch exec --` so CPU-heavy verification stays offloaded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_runner: Option<String>,
    /// Truthfulness evidence captured for replay/debugging.
    #[serde(default)]
    pub truthfulness: TruthfulnessSummary,
}

impl ReplayEnvelope {
    /// Create a new replay envelope.
    #[must_use]
    pub fn new(
        scenario_id: ScenarioId,
        trace_id: TraceId,
        command_line: impl Into<String>,
        working_directory: impl Into<String>,
    ) -> Self {
        let command_line = command_line.into();
        Self {
            scenario_id,
            trace_id,
            timestamp: SystemTime::now(),
            command_line: command_line.clone(),
            working_directory: working_directory.into(),
            environment: BTreeMap::new(),
            git_sha: None,
            rust_version: None,
            command_runner: default_command_runner(&command_line),
            truthfulness: TruthfulnessSummary::default(),
        }
    }

    /// Add a redacted environment variable.
    #[must_use]
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.environment.insert(key.into(), value.into());
        self
    }

    /// Set the git SHA.
    #[must_use]
    pub fn with_git_sha(mut self, sha: impl Into<String>) -> Self {
        self.git_sha = Some(sha.into());
        self
    }

    /// Set the Rust version.
    #[must_use]
    pub fn with_rust_version(mut self, version: impl Into<String>) -> Self {
        self.rust_version = Some(version.into());
        self
    }

    /// Override the command runner prefix.
    #[must_use]
    pub fn with_command_runner(mut self, runner: impl Into<String>) -> Self {
        self.command_runner = Some(runner.into());
        self
    }

    /// Attach truthfulness evidence for replay/debugging.
    #[must_use]
    pub fn with_truthfulness(mut self, truthfulness: TruthfulnessSummary) -> Self {
        self.truthfulness = truthfulness;
        self
    }
}

/// Human-readable replay instructions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplayInstructions {
    /// The shell commands to reproduce the scenario.
    pub steps: Vec<String>,
    /// Any prerequisites (tools, environment).
    pub prerequisites: Vec<String>,
    /// Notes or caveats.
    pub notes: Vec<String>,
}

impl ReplayInstructions {
    /// Generate replay instructions from an envelope.
    #[must_use]
    pub fn from_envelope(envelope: &ReplayEnvelope) -> Self {
        let mut steps = Vec::new();
        let mut prerequisites = Vec::new();
        let mut notes = Vec::new();

        // Step 1: cd
        steps.push(format!(
            "cd -- {}",
            shell_quote(&envelope.working_directory)
        ));

        // Step 2: git checkout if SHA available
        if let Some(sha) = &envelope.git_sha {
            steps.push(format!("git checkout {}", shell_quote(sha)));
            prerequisites.push("git".to_string());
        }

        // Step 3: run command under the captured environment.
        let command = render_replay_command(
            &envelope.command_line,
            envelope.command_runner.as_deref(),
            &envelope.environment,
        );
        steps.push(command);

        if let Some(rv) = &envelope.rust_version {
            prerequisites.push(format!("rustc {rv}"));
        }
        if envelope.command_runner.as_deref() == Some("rch exec --") {
            prerequisites.push("rch".to_string());
        }

        notes.push(format!("Original trace ID: {}", envelope.trace_id));
        notes.push(format!("Scenario: {}", envelope.scenario_id));
        if envelope.command_runner.as_deref() == Some("rch exec --") {
            notes.push(
                "Cargo-backed replay remains offloaded through `rch exec -- ...`.".to_owned(),
            );
        }
        if !envelope.truthfulness.command_availabilities.is_empty() {
            notes.push(format!(
                "Observed availability states: {}",
                envelope
                    .truthfulness
                    .command_availabilities
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if !envelope.truthfulness.provenance_markers.is_empty() {
            notes.push(format!(
                "Provenance markers: {}",
                envelope.truthfulness.provenance_markers.join(", ")
            ));
        }
        if !envelope.truthfulness.phases.is_empty() {
            notes.push(format!(
                "Truthfulness phases: {}",
                envelope.truthfulness.phases.join(", ")
            ));
        }
        if !envelope.truthfulness.host_request_ids.is_empty() {
            notes.push(format!(
                "Host request ids: {}",
                envelope.truthfulness.host_request_ids.join(", ")
            ));
        }
        if !envelope.truthfulness.receipt_ids.is_empty() {
            notes.push(format!(
                "Receipt ids: {}",
                envelope.truthfulness.receipt_ids.join(", ")
            ));
        }

        Self {
            steps,
            prerequisites,
            notes,
        }
    }

    /// Render as a shell script string.
    #[must_use]
    pub fn to_shell_script(&self) -> String {
        let mut script = String::from("#!/usr/bin/env bash\nset -euo pipefail\n\n");

        if !self.prerequisites.is_empty() {
            script.push_str("# Prerequisites:\n");
            for p in &self.prerequisites {
                let _ = writeln!(script, "#   - {p}");
            }
            script.push('\n');
        }

        if !self.notes.is_empty() {
            script.push_str("# Notes:\n");
            for n in &self.notes {
                let _ = writeln!(script, "#   {n}");
            }
            script.push('\n');
        }

        for step in &self.steps {
            script.push_str(step);
            script.push('\n');
        }

        script
    }
}

fn render_replay_command(
    command_line: &str,
    command_runner: Option<&str>,
    environment: &BTreeMap<String, String>,
) -> String {
    let mut parts = Vec::new();

    if !environment.is_empty() {
        parts.push("env --".to_owned());
        for (key, value) in environment {
            parts.push(shell_quote(&format!("{key}={value}")));
        }
    }

    if let Some(runner) = command_runner {
        parts.extend(shell_split_prefix(runner));
    }

    parts.push("bash".to_owned());
    parts.push("-lc".to_owned());
    parts.push(shell_quote(command_line));
    parts.join(" ")
}

fn shell_split_prefix(prefix: &str) -> Vec<String> {
    let trimmed = prefix.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let mut parts = Vec::new();
    let mut current = String::new();
    let mut chars = trimmed.chars();
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    while let Some(ch) = chars.next() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }

        if in_single {
            if ch == '\'' {
                in_single = false;
            } else {
                current.push(ch);
            }
            continue;
        }

        if in_double {
            match ch {
                '"' => in_double = false,
                '\\' => {
                    if let Some(next) = chars.next() {
                        current.push(next);
                    } else {
                        escaped = true;
                    }
                }
                _ => current.push(ch),
            }
            continue;
        }

        match ch {
            '\'' => in_single = true,
            '"' => in_double = true,
            '\\' => escaped = true,
            ch if ch.is_whitespace() => {
                if !current.is_empty() {
                    parts.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }

    if escaped || in_single || in_double {
        return vec![trimmed.to_owned()];
    }
    if !current.is_empty() {
        parts.push(current);
    }

    parts.into_iter().map(|part| shell_quote(&part)).collect()
}

fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_owned();
    }
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

// ── 6. Test Helpers ─────────────────────────────────────────────────────────

/// Build a `ScenarioContext` for a test.
#[must_use]
pub fn scenario_context(layer: ScenarioLayer, suite: &str, case: &str) -> ScenarioContext {
    ScenarioContext::new(ScenarioId::new(layer, suite, case))
}

/// Create a new empty trace log.
#[must_use]
pub const fn new_trace_log() -> TraceLog {
    TraceLog::new()
}

/// Emit a trace entry into a log.
pub fn emit_entry(
    log: &mut TraceLog,
    ctx: &ScenarioContext,
    level: TraceLevel,
    category: TraceCategory,
    message: &str,
) {
    let entry = TraceEntry::new(&ctx.trace_id, &ctx.scenario_id, level, category, message);
    log.append(entry);
}

/// Create an artifact bundle from a trace log and scenario context.
///
/// Returns the bundle metadata; does not write to disk.
#[must_use]
pub fn create_bundle(
    base: &std::path::Path,
    ctx: &ScenarioContext,
    log: &TraceLog,
    outcome: BundleOutcome,
) -> (ArtifactBundle, ArtifactManifest) {
    let bundle = ArtifactBundle::new(base, &ctx.scenario_id, &ctx.trace_id);
    let manifest = ArtifactManifest::new(
        ctx.scenario_id.clone(),
        ctx.trace_id.clone(),
        5, // trace.jsonl, summary.json, environment.json, session_transcript.json, replay.sh
        0, // no actual bytes written in-memory
        outcome,
    )
    .with_bundle(&bundle)
    .with_trace_log(log);
    (bundle, manifest)
}

fn default_command_runner(command_line: &str) -> Option<String> {
    if command_line.trim_start().starts_with("cargo ") {
        Some("rch exec --".to_owned())
    } else {
        None
    }
}

// We use hex encoding for SHA-256 digests. The `sha2` crate produces raw bytes;
// this tiny helper avoids pulling in a full `hex` crate for test-observability.
mod hex {
    /// Encode bytes as lowercase hexadecimal.
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().fold(String::new(), |mut acc, b| {
            use std::fmt::Write;
            let _ = write!(acc, "{b:02x}");
            acc
        })
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ScenarioLayer ───────────────────────────────────────────────────

    #[test]
    fn layer_as_str_roundtrip() {
        let layers = [
            (ScenarioLayer::Unit, "unit"),
            (ScenarioLayer::Integration, "integration"),
            (ScenarioLayer::E2E, "e2e"),
            (ScenarioLayer::Snapshot, "snapshot"),
            (ScenarioLayer::Benchmark, "benchmark"),
        ];
        for (layer, expected) in layers {
            assert_eq!(layer.as_str(), expected);
            assert_eq!(layer.to_string(), expected);
        }
    }

    #[test]
    fn layer_serde_roundtrip() {
        let layer = ScenarioLayer::E2E;
        let json = serde_json::to_string(&layer).unwrap();
        assert_eq!(json, r#""e2e""#);
        let back: ScenarioLayer = serde_json::from_str(&json).unwrap();
        assert_eq!(back, layer);
    }

    #[test]
    fn layer_all_variants_serialize() {
        let variants = [
            ScenarioLayer::Unit,
            ScenarioLayer::Integration,
            ScenarioLayer::E2E,
            ScenarioLayer::Snapshot,
            ScenarioLayer::Benchmark,
        ];
        for v in variants {
            let json = serde_json::to_string(&v).unwrap();
            let back: ScenarioLayer = serde_json::from_str(&json).unwrap();
            assert_eq!(back, v);
        }
    }

    // ── ScenarioId ──────────────────────────────────────────────────────

    #[test]
    fn scenario_id_display() {
        let id = ScenarioId::new(ScenarioLayer::Unit, "routing", "ambiguous_alias");
        assert_eq!(id.to_string(), "unit:routing:ambiguous_alias");
    }

    #[test]
    fn scenario_id_to_string_id() {
        let id = ScenarioId::new(ScenarioLayer::E2E, "lifecycle", "install_verify_invoke");
        assert_eq!(id.to_string_id(), "e2e:lifecycle:install_verify_invoke");
    }

    #[test]
    fn scenario_id_parse_valid() {
        let parsed = ScenarioId::parse("unit:routing:ambiguous_alias").unwrap();
        assert_eq!(parsed.layer, ScenarioLayer::Unit);
        assert_eq!(parsed.suite, "routing");
        assert_eq!(parsed.case, "ambiguous_alias");
    }

    #[test]
    fn scenario_id_parse_all_layers() {
        for layer_str in ["unit", "integration", "e2e", "snapshot", "benchmark"] {
            let input = format!("{layer_str}:suite:case");
            let parsed = ScenarioId::parse(&input);
            assert!(parsed.is_some(), "failed to parse layer {layer_str}");
        }
    }

    #[test]
    fn scenario_id_parse_invalid_layer() {
        assert!(ScenarioId::parse("unknown:suite:case").is_none());
    }

    #[test]
    fn scenario_id_parse_too_few_parts() {
        assert!(ScenarioId::parse("unit:routing").is_none());
        assert!(ScenarioId::parse("unit").is_none());
        assert!(ScenarioId::parse("").is_none());
    }

    #[test]
    fn scenario_id_parse_preserves_colons_in_case() {
        // splitn(3, ':') means the third part can contain colons
        let parsed = ScenarioId::parse("e2e:lifecycle:step:one:two").unwrap();
        assert_eq!(parsed.case, "step:one:two");
    }

    #[test]
    fn scenario_id_serde_roundtrip() {
        let id = ScenarioId::new(ScenarioLayer::Integration, "auth", "bearer_refresh");
        let json = serde_json::to_string(&id).unwrap();
        let back: ScenarioId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
    }

    #[test]
    fn scenario_id_equality() {
        let a = ScenarioId::new(ScenarioLayer::Unit, "x", "y");
        let b = ScenarioId::new(ScenarioLayer::Unit, "x", "y");
        let c = ScenarioId::new(ScenarioLayer::E2E, "x", "y");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // ── TraceId ─────────────────────────────────────────────────────────

    #[test]
    fn trace_id_generate_unique() {
        let a = TraceId::generate();
        let b = TraceId::generate();
        assert_ne!(a, b);
    }

    #[test]
    fn trace_id_from_string() {
        let id = TraceId::from_string("test-trace-123");
        assert_eq!(id.as_str(), "test-trace-123");
        assert_eq!(id.to_string(), "test-trace-123");
    }

    #[test]
    fn trace_id_serde_roundtrip() {
        let id = TraceId::from_string("abc-def");
        let json = serde_json::to_string(&id).unwrap();
        let back: TraceId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
    }

    // ── ScenarioContext ─────────────────────────────────────────────────

    #[test]
    fn scenario_context_builder() {
        let ctx = scenario_context(ScenarioLayer::Unit, "routing", "test_case")
            .with_tag("fast")
            .with_tag("deterministic")
            .with_env("RUST_LOG", "debug");

        assert_eq!(ctx.scenario_id.suite, "routing");
        assert_eq!(ctx.layer, ScenarioLayer::Unit);
        assert_eq!(ctx.tags.len(), 2);
        assert_eq!(ctx.tags[0], "fast");
        assert_eq!(ctx.environment.get("RUST_LOG").unwrap(), "debug");
    }

    #[test]
    fn scenario_context_with_trace_id() {
        let fixed_id = TraceId::from_string("fixed-trace");
        let ctx = scenario_context(ScenarioLayer::E2E, "s", "c").with_trace_id(fixed_id.clone());
        assert_eq!(ctx.trace_id, fixed_id);
    }

    #[test]
    fn scenario_context_serde_roundtrip() {
        let ctx = scenario_context(ScenarioLayer::Snapshot, "snap", "golden");
        let json = serde_json::to_string(&ctx).unwrap();
        let back: ScenarioContext = serde_json::from_str(&json).unwrap();
        assert_eq!(back.scenario_id, ctx.scenario_id);
        assert_eq!(back.trace_id, ctx.trace_id);
    }

    #[test]
    fn scenario_context_default_empty_tags_and_env() {
        let ctx = scenario_context(ScenarioLayer::Benchmark, "perf", "throughput");
        assert!(ctx.tags.is_empty());
        assert!(ctx.environment.is_empty());
    }

    // ── TraceLevel ──────────────────────────────────────────────────────

    #[test]
    fn trace_level_as_str() {
        assert_eq!(TraceLevel::Debug.as_str(), "debug");
        assert_eq!(TraceLevel::Info.as_str(), "info");
        assert_eq!(TraceLevel::Warn.as_str(), "warn");
        assert_eq!(TraceLevel::Error.as_str(), "error");
    }

    #[test]
    fn trace_level_display() {
        assert_eq!(TraceLevel::Error.to_string(), "error");
    }

    #[test]
    fn trace_level_serde_roundtrip() {
        for level in [
            TraceLevel::Debug,
            TraceLevel::Info,
            TraceLevel::Warn,
            TraceLevel::Error,
        ] {
            let json = serde_json::to_string(&level).unwrap();
            let back: TraceLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(back, level);
        }
    }

    // ── TraceCategory ───────────────────────────────────────────────────

    #[test]
    fn trace_category_as_str() {
        let cases = [
            (TraceCategory::CliStep, "cli_step"),
            (TraceCategory::HostRequest, "host_request"),
            (TraceCategory::HostReceipt, "host_receipt"),
            (TraceCategory::Approval, "approval"),
            (TraceCategory::TokenCount, "token_count"),
            (TraceCategory::Replay, "replay"),
            (TraceCategory::Assertion, "assertion"),
            (TraceCategory::Setup, "setup"),
            (TraceCategory::Teardown, "teardown"),
        ];
        for (cat, expected) in cases {
            assert_eq!(cat.as_str(), expected);
            assert_eq!(cat.to_string(), expected);
        }
    }

    #[test]
    fn trace_category_serde_roundtrip() {
        let cats = [
            TraceCategory::CliStep,
            TraceCategory::HostRequest,
            TraceCategory::HostReceipt,
            TraceCategory::Approval,
            TraceCategory::TokenCount,
            TraceCategory::Replay,
            TraceCategory::Assertion,
            TraceCategory::Setup,
            TraceCategory::Teardown,
        ];
        for cat in cats {
            let json = serde_json::to_string(&cat).unwrap();
            let back: TraceCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(back, cat);
        }
    }

    // ── TruthPhase / TruthContext ──────────────────────────────────────

    #[test]
    fn truth_phase_as_str_and_serde_roundtrip() {
        let phases = [
            TruthPhase::Setup,
            TruthPhase::OfflineArtifact,
            TruthPhase::HostDiscovery,
            TruthPhase::Preflight,
            TruthPhase::Simulate,
            TruthPhase::Invoke,
            TruthPhase::HostReceipt,
            TruthPhase::Reconnect,
            TruthPhase::Cancellation,
            TruthPhase::Teardown,
        ];
        for phase in phases {
            assert!(!phase.as_str().is_empty());
            let json = serde_json::to_string(&phase).unwrap();
            let back: TruthPhase = serde_json::from_str(&json).unwrap();
            assert_eq!(back, phase);
        }
    }

    #[test]
    fn truth_context_builder_sets_all_markers() {
        let truth = TruthContext::new(CommandAvailability::LiveRuntime)
            .with_provenance_marker("live-host-introspection")
            .with_phase(TruthPhase::Invoke)
            .with_host_request_id("req-1")
            .with_host_response_id("resp-1")
            .with_receipt_id("receipt-1")
            .with_reconnect_event(ReconnectEvent::Succeeded)
            .with_cancellation_event(CancellationEvent::Acknowledged);

        assert_eq!(
            truth.command_availability,
            Some(CommandAvailability::LiveRuntime)
        );
        assert_eq!(truth.provenance_markers, vec!["live-host-introspection"]);
        assert_eq!(truth.phase, Some(TruthPhase::Invoke));
        assert_eq!(truth.host_request_id.as_deref(), Some("req-1"));
        assert_eq!(truth.host_response_id.as_deref(), Some("resp-1"));
        assert_eq!(truth.receipt_id.as_deref(), Some("receipt-1"));
        assert_eq!(truth.reconnect_event, Some(ReconnectEvent::Succeeded));
        assert_eq!(
            truth.cancellation_event,
            Some(CancellationEvent::Acknowledged)
        );
    }

    // ── TraceEntry ──────────────────────────────────────────────────────

    #[test]
    fn trace_entry_construction() {
        let tid = TraceId::from_string("t1");
        let sid = ScenarioId::new(ScenarioLayer::Unit, "s", "c");
        let entry = TraceEntry::new(
            &tid,
            &sid,
            TraceLevel::Info,
            TraceCategory::CliStep,
            "hello",
        );
        assert_eq!(entry.message, "hello");
        assert_eq!(entry.level, TraceLevel::Info);
        assert_eq!(entry.category, TraceCategory::CliStep);
        assert!(!entry.redacted);
        assert!(entry.duration_ms.is_none());
        assert!(entry.fields.is_empty());
        assert!(entry.truth.is_none());
    }

    #[test]
    fn trace_entry_with_field() {
        let tid = TraceId::from_string("t1");
        let sid = ScenarioId::new(ScenarioLayer::Unit, "s", "c");
        let entry = TraceEntry::new(&tid, &sid, TraceLevel::Debug, TraceCategory::Setup, "setup")
            .with_field("connector", serde_json::Value::String("github".to_string()))
            .with_field("count", serde_json::json!(42));
        assert_eq!(entry.fields.len(), 2);
        assert_eq!(entry.fields["connector"], serde_json::json!("github"));
        assert_eq!(entry.fields["count"], serde_json::json!(42));
    }

    #[test]
    fn trace_entry_with_duration() {
        let tid = TraceId::from_string("t1");
        let sid = ScenarioId::new(ScenarioLayer::Unit, "s", "c");
        let entry = TraceEntry::new(&tid, &sid, TraceLevel::Info, TraceCategory::CliStep, "step")
            .with_duration_ms(150);
        assert_eq!(entry.duration_ms, Some(150));
    }

    #[test]
    fn trace_entry_with_truth_context() {
        let tid = TraceId::from_string("t1");
        let sid = ScenarioId::new(ScenarioLayer::Unit, "s", "c");
        let truth = TruthContext::new(CommandAvailability::OfflineArtifact)
            .with_provenance_marker("workspace-manifest")
            .with_phase(TruthPhase::OfflineArtifact);
        let entry = TraceEntry::new(&tid, &sid, TraceLevel::Info, TraceCategory::CliStep, "step")
            .with_truth_context(truth.clone());
        assert_eq!(entry.truth, Some(truth));
    }

    #[test]
    fn trace_entry_mark_redacted() {
        let tid = TraceId::from_string("t1");
        let sid = ScenarioId::new(ScenarioLayer::Unit, "s", "c");
        let entry = TraceEntry::new(
            &tid,
            &sid,
            TraceLevel::Warn,
            TraceCategory::Assertion,
            "warn",
        )
        .mark_redacted();
        assert!(entry.redacted);
    }

    #[test]
    fn trace_entry_serde_roundtrip() {
        let tid = TraceId::from_string("t1");
        let sid = ScenarioId::new(ScenarioLayer::Unit, "s", "c");
        let entry = TraceEntry::new(
            &tid,
            &sid,
            TraceLevel::Error,
            TraceCategory::HostReceipt,
            "fail",
        )
        .with_field("code", serde_json::json!(500))
        .with_duration_ms(99);
        let json = serde_json::to_string(&entry).unwrap();
        let back: TraceEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.message, "fail");
        assert_eq!(back.level, TraceLevel::Error);
        assert_eq!(back.duration_ms, Some(99));
    }

    // ── TraceLog ────────────────────────────────────────────────────────

    #[test]
    fn trace_log_empty() {
        let log = new_trace_log();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
    }

    #[test]
    fn trace_log_append_and_len() {
        let ctx = scenario_context(ScenarioLayer::Unit, "s", "c");
        let mut log = new_trace_log();
        emit_entry(
            &mut log,
            &ctx,
            TraceLevel::Info,
            TraceCategory::Setup,
            "start",
        );
        emit_entry(
            &mut log,
            &ctx,
            TraceLevel::Debug,
            TraceCategory::CliStep,
            "step",
        );
        assert_eq!(log.len(), 2);
        assert!(!log.is_empty());
    }

    #[test]
    fn trace_log_filter_by_category() {
        let ctx = scenario_context(ScenarioLayer::Unit, "s", "c");
        let mut log = new_trace_log();
        emit_entry(&mut log, &ctx, TraceLevel::Info, TraceCategory::Setup, "a");
        emit_entry(
            &mut log,
            &ctx,
            TraceLevel::Info,
            TraceCategory::CliStep,
            "b",
        );
        emit_entry(&mut log, &ctx, TraceLevel::Info, TraceCategory::Setup, "c");
        let setups = log.filter_by_category(TraceCategory::Setup);
        assert_eq!(setups.len(), 2);
        let cli = log.filter_by_category(TraceCategory::CliStep);
        assert_eq!(cli.len(), 1);
    }

    #[test]
    fn trace_log_filter_by_level() {
        let ctx = scenario_context(ScenarioLayer::Unit, "s", "c");
        let mut log = new_trace_log();
        emit_entry(&mut log, &ctx, TraceLevel::Debug, TraceCategory::Setup, "d");
        emit_entry(
            &mut log,
            &ctx,
            TraceLevel::Error,
            TraceCategory::Assertion,
            "e",
        );
        emit_entry(
            &mut log,
            &ctx,
            TraceLevel::Debug,
            TraceCategory::Teardown,
            "f",
        );
        assert_eq!(log.filter_by_level(TraceLevel::Debug).len(), 2);
        assert_eq!(log.filter_by_level(TraceLevel::Error).len(), 1);
        assert_eq!(log.filter_by_level(TraceLevel::Warn).len(), 0);
    }

    #[test]
    fn trace_log_summary() {
        let ctx = scenario_context(ScenarioLayer::Unit, "s", "c");
        let mut log = new_trace_log();
        emit_entry(&mut log, &ctx, TraceLevel::Info, TraceCategory::Setup, "a");
        emit_entry(
            &mut log,
            &ctx,
            TraceLevel::Debug,
            TraceCategory::CliStep,
            "b",
        );
        emit_entry(
            &mut log,
            &ctx,
            TraceLevel::Warn,
            TraceCategory::Assertion,
            "c",
        );
        emit_entry(
            &mut log,
            &ctx,
            TraceLevel::Error,
            TraceCategory::HostReceipt,
            "d",
        );

        let s = log.summary();
        assert_eq!(s.total_entries, 4);
        assert_eq!(s.info_count, 1);
        assert_eq!(s.debug_count, 1);
        assert_eq!(s.warn_count, 1);
        assert_eq!(s.error_count, 1);
        assert_eq!(s.categories.len(), 4);
        assert_eq!(s.categories["setup"], 1);
        assert_eq!(s.redacted_count, 0);
    }

    #[test]
    fn trace_log_summary_with_redacted() {
        let tid = TraceId::from_string("t");
        let sid = ScenarioId::new(ScenarioLayer::Unit, "s", "c");
        let mut log = new_trace_log();
        log.append(
            TraceEntry::new(&tid, &sid, TraceLevel::Info, TraceCategory::Setup, "ok")
                .mark_redacted(),
        );
        log.append(TraceEntry::new(
            &tid,
            &sid,
            TraceLevel::Info,
            TraceCategory::Teardown,
            "clean",
        ));
        assert_eq!(log.summary().redacted_count, 1);
    }

    #[test]
    fn trace_log_to_jsonl() {
        let ctx = scenario_context(ScenarioLayer::Unit, "s", "c");
        let mut log = new_trace_log();
        emit_entry(
            &mut log,
            &ctx,
            TraceLevel::Info,
            TraceCategory::Setup,
            "line1",
        );
        emit_entry(
            &mut log,
            &ctx,
            TraceLevel::Debug,
            TraceCategory::CliStep,
            "line2",
        );

        let jsonl = log.to_jsonl().unwrap();
        let lines: Vec<&str> = jsonl.lines().collect();
        assert_eq!(lines.len(), 2);
        // Each line should be valid JSON
        for line in lines {
            let _v: serde_json::Value = serde_json::from_str(line).unwrap();
        }
    }

    #[test]
    fn trace_log_serde_roundtrip() {
        let ctx = scenario_context(ScenarioLayer::Unit, "s", "c");
        let mut log = new_trace_log();
        emit_entry(&mut log, &ctx, TraceLevel::Info, TraceCategory::Setup, "hi");
        let json = serde_json::to_string(&log).unwrap();
        let back: TraceLog = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 1);
    }

    #[test]
    fn trace_log_entries_slice() {
        let ctx = scenario_context(ScenarioLayer::Unit, "s", "c");
        let mut log = new_trace_log();
        emit_entry(&mut log, &ctx, TraceLevel::Info, TraceCategory::Setup, "hi");
        let entries = log.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].message, "hi");
    }

    // ── BundleOutcome ───────────────────────────────────────────────────

    #[test]
    fn bundle_outcome_pass() {
        let o = BundleOutcome::Pass;
        assert!(o.is_pass());
        assert!(!o.is_fail());
        assert_eq!(o.to_string(), "pass");
    }

    #[test]
    fn bundle_outcome_fail() {
        let o = BundleOutcome::Fail {
            reason: "assertion".to_string(),
        };
        assert!(o.is_fail());
        assert!(!o.is_pass());
        assert!(o.to_string().contains("assertion"));
    }

    #[test]
    fn bundle_outcome_skip() {
        let o = BundleOutcome::Skip {
            reason: "not applicable".to_string(),
        };
        assert!(!o.is_pass());
        assert!(!o.is_fail());
        assert!(o.to_string().contains("not applicable"));
    }

    #[test]
    fn bundle_outcome_error() {
        let o = BundleOutcome::Error {
            reason: "timeout".to_string(),
        };
        assert!(!o.is_pass());
        assert!(o.to_string().contains("timeout"));
    }

    #[test]
    fn bundle_outcome_serde_roundtrip() {
        let cases = [
            BundleOutcome::Pass,
            BundleOutcome::Fail {
                reason: "r".to_string(),
            },
            BundleOutcome::Skip {
                reason: "s".to_string(),
            },
            BundleOutcome::Error {
                reason: "e".to_string(),
            },
        ];
        for o in cases {
            let json = serde_json::to_string(&o).unwrap();
            let back: BundleOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(back, o);
        }
    }

    // ── ArtifactBundle ──────────────────────────────────────────────────

    #[test]
    fn artifact_bundle_path_layout() {
        let base = PathBuf::from("/tmp/test-obs");
        let sid = ScenarioId::new(ScenarioLayer::Unit, "routing", "alias");
        let tid = TraceId::from_string("trace-1");
        let bundle = ArtifactBundle::new(&base, &sid, &tid);

        let root_str = bundle.root.to_string_lossy().to_string();
        assert!(root_str.starts_with("/tmp/test-obs/artifacts/unit/routing/alias/"));
        assert!(bundle.bundle_id.starts_with("unit:routing:alias@"));
    }

    #[test]
    fn artifact_bundle_expected_files() {
        let base = PathBuf::from("/tmp/tb");
        let sid = ScenarioId::new(ScenarioLayer::E2E, "life", "boot");
        let tid = TraceId::from_string("t");
        let bundle = ArtifactBundle::new(&base, &sid, &tid);
        let files = bundle.expected_files();
        assert_eq!(files.len(), 5);
    }

    #[test]
    fn artifact_bundle_report_artifact_paths_have_stable_labels() {
        let base = PathBuf::from("/tmp/tb");
        let sid = ScenarioId::new(ScenarioLayer::E2E, "life", "boot");
        let tid = TraceId::from_string("t");
        let bundle = ArtifactBundle::new(&base, &sid, &tid);
        let artifacts = bundle.report_artifact_paths();
        assert!(artifacts.contains_key("trace_jsonl"));
        assert!(artifacts.contains_key("summary_json"));
        assert!(artifacts.contains_key("environment_json"));
        assert!(artifacts.contains_key("session_transcript_json"));
        assert!(artifacts.contains_key("replay_sh"));
    }

    #[test]
    fn artifact_bundle_trace_path() {
        let base = PathBuf::from("/tmp/bp");
        let sid = ScenarioId::new(ScenarioLayer::Snapshot, "s", "c");
        let tid = TraceId::from_string("t");
        let bundle = ArtifactBundle::new(&base, &sid, &tid);
        assert!(bundle.trace_path().ends_with("trace.jsonl"));
    }

    #[test]
    fn artifact_bundle_summary_path() {
        let base = PathBuf::from("/tmp/bp");
        let sid = ScenarioId::new(ScenarioLayer::Snapshot, "s", "c");
        let tid = TraceId::from_string("t");
        let bundle = ArtifactBundle::new(&base, &sid, &tid);
        assert!(bundle.summary_path().ends_with("summary.json"));
    }

    #[test]
    fn artifact_bundle_environment_path() {
        let base = PathBuf::from("/tmp/bp");
        let sid = ScenarioId::new(ScenarioLayer::Snapshot, "s", "c");
        let tid = TraceId::from_string("t");
        let bundle = ArtifactBundle::new(&base, &sid, &tid);
        assert!(bundle.environment_path().ends_with("environment.json"));
    }

    #[test]
    fn artifact_bundle_session_transcript_path() {
        let base = PathBuf::from("/tmp/bp");
        let sid = ScenarioId::new(ScenarioLayer::Snapshot, "s", "c");
        let tid = TraceId::from_string("t");
        let bundle = ArtifactBundle::new(&base, &sid, &tid);
        assert!(
            bundle
                .session_transcript_path()
                .ends_with("session_transcript.json")
        );
    }

    #[test]
    fn artifact_bundle_replay_script_path() {
        let base = PathBuf::from("/tmp/bp");
        let sid = ScenarioId::new(ScenarioLayer::Snapshot, "s", "c");
        let tid = TraceId::from_string("t");
        let bundle = ArtifactBundle::new(&base, &sid, &tid);
        assert!(bundle.replay_script_path().ends_with("replay.sh"));
    }

    #[test]
    fn artifact_bundle_golden_snapshot_path() {
        let base = PathBuf::from("/tmp/bp");
        let sid = ScenarioId::new(ScenarioLayer::Snapshot, "s", "c");
        let tid = TraceId::from_string("t");
        let bundle = ArtifactBundle::new(&base, &sid, &tid);
        assert!(bundle.golden_snapshot_path().ends_with("golden_snapshot"));
    }

    #[test]
    fn artifact_bundle_serde_roundtrip() {
        let base = PathBuf::from("/tmp/sr");
        let sid = ScenarioId::new(ScenarioLayer::Benchmark, "perf", "throughput");
        let tid = TraceId::from_string("t");
        let bundle = ArtifactBundle::new(&base, &sid, &tid);
        let json = serde_json::to_string(&bundle).unwrap();
        let back: ArtifactBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(back.bundle_id, bundle.bundle_id);
        assert_eq!(back.scenario_id, bundle.scenario_id);
    }

    // ── ArtifactManifest ────────────────────────────────────────────────

    #[test]
    fn artifact_manifest_construction() {
        let sid = ScenarioId::new(ScenarioLayer::Unit, "s", "c");
        let tid = TraceId::from_string("t");
        let m = ArtifactManifest::new(sid.clone(), tid, 4, 1024, BundleOutcome::Pass);
        assert_eq!(m.schema_version, VERIFICATION_BUNDLE_SCHEMA_VERSION);
        assert_eq!(m.scenario_id, sid);
        assert_eq!(m.layer, ScenarioLayer::Unit);
        assert_eq!(m.file_count, 4);
        assert_eq!(m.total_bytes, 1024);
        assert!(m.outcome.is_pass());
        assert!(m.bundle_root.is_empty());
        assert!(m.artifact_paths.is_empty());
        assert_eq!(m.log_summary.total_entries, 0);
        assert!(m.truthfulness.command_availabilities.is_empty());
    }

    #[test]
    fn artifact_manifest_serde_roundtrip() {
        let sid = ScenarioId::new(ScenarioLayer::Unit, "s", "c");
        let tid = TraceId::from_string("t");
        let m = ArtifactManifest::new(
            sid,
            tid,
            3,
            512,
            BundleOutcome::Fail {
                reason: "oops".to_string(),
            },
        );
        let json = serde_json::to_string(&m).unwrap();
        let back: ArtifactManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.schema_version, VERIFICATION_BUNDLE_SCHEMA_VERSION);
        assert_eq!(back.layer, ScenarioLayer::Unit);
        assert_eq!(back.file_count, 3);
        assert!(back.outcome.is_fail());
    }

    // ── RedactionRule ───────────────────────────────────────────────────

    #[test]
    fn redaction_rule_field_match() {
        let rule =
            RedactionRule::field_based("test", vec!["token".to_string(), "secret".to_string()]);
        assert!(rule.matches_field("auth_token"));
        assert!(rule.matches_field("SECRET_KEY"));
        assert!(rule.matches_field("my_Token_id"));
        assert!(!rule.matches_field("username"));
    }

    #[test]
    fn redaction_rule_value_match() {
        let rule =
            RedactionRule::value_based("test", vec!["Bearer ".to_string(), "sk-".to_string()]);
        assert!(rule.matches_value("Bearer abc123"));
        assert!(rule.matches_value("sk-live-xyz"));
        assert!(!rule.matches_value("basic auth"));
    }

    #[test]
    fn redaction_rule_field_based_no_value_match() {
        let rule = RedactionRule::field_based("test", vec!["password".to_string()]);
        assert!(!rule.matches_value("password123"));
    }

    #[test]
    fn redaction_rule_value_based_no_field_match() {
        let rule = RedactionRule::value_based("test", vec!["ghp_".to_string()]);
        assert!(!rule.matches_field("ghp_field"));
    }

    #[test]
    fn redaction_rule_serde_roundtrip() {
        let rule = RedactionRule::field_based("sensitive", vec!["api_key".to_string()]);
        let json = serde_json::to_string(&rule).unwrap();
        let back: RedactionRule = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "sensitive");
        assert_eq!(back.field_patterns, vec!["api_key"]);
    }

    // ── RedactedValue ───────────────────────────────────────────────────

    #[test]
    fn redacted_value_format() {
        let rv = RedactedValue::from_original("my-secret-token");
        assert!(rv.placeholder.starts_with("[REDACTED:sha256:"));
        assert!(rv.placeholder.ends_with(']'));
        assert_eq!(rv.short_digest().len(), 8);
        assert_eq!(rv.full_digest().len(), 64); // SHA-256 hex is 64 chars
    }

    #[test]
    fn redacted_value_deterministic() {
        let a = RedactedValue::from_original("same-input");
        let b = RedactedValue::from_original("same-input");
        assert_eq!(a, b);
        assert_eq!(a.placeholder, b.placeholder);
        assert_eq!(a.digest, b.digest);
    }

    #[test]
    fn redacted_value_different_inputs_different_digests() {
        let a = RedactedValue::from_original("secret-a");
        let b = RedactedValue::from_original("secret-b");
        assert_ne!(a.digest, b.digest);
        assert_ne!(a.placeholder, b.placeholder);
    }

    #[test]
    fn redacted_value_display() {
        let rv = RedactedValue::from_original("test");
        assert_eq!(rv.to_string(), rv.placeholder);
    }

    #[test]
    fn redacted_value_serde_roundtrip() {
        let rv = RedactedValue::from_original("secret");
        let json = serde_json::to_string(&rv).unwrap();
        let back: RedactedValue = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rv);
    }

    // ── RedactionEngine ─────────────────────────────────────────────────

    #[test]
    fn redaction_engine_default_rules() {
        let engine = RedactionEngine::default_rules();
        assert_eq!(engine.rules().len(), 2);
    }

    #[test]
    fn redaction_engine_should_redact_field() {
        let engine = RedactionEngine::default_rules();
        assert!(engine.should_redact_field("api_token"));
        assert!(engine.should_redact_field("SECRET"));
        assert!(engine.should_redact_field("password"));
        assert!(engine.should_redact_field("API_KEY"));
        assert!(engine.should_redact_field("credential"));
        assert!(engine.should_redact_field("Authorization"));
        assert!(!engine.should_redact_field("username"));
        assert!(!engine.should_redact_field("email"));
    }

    #[test]
    fn redaction_engine_redact_value() {
        let engine = RedactionEngine::default_rules();
        assert!(engine.redact_value("Bearer abc123").is_some());
        assert!(engine.redact_value("sk-live-key").is_some());
        assert!(engine.redact_value("ghp_xxxx").is_some());
        assert!(engine.redact_value("xoxb-token").is_some());
        assert!(engine.redact_value("normal-value").is_none());
    }

    #[test]
    fn redaction_engine_redact_entry_fields() {
        let engine = RedactionEngine::default_rules();
        let tid = TraceId::from_string("t");
        let sid = ScenarioId::new(ScenarioLayer::Unit, "s", "c");
        let entry = TraceEntry::new(&tid, &sid, TraceLevel::Info, TraceCategory::CliStep, "test")
            .with_field("api_token", serde_json::json!("super-secret"))
            .with_field("user", serde_json::json!("alice"));

        let redacted = engine.redact_entry(&entry);
        assert!(redacted.redacted);
        // api_token should be redacted
        let token_val = redacted.fields.get("api_token").unwrap();
        assert!(token_val.as_str().unwrap().starts_with("[REDACTED:sha256:"));
        // user should remain
        assert_eq!(redacted.fields["user"], serde_json::json!("alice"));
    }

    #[test]
    fn redaction_engine_redact_entry_value_patterns() {
        let engine = RedactionEngine::default_rules();
        let tid = TraceId::from_string("t");
        let sid = ScenarioId::new(ScenarioLayer::Unit, "s", "c");
        let entry = TraceEntry::new(&tid, &sid, TraceLevel::Info, TraceCategory::CliStep, "ok")
            .with_field("header", serde_json::json!("Bearer sk-live-abc"));

        let redacted = engine.redact_entry(&entry);
        assert!(redacted.redacted);
        let val = redacted.fields["header"].as_str().unwrap();
        assert!(val.starts_with("[REDACTED:sha256:"));
    }

    #[test]
    fn redaction_engine_redact_entry_message() {
        let engine = RedactionEngine::default_rules();
        let tid = TraceId::from_string("t");
        let sid = ScenarioId::new(ScenarioLayer::Unit, "s", "c");
        let entry = TraceEntry::new(
            &tid,
            &sid,
            TraceLevel::Info,
            TraceCategory::CliStep,
            "using Bearer abc123 for auth",
        );

        let redacted = engine.redact_entry(&entry);
        assert!(redacted.redacted);
        assert!(!redacted.message.contains("abc123"));
        assert!(redacted.message.contains("[REDACTED:sha256:"));
    }

    #[test]
    fn redaction_engine_no_redaction_needed() {
        let engine = RedactionEngine::default_rules();
        let tid = TraceId::from_string("t");
        let sid = ScenarioId::new(ScenarioLayer::Unit, "s", "c");
        let entry = TraceEntry::new(&tid, &sid, TraceLevel::Info, TraceCategory::Setup, "clean")
            .with_field("host", serde_json::json!("localhost"));

        let redacted = engine.redact_entry(&entry);
        assert!(!redacted.redacted);
        assert_eq!(redacted.message, "clean");
        assert_eq!(redacted.fields["host"], serde_json::json!("localhost"));
    }

    #[test]
    fn redaction_engine_redact_log() {
        let engine = RedactionEngine::default_rules();
        let ctx = scenario_context(ScenarioLayer::Unit, "s", "c");
        let mut log = new_trace_log();
        let entry = TraceEntry::new(
            &ctx.trace_id,
            &ctx.scenario_id,
            TraceLevel::Info,
            TraceCategory::CliStep,
            "ok",
        )
        .with_field("secret", serde_json::json!("hunter2"));
        log.append(entry);
        emit_entry(
            &mut log,
            &ctx,
            TraceLevel::Debug,
            TraceCategory::Setup,
            "clean",
        );

        let redacted = engine.redact_log(&log);
        assert_eq!(redacted.len(), 2);
        assert!(redacted.entries()[0].redacted);
        assert!(!redacted.entries()[1].redacted);
    }

    #[test]
    fn redaction_engine_custom_rules() {
        let engine = RedactionEngine::new(vec![RedactionRule::field_based(
            "custom",
            vec!["ssn".to_string()],
        )]);
        assert!(engine.should_redact_field("ssn_number"));
        assert!(!engine.should_redact_field("api_key")); // not in custom rules
    }

    // ── ReplayEnvelope ──────────────────────────────────────────────────

    #[test]
    fn replay_envelope_construction() {
        let sid = ScenarioId::new(ScenarioLayer::E2E, "lifecycle", "boot");
        let tid = TraceId::from_string("t");
        let env = ReplayEnvelope::new(
            sid.clone(),
            tid,
            "fwc invoke github.list_repos",
            "/home/user/project",
        );
        assert_eq!(env.scenario_id, sid);
        assert_eq!(env.command_line, "fwc invoke github.list_repos");
        assert_eq!(env.working_directory, "/home/user/project");
        assert!(env.git_sha.is_none());
        assert!(env.rust_version.is_none());
        assert!(env.command_runner.is_none());
    }

    #[test]
    fn replay_envelope_builder() {
        let sid = ScenarioId::new(ScenarioLayer::E2E, "s", "c");
        let tid = TraceId::from_string("t");
        let truthfulness = TruthfulnessSummary {
            command_availabilities: BTreeMap::from([("offline-artifact".to_string(), 1)]),
            provenance_markers: vec!["workspace-manifest".to_string()],
            phases: vec!["offline-artifact".to_string()],
            host_request_ids: Vec::new(),
            host_response_ids: Vec::new(),
            receipt_ids: Vec::new(),
            reconnect_events: Vec::new(),
            cancellation_events: Vec::new(),
            live_entry_count: 0,
            offline_entry_count: 1,
        };
        let env = ReplayEnvelope::new(sid, tid, "cmd", "/dir")
            .with_env("RUST_LOG", "debug")
            .with_git_sha("abc123")
            .with_rust_version("1.85.0")
            .with_command_runner("custom-runner --")
            .with_truthfulness(truthfulness.clone());
        assert_eq!(env.environment["RUST_LOG"], "debug");
        assert_eq!(env.git_sha.as_deref(), Some("abc123"));
        assert_eq!(env.rust_version.as_deref(), Some("1.85.0"));
        assert_eq!(env.command_runner.as_deref(), Some("custom-runner --"));
        assert_eq!(env.truthfulness, truthfulness);
    }

    #[test]
    fn replay_envelope_serde_roundtrip() {
        let sid = ScenarioId::new(ScenarioLayer::E2E, "s", "c");
        let tid = TraceId::from_string("t");
        let env = ReplayEnvelope::new(sid, tid, "cmd", "/dir").with_git_sha("deadbeef");
        let json = serde_json::to_string(&env).unwrap();
        let back: ReplayEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back.git_sha.as_deref(), Some("deadbeef"));
        assert_eq!(back.command_line, "cmd");
    }

    #[test]
    fn replay_envelope_defaults_cargo_to_rch_runner() {
        let sid = ScenarioId::new(ScenarioLayer::E2E, "verify", "cargo");
        let tid = TraceId::from_string("t");
        let env = ReplayEnvelope::new(sid, tid, "cargo test -p fwc test_observability", "/repo");
        assert_eq!(env.command_runner.as_deref(), Some("rch exec --"));
    }

    // ── ReplayInstructions ──────────────────────────────────────────────

    #[test]
    fn replay_instructions_from_envelope() {
        let sid = ScenarioId::new(ScenarioLayer::E2E, "lifecycle", "boot");
        let tid = TraceId::from_string("trace-42");
        let env = ReplayEnvelope::new(sid, tid, "fwc invoke github.list_repos", "/home/user")
            .with_git_sha("abc123")
            .with_rust_version("1.85.0")
            .with_env("FWC_HOST", "localhost:9000");

        let instructions = ReplayInstructions::from_envelope(&env);
        assert!(!instructions.steps.is_empty());
        assert!(instructions.steps[0].contains("/home/user"));
        assert!(instructions.steps.iter().any(|s| s.contains("abc123")));
        assert!(instructions.steps.iter().any(|s| s.contains("FWC_HOST")));
        assert!(
            instructions
                .steps
                .iter()
                .any(|s| s.contains("github.list_repos"))
        );
        assert!(instructions.prerequisites.iter().any(|p| p.contains("git")));
        assert!(
            instructions
                .prerequisites
                .iter()
                .any(|p| p.contains("1.85.0"))
        );
    }

    #[test]
    fn replay_instructions_no_git_sha() {
        let sid = ScenarioId::new(ScenarioLayer::Unit, "s", "c");
        let tid = TraceId::from_string("t");
        let env = ReplayEnvelope::new(sid, tid, "cargo test", "/project");
        let instructions = ReplayInstructions::from_envelope(&env);
        assert!(
            !instructions
                .steps
                .iter()
                .any(|s| s.contains("git checkout"))
        );
        assert!(
            instructions
                .steps
                .iter()
                .any(|s| s.contains("'rch' 'exec' '--' bash -lc 'cargo test'"))
        );
        assert!(instructions.prerequisites.iter().any(|p| p == "rch"));
    }

    #[test]
    fn replay_instructions_custom_runner_does_not_claim_rch_prerequisite() {
        let sid = ScenarioId::new(ScenarioLayer::Unit, "runner", "custom");
        let tid = TraceId::from_string("trace-custom");
        let env = ReplayEnvelope::new(sid, tid, "cargo test", "/project")
            .with_command_runner("custom-runner --");
        let instructions = ReplayInstructions::from_envelope(&env);
        assert!(!instructions.prerequisites.iter().any(|p| p == "rch"));
        assert!(
            instructions
                .steps
                .iter()
                .any(|s| s.contains("'custom-runner' '--' bash -lc 'cargo test'"))
        );
    }

    #[test]
    fn replay_instructions_quoted_runner_path_preserves_grouping() {
        let sid = ScenarioId::new(ScenarioLayer::Unit, "runner", "quoted-path");
        let tid = TraceId::from_string("trace-quoted-runner");
        let env = ReplayEnvelope::new(sid, tid, "cargo test", "/project")
            .with_command_runner("\"/opt/custom tools/bin/run\" --flag");
        let instructions = ReplayInstructions::from_envelope(&env);

        assert!(
            instructions
                .steps
                .iter()
                .any(|s| s.contains("'/opt/custom tools/bin/run' '--flag' bash -lc 'cargo test'"))
        );
    }

    #[test]
    fn replay_instructions_include_truthfulness_notes() {
        let sid = ScenarioId::new(ScenarioLayer::E2E, "truth", "notes");
        let tid = TraceId::from_string("trace-99");
        let truthfulness = TruthfulnessSummary {
            command_availabilities: BTreeMap::from([
                ("live-runtime".to_string(), 1),
                ("offline-artifact".to_string(), 1),
            ]),
            provenance_markers: vec!["live-host-inventory".to_string()],
            phases: vec!["preflight".to_string(), "invoke".to_string()],
            host_request_ids: vec!["req-1".to_string()],
            host_response_ids: vec!["resp-1".to_string()],
            receipt_ids: vec!["receipt-1".to_string()],
            reconnect_events: Vec::new(),
            cancellation_events: Vec::new(),
            live_entry_count: 1,
            offline_entry_count: 1,
        };
        let env = ReplayEnvelope::new(sid, tid, "cargo test -p fwc", "/repo")
            .with_truthfulness(truthfulness);
        let instructions = ReplayInstructions::from_envelope(&env);
        assert!(
            instructions
                .notes
                .iter()
                .any(|n| n.contains("Observed availability states"))
        );
        assert!(
            instructions
                .notes
                .iter()
                .any(|n| n.contains("Provenance markers"))
        );
        assert!(
            instructions
                .notes
                .iter()
                .any(|n| n.contains("Host request ids"))
        );
        assert!(instructions.notes.iter().any(|n| n.contains("Receipt ids")));
    }

    #[test]
    fn replay_instructions_to_shell_script() {
        let sid = ScenarioId::new(ScenarioLayer::E2E, "s", "c");
        let tid = TraceId::from_string("t");
        let env = ReplayEnvelope::new(sid, tid, "fwc status", "/home")
            .with_git_sha("beef")
            .with_rust_version("1.85.0");

        let instructions = ReplayInstructions::from_envelope(&env);
        let script = instructions.to_shell_script();
        assert!(script.starts_with("#!/usr/bin/env bash"));
        assert!(script.contains("set -euo pipefail"));
        assert!(script.contains("cd -- '/home'"));
        assert!(script.contains("bash -lc 'fwc status'"));
    }

    #[test]
    fn replay_instructions_shell_quote_dangerous_values() {
        let sid = ScenarioId::new(ScenarioLayer::E2E, "danger", "quote");
        let tid = TraceId::from_string("trace-danger");
        let env = ReplayEnvelope::new(
            sid,
            tid,
            "printf '%s' \"$HOME\"; touch /tmp/should-not-inline",
            "/tmp/replay dir",
        )
        .with_env("FWC_TOKEN", "abc $(rm -rf /)");

        let instructions = ReplayInstructions::from_envelope(&env);

        assert_eq!(instructions.steps[0], "cd -- '/tmp/replay dir'");
        assert!(instructions.steps[1].contains("env -- 'FWC_TOKEN=abc $(rm -rf /)' bash -lc"));
        assert!(
            instructions.steps[1]
                .contains("'printf '\"'\"'%s'\"'\"' \"$HOME\"; touch /tmp/should-not-inline'")
        );
    }

    #[test]
    fn replay_instructions_serde_roundtrip() {
        let instr = ReplayInstructions {
            steps: vec!["cd /tmp".to_string(), "cargo test".to_string()],
            prerequisites: vec!["cargo".to_string()],
            notes: vec!["note1".to_string()],
        };
        let json = serde_json::to_string(&instr).unwrap();
        let back: ReplayInstructions = serde_json::from_str(&json).unwrap();
        assert_eq!(back.steps.len(), 2);
        assert_eq!(back.prerequisites.len(), 1);
    }

    // ── Test helpers (create_bundle) ────────────────────────────────────

    #[test]
    fn create_bundle_returns_bundle_and_manifest() {
        let ctx = scenario_context(ScenarioLayer::Unit, "routing", "alias_test");
        let base = PathBuf::from("/tmp/obs");
        let (bundle, manifest) = create_bundle(&base, &ctx, &new_trace_log(), BundleOutcome::Pass);
        assert!(bundle.bundle_id.starts_with("unit:routing:alias_test@"));
        assert!(manifest.outcome.is_pass());
        assert_eq!(manifest.file_count, 5);
        assert_eq!(manifest.layer, ScenarioLayer::Unit);
        assert!(
            manifest
                .bundle_root
                .contains("/tmp/obs/artifacts/unit/routing/alias_test/")
        );
        let expected_replay_path = bundle.replay_script_path().to_string_lossy().to_string();
        assert_eq!(
            manifest.artifact_paths.get("replay_sh"),
            Some(&expected_replay_path)
        );
        assert_eq!(manifest.log_summary.total_entries, 0);
        assert!(manifest.truthfulness.command_availabilities.is_empty());
    }

    #[test]
    fn create_bundle_fail_outcome() {
        let ctx = scenario_context(ScenarioLayer::E2E, "s", "c");
        let base = PathBuf::from("/tmp/obs");
        let outcome = BundleOutcome::Fail {
            reason: "assertion failed".to_string(),
        };
        let (_bundle, manifest) = create_bundle(&base, &ctx, &new_trace_log(), outcome);
        assert!(manifest.outcome.is_fail());
    }

    // ── hex encoding ────────────────────────────────────────────────────

    #[test]
    fn hex_encode_empty() {
        assert_eq!(hex::encode([]), "");
    }

    #[test]
    fn hex_encode_known() {
        assert_eq!(hex::encode([0x00, 0xff, 0xab]), "00ffab");
    }

    #[test]
    fn hex_encode_single_byte() {
        assert_eq!(hex::encode([0x0a]), "0a");
    }

    // ── TraceLogSummary ─────────────────────────────────────────────────

    #[test]
    fn trace_log_summary_default() {
        let s = TraceLogSummary::default();
        assert_eq!(s.total_entries, 0);
        assert_eq!(s.debug_count, 0);
        assert_eq!(s.info_count, 0);
        assert_eq!(s.warn_count, 0);
        assert_eq!(s.error_count, 0);
        assert!(s.categories.is_empty());
        assert_eq!(s.redacted_count, 0);
    }

    #[test]
    fn trace_log_summary_serde_roundtrip() {
        let s = TraceLogSummary {
            total_entries: 10,
            debug_count: 3,
            info_count: 4,
            warn_count: 2,
            error_count: 1,
            categories: BTreeMap::from([("setup".to_string(), 5), ("teardown".to_string(), 5)]),
            redacted_count: 1,
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: TraceLogSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(back.total_entries, 10);
        assert_eq!(back.categories["setup"], 5);
    }

    #[test]
    fn trace_log_truthfulness_summary_collects_modes_markers_and_ids() {
        let ctx = scenario_context(ScenarioLayer::E2E, "truth", "markers");
        let mut log = new_trace_log();
        let live_truth = TruthContext::new(CommandAvailability::LiveRuntime)
            .with_provenance_marker("live-host-introspection")
            .with_phase(TruthPhase::Invoke)
            .with_host_request_id("req-live")
            .with_host_response_id("resp-live")
            .with_receipt_id("receipt-live");
        let offline_truth = TruthContext::new(CommandAvailability::OfflineArtifact)
            .with_provenance_marker("workspace-manifest")
            .with_phase(TruthPhase::OfflineArtifact)
            .with_reconnect_event(ReconnectEvent::Attempted)
            .with_cancellation_event(CancellationEvent::Requested);

        log.append(
            TraceEntry::new(
                &ctx.trace_id,
                &ctx.scenario_id,
                TraceLevel::Info,
                TraceCategory::HostRequest,
                "live invoke",
            )
            .with_truth_context(live_truth),
        );
        log.append(
            TraceEntry::new(
                &ctx.trace_id,
                &ctx.scenario_id,
                TraceLevel::Info,
                TraceCategory::CliStep,
                "offline inspect",
            )
            .with_truth_context(offline_truth),
        );

        let summary = log.truthfulness_summary();
        assert_eq!(summary.command_availabilities["live-runtime"], 1);
        assert_eq!(summary.command_availabilities["offline-artifact"], 1);
        assert_eq!(summary.live_entry_count, 1);
        assert_eq!(summary.offline_entry_count, 1);
        assert_eq!(
            summary.provenance_markers,
            vec![
                "live-host-introspection".to_string(),
                "workspace-manifest".to_string()
            ]
        );
        assert_eq!(
            summary.phases,
            vec!["invoke".to_string(), "offline-artifact".to_string()]
        );
        assert_eq!(summary.host_request_ids, vec!["req-live".to_string()]);
        assert_eq!(summary.host_response_ids, vec!["resp-live".to_string()]);
        assert_eq!(summary.receipt_ids, vec!["receipt-live".to_string()]);
        assert_eq!(summary.reconnect_events, vec!["attempted".to_string()]);
        assert_eq!(summary.cancellation_events, vec!["requested".to_string()]);
    }

    // ── Integration: full workflow ──────────────────────────────────────

    #[test]
    fn full_workflow_emit_redact_bundle() {
        // 1. Create scenario context
        let ctx = scenario_context(ScenarioLayer::E2E, "lifecycle", "install_flow")
            .with_tag("integration")
            .with_env("FWC_HOST", "localhost");

        // 2. Emit entries
        let mut log = new_trace_log();
        emit_entry(
            &mut log,
            &ctx,
            TraceLevel::Info,
            TraceCategory::Setup,
            "initializing",
        );
        let sensitive = TraceEntry::new(
            &ctx.trace_id,
            &ctx.scenario_id,
            TraceLevel::Info,
            TraceCategory::HostRequest,
            "calling API",
        )
        .with_field("api_key", serde_json::json!("sk-live-test-key"))
        .with_field("endpoint", serde_json::json!("/v1/repos"))
        .with_truth_context(
            TruthContext::new(CommandAvailability::LiveRuntime)
                .with_provenance_marker("live-host-inventory")
                .with_phase(TruthPhase::Invoke)
                .with_host_request_id("req-42")
                .with_receipt_id("receipt-42"),
        )
        .with_duration_ms(42);
        log.append(sensitive);
        emit_entry(
            &mut log,
            &ctx,
            TraceLevel::Info,
            TraceCategory::Teardown,
            "cleanup",
        );

        // 3. Redact
        let engine = RedactionEngine::default_rules();
        let redacted = engine.redact_log(&log);
        assert_eq!(redacted.len(), 3);
        // The middle entry should be redacted (api_key field)
        assert!(redacted.entries()[1].redacted);
        assert!(!redacted.entries()[0].redacted);
        assert!(!redacted.entries()[2].redacted);

        // 4. Create bundle
        let base = PathBuf::from("/tmp/test-workflow");
        let (bundle, manifest) = create_bundle(&base, &ctx, &redacted, BundleOutcome::Pass);
        assert!(manifest.outcome.is_pass());
        assert!(bundle.root.to_string_lossy().contains("lifecycle"));

        // 5. Summary stats
        let summary = redacted.summary();
        assert_eq!(summary.total_entries, 3);
        assert_eq!(summary.redacted_count, 1);
        assert_eq!(summary.info_count, 3);
        assert_eq!(
            manifest.truthfulness.command_availabilities["live-runtime"],
            1
        );
        assert_eq!(
            manifest.truthfulness.provenance_markers,
            vec!["live-host-inventory".to_string()]
        );
        assert_eq!(
            manifest.truthfulness.receipt_ids,
            vec!["receipt-42".to_string()]
        );
    }

    #[test]
    fn full_workflow_replay_round_trip() {
        let ctx = scenario_context(ScenarioLayer::E2E, "lifecycle", "boot");
        let tid = ctx.trace_id.clone();
        let envelope = ReplayEnvelope::new(
            ctx.scenario_id,
            tid,
            "fwc invoke github.list_repos",
            "/home/user/project",
        )
        .with_git_sha("abc123")
        .with_rust_version("1.85.0")
        .with_env("FWC_HOST", "localhost:9000");

        // Serialize and deserialize
        let json = serde_json::to_string_pretty(&envelope).unwrap();
        let back: ReplayEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back.command_line, "fwc invoke github.list_repos");

        // Generate instructions
        let instructions = ReplayInstructions::from_envelope(&back);
        let script = instructions.to_shell_script();
        assert!(script.contains("fwc invoke github.list_repos"));
        assert!(script.contains("abc123"));
    }

    #[test]
    fn scenario_id_hash_eq_consistency() {
        use std::collections::HashSet;
        let a = ScenarioId::new(ScenarioLayer::Unit, "s", "c");
        let b = ScenarioId::new(ScenarioLayer::Unit, "s", "c");
        let c = ScenarioId::new(ScenarioLayer::E2E, "s", "c");
        let mut set = HashSet::new();
        set.insert(a);
        set.insert(b);
        set.insert(c);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn trace_id_hash_eq_consistency() {
        use std::collections::HashSet;
        let a = TraceId::from_string("x");
        let b = TraceId::from_string("x");
        let c = TraceId::from_string("y");
        let mut set = HashSet::new();
        set.insert(a);
        set.insert(b);
        set.insert(c);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn trace_log_filter_empty_category() {
        let log = new_trace_log();
        assert!(log.filter_by_category(TraceCategory::Approval).is_empty());
    }

    #[test]
    fn trace_log_filter_empty_level() {
        let log = new_trace_log();
        assert!(log.filter_by_level(TraceLevel::Error).is_empty());
    }

    #[test]
    fn trace_log_to_jsonl_empty() {
        let log = new_trace_log();
        let jsonl = log.to_jsonl().unwrap();
        assert!(jsonl.is_empty());
    }

    #[test]
    fn redaction_engine_empty_rules() {
        let engine = RedactionEngine::new(vec![]);
        assert!(engine.rules().is_empty());
        assert!(!engine.should_redact_field("secret"));
        assert!(engine.redact_value("Bearer abc").is_none());
    }

    // ── ScenarioLayer additional coverage ───────────────────────────────

    #[test]
    fn scenario_layer_parse_label_all_valid() {
        let cases = [
            ("unit", ScenarioLayer::Unit),
            ("integration", ScenarioLayer::Integration),
            ("e2e", ScenarioLayer::E2E),
            ("snapshot", ScenarioLayer::Snapshot),
            ("benchmark", ScenarioLayer::Benchmark),
        ];
        for (label, expected) in cases {
            assert_eq!(ScenarioLayer::parse_label(label), Some(expected));
        }
    }

    #[test]
    fn scenario_layer_parse_label_invalid_returns_none() {
        assert!(ScenarioLayer::parse_label("unknown").is_none());
        assert!(ScenarioLayer::parse_label("").is_none());
        assert!(ScenarioLayer::parse_label("Unit").is_none()); // case sensitive
        assert!(ScenarioLayer::parse_label("E2E").is_none()); // case sensitive
    }

    #[test]
    fn scenario_layer_display_matches_as_str() {
        for layer in [
            ScenarioLayer::Unit,
            ScenarioLayer::Integration,
            ScenarioLayer::E2E,
            ScenarioLayer::Snapshot,
            ScenarioLayer::Benchmark,
        ] {
            assert_eq!(layer.to_string(), layer.as_str());
        }
    }

    #[test]
    fn scenario_layer_deserialize_unknown_variant_errors() {
        let result = serde_json::from_str::<ScenarioLayer>("\"not_a_layer\"");
        assert!(result.is_err());
    }

    #[test]
    fn scenario_layer_copy_semantics() {
        let a = ScenarioLayer::E2E;
        let b = a; // Copy, not move
        assert_eq!(a, b);
    }

    // ── ScenarioId additional coverage ──────────────────────────────────

    #[test]
    fn scenario_id_parse_with_colons_in_suite_not_supported() {
        // splitn(3, ':') gives [layer, suite, case] so suite cannot contain colons;
        // a string with 4 parts uses the third colon as part of 'case'.
        let parsed = ScenarioId::parse("unit:suite:case").unwrap();
        assert_eq!(parsed.suite, "suite");
        assert_eq!(parsed.case, "case");
    }

    #[test]
    fn scenario_id_parse_empty_suite_and_case_rejected() {
        assert!(ScenarioId::parse("unit::").is_none());
    }

    #[test]
    fn scenario_id_parse_rejects_path_unsafe_components() {
        assert!(ScenarioId::parse("unit:../suite:case").is_none());
        assert!(ScenarioId::parse("unit:suite:../case").is_none());
        assert!(ScenarioId::parse("unit:suite/child:case").is_none());
        assert!(ScenarioId::parse("unit:suite:case/child").is_none());
    }

    #[test]
    fn scenario_id_new_rejects_path_unsafe_components() {
        let panic = std::panic::catch_unwind(|| {
            let _ = ScenarioId::new(ScenarioLayer::Unit, "../suite", "case");
        });
        assert!(panic.is_err());
    }

    #[test]
    fn scenario_id_clone() {
        let id = ScenarioId::new(ScenarioLayer::Integration, "auth", "token_refresh");
        let cloned = id.clone();
        assert_eq!(id, cloned);
    }

    #[test]
    fn scenario_id_hash_in_btreemap() {
        let mut map = std::collections::BTreeMap::new();
        let id = ScenarioId::new(ScenarioLayer::Unit, "s", "c");
        map.insert(id.to_string_id(), 42usize);
        assert_eq!(map["unit:s:c"], 42);
    }

    // ── TraceId additional coverage ──────────────────────────────────────

    #[test]
    fn trace_id_generate_is_uuid_format() {
        let id = TraceId::generate();
        // UUID v4 format: 8-4-4-4-12 hex chars separated by dashes
        let s = id.as_str();
        assert_eq!(s.len(), 36, "UUID should be 36 chars");
        let parts: Vec<&str> = s.split('-').collect();
        assert_eq!(parts.len(), 5);
    }

    #[test]
    fn trace_id_clone() {
        let id = TraceId::from_string("t-abc");
        let cloned = id.clone();
        assert_eq!(id, cloned);
    }

    #[test]
    fn trace_id_display_matches_as_str() {
        let id = TraceId::from_string("trace-xyz");
        assert_eq!(id.to_string(), id.as_str());
    }

    // ── ScenarioContext additional coverage ──────────────────────────────

    #[test]
    fn scenario_context_multiple_env_entries() {
        let ctx = scenario_context(ScenarioLayer::Unit, "s", "c")
            .with_env("A", "1")
            .with_env("B", "2")
            .with_env("C", "3");
        assert_eq!(ctx.environment.len(), 3);
        assert_eq!(ctx.environment["A"], "1");
        assert_eq!(ctx.environment["C"], "3");
    }

    #[test]
    fn scenario_context_multiple_tags() {
        let ctx = scenario_context(ScenarioLayer::E2E, "s", "c")
            .with_tag("fast")
            .with_tag("smoke")
            .with_tag("ci");
        assert_eq!(ctx.tags.len(), 3);
        assert_eq!(ctx.tags[2], "ci");
    }

    #[test]
    fn scenario_context_layer_matches_scenario_id() {
        let ctx = scenario_context(ScenarioLayer::Benchmark, "perf", "throughput");
        assert_eq!(ctx.layer, ScenarioLayer::Benchmark);
        assert_eq!(ctx.scenario_id.layer, ScenarioLayer::Benchmark);
    }

    // ── TruthPhase display / serde ────────────────────────────────────────

    #[test]
    fn truth_phase_display_matches_as_str() {
        for phase in [
            TruthPhase::Setup,
            TruthPhase::OfflineArtifact,
            TruthPhase::HostDiscovery,
            TruthPhase::Preflight,
            TruthPhase::Simulate,
            TruthPhase::Invoke,
            TruthPhase::HostReceipt,
            TruthPhase::Reconnect,
            TruthPhase::Cancellation,
            TruthPhase::Teardown,
        ] {
            assert_eq!(phase.to_string(), phase.as_str());
        }
    }

    #[test]
    fn truth_phase_kebab_case_serialization() {
        let phase = TruthPhase::OfflineArtifact;
        let json = serde_json::to_string(&phase).unwrap();
        assert_eq!(json, r#""offline-artifact""#);
    }

    #[test]
    fn reconnect_event_as_str_and_serde() {
        let cases = [
            (ReconnectEvent::Attempted, "attempted"),
            (ReconnectEvent::Succeeded, "succeeded"),
            (ReconnectEvent::Failed, "failed"),
        ];
        for (event, expected) in cases {
            assert_eq!(event.as_str(), expected);
            let json = serde_json::to_string(&event).unwrap();
            let back: ReconnectEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(back, event);
        }
    }

    #[test]
    fn cancellation_event_as_str_and_serde() {
        let cases = [
            (CancellationEvent::Requested, "requested"),
            (CancellationEvent::Acknowledged, "acknowledged"),
            (CancellationEvent::Completed, "completed"),
            (CancellationEvent::Rejected, "rejected"),
        ];
        for (event, expected) in cases {
            assert_eq!(event.as_str(), expected);
            let json = serde_json::to_string(&event).unwrap();
            let back: CancellationEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(back, event);
        }
    }

    // ── TruthContext additional coverage ─────────────────────────────────

    #[test]
    fn truth_context_default_is_empty() {
        let tc = TruthContext::default();
        assert!(tc.command_availability.is_none());
        assert!(tc.provenance_markers.is_empty());
        assert!(tc.phase.is_none());
        assert!(tc.host_request_id.is_none());
        assert!(tc.host_response_id.is_none());
        assert!(tc.receipt_id.is_none());
        assert!(tc.reconnect_event.is_none());
        assert!(tc.cancellation_event.is_none());
    }

    #[test]
    fn truth_context_multiple_provenance_markers() {
        let tc = TruthContext::default()
            .with_provenance_marker("live-host-introspection")
            .with_provenance_marker("workspace-manifest")
            .with_provenance_marker("external-registry");
        assert_eq!(tc.provenance_markers.len(), 3);
    }

    #[test]
    fn truth_context_serde_roundtrip_full() {
        let tc = TruthContext::new(CommandAvailability::Planned)
            .with_provenance_marker("marker-1")
            .with_phase(TruthPhase::Preflight)
            .with_host_request_id("req-123")
            .with_host_response_id("resp-456")
            .with_receipt_id("rec-789")
            .with_reconnect_event(ReconnectEvent::Failed)
            .with_cancellation_event(CancellationEvent::Completed);

        let json = serde_json::to_string(&tc).unwrap();
        let back: TruthContext = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.command_availability,
            Some(CommandAvailability::Planned)
        );
        assert_eq!(back.provenance_markers, vec!["marker-1"]);
        assert_eq!(back.phase, Some(TruthPhase::Preflight));
        assert_eq!(back.host_request_id.as_deref(), Some("req-123"));
        assert_eq!(back.receipt_id.as_deref(), Some("rec-789"));
        assert_eq!(back.reconnect_event, Some(ReconnectEvent::Failed));
        assert_eq!(back.cancellation_event, Some(CancellationEvent::Completed));
    }

    #[test]
    fn truth_context_serde_skips_none_fields() {
        let tc = TruthContext::default();
        let json = serde_json::to_string(&tc).unwrap();
        // All optional/Vec fields should be skipped when absent
        assert!(!json.contains("command_availability"));
        assert!(!json.contains("phase"));
        assert!(!json.contains("host_request_id"));
    }

    #[test]
    fn host_integration_truth_profile_builds_truth_context_markers() {
        let profile = HostIntegrationTruthProfile::new(
            "github_issue_workflow",
            "request_response",
            "mock_host",
            "medium",
            CommandAvailability::LiveRuntime,
        )
        .with_provenance_marker("live-host-discovery")
        .with_provenance_marker("mock-host-sequence");

        let truth = profile.truth_context();
        assert_eq!(
            truth.command_availability,
            Some(CommandAvailability::LiveRuntime)
        );
        assert!(
            truth
                .provenance_markers
                .contains(&"fixture:github_issue_workflow".to_string())
        );
        assert!(
            truth
                .provenance_markers
                .contains(&"archetype:request_response".to_string())
        );
        assert!(
            truth
                .provenance_markers
                .contains(&"coverage-mode:mock_host".to_string())
        );
        assert!(
            truth
                .provenance_markers
                .contains(&"risk-level:medium".to_string())
        );
        assert!(
            truth
                .provenance_markers
                .contains(&"live-host-discovery".to_string())
        );
        assert!(
            truth
                .provenance_markers
                .contains(&"mock-host-sequence".to_string())
        );
    }

    #[test]
    fn host_integration_truth_profile_respects_existing_availability() {
        let profile = HostIntegrationTruthProfile::new(
            "fixture-1",
            "streaming",
            "real_host",
            "high",
            CommandAvailability::OfflineArtifact,
        )
        .with_provenance_marker("artifact-bundle");

        let truth = profile.apply_to_truth_context(
            TruthContext::new(CommandAvailability::LiveRuntime)
                .with_provenance_marker("existing-marker"),
        );
        assert_eq!(
            truth.command_availability,
            Some(CommandAvailability::LiveRuntime)
        );
        assert!(
            truth
                .provenance_markers
                .contains(&"existing-marker".to_string())
        );
        assert!(
            truth
                .provenance_markers
                .contains(&"fixture:fixture-1".to_string())
        );
        assert!(
            truth
                .provenance_markers
                .contains(&"archetype:streaming".to_string())
        );
        assert!(
            truth
                .provenance_markers
                .contains(&"coverage-mode:real_host".to_string())
        );
        assert!(
            truth
                .provenance_markers
                .contains(&"risk-level:high".to_string())
        );
        assert!(
            truth
                .provenance_markers
                .contains(&"artifact-bundle".to_string())
        );
    }

    #[test]
    fn truth_context_deserializes_legacy_command_mode_field() {
        let json = r#"{"command_mode":"planned","phase":"preflight"}"#;
        let back: TruthContext = serde_json::from_str(json).unwrap();
        assert_eq!(
            back.command_availability,
            Some(CommandAvailability::Planned)
        );
        assert_eq!(back.phase, Some(TruthPhase::Preflight));
    }

    #[test]
    fn truthfulness_summary_deserializes_legacy_command_modes_field() {
        let json = r#"{
            "command_modes":{"offline-artifact":2},
            "provenance_markers":["workspace-manifest"],
            "phases":["offline-artifact"],
            "host_request_ids":[],
            "host_response_ids":[],
            "receipt_ids":[],
            "reconnect_events":[],
            "cancellation_events":[],
            "live_entry_count":0,
            "offline_entry_count":2
        }"#;
        let back: TruthfulnessSummary = serde_json::from_str(json).unwrap();
        assert_eq!(back.command_availabilities["offline-artifact"], 2);
        assert_eq!(back.offline_entry_count, 2);
    }

    // ── TraceEntry additional coverage ───────────────────────────────────

    #[test]
    fn trace_entry_multiple_fields() {
        let tid = TraceId::from_string("t");
        let sid = ScenarioId::new(ScenarioLayer::Unit, "s", "c");
        let entry = TraceEntry::new(&tid, &sid, TraceLevel::Debug, TraceCategory::Setup, "msg")
            .with_field("a", serde_json::json!(1))
            .with_field("b", serde_json::json!("hello"))
            .with_field("c", serde_json::json!(true));
        assert_eq!(entry.fields.len(), 3);
        assert_eq!(entry.fields["a"], serde_json::json!(1));
        assert_eq!(entry.fields["b"], serde_json::json!("hello"));
        assert_eq!(entry.fields["c"], serde_json::json!(true));
    }

    #[test]
    fn trace_entry_with_zero_duration() {
        let tid = TraceId::from_string("t");
        let sid = ScenarioId::new(ScenarioLayer::Unit, "s", "c");
        let entry = TraceEntry::new(&tid, &sid, TraceLevel::Info, TraceCategory::CliStep, "fast")
            .with_duration_ms(0);
        assert_eq!(entry.duration_ms, Some(0));
    }

    #[test]
    fn trace_entry_clone() {
        let tid = TraceId::from_string("t");
        let sid = ScenarioId::new(ScenarioLayer::Unit, "s", "c");
        let entry = TraceEntry::new(&tid, &sid, TraceLevel::Info, TraceCategory::CliStep, "msg")
            .with_field("key", serde_json::json!("val"));
        let cloned = entry.clone();
        assert_eq!(cloned.message, entry.message);
        assert_eq!(cloned.fields, entry.fields);
    }

    #[test]
    fn trace_entry_with_null_json_field() {
        let tid = TraceId::from_string("t");
        let sid = ScenarioId::new(ScenarioLayer::Unit, "s", "c");
        let entry = TraceEntry::new(&tid, &sid, TraceLevel::Info, TraceCategory::CliStep, "msg")
            .with_field("nullable", serde_json::Value::Null);
        assert_eq!(entry.fields["nullable"], serde_json::Value::Null);
    }

    // ── TraceLog additional coverage ──────────────────────────────────────

    #[test]
    fn trace_log_filter_all_categories() {
        let ctx = scenario_context(ScenarioLayer::Unit, "s", "c");
        let mut log = new_trace_log();
        let categories = [
            TraceCategory::CliStep,
            TraceCategory::HostRequest,
            TraceCategory::HostReceipt,
            TraceCategory::Approval,
            TraceCategory::TokenCount,
            TraceCategory::Replay,
            TraceCategory::Assertion,
            TraceCategory::Setup,
            TraceCategory::Teardown,
        ];
        for cat in categories {
            emit_entry(&mut log, &ctx, TraceLevel::Info, cat, "x");
        }
        for cat in categories {
            assert_eq!(log.filter_by_category(cat).len(), 1);
        }
        assert_eq!(log.len(), 9);
    }

    #[test]
    fn trace_log_summary_counts_all_categories() {
        let ctx = scenario_context(ScenarioLayer::Unit, "s", "c");
        let mut log = new_trace_log();
        emit_entry(&mut log, &ctx, TraceLevel::Info, TraceCategory::Setup, "a");
        emit_entry(&mut log, &ctx, TraceLevel::Info, TraceCategory::Setup, "b");
        emit_entry(
            &mut log,
            &ctx,
            TraceLevel::Error,
            TraceCategory::Assertion,
            "c",
        );
        let s = log.summary();
        assert_eq!(s.categories["setup"], 2);
        assert_eq!(s.categories["assertion"], 1);
    }

    #[test]
    fn trace_log_to_jsonl_each_line_has_message() {
        let ctx = scenario_context(ScenarioLayer::Unit, "s", "c");
        let mut log = new_trace_log();
        emit_entry(
            &mut log,
            &ctx,
            TraceLevel::Info,
            TraceCategory::Setup,
            "msg-1",
        );
        emit_entry(
            &mut log,
            &ctx,
            TraceLevel::Debug,
            TraceCategory::CliStep,
            "msg-2",
        );

        let jsonl = log.to_jsonl().unwrap();
        let lines: Vec<&str> = jsonl.trim_end_matches('\n').split('\n').collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("msg-1"));
        assert!(lines[1].contains("msg-2"));
    }

    #[test]
    fn trace_log_truthfulness_summary_empty_log() {
        let log = new_trace_log();
        let ts = log.truthfulness_summary();
        assert!(ts.command_availabilities.is_empty());
        assert!(ts.provenance_markers.is_empty());
        assert!(ts.phases.is_empty());
        assert_eq!(ts.live_entry_count, 0);
        assert_eq!(ts.offline_entry_count, 0);
    }

    #[test]
    fn trace_log_truthfulness_summary_no_truth_entries_yields_empty() {
        let ctx = scenario_context(ScenarioLayer::Unit, "s", "c");
        let mut log = new_trace_log();
        emit_entry(
            &mut log,
            &ctx,
            TraceLevel::Info,
            TraceCategory::Setup,
            "no-truth",
        );
        emit_entry(
            &mut log,
            &ctx,
            TraceLevel::Debug,
            TraceCategory::CliStep,
            "no-truth-2",
        );
        let ts = log.truthfulness_summary();
        assert!(ts.command_availabilities.is_empty());
        assert_eq!(ts.live_entry_count, 0);
    }

    #[test]
    fn trace_log_truthfulness_multiple_same_availability_accumulates() {
        let ctx = scenario_context(ScenarioLayer::E2E, "t", "m");
        let mut log = new_trace_log();
        for _ in 0..5 {
            let truth = TruthContext::new(CommandAvailability::LiveRuntime);
            log.append(
                TraceEntry::new(
                    &ctx.trace_id,
                    &ctx.scenario_id,
                    TraceLevel::Info,
                    TraceCategory::HostRequest,
                    "live",
                )
                .with_truth_context(truth),
            );
        }
        let ts = log.truthfulness_summary();
        assert_eq!(ts.command_availabilities["live-runtime"], 5);
        assert_eq!(ts.live_entry_count, 5);
    }

    #[test]
    fn trace_log_truthfulness_unavailable_counts_without_live_or_offline_bucket() {
        let ctx = scenario_context(ScenarioLayer::E2E, "t", "u");
        let mut log = new_trace_log();
        let truth = TruthContext::new(CommandAvailability::Unavailable);
        log.append(
            TraceEntry::new(
                &ctx.trace_id,
                &ctx.scenario_id,
                TraceLevel::Warn,
                TraceCategory::CliStep,
                "unavailable",
            )
            .with_truth_context(truth),
        );

        let ts = log.truthfulness_summary();
        assert_eq!(ts.command_availabilities["unavailable"], 1);
        assert_eq!(ts.live_entry_count, 0);
        assert_eq!(ts.offline_entry_count, 0);
    }

    #[test]
    fn trace_log_truthfulness_deduplicates_markers_and_ids() {
        let ctx = scenario_context(ScenarioLayer::E2E, "t", "d");
        let mut log = new_trace_log();
        // Same provenance marker emitted from two entries — should appear once in summary
        for _ in 0..3 {
            let truth = TruthContext::new(CommandAvailability::LiveRuntime)
                .with_provenance_marker("live-host")
                .with_phase(TruthPhase::Invoke)
                .with_host_request_id("req-same");
            log.append(
                TraceEntry::new(
                    &ctx.trace_id,
                    &ctx.scenario_id,
                    TraceLevel::Info,
                    TraceCategory::HostRequest,
                    "invoke",
                )
                .with_truth_context(truth),
            );
        }
        let ts = log.truthfulness_summary();
        assert_eq!(ts.provenance_markers, vec!["live-host"]);
        assert_eq!(ts.host_request_ids, vec!["req-same"]);
        assert_eq!(ts.phases, vec!["invoke"]);
    }

    // ── BundleOutcome additional coverage ────────────────────────────────

    #[test]
    fn bundle_outcome_is_fail_skip_error() {
        let skip = BundleOutcome::Skip {
            reason: "skipped".to_string(),
        };
        let error = BundleOutcome::Error {
            reason: "timeout".to_string(),
        };
        assert!(!skip.is_pass());
        assert!(!skip.is_fail());
        assert!(!error.is_pass());
        assert!(!error.is_fail());
    }

    #[test]
    fn bundle_outcome_display_skip_contains_reason() {
        let o = BundleOutcome::Skip {
            reason: "needs fixture".to_string(),
        };
        assert!(o.to_string().contains("needs fixture"));
    }

    #[test]
    fn bundle_outcome_display_error_contains_reason() {
        let o = BundleOutcome::Error {
            reason: "network timeout".to_string(),
        };
        assert!(o.to_string().contains("network timeout"));
    }

    // ── ArtifactBundle additional coverage ───────────────────────────────

    #[test]
    fn artifact_bundle_bundle_id_contains_layer_suite_case() {
        let base = PathBuf::from("/tmp/ab");
        let sid = ScenarioId::new(ScenarioLayer::Integration, "auth", "refresh");
        let tid = TraceId::from_string("t");
        let bundle = ArtifactBundle::new(&base, &sid, &tid);
        assert!(bundle.bundle_id.starts_with("integration:auth:refresh@"));
    }

    #[test]
    fn artifact_bundle_new_rejects_deserialized_path_unsafe_scenario_ids() {
        let base = PathBuf::from("/tmp/ab");
        let sid = ScenarioId {
            layer: ScenarioLayer::Unit,
            suite: "../suite".to_string(),
            case: "case".to_string(),
        };
        let tid = TraceId::from_string("t");
        let panic = std::panic::catch_unwind(|| ArtifactBundle::new(&base, &sid, &tid));
        assert!(panic.is_err());
    }

    #[test]
    fn artifact_bundle_root_contains_layer_path() {
        let base = PathBuf::from("/artifacts-root");
        let sid = ScenarioId::new(ScenarioLayer::Benchmark, "perf", "speed");
        let tid = TraceId::from_string("t");
        let bundle = ArtifactBundle::new(&base, &sid, &tid);
        let root = bundle.root.to_string_lossy();
        assert!(root.contains("benchmark"));
        assert!(root.contains("perf"));
        assert!(root.contains("speed"));
    }

    #[test]
    fn artifact_bundle_expected_files_all_have_correct_extensions() {
        let base = PathBuf::from("/tmp/ef");
        let sid = ScenarioId::new(ScenarioLayer::Unit, "s", "c");
        let tid = TraceId::from_string("t");
        let bundle = ArtifactBundle::new(&base, &sid, &tid);
        let files = bundle.expected_files();
        let names: Vec<String> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert!(names.contains(&"trace.jsonl".to_string()));
        assert!(names.contains(&"summary.json".to_string()));
        assert!(names.contains(&"environment.json".to_string()));
        assert!(names.contains(&"session_transcript.json".to_string()));
        assert!(names.contains(&"replay.sh".to_string()));
    }

    #[test]
    fn artifact_bundle_golden_snapshot_not_in_expected_files() {
        let base = PathBuf::from("/tmp/gs");
        let sid = ScenarioId::new(ScenarioLayer::Snapshot, "snap", "gold");
        let tid = TraceId::from_string("t");
        let bundle = ArtifactBundle::new(&base, &sid, &tid);
        // golden_snapshot is NOT in expected_files() — it's optional
        let expected = bundle.expected_files();
        assert!(!expected.contains(&bundle.golden_snapshot_path()));
    }

    #[test]
    fn artifact_bundle_trace_id_preserved() {
        let base = PathBuf::from("/tmp/ti");
        let sid = ScenarioId::new(ScenarioLayer::Unit, "s", "c");
        let tid = TraceId::from_string("specific-trace-id");
        let bundle = ArtifactBundle::new(&base, &sid, &tid);
        assert_eq!(bundle.trace_id.as_str(), "specific-trace-id");
    }

    // ── ArtifactManifest additional coverage ──────────────────────────────

    #[test]
    fn artifact_manifest_with_trace_log_populates_log_summary() {
        let ctx = scenario_context(ScenarioLayer::Unit, "s", "c");
        let mut log = new_trace_log();
        emit_entry(&mut log, &ctx, TraceLevel::Info, TraceCategory::Setup, "a");
        emit_entry(
            &mut log,
            &ctx,
            TraceLevel::Error,
            TraceCategory::Assertion,
            "b",
        );

        let sid = ctx.scenario_id.clone();
        let tid = ctx.trace_id.clone();
        let m = ArtifactManifest::new(sid, tid, 4, 512, BundleOutcome::Pass).with_trace_log(&log);
        assert_eq!(m.log_summary.total_entries, 2);
        assert_eq!(m.log_summary.info_count, 1);
        assert_eq!(m.log_summary.error_count, 1);
    }

    #[test]
    fn artifact_manifest_render_e2e_summary_lists_artifacts() {
        let base = PathBuf::from("/tmp/summary");
        let ctx = scenario_context(ScenarioLayer::E2E, "suite", "case");
        let mut log = new_trace_log();
        emit_entry(
            &mut log,
            &ctx,
            TraceLevel::Info,
            TraceCategory::Setup,
            "setup complete",
        );
        let (bundle, manifest) = create_bundle(&base, &ctx, &log, BundleOutcome::Pass);
        let summary = manifest.render_e2e_summary(&bundle);
        assert!(summary.contains("Bundle:"));
        assert!(summary.contains("trace_jsonl"));
        assert!(summary.contains("summary_json"));
        assert!(summary.contains("session_transcript_json"));
    }

    #[test]
    fn scan_trace_log_detects_leaks_with_shared_scanner() {
        let ctx = scenario_context(ScenarioLayer::E2E, "suite", "case");
        let mut log = new_trace_log();
        let entry = TraceEntry::new(
            &ctx.trace_id,
            &ctx.scenario_id,
            TraceLevel::Error,
            TraceCategory::Assertion,
            "token leaked",
        )
        .with_field(
            "authorization",
            serde_json::json!("Bearer abcdefghijklmnopqrstuvwxyz012345"),
        );
        log.append(entry);
        let report = scan_trace_log(&log).expect("trace log should serialize");
        assert_eq!(report.error_count, 1);
        assert!(!report.passed());
    }

    #[test]
    fn artifact_manifest_with_trace_log_populates_truthfulness() {
        let ctx = scenario_context(ScenarioLayer::E2E, "truth", "manifest");
        let mut log = new_trace_log();
        let truth = TruthContext::new(CommandAvailability::OfflineArtifact)
            .with_phase(TruthPhase::OfflineArtifact);
        log.append(
            TraceEntry::new(
                &ctx.trace_id,
                &ctx.scenario_id,
                TraceLevel::Info,
                TraceCategory::CliStep,
                "offline",
            )
            .with_truth_context(truth),
        );

        let m = ArtifactManifest::new(
            ctx.scenario_id.clone(),
            ctx.trace_id.clone(),
            4,
            0,
            BundleOutcome::Pass,
        )
        .with_trace_log(&log);
        assert_eq!(m.truthfulness.offline_entry_count, 1);
        assert_eq!(m.truthfulness.phases, vec!["offline-artifact"]);
    }

    // ── RedactionRule additional coverage ─────────────────────────────────

    #[test]
    fn redaction_rule_empty_field_patterns_no_match() {
        let rule = RedactionRule {
            name: "empty_fields".to_string(),
            field_patterns: Vec::new(),
            value_patterns: vec!["Bearer ".to_string()],
        };
        assert!(!rule.matches_field("token"));
        assert!(!rule.matches_field("secret"));
    }

    #[test]
    fn redaction_rule_empty_value_patterns_no_match() {
        let rule = RedactionRule {
            name: "empty_values".to_string(),
            field_patterns: vec!["token".to_string()],
            value_patterns: Vec::new(),
        };
        assert!(!rule.matches_value("Bearer abc"));
        assert!(!rule.matches_value("token-value"));
    }

    #[test]
    fn redaction_rule_field_match_case_insensitive() {
        let rule = RedactionRule::field_based("test", vec!["password".to_string()]);
        assert!(rule.matches_field("PASSWORD"));
        assert!(rule.matches_field("MyPassword"));
        assert!(rule.matches_field("password_hash"));
    }

    #[test]
    fn redaction_rule_value_match_case_sensitive_prefix() {
        let rule = RedactionRule::value_based("test", vec!["sk-".to_string()]);
        // value matching is prefix-based and case-sensitive
        assert!(rule.matches_value("sk-live-abc"));
        assert!(!rule.matches_value("SK-live-abc")); // uppercase prefix won't match
    }

    // ── RedactedValue additional coverage ─────────────────────────────────

    #[test]
    fn redacted_value_short_digest_is_8_chars() {
        let rv = RedactedValue::from_original("any-secret");
        assert_eq!(rv.short_digest().len(), 8);
    }

    #[test]
    fn redacted_value_full_digest_is_64_chars() {
        let rv = RedactedValue::from_original("any-secret");
        assert_eq!(rv.full_digest().len(), 64);
    }

    #[test]
    fn redacted_value_placeholder_format() {
        let rv = RedactedValue::from_original("test-secret");
        assert!(rv.placeholder.starts_with("[REDACTED:sha256:"));
        assert!(rv.placeholder.ends_with(']'));
        // Short digest is embedded in placeholder
        assert!(rv.placeholder.contains(rv.short_digest()));
    }

    #[test]
    fn redacted_value_empty_string() {
        let rv = RedactedValue::from_original("");
        assert_eq!(rv.full_digest().len(), 64);
        assert!(rv.placeholder.starts_with("[REDACTED:sha256:"));
    }

    #[test]
    fn redacted_value_unicode_input() {
        let rv = RedactedValue::from_original("sécret-clé-123");
        assert_eq!(rv.full_digest().len(), 64);
        assert!(rv.placeholder.starts_with("[REDACTED:sha256:"));
    }

    // ── RedactionEngine additional coverage ──────────────────────────────

    #[test]
    fn redaction_engine_redact_entry_no_fields_no_trigger() {
        let engine = RedactionEngine::default_rules();
        let tid = TraceId::from_string("t");
        let sid = ScenarioId::new(ScenarioLayer::Unit, "s", "c");
        let entry = TraceEntry::new(
            &tid,
            &sid,
            TraceLevel::Info,
            TraceCategory::CliStep,
            "simple",
        );
        let redacted = engine.redact_entry(&entry);
        assert!(!redacted.redacted);
        assert_eq!(redacted.message, "simple");
    }

    #[test]
    fn redaction_engine_redact_entry_non_string_field_unchanged() {
        let engine = RedactionEngine::default_rules();
        let tid = TraceId::from_string("t");
        let sid = ScenarioId::new(ScenarioLayer::Unit, "s", "c");
        // A non-string field named "count" shouldn't be redacted
        let entry = TraceEntry::new(&tid, &sid, TraceLevel::Info, TraceCategory::CliStep, "ok")
            .with_field("count", serde_json::json!(42))
            .with_field("enabled", serde_json::json!(false));
        let redacted = engine.redact_entry(&entry);
        assert!(!redacted.redacted);
        assert_eq!(redacted.fields["count"], serde_json::json!(42));
        assert_eq!(redacted.fields["enabled"], serde_json::json!(false));
    }

    #[test]
    fn redaction_engine_redact_entry_secret_field_non_string_value_redacted() {
        let engine = RedactionEngine::default_rules();
        let tid = TraceId::from_string("t");
        let sid = ScenarioId::new(ScenarioLayer::Unit, "s", "c");
        // Field named "secret" (matches field rule) with numeric value
        let entry = TraceEntry::new(&tid, &sid, TraceLevel::Info, TraceCategory::CliStep, "ok")
            .with_field("secret_count", serde_json::json!(999));
        let redacted = engine.redact_entry(&entry);
        // The field matches "secret" pattern, so it WILL be redacted
        assert!(redacted.redacted);
        let val = redacted.fields["secret_count"].as_str().unwrap();
        assert!(val.starts_with("[REDACTED:sha256:"));
    }

    #[test]
    fn redaction_engine_redact_log_preserves_non_sensitive_entries() {
        let engine = RedactionEngine::default_rules();
        let ctx = scenario_context(ScenarioLayer::Unit, "s", "c");
        let mut log = new_trace_log();
        // First entry: clean
        emit_entry(
            &mut log,
            &ctx,
            TraceLevel::Info,
            TraceCategory::Setup,
            "clean",
        );
        // Second entry: sensitive
        log.append(
            TraceEntry::new(
                &ctx.trace_id,
                &ctx.scenario_id,
                TraceLevel::Info,
                TraceCategory::HostRequest,
                "calling",
            )
            .with_field(
                "authorization",
                serde_json::json!("Bearer super-secret-token"),
            ),
        );
        // Third entry: clean
        emit_entry(
            &mut log,
            &ctx,
            TraceLevel::Info,
            TraceCategory::Teardown,
            "done",
        );

        let redacted = engine.redact_log(&log);
        assert_eq!(redacted.len(), 3);
        assert!(!redacted.entries()[0].redacted);
        assert!(redacted.entries()[1].redacted);
        assert!(!redacted.entries()[2].redacted);
    }

    #[test]
    fn redaction_engine_default_covers_all_expected_patterns() {
        let engine = RedactionEngine::default_rules();
        // Field-based patterns
        for field in [
            "my_token",
            "api_secret",
            "password",
            "my_api_key",
            "my_credential",
            "authorization_header",
        ] {
            assert!(
                engine.should_redact_field(field),
                "expected {field} to be redacted"
            );
        }
        // Value-based patterns
        for value in [
            "Bearer token123",
            "sk-live-key",
            "ghp_abc123",
            "xoxb-slack-token",
        ] {
            assert!(
                engine.redact_value(value).is_some(),
                "expected {value} to be redacted"
            );
        }
    }

    // ── ReplayEnvelope additional coverage ───────────────────────────────

    #[test]
    fn replay_envelope_non_cargo_cmd_no_runner() {
        let sid = ScenarioId::new(ScenarioLayer::E2E, "s", "c");
        let tid = TraceId::from_string("t");
        let env = ReplayEnvelope::new(sid, tid, "fwc invoke github.list", "/project");
        assert!(env.command_runner.is_none());
    }

    #[test]
    fn replay_envelope_cargo_cmd_gets_rch_runner() {
        let sid = ScenarioId::new(ScenarioLayer::E2E, "s", "c");
        let tid = TraceId::from_string("t");
        let env = ReplayEnvelope::new(sid, tid, "cargo test -p fwc", "/project");
        assert_eq!(env.command_runner.as_deref(), Some("rch exec --"));
    }

    #[test]
    fn replay_envelope_with_command_runner_overrides_default() {
        let sid = ScenarioId::new(ScenarioLayer::E2E, "s", "c");
        let tid = TraceId::from_string("t");
        let env = ReplayEnvelope::new(sid, tid, "cargo test", "/project")
            .with_command_runner("my-runner --");
        assert_eq!(env.command_runner.as_deref(), Some("my-runner --"));
    }

    #[test]
    fn replay_envelope_multiple_env_vars() {
        let sid = ScenarioId::new(ScenarioLayer::E2E, "s", "c");
        let tid = TraceId::from_string("t");
        let env = ReplayEnvelope::new(sid, tid, "cmd", "/dir")
            .with_env("A", "1")
            .with_env("B", "2")
            .with_env("C", "3");
        assert_eq!(env.environment.len(), 3);
        assert_eq!(env.environment["B"], "2");
    }

    // ── ReplayInstructions additional coverage ────────────────────────────

    #[test]
    fn replay_instructions_to_shell_script_starts_with_shebang() {
        let instr = ReplayInstructions {
            steps: vec!["echo hello".to_string()],
            prerequisites: Vec::new(),
            notes: Vec::new(),
        };
        let script = instr.to_shell_script();
        assert!(script.starts_with("#!/usr/bin/env bash"));
    }

    #[test]
    fn replay_instructions_no_prerequisites_no_prereq_section() {
        let instr = ReplayInstructions {
            steps: vec!["cd /tmp".to_string()],
            prerequisites: Vec::new(),
            notes: Vec::new(),
        };
        let script = instr.to_shell_script();
        assert!(!script.contains("Prerequisites"));
    }

    #[test]
    fn replay_instructions_no_notes_no_notes_section() {
        let instr = ReplayInstructions {
            steps: vec!["echo test".to_string()],
            prerequisites: Vec::new(),
            notes: Vec::new(),
        };
        let script = instr.to_shell_script();
        assert!(!script.contains("Notes"));
    }

    #[test]
    fn replay_instructions_prerequisites_appear_as_comments() {
        let instr = ReplayInstructions {
            steps: vec!["cargo test".to_string()],
            prerequisites: vec!["cargo".to_string(), "rch".to_string()],
            notes: Vec::new(),
        };
        let script = instr.to_shell_script();
        assert!(script.contains("# Prerequisites:"));
        assert!(script.contains("#   - cargo"));
        assert!(script.contains("#   - rch"));
    }

    #[test]
    fn replay_instructions_notes_appear_as_comments() {
        let instr = ReplayInstructions {
            steps: vec!["fwc status".to_string()],
            prerequisites: Vec::new(),
            notes: vec!["trace id: abc-123".to_string()],
        };
        let script = instr.to_shell_script();
        assert!(script.contains("# Notes:"));
        assert!(script.contains("#   trace id: abc-123"));
    }

    // ── create_bundle helper ──────────────────────────────────────────────

    #[test]
    fn create_bundle_with_trace_log_sets_summary() {
        let ctx = scenario_context(ScenarioLayer::E2E, "s", "c");
        let base = PathBuf::from("/tmp/bundle-test");

        let mut log = new_trace_log();
        emit_entry(&mut log, &ctx, TraceLevel::Info, TraceCategory::Setup, "a");
        emit_entry(
            &mut log,
            &ctx,
            TraceLevel::Error,
            TraceCategory::Assertion,
            "b",
        );
        emit_entry(
            &mut log,
            &ctx,
            TraceLevel::Warn,
            TraceCategory::Teardown,
            "c",
        );

        let (_bundle, manifest) = create_bundle(&base, &ctx, &log, BundleOutcome::Pass);
        assert_eq!(manifest.log_summary.total_entries, 3);
        assert_eq!(manifest.log_summary.info_count, 1);
        assert_eq!(manifest.log_summary.error_count, 1);
        assert_eq!(manifest.log_summary.warn_count, 1);
        assert!(manifest.outcome.is_pass());
    }

    #[test]
    fn create_bundle_skip_outcome() {
        let ctx = scenario_context(ScenarioLayer::Unit, "s", "c");
        let base = PathBuf::from("/tmp/bundle-skip");
        let (_bundle, manifest) = create_bundle(
            &base,
            &ctx,
            &new_trace_log(),
            BundleOutcome::Skip {
                reason: "env not configured".to_string(),
            },
        );
        assert!(!manifest.outcome.is_pass());
        assert!(!manifest.outcome.is_fail());
    }

    // ── default_command_runner ────────────────────────────────────────────

    #[test]
    fn default_command_runner_cargo_prefix() {
        // We can indirectly verify via ReplayEnvelope
        let sid = ScenarioId::new(ScenarioLayer::Unit, "s", "c");
        let tid = TraceId::from_string("t");
        let env = ReplayEnvelope::new(sid.clone(), tid.clone(), "  cargo build", "/dir");
        assert_eq!(env.command_runner.as_deref(), Some("rch exec --"));
    }

    #[test]
    fn default_command_runner_non_cargo() {
        let sid = ScenarioId::new(ScenarioLayer::Unit, "s", "c");
        let tid = TraceId::from_string("t");
        let env = ReplayEnvelope::new(sid, tid, "echo hello", "/dir");
        assert!(env.command_runner.is_none());
    }
}
