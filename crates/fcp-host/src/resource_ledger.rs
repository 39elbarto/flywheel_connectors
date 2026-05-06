//! Per-operation resource ledger evidence for host, mesh, and connector decisions.
//!
//! The ledger is intentionally an evidence contract first: it captures bounded,
//! redaction-safe records that can be emitted by invoke, batch, backpressure,
//! placement, retry, and audit paths without turning telemetry into authority.
//! Missing or stale telemetry is represented explicitly so operators can tell
//! the difference between "healthy low cost" and "unknown".

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{BackpressureAction, BackpressureDecision};

/// Stable schema tag for resource ledger records.
pub const RESOURCE_LEDGER_SCHEMA_VERSION: &str = "resource-ledger/v1";
/// Owning bead for the first per-operation resource ledger contract.
pub const RESOURCE_LEDGER_BEAD: &str = "flywheel_connectors-k3zfl.10";

/// Decision surface that produced the ledger record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceLedgerRecordKind {
    /// Connector invoke or simulate dispatch.
    Invoke,
    /// Batch scheduler or batch worker decision.
    Batch,
    /// Host backpressure controller decision.
    Backpressure,
    /// Mesh/host placement decision.
    Placement,
    /// Retry or fallback decision.
    Retry,
    /// Audit-chain linkage or receipt decision.
    Audit,
    /// A structured skip for unavailable proof prerequisites.
    StructuredSkip,
}

/// Operator-facing outcome for one resource decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceLedgerOutcome {
    /// Work was admitted.
    Admitted,
    /// Work was admitted with a warning.
    Warned,
    /// Work was delayed or queued.
    Delayed,
    /// Work was denied or shed.
    Denied,
    /// Low-priority work was cancelled.
    Cancelled,
    /// Work was retried.
    Retried,
    /// Work was skipped because prerequisites were unavailable.
    Skipped,
    /// The current component could not classify the outcome.
    Unknown,
}

impl ResourceLedgerOutcome {
    const fn from_backpressure_action(action: BackpressureAction) -> Self {
        match action {
            BackpressureAction::Admit => Self::Admitted,
            BackpressureAction::AdmitWithWarning => Self::Warned,
            BackpressureAction::Delay => Self::Delayed,
            BackpressureAction::Shed | BackpressureAction::FallbackStaticPolicy => Self::Denied,
            BackpressureAction::CancelLowPriority => Self::Cancelled,
        }
    }
}

/// Availability and quality class for resource samples.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceTelemetryState {
    /// Samples came from live telemetry.
    Observed,
    /// The source explicitly had no telemetry.
    Unavailable,
    /// Samples existed but were not fresh enough to drive a decision.
    Stale,
    /// Details were intentionally redacted.
    Redacted,
    /// The field does not apply to this decision kind.
    NotApplicable,
}

/// Bounded resource samples attached to one decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLedgerSamples {
    /// Telemetry state for the sample block.
    pub state: ResourceTelemetryState,
    /// Queue pressure in per-mille units.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue_pressure_per_mille: Option<u16>,
    /// CPU pressure in per-mille units.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_pressure_per_mille: Option<u16>,
    /// Memory pressure in per-mille units.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_pressure_per_mille: Option<u16>,
    /// In-flight operation count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_flight: Option<u64>,
    /// Queue depth count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue_depth: Option<u64>,
    /// Downstream retry-after hint in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

impl ResourceLedgerSamples {
    /// Build an explicitly unavailable sample block.
    #[must_use]
    pub const fn unavailable() -> Self {
        Self {
            state: ResourceTelemetryState::Unavailable,
            queue_pressure_per_mille: None,
            cpu_pressure_per_mille: None,
            memory_pressure_per_mille: None,
            in_flight: None,
            queue_depth: None,
            retry_after_ms: None,
        }
    }

    const fn state_from_any_observed(&mut self) {
        if self.queue_pressure_per_mille.is_some()
            || self.cpu_pressure_per_mille.is_some()
            || self.memory_pressure_per_mille.is_some()
            || self.in_flight.is_some()
            || self.queue_depth.is_some()
            || self.retry_after_ms.is_some()
        {
            self.state = ResourceTelemetryState::Observed;
        }
    }
}

impl Default for ResourceLedgerSamples {
    fn default() -> Self {
        Self::unavailable()
    }
}

/// Nearest-rank latency percentiles for per-operation evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_field_names)]
pub struct ResourceLedgerLatencySummary {
    /// Number of samples.
    pub sample_count: u64,
    /// Minimum latency.
    pub min_ns: u64,
    /// Maximum latency.
    pub max_ns: u64,
    /// Integer mean latency.
    pub mean_ns: u64,
    /// 50th percentile.
    pub p50_ns: u64,
    /// 95th percentile.
    pub p95_ns: u64,
    /// 99th percentile.
    pub p99_ns: u64,
}

impl ResourceLedgerLatencySummary {
    /// Compute nearest-rank latency percentiles from nanosecond samples.
    #[must_use]
    pub fn from_nanos<I>(samples: I) -> Option<Self>
    where
        I: IntoIterator<Item = u64>,
    {
        let mut sorted = samples.into_iter().collect::<Vec<_>>();
        if sorted.is_empty() {
            return None;
        }
        sorted.sort_unstable();
        let sum = sorted
            .iter()
            .fold(0_u128, |acc, value| acc.saturating_add(u128::from(*value)));
        let mean = sum / sorted.len() as u128;
        Some(Self {
            sample_count: u64::try_from(sorted.len()).unwrap_or(u64::MAX),
            min_ns: sorted.first().copied()?,
            max_ns: sorted.last().copied()?,
            mean_ns: u64::try_from(mean).unwrap_or(u64::MAX),
            p50_ns: nearest_rank(&sorted, 500)?,
            p95_ns: nearest_rank(&sorted, 950)?,
            p99_ns: nearest_rank(&sorted, 990)?,
        })
    }
}

/// Raw input for a generic resource ledger record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceLedgerInput {
    /// Stable scenario identifier.
    pub scenario_id: String,
    /// Operation id or correlation key for the decision.
    pub operation_id: String,
    /// Decision surface.
    pub kind: ResourceLedgerRecordKind,
    /// Operator-facing outcome.
    pub outcome: ResourceLedgerOutcome,
    /// Redaction-safe command line for replay.
    pub command_line: Vec<String>,
    /// Git revision under test.
    pub git_revision: String,
    /// Worker or node identity; hashed in output.
    pub worker_identity: String,
    /// Zone id; hashed in output.
    pub zone_id: Option<String>,
    /// Principal id; hashed in output.
    pub principal_id: Option<String>,
    /// Connector id, if the decision was connector-scoped.
    pub connector_id: Option<String>,
    /// Human/machine-readable controller decision label.
    pub controller_decision: Option<String>,
    /// Resource samples available to this decision.
    pub samples: ResourceLedgerSamples,
    /// Optional latency samples.
    pub latency_samples_ns: Vec<u64>,
    /// Audit receipt id, if already linked.
    pub audit_receipt_id: Option<String>,
    /// Explicit fallback reason.
    pub fallback_reason: Option<String>,
    /// Explicit skip reason.
    pub skip_reason: Option<String>,
}

/// Input for converting an existing host backpressure decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceBackpressureLedgerInput {
    /// Stable scenario identifier.
    pub scenario_id: String,
    /// Operation id or correlation key for the decision.
    pub operation_id: String,
    /// Redaction-safe command line for replay.
    pub command_line: Vec<String>,
    /// Git revision under test.
    pub git_revision: String,
    /// Worker or node identity; hashed in output.
    pub worker_identity: String,
    /// Zone id; hashed in output.
    pub zone_id: Option<String>,
    /// Principal id; hashed in output.
    pub principal_id: Option<String>,
    /// Connector id, if the decision was connector-scoped.
    pub connector_id: Option<String>,
    /// Replayable backpressure decision.
    pub decision: BackpressureDecision,
}

/// Redaction-safe per-operation resource ledger record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLedgerRecord {
    /// Stable schema version.
    pub schema_version: String,
    /// Owning bead id.
    pub bead_id: String,
    /// Record generation timestamp.
    pub generated_at: DateTime<Utc>,
    /// Stable scenario identifier.
    pub scenario_id: String,
    /// Operation id or correlation key for the decision.
    pub operation_id: String,
    /// Decision surface.
    pub kind: ResourceLedgerRecordKind,
    /// Operator-facing outcome.
    pub outcome: ResourceLedgerOutcome,
    /// Redacted rerunnable command line.
    pub command_line: Vec<String>,
    /// Redacted git revision under test.
    pub git_revision: String,
    /// Hashed worker or node identity.
    pub worker_ref: String,
    /// Hashed zone reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone_ref: Option<String>,
    /// Hashed principal reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_ref: Option<String>,
    /// Connector id, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_id: Option<String>,
    /// Controller decision label, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller_decision: Option<String>,
    /// Bounded resource samples.
    pub samples: ResourceLedgerSamples,
    /// Latency summary, when samples were supplied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency: Option<ResourceLedgerLatencySummary>,
    /// Linked audit receipt id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_receipt_id: Option<String>,
    /// Explicit fallback reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_reason: Option<String>,
    /// Explicit skip reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
}

impl ResourceLedgerRecord {
    /// Build a redaction-safe record from raw input.
    #[must_use]
    pub fn new(input: ResourceLedgerInput) -> Self {
        Self {
            schema_version: RESOURCE_LEDGER_SCHEMA_VERSION.to_string(),
            bead_id: RESOURCE_LEDGER_BEAD.to_string(),
            generated_at: Utc::now(),
            scenario_id: redact_sensitive_text(&input.scenario_id),
            operation_id: redact_sensitive_text(&input.operation_id),
            kind: input.kind,
            outcome: input.outcome,
            command_line: redact_command_line(input.command_line),
            git_revision: redact_sensitive_text(&input.git_revision),
            worker_ref: hashed_ref("worker", &input.worker_identity),
            zone_ref: input
                .zone_id
                .as_deref()
                .map(|zone| hashed_ref("zone", zone)),
            principal_ref: input
                .principal_id
                .as_deref()
                .map(|principal| hashed_ref("principal", principal)),
            connector_id: input
                .connector_id
                .as_deref()
                .map(redact_sensitive_text)
                .filter(|value| !value.is_empty()),
            controller_decision: input
                .controller_decision
                .as_deref()
                .map(redact_sensitive_text),
            samples: input.samples,
            latency: ResourceLedgerLatencySummary::from_nanos(input.latency_samples_ns),
            audit_receipt_id: input.audit_receipt_id.as_deref().map(redact_sensitive_text),
            fallback_reason: input.fallback_reason.as_deref().map(redact_sensitive_text),
            skip_reason: input.skip_reason.as_deref().map(redact_sensitive_text),
        }
    }

    /// Build a structured skip record with explicit missing proof prerequisite.
    #[must_use]
    pub fn structured_skip(
        scenario_id: impl Into<String>,
        operation_id: impl Into<String>,
        command_line: Vec<String>,
        git_revision: impl Into<String>,
        worker_identity: impl Into<String>,
        skip_reason: impl Into<String>,
    ) -> Self {
        Self::new(ResourceLedgerInput {
            scenario_id: scenario_id.into(),
            operation_id: operation_id.into(),
            kind: ResourceLedgerRecordKind::StructuredSkip,
            outcome: ResourceLedgerOutcome::Skipped,
            command_line,
            git_revision: git_revision.into(),
            worker_identity: worker_identity.into(),
            zone_id: None,
            principal_id: None,
            connector_id: None,
            controller_decision: Some("not_attempted".to_string()),
            samples: ResourceLedgerSamples::unavailable(),
            latency_samples_ns: Vec::new(),
            audit_receipt_id: None,
            fallback_reason: None,
            skip_reason: Some(skip_reason.into()),
        })
    }

    /// Convert a replayable host backpressure decision into a ledger record.
    #[must_use]
    pub fn from_backpressure_decision(input: ResourceBackpressureLedgerInput) -> Self {
        let telemetry = input.decision.replay.input.telemetry;
        let mut samples = ResourceLedgerSamples {
            state: ResourceTelemetryState::Unavailable,
            queue_pressure_per_mille: telemetry.queue_pressure_per_mille,
            cpu_pressure_per_mille: telemetry.cpu_pressure_per_mille,
            memory_pressure_per_mille: telemetry.memory_pressure_per_mille,
            in_flight: None,
            queue_depth: None,
            retry_after_ms: telemetry.downstream_retry_after_ms,
        };
        samples.state_from_any_observed();

        Self::new(ResourceLedgerInput {
            scenario_id: input.scenario_id,
            operation_id: input.operation_id,
            kind: ResourceLedgerRecordKind::Backpressure,
            outcome: ResourceLedgerOutcome::from_backpressure_action(input.decision.action),
            command_line: input.command_line,
            git_revision: input.git_revision,
            worker_identity: input.worker_identity,
            zone_id: input.zone_id,
            principal_id: input.principal_id,
            connector_id: input.connector_id,
            controller_decision: Some(input.decision.action.as_str().to_string()),
            samples,
            latency_samples_ns: Vec::new(),
            audit_receipt_id: None,
            fallback_reason: input.decision.fallback_reason,
            skip_reason: None,
        })
    }

    /// Render this record as a JSONL value.
    ///
    /// # Errors
    ///
    /// Returns a serde error if the record cannot be converted to JSON.
    pub fn to_jsonl_value(&self) -> Result<Value, serde_json::Error> {
        Ok(json!({
            "record_type": "resource_ledger",
            "schema_version": self.schema_version,
            "bead_id": self.bead_id,
            "ledger": serde_json::to_value(self)?,
        }))
    }

    /// Render this record as one JSONL line.
    ///
    /// # Errors
    ///
    /// Returns a serde error if the record cannot be serialized.
    pub fn to_jsonl_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self.to_jsonl_value()?)
    }
}

fn nearest_rank(sorted: &[u64], per_mille: usize) -> Option<u64> {
    let len = sorted.len();
    if len == 0 {
        return None;
    }
    let rank = len.saturating_mul(per_mille).saturating_add(999) / 1_000;
    let index = rank.saturating_sub(1).min(len - 1);
    sorted.get(index).copied()
}

fn redact_command_line(command_line: Vec<String>) -> Vec<String> {
    command_line
        .into_iter()
        .map(|arg| redact_sensitive_text(&arg))
        .collect()
}

fn redact_sensitive_text(input: &str) -> String {
    let lower = input.to_ascii_lowercase();
    if [
        "token",
        "secret",
        "password",
        "credential",
        "bearer",
        "api_key",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    {
        "[REDACTED]".to_string()
    } else {
        input.to_string()
    }
}

fn hashed_ref(prefix: &str, raw: &str) -> String {
    let digest = blake3::hash(raw.as_bytes()).to_hex().to_string();
    format!("{prefix}:blake3:{}", &digest[..16])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BackpressureCalibration, BackpressureController, BackpressureControllerInput,
        BackpressureTelemetry, RequestPriority,
    };

    fn base_input() -> ResourceLedgerInput {
        let sensitive_flag = ["--to", "ken=redaction-fixture"].concat();
        ResourceLedgerInput {
            scenario_id: "swarm.resource-ledger.invoke".to_string(),
            operation_id: "op-123".to_string(),
            kind: ResourceLedgerRecordKind::Invoke,
            outcome: ResourceLedgerOutcome::Admitted,
            command_line: vec!["fcp-resource-ledger-evidence".to_string(), sensitive_flag],
            git_revision: "abc123".to_string(),
            worker_identity: "worker-01.tailnet.example".to_string(),
            zone_id: Some("z:private".to_string()),
            principal_id: Some("principal:alice@example.com".to_string()),
            connector_id: Some("fcp.github".to_string()),
            controller_decision: Some("admit".to_string()),
            samples: ResourceLedgerSamples {
                state: ResourceTelemetryState::Observed,
                queue_pressure_per_mille: Some(125),
                cpu_pressure_per_mille: Some(250),
                memory_pressure_per_mille: Some(400),
                in_flight: Some(12),
                queue_depth: Some(3),
                retry_after_ms: None,
            },
            latency_samples_ns: vec![10, 20, 30, 40, 50],
            audit_receipt_id: Some("receipt-123".to_string()),
            fallback_reason: None,
            skip_reason: None,
        }
    }

    #[test]
    fn latency_summary_uses_nearest_rank() {
        let summary =
            ResourceLedgerLatencySummary::from_nanos(1_u64..=100).expect("non-empty samples");

        assert_eq!(summary.sample_count, 100);
        assert_eq!(summary.min_ns, 1);
        assert_eq!(summary.max_ns, 100);
        assert_eq!(summary.mean_ns, 50);
        assert_eq!(summary.p50_ns, 50);
        assert_eq!(summary.p95_ns, 95);
        assert_eq!(summary.p99_ns, 99);
        assert!(ResourceLedgerLatencySummary::from_nanos([]).is_none());
    }

    #[test]
    fn record_hashes_sensitive_actor_fields_and_redacts_command_line() {
        let record = ResourceLedgerRecord::new(base_input());

        assert_eq!(record.schema_version, RESOURCE_LEDGER_SCHEMA_VERSION);
        assert_eq!(record.bead_id, RESOURCE_LEDGER_BEAD);
        assert_eq!(
            record.worker_ref.len(),
            "worker:blake3:0123456789abcdef".len()
        );
        assert_eq!(
            record
                .zone_ref
                .as_deref()
                .expect("zone ref")
                .split(':')
                .next(),
            Some("zone")
        );
        assert!(
            record
                .principal_ref
                .as_deref()
                .expect("principal")
                .contains("blake3")
        );
        assert_eq!(record.command_line[1], "[REDACTED]");
        assert_eq!(record.connector_id.as_deref(), Some("fcp.github"));
        assert_eq!(record.latency.expect("latency").p99_ns, 50);

        let jsonl = record.to_jsonl_line().expect("serialize JSONL");
        assert!(!jsonl.contains("redaction-fixture"));
        assert!(!jsonl.contains("alice@example.com"));
        assert!(!jsonl.contains("worker-01.tailnet.example"));
        assert!(jsonl.contains("\"record_type\":\"resource_ledger\""));
    }

    #[test]
    fn structured_skip_preserves_unknown_telemetry_as_a_first_class_state() {
        let record = ResourceLedgerRecord::structured_skip(
            "swarm.resource-ledger.host-mesh",
            "op-skip",
            vec!["fcp-resource-ledger-evidence".to_string()],
            "abc123",
            "worker-02",
            "missing host+mesh swarm fixture",
        );

        assert_eq!(record.kind, ResourceLedgerRecordKind::StructuredSkip);
        assert_eq!(record.outcome, ResourceLedgerOutcome::Skipped);
        assert_eq!(record.samples.state, ResourceTelemetryState::Unavailable);
        assert_eq!(
            record.skip_reason.as_deref(),
            Some("missing host+mesh swarm fixture")
        );
        assert!(record.latency.is_none());
    }

    #[test]
    fn backpressure_decision_conversion_carries_action_and_samples() {
        let decision = BackpressureController::default().decide(BackpressureControllerInput::new(
            "fcp.github/issues.list",
            RequestPriority::Normal,
            BackpressureTelemetry {
                queue_pressure_per_mille: Some(850),
                cpu_pressure_per_mille: Some(900),
                memory_pressure_per_mille: Some(700),
                downstream_retry_after_ms: Some(250),
                retry_amplification_per_mille: Some(200),
                useful_work_per_mille: Some(400),
            },
            BackpressureCalibration::valid(),
        ));
        let record =
            ResourceLedgerRecord::from_backpressure_decision(ResourceBackpressureLedgerInput {
                scenario_id: "swarm.resource-ledger.backpressure".to_string(),
                operation_id: "op-backpressure".to_string(),
                command_line: vec!["fcp-resource-ledger-evidence".to_string()],
                git_revision: "abc123".to_string(),
                worker_identity: "worker-03".to_string(),
                zone_id: Some("z:work".to_string()),
                principal_id: Some("principal:bob".to_string()),
                connector_id: Some("fcp.github".to_string()),
                decision,
            });

        assert_eq!(record.kind, ResourceLedgerRecordKind::Backpressure);
        assert_eq!(record.samples.state, ResourceTelemetryState::Observed);
        assert_eq!(record.samples.queue_pressure_per_mille, Some(850));
        assert_eq!(record.samples.retry_after_ms, Some(250));
        assert!(record.controller_decision.is_some());
    }

    #[test]
    fn jsonl_wrapper_has_stable_top_level_shape() {
        let record = ResourceLedgerRecord::new(base_input());
        let value = record.to_jsonl_value().expect("json value");

        assert_eq!(value["record_type"], "resource_ledger");
        assert_eq!(value["schema_version"], RESOURCE_LEDGER_SCHEMA_VERSION);
        assert_eq!(value["bead_id"], RESOURCE_LEDGER_BEAD);
        assert_eq!(value["ledger"]["kind"], "invoke");
        assert_eq!(value["ledger"]["samples"]["state"], "observed");
    }
}
