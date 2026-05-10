//! High-core swarm performance evidence adapter for `ProofGraph`.
//!
//! This module does not run swarm benchmarks. It records redaction-safe
//! summaries from `rch` or fixture outputs and classifies whether those
//! summaries are strong enough to prove large-swarm readiness.

#![allow(clippy::module_name_repetitions)]

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::proof_graph::{
    BeadOwner, ClaimId, ClaimNode, ClaimStatus, EvidenceId, EvidenceKind, EvidenceNode,
    FreshnessWindow, ProofGap, ProofGapId, ProofGapStatus, ProofGraph, ProofGraphError,
    RedactionClass, SuggestedActionId, SuggestedNextAction, SupportEdge, SupportRelationship,
    TruthSource,
};
use crate::proof_runner::{ProofCommandSpec, ProofRunClassification, ProofRunnerKind};

/// Stable schema for high-core swarm evidence JSONL records.
pub const HIGH_CORE_SWARM_EVIDENCE_SCHEMA: &str = "fcp.high-core-swarm-evidence.v1";

const MAX_KEY_FRAGMENT_LEN: usize = 96;

/// Redaction-safe swarm performance evidence captured from a remote proof run
/// or a local fixture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HighCoreSwarmEvidenceRecord {
    /// Schema identifier; must be [`HIGH_CORE_SWARM_EVIDENCE_SCHEMA`].
    #[serde(default = "default_high_core_swarm_schema")]
    pub schema: String,
    /// Stable scenario id used in graph node ids.
    pub scenario_id: String,
    /// Bead that owns the scenario claim.
    pub owner_bead_id: String,
    /// Optional agent currently responsible for the scenario.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_agent: Option<String>,
    /// Unix millisecond timestamp when the run was observed.
    pub observed_at_unix_ms: u64,
    /// Maximum freshness window for the record.
    pub valid_for_ms: u64,
    /// Requirements that must be met before this can prove high-core readiness.
    pub requirements: SwarmEvidenceRequirements,
    /// Hardware and execution class that produced the run.
    pub hardware: SwarmHardwareProfile,
    /// Workload shape exercised by the run.
    pub scenario: SwarmScenarioShape,
    /// Scheduling, admission, and backpressure decisions observed during the run.
    #[serde(default)]
    pub decisions: Vec<SwarmControlDecision>,
    /// Queue latency percentiles from the run.
    pub queue_latency: QueueLatencyPercentiles,
    /// Memory headroom observed at peak load.
    pub memory: MemoryHeadroom,
    /// Drop/retry/cancel/fail counters.
    pub outcomes: SwarmOutcomeCounters,
    /// Terminal command classification from the proof runner.
    pub run_classification: ProofRunClassification,
    /// Exact redaction-safe command metadata that produced the run.
    pub proof_command: ProofCommandSpec,
    /// Redaction-safe source reference such as a fixture id or artifact path.
    pub source_ref: String,
    /// Optional digest for the external evidence bundle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_digest: Option<String>,
    /// Redaction class for graph fields derived from this record.
    pub redaction_class: RedactionClass,
    /// Operator value used for proof-debt ranking.
    pub proof_value: SwarmProofValue,
}

impl HighCoreSwarmEvidenceRecord {
    /// Validate the evidence record and all nested redaction-safe fields.
    ///
    /// # Errors
    ///
    /// Returns [`HighCoreSwarmEvidenceError`] when required fields are missing,
    /// percentile claims conflict, redaction rules are violated, or graph
    /// conversion metadata is invalid.
    pub fn validate(&self) -> Result<(), HighCoreSwarmEvidenceError> {
        if self.schema != HIGH_CORE_SWARM_EVIDENCE_SCHEMA {
            return Err(HighCoreSwarmEvidenceError::InvalidSchema {
                expected: HIGH_CORE_SWARM_EVIDENCE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        validate_key_fragment("scenario_id", &self.scenario_id)?;
        validate_key_fragment("owner_bead_id", &self.owner_bead_id)?;
        if let Some(owner_agent) = &self.owner_agent {
            validate_key_fragment("owner_agent", owner_agent)?;
        }
        if self.valid_for_ms == 0 {
            return Err(HighCoreSwarmEvidenceError::InvalidCount {
                field: "valid_for_ms",
            });
        }
        self.requirements.validate()?;
        self.hardware.validate()?;
        self.scenario.validate()?;
        self.validate_decisions()?;
        self.queue_latency.validate()?;
        self.memory.validate()?;
        self.proof_command.validate()?;
        validate_safe_text("source_ref", &self.source_ref)?;
        if let Some(artifact_digest) = &self.artifact_digest {
            validate_digest("artifact_digest", artifact_digest)?;
        }
        if !self.redaction_class.is_graph_safe() {
            return Err(HighCoreSwarmEvidenceError::UnsafeRedactionClass {
                redaction_class: self.redaction_class,
            });
        }
        self.proof_value.validate()
    }

    /// Classify the record at the supplied wall-clock timestamp.
    ///
    /// # Errors
    ///
    /// Returns [`HighCoreSwarmEvidenceError`] when the record is invalid.
    pub fn analyze_at(
        &self,
        now_unix_ms: u64,
    ) -> Result<HighCoreSwarmAnalysis, HighCoreSwarmEvidenceError> {
        self.validate()?;

        let classification = self.classification_at(now_unix_ms);
        let proof_gaps = self.proof_gaps(classification)?;
        let analysis = HighCoreSwarmAnalysis {
            classification,
            claim_status: classification.claim_status(self.freshness_window().expires_at_unix_ms()),
            relationship: classification.support_relationship(),
            truth_source: classification.truth_source(self.hardware.remote_execution),
            evidence_kind: classification.evidence_kind(self.hardware.remote_execution),
            proof_gaps,
            summary: classification.summary(&self.scenario_id),
        };
        Ok(analysis)
    }

    /// Convert the record into a complete one-claim [`ProofGraph`].
    ///
    /// # Errors
    ///
    /// Returns [`HighCoreSwarmEvidenceError`] when record or graph validation
    /// fails.
    pub fn to_proof_graph_at(
        &self,
        now_unix_ms: u64,
    ) -> Result<ProofGraph, HighCoreSwarmEvidenceError> {
        let claim = self.to_claim_node_at(now_unix_ms)?;
        let evidence = self.to_evidence_node_at(now_unix_ms)?;
        let edge = self.to_support_edge_at(now_unix_ms)?;
        let actions = self.suggested_actions_at(now_unix_ms, &claim.id)?;
        Ok(ProofGraph::from_nodes(
            vec![claim],
            vec![evidence],
            vec![edge],
            actions,
        )?)
    }

    /// Convert the record into a [`ClaimNode`].
    ///
    /// # Errors
    ///
    /// Returns [`HighCoreSwarmEvidenceError`] when record or graph validation
    /// fails.
    pub fn to_claim_node_at(
        &self,
        now_unix_ms: u64,
    ) -> Result<ClaimNode, HighCoreSwarmEvidenceError> {
        let analysis = self.analyze_at(now_unix_ms)?;
        let claim = ClaimNode {
            id: self.claim_id()?,
            title: format!("High-core swarm proof for {}", self.scenario_id),
            statement: format!(
                "Scenario {} proves {} connectors can run on high-core remote hardware with bounded queueing and memory headroom",
                self.scenario_id, self.scenario.target_connector_count
            ),
            status: analysis.claim_status,
            required_truth_source: TruthSource::MeshBacked,
            freshness: self.freshness_window(),
            redaction_class: self.redaction_class,
            owner: Some(BeadOwner {
                bead_id: self.owner_bead_id.clone(),
                agent_name: self.owner_agent.clone(),
            }),
            tags: BTreeSet::from([
                "high-core".to_owned(),
                "performance".to_owned(),
                "proofgraph".to_owned(),
                "rch".to_owned(),
                "swarm".to_owned(),
                analysis.classification.as_str().to_owned(),
            ]),
            proof_gaps: analysis.proof_gaps,
        };
        claim.validate()?;
        Ok(claim)
    }

    /// Convert the record into an [`EvidenceNode`].
    ///
    /// # Errors
    ///
    /// Returns [`HighCoreSwarmEvidenceError`] when record or graph validation
    /// fails.
    pub fn to_evidence_node_at(
        &self,
        now_unix_ms: u64,
    ) -> Result<EvidenceNode, HighCoreSwarmEvidenceError> {
        let analysis = self.analyze_at(now_unix_ms)?;
        let evidence = EvidenceNode {
            id: self.evidence_id()?,
            kind: analysis.evidence_kind,
            summary: analysis.summary,
            truth_source: analysis.truth_source,
            freshness: self.freshness_window(),
            redaction_class: self.redaction_class,
            source_ref: self.source_ref.clone(),
            content_digest: Some(self.record_digest()?),
            rerun_command: Some(
                self.proof_command
                    .to_rerun_command(format!("rerun:high-core-swarm:{}", self.scenario_id))?,
            ),
        };
        evidence.validate()?;
        Ok(evidence)
    }

    /// Convert the record into a support edge.
    ///
    /// # Errors
    ///
    /// Returns [`HighCoreSwarmEvidenceError`] when edge validation fails.
    pub fn to_support_edge_at(
        &self,
        now_unix_ms: u64,
    ) -> Result<SupportEdge, HighCoreSwarmEvidenceError> {
        let analysis = self.analyze_at(now_unix_ms)?;
        Ok(SupportEdge::new(
            self.claim_id()?,
            self.evidence_id()?,
            analysis.relationship,
            analysis.classification.edge_rationale(),
        )?)
    }

    /// Convert each control decision to a deterministic JSONL-ready event.
    ///
    /// # Errors
    ///
    /// Returns [`HighCoreSwarmEvidenceError`] when the record is invalid.
    pub fn to_jsonl_events_at(
        &self,
        now_unix_ms: u64,
    ) -> Result<Vec<HighCoreSwarmJsonlEvent>, HighCoreSwarmEvidenceError> {
        let analysis = self.analyze_at(now_unix_ms)?;
        Ok(self
            .decisions
            .iter()
            .map(|decision| HighCoreSwarmJsonlEvent {
                schema: HIGH_CORE_SWARM_EVIDENCE_SCHEMA.to_owned(),
                scenario_id: self.scenario_id.clone(),
                observed_at_unix_ms: self.observed_at_unix_ms,
                event_sequence: decision.sequence,
                hardware_class: self.hardware.hardware_class.clone(),
                logical_cpus: self.hardware.logical_cpus,
                physical_cores: self.hardware.physical_cores,
                ram_gib: self.hardware.ram_gib,
                target_connector_count: self.scenario.target_connector_count,
                active_agent_count: self.scenario.active_agent_count,
                decision_kind: decision.kind,
                queue_p99_ms: self.queue_latency.p99_ms,
                memory_headroom_gib: self.memory.available_headroom_gib,
                dropped_count: self.outcomes.dropped_count,
                retried_count: self.outcomes.retried_count,
                cancelled_count: self.outcomes.cancelled_count,
                failed_count: self.outcomes.failed_count,
                run_classification: self.run_classification,
                swarm_classification: analysis.classification,
                summary: decision.summary.clone(),
            })
            .collect())
    }

    /// Deterministic digest of the record fields carried by this adapter.
    ///
    /// # Errors
    ///
    /// Returns [`HighCoreSwarmEvidenceError`] when serialization fails or the
    /// record is invalid.
    pub fn record_digest(&self) -> Result<String, HighCoreSwarmEvidenceError> {
        self.validate()?;
        if let Some(artifact_digest) = &self.artifact_digest {
            return Ok(artifact_digest.clone());
        }
        let mut clone = self.clone();
        clone.artifact_digest = None;
        let bytes = serde_json::to_vec(&clone)?;
        Ok(format!(
            "blake3:{}",
            hex::encode(blake3::hash(&bytes).as_bytes())
        ))
    }

    /// Build a proof-debt ranking item for this record, if the record still
    /// needs action.
    ///
    /// # Errors
    ///
    /// Returns [`HighCoreSwarmEvidenceError`] when record or graph metadata is
    /// invalid.
    pub fn proof_debt_item_at(
        &self,
        now_unix_ms: u64,
    ) -> Result<Option<SwarmProofDebtItem>, HighCoreSwarmEvidenceError> {
        let analysis = self.analyze_at(now_unix_ms)?;
        if analysis.classification == HighCoreSwarmClassification::RemoteHighCoreProof
            && !self.proof_value.rerun_requested
        {
            return Ok(None);
        }
        let debt_kind = SwarmProofDebtKind::from_classification(
            analysis.classification,
            self.proof_value.rerun_requested,
        );
        Ok(Some(SwarmProofDebtItem::new(
            self.scenario_id.clone(),
            self.claim_id()?,
            debt_kind,
            analysis.summary,
            self.proof_value.user_impact_score,
            self.proof_value.proof_reuse_score,
        )?))
    }

    fn validate_decisions(&self) -> Result<(), HighCoreSwarmEvidenceError> {
        if self.decisions.is_empty() {
            return Err(HighCoreSwarmEvidenceError::NoDecisions);
        }
        let mut seen_sequences = BTreeSet::new();
        let mut previous_sequence = None;
        for decision in &self.decisions {
            decision.validate()?;
            if !seen_sequences.insert(decision.sequence) {
                return Err(HighCoreSwarmEvidenceError::DuplicateDecisionSequence {
                    sequence: decision.sequence,
                });
            }
            if let Some(previous) = previous_sequence
                && decision.sequence <= previous
            {
                return Err(HighCoreSwarmEvidenceError::NonMonotonicDecisionSequence {
                    previous,
                    current: decision.sequence,
                });
            }
            previous_sequence = Some(decision.sequence);
        }
        Ok(())
    }

    fn classification_at(&self, now_unix_ms: u64) -> HighCoreSwarmClassification {
        if self.run_failed_or_stopped() {
            return HighCoreSwarmClassification::FailedRun;
        }
        if matches!(
            self.run_classification,
            ProofRunClassification::RetrievalFailedAfterSuccess
                | ProofRunClassification::RetrievalMissingAfterSuccess
        ) {
            return HighCoreSwarmClassification::PartialArtifactRetrieval;
        }
        if !self.hardware.remote_execution
            || matches!(self.hardware.hardware_class, SwarmHardwareClass::LocalSmall)
            || !matches!(self.proof_command.runner, ProofRunnerKind::Rch)
        {
            return HighCoreSwarmClassification::LocalSmallProof;
        }
        if !self.reproducible_remote_command() {
            return HighCoreSwarmClassification::NonReproducibleCommand;
        }
        if !self.hardware.meets_requirements(&self.requirements) {
            return HighCoreSwarmClassification::InsufficientHardware;
        }
        if self.scenario.target_connector_count < self.requirements.minimum_connector_count {
            return HighCoreSwarmClassification::InsufficientScale;
        }
        if !self.has_decision_kind(SwarmControlDecisionKind::SchedulingPlanned)
            || !self.has_decision_kind(SwarmControlDecisionKind::AdmissionEvaluated)
            || !self.has_decision_kind(SwarmControlDecisionKind::BackpressureApplied)
        {
            return HighCoreSwarmClassification::MissingDecisionEvidence;
        }
        if !self.freshness_window().is_fresh_at(now_unix_ms) {
            return HighCoreSwarmClassification::StaleHighCoreProof;
        }
        if self.queue_latency.p99_ms > self.requirements.maximum_p99_queue_latency_ms {
            return HighCoreSwarmClassification::QueueSloExceeded;
        }
        if self.memory.available_headroom_gib < self.requirements.minimum_memory_headroom_gib {
            return HighCoreSwarmClassification::MemoryHeadroomTooLow;
        }
        HighCoreSwarmClassification::RemoteHighCoreProof
    }

    fn claim_id(&self) -> Result<ClaimId, ProofGraphError> {
        ClaimId::new(format!("claim.high-core-swarm.{}", self.scenario_id))
    }

    fn evidence_id(&self) -> Result<EvidenceId, ProofGraphError> {
        EvidenceId::new(format!("evidence.high-core-swarm.{}.run", self.scenario_id))
    }

    fn freshness_window(&self) -> FreshnessWindow {
        FreshnessWindow::new(
            self.observed_at_unix_ms,
            self.valid_for_ms.min(self.requirements.maximum_age_ms),
        )
    }

    fn proof_gaps(
        &self,
        classification: HighCoreSwarmClassification,
    ) -> Result<Vec<ProofGap>, ProofGraphError> {
        match classification {
            HighCoreSwarmClassification::RemoteHighCoreProof => Ok(Vec::new()),
            HighCoreSwarmClassification::LocalSmallProof => Ok(vec![self.proof_gap(
                "local-small-proof",
                "local or single-node proof cannot prove high-core swarm readiness",
                ProofGapStatus::Blocked,
            )?]),
            HighCoreSwarmClassification::NonReproducibleCommand => Ok(vec![self.proof_gap(
                "non-reproducible-command",
                "proof command must require rch remote execution and refuse local fallback",
                ProofGapStatus::Missing,
            )?]),
            HighCoreSwarmClassification::InsufficientHardware => Ok(vec![self.proof_gap(
                "insufficient-hardware",
                "remote worker does not meet the required CPU or memory floor",
                ProofGapStatus::Blocked,
            )?]),
            HighCoreSwarmClassification::InsufficientScale => Ok(vec![self.proof_gap(
                "insufficient-scale",
                "scenario target connector count is below the high-core requirement",
                ProofGapStatus::Missing,
            )?]),
            HighCoreSwarmClassification::StaleHighCoreProof => Ok(vec![self.proof_gap(
                "stale-high-core-proof",
                "high-core evidence is outside the accepted freshness window",
                ProofGapStatus::Stale,
            )?]),
            HighCoreSwarmClassification::FailedRun => Ok(vec![self.proof_gap(
                "failed-run",
                "proof run failed, timed out, was cancelled, or never reached terminal success",
                ProofGapStatus::Failed,
            )?]),
            HighCoreSwarmClassification::PartialArtifactRetrieval => Ok(vec![self.proof_gap(
                "partial-artifact-retrieval",
                "remote command succeeded but required artifact retrieval was incomplete",
                ProofGapStatus::Missing,
            )?]),
            HighCoreSwarmClassification::MissingDecisionEvidence => Ok(vec![self.proof_gap(
                "missing-decision-evidence",
                "capture scheduling, admission, and backpressure decisions in the evidence bundle",
                ProofGapStatus::Missing,
            )?]),
            HighCoreSwarmClassification::QueueSloExceeded => Ok(vec![self.proof_gap(
                "queue-slo-exceeded",
                "p99 queue latency exceeds the accepted high-core swarm threshold",
                ProofGapStatus::Failed,
            )?]),
            HighCoreSwarmClassification::MemoryHeadroomTooLow => Ok(vec![self.proof_gap(
                "memory-headroom-too-low",
                "peak memory headroom is below the accepted safety threshold",
                ProofGapStatus::Failed,
            )?]),
        }
    }

    fn proof_gap(
        &self,
        suffix: &str,
        summary: &str,
        status: ProofGapStatus,
    ) -> Result<ProofGap, ProofGraphError> {
        let gap = ProofGap {
            id: ProofGapId::new(format!(
                "gap.high-core-swarm.{}.{}",
                self.scenario_id, suffix
            ))?,
            summary: summary.to_owned(),
            status,
            target_truth_source: TruthSource::MeshBacked,
        };
        gap.validate()?;
        Ok(gap)
    }

    fn suggested_actions_at(
        &self,
        now_unix_ms: u64,
        claim_id: &ClaimId,
    ) -> Result<Vec<SuggestedNextAction>, HighCoreSwarmEvidenceError> {
        let Some(debt_item) = self.proof_debt_item_at(now_unix_ms)? else {
            return Ok(Vec::new());
        };
        let action = SuggestedNextAction {
            id: debt_item.action_id,
            claim_id: claim_id.clone(),
            summary: debt_item.summary,
            rerun_command: Some(
                self.proof_command
                    .to_rerun_command(format!("rerun:high-core-swarm:{}", self.scenario_id))?,
            ),
        };
        Ok(vec![action])
    }

    fn has_decision_kind(&self, kind: SwarmControlDecisionKind) -> bool {
        self.decisions.iter().any(|decision| decision.kind == kind)
    }

    const fn reproducible_remote_command(&self) -> bool {
        matches!(self.proof_command.runner, ProofRunnerKind::Rch)
            && self.proof_command.policy.remote_required
            && !self.proof_command.policy.allow_local_fallback
    }

    const fn run_failed_or_stopped(&self) -> bool {
        matches!(
            self.run_classification,
            ProofRunClassification::RemoteFailure { .. }
                | ProofRunClassification::QueueTimeout
                | ProofRunClassification::LocalFallbackRefused
                | ProofRunClassification::LocalFailure { .. }
                | ProofRunClassification::TimedOut { .. }
                | ProofRunClassification::Cancelled
                | ProofRunClassification::Queued
                | ProofRunClassification::Incomplete
        )
    }
}

fn default_high_core_swarm_schema() -> String {
    HIGH_CORE_SWARM_EVIDENCE_SCHEMA.to_owned()
}

/// Hardware class attached to a swarm proof run.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmHardwareClass {
    /// Small local machine or developer laptop.
    LocalSmall,
    /// Remote worker below the high-core proof floor.
    RemoteStandard,
    /// Remote worker expected to satisfy the high-core proof floor.
    RemoteHighCore,
    /// Forward-compatible hardware class.
    Unknown(String),
}

impl SwarmHardwareClass {
    fn validate(&self) -> Result<(), HighCoreSwarmEvidenceError> {
        if let Self::Unknown(value) = self {
            validate_key_fragment("hardware_class.unknown", value)?;
        }
        Ok(())
    }
}

/// CPU, memory, and remote-execution topology for a proof run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmHardwareProfile {
    /// Hardware class recorded by the runner.
    pub hardware_class: SwarmHardwareClass,
    /// Logical CPU count available to the run.
    pub logical_cpus: u16,
    /// Physical core count available to the run.
    pub physical_cores: u16,
    /// Total memory available to the run, in GiB.
    pub ram_gib: u32,
    /// Number of NUMA nodes or memory domains visible to the run.
    pub numa_nodes: u16,
    /// Whether the command executed on a remote worker.
    pub remote_execution: bool,
    /// Redaction-safe worker or pool id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_id: Option<String>,
}

impl SwarmHardwareProfile {
    fn validate(&self) -> Result<(), HighCoreSwarmEvidenceError> {
        self.hardware_class.validate()?;
        if self.logical_cpus == 0 {
            return Err(HighCoreSwarmEvidenceError::InvalidCount {
                field: "logical_cpus",
            });
        }
        if self.physical_cores == 0 {
            return Err(HighCoreSwarmEvidenceError::InvalidCount {
                field: "physical_cores",
            });
        }
        if self.ram_gib == 0 {
            return Err(HighCoreSwarmEvidenceError::InvalidCount { field: "ram_gib" });
        }
        if self.numa_nodes == 0 {
            return Err(HighCoreSwarmEvidenceError::InvalidCount {
                field: "numa_nodes",
            });
        }
        if let Some(worker_id) = &self.worker_id {
            validate_key_fragment("hardware.worker_id", worker_id)?;
        }
        Ok(())
    }

    const fn meets_requirements(&self, requirements: &SwarmEvidenceRequirements) -> bool {
        self.logical_cpus >= requirements.minimum_logical_cpus
            && self.ram_gib >= requirements.minimum_ram_gib
            && matches!(self.hardware_class, SwarmHardwareClass::RemoteHighCore)
    }
}

/// Shape of the swarm workload exercised by a proof run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmScenarioShape {
    /// Workload family.
    pub scenario_kind: SwarmScenarioKind,
    /// Target number of connector instances in the swarm.
    pub target_connector_count: u32,
    /// Number of active agents driving the run.
    pub active_agent_count: u32,
    /// Total operation count requested by the scenario.
    pub requested_operation_count: u64,
    /// Run duration in milliseconds.
    pub duration_ms: u64,
}

impl SwarmScenarioShape {
    fn validate(&self) -> Result<(), HighCoreSwarmEvidenceError> {
        self.scenario_kind.validate()?;
        if self.target_connector_count == 0 {
            return Err(HighCoreSwarmEvidenceError::InvalidCount {
                field: "target_connector_count",
            });
        }
        if self.active_agent_count == 0 {
            return Err(HighCoreSwarmEvidenceError::InvalidCount {
                field: "active_agent_count",
            });
        }
        if self.requested_operation_count == 0 {
            return Err(HighCoreSwarmEvidenceError::InvalidCount {
                field: "requested_operation_count",
            });
        }
        if self.duration_ms == 0 {
            return Err(HighCoreSwarmEvidenceError::InvalidCount {
                field: "duration_ms",
            });
        }
        Ok(())
    }
}

/// Swarm benchmark family.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmScenarioKind {
    /// Connector activation and steady-state admission.
    ConnectorActivation,
    /// Multi-priority backpressure under load.
    Backpressure,
    /// Mixed connector operations under sustained load.
    MixedConnectorLoad,
    /// Forward-compatible scenario family.
    Unknown(String),
}

impl SwarmScenarioKind {
    fn validate(&self) -> Result<(), HighCoreSwarmEvidenceError> {
        if let Self::Unknown(value) = self {
            validate_key_fragment("scenario_kind.unknown", value)?;
        }
        Ok(())
    }
}

/// Requirements that gate high-core proof classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmEvidenceRequirements {
    /// Minimum logical CPUs for high-core proof.
    pub minimum_logical_cpus: u16,
    /// Minimum memory, in GiB, for high-core proof.
    pub minimum_ram_gib: u32,
    /// Minimum target connector count for high-core proof.
    pub minimum_connector_count: u32,
    /// Maximum age accepted for hardware-class proof.
    pub maximum_age_ms: u64,
    /// Maximum accepted p99 queue latency.
    pub maximum_p99_queue_latency_ms: u64,
    /// Minimum memory headroom that must remain at peak load.
    pub minimum_memory_headroom_gib: u32,
}

impl SwarmEvidenceRequirements {
    const fn validate(self) -> Result<(), HighCoreSwarmEvidenceError> {
        if self.minimum_logical_cpus == 0 {
            return Err(HighCoreSwarmEvidenceError::InvalidCount {
                field: "minimum_logical_cpus",
            });
        }
        if self.minimum_ram_gib == 0 {
            return Err(HighCoreSwarmEvidenceError::InvalidCount {
                field: "minimum_ram_gib",
            });
        }
        if self.minimum_connector_count == 0 {
            return Err(HighCoreSwarmEvidenceError::InvalidCount {
                field: "minimum_connector_count",
            });
        }
        if self.maximum_age_ms == 0 {
            return Err(HighCoreSwarmEvidenceError::InvalidCount {
                field: "maximum_age_ms",
            });
        }
        if self.maximum_p99_queue_latency_ms == 0 {
            return Err(HighCoreSwarmEvidenceError::InvalidCount {
                field: "maximum_p99_queue_latency_ms",
            });
        }
        Ok(())
    }
}

/// One scheduling, admission, or backpressure decision observed during a run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmControlDecision {
    /// Monotonic decision sequence.
    pub sequence: u32,
    /// Decision family.
    pub kind: SwarmControlDecisionKind,
    /// Redaction-safe decision summary.
    pub summary: String,
}

impl SwarmControlDecision {
    fn validate(&self) -> Result<(), HighCoreSwarmEvidenceError> {
        validate_safe_text("decision.summary", &self.summary)
    }
}

/// Decision kinds captured by the swarm adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmControlDecisionKind {
    /// Scheduler planned worker placement.
    SchedulingPlanned,
    /// Admission controller evaluated the requested swarm.
    AdmissionEvaluated,
    /// Admission controller accepted the requested swarm.
    AdmissionAccepted,
    /// Admission controller rejected part of the requested swarm.
    AdmissionRejected,
    /// Backpressure was applied and recorded.
    BackpressureApplied,
    /// Retry policy scheduled retries.
    RetryScheduled,
    /// Cancellation path was exercised.
    CancellationPropagated,
}

/// Queue latency percentiles for a swarm proof run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueLatencyPercentiles {
    /// p50 queue latency in milliseconds.
    pub p50_ms: u64,
    /// p95 queue latency in milliseconds.
    pub p95_ms: u64,
    /// p99 queue latency in milliseconds.
    pub p99_ms: u64,
    /// Maximum queue latency in milliseconds.
    pub max_ms: u64,
}

impl QueueLatencyPercentiles {
    const fn validate(self) -> Result<(), HighCoreSwarmEvidenceError> {
        if self.p50_ms > self.p95_ms || self.p95_ms > self.p99_ms || self.p99_ms > self.max_ms {
            return Err(HighCoreSwarmEvidenceError::ConflictingPercentiles {
                p50_ms: self.p50_ms,
                p95_ms: self.p95_ms,
                p99_ms: self.p99_ms,
                max_ms: self.max_ms,
            });
        }
        Ok(())
    }
}

/// Memory pressure summary for a swarm proof run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryHeadroom {
    /// Peak resident memory in GiB.
    pub peak_rss_gib: u32,
    /// Memory still available at peak, in GiB.
    pub available_headroom_gib: u32,
    /// Memory limit or machine memory, in GiB.
    pub limit_gib: u32,
}

impl MemoryHeadroom {
    const fn validate(self) -> Result<(), HighCoreSwarmEvidenceError> {
        if self.limit_gib == 0 {
            return Err(HighCoreSwarmEvidenceError::InvalidCount {
                field: "memory.limit_gib",
            });
        }
        if self.peak_rss_gib > self.limit_gib
            || self.available_headroom_gib > self.limit_gib
            || self
                .peak_rss_gib
                .saturating_add(self.available_headroom_gib)
                > self.limit_gib
        {
            return Err(HighCoreSwarmEvidenceError::InvalidMemoryHeadroom);
        }
        Ok(())
    }
}

/// Outcome counters from a swarm proof run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SwarmOutcomeCounters {
    /// Dropped operation count.
    pub dropped_count: u64,
    /// Retried operation count.
    pub retried_count: u64,
    /// Cancelled operation count.
    pub cancelled_count: u64,
    /// Failed operation count.
    pub failed_count: u64,
}

/// Operator value used when ranking proof gaps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmProofValue {
    /// User-impact score from 0 to 100.
    pub user_impact_score: u16,
    /// Reuse value score from 0 to 100.
    pub proof_reuse_score: u16,
    /// Whether a fresh proof should still be rerun opportunistically.
    pub rerun_requested: bool,
}

impl SwarmProofValue {
    const fn validate(self) -> Result<(), HighCoreSwarmEvidenceError> {
        if self.user_impact_score > 100 {
            return Err(HighCoreSwarmEvidenceError::InvalidScore {
                field: "user_impact_score",
                score: self.user_impact_score,
            });
        }
        if self.proof_reuse_score > 100 {
            return Err(HighCoreSwarmEvidenceError::InvalidScore {
                field: "proof_reuse_score",
                score: self.proof_reuse_score,
            });
        }
        Ok(())
    }
}

/// Classification derived from a high-core swarm evidence record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HighCoreSwarmClassification {
    /// Fresh remote high-core run satisfied all requirements.
    RemoteHighCoreProof,
    /// Run was local or underspecified as local/single-node evidence.
    LocalSmallProof,
    /// Remote command metadata is not reproducible as a remote-only proof.
    NonReproducibleCommand,
    /// Remote hardware did not meet the required CPU or memory floor.
    InsufficientHardware,
    /// Workload target was below the required connector count.
    InsufficientScale,
    /// High-core proof exists but is stale.
    StaleHighCoreProof,
    /// Proof runner failed, timed out, or stopped before useful success.
    FailedRun,
    /// Remote command succeeded but artifacts were not fully retrieved.
    PartialArtifactRetrieval,
    /// Evidence is missing scheduling, admission, or backpressure decisions.
    MissingDecisionEvidence,
    /// Queue latency exceeded the scenario threshold.
    QueueSloExceeded,
    /// Memory headroom was below the safety threshold.
    MemoryHeadroomTooLow,
}

impl HighCoreSwarmClassification {
    /// Stable classification label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RemoteHighCoreProof => "remote_high_core_proof",
            Self::LocalSmallProof => "local_small_proof",
            Self::NonReproducibleCommand => "non_reproducible_command",
            Self::InsufficientHardware => "insufficient_hardware",
            Self::InsufficientScale => "insufficient_scale",
            Self::StaleHighCoreProof => "stale_high_core_proof",
            Self::FailedRun => "failed_run",
            Self::PartialArtifactRetrieval => "partial_artifact_retrieval",
            Self::MissingDecisionEvidence => "missing_decision_evidence",
            Self::QueueSloExceeded => "queue_slo_exceeded",
            Self::MemoryHeadroomTooLow => "memory_headroom_too_low",
        }
    }

    fn claim_status(self, stale_at_unix_ms: u64) -> ClaimStatus {
        match self {
            Self::RemoteHighCoreProof => ClaimStatus::Proven,
            Self::StaleHighCoreProof => ClaimStatus::Stale { stale_at_unix_ms },
            Self::FailedRun => ClaimStatus::Failed {
                reason: "high-core swarm proof run did not complete successfully".to_owned(),
            },
            Self::QueueSloExceeded => ClaimStatus::Failed {
                reason: "p99 queue latency exceeded the accepted threshold".to_owned(),
            },
            Self::MemoryHeadroomTooLow => ClaimStatus::Failed {
                reason: "memory headroom fell below the accepted threshold".to_owned(),
            },
            Self::LocalSmallProof | Self::InsufficientHardware => ClaimStatus::SkippedWithReason {
                reason: "evidence is below the required high-core hardware class".to_owned(),
            },
            Self::NonReproducibleCommand
            | Self::InsufficientScale
            | Self::PartialArtifactRetrieval
            | Self::MissingDecisionEvidence => ClaimStatus::Missing,
        }
    }

    const fn support_relationship(self) -> SupportRelationship {
        match self {
            Self::RemoteHighCoreProof => SupportRelationship::Supports,
            Self::FailedRun | Self::QueueSloExceeded | Self::MemoryHeadroomTooLow => {
                SupportRelationship::Contradicts
            }
            Self::LocalSmallProof
            | Self::NonReproducibleCommand
            | Self::InsufficientHardware
            | Self::InsufficientScale
            | Self::StaleHighCoreProof
            | Self::PartialArtifactRetrieval
            | Self::MissingDecisionEvidence => SupportRelationship::PartiallySupports,
        }
    }

    const fn truth_source(self, remote_execution: bool) -> TruthSource {
        match self {
            Self::LocalSmallProof if !remote_execution => TruthSource::NodeLocal,
            Self::LocalSmallProof | Self::InsufficientHardware => TruthSource::HostBacked,
            Self::RemoteHighCoreProof
            | Self::NonReproducibleCommand
            | Self::InsufficientScale
            | Self::StaleHighCoreProof
            | Self::FailedRun
            | Self::PartialArtifactRetrieval
            | Self::MissingDecisionEvidence
            | Self::QueueSloExceeded
            | Self::MemoryHeadroomTooLow => TruthSource::MeshBacked,
        }
    }

    const fn evidence_kind(self, remote_execution: bool) -> EvidenceKind {
        match self {
            Self::LocalSmallProof if !remote_execution => EvidenceKind::NodeLocalRun,
            Self::LocalSmallProof | Self::InsufficientHardware => EvidenceKind::HostIntegration,
            Self::RemoteHighCoreProof
            | Self::NonReproducibleCommand
            | Self::InsufficientScale
            | Self::StaleHighCoreProof
            | Self::FailedRun
            | Self::PartialArtifactRetrieval
            | Self::MissingDecisionEvidence
            | Self::QueueSloExceeded
            | Self::MemoryHeadroomTooLow => EvidenceKind::MeshExecution,
        }
    }

    fn summary(self, scenario_id: &str) -> String {
        match self {
            Self::RemoteHighCoreProof => {
                format!("high-core swarm scenario {scenario_id} satisfied remote proof thresholds")
            }
            Self::LocalSmallProof => {
                format!("swarm scenario {scenario_id} is only local or small-host evidence")
            }
            Self::NonReproducibleCommand => {
                format!("swarm scenario {scenario_id} lacks a reproducible remote-only command")
            }
            Self::InsufficientHardware => {
                format!("swarm scenario {scenario_id} ran on undersized remote hardware")
            }
            Self::InsufficientScale => {
                format!("swarm scenario {scenario_id} did not exercise enough connectors")
            }
            Self::StaleHighCoreProof => {
                format!("high-core swarm scenario {scenario_id} is stale")
            }
            Self::FailedRun => {
                format!("high-core swarm scenario {scenario_id} failed or stopped")
            }
            Self::PartialArtifactRetrieval => {
                format!("high-core swarm scenario {scenario_id} has incomplete artifact retrieval")
            }
            Self::MissingDecisionEvidence => format!(
                "high-core swarm scenario {scenario_id} lacks scheduling admission or backpressure evidence"
            ),
            Self::QueueSloExceeded => {
                format!("high-core swarm scenario {scenario_id} exceeded p99 queue latency")
            }
            Self::MemoryHeadroomTooLow => {
                format!("high-core swarm scenario {scenario_id} exhausted memory headroom")
            }
        }
    }

    const fn edge_rationale(self) -> &'static str {
        match self {
            Self::RemoteHighCoreProof => {
                "Remote high-core run met hardware, scale, latency, memory, and reproducibility thresholds"
            }
            Self::LocalSmallProof => {
                "Local or small-host proof cannot prove high-core swarm readiness"
            }
            Self::NonReproducibleCommand => {
                "Command metadata does not force remote-only reproducible execution"
            }
            Self::InsufficientHardware => {
                "Remote worker did not meet the required CPU or memory floor"
            }
            Self::InsufficientScale => "Scenario target connector count was below the proof floor",
            Self::StaleHighCoreProof => {
                "High-core evidence is outside the hardware-class freshness window"
            }
            Self::FailedRun => "Proof runner did not produce a successful terminal run",
            Self::PartialArtifactRetrieval => {
                "Remote command succeeded but required evidence artifacts were incomplete"
            }
            Self::MissingDecisionEvidence => {
                "Evidence is missing scheduling, admission, or backpressure decisions"
            }
            Self::QueueSloExceeded => "p99 queue latency exceeded the accepted threshold",
            Self::MemoryHeadroomTooLow => "Peak run did not retain required memory headroom",
        }
    }
}

/// Derived operator-facing analysis for swarm evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HighCoreSwarmAnalysis {
    /// Classification derived from the record.
    pub classification: HighCoreSwarmClassification,
    /// `ProofGraph` claim status.
    pub claim_status: ClaimStatus,
    /// Relationship between the evidence and claim.
    pub relationship: SupportRelationship,
    /// Truth source represented by the evidence.
    pub truth_source: TruthSource,
    /// Evidence kind represented by the evidence.
    pub evidence_kind: EvidenceKind,
    /// Gaps that prevent stronger proof.
    pub proof_gaps: Vec<ProofGap>,
    /// Redaction-safe summary.
    pub summary: String,
}

/// JSONL-ready decision row emitted from high-core swarm evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HighCoreSwarmJsonlEvent {
    /// Schema identifier.
    pub schema: String,
    /// Scenario id.
    pub scenario_id: String,
    /// Unix millisecond observation time.
    pub observed_at_unix_ms: u64,
    /// Decision sequence.
    pub event_sequence: u32,
    /// Hardware class.
    pub hardware_class: SwarmHardwareClass,
    /// Logical CPU count.
    pub logical_cpus: u16,
    /// Physical core count.
    pub physical_cores: u16,
    /// Memory in GiB.
    pub ram_gib: u32,
    /// Target connector count.
    pub target_connector_count: u32,
    /// Active agent count.
    pub active_agent_count: u32,
    /// Decision kind.
    pub decision_kind: SwarmControlDecisionKind,
    /// p99 queue latency in milliseconds.
    pub queue_p99_ms: u64,
    /// Remaining memory headroom in GiB.
    pub memory_headroom_gib: u32,
    /// Dropped operation count.
    pub dropped_count: u64,
    /// Retried operation count.
    pub retried_count: u64,
    /// Cancelled operation count.
    pub cancelled_count: u64,
    /// Failed operation count.
    pub failed_count: u64,
    /// Proof-runner classification.
    pub run_classification: ProofRunClassification,
    /// Swarm evidence classification.
    pub swarm_classification: HighCoreSwarmClassification,
    /// Redaction-safe decision summary.
    pub summary: String,
}

/// Proof-debt kind used by high-core swarm ranking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmProofDebtKind {
    /// No evidence exists for an expected scenario.
    Missing,
    /// Evidence is stale.
    Stale,
    /// Last evidence failed or contradicted the claim.
    Failed,
    /// Evidence is blocked by environment or hardware class.
    Blocked,
    /// Evidence is incomplete but not known failed.
    Incomplete,
    /// Fresh proof exists, but an optional rerun was requested.
    OptionalRerun,
}

impl SwarmProofDebtKind {
    const fn from_classification(
        classification: HighCoreSwarmClassification,
        rerun_requested: bool,
    ) -> Self {
        match classification {
            HighCoreSwarmClassification::RemoteHighCoreProof if rerun_requested => {
                Self::OptionalRerun
            }
            HighCoreSwarmClassification::RemoteHighCoreProof => Self::OptionalRerun,
            HighCoreSwarmClassification::StaleHighCoreProof => Self::Stale,
            HighCoreSwarmClassification::FailedRun
            | HighCoreSwarmClassification::QueueSloExceeded
            | HighCoreSwarmClassification::MemoryHeadroomTooLow => Self::Failed,
            HighCoreSwarmClassification::LocalSmallProof
            | HighCoreSwarmClassification::InsufficientHardware => Self::Blocked,
            HighCoreSwarmClassification::NonReproducibleCommand
            | HighCoreSwarmClassification::InsufficientScale
            | HighCoreSwarmClassification::PartialArtifactRetrieval
            | HighCoreSwarmClassification::MissingDecisionEvidence => Self::Incomplete,
        }
    }

    const fn base_score(self) -> u32 {
        match self {
            Self::Failed => 9_000,
            Self::Missing => 8_500,
            Self::Stale => 8_000,
            Self::Incomplete => 7_000,
            Self::Blocked => 6_000,
            Self::OptionalRerun => 1_000,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Stale => "stale",
            Self::Failed => "failed",
            Self::Blocked => "blocked",
            Self::Incomplete => "incomplete",
            Self::OptionalRerun => "optional-rerun",
        }
    }
}

/// Ranked proof-debt item for high-core swarm evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmProofDebtItem {
    /// Suggested action id for the debt item.
    pub action_id: SuggestedActionId,
    /// Claim this item improves.
    pub claim_id: ClaimId,
    /// Scenario id.
    pub scenario_id: String,
    /// Debt kind.
    pub kind: SwarmProofDebtKind,
    /// Redaction-safe summary.
    pub summary: String,
    /// User-impact score from 0 to 100.
    pub user_impact_score: u16,
    /// Reuse score from 0 to 100.
    pub proof_reuse_score: u16,
    /// Higher values should be addressed first.
    pub rank_score: u32,
}

impl SwarmProofDebtItem {
    /// Build a missing-evidence ranking item for an expected scenario.
    ///
    /// # Errors
    ///
    /// Returns [`HighCoreSwarmEvidenceError`] if ids, scores, or summaries are
    /// not graph-safe.
    pub fn missing(
        scenario_id: impl Into<String>,
        claim_id: ClaimId,
        summary: impl Into<String>,
        user_impact_score: u16,
        proof_reuse_score: u16,
    ) -> Result<Self, HighCoreSwarmEvidenceError> {
        Self::new(
            scenario_id,
            claim_id,
            SwarmProofDebtKind::Missing,
            summary,
            user_impact_score,
            proof_reuse_score,
        )
    }

    fn new(
        scenario_id: impl Into<String>,
        claim_id: ClaimId,
        kind: SwarmProofDebtKind,
        summary: impl Into<String>,
        user_impact_score: u16,
        proof_reuse_score: u16,
    ) -> Result<Self, HighCoreSwarmEvidenceError> {
        let scenario_id = scenario_id.into();
        let summary = summary.into();
        validate_key_fragment("debt.scenario_id", &scenario_id)?;
        validate_safe_text("debt.summary", &summary)?;
        SwarmProofValue {
            user_impact_score,
            proof_reuse_score,
            rerun_requested: false,
        }
        .validate()?;
        let action_id = SuggestedActionId::new(format!(
            "action.high-core-swarm.{scenario_id}.{}",
            kind.as_str()
        ))?;
        let rank_score =
            kind.base_score() + (u32::from(user_impact_score) * 10) + u32::from(proof_reuse_score);
        Ok(Self {
            action_id,
            claim_id,
            scenario_id,
            kind,
            summary,
            user_impact_score,
            proof_reuse_score,
            rank_score,
        })
    }
}

/// Sort high-core swarm proof debt by operator value and severity.
#[must_use]
pub fn rank_swarm_proof_debt(mut items: Vec<SwarmProofDebtItem>) -> Vec<SwarmProofDebtItem> {
    items.sort_by(|left, right| {
        right
            .rank_score
            .cmp(&left.rank_score)
            .then_with(|| left.scenario_id.cmp(&right.scenario_id))
            .then_with(|| left.action_id.cmp(&right.action_id))
    });
    items
}

/// Errors produced by the high-core swarm evidence adapter.
#[derive(Debug, Error)]
pub enum HighCoreSwarmEvidenceError {
    /// Record schema was not recognized.
    #[error("invalid high-core swarm evidence schema: expected {expected}, got {actual}")]
    InvalidSchema {
        /// Expected schema identifier.
        expected: &'static str,
        /// Actual schema identifier.
        actual: String,
    },
    /// No control decisions were recorded.
    #[error("high-core swarm evidence must include control decisions")]
    NoDecisions,
    /// Numeric count field was invalid.
    #[error("{field} must be greater than zero")]
    InvalidCount {
        /// Field name.
        field: &'static str,
    },
    /// Score was outside the accepted range.
    #[error("{field} score {score} must be between 0 and 100")]
    InvalidScore {
        /// Field name.
        field: &'static str,
        /// Invalid score.
        score: u16,
    },
    /// Duplicate decision sequence found.
    #[error("duplicate swarm control decision sequence {sequence}")]
    DuplicateDecisionSequence {
        /// Duplicate sequence.
        sequence: u32,
    },
    /// Decision sequence was not strictly increasing.
    #[error("decision sequence must increase: previous {previous}, current {current}")]
    NonMonotonicDecisionSequence {
        /// Previous sequence.
        previous: u32,
        /// Current sequence.
        current: u32,
    },
    /// Percentiles were not monotonically ordered.
    #[error(
        "conflicting latency percentiles: p50={p50_ms}, p95={p95_ms}, p99={p99_ms}, max={max_ms}"
    )]
    ConflictingPercentiles {
        /// p50 queue latency.
        p50_ms: u64,
        /// p95 queue latency.
        p95_ms: u64,
        /// p99 queue latency.
        p99_ms: u64,
        /// Maximum queue latency.
        max_ms: u64,
    },
    /// Memory fields were internally inconsistent.
    #[error("invalid memory headroom: peak plus headroom must fit within the limit")]
    InvalidMemoryHeadroom,
    /// Text or identifier was unsafe for graph storage.
    #[error("unsafe {field}: {reason}")]
    UnsafeText {
        /// Field name.
        field: &'static str,
        /// Reason text.
        reason: &'static str,
    },
    /// Redaction class is not safe for graph storage.
    #[error("high-core swarm evidence carries graph-unsafe redaction class {redaction_class:?}")]
    UnsafeRedactionClass {
        /// Unsafe redaction class.
        redaction_class: RedactionClass,
    },
    /// `ProofGraph` validation failed.
    #[error(transparent)]
    Graph(#[from] ProofGraphError),
    /// Proof-runner validation failed.
    #[error(transparent)]
    ProofRun(#[from] crate::ProofRunError),
    /// JSON serialization failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

fn validate_key_fragment(
    field: &'static str,
    value: &str,
) -> Result<(), HighCoreSwarmEvidenceError> {
    validate_safe_text(field, value)?;
    if value.len() > MAX_KEY_FRAGMENT_LEN {
        return Err(HighCoreSwarmEvidenceError::UnsafeText {
            field,
            reason: "identifier is too long",
        });
    }
    if value.trim() != value || value.chars().any(char::is_whitespace) {
        return Err(HighCoreSwarmEvidenceError::UnsafeText {
            field,
            reason: "identifier must not contain whitespace",
        });
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':'))
    {
        return Err(HighCoreSwarmEvidenceError::UnsafeText {
            field,
            reason: "identifier contains unsupported characters",
        });
    }
    Ok(())
}

fn validate_safe_text(field: &'static str, value: &str) -> Result<(), HighCoreSwarmEvidenceError> {
    if value.trim().is_empty() {
        return Err(HighCoreSwarmEvidenceError::UnsafeText {
            field,
            reason: "empty text",
        });
    }
    if value.contains("://") {
        return Err(HighCoreSwarmEvidenceError::UnsafeText {
            field,
            reason: "raw endpoints must be replaced with artifact ids",
        });
    }
    if looks_like_secret(value) {
        return Err(HighCoreSwarmEvidenceError::UnsafeText {
            field,
            reason: "raw secret-like text is not allowed",
        });
    }
    Ok(())
}

fn validate_digest(field: &'static str, value: &str) -> Result<(), HighCoreSwarmEvidenceError> {
    validate_safe_text(field, value)?;
    let Some((algorithm, digest)) = value.split_once(':') else {
        return Err(HighCoreSwarmEvidenceError::UnsafeText {
            field,
            reason: "digest must be algorithm-prefixed",
        });
    };
    validate_key_fragment("digest.algorithm", algorithm)?;
    if digest.len() < 16 || !digest.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(HighCoreSwarmEvidenceError::UnsafeText {
            field,
            reason: "digest must be hex with at least 16 nybbles",
        });
    }
    Ok(())
}

fn looks_like_secret(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("authorization:")
        || lower.contains("bearer ")
        || lower.contains("token=")
        || lower.contains("password=")
        || lower.contains("secret=")
        || lower.contains("api_key=")
        || lower.contains("apikey=")
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use crate::proof_runner::{
        CargoProofInvocation, ProofRunPolicy, RedactedEnvValue, TargetDirPolicy,
    };

    use super::*;

    const NOW: u64 = 1_800_000_000_000;
    const DAY_MS: u64 = 86_400_000;

    fn remote_command() -> ProofCommandSpec {
        ProofCommandSpec {
            runner: ProofRunnerKind::Rch,
            argv: vec![
                "rch".to_owned(),
                "exec".to_owned(),
                "--".to_owned(),
                "cargo".to_owned(),
                "test".to_owned(),
                "-p".to_owned(),
                "fcp-mesh".to_owned(),
                "backpressure_concurrent_multi_priority_real_load".to_owned(),
            ],
            working_directory: ".".to_owned(),
            git_revision: Some("main".to_owned()),
            target_dir_policy: TargetDirPolicy::Explicit {
                path: "/tmp/fcp-swarm-proof".to_owned(),
            },
            cargo: Some(CargoProofInvocation {
                subcommand: "test".to_owned(),
                package: Some("fcp-mesh".to_owned()),
                target_filters: BTreeSet::from([
                    "backpressure_concurrent_multi_priority_real_load".to_owned(),
                ]),
                features: BTreeSet::new(),
                all_targets: false,
                all_features: false,
                trailing_args: Vec::new(),
            }),
            env: BTreeMap::from([(
                "CARGO_BUILD_JOBS".to_owned(),
                RedactedEnvValue::PublicLiteral {
                    value: "1".to_owned(),
                },
            )]),
            required_env_keys: BTreeSet::from(["RCH_REQUIRE_REMOTE".to_owned()]),
            worker_affinity: None,
            policy: ProofRunPolicy::remote_only(30 * 60 * 1_000),
        }
    }

    fn local_command() -> ProofCommandSpec {
        let mut command = remote_command();
        command.runner = ProofRunnerKind::LocalShell;
        command.argv = vec![
            "cargo".to_owned(),
            "test".to_owned(),
            "-p".to_owned(),
            "fcp-mesh".to_owned(),
            "local_fixture".to_owned(),
        ];
        command.target_dir_policy = TargetDirPolicy::Explicit {
            path: "/tmp/fcp-swarm-local-proof".to_owned(),
        };
        command.policy = ProofRunPolicy {
            remote_required: false,
            allow_local_fallback: true,
            queue_timeout_ms: 1_000,
            command_timeout_ms: 60_000,
            artifact_retrieval_required: false,
        };
        command
    }

    fn decision(
        sequence: u32,
        kind: SwarmControlDecisionKind,
        summary: &str,
    ) -> SwarmControlDecision {
        SwarmControlDecision {
            sequence,
            kind,
            summary: summary.to_owned(),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn high_core_record() -> HighCoreSwarmEvidenceRecord {
        HighCoreSwarmEvidenceRecord {
            schema: HIGH_CORE_SWARM_EVIDENCE_SCHEMA.to_owned(),
            scenario_id: "massive-swarm-4096".to_owned(),
            owner_bead_id: "flywheel_connectors-b88ec.7".to_owned(),
            owner_agent: Some("Codex".to_owned()),
            observed_at_unix_ms: NOW,
            valid_for_ms: DAY_MS,
            requirements: SwarmEvidenceRequirements {
                minimum_logical_cpus: 64,
                minimum_ram_gib: 256,
                minimum_connector_count: 4_096,
                maximum_age_ms: DAY_MS,
                maximum_p99_queue_latency_ms: 250,
                minimum_memory_headroom_gib: 64,
            },
            hardware: SwarmHardwareProfile {
                hardware_class: SwarmHardwareClass::RemoteHighCore,
                logical_cpus: 96,
                physical_cores: 64,
                ram_gib: 512,
                numa_nodes: 2,
                remote_execution: true,
                worker_id: Some("rch-highcore-a".to_owned()),
            },
            scenario: SwarmScenarioShape {
                scenario_kind: SwarmScenarioKind::Backpressure,
                target_connector_count: 4_096,
                active_agent_count: 512,
                requested_operation_count: 2_000_000,
                duration_ms: 180_000,
            },
            decisions: vec![
                decision(
                    1,
                    SwarmControlDecisionKind::SchedulingPlanned,
                    "scheduler placed shards across high-core worker pool",
                ),
                decision(
                    2,
                    SwarmControlDecisionKind::AdmissionEvaluated,
                    "admission evaluated connector and operation budgets",
                ),
                decision(
                    3,
                    SwarmControlDecisionKind::AdmissionAccepted,
                    "admission accepted requested high-core swarm",
                ),
                decision(
                    4,
                    SwarmControlDecisionKind::BackpressureApplied,
                    "backpressure maintained bounded queue latency",
                ),
            ],
            queue_latency: QueueLatencyPercentiles {
                p50_ms: 12,
                p95_ms: 88,
                p99_ms: 144,
                max_ms: 210,
            },
            memory: MemoryHeadroom {
                peak_rss_gib: 192,
                available_headroom_gib: 128,
                limit_gib: 512,
            },
            outcomes: SwarmOutcomeCounters {
                dropped_count: 0,
                retried_count: 32,
                cancelled_count: 4,
                failed_count: 0,
            },
            run_classification: ProofRunClassification::RemoteSuccess,
            proof_command: remote_command(),
            source_ref: "artifacts:swarm:massive-swarm-4096".to_owned(),
            artifact_digest: None,
            redaction_class: RedactionClass::Internal,
            proof_value: SwarmProofValue {
                user_impact_score: 95,
                proof_reuse_score: 90,
                rerun_requested: false,
            },
        }
    }

    #[test]
    fn remote_high_core_record_builds_supporting_proof_graph() {
        let record = high_core_record();
        let analysis = record.analyze_at(NOW).expect("analyze high-core record");

        assert_eq!(
            analysis.classification,
            HighCoreSwarmClassification::RemoteHighCoreProof
        );
        assert_eq!(analysis.relationship, SupportRelationship::Supports);
        assert_eq!(analysis.truth_source, TruthSource::MeshBacked);
        assert!(analysis.proof_gaps.is_empty());

        let graph = record.to_proof_graph_at(NOW).expect("graph builds");
        graph.validate().expect("graph validates");
        let claim = graph
            .claims
            .get(&ClaimId::new("claim.high-core-swarm.massive-swarm-4096").expect("valid claim id"))
            .expect("claim present");
        assert_eq!(claim.status, ClaimStatus::Proven);
        let evidence = graph
            .evidence
            .get(
                &EvidenceId::new("evidence.high-core-swarm.massive-swarm-4096.run")
                    .expect("valid evidence id"),
            )
            .expect("evidence present");
        assert!(
            evidence
                .rerun_command
                .as_ref()
                .expect("rerun command")
                .requires_rch
        );
    }

    #[test]
    fn local_small_record_never_proves_high_core_readiness() {
        let mut record = high_core_record();
        record.scenario_id = "local-small".to_owned();
        record.hardware = SwarmHardwareProfile {
            hardware_class: SwarmHardwareClass::LocalSmall,
            logical_cpus: 8,
            physical_cores: 8,
            ram_gib: 32,
            numa_nodes: 1,
            remote_execution: false,
            worker_id: None,
        };
        record.scenario.target_connector_count = 256;
        record.run_classification = ProofRunClassification::LocalFallback;
        record.proof_command = local_command();

        let analysis = record.analyze_at(NOW).expect("local record analyzes");

        assert_eq!(
            analysis.classification,
            HighCoreSwarmClassification::LocalSmallProof
        );
        assert_eq!(analysis.truth_source, TruthSource::NodeLocal);
        assert_eq!(
            analysis.relationship,
            SupportRelationship::PartiallySupports
        );
        assert_eq!(analysis.proof_gaps[0].status, ProofGapStatus::Blocked);
        assert!(matches!(
            analysis.claim_status,
            ClaimStatus::SkippedWithReason { .. }
        ));
    }

    #[test]
    fn stale_high_core_record_is_not_current_proof() {
        let record = high_core_record();
        let analysis = record
            .analyze_at(NOW + DAY_MS + 1)
            .expect("stale record analyzes");

        assert_eq!(
            analysis.classification,
            HighCoreSwarmClassification::StaleHighCoreProof
        );
        assert!(matches!(analysis.claim_status, ClaimStatus::Stale { .. }));
        assert_eq!(analysis.proof_gaps[0].status, ProofGapStatus::Stale);
    }

    #[test]
    fn failed_remote_run_contradicts_readiness() {
        let mut record = high_core_record();
        record.scenario_id = "failed-run".to_owned();
        record.run_classification = ProofRunClassification::RemoteFailure { exit_code: 101 };

        let graph = record.to_proof_graph_at(NOW).expect("graph builds");
        let edge = graph.support_edges.first().expect("edge present");
        let claim = graph
            .claims
            .get(&ClaimId::new("claim.high-core-swarm.failed-run").expect("valid claim id"))
            .expect("claim present");

        assert_eq!(edge.relationship, SupportRelationship::Contradicts);
        assert!(matches!(claim.status, ClaimStatus::Failed { .. }));
        assert_eq!(claim.proof_gaps[0].status, ProofGapStatus::Failed);
    }

    #[test]
    fn partial_artifact_retrieval_after_success_is_named_gap() {
        let mut record = high_core_record();
        record.scenario_id = "partial-artifacts".to_owned();
        record.run_classification = ProofRunClassification::RetrievalFailedAfterSuccess;

        let analysis = record.analyze_at(NOW).expect("partial record analyzes");

        assert_eq!(
            analysis.classification,
            HighCoreSwarmClassification::PartialArtifactRetrieval
        );
        assert_eq!(
            analysis.relationship,
            SupportRelationship::PartiallySupports
        );
        assert_eq!(analysis.proof_gaps[0].status, ProofGapStatus::Missing);
        assert_eq!(
            analysis.proof_gaps[0].id,
            ProofGapId::new("gap.high-core-swarm.partial-artifacts.partial-artifact-retrieval")
                .expect("valid gap id")
        );
    }

    #[test]
    fn conflicting_percentile_claims_are_rejected() {
        let mut record = high_core_record();
        record.queue_latency = QueueLatencyPercentiles {
            p50_ms: 90,
            p95_ms: 80,
            p99_ms: 100,
            max_ms: 120,
        };

        let err = record
            .validate()
            .expect_err("conflicting percentile claims rejected");

        assert!(matches!(
            err,
            HighCoreSwarmEvidenceError::ConflictingPercentiles { .. }
        ));
    }

    #[test]
    fn jsonl_events_are_deterministic_and_redaction_safe() {
        let record = high_core_record();
        let events = record.to_jsonl_events_at(NOW).expect("jsonl events");
        let first = serde_json::to_string(&events[0]).expect("serialize event");

        assert_eq!(events.len(), 4);
        assert_eq!(
            first,
            r#"{"schema":"fcp.high-core-swarm-evidence.v1","scenario_id":"massive-swarm-4096","observed_at_unix_ms":1800000000000,"event_sequence":1,"hardware_class":"remote_high_core","logical_cpus":96,"physical_cores":64,"ram_gib":512,"target_connector_count":4096,"active_agent_count":512,"decision_kind":"scheduling_planned","queue_p99_ms":144,"memory_headroom_gib":128,"dropped_count":0,"retried_count":32,"cancelled_count":4,"failed_count":0,"run_classification":{"state":"remote_success"},"swarm_classification":"remote_high_core_proof","summary":"scheduler placed shards across high-core worker pool"}"#
        );
        let joined = events
            .iter()
            .map(|event| serde_json::to_string(event).expect("serialize event"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!joined.contains("://"));
        assert!(!looks_like_secret(&joined));
    }

    #[test]
    fn proof_debt_ranking_prioritizes_high_impact_missing_over_low_value_rerun() {
        let mut stale = high_core_record();
        stale.scenario_id = "stale-important".to_owned();
        stale.proof_value = SwarmProofValue {
            user_impact_score: 90,
            proof_reuse_score: 90,
            rerun_requested: false,
        };
        let stale_item = stale
            .proof_debt_item_at(NOW + DAY_MS + 1)
            .expect("debt item")
            .expect("stale debt");

        let missing_item = SwarmProofDebtItem::missing(
            "missing-critical",
            ClaimId::new("claim.high-core-swarm.missing-critical").expect("valid claim id"),
            "collect missing high-core swarm proof",
            100,
            95,
        )
        .expect("missing item");

        let mut optional = high_core_record();
        optional.scenario_id = "low-value-rerun".to_owned();
        optional.proof_value = SwarmProofValue {
            user_impact_score: 1,
            proof_reuse_score: 1,
            rerun_requested: true,
        };
        let optional_item = optional
            .proof_debt_item_at(NOW)
            .expect("debt item")
            .expect("optional rerun debt");

        let ranked = rank_swarm_proof_debt(vec![optional_item, stale_item, missing_item]);

        assert_eq!(ranked[0].scenario_id, "missing-critical");
        assert_eq!(ranked[1].scenario_id, "stale-important");
        assert_eq!(ranked[2].scenario_id, "low-value-rerun");
        assert_eq!(ranked[2].kind, SwarmProofDebtKind::OptionalRerun);
    }

    #[test]
    fn unsafe_endpoint_or_secret_text_is_rejected() {
        let mut record = high_core_record();
        record.source_ref = "https://perf.example.test/raw".to_owned();
        let err = record
            .validate()
            .expect_err("raw endpoint source ref rejected");
        assert!(matches!(err, HighCoreSwarmEvidenceError::UnsafeText { .. }));

        let mut record = high_core_record();
        record.decisions[0].summary = "bearer token leaked".to_owned();
        let err = record
            .validate()
            .expect_err("secret-like decision summary rejected");
        assert!(matches!(err, HighCoreSwarmEvidenceError::UnsafeText { .. }));
    }
}
