//! Mesh failover flight-recorder adapter for `ProofGraph`.
//!
//! This module does not implement mesh cutover. It records redaction-safe
//! timelines from mesh drills and classifies the evidence so operators can see
//! whether a failover claim is proven, downgraded, incomplete, or contradicted.

#![allow(clippy::module_name_repetitions)]

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::proof_graph::{
    BeadOwner, ClaimId, ClaimNode, ClaimStatus, EvidenceId, EvidenceKind, EvidenceNode,
    FreshnessWindow, ProofGap, ProofGapId, ProofGapStatus, ProofGraph, ProofGraphError,
    RedactionClass, SuggestedNextAction, SupportEdge, SupportRelationship, TruthSource,
};

/// Stable schema for mesh failover flight-recorder JSONL event records.
pub const MESH_FAILOVER_RECORDER_EVENT_SCHEMA: &str = "fcp.mesh-failover-flight-recorder.v1";

const MAX_KEY_FRAGMENT_LEN: usize = 96;

/// Redaction-safe mesh failover evidence captured from a drill or fixture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshFailoverFlightRecord {
    /// Schema identifier; must be [`MESH_FAILOVER_RECORDER_EVENT_SCHEMA`].
    #[serde(default = "default_mesh_failover_schema")]
    pub schema: String,
    /// Stable scenario id used in graph node ids.
    pub scenario_id: String,
    /// Connector id or fixture connector id under failover.
    pub connector_id: String,
    /// Bead that owns the scenario claim.
    pub owner_bead_id: String,
    /// Optional agent currently responsible for this scenario.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_agent: Option<String>,
    /// Unix millisecond timestamp when the timeline was observed.
    pub observed_at_unix_ms: u64,
    /// Freshness window for this failover proof.
    pub valid_for_ms: u64,
    /// Minimum distinct nodes required before the evidence can be mesh-backed.
    pub required_node_count: usize,
    /// Nodes that participated in the timeline.
    #[serde(default)]
    pub participating_nodes: BTreeSet<String>,
    /// Primary node before failover.
    pub primary_before: String,
    /// Primary node after failover, if failover reached a new owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_after: Option<String>,
    /// State root before failover, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_root_before: Option<MeshStateRootRef>,
    /// State root after replay, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_root_after: Option<MeshStateRootRef>,
    /// Redaction-safe source reference such as a fixture id or artifact path.
    pub source_ref: String,
    /// Optional digest for the external evidence bundle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_digest: Option<String>,
    /// Redaction class for graph fields derived from this record.
    pub redaction_class: RedactionClass,
    /// Ordered timeline events.
    pub events: Vec<MeshFailoverEvent>,
}

impl MeshFailoverFlightRecord {
    /// Validate the flight record and all nested redaction-safe fields.
    ///
    /// # Errors
    ///
    /// Returns [`MeshFailoverRecordError`] when required fields are missing,
    /// event ordering is invalid, a participant reference is unknown, or graph
    /// validation rejects derived metadata.
    pub fn validate(&self) -> Result<(), MeshFailoverRecordError> {
        if self.schema != MESH_FAILOVER_RECORDER_EVENT_SCHEMA {
            return Err(MeshFailoverRecordError::InvalidSchema {
                expected: MESH_FAILOVER_RECORDER_EVENT_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        validate_key_fragment("scenario_id", &self.scenario_id)?;
        validate_key_fragment("connector_id", &self.connector_id)?;
        validate_key_fragment("owner_bead_id", &self.owner_bead_id)?;
        if let Some(owner_agent) = &self.owner_agent {
            validate_key_fragment("owner_agent", owner_agent)?;
        }
        if self.required_node_count == 0 {
            return Err(MeshFailoverRecordError::InvalidCount {
                field: "required_node_count",
            });
        }
        if self.participating_nodes.is_empty() {
            return Err(MeshFailoverRecordError::MissingParticipants);
        }
        for node_id in &self.participating_nodes {
            validate_key_fragment("participating_node", node_id)?;
        }
        validate_known_node(
            "primary_before",
            &self.primary_before,
            &self.participating_nodes,
        )?;
        if let Some(primary_after) = &self.primary_after {
            validate_known_node("primary_after", primary_after, &self.participating_nodes)?;
        }
        if let Some(state_root_before) = &self.state_root_before {
            state_root_before.validate()?;
        }
        if let Some(state_root_after) = &self.state_root_after {
            state_root_after.validate()?;
        }
        validate_safe_text("source_ref", &self.source_ref)?;
        if let Some(artifact_digest) = &self.artifact_digest {
            validate_digest("artifact_digest", artifact_digest)?;
        }
        if !self.redaction_class.is_graph_safe() {
            return Err(MeshFailoverRecordError::UnsafeRedactionClass {
                redaction_class: self.redaction_class,
            });
        }
        if self.events.is_empty() {
            return Err(MeshFailoverRecordError::NoEvents);
        }

        let mut seen_sequences = BTreeSet::new();
        let mut previous_sequence = None;
        let mut previous_observed_at = None;
        for event in &self.events {
            event.validate(&self.participating_nodes)?;
            if !seen_sequences.insert(event.sequence) {
                return Err(MeshFailoverRecordError::DuplicateEventSequence {
                    sequence: event.sequence,
                });
            }
            if let Some(previous) = previous_sequence
                && event.sequence <= previous
            {
                return Err(MeshFailoverRecordError::NonMonotonicEventSequence {
                    previous,
                    current: event.sequence,
                });
            }
            if let Some(previous) = previous_observed_at
                && event.observed_at_unix_ms < previous
            {
                return Err(MeshFailoverRecordError::NonMonotonicEventTimestamp {
                    previous,
                    current: event.observed_at_unix_ms,
                });
            }
            previous_sequence = Some(event.sequence);
            previous_observed_at = Some(event.observed_at_unix_ms);
        }

        Ok(())
    }

    /// Classify the timeline into its operator-facing evidence state.
    ///
    /// # Errors
    ///
    /// Returns [`MeshFailoverRecordError`] when the record is invalid.
    pub fn analyze(&self) -> Result<MeshFailoverAnalysis, MeshFailoverRecordError> {
        self.validate()?;

        let classification = self.classification();
        let claim_status = classification.claim_status();
        let relationship = classification.support_relationship();
        let truth_source = classification.truth_source();
        let evidence_kind = classification.evidence_kind();
        let proof_gaps = self.proof_gaps(classification)?;
        let summary = classification.summary(&self.scenario_id);

        Ok(MeshFailoverAnalysis {
            classification,
            claim_status,
            relationship,
            truth_source,
            evidence_kind,
            proof_gaps,
            summary,
        })
    }

    /// Convert the timeline into a complete one-claim [`ProofGraph`].
    ///
    /// # Errors
    ///
    /// Returns [`MeshFailoverRecordError`] when record or graph validation
    /// fails.
    pub fn to_proof_graph(&self) -> Result<ProofGraph, MeshFailoverRecordError> {
        let claim = self.to_claim_node()?;
        let evidence = self.to_evidence_node()?;
        let edge = self.to_support_edge()?;
        let actions = self.suggested_actions(&claim.id)?;
        Ok(ProofGraph::from_nodes(
            vec![claim],
            vec![evidence],
            vec![edge],
            actions,
        )?)
    }

    /// Convert the timeline into a [`ClaimNode`].
    ///
    /// # Errors
    ///
    /// Returns [`MeshFailoverRecordError`] when record or graph validation
    /// fails.
    pub fn to_claim_node(&self) -> Result<ClaimNode, MeshFailoverRecordError> {
        let analysis = self.analyze()?;
        let claim = ClaimNode {
            id: self.claim_id()?,
            title: format!("Mesh failover proof for {}", self.connector_id),
            statement: format!(
                "Scenario {} proves connector {} can fail over without losing canonical state",
                self.scenario_id, self.connector_id
            ),
            status: analysis.claim_status,
            required_truth_source: TruthSource::MeshBacked,
            freshness: FreshnessWindow::new(self.observed_at_unix_ms, self.valid_for_ms),
            redaction_class: self.redaction_class,
            owner: Some(BeadOwner {
                bead_id: self.owner_bead_id.clone(),
                agent_name: self.owner_agent.clone(),
            }),
            tags: BTreeSet::from([
                "failover".to_owned(),
                "mesh".to_owned(),
                "proofgraph".to_owned(),
                analysis.classification.as_str().to_owned(),
            ]),
            proof_gaps: analysis.proof_gaps,
        };
        claim.validate()?;
        Ok(claim)
    }

    /// Convert the timeline into an [`EvidenceNode`].
    ///
    /// # Errors
    ///
    /// Returns [`MeshFailoverRecordError`] when record or graph validation
    /// fails.
    pub fn to_evidence_node(&self) -> Result<EvidenceNode, MeshFailoverRecordError> {
        let analysis = self.analyze()?;
        let evidence = EvidenceNode {
            id: self.evidence_id()?,
            kind: analysis.evidence_kind,
            summary: analysis.summary,
            truth_source: analysis.truth_source,
            freshness: FreshnessWindow::new(self.observed_at_unix_ms, self.valid_for_ms),
            redaction_class: self.redaction_class,
            source_ref: self.source_ref.clone(),
            content_digest: Some(self.timeline_digest()?),
            rerun_command: None,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    /// Convert the classified timeline into a support edge.
    ///
    /// # Errors
    ///
    /// Returns [`MeshFailoverRecordError`] when edge validation fails.
    pub fn to_support_edge(&self) -> Result<SupportEdge, MeshFailoverRecordError> {
        let analysis = self.analyze()?;
        Ok(SupportEdge::new(
            self.claim_id()?,
            self.evidence_id()?,
            analysis.relationship,
            analysis.classification.edge_rationale(),
        )?)
    }

    /// Convert each timeline event to a deterministic JSONL-ready record.
    ///
    /// # Errors
    ///
    /// Returns [`MeshFailoverRecordError`] when the record is invalid.
    pub fn to_jsonl_events(&self) -> Result<Vec<MeshFailoverJsonlEvent>, MeshFailoverRecordError> {
        let analysis = self.analyze()?;
        Ok(self
            .events
            .iter()
            .map(|event| MeshFailoverJsonlEvent {
                schema: MESH_FAILOVER_RECORDER_EVENT_SCHEMA.to_owned(),
                scenario_id: self.scenario_id.clone(),
                connector_id: self.connector_id.clone(),
                event_sequence: event.sequence,
                observed_at_unix_ms: event.observed_at_unix_ms,
                kind: event.kind,
                node_id: event.node_id.clone(),
                lease_id: event.lease_id.clone(),
                state_root_id: event.state_root_id.clone(),
                audit_receipt_id: event.audit_receipt_id.clone(),
                truth_source: analysis.truth_source.clone(),
                classification: analysis.classification,
                summary: event.summary.clone(),
            })
            .collect())
    }

    /// Deterministic digest of the timeline fields carried by this record.
    ///
    /// # Errors
    ///
    /// Returns [`MeshFailoverRecordError`] when serialization fails or the
    /// record is invalid.
    pub fn timeline_digest(&self) -> Result<String, MeshFailoverRecordError> {
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

    fn claim_id(&self) -> Result<ClaimId, ProofGraphError> {
        ClaimId::new(format!("claim.mesh-failover.{}", self.scenario_id))
    }

    fn evidence_id(&self) -> Result<EvidenceId, ProofGraphError> {
        EvidenceId::new(format!(
            "evidence.mesh-failover.{}.timeline",
            self.scenario_id
        ))
    }

    fn classification(&self) -> MeshFailoverClassification {
        if self.has_event(MeshFailoverEventKind::StaleStateRootRejected) {
            return MeshFailoverClassification::StaleStateRootRejected;
        }
        if self.has_event(MeshFailoverEventKind::ReplayConflict) {
            return MeshFailoverClassification::ReplayConflict;
        }
        if self.participating_nodes.len() < self.required_node_count
            || self.has_event(MeshFailoverEventKind::DowngradeWarning)
        {
            return MeshFailoverClassification::SingleHostDowngrade;
        }
        if !self.has_event(MeshFailoverEventKind::AuditReceiptRecorded) {
            return MeshFailoverClassification::MissingAuditReceipt;
        }
        if self.has_event(MeshFailoverEventKind::PartitionObserved) {
            return if self.has_event(MeshFailoverEventKind::PartitionHealed)
                && self.has_event(MeshFailoverEventKind::ReplayCompleted)
                && self.has_event(MeshFailoverEventKind::CleanupCompleted)
            {
                MeshFailoverClassification::PartitionHealed
            } else {
                MeshFailoverClassification::IncompleteTimeline
            };
        }
        if self.has_event(MeshFailoverEventKind::FailoverTriggered)
            && self.has_event(MeshFailoverEventKind::LeaseAcquired)
            && self.has_event(MeshFailoverEventKind::StateRootCommitted)
            && self.has_event(MeshFailoverEventKind::ReplayCompleted)
            && self.has_event(MeshFailoverEventKind::CleanupCompleted)
        {
            MeshFailoverClassification::CleanFailover
        } else {
            MeshFailoverClassification::IncompleteTimeline
        }
    }

    fn has_event(&self, kind: MeshFailoverEventKind) -> bool {
        self.events.iter().any(|event| event.kind == kind)
    }

    fn proof_gaps(
        &self,
        classification: MeshFailoverClassification,
    ) -> Result<Vec<ProofGap>, ProofGraphError> {
        match classification {
            MeshFailoverClassification::CleanFailover
            | MeshFailoverClassification::PartitionHealed => Ok(Vec::new()),
            MeshFailoverClassification::SingleHostDowngrade => Ok(vec![self.proof_gap(
                "single-host-downgrade",
                "collect multi-node mesh evidence; single-host fallback cannot prove failover",
                ProofGapStatus::Blocked,
            )?]),
            MeshFailoverClassification::StaleStateRootRejected => Ok(vec![self.proof_gap(
                "stale-state-root",
                "rerun with a current ConnectorStateRoot and prove stale roots are rejected",
                ProofGapStatus::Failed,
            )?]),
            MeshFailoverClassification::ReplayConflict => Ok(vec![self.proof_gap(
                "replay-conflict",
                "resolve replay conflict and capture bounded replay completion evidence",
                ProofGapStatus::Failed,
            )?]),
            MeshFailoverClassification::MissingAuditReceipt => Ok(vec![self.proof_gap(
                "missing-audit-receipt",
                "record audit receipt for lease, replay, truth-source transition, and cleanup",
                ProofGapStatus::Missing,
            )?]),
            MeshFailoverClassification::IncompleteTimeline => Ok(vec![self.proof_gap(
                "incomplete-timeline",
                "capture failover trigger, lease acquisition, replay completion, audit receipt, and cleanup",
                ProofGapStatus::Missing,
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
            id: ProofGapId::new(format!("gap.mesh-failover.{}.{}", self.scenario_id, suffix))?,
            summary: summary.to_owned(),
            status,
            target_truth_source: TruthSource::MeshBacked,
        };
        gap.validate()?;
        Ok(gap)
    }

    fn suggested_actions(
        &self,
        claim_id: &ClaimId,
    ) -> Result<Vec<SuggestedNextAction>, MeshFailoverRecordError> {
        let analysis = self.analyze()?;
        if analysis.proof_gaps.is_empty() {
            return Ok(Vec::new());
        }
        let action = SuggestedNextAction {
            id: crate::proof_graph::SuggestedActionId::new(format!(
                "action.mesh-failover.{}.rerun",
                self.scenario_id
            ))?,
            claim_id: claim_id.clone(),
            summary: "rerun the mesh failover drill and attach a complete flight-recorder bundle"
                .to_owned(),
            rerun_command: None,
        };
        Ok(vec![action])
    }
}

fn default_mesh_failover_schema() -> String {
    MESH_FAILOVER_RECORDER_EVENT_SCHEMA.to_owned()
}

/// Redaction-safe state-root reference in a failover timeline.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MeshStateRootRef {
    /// Redaction-safe state root id.
    pub root_id: String,
    /// Monotonic state chain sequence.
    pub seq: u64,
    /// Digest of the state root or object bytes.
    pub digest: String,
}

impl MeshStateRootRef {
    fn validate(&self) -> Result<(), MeshFailoverRecordError> {
        validate_key_fragment("state_root.root_id", &self.root_id)?;
        validate_digest("state_root.digest", &self.digest)
    }
}

/// Single timeline event in a mesh failover flight record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshFailoverEvent {
    /// Monotonic event sequence within the scenario.
    pub sequence: u32,
    /// Unix millisecond timestamp for the observation.
    pub observed_at_unix_ms: u64,
    /// Event kind.
    pub kind: MeshFailoverEventKind,
    /// Optional participating node id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    /// Optional lease id involved in the event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
    /// Optional state root involved in the event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_root_id: Option<String>,
    /// Optional audit receipt id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_receipt_id: Option<String>,
    /// Redaction-safe event summary.
    pub summary: String,
}

impl MeshFailoverEvent {
    fn validate(
        &self,
        participating_nodes: &BTreeSet<String>,
    ) -> Result<(), MeshFailoverRecordError> {
        if let Some(node_id) = &self.node_id {
            validate_known_node("event.node_id", node_id, participating_nodes)?;
        }
        if let Some(lease_id) = &self.lease_id {
            validate_key_fragment("event.lease_id", lease_id)?;
        }
        if let Some(state_root_id) = &self.state_root_id {
            validate_key_fragment("event.state_root_id", state_root_id)?;
        }
        if let Some(audit_receipt_id) = &self.audit_receipt_id {
            validate_key_fragment("event.audit_receipt_id", audit_receipt_id)?;
        }
        validate_safe_text("event.summary", &self.summary)
    }
}

/// Event kinds recorded by the mesh failover flight recorder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshFailoverEventKind {
    /// Placement planner selected owners or replicas.
    PlacementDecided,
    /// Lease was acquired by a node.
    LeaseAcquired,
    /// Lease was renewed by the current owner.
    LeaseRenewed,
    /// Lease was released by the old owner.
    LeaseReleased,
    /// Connector state root was committed.
    StateRootCommitted,
    /// Connector state object was appended.
    StateObjectAppended,
    /// Failover was triggered.
    FailoverTriggered,
    /// Replay started on the new owner.
    ReplayStarted,
    /// Replay completed on the new owner.
    ReplayCompleted,
    /// Audit receipt was recorded.
    AuditReceiptRecorded,
    /// Truth source changed, for example host-backed to mesh-backed.
    TruthSourceTransition,
    /// Single-host or other downgrade warning was emitted.
    DowngradeWarning,
    /// Cleanup completed after failover.
    CleanupCompleted,
    /// Mesh partition was observed.
    PartitionObserved,
    /// Mesh partition healed.
    PartitionHealed,
    /// Stale state root was rejected.
    StaleStateRootRejected,
    /// Replay detected a conflict.
    ReplayConflict,
}

/// Classification derived from a flight-recorder timeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshFailoverClassification {
    /// Multi-node failover completed with audit evidence.
    CleanFailover,
    /// Partition occurred, healed, and replay completed with audit evidence.
    PartitionHealed,
    /// Evidence downgraded to a single-host or host-backed path.
    SingleHostDowngrade,
    /// Stale state root was rejected, contradicting current failover readiness.
    StaleStateRootRejected,
    /// Replay conflict prevented proof.
    ReplayConflict,
    /// Timeline is missing an audit receipt.
    MissingAuditReceipt,
    /// Timeline is missing one or more required phases.
    IncompleteTimeline,
}

impl MeshFailoverClassification {
    /// Stable classification label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CleanFailover => "clean_failover",
            Self::PartitionHealed => "partition_healed",
            Self::SingleHostDowngrade => "single_host_downgrade",
            Self::StaleStateRootRejected => "stale_state_root_rejected",
            Self::ReplayConflict => "replay_conflict",
            Self::MissingAuditReceipt => "missing_audit_receipt",
            Self::IncompleteTimeline => "incomplete_timeline",
        }
    }

    fn claim_status(self) -> ClaimStatus {
        match self {
            Self::CleanFailover | Self::PartitionHealed => ClaimStatus::Proven,
            Self::SingleHostDowngrade => ClaimStatus::SkippedWithReason {
                reason: "single-host fallback cannot prove mesh failover".to_owned(),
            },
            Self::StaleStateRootRejected => ClaimStatus::Failed {
                reason: "stale state root was rejected during failover".to_owned(),
            },
            Self::ReplayConflict => ClaimStatus::Failed {
                reason: "replay conflict prevented bounded failover proof".to_owned(),
            },
            Self::MissingAuditReceipt | Self::IncompleteTimeline => ClaimStatus::Missing,
        }
    }

    const fn support_relationship(self) -> SupportRelationship {
        match self {
            Self::CleanFailover | Self::PartitionHealed => SupportRelationship::Supports,
            Self::StaleStateRootRejected | Self::ReplayConflict => SupportRelationship::Contradicts,
            Self::SingleHostDowngrade | Self::MissingAuditReceipt | Self::IncompleteTimeline => {
                SupportRelationship::PartiallySupports
            }
        }
    }

    const fn truth_source(self) -> TruthSource {
        match self {
            Self::SingleHostDowngrade => TruthSource::HostBacked,
            Self::CleanFailover
            | Self::PartitionHealed
            | Self::StaleStateRootRejected
            | Self::ReplayConflict
            | Self::MissingAuditReceipt
            | Self::IncompleteTimeline => TruthSource::MeshBacked,
        }
    }

    const fn evidence_kind(self) -> EvidenceKind {
        match self {
            Self::SingleHostDowngrade => EvidenceKind::HostIntegration,
            Self::CleanFailover
            | Self::PartitionHealed
            | Self::StaleStateRootRejected
            | Self::ReplayConflict
            | Self::MissingAuditReceipt
            | Self::IncompleteTimeline => EvidenceKind::MeshExecution,
        }
    }

    fn summary(self, scenario_id: &str) -> String {
        match self {
            Self::CleanFailover => {
                format!("mesh failover scenario {scenario_id} completed with audited replay")
            }
            Self::PartitionHealed => format!(
                "mesh failover scenario {scenario_id} recovered after partition and healed replay"
            ),
            Self::SingleHostDowngrade => format!(
                "mesh failover scenario {scenario_id} downgraded to host-backed single-node evidence"
            ),
            Self::StaleStateRootRejected => {
                format!("mesh failover scenario {scenario_id} rejected a stale state root")
            }
            Self::ReplayConflict => {
                format!("mesh failover scenario {scenario_id} hit a replay conflict")
            }
            Self::MissingAuditReceipt => {
                format!("mesh failover scenario {scenario_id} is missing audit receipt evidence")
            }
            Self::IncompleteTimeline => {
                format!("mesh failover scenario {scenario_id} has an incomplete timeline")
            }
        }
    }

    const fn edge_rationale(self) -> &'static str {
        match self {
            Self::CleanFailover => {
                "Timeline includes failover trigger, lease acquisition, state-root commit, replay completion, audit receipt, and cleanup"
            }
            Self::PartitionHealed => {
                "Timeline includes partition observation, heal, replay completion, audit receipt, and cleanup"
            }
            Self::SingleHostDowngrade => {
                "Timeline records a downgrade warning or insufficient distinct mesh nodes"
            }
            Self::StaleStateRootRejected => {
                "Timeline contradicts readiness because a stale state root was rejected"
            }
            Self::ReplayConflict => {
                "Timeline contradicts readiness because replay reached a conflict"
            }
            Self::MissingAuditReceipt => {
                "Timeline covers failover mechanics but lacks the audit receipt required for proof"
            }
            Self::IncompleteTimeline => {
                "Timeline is missing required failover, replay, audit, or cleanup phases"
            }
        }
    }
}

/// Derived operator-facing analysis for a flight record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshFailoverAnalysis {
    /// Classification derived from the timeline.
    pub classification: MeshFailoverClassification,
    /// `ProofGraph` claim status.
    pub claim_status: ClaimStatus,
    /// Relationship between the evidence and claim.
    pub relationship: SupportRelationship,
    /// Truth source represented by the timeline.
    pub truth_source: TruthSource,
    /// Evidence kind represented by the timeline.
    pub evidence_kind: EvidenceKind,
    /// Gaps that prevent stronger proof.
    pub proof_gaps: Vec<ProofGap>,
    /// Redaction-safe summary.
    pub summary: String,
}

/// JSONL-ready event emitted from a flight record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshFailoverJsonlEvent {
    /// Schema identifier.
    pub schema: String,
    /// Scenario id.
    pub scenario_id: String,
    /// Connector id.
    pub connector_id: String,
    /// Event sequence.
    pub event_sequence: u32,
    /// Unix millisecond observation time.
    pub observed_at_unix_ms: u64,
    /// Event kind.
    pub kind: MeshFailoverEventKind,
    /// Optional node id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    /// Optional lease id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
    /// Optional state root id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_root_id: Option<String>,
    /// Optional audit receipt id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_receipt_id: Option<String>,
    /// Timeline truth source.
    pub truth_source: TruthSource,
    /// Timeline classification.
    pub classification: MeshFailoverClassification,
    /// Event summary.
    pub summary: String,
}

/// Errors produced by the mesh failover flight-recorder adapter.
#[derive(Debug, Error)]
pub enum MeshFailoverRecordError {
    /// Record schema was not recognized.
    #[error("invalid mesh failover record schema: expected {expected}, got {actual}")]
    InvalidSchema {
        /// Expected schema identifier.
        expected: &'static str,
        /// Actual schema identifier.
        actual: String,
    },
    /// Required timeline events were absent.
    #[error("mesh failover record must include at least one event")]
    NoEvents,
    /// Record did not include any participating nodes.
    #[error("mesh failover record must include participating nodes")]
    MissingParticipants,
    /// Numeric count field was invalid.
    #[error("{field} must be greater than zero")]
    InvalidCount {
        /// Field name.
        field: &'static str,
    },
    /// A node reference was not declared as a participant.
    #[error("{field} references unknown node {node_id}")]
    UnknownNode {
        /// Field name.
        field: &'static str,
        /// Unknown node id.
        node_id: String,
    },
    /// Duplicate event sequence found.
    #[error("duplicate mesh failover event sequence {sequence}")]
    DuplicateEventSequence {
        /// Duplicate sequence.
        sequence: u32,
    },
    /// Event sequence was not strictly increasing.
    #[error("event sequence must increase: previous {previous}, current {current}")]
    NonMonotonicEventSequence {
        /// Previous sequence.
        previous: u32,
        /// Current sequence.
        current: u32,
    },
    /// Event timestamps moved backwards.
    #[error("event timestamp moved backwards: previous {previous}, current {current}")]
    NonMonotonicEventTimestamp {
        /// Previous timestamp.
        previous: u64,
        /// Current timestamp.
        current: u64,
    },
    /// Text or identifier was unsafe for graph storage.
    #[error("unsafe {field}: {reason}")]
    UnsafeText {
        /// Field name.
        field: &'static str,
        /// Reason text.
        reason: &'static str,
    },
    /// Redaction class is not safe for graph storage.
    #[error("mesh failover record carries graph-unsafe redaction class {redaction_class:?}")]
    UnsafeRedactionClass {
        /// Unsafe redaction class.
        redaction_class: RedactionClass,
    },
    /// `ProofGraph` validation failed.
    #[error(transparent)]
    Graph(#[from] ProofGraphError),
    /// JSON serialization failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

fn validate_known_node(
    field: &'static str,
    node_id: &str,
    participating_nodes: &BTreeSet<String>,
) -> Result<(), MeshFailoverRecordError> {
    validate_key_fragment(field, node_id)?;
    if participating_nodes.contains(node_id) {
        Ok(())
    } else {
        Err(MeshFailoverRecordError::UnknownNode {
            field,
            node_id: node_id.to_owned(),
        })
    }
}

fn validate_key_fragment(field: &'static str, value: &str) -> Result<(), MeshFailoverRecordError> {
    validate_safe_text(field, value)?;
    if value.len() > MAX_KEY_FRAGMENT_LEN {
        return Err(MeshFailoverRecordError::UnsafeText {
            field,
            reason: "identifier is too long",
        });
    }
    if value.trim() != value || value.chars().any(char::is_whitespace) {
        return Err(MeshFailoverRecordError::UnsafeText {
            field,
            reason: "identifier must not contain whitespace",
        });
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':'))
    {
        return Err(MeshFailoverRecordError::UnsafeText {
            field,
            reason: "identifier contains unsupported characters",
        });
    }
    Ok(())
}

fn validate_safe_text(field: &'static str, value: &str) -> Result<(), MeshFailoverRecordError> {
    if value.trim().is_empty() {
        return Err(MeshFailoverRecordError::UnsafeText {
            field,
            reason: "empty text",
        });
    }
    if value.contains("://") {
        return Err(MeshFailoverRecordError::UnsafeText {
            field,
            reason: "raw endpoints must be replaced with artifact ids",
        });
    }
    if looks_like_secret(value) {
        return Err(MeshFailoverRecordError::UnsafeText {
            field,
            reason: "raw secret-like text is not allowed",
        });
    }
    Ok(())
}

fn validate_digest(field: &'static str, value: &str) -> Result<(), MeshFailoverRecordError> {
    validate_safe_text(field, value)?;
    let Some((algorithm, digest)) = value.split_once(':') else {
        return Err(MeshFailoverRecordError::UnsafeText {
            field,
            reason: "digest must be algorithm-prefixed",
        });
    };
    validate_key_fragment("digest.algorithm", algorithm)?;
    if digest.len() < 16 || !digest.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(MeshFailoverRecordError::UnsafeText {
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
    use super::*;

    const NOW: u64 = 1_770_000_000_000;
    const DAY_MS: u64 = 86_400_000;

    fn event(
        sequence: u32,
        kind: MeshFailoverEventKind,
        node_id: Option<&str>,
        summary: &str,
    ) -> MeshFailoverEvent {
        MeshFailoverEvent {
            sequence,
            observed_at_unix_ms: NOW + u64::from(sequence),
            kind,
            node_id: node_id.map(str::to_owned),
            lease_id: matches!(
                kind,
                MeshFailoverEventKind::LeaseAcquired
                    | MeshFailoverEventKind::LeaseRenewed
                    | MeshFailoverEventKind::LeaseReleased
            )
            .then(|| format!("lease-{sequence}")),
            state_root_id: matches!(
                kind,
                MeshFailoverEventKind::StateRootCommitted
                    | MeshFailoverEventKind::StateObjectAppended
                    | MeshFailoverEventKind::ReplayCompleted
                    | MeshFailoverEventKind::StaleStateRootRejected
            )
            .then(|| format!("state-root-{sequence}")),
            audit_receipt_id: (kind == MeshFailoverEventKind::AuditReceiptRecorded)
                .then(|| format!("audit-receipt-{sequence}")),
            summary: summary.to_owned(),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn clean_record() -> MeshFailoverFlightRecord {
        MeshFailoverFlightRecord {
            schema: MESH_FAILOVER_RECORDER_EVENT_SCHEMA.to_owned(),
            scenario_id: "clean-2node".to_owned(),
            connector_id: "connector.github".to_owned(),
            owner_bead_id: "flywheel_connectors-b88ec.6".to_owned(),
            owner_agent: Some("Codex".to_owned()),
            observed_at_unix_ms: NOW,
            valid_for_ms: DAY_MS,
            required_node_count: 2,
            participating_nodes: BTreeSet::from(["node-a".to_owned(), "node-b".to_owned()]),
            primary_before: "node-a".to_owned(),
            primary_after: Some("node-b".to_owned()),
            state_root_before: Some(MeshStateRootRef {
                root_id: "state-root-before".to_owned(),
                seq: 41,
                digest: "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            }),
            state_root_after: Some(MeshStateRootRef {
                root_id: "state-root-after".to_owned(),
                seq: 42,
                digest: "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
            }),
            source_ref: "fixtures:mesh-failover:clean-2node".to_owned(),
            artifact_digest: None,
            redaction_class: RedactionClass::Internal,
            events: vec![
                event(
                    1,
                    MeshFailoverEventKind::PlacementDecided,
                    Some("node-a"),
                    "placement selected node-a and node-b",
                ),
                event(
                    2,
                    MeshFailoverEventKind::LeaseAcquired,
                    Some("node-a"),
                    "node-a acquired initial lease",
                ),
                event(
                    3,
                    MeshFailoverEventKind::StateRootCommitted,
                    Some("node-a"),
                    "node-a committed state root before failover",
                ),
                event(
                    4,
                    MeshFailoverEventKind::FailoverTriggered,
                    Some("node-b"),
                    "node-b observed owner loss",
                ),
                event(
                    5,
                    MeshFailoverEventKind::LeaseAcquired,
                    Some("node-b"),
                    "node-b acquired failover lease",
                ),
                event(
                    6,
                    MeshFailoverEventKind::ReplayStarted,
                    Some("node-b"),
                    "node-b started bounded replay",
                ),
                event(
                    7,
                    MeshFailoverEventKind::ReplayCompleted,
                    Some("node-b"),
                    "node-b completed bounded replay",
                ),
                event(
                    8,
                    MeshFailoverEventKind::AuditReceiptRecorded,
                    Some("node-b"),
                    "audit receipt recorded lease replay and cleanup",
                ),
                event(
                    9,
                    MeshFailoverEventKind::CleanupCompleted,
                    Some("node-b"),
                    "old lease cleanup completed",
                ),
            ],
        }
    }

    #[test]
    fn clean_failover_builds_supporting_proof_graph() {
        let record = clean_record();
        let analysis = record.analyze().expect("clean record analyzes");

        assert_eq!(
            analysis.classification,
            MeshFailoverClassification::CleanFailover
        );
        assert_eq!(analysis.relationship, SupportRelationship::Supports);
        assert_eq!(analysis.truth_source, TruthSource::MeshBacked);
        assert!(analysis.proof_gaps.is_empty());

        let graph = record.to_proof_graph().expect("graph builds");
        graph.validate().expect("graph validates");
        let claim = graph
            .claims
            .get(&ClaimId::new("claim.mesh-failover.clean-2node").expect("valid claim id"))
            .expect("claim present");
        assert_eq!(claim.status, ClaimStatus::Proven);
    }

    #[test]
    fn partition_then_heal_is_mesh_backed_proof() {
        let mut record = clean_record();
        record.scenario_id = "partition-heal".to_owned();
        record.events.insert(
            6,
            event(
                7,
                MeshFailoverEventKind::PartitionObserved,
                Some("node-b"),
                "partition isolated the old owner",
            ),
        );
        record.events.insert(
            7,
            event(
                8,
                MeshFailoverEventKind::PartitionHealed,
                Some("node-b"),
                "partition healed before cleanup",
            ),
        );
        for (index, event) in record.events.iter_mut().enumerate() {
            event.sequence = u32::try_from(index + 1).expect("test sequence fits");
            event.observed_at_unix_ms = NOW + u64::from(event.sequence);
        }

        let analysis = record.analyze().expect("partition record analyzes");

        assert_eq!(
            analysis.classification,
            MeshFailoverClassification::PartitionHealed
        );
        assert_eq!(analysis.relationship, SupportRelationship::Supports);
        assert_eq!(analysis.truth_source, TruthSource::MeshBacked);
    }

    #[test]
    fn single_host_downgrade_is_not_mesh_proof() {
        let mut record = clean_record();
        record.scenario_id = "single-host".to_owned();
        record.required_node_count = 3;
        record.participating_nodes = BTreeSet::from(["node-a".to_owned()]);
        record.primary_before = "node-a".to_owned();
        record.primary_after = Some("node-a".to_owned());
        record.events = vec![
            event(
                1,
                MeshFailoverEventKind::DowngradeWarning,
                Some("node-a"),
                "single-host fallback warning emitted",
            ),
            event(
                2,
                MeshFailoverEventKind::AuditReceiptRecorded,
                Some("node-a"),
                "host-backed audit receipt recorded",
            ),
        ];

        let analysis = record.analyze().expect("downgrade record analyzes");

        assert_eq!(
            analysis.classification,
            MeshFailoverClassification::SingleHostDowngrade
        );
        assert_eq!(
            analysis.relationship,
            SupportRelationship::PartiallySupports
        );
        assert_eq!(analysis.truth_source, TruthSource::HostBacked);
        assert_eq!(analysis.proof_gaps[0].status, ProofGapStatus::Blocked);
    }

    #[test]
    fn stale_state_root_rejection_contradicts_failover_readiness() {
        let mut record = clean_record();
        record.scenario_id = "stale-root".to_owned();
        record.events.push(event(
            10,
            MeshFailoverEventKind::StaleStateRootRejected,
            Some("node-b"),
            "stale state root rejected during restore",
        ));

        let graph = record.to_proof_graph().expect("graph builds");
        let edge = graph.support_edges.first().expect("edge present");
        let claim = graph
            .claims
            .get(&ClaimId::new("claim.mesh-failover.stale-root").expect("valid claim id"))
            .expect("claim present");

        assert_eq!(edge.relationship, SupportRelationship::Contradicts);
        assert!(matches!(claim.status, ClaimStatus::Failed { .. }));
        assert_eq!(claim.proof_gaps[0].status, ProofGapStatus::Failed);
    }

    #[test]
    fn replay_conflict_contradicts_failover_readiness() {
        let mut record = clean_record();
        record.scenario_id = "replay-conflict".to_owned();
        record.events.push(event(
            10,
            MeshFailoverEventKind::ReplayConflict,
            Some("node-b"),
            "bounded replay detected conflicting append",
        ));

        let analysis = record.analyze().expect("conflict record analyzes");

        assert_eq!(
            analysis.classification,
            MeshFailoverClassification::ReplayConflict
        );
        assert_eq!(analysis.relationship, SupportRelationship::Contradicts);
        assert_eq!(analysis.proof_gaps[0].status, ProofGapStatus::Failed);
    }

    #[test]
    fn missing_audit_receipt_is_a_named_gap() {
        let mut record = clean_record();
        record.scenario_id = "missing-audit".to_owned();
        record
            .events
            .retain(|event| event.kind != MeshFailoverEventKind::AuditReceiptRecorded);
        for (index, event) in record.events.iter_mut().enumerate() {
            event.sequence = u32::try_from(index + 1).expect("test sequence fits");
            event.observed_at_unix_ms = NOW + u64::from(event.sequence);
        }

        let analysis = record.analyze().expect("missing audit analyzes");

        assert_eq!(
            analysis.classification,
            MeshFailoverClassification::MissingAuditReceipt
        );
        assert_eq!(
            analysis.relationship,
            SupportRelationship::PartiallySupports
        );
        assert_eq!(analysis.proof_gaps[0].status, ProofGapStatus::Missing);
        assert_eq!(
            analysis.proof_gaps[0].id,
            ProofGapId::new("gap.mesh-failover.missing-audit.missing-audit-receipt")
                .expect("valid gap id")
        );
    }

    #[test]
    fn jsonl_sample_events_are_deterministic_and_redaction_safe() {
        let record = clean_record();
        let events = record.to_jsonl_events().expect("jsonl events");
        let first = serde_json::to_string(&events[0]).expect("serialize event");

        assert_eq!(events.len(), 9);
        assert_eq!(
            first,
            r#"{"schema":"fcp.mesh-failover-flight-recorder.v1","scenario_id":"clean-2node","connector_id":"connector.github","event_sequence":1,"observed_at_unix_ms":1770000000001,"kind":"placement_decided","node_id":"node-a","truth_source":"mesh_backed","classification":"clean_failover","summary":"placement selected node-a and node-b"}"#
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
    fn unsafe_endpoint_or_secret_text_is_rejected() {
        let mut record = clean_record();
        record.source_ref = "https://mesh.example.test/raw".to_owned();
        let err = record
            .validate()
            .expect_err("raw endpoint source ref rejected");
        assert!(matches!(err, MeshFailoverRecordError::UnsafeText { .. }));

        let mut record = clean_record();
        record.events[0].summary = "bearer token leaked".to_owned();
        let err = record
            .validate()
            .expect_err("secret-like event summary rejected");
        assert!(matches!(err, MeshFailoverRecordError::UnsafeText { .. }));
    }

    #[test]
    fn duplicate_or_unknown_event_references_are_rejected() {
        let mut record = clean_record();
        record.events[1].sequence = record.events[0].sequence;
        let err = record
            .validate()
            .expect_err("duplicate sequence rejected before graph conversion");
        assert!(matches!(
            err,
            MeshFailoverRecordError::DuplicateEventSequence { .. }
                | MeshFailoverRecordError::NonMonotonicEventSequence { .. }
        ));

        let mut record = clean_record();
        record.events[0].node_id = Some("node-c".to_owned());
        let err = record
            .validate()
            .expect_err("unknown node reference rejected");
        assert!(matches!(err, MeshFailoverRecordError::UnknownNode { .. }));
    }
}
