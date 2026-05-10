//! Redaction-safe proof graph schema for operator-facing evidence routing.
//!
//! The graph stores claims, evidence, and support edges in deterministic
//! containers so it can be rendered, diffed, and re-run without leaking raw
//! provider bodies, endpoints, or secrets into graph keys.

#![allow(clippy::module_name_repetitions)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// Current `ProofGraph` schema identifier.
pub const PROOF_GRAPH_SCHEMA: &str = "fcp.proof-graph.v1";

const MAX_GRAPH_KEY_LEN: usize = 160;

/// Canonical graph of claims, evidence, and support relationships.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofGraph {
    /// Schema identifier; must be [`PROOF_GRAPH_SCHEMA`].
    pub schema: String,
    /// Claims keyed by their redaction-safe id.
    pub claims: BTreeMap<ClaimId, ClaimNode>,
    /// Evidence keyed by its redaction-safe id.
    pub evidence: BTreeMap<EvidenceId, EvidenceNode>,
    /// Support edges, sorted deterministically by claim id, evidence id, and relationship.
    pub support_edges: Vec<SupportEdge>,
    /// Redaction-safe follow-up actions that can close known proof gaps.
    pub suggested_next_actions: Vec<SuggestedNextAction>,
}

impl Default for ProofGraph {
    fn default() -> Self {
        Self::empty()
    }
}

impl ProofGraph {
    /// Construct an empty v1 graph.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            schema: PROOF_GRAPH_SCHEMA.to_owned(),
            claims: BTreeMap::new(),
            evidence: BTreeMap::new(),
            support_edges: Vec::new(),
            suggested_next_actions: Vec::new(),
        }
    }

    /// Construct a graph from node and edge lists, rejecting duplicate ids.
    ///
    /// # Errors
    ///
    /// Returns [`ProofGraphError`] when an id is duplicated, an edge points at
    /// a missing node, an edge lacks rationale, or any field violates the
    /// redaction-safe graph-key policy.
    pub fn from_nodes(
        claims: Vec<ClaimNode>,
        evidence: Vec<EvidenceNode>,
        support_edges: Vec<SupportEdge>,
        suggested_next_actions: Vec<SuggestedNextAction>,
    ) -> Result<Self, ProofGraphError> {
        let mut graph = Self::empty();

        for claim in claims {
            let id = claim.id.clone();
            if graph.claims.insert(id.clone(), claim).is_some() {
                return Err(ProofGraphError::DuplicateClaimId { id });
            }
        }

        for evidence_node in evidence {
            let id = evidence_node.id.clone();
            if graph.evidence.insert(id.clone(), evidence_node).is_some() {
                return Err(ProofGraphError::DuplicateEvidenceId { id });
            }
        }

        let mut action_ids = BTreeSet::new();
        for action in suggested_next_actions {
            let id = action.id.clone();
            if !action_ids.insert(id.clone()) {
                return Err(ProofGraphError::DuplicateActionId { id });
            }
            graph.suggested_next_actions.push(action);
        }

        graph.support_edges = sorted_edges(support_edges);
        graph
            .suggested_next_actions
            .sort_by(|left, right| left.id.cmp(&right.id));
        graph.validate()?;
        Ok(graph)
    }

    /// Validate graph structure, edge referential integrity, and redaction rules.
    ///
    /// # Errors
    ///
    /// Returns [`ProofGraphError`] when the schema, node ids, support edges,
    /// freshness-bearing actions, or redaction classes are invalid.
    pub fn validate(&self) -> Result<(), ProofGraphError> {
        if self.schema != PROOF_GRAPH_SCHEMA {
            return Err(ProofGraphError::InvalidSchema {
                expected: PROOF_GRAPH_SCHEMA,
                actual: self.schema.clone(),
            });
        }

        for (id, claim) in &self.claims {
            id.validate("claim_id")?;
            if id != &claim.id {
                return Err(ProofGraphError::MapKeyMismatch {
                    kind: "claim",
                    key: id.to_string(),
                    embedded: claim.id.to_string(),
                });
            }
            claim.validate()?;
        }

        for (id, evidence) in &self.evidence {
            id.validate("evidence_id")?;
            if id != &evidence.id {
                return Err(ProofGraphError::MapKeyMismatch {
                    kind: "evidence",
                    key: id.to_string(),
                    embedded: evidence.id.to_string(),
                });
            }
            evidence.validate()?;
        }

        for edge in &self.support_edges {
            edge.validate(self)?;
        }

        let mut action_ids = BTreeSet::new();
        for action in &self.suggested_next_actions {
            action.validate(self)?;
            if !action_ids.insert(action.id.clone()) {
                return Err(ProofGraphError::DuplicateActionId {
                    id: action.id.clone(),
                });
            }
        }

        Ok(())
    }
}

/// Redaction-safe claim identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClaimId(pub String);

impl ClaimId {
    /// Construct a validated claim id.
    ///
    /// # Errors
    ///
    /// Returns [`ProofGraphError::InvalidIdentifier`] if the id is empty,
    /// too long, URL-like, whitespace-bearing, or contains unsafe characters.
    pub fn new(value: impl Into<String>) -> Result<Self, ProofGraphError> {
        let value = value.into();
        validate_graph_key("claim_id", &value)?;
        Ok(Self(value))
    }

    /// Borrow the id string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self, kind: &'static str) -> Result<(), ProofGraphError> {
        validate_graph_key(kind, &self.0)
    }
}

impl fmt::Display for ClaimId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Redaction-safe evidence identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EvidenceId(pub String);

impl EvidenceId {
    /// Construct a validated evidence id.
    ///
    /// # Errors
    ///
    /// Returns [`ProofGraphError::InvalidIdentifier`] if the id is empty,
    /// too long, URL-like, whitespace-bearing, or contains unsafe characters.
    pub fn new(value: impl Into<String>) -> Result<Self, ProofGraphError> {
        let value = value.into();
        validate_graph_key("evidence_id", &value)?;
        Ok(Self(value))
    }

    /// Borrow the id string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self, kind: &'static str) -> Result<(), ProofGraphError> {
        validate_graph_key(kind, &self.0)
    }
}

impl fmt::Display for EvidenceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Redaction-safe rerun command identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RerunCommandId(pub String);

impl RerunCommandId {
    /// Construct a validated rerun command id.
    ///
    /// # Errors
    ///
    /// Returns [`ProofGraphError::InvalidIdentifier`] if the id is empty,
    /// too long, URL-like, whitespace-bearing, or contains unsafe characters.
    pub fn new(value: impl Into<String>) -> Result<Self, ProofGraphError> {
        let value = value.into();
        validate_graph_key("rerun_command_id", &value)?;
        Ok(Self(value))
    }

    /// Borrow the id string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self, kind: &'static str) -> Result<(), ProofGraphError> {
        validate_graph_key(kind, &self.0)
    }
}

impl fmt::Display for RerunCommandId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Redaction-safe proof-gap identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProofGapId(pub String);

impl ProofGapId {
    /// Construct a validated proof-gap id.
    ///
    /// # Errors
    ///
    /// Returns [`ProofGraphError::InvalidIdentifier`] if the id is empty,
    /// too long, URL-like, whitespace-bearing, or contains unsafe characters.
    pub fn new(value: impl Into<String>) -> Result<Self, ProofGraphError> {
        let value = value.into();
        validate_graph_key("proof_gap_id", &value)?;
        Ok(Self(value))
    }

    fn validate(&self, kind: &'static str) -> Result<(), ProofGraphError> {
        validate_graph_key(kind, &self.0)
    }
}

impl fmt::Display for ProofGapId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Redaction-safe suggested action identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SuggestedActionId(pub String);

impl SuggestedActionId {
    /// Construct a validated suggested action id.
    ///
    /// # Errors
    ///
    /// Returns [`ProofGraphError::InvalidIdentifier`] if the id is empty,
    /// too long, URL-like, whitespace-bearing, or contains unsafe characters.
    pub fn new(value: impl Into<String>) -> Result<Self, ProofGraphError> {
        let value = value.into();
        validate_graph_key("suggested_action_id", &value)?;
        Ok(Self(value))
    }

    fn validate(&self, kind: &'static str) -> Result<(), ProofGraphError> {
        validate_graph_key(kind, &self.0)
    }
}

impl fmt::Display for SuggestedActionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A claim whose proof state can be evaluated from evidence nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimNode {
    /// Redaction-safe claim id.
    pub id: ClaimId,
    /// Short operator-facing claim title.
    pub title: String,
    /// Redaction-safe claim statement.
    pub statement: String,
    /// Current proof state for this claim.
    pub status: ClaimStatus,
    /// Strongest truth source required to prove this claim.
    pub required_truth_source: TruthSource,
    /// Freshness window for the current claim state.
    pub freshness: FreshnessWindow,
    /// Classification of the graph fields carried by this node.
    pub redaction_class: RedactionClass,
    /// Bead or agent owner for this claim.
    pub owner: Option<BeadOwner>,
    /// Stable labels used for filtering and routing.
    pub tags: BTreeSet<String>,
    /// Known gaps preventing stronger proof.
    pub proof_gaps: Vec<ProofGap>,
}

impl ClaimNode {
    /// Validate this claim node.
    ///
    /// # Errors
    ///
    /// Returns [`ProofGraphError`] when identifiers, redaction classes, tags,
    /// owner, status reason text, or proof gaps are invalid.
    pub fn validate(&self) -> Result<(), ProofGraphError> {
        self.id.validate("claim_id")?;
        ensure_redaction_safe_class("claim", self.redaction_class)?;
        validate_safe_text("claim.title", &self.title)?;
        validate_safe_text("claim.statement", &self.statement)?;
        self.status.validate()?;
        if let Some(owner) = &self.owner {
            owner.validate()?;
        }
        for tag in &self.tags {
            validate_graph_key("claim.tag", tag)?;
        }
        let mut gap_ids = BTreeSet::new();
        for gap in &self.proof_gaps {
            gap.validate()?;
            if !gap_ids.insert(gap.id.clone()) {
                return Err(ProofGraphError::DuplicateProofGapId { id: gap.id.clone() });
            }
        }
        Ok(())
    }
}

/// Evidence that may support, contradict, or fail to support a claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceNode {
    /// Redaction-safe evidence id.
    pub id: EvidenceId,
    /// Evidence category.
    pub kind: EvidenceKind,
    /// Redaction-safe operator summary of what was observed.
    pub summary: String,
    /// Where the evidence was obtained in the truth hierarchy.
    pub truth_source: TruthSource,
    /// Freshness window for the observation.
    pub freshness: FreshnessWindow,
    /// Classification of the graph fields carried by this node.
    pub redaction_class: RedactionClass,
    /// Redaction-safe locator such as a test name, commit, artifact id, or bead comment id.
    pub source_ref: String,
    /// Optional digest of external evidence bytes; raw evidence bytes stay out of the graph.
    pub content_digest: Option<String>,
    /// Optional command for regenerating this evidence.
    pub rerun_command: Option<RerunCommand>,
}

impl EvidenceNode {
    /// Validate this evidence node.
    ///
    /// # Errors
    ///
    /// Returns [`ProofGraphError`] when identifiers, source references,
    /// summaries, digests, rerun commands, or redaction classes are invalid.
    pub fn validate(&self) -> Result<(), ProofGraphError> {
        self.id.validate("evidence_id")?;
        ensure_redaction_safe_class("evidence", self.redaction_class)?;
        validate_safe_text("evidence.summary", &self.summary)?;
        validate_safe_text("evidence.source_ref", &self.source_ref)?;
        if looks_like_raw_endpoint(&self.source_ref) {
            return Err(ProofGraphError::UnsafeText {
                field: "evidence.source_ref",
                reason: "raw endpoint references must be redacted or replaced with an artifact id",
            });
        }
        if let Some(digest) = &self.content_digest {
            validate_digest("evidence.content_digest", digest)?;
        }
        if let Some(command) = &self.rerun_command {
            command.validate()?;
        }
        Ok(())
    }
}

/// Evidence categories tracked by the graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// Evidence from mesh-backed live execution.
    MeshExecution,
    /// Evidence from a host-backed integration test or admin path.
    HostIntegration,
    /// Evidence from a node-local command or fixture.
    NodeLocalRun,
    /// Evidence from an offline fixture, transcript digest, or generated artifact.
    OfflineArtifact,
    /// Evidence from a commit, diff, or repository object.
    RepositoryObject,
    /// Evidence from a bead, operator comment, or planning artifact.
    OperatorRecord,
    /// Evidence from project documentation.
    Documentation,
}

/// Relationship between one evidence node and one claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportRelationship {
    /// Evidence proves or materially supports the claim.
    Supports,
    /// Evidence proves the claim is false.
    Contradicts,
    /// Evidence covers part of the claim but leaves a named gap.
    PartiallySupports,
    /// Evidence was checked and does not support the claim.
    DoesNotSupport,
}

/// A rationale-bearing edge between an evidence node and a claim node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportEdge {
    /// Claim receiving support or contradiction.
    pub claim_id: ClaimId,
    /// Evidence being interpreted.
    pub evidence_id: EvidenceId,
    /// How this evidence relates to the claim.
    pub relationship: SupportRelationship,
    /// Human-readable explanation of why the evidence has this relationship.
    pub rationale: String,
}

impl SupportEdge {
    /// Construct a support edge.
    ///
    /// # Errors
    ///
    /// Returns [`ProofGraphError::EmptyEdgeRationale`] when rationale is empty.
    pub fn new(
        claim_id: ClaimId,
        evidence_id: EvidenceId,
        relationship: SupportRelationship,
        rationale: impl Into<String>,
    ) -> Result<Self, ProofGraphError> {
        let edge = Self {
            claim_id,
            evidence_id,
            relationship,
            rationale: rationale.into(),
        };
        edge.validate_rationale()?;
        Ok(edge)
    }

    fn validate(&self, graph: &ProofGraph) -> Result<(), ProofGraphError> {
        self.claim_id.validate("edge.claim_id")?;
        self.evidence_id.validate("edge.evidence_id")?;
        self.validate_rationale()?;
        if !graph.claims.contains_key(&self.claim_id) {
            return Err(ProofGraphError::UnknownClaimInEdge {
                claim_id: self.claim_id.clone(),
            });
        }
        if !graph.evidence.contains_key(&self.evidence_id) {
            return Err(ProofGraphError::UnknownEvidenceInEdge {
                evidence_id: self.evidence_id.clone(),
            });
        }
        validate_safe_text("support_edge.rationale", &self.rationale)?;
        Ok(())
    }

    fn validate_rationale(&self) -> Result<(), ProofGraphError> {
        if self.rationale.trim().is_empty() {
            return Err(ProofGraphError::EmptyEdgeRationale {
                claim_id: self.claim_id.clone(),
                evidence_id: self.evidence_id.clone(),
            });
        }
        Ok(())
    }
}

/// Current proof state of a claim.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ClaimStatus {
    /// Claim has sufficient fresh evidence.
    Proven,
    /// Fresh evidence contradicts the claim.
    Failed {
        /// Redaction-safe failure reason.
        reason: String,
    },
    /// Evidence exists but is outside its freshness window.
    Stale {
        /// Millisecond timestamp when the proof became stale.
        stale_at_unix_ms: u64,
    },
    /// Required evidence has not been collected.
    Missing,
    /// Claim cannot be evaluated until a blocker clears.
    Blocked {
        /// Redaction-safe blocker reason.
        reason: String,
    },
    /// Claim was intentionally skipped and carries the explicit reason.
    SkippedWithReason {
        /// Redaction-safe skip reason.
        reason: String,
    },
}

impl ClaimStatus {
    fn validate(&self) -> Result<(), ProofGraphError> {
        match self {
            Self::Proven | Self::Missing | Self::Stale { .. } => Ok(()),
            Self::Failed { reason }
            | Self::Blocked { reason }
            | Self::SkippedWithReason { reason } => {
                validate_safe_text("claim.status.reason", reason)
            }
        }
    }
}

/// Freshness interval for a claim or evidence observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FreshnessWindow {
    /// Unix millisecond timestamp when the observation was collected.
    pub observed_at_unix_ms: u64,
    /// Milliseconds for which the observation remains fresh.
    pub valid_for_ms: u64,
}

impl FreshnessWindow {
    /// Construct a freshness window.
    #[must_use]
    pub const fn new(observed_at_unix_ms: u64, valid_for_ms: u64) -> Self {
        Self {
            observed_at_unix_ms,
            valid_for_ms,
        }
    }

    /// Unix millisecond timestamp at which the observation becomes stale.
    #[must_use]
    pub const fn expires_at_unix_ms(self) -> u64 {
        self.observed_at_unix_ms.saturating_add(self.valid_for_ms)
    }

    /// Whether the observation is still fresh at `now_unix_ms`.
    #[must_use]
    pub const fn is_fresh_at(self, now_unix_ms: u64) -> bool {
        now_unix_ms <= self.expires_at_unix_ms()
    }
}

/// Truth hierarchy used when routing proof debt.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TruthSource {
    /// Mesh-backed live evidence; strongest accepted truth source.
    MeshBacked,
    /// Host-backed live integration evidence.
    HostBacked,
    /// Node-local command evidence.
    NodeLocal,
    /// Offline fixture, digest, or documentation evidence.
    Offline,
    /// Forward-compatible truth source not understood by this build.
    Unknown(String),
}

impl TruthSource {
    /// Stable string representation used on the wire.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::MeshBacked => "mesh_backed",
            Self::HostBacked => "host_backed",
            Self::NodeLocal => "node_local",
            Self::Offline => "offline",
            Self::Unknown(value) => value,
        }
    }

    /// Rank in the truth hierarchy: mesh-backed > host-backed > node-local > offline > unknown.
    #[must_use]
    pub const fn rank(&self) -> u8 {
        match self {
            Self::MeshBacked => 4,
            Self::HostBacked => 3,
            Self::NodeLocal => 2,
            Self::Offline => 1,
            Self::Unknown(_) => 0,
        }
    }

    /// Whether this source is at least as strong as `required`.
    #[must_use]
    pub const fn satisfies(&self, required: &Self) -> bool {
        self.rank() >= required.rank()
    }
}

impl From<&str> for TruthSource {
    fn from(value: &str) -> Self {
        match value {
            "mesh_backed" => Self::MeshBacked,
            "host_backed" => Self::HostBacked,
            "node_local" => Self::NodeLocal,
            "offline" => Self::Offline,
            other => Self::Unknown(other.to_owned()),
        }
    }
}

impl Serialize for TruthSource {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for TruthSource {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(TruthSourceVisitor)
    }
}

struct TruthSourceVisitor;

impl Visitor<'_> for TruthSourceVisitor {
    type Value = TruthSource;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a truth-source string")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(TruthSource::from(value))
    }
}

/// Redaction classification for graph fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionClass {
    /// Safe for public issue references.
    Public,
    /// Safe for internal operator logs.
    Internal,
    /// Raw sensitive value has been removed or replaced with a placeholder.
    Redacted,
    /// Only a digest or synthetic id derived from sensitive material is present.
    DigestOnly,
    /// Raw secret material is present; rejected by [`ProofGraph::validate`].
    ContainsSecret,
    /// Raw personal data is present; rejected by [`ProofGraph::validate`].
    ContainsPii,
}

impl RedactionClass {
    /// Whether fields in this class are allowed inside proof graph nodes.
    #[must_use]
    pub const fn is_graph_safe(self) -> bool {
        matches!(
            self,
            Self::Public | Self::Internal | Self::Redacted | Self::DigestOnly
        )
    }
}

/// Bead and optional agent currently responsible for a claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeadOwner {
    /// Bead id that owns this claim.
    pub bead_id: String,
    /// Optional current assignee.
    pub agent_name: Option<String>,
}

impl BeadOwner {
    /// Validate owner metadata.
    ///
    /// # Errors
    ///
    /// Returns [`ProofGraphError`] if the bead id or agent name is not
    /// redaction-safe graph metadata.
    pub fn validate(&self) -> Result<(), ProofGraphError> {
        validate_graph_key("owner.bead_id", &self.bead_id)?;
        if let Some(agent_name) = &self.agent_name {
            validate_graph_key("owner.agent_name", agent_name)?;
        }
        Ok(())
    }
}

/// Rerunnable command for regenerating an evidence node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RerunCommand {
    /// Redaction-safe command id.
    pub id: RerunCommandId,
    /// Argument vector, excluding raw secret values.
    pub argv: Vec<String>,
    /// Environment variable names required by the command; values are not stored.
    pub required_env_keys: BTreeSet<String>,
    /// Optional working-directory hint.
    pub working_directory: Option<String>,
    /// Whether this command must be run through remote Cargo host orchestration.
    pub requires_rch: bool,
}

impl RerunCommand {
    /// Validate command metadata.
    ///
    /// # Errors
    ///
    /// Returns [`ProofGraphError`] if the command id, argument vector,
    /// environment keys, or working directory contain unsafe graph metadata.
    pub fn validate(&self) -> Result<(), ProofGraphError> {
        self.id.validate("rerun_command.id")?;
        if self.argv.is_empty() {
            return Err(ProofGraphError::EmptyRerunCommand {
                command_id: self.id.clone(),
            });
        }
        for arg in &self.argv {
            validate_safe_text("rerun_command.argv", arg)?;
            if looks_like_secret(arg) {
                return Err(ProofGraphError::UnsafeText {
                    field: "rerun_command.argv",
                    reason: "command arguments must use placeholders instead of raw secret values",
                });
            }
        }
        for key in &self.required_env_keys {
            validate_graph_key("rerun_command.required_env_key", key)?;
        }
        if let Some(working_directory) = &self.working_directory {
            validate_safe_text("rerun_command.working_directory", working_directory)?;
        }
        Ok(())
    }
}

/// Known proof gap attached to a claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofGap {
    /// Redaction-safe proof-gap id.
    pub id: ProofGapId,
    /// Operator-facing summary of the missing or weak evidence.
    pub summary: String,
    /// Status represented by the gap.
    pub status: ProofGapStatus,
    /// Strongest truth source that would close this gap.
    pub target_truth_source: TruthSource,
}

impl ProofGap {
    /// Validate proof-gap metadata.
    ///
    /// # Errors
    ///
    /// Returns [`ProofGraphError`] if the id or summary is not redaction-safe.
    pub fn validate(&self) -> Result<(), ProofGraphError> {
        self.id.validate("proof_gap.id")?;
        validate_safe_text("proof_gap.summary", &self.summary)?;
        Ok(())
    }
}

/// Gap state used to route the next proof action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofGapStatus {
    /// Evidence is stale.
    Stale,
    /// Evidence has not been collected.
    Missing,
    /// Evaluation is blocked by another task or environment constraint.
    Blocked,
    /// Evidence path was skipped and must carry rationale elsewhere.
    SkippedWithReason,
    /// Last evidence collection failed.
    Failed,
}

/// Redaction-safe action recommended by proof-debt routing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuggestedNextAction {
    /// Redaction-safe action id.
    pub id: SuggestedActionId,
    /// Claim this action is intended to improve.
    pub claim_id: ClaimId,
    /// Operator-facing action summary.
    pub summary: String,
    /// Optional rerun command.
    pub rerun_command: Option<RerunCommand>,
}

impl SuggestedNextAction {
    /// Validate suggested action metadata.
    ///
    /// # Errors
    ///
    /// Returns [`ProofGraphError`] if the id, claim reference, summary, or
    /// optional rerun command is invalid.
    pub fn validate(&self, graph: &ProofGraph) -> Result<(), ProofGraphError> {
        self.id.validate("suggested_action.id")?;
        self.claim_id.validate("suggested_action.claim_id")?;
        if !graph.claims.contains_key(&self.claim_id) {
            return Err(ProofGraphError::UnknownClaimInAction {
                claim_id: self.claim_id.clone(),
            });
        }
        validate_safe_text("suggested_action.summary", &self.summary)?;
        if let Some(command) = &self.rerun_command {
            command.validate()?;
        }
        Ok(())
    }
}

/// Errors returned by `ProofGraph` construction and validation.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProofGraphError {
    /// Graph schema was not recognized.
    #[error("invalid proof graph schema: expected {expected}, got {actual}")]
    InvalidSchema {
        /// Expected schema identifier.
        expected: &'static str,
        /// Actual schema identifier.
        actual: String,
    },
    /// Identifier does not meet graph-key safety rules.
    #[error("invalid {kind} identifier {value:?}: {reason}")]
    InvalidIdentifier {
        /// Identifier kind.
        kind: &'static str,
        /// Rejected value.
        value: String,
        /// Human-readable reason.
        reason: &'static str,
    },
    /// Duplicate claim id in constructor input.
    #[error("duplicate claim id: {id}")]
    DuplicateClaimId {
        /// Duplicated id.
        id: ClaimId,
    },
    /// Duplicate evidence id in constructor input.
    #[error("duplicate evidence id: {id}")]
    DuplicateEvidenceId {
        /// Duplicated id.
        id: EvidenceId,
    },
    /// Duplicate proof-gap id inside one claim.
    #[error("duplicate proof gap id: {id}")]
    DuplicateProofGapId {
        /// Duplicated id.
        id: ProofGapId,
    },
    /// Duplicate suggested action id.
    #[error("duplicate suggested action id: {id}")]
    DuplicateActionId {
        /// Duplicated id.
        id: SuggestedActionId,
    },
    /// Map key and embedded node id disagree.
    #[error("{kind} map key {key:?} does not match embedded id {embedded:?}")]
    MapKeyMismatch {
        /// Node kind.
        kind: &'static str,
        /// Map key.
        key: String,
        /// Embedded node id.
        embedded: String,
    },
    /// Support edge references a missing claim.
    #[error("support edge references unknown claim: {claim_id}")]
    UnknownClaimInEdge {
        /// Missing claim id.
        claim_id: ClaimId,
    },
    /// Support edge references missing evidence.
    #[error("support edge references unknown evidence: {evidence_id}")]
    UnknownEvidenceInEdge {
        /// Missing evidence id.
        evidence_id: EvidenceId,
    },
    /// Suggested action references a missing claim.
    #[error("suggested action references unknown claim: {claim_id}")]
    UnknownClaimInAction {
        /// Missing claim id.
        claim_id: ClaimId,
    },
    /// Support edge is missing its explanatory rationale.
    #[error("support edge {claim_id} -> {evidence_id} must include rationale")]
    EmptyEdgeRationale {
        /// Edge claim id.
        claim_id: ClaimId,
        /// Edge evidence id.
        evidence_id: EvidenceId,
    },
    /// Redaction class is unsafe for proof graph storage.
    #[error("{kind} carries graph-unsafe redaction class {redaction_class:?}")]
    UnsafeRedactionClass {
        /// Node kind.
        kind: &'static str,
        /// Rejected redaction class.
        redaction_class: RedactionClass,
    },
    /// Text field contains unsafe raw material.
    #[error("{field} is not redaction-safe: {reason}")]
    UnsafeText {
        /// Field name.
        field: &'static str,
        /// Rejection reason.
        reason: &'static str,
    },
    /// Rerun command has no argv entries.
    #[error("rerun command {command_id} must include argv")]
    EmptyRerunCommand {
        /// Command id.
        command_id: RerunCommandId,
    },
}

fn sorted_edges(mut edges: Vec<SupportEdge>) -> Vec<SupportEdge> {
    edges.sort_by(|left, right| {
        (
            &left.claim_id,
            &left.evidence_id,
            left.relationship,
            &left.rationale,
        )
            .cmp(&(
                &right.claim_id,
                &right.evidence_id,
                right.relationship,
                &right.rationale,
            ))
    });
    edges
}

fn validate_graph_key(kind: &'static str, value: &str) -> Result<(), ProofGraphError> {
    if value.is_empty() {
        return Err(ProofGraphError::InvalidIdentifier {
            kind,
            value: value.to_owned(),
            reason: "empty",
        });
    }
    if value.len() > MAX_GRAPH_KEY_LEN {
        return Err(ProofGraphError::InvalidIdentifier {
            kind,
            value: value.to_owned(),
            reason: "too long",
        });
    }
    if value.trim() != value || value.chars().any(char::is_whitespace) {
        return Err(ProofGraphError::InvalidIdentifier {
            kind,
            value: value.to_owned(),
            reason: "whitespace is not allowed in graph keys",
        });
    }
    if looks_like_raw_endpoint(value) {
        return Err(ProofGraphError::InvalidIdentifier {
            kind,
            value: value.to_owned(),
            reason: "raw endpoints must not be graph keys",
        });
    }
    if looks_like_secret(value) {
        return Err(ProofGraphError::InvalidIdentifier {
            kind,
            value: value.to_owned(),
            reason: "raw secrets must not be graph keys",
        });
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':'))
    {
        return Err(ProofGraphError::InvalidIdentifier {
            kind,
            value: value.to_owned(),
            reason: "only ascii alphanumeric, dash, underscore, dot, and colon are allowed",
        });
    }
    Ok(())
}

fn validate_safe_text(field: &'static str, value: &str) -> Result<(), ProofGraphError> {
    if value.trim().is_empty() {
        return Err(ProofGraphError::UnsafeText {
            field,
            reason: "empty text",
        });
    }
    if looks_like_secret(value) {
        return Err(ProofGraphError::UnsafeText {
            field,
            reason: "raw secret-like text is not allowed",
        });
    }
    Ok(())
}

fn validate_digest(field: &'static str, value: &str) -> Result<(), ProofGraphError> {
    validate_safe_text(field, value)?;
    let Some((algorithm, digest)) = value.split_once(':') else {
        return Err(ProofGraphError::UnsafeText {
            field,
            reason: "digest must be algorithm-prefixed",
        });
    };
    validate_graph_key("digest.algorithm", algorithm)?;
    if digest.len() < 16 || !digest.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(ProofGraphError::UnsafeText {
            field,
            reason: "digest must be lowercase or uppercase hex with at least 16 nybbles",
        });
    }
    Ok(())
}

const fn ensure_redaction_safe_class(
    kind: &'static str,
    redaction_class: RedactionClass,
) -> Result<(), ProofGraphError> {
    if redaction_class.is_graph_safe() {
        Ok(())
    } else {
        Err(ProofGraphError::UnsafeRedactionClass {
            kind,
            redaction_class,
        })
    }
}

fn looks_like_raw_endpoint(value: &str) -> bool {
    value.contains("://")
}

fn looks_like_secret(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("authorization:")
        || lower.contains("bearer ")
        || lower.contains("token=")
        || lower.contains("password=")
        || lower.contains("secret=")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim_id(value: &str) -> ClaimId {
        ClaimId::new(value).expect("valid claim id")
    }

    fn evidence_id(value: &str) -> EvidenceId {
        EvidenceId::new(value).expect("valid evidence id")
    }

    fn command_id(value: &str) -> RerunCommandId {
        RerunCommandId::new(value).expect("valid command id")
    }

    fn action_id(value: &str) -> SuggestedActionId {
        SuggestedActionId::new(value).expect("valid action id")
    }

    fn gap_id(value: &str) -> ProofGapId {
        ProofGapId::new(value).expect("valid proof gap id")
    }

    fn sample_claim(id: &str) -> ClaimNode {
        ClaimNode {
            id: claim_id(id),
            title: "OTLP exporter has timeout proof".to_owned(),
            statement: "The exporter records bounded slow-collector cancellation evidence"
                .to_owned(),
            status: ClaimStatus::Proven,
            required_truth_source: TruthSource::HostBacked,
            freshness: FreshnessWindow::new(1_700_000_000_000, 86_400_000),
            redaction_class: RedactionClass::Internal,
            owner: Some(BeadOwner {
                bead_id: "flywheel_connectors-b88ec.1".to_owned(),
                agent_name: Some("Codex".to_owned()),
            }),
            tags: BTreeSet::from(["fcp-evidence".to_owned(), "proof-graph".to_owned()]),
            proof_gaps: Vec::new(),
        }
    }

    fn sample_evidence(id: &str) -> EvidenceNode {
        EvidenceNode {
            id: evidence_id(id),
            kind: EvidenceKind::HostIntegration,
            summary: "Remote rch cargo test passed for the timeout fixture".to_owned(),
            truth_source: TruthSource::HostBacked,
            freshness: FreshnessWindow::new(1_700_000_000_500, 86_400_000),
            redaction_class: RedactionClass::Internal,
            source_ref: "rch:vmi1152480:otlp_timeout_fixture".to_owned(),
            content_digest: Some("blake3:0123456789abcdef0123456789abcdef".to_owned()),
            rerun_command: Some(RerunCommand {
                id: command_id("cmd.otlp-timeout"),
                argv: vec![
                    "rch".to_owned(),
                    "exec".to_owned(),
                    "--".to_owned(),
                    "cargo".to_owned(),
                    "test".to_owned(),
                    "-p".to_owned(),
                    "fcp-telemetry".to_owned(),
                ],
                required_env_keys: BTreeSet::from(["RCH_REQUIRE_REMOTE".to_owned()]),
                working_directory: Some("crates/fcp-telemetry".to_owned()),
                requires_rch: true,
            }),
        }
    }

    fn sample_edge(claim: &str, evidence: &str) -> SupportEdge {
        SupportEdge::new(
            claim_id(claim),
            evidence_id(evidence),
            SupportRelationship::Supports,
            "The fixture observed a deadline-exceeded export failure and clean shutdown",
        )
        .expect("valid support edge")
    }

    fn sample_graph() -> ProofGraph {
        ProofGraph::from_nodes(
            vec![sample_claim("claim.otlp-timeout")],
            vec![sample_evidence("evidence.otlp-timeout.remote-test")],
            vec![sample_edge(
                "claim.otlp-timeout",
                "evidence.otlp-timeout.remote-test",
            )],
            vec![SuggestedNextAction {
                id: action_id("action.host-admin-proof"),
                claim_id: claim_id("claim.otlp-timeout"),
                summary: "Add host/admin integration evidence when the admin surface lands"
                    .to_owned(),
                rerun_command: None,
            }],
        )
        .expect("sample graph validates")
    }

    #[test]
    fn serde_roundtrip_preserves_graph() {
        let graph = sample_graph();
        let json = serde_json::to_string_pretty(&graph).expect("serialize graph");
        let decoded: ProofGraph = serde_json::from_str(&json).expect("deserialize graph");

        assert_eq!(decoded, graph);
        decoded.validate().expect("round-tripped graph validates");
    }

    #[test]
    fn deterministic_ordering_sorts_maps_edges_and_actions() {
        let graph = ProofGraph::from_nodes(
            vec![sample_claim("claim.z"), sample_claim("claim.a")],
            vec![sample_evidence("evidence.z"), sample_evidence("evidence.a")],
            vec![
                sample_edge("claim.z", "evidence.z"),
                sample_edge("claim.a", "evidence.a"),
            ],
            vec![
                SuggestedNextAction {
                    id: action_id("action.z"),
                    claim_id: claim_id("claim.z"),
                    summary: "Later sorted action".to_owned(),
                    rerun_command: None,
                },
                SuggestedNextAction {
                    id: action_id("action.a"),
                    claim_id: claim_id("claim.a"),
                    summary: "Earlier sorted action".to_owned(),
                    rerun_command: None,
                },
            ],
        )
        .expect("graph validates");

        assert_eq!(
            graph.claims.keys().cloned().collect::<Vec<_>>(),
            vec![claim_id("claim.a"), claim_id("claim.z")]
        );
        assert_eq!(
            graph.evidence.keys().cloned().collect::<Vec<_>>(),
            vec![evidence_id("evidence.a"), evidence_id("evidence.z")]
        );
        assert_eq!(graph.support_edges[0].claim_id, claim_id("claim.a"));
        assert_eq!(graph.suggested_next_actions[0].id, action_id("action.a"));
    }

    #[test]
    fn freshness_boundary_is_inclusive() {
        let window = FreshnessWindow::new(1_000, 500);

        assert!(window.is_fresh_at(1_000));
        assert!(window.is_fresh_at(1_500));
        assert!(!window.is_fresh_at(1_501));
    }

    #[test]
    fn unknown_truth_source_roundtrips_and_ranks_below_offline() {
        let json = r#""provider_live_shadow""#;
        let source: TruthSource = serde_json::from_str(json).expect("unknown source decodes");

        assert_eq!(
            source,
            TruthSource::Unknown("provider_live_shadow".to_owned())
        );
        assert!(TruthSource::Offline.satisfies(&source));
        assert!(!source.satisfies(&TruthSource::Offline));
        assert_eq!(
            serde_json::to_string(&source).expect("unknown source encodes"),
            json
        );
    }

    #[test]
    fn redaction_class_rejects_raw_secret_or_pii_nodes() {
        let mut evidence = sample_evidence("evidence.raw-secret");
        evidence.redaction_class = RedactionClass::ContainsSecret;
        let err = ProofGraph::from_nodes(
            vec![sample_claim("claim.raw-secret")],
            vec![evidence],
            vec![sample_edge("claim.raw-secret", "evidence.raw-secret")],
            Vec::new(),
        )
        .expect_err("raw secret evidence must be rejected");

        assert!(matches!(err, ProofGraphError::UnsafeRedactionClass { .. }));
    }

    #[test]
    fn graph_keys_reject_raw_endpoints() {
        let err = EvidenceId::new("https://api.example.test/raw").expect_err("url id rejected");

        assert!(matches!(
            err,
            ProofGraphError::InvalidIdentifier {
                kind: "evidence_id",
                ..
            }
        ));
    }

    #[test]
    fn duplicate_evidence_ids_are_rejected() {
        let err = ProofGraph::from_nodes(
            vec![sample_claim("claim.duplicate-evidence")],
            vec![
                sample_evidence("evidence.dup"),
                sample_evidence("evidence.dup"),
            ],
            vec![sample_edge("claim.duplicate-evidence", "evidence.dup")],
            Vec::new(),
        )
        .expect_err("duplicate evidence ids must be rejected");

        assert!(matches!(err, ProofGraphError::DuplicateEvidenceId { .. }));
    }

    #[test]
    fn invalid_support_edges_are_rejected() {
        let missing_evidence = SupportEdge::new(
            claim_id("claim.edge"),
            evidence_id("evidence.missing"),
            SupportRelationship::DoesNotSupport,
            "The expected evidence node is absent",
        )
        .expect("edge has rationale");
        let err = ProofGraph::from_nodes(
            vec![sample_claim("claim.edge")],
            vec![sample_evidence("evidence.present")],
            vec![missing_evidence],
            Vec::new(),
        )
        .expect_err("missing evidence id must be rejected");
        assert!(matches!(err, ProofGraphError::UnknownEvidenceInEdge { .. }));

        let empty_rationale = SupportEdge {
            claim_id: claim_id("claim.edge"),
            evidence_id: evidence_id("evidence.present"),
            relationship: SupportRelationship::PartiallySupports,
            rationale: " ".to_owned(),
        };
        let err = ProofGraph::from_nodes(
            vec![sample_claim("claim.edge")],
            vec![sample_evidence("evidence.present")],
            vec![empty_rationale],
            Vec::new(),
        )
        .expect_err("empty rationale must be rejected");
        assert!(matches!(err, ProofGraphError::EmptyEdgeRationale { .. }));
    }

    #[test]
    fn proof_gap_statuses_cover_routing_states() {
        let mut claim = sample_claim("claim.gaps");
        claim.status = ClaimStatus::Blocked {
            reason: "blocked by host-admin fixture".to_owned(),
        };
        claim.proof_gaps = vec![
            ProofGap {
                id: gap_id("gap.stale"),
                summary: "rerun stale mesh evidence".to_owned(),
                status: ProofGapStatus::Stale,
                target_truth_source: TruthSource::MeshBacked,
            },
            ProofGap {
                id: gap_id("gap.missing"),
                summary: "collect missing host-backed proof".to_owned(),
                status: ProofGapStatus::Missing,
                target_truth_source: TruthSource::HostBacked,
            },
            ProofGap {
                id: gap_id("gap.blocked"),
                summary: "wait for host/admin surface".to_owned(),
                status: ProofGapStatus::Blocked,
                target_truth_source: TruthSource::HostBacked,
            },
            ProofGap {
                id: gap_id("gap.skipped"),
                summary: "skipped because remote host unavailable".to_owned(),
                status: ProofGapStatus::SkippedWithReason,
                target_truth_source: TruthSource::NodeLocal,
            },
            ProofGap {
                id: gap_id("gap.failed"),
                summary: "last proof command failed".to_owned(),
                status: ProofGapStatus::Failed,
                target_truth_source: TruthSource::NodeLocal,
            },
        ];

        ProofGraph::from_nodes(
            vec![claim],
            vec![sample_evidence("evidence.gaps")],
            vec![sample_edge("claim.gaps", "evidence.gaps")],
            Vec::new(),
        )
        .expect("all proof gap statuses validate");
    }
}
