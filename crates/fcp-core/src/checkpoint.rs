//! Checkpoint/Frontier Management: Advancement Protocol, Fork Detection, Convergence (NORMATIVE).
//!
//! This module implements the checkpoint advancement protocol as described in
//! `FCP_Specification_V2.md` §24. `ZoneCheckpoints` are the "heartbeat" of mesh security;
//! stale checkpoints mean stale revocation/audit enforcement.
//!
//! # Protocol Overview
//!
//! 1. **Trigger Conditions**: New checkpoint issued when time elapsed, chains grew, or policy changed
//! 2. **Coordinator Selection**: HRW hash over (`zone_id`, "checkpoint", epoch)
//! 3. **Proposal**: Coordinator broadcasts `CheckpointProposal`
//! 4. **Signature Collection**: Nodes sign if all heads known/valid and seq = `prev_seq` + 1
//! 5. **Finalization**: Once n-f signatures collected, checkpoint published
//! 6. **Fork Detection**: Same `zone_id` + same seq + different `checkpoint_id` = fork

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{EpochId, NodeSignature, ObjectId, SignatureSet, TailscaleNodeId, ZoneId};

// ─────────────────────────────────────────────────────────────────────────────
// Checkpoint Trigger Conditions
// ─────────────────────────────────────────────────────────────────────────────

/// Default checkpoint interval in seconds (NORMATIVE).
pub const DEFAULT_CHECKPOINT_INTERVAL_SECS: u64 = 60;

/// Default audit chain growth threshold (NORMATIVE).
pub const DEFAULT_AUDIT_CHAIN_GROWTH_THRESHOLD: u64 = 100;

/// Trigger conditions for checkpoint advancement (NORMATIVE).
///
/// A new checkpoint SHOULD be issued when any of these conditions are met.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CheckpointTrigger {
    /// Time since last checkpoint exceeds interval.
    TimeElapsed {
        /// Seconds since last checkpoint.
        elapsed_secs: u64,
        /// Configured interval threshold.
        threshold_secs: u64,
    },
    /// Audit chain has grown beyond threshold.
    AuditChainGrowth {
        /// Number of new events since last checkpoint.
        new_events: u64,
        /// Configured threshold.
        threshold: u64,
    },
    /// Revocation chain has new events (any new revocation triggers checkpoint).
    RevocationChainGrowth {
        /// Number of new revocation events.
        new_events: u64,
    },
    /// Zone policy or configuration changed.
    PolicyChange {
        /// Previous policy head.
        old_policy_head: ObjectId,
        /// New policy head.
        new_policy_head: ObjectId,
    },
    /// Manual checkpoint requested by operator.
    Manual {
        /// Optional reason for manual trigger.
        reason: Option<String>,
    },
}

impl CheckpointTrigger {
    /// Check if time-based trigger condition is met.
    #[must_use]
    pub const fn check_time_elapsed(elapsed_secs: u64, threshold_secs: u64) -> Option<Self> {
        if elapsed_secs > threshold_secs {
            Some(Self::TimeElapsed {
                elapsed_secs,
                threshold_secs,
            })
        } else {
            None
        }
    }

    /// Check if audit chain growth trigger is met.
    #[must_use]
    pub const fn check_audit_growth(new_events: u64, threshold: u64) -> Option<Self> {
        if new_events > threshold {
            Some(Self::AuditChainGrowth {
                new_events,
                threshold,
            })
        } else {
            None
        }
    }

    /// Check if revocation chain has new events.
    #[must_use]
    pub const fn check_revocation_growth(new_events: u64) -> Option<Self> {
        if new_events > 0 {
            Some(Self::RevocationChainGrowth { new_events })
        } else {
            None
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Checkpoint Proposal
// ─────────────────────────────────────────────────────────────────────────────

/// Checkpoint proposal broadcast by coordinator (NORMATIVE).
///
/// The coordinator creates this proposal after being selected via HRW hash.
/// Nodes verify the proposal and sign if valid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointProposal {
    /// Zone this checkpoint covers.
    pub zone_id: ZoneId,
    /// Proposed checkpoint sequence (MUST be `prev_seq` + 1).
    pub proposed_seq: u64,
    /// Previous checkpoint ID (for chain linking).
    pub prev_checkpoint_id: Option<ObjectId>,
    /// Proposed audit head binding.
    pub audit_head_id: ObjectId,
    pub audit_head_seq: u64,
    /// Proposed revocation head binding.
    pub revocation_head_id: ObjectId,
    pub revocation_head_seq: u64,
    /// Policy/config head bindings.
    pub zone_definition_head: ObjectId,
    pub zone_policy_head: ObjectId,
    pub active_zone_key_manifest: ObjectId,
    /// Epoch at proposal time.
    pub epoch_id: EpochId,
    /// Proposal timestamp (Unix seconds).
    pub proposed_at: u64,
    /// Coordinator who created this proposal.
    pub coordinator: TailscaleNodeId,
    /// Signature by coordinator.
    pub coordinator_signature: NodeSignature,
    /// Trigger condition(s) that caused this proposal.
    pub triggers: Vec<CheckpointTrigger>,
}

impl CheckpointProposal {
    /// Verify that `proposed_seq` follows the previous checkpoint correctly.
    #[must_use]
    pub fn seq_follows_prev(&self, prev_seq: u64) -> bool {
        prev_seq
            .checked_add(1)
            .is_some_and(|expected| self.proposed_seq == expected)
    }

    /// Check if timestamp is within acceptable skew tolerance.
    #[must_use]
    pub const fn timestamp_within_skew(&self, local_time: u64, max_skew_secs: u64) -> bool {
        self.proposed_at.abs_diff(local_time) <= max_skew_secs
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Fork Detection
// ─────────────────────────────────────────────────────────────────────────────

/// Fork detection result (NORMATIVE).
///
/// A fork exists when two checkpoints have:
/// - Same `zone_id`
/// - Same seq
/// - Different `checkpoint_id`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForkDetectionResult {
    /// No fork detected.
    NoFork,
    /// Fork detected with evidence.
    ForkDetected(ForkEvidence),
}

impl ForkDetectionResult {
    /// Returns true if a fork was detected.
    #[must_use]
    pub const fn is_fork(&self) -> bool {
        matches!(self, Self::ForkDetected(_))
    }
}

/// Evidence of a detected fork (CRITICAL SECURITY EVENT).
///
/// When a fork is detected:
/// 1. Halt checkpoint advancement immediately
/// 2. Emit `audit.fork_detected` audit event
/// 3. Push alert to operator
/// 4. Operations requiring fresh checkpoint MUST fail
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkEvidence {
    /// Zone where fork was detected.
    pub zone_id: ZoneId,
    /// Conflicting sequence number.
    pub conflicting_seq: u64,
    /// First checkpoint ID at this seq.
    pub checkpoint_a: ObjectId,
    /// Second (conflicting) checkpoint ID at same seq.
    pub checkpoint_b: ObjectId,
    /// When fork was detected (Unix timestamp).
    pub detected_at: u64,
    /// Node that detected the fork.
    pub detected_by: TailscaleNodeId,
    /// Signers of checkpoint A (if known).
    pub signers_a: BTreeSet<String>,
    /// Signers of checkpoint B (if known).
    pub signers_b: BTreeSet<String>,
}

impl ForkEvidence {
    /// Create new fork evidence.
    #[must_use]
    pub const fn new(
        zone_id: ZoneId,
        conflicting_seq: u64,
        checkpoint_a: ObjectId,
        checkpoint_b: ObjectId,
        detected_at: u64,
        detected_by: TailscaleNodeId,
    ) -> Self {
        Self {
            zone_id,
            conflicting_seq,
            checkpoint_a,
            checkpoint_b,
            detected_at,
            detected_by,
            signers_a: BTreeSet::new(),
            signers_b: BTreeSet::new(),
        }
    }

    /// Detect fork between two checkpoints with same seq.
    ///
    /// Returns `Some(ForkEvidence)` if checkpoints have same `zone_id` and seq
    /// but different IDs.
    #[must_use]
    pub fn detect(
        zone_id: &ZoneId,
        seq: u64,
        id_a: &ObjectId,
        id_b: &ObjectId,
        now: u64,
        detector: TailscaleNodeId,
    ) -> Option<Self> {
        if id_a == id_b {
            None
        } else {
            Some(Self::new(zone_id.clone(), seq, *id_a, *id_b, now, detector))
        }
    }

    /// Add signers from checkpoint A.
    #[must_use]
    pub fn with_signers_a(mut self, signers: impl IntoIterator<Item = String>) -> Self {
        self.signers_a = signers.into_iter().collect();
        self
    }

    /// Add signers from checkpoint B.
    #[must_use]
    pub fn with_signers_b(mut self, signers: impl IntoIterator<Item = String>) -> Self {
        self.signers_b = signers.into_iter().collect();
        self
    }

    /// Find nodes that signed both conflicting checkpoints (Byzantine nodes).
    #[must_use]
    pub fn double_signers(&self) -> BTreeSet<String> {
        self.signers_a
            .intersection(&self.signers_b)
            .cloned()
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Coordinator Selection (HRW Hash)
// ─────────────────────────────────────────────────────────────────────────────

/// Compute HRW hash for coordinator selection (NORMATIVE).
///
/// Uses BLAKE3 hash of (`zone_id`, "checkpoint", epoch, `node_id`) to produce
/// a deterministic ordering of nodes. The highest hash value wins.
///
/// # Panics
///
/// Panics if any input byte length exceeds `u32::MAX`.
#[must_use]
pub fn hrw_hash_checkpoint(zone_id: &ZoneId, epoch: &EpochId, node_id: &TailscaleNodeId) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"FCP2-HRW-CHECKPOINT-V1");

    let z_bytes = zone_id.as_bytes();
    hasher.update(
        &u32::try_from(z_bytes.len())
            .expect("zone_id length exceeds u32::MAX")
            .to_le_bytes(),
    );
    hasher.update(z_bytes);

    let e_bytes = epoch.as_str().as_bytes();
    hasher.update(
        &u32::try_from(e_bytes.len())
            .expect("epoch_id length exceeds u32::MAX")
            .to_le_bytes(),
    );
    hasher.update(e_bytes);

    let n_bytes = node_id.as_str().as_bytes();
    hasher.update(
        &u32::try_from(n_bytes.len())
            .expect("node_id length exceeds u32::MAX")
            .to_le_bytes(),
    );
    hasher.update(n_bytes);

    let hash = hasher.finalize();
    let bytes = hash.as_bytes();
    // Take first 8 bytes as u64 for comparison
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

/// Select checkpoint coordinator from eligible nodes (NORMATIVE).
///
/// Uses Highest Random Weight (HRW) hashing for deterministic, consistent
/// coordinator selection across all nodes.
///
/// # Arguments
///
/// * `zone_id` - The zone for checkpoint
/// * `epoch` - Current epoch
/// * `eligible_nodes` - Nodes eligible to be coordinator
///
/// # Returns
///
/// The node with highest HRW hash, or None if no eligible nodes.
#[must_use]
pub fn select_checkpoint_coordinator(
    zone_id: &ZoneId,
    epoch: &EpochId,
    eligible_nodes: &[TailscaleNodeId],
) -> Option<TailscaleNodeId> {
    eligible_nodes
        .iter()
        .max_by_key(|node| hrw_hash_checkpoint(zone_id, epoch, node))
        .cloned()
}

/// Rank nodes by HRW hash for fallback coordinator selection (NORMATIVE).
///
/// Returns nodes sorted by descending HRW hash. If primary coordinator fails,
/// the next node in the ranking becomes coordinator.
#[must_use]
pub fn rank_checkpoint_coordinators(
    zone_id: &ZoneId,
    epoch: &EpochId,
    eligible_nodes: &[TailscaleNodeId],
) -> Vec<TailscaleNodeId> {
    let mut ranked: Vec<_> = eligible_nodes
        .iter()
        .map(|node| (hrw_hash_checkpoint(zone_id, epoch, node), node.clone()))
        .collect();
    ranked.sort_by_key(|item| std::cmp::Reverse(item.0)); // Descending by hash
    ranked.into_iter().map(|(_, node)| node).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Checkpoint Advancement State Machine
// ─────────────────────────────────────────────────────────────────────────────

/// State of checkpoint advancement protocol (NORMATIVE).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CheckpointAdvanceState {
    /// Idle, waiting for trigger condition.
    Idle {
        /// Current checkpoint seq.
        current_seq: u64,
        /// When last checkpoint was finalized.
        last_checkpoint_at: u64,
    },
    /// Trigger condition met, selecting coordinator.
    TriggeredAwaitingCoordinator {
        /// Trigger that caused advancement.
        trigger: CheckpointTrigger,
        /// When trigger occurred.
        triggered_at: u64,
    },
    /// Coordinator selected, proposal broadcast.
    ProposalBroadcast {
        /// The broadcast proposal (boxed to reduce enum size).
        proposal: Box<CheckpointProposal>,
        /// Signatures collected so far.
        collected_signatures: SignatureSet,
        /// Required signature count (n-f).
        required_signatures: usize,
    },
    /// Sufficient signatures collected, checkpoint finalized.
    Finalized {
        /// Finalized checkpoint ID.
        checkpoint_id: ObjectId,
        /// Finalized sequence.
        finalized_seq: u64,
        /// When finalized.
        finalized_at: u64,
    },
    /// Fork detected, advancement halted.
    Halted {
        /// Fork evidence.
        fork_evidence: ForkEvidence,
        /// When halted.
        halted_at: u64,
    },
}

impl CheckpointAdvanceState {
    /// Create initial idle state.
    #[must_use]
    pub const fn idle(current_seq: u64, last_checkpoint_at: u64) -> Self {
        Self::Idle {
            current_seq,
            last_checkpoint_at,
        }
    }

    /// Check if advancement is halted due to fork.
    #[must_use]
    pub const fn is_halted(&self) -> bool {
        matches!(self, Self::Halted { .. })
    }

    /// Check if checkpoint can advance (not halted).
    #[must_use]
    pub const fn can_advance(&self) -> bool {
        !self.is_halted()
    }

    /// Get fork evidence if halted.
    #[must_use]
    pub const fn fork_evidence(&self) -> Option<&ForkEvidence> {
        match self {
            Self::Halted { fork_evidence, .. } => Some(fork_evidence),
            _ => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Checkpoint Validation
// ─────────────────────────────────────────────────────────────────────────────

/// Errors during checkpoint proposal validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum CheckpointValidationError {
    /// Sequence number does not follow previous checkpoint.
    InvalidSequence { expected: u64, got: u64 },
    /// Proposal timestamp outside acceptable skew.
    TimestampSkew {
        local_time: u64,
        proposal_time: u64,
        max_skew: u64,
    },
    /// Referenced head is unknown.
    UnknownHead {
        head_type: String,
        head_id: ObjectId,
    },
    /// Referenced head is invalid.
    InvalidHead {
        head_type: String,
        head_id: ObjectId,
        reason: String,
    },
    /// Proposer is not the valid coordinator.
    NotCoordinator {
        expected: TailscaleNodeId,
        got: TailscaleNodeId,
    },
    /// Coordinator signature is invalid.
    InvalidCoordinatorSignature,
    /// Fork was detected.
    ForkDetected(ForkEvidence),
    /// Zone mismatch.
    ZoneMismatch { expected: ZoneId, got: ZoneId },
    /// Epoch mismatch.
    EpochMismatch { expected: EpochId, got: EpochId },
}

impl CheckpointValidationError {
    /// Check if this error indicates a fork (critical security event).
    #[must_use]
    pub const fn is_fork(&self) -> bool {
        matches!(self, Self::ForkDetected(_))
    }

    /// Get reason code for audit/logging.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::InvalidSequence { .. } => "FCP-5001",
            Self::TimestampSkew { .. } => "FCP-5002",
            Self::UnknownHead { .. } => "FCP-5003",
            Self::InvalidHead { .. } => "FCP-5004",
            Self::NotCoordinator { .. } => "FCP-5005",
            Self::InvalidCoordinatorSignature => "FCP-5006",
            Self::ForkDetected(_) => "FCP-5010",
            Self::ZoneMismatch { .. } => "FCP-5007",
            Self::EpochMismatch { .. } => "FCP-5008",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Freshness Verification
// ─────────────────────────────────────────────────────────────────────────────

/// Freshness check result for token/revocation verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FreshnessResult {
    /// Checkpoint is fresh enough.
    Fresh,
    /// Checkpoint is stale but operation allowed in degraded mode.
    DegradedMode,
    /// Checkpoint too stale, operation must fail.
    TooStale,
}

impl FreshnessResult {
    /// Check token freshness against local checkpoint (NORMATIVE).
    ///
    /// Token is fresh if `token.chk_seq <= local_checkpoint_seq`.
    #[must_use]
    pub const fn check_token_freshness(
        token_chk_seq: u64,
        local_checkpoint_seq: u64,
        degraded_mode_allowed: bool,
    ) -> Self {
        if token_chk_seq <= local_checkpoint_seq {
            Self::Fresh
        } else if degraded_mode_allowed {
            Self::DegradedMode
        } else {
            Self::TooStale
        }
    }

    /// Check revocation freshness (NORMATIVE).
    ///
    /// Local revocation head must be >= policy minimum.
    #[must_use]
    pub const fn check_revocation_freshness(
        local_rev_head_seq: u64,
        policy_min_rev_seq: u64,
        degraded_mode_allowed: bool,
    ) -> Self {
        if local_rev_head_seq >= policy_min_rev_seq {
            Self::Fresh
        } else if degraded_mode_allowed {
            Self::DegradedMode
        } else {
            Self::TooStale
        }
    }

    /// Returns true if operation can proceed.
    #[must_use]
    pub const fn allows_operation(&self) -> bool {
        !matches!(self, Self::TooStale)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NodeId;

    // ─────────────────────────────────────────────────────────────────────────
    // Test Helpers
    // ─────────────────────────────────────────────────────────────────────────

    fn test_zone() -> ZoneId {
        ZoneId::work()
    }

    fn test_epoch() -> EpochId {
        EpochId::new("epoch-42")
    }

    fn test_node(name: &str) -> TailscaleNodeId {
        TailscaleNodeId::new(name)
    }

    fn test_object_id(label: &str) -> ObjectId {
        ObjectId::test_id(label)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CheckpointTrigger Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn trigger_time_elapsed_met() {
        let trigger = CheckpointTrigger::check_time_elapsed(65, 60);
        assert!(trigger.is_some());
        if let Some(CheckpointTrigger::TimeElapsed {
            elapsed_secs,
            threshold_secs,
        }) = trigger
        {
            assert_eq!(elapsed_secs, 65);
            assert_eq!(threshold_secs, 60);
        }
    }

    #[test]
    fn trigger_time_elapsed_not_met() {
        let trigger = CheckpointTrigger::check_time_elapsed(55, 60);
        assert!(trigger.is_none());
    }

    #[test]
    fn trigger_time_elapsed_boundary() {
        // Exactly at threshold - should NOT trigger (must exceed)
        let trigger = CheckpointTrigger::check_time_elapsed(60, 60);
        assert!(trigger.is_none());
    }

    #[test]
    fn trigger_audit_growth_met() {
        let trigger = CheckpointTrigger::check_audit_growth(150, 100);
        assert!(trigger.is_some());
        if let Some(CheckpointTrigger::AuditChainGrowth {
            new_events,
            threshold,
        }) = trigger
        {
            assert_eq!(new_events, 150);
            assert_eq!(threshold, 100);
        }
    }

    #[test]
    fn trigger_audit_growth_not_met() {
        let trigger = CheckpointTrigger::check_audit_growth(50, 100);
        assert!(trigger.is_none());
    }

    #[test]
    fn trigger_revocation_growth_any_events() {
        let trigger = CheckpointTrigger::check_revocation_growth(1);
        assert!(trigger.is_some());
    }

    #[test]
    fn trigger_revocation_growth_zero_events() {
        let trigger = CheckpointTrigger::check_revocation_growth(0);
        assert!(trigger.is_none());
    }

    #[test]
    fn trigger_serialization_roundtrip() {
        let triggers = vec![
            CheckpointTrigger::TimeElapsed {
                elapsed_secs: 120,
                threshold_secs: 60,
            },
            CheckpointTrigger::AuditChainGrowth {
                new_events: 200,
                threshold: 100,
            },
            CheckpointTrigger::RevocationChainGrowth { new_events: 5 },
            CheckpointTrigger::PolicyChange {
                old_policy_head: test_object_id("old-policy"),
                new_policy_head: test_object_id("new-policy"),
            },
            CheckpointTrigger::Manual {
                reason: Some("Operator requested".to_string()),
            },
        ];

        for trigger in triggers {
            let json = serde_json::to_string(&trigger).unwrap();
            let decoded: CheckpointTrigger = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, trigger);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Fork Detection Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn fork_detection_different_ids() {
        let zone = test_zone();
        let id_a = test_object_id("checkpoint-a");
        let id_b = test_object_id("checkpoint-b");
        let detector = test_node("detector-node");

        let evidence = ForkEvidence::detect(&zone, 10, &id_a, &id_b, 1_700_000_000, detector);

        assert!(evidence.is_some());
        let ev = evidence.unwrap();
        assert_eq!(ev.zone_id.as_str(), "z:work");
        assert_eq!(ev.conflicting_seq, 10);
        assert_eq!(ev.checkpoint_a, id_a);
        assert_eq!(ev.checkpoint_b, id_b);
    }

    #[test]
    fn fork_detection_same_ids_no_fork() {
        let zone = test_zone();
        let id_a = test_object_id("checkpoint-same");
        let id_b = test_object_id("checkpoint-same");
        let detector = test_node("detector-node");

        let evidence = ForkEvidence::detect(&zone, 10, &id_a, &id_b, 1_700_000_000, detector);

        assert!(evidence.is_none());
    }

    #[test]
    fn fork_evidence_double_signers() {
        let evidence = ForkEvidence::new(
            test_zone(),
            10,
            test_object_id("a"),
            test_object_id("b"),
            1_700_000_000,
            test_node("detector"),
        )
        .with_signers_a([
            "alice".to_string(),
            "bob".to_string(),
            "charlie".to_string(),
        ])
        .with_signers_b([
            "bob".to_string(),
            "david".to_string(),
            "charlie".to_string(),
        ]);

        let double_signers = evidence.double_signers();

        // bob and charlie signed both
        assert_eq!(double_signers.len(), 2);
        assert!(double_signers.contains("bob"));
        assert!(double_signers.contains("charlie"));
    }

    #[test]
    fn fork_detection_result_is_fork() {
        let result = ForkDetectionResult::NoFork;
        assert!(!result.is_fork());

        let evidence = ForkEvidence::new(
            test_zone(),
            10,
            test_object_id("a"),
            test_object_id("b"),
            1_700_000_000,
            test_node("detector"),
        );
        let result = ForkDetectionResult::ForkDetected(evidence);
        assert!(result.is_fork());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HRW Coordinator Selection Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn hrw_hash_deterministic() {
        let zone = test_zone();
        let epoch = test_epoch();
        let node = test_node("node-1");

        let hash1 = hrw_hash_checkpoint(&zone, &epoch, &node);
        let hash2 = hrw_hash_checkpoint(&zone, &epoch, &node);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn hrw_hash_differs_by_node() {
        let zone = test_zone();
        let epoch = test_epoch();

        let hash1 = hrw_hash_checkpoint(&zone, &epoch, &test_node("node-1"));
        let hash2 = hrw_hash_checkpoint(&zone, &epoch, &test_node("node-2"));

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn hrw_hash_differs_by_epoch() {
        let zone = test_zone();
        let node = test_node("node-1");

        let hash1 = hrw_hash_checkpoint(&zone, &EpochId::new("epoch-1"), &node);
        let hash2 = hrw_hash_checkpoint(&zone, &EpochId::new("epoch-2"), &node);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn hrw_hash_differs_by_zone() {
        let epoch = test_epoch();
        let node = test_node("node-1");

        let hash1 = hrw_hash_checkpoint(&ZoneId::work(), &epoch, &node);
        let hash2 = hrw_hash_checkpoint(&ZoneId::public(), &epoch, &node);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn coordinator_selection_deterministic() {
        let zone = test_zone();
        let epoch = test_epoch();
        let nodes = vec![
            test_node("node-a"),
            test_node("node-b"),
            test_node("node-c"),
        ];

        let coord1 = select_checkpoint_coordinator(&zone, &epoch, &nodes);
        let coord2 = select_checkpoint_coordinator(&zone, &epoch, &nodes);

        assert_eq!(coord1, coord2);
        assert!(coord1.is_some());
    }

    #[test]
    fn coordinator_selection_empty_nodes() {
        let zone = test_zone();
        let epoch = test_epoch();
        let nodes: Vec<TailscaleNodeId> = vec![];

        let coord = select_checkpoint_coordinator(&zone, &epoch, &nodes);

        assert!(coord.is_none());
    }

    #[test]
    fn coordinator_ranking_all_nodes_included() {
        let zone = test_zone();
        let epoch = test_epoch();
        let nodes = vec![
            test_node("node-a"),
            test_node("node-b"),
            test_node("node-c"),
            test_node("node-d"),
        ];

        let ranked = rank_checkpoint_coordinators(&zone, &epoch, &nodes);

        assert_eq!(ranked.len(), nodes.len());
        // First in ranking should be the selected coordinator
        let coord = select_checkpoint_coordinator(&zone, &epoch, &nodes);
        assert_eq!(Some(&ranked[0]), coord.as_ref());
    }

    #[test]
    fn coordinator_ranking_order_preserved() {
        let zone = test_zone();
        let epoch = test_epoch();
        let nodes = vec![
            test_node("node-x"),
            test_node("node-y"),
            test_node("node-z"),
        ];

        let ranked1 = rank_checkpoint_coordinators(&zone, &epoch, &nodes);
        let ranked2 = rank_checkpoint_coordinators(&zone, &epoch, &nodes);

        assert_eq!(ranked1, ranked2);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Checkpoint Advancement State Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn advance_state_idle() {
        let state = CheckpointAdvanceState::idle(10, 1_700_000_000);

        assert!(!state.is_halted());
        assert!(state.can_advance());
        assert!(state.fork_evidence().is_none());
    }

    #[test]
    fn advance_state_halted() {
        let evidence = ForkEvidence::new(
            test_zone(),
            10,
            test_object_id("a"),
            test_object_id("b"),
            1_700_000_000,
            test_node("detector"),
        );
        let state = CheckpointAdvanceState::Halted {
            fork_evidence: evidence,
            halted_at: 1_700_000_001,
        };

        assert!(state.is_halted());
        assert!(!state.can_advance());
        assert!(state.fork_evidence().is_some());
        assert_eq!(state.fork_evidence().unwrap().conflicting_seq, 10);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Checkpoint Proposal Validation Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn proposal_seq_follows_prev() {
        let proposal = CheckpointProposal {
            zone_id: test_zone(),
            proposed_seq: 11,
            prev_checkpoint_id: Some(test_object_id("prev-chk")),
            audit_head_id: test_object_id("audit"),
            audit_head_seq: 100,
            revocation_head_id: test_object_id("rev"),
            revocation_head_seq: 50,
            zone_definition_head: test_object_id("zone-def"),
            zone_policy_head: test_object_id("policy"),
            active_zone_key_manifest: test_object_id("zkm"),
            epoch_id: test_epoch(),
            proposed_at: 1_700_000_000,
            coordinator: test_node("coord"),
            coordinator_signature: NodeSignature::new(
                NodeId::new("coord"),
                [0u8; 64],
                1_700_000_000,
            ),
            triggers: vec![],
        };

        assert!(proposal.seq_follows_prev(10));
        assert!(!proposal.seq_follows_prev(9));
        assert!(!proposal.seq_follows_prev(11));
    }

    #[test]
    fn proposal_seq_handles_overflow() {
        let proposal = CheckpointProposal {
            zone_id: test_zone(),
            proposed_seq: 0, // Would be u64::MAX + 1
            prev_checkpoint_id: None,
            audit_head_id: test_object_id("audit"),
            audit_head_seq: 100,
            revocation_head_id: test_object_id("rev"),
            revocation_head_seq: 50,
            zone_definition_head: test_object_id("zone-def"),
            zone_policy_head: test_object_id("policy"),
            active_zone_key_manifest: test_object_id("zkm"),
            epoch_id: test_epoch(),
            proposed_at: 1_700_000_000,
            coordinator: test_node("coord"),
            coordinator_signature: NodeSignature::new(
                NodeId::new("coord"),
                [0u8; 64],
                1_700_000_000,
            ),
            triggers: vec![],
        };

        // u64::MAX + 1 would overflow, so checked_add returns None
        assert!(!proposal.seq_follows_prev(u64::MAX));
    }

    #[test]
    fn proposal_timestamp_within_skew() {
        let proposal = CheckpointProposal {
            zone_id: test_zone(),
            proposed_seq: 1,
            prev_checkpoint_id: None,
            audit_head_id: test_object_id("audit"),
            audit_head_seq: 100,
            revocation_head_id: test_object_id("rev"),
            revocation_head_seq: 50,
            zone_definition_head: test_object_id("zone-def"),
            zone_policy_head: test_object_id("policy"),
            active_zone_key_manifest: test_object_id("zkm"),
            epoch_id: test_epoch(),
            proposed_at: 1_700_000_000,
            coordinator: test_node("coord"),
            coordinator_signature: NodeSignature::new(
                NodeId::new("coord"),
                [0u8; 64],
                1_700_000_000,
            ),
            triggers: vec![],
        };

        // Within skew
        assert!(proposal.timestamp_within_skew(1_700_000_005, 10));
        assert!(proposal.timestamp_within_skew(1_699_999_995, 10));
        // Exactly at boundary
        assert!(proposal.timestamp_within_skew(1_700_000_010, 10));
        // Outside skew
        assert!(!proposal.timestamp_within_skew(1_700_000_015, 10));
        assert!(!proposal.timestamp_within_skew(1_699_999_985, 10));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Validation Error Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn validation_error_reason_codes() {
        let errors = vec![
            (
                CheckpointValidationError::InvalidSequence {
                    expected: 10,
                    got: 12,
                },
                "FCP-5001",
            ),
            (
                CheckpointValidationError::TimestampSkew {
                    local_time: 100,
                    proposal_time: 200,
                    max_skew: 10,
                },
                "FCP-5002",
            ),
            (
                CheckpointValidationError::UnknownHead {
                    head_type: "audit".to_string(),
                    head_id: test_object_id("h"),
                },
                "FCP-5003",
            ),
            (
                CheckpointValidationError::InvalidHead {
                    head_type: "rev".to_string(),
                    head_id: test_object_id("h"),
                    reason: "bad".to_string(),
                },
                "FCP-5004",
            ),
            (
                CheckpointValidationError::NotCoordinator {
                    expected: test_node("a"),
                    got: test_node("b"),
                },
                "FCP-5005",
            ),
            (
                CheckpointValidationError::InvalidCoordinatorSignature,
                "FCP-5006",
            ),
            (
                CheckpointValidationError::ZoneMismatch {
                    expected: test_zone(),
                    got: ZoneId::public(),
                },
                "FCP-5007",
            ),
            (
                CheckpointValidationError::EpochMismatch {
                    expected: test_epoch(),
                    got: EpochId::new("other"),
                },
                "FCP-5008",
            ),
        ];

        for (error, expected_code) in errors {
            assert_eq!(error.reason_code(), expected_code);
            assert!(!error.is_fork());
        }

        // Fork error
        let fork_error = CheckpointValidationError::ForkDetected(ForkEvidence::new(
            test_zone(),
            10,
            test_object_id("a"),
            test_object_id("b"),
            1_700_000_000,
            test_node("d"),
        ));
        assert_eq!(fork_error.reason_code(), "FCP-5010");
        assert!(fork_error.is_fork());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Freshness Verification Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn freshness_token_fresh() {
        let result = FreshnessResult::check_token_freshness(5, 10, false);
        assert_eq!(result, FreshnessResult::Fresh);
        assert!(result.allows_operation());
    }

    #[test]
    fn freshness_token_stale_no_degraded() {
        let result = FreshnessResult::check_token_freshness(15, 10, false);
        assert_eq!(result, FreshnessResult::TooStale);
        assert!(!result.allows_operation());
    }

    #[test]
    fn freshness_token_stale_with_degraded() {
        let result = FreshnessResult::check_token_freshness(15, 10, true);
        assert_eq!(result, FreshnessResult::DegradedMode);
        assert!(result.allows_operation());
    }

    #[test]
    fn freshness_revocation_fresh() {
        let result = FreshnessResult::check_revocation_freshness(50, 40, false);
        assert_eq!(result, FreshnessResult::Fresh);
        assert!(result.allows_operation());
    }

    #[test]
    fn freshness_revocation_stale_no_degraded() {
        let result = FreshnessResult::check_revocation_freshness(30, 40, false);
        assert_eq!(result, FreshnessResult::TooStale);
        assert!(!result.allows_operation());
    }

    #[test]
    fn freshness_revocation_stale_with_degraded() {
        let result = FreshnessResult::check_revocation_freshness(30, 40, true);
        assert_eq!(result, FreshnessResult::DegradedMode);
        assert!(result.allows_operation());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden Vector Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn golden_hrw_checkpoint_hash() {
        // Deterministic golden vector for HRW hash
        let zone: ZoneId = "z:work".parse().unwrap();
        let epoch = EpochId::new("epoch-test-golden");
        let node = TailscaleNodeId::new("node-golden-test");

        let hash = hrw_hash_checkpoint(&zone, &epoch, &node);

        // This is a golden vector - if it changes, the hash algorithm changed
        let mut expected_hasher = blake3::Hasher::new();
        expected_hasher.update(b"FCP2-HRW-CHECKPOINT-V1");

        let z_bytes = zone.as_bytes();
        expected_hasher.update(
            &u32::try_from(z_bytes.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        expected_hasher.update(z_bytes);

        let e_bytes = epoch.as_str().as_bytes();
        expected_hasher.update(
            &u32::try_from(e_bytes.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        expected_hasher.update(e_bytes);

        let n_bytes = node.as_str().as_bytes();
        expected_hasher.update(
            &u32::try_from(n_bytes.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        expected_hasher.update(n_bytes);

        let expected_bytes = expected_hasher.finalize();
        let mut expected_buf = [0u8; 8];
        expected_buf.copy_from_slice(&expected_bytes.as_bytes()[0..8]);
        let expected_u64 = u64::from_le_bytes(expected_buf);

        assert_eq!(
            hash, expected_u64,
            "HRW checkpoint hash golden vector mismatch"
        );
    }

    #[test]
    fn golden_coordinator_selection() {
        // Deterministic coordinator selection test
        let zone: ZoneId = "z:work".parse().unwrap();
        let epoch = EpochId::new("epoch-golden");
        let nodes = vec![
            TailscaleNodeId::new("node-alice"),
            TailscaleNodeId::new("node-bob"),
            TailscaleNodeId::new("node-charlie"),
        ];

        let coord = select_checkpoint_coordinator(&zone, &epoch, &nodes).unwrap();

        // Golden vector - the winning coordinator for this input
        // If this changes, HRW selection semantics changed
        assert_eq!(
            coord.as_str(),
            "node-charlie",
            "Coordinator selection golden vector mismatch"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Constants
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn default_checkpoint_interval_is_60() {
        assert_eq!(DEFAULT_CHECKPOINT_INTERVAL_SECS, 60);
    }

    #[test]
    fn default_audit_chain_growth_threshold_is_100() {
        assert_eq!(DEFAULT_AUDIT_CHAIN_GROWTH_THRESHOLD, 100);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CheckpointTrigger – additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn trigger_clone_preserves_equality() {
        let trigger = CheckpointTrigger::TimeElapsed {
            elapsed_secs: 120,
            threshold_secs: 60,
        };
        let cloned = trigger.clone();
        assert_eq!(trigger, cloned);
    }

    #[test]
    fn trigger_manual_none_reason_serde() {
        let trigger = CheckpointTrigger::Manual { reason: None };
        let json = serde_json::to_string(&trigger).unwrap();
        let decoded: CheckpointTrigger = serde_json::from_str(&json).unwrap();
        assert_eq!(trigger, decoded);
        if let CheckpointTrigger::Manual { reason } = decoded {
            assert!(reason.is_none());
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn trigger_inequality_across_variants() {
        let a = CheckpointTrigger::TimeElapsed {
            elapsed_secs: 120,
            threshold_secs: 60,
        };
        let b = CheckpointTrigger::RevocationChainGrowth { new_events: 1 };
        assert_ne!(a, b);
    }

    #[test]
    fn trigger_audit_growth_boundary_not_met() {
        // Exactly at threshold - should NOT trigger (must exceed)
        let trigger = CheckpointTrigger::check_audit_growth(100, 100);
        assert!(trigger.is_none());
    }

    #[test]
    fn trigger_revocation_growth_large_count() {
        let trigger = CheckpointTrigger::check_revocation_growth(u64::MAX);
        assert!(trigger.is_some());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ForkEvidence – additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn fork_evidence_clone() {
        let evidence = ForkEvidence::new(
            test_zone(),
            5,
            test_object_id("a"),
            test_object_id("b"),
            1_700_000_000,
            test_node("det"),
        );
        let cloned = evidence.clone();
        assert_eq!(evidence, cloned);
    }

    #[test]
    fn fork_evidence_double_signers_no_overlap() {
        let evidence = ForkEvidence::new(
            test_zone(),
            1,
            test_object_id("x"),
            test_object_id("y"),
            100,
            test_node("d"),
        )
        .with_signers_a(["alice".to_string()])
        .with_signers_b(["bob".to_string()]);
        assert!(evidence.double_signers().is_empty());
    }

    #[test]
    fn fork_evidence_double_signers_empty_sets() {
        let evidence = ForkEvidence::new(
            test_zone(),
            1,
            test_object_id("x"),
            test_object_id("y"),
            100,
            test_node("d"),
        );
        assert!(evidence.signers_a.is_empty());
        assert!(evidence.signers_b.is_empty());
        assert!(evidence.double_signers().is_empty());
    }

    #[test]
    fn fork_evidence_serde_roundtrip() {
        let evidence = ForkEvidence::new(
            test_zone(),
            99,
            test_object_id("cp-a"),
            test_object_id("cp-b"),
            1_700_000_000,
            test_node("detector"),
        )
        .with_signers_a(["node1".to_string()])
        .with_signers_b(["node2".to_string()]);
        let json = serde_json::to_string(&evidence).unwrap();
        let decoded: ForkEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(evidence, decoded);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ForkDetectionResult – additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn fork_detection_result_no_fork_serde() {
        let result = ForkDetectionResult::NoFork;
        let json = serde_json::to_string(&result).unwrap();
        let decoded: ForkDetectionResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, decoded);
        assert!(!decoded.is_fork());
    }

    #[test]
    fn fork_detection_result_fork_detected_serde() {
        let evidence = ForkEvidence::new(
            test_zone(),
            7,
            test_object_id("a"),
            test_object_id("b"),
            100,
            test_node("d"),
        );
        let result = ForkDetectionResult::ForkDetected(evidence);
        let json = serde_json::to_string(&result).unwrap();
        let decoded: ForkDetectionResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, decoded);
        assert!(decoded.is_fork());
    }

    #[test]
    fn fork_detection_result_clone() {
        let evidence = ForkEvidence::new(
            test_zone(),
            7,
            test_object_id("a"),
            test_object_id("b"),
            100,
            test_node("d"),
        );
        let result = ForkDetectionResult::ForkDetected(evidence);
        let cloned = result.clone();
        assert_eq!(result, cloned);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CheckpointAdvanceState – serde all variants
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn advance_state_idle_serde() {
        let state = CheckpointAdvanceState::idle(5, 1_700_000_000);
        let json = serde_json::to_string(&state).unwrap();
        let decoded: CheckpointAdvanceState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, decoded);
    }

    #[test]
    fn advance_state_triggered_serde() {
        let state = CheckpointAdvanceState::TriggeredAwaitingCoordinator {
            trigger: CheckpointTrigger::RevocationChainGrowth { new_events: 3 },
            triggered_at: 1_700_000_050,
        };
        let json = serde_json::to_string(&state).unwrap();
        let decoded: CheckpointAdvanceState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, decoded);
        assert!(decoded.can_advance());
    }

    #[test]
    fn advance_state_finalized_serde() {
        let state = CheckpointAdvanceState::Finalized {
            checkpoint_id: test_object_id("final-chk"),
            finalized_seq: 42,
            finalized_at: 1_700_001_000,
        };
        let json = serde_json::to_string(&state).unwrap();
        let decoded: CheckpointAdvanceState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, decoded);
        assert!(!decoded.is_halted());
        assert!(decoded.can_advance());
        assert!(decoded.fork_evidence().is_none());
    }

    #[test]
    fn advance_state_halted_serde() {
        let evidence = ForkEvidence::new(
            test_zone(),
            10,
            test_object_id("a"),
            test_object_id("b"),
            1_700_000_000,
            test_node("d"),
        );
        let state = CheckpointAdvanceState::Halted {
            fork_evidence: evidence,
            halted_at: 1_700_000_001,
        };
        let json = serde_json::to_string(&state).unwrap();
        let decoded: CheckpointAdvanceState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, decoded);
        assert!(decoded.is_halted());
    }

    #[test]
    fn advance_state_clone() {
        let state = CheckpointAdvanceState::idle(0, 0);
        let cloned = state.clone();
        assert_eq!(state, cloned);
    }

    #[test]
    fn advance_state_triggered_can_advance() {
        let state = CheckpointAdvanceState::TriggeredAwaitingCoordinator {
            trigger: CheckpointTrigger::Manual {
                reason: Some("test".into()),
            },
            triggered_at: 0,
        };
        assert!(state.can_advance());
        assert!(!state.is_halted());
        assert!(state.fork_evidence().is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CheckpointValidationError – additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn validation_error_invalid_sequence_serde() {
        let err = CheckpointValidationError::InvalidSequence {
            expected: 10,
            got: 12,
        };
        let json = serde_json::to_string(&err).unwrap();
        let decoded: CheckpointValidationError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, decoded);
    }

    #[test]
    fn validation_error_timestamp_skew_serde() {
        let err = CheckpointValidationError::TimestampSkew {
            local_time: 100,
            proposal_time: 200,
            max_skew: 10,
        };
        let json = serde_json::to_string(&err).unwrap();
        let decoded: CheckpointValidationError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, decoded);
    }

    #[test]
    fn validation_error_not_coordinator_serde() {
        let err = CheckpointValidationError::NotCoordinator {
            expected: test_node("a"),
            got: test_node("b"),
        };
        let json = serde_json::to_string(&err).unwrap();
        let decoded: CheckpointValidationError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, decoded);
    }

    #[test]
    fn validation_error_invalid_coordinator_signature_serde() {
        let err = CheckpointValidationError::InvalidCoordinatorSignature;
        let json = serde_json::to_string(&err).unwrap();
        let decoded: CheckpointValidationError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, decoded);
    }

    #[test]
    fn validation_error_zone_mismatch_serde() {
        let err = CheckpointValidationError::ZoneMismatch {
            expected: test_zone(),
            got: ZoneId::public(),
        };
        let json = serde_json::to_string(&err).unwrap();
        let decoded: CheckpointValidationError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, decoded);
    }

    #[test]
    fn validation_error_epoch_mismatch_serde() {
        let err = CheckpointValidationError::EpochMismatch {
            expected: test_epoch(),
            got: EpochId::new("other"),
        };
        let json = serde_json::to_string(&err).unwrap();
        let decoded: CheckpointValidationError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, decoded);
    }

    #[test]
    fn validation_error_fork_detected_serde() {
        let err = CheckpointValidationError::ForkDetected(ForkEvidence::new(
            test_zone(),
            10,
            test_object_id("a"),
            test_object_id("b"),
            100,
            test_node("d"),
        ));
        let json = serde_json::to_string(&err).unwrap();
        let decoded: CheckpointValidationError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, decoded);
        assert!(decoded.is_fork());
    }

    #[test]
    fn validation_error_clone() {
        let err = CheckpointValidationError::InvalidSequence {
            expected: 1,
            got: 2,
        };
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FreshnessResult – additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn freshness_result_copy() {
        let a = FreshnessResult::Fresh;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn freshness_result_serde_all_variants() {
        for variant in [
            FreshnessResult::Fresh,
            FreshnessResult::DegradedMode,
            FreshnessResult::TooStale,
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let decoded: FreshnessResult = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, decoded);
        }
    }

    #[test]
    fn freshness_token_boundary_equal_seq_is_fresh() {
        // token_chk_seq == local_checkpoint_seq → Fresh
        let result = FreshnessResult::check_token_freshness(10, 10, false);
        assert_eq!(result, FreshnessResult::Fresh);
    }

    #[test]
    fn freshness_revocation_boundary_equal_seq_is_fresh() {
        // local_rev_head_seq == policy_min_rev_seq → Fresh
        let result = FreshnessResult::check_revocation_freshness(40, 40, false);
        assert_eq!(result, FreshnessResult::Fresh);
    }

    #[test]
    fn freshness_allows_operation_all_variants() {
        assert!(FreshnessResult::Fresh.allows_operation());
        assert!(FreshnessResult::DegradedMode.allows_operation());
        assert!(!FreshnessResult::TooStale.allows_operation());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CheckpointProposal – additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn proposal_clone() {
        let proposal = CheckpointProposal {
            zone_id: test_zone(),
            proposed_seq: 1,
            prev_checkpoint_id: None,
            audit_head_id: test_object_id("audit"),
            audit_head_seq: 100,
            revocation_head_id: test_object_id("rev"),
            revocation_head_seq: 50,
            zone_definition_head: test_object_id("zone-def"),
            zone_policy_head: test_object_id("policy"),
            active_zone_key_manifest: test_object_id("zkm"),
            epoch_id: test_epoch(),
            proposed_at: 1_700_000_000,
            coordinator: test_node("coord"),
            coordinator_signature: NodeSignature::new(
                NodeId::new("coord"),
                [0u8; 64],
                1_700_000_000,
            ),
            triggers: vec![CheckpointTrigger::Manual { reason: None }],
        };
        let cloned = proposal.clone();
        assert_eq!(proposal, cloned);
    }

    #[test]
    fn proposal_serde_roundtrip() {
        let proposal = CheckpointProposal {
            zone_id: test_zone(),
            proposed_seq: 5,
            prev_checkpoint_id: Some(test_object_id("prev")),
            audit_head_id: test_object_id("audit"),
            audit_head_seq: 200,
            revocation_head_id: test_object_id("rev"),
            revocation_head_seq: 75,
            zone_definition_head: test_object_id("zone-def"),
            zone_policy_head: test_object_id("policy"),
            active_zone_key_manifest: test_object_id("zkm"),
            epoch_id: test_epoch(),
            proposed_at: 1_700_000_000,
            coordinator: test_node("coord"),
            coordinator_signature: NodeSignature::new(
                NodeId::new("coord"),
                [0u8; 64],
                1_700_000_000,
            ),
            triggers: vec![
                CheckpointTrigger::TimeElapsed {
                    elapsed_secs: 120,
                    threshold_secs: 60,
                },
                CheckpointTrigger::RevocationChainGrowth { new_events: 3 },
            ],
        };
        let json = serde_json::to_string(&proposal).unwrap();
        let decoded: CheckpointProposal = serde_json::from_str(&json).unwrap();
        assert_eq!(proposal, decoded);
    }

    #[test]
    fn proposal_seq_follows_genesis() {
        let proposal = CheckpointProposal {
            zone_id: test_zone(),
            proposed_seq: 1,
            prev_checkpoint_id: None,
            audit_head_id: test_object_id("audit"),
            audit_head_seq: 0,
            revocation_head_id: test_object_id("rev"),
            revocation_head_seq: 0,
            zone_definition_head: test_object_id("zone-def"),
            zone_policy_head: test_object_id("policy"),
            active_zone_key_manifest: test_object_id("zkm"),
            epoch_id: test_epoch(),
            proposed_at: 1_700_000_000,
            coordinator: test_node("coord"),
            coordinator_signature: NodeSignature::new(
                NodeId::new("coord"),
                [0u8; 64],
                1_700_000_000,
            ),
            triggers: vec![],
        };
        // Genesis: prev_seq = 0, proposed_seq = 1
        assert!(proposal.seq_follows_prev(0));
    }

    #[test]
    fn proposal_timestamp_within_skew_zero_skew() {
        let proposal = CheckpointProposal {
            zone_id: test_zone(),
            proposed_seq: 1,
            prev_checkpoint_id: None,
            audit_head_id: test_object_id("audit"),
            audit_head_seq: 0,
            revocation_head_id: test_object_id("rev"),
            revocation_head_seq: 0,
            zone_definition_head: test_object_id("zone-def"),
            zone_policy_head: test_object_id("policy"),
            active_zone_key_manifest: test_object_id("zkm"),
            epoch_id: test_epoch(),
            proposed_at: 1_700_000_000,
            coordinator: test_node("coord"),
            coordinator_signature: NodeSignature::new(
                NodeId::new("coord"),
                [0u8; 64],
                1_700_000_000,
            ),
            triggers: vec![],
        };
        // Zero skew: only exact match
        assert!(proposal.timestamp_within_skew(1_700_000_000, 0));
        assert!(!proposal.timestamp_within_skew(1_700_000_001, 0));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Coordinator ranking – edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn coordinator_ranking_single_node() {
        let zone = test_zone();
        let epoch = test_epoch();
        let nodes = vec![test_node("only-node")];
        let ranked = rank_checkpoint_coordinators(&zone, &epoch, &nodes);
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].as_str(), "only-node");
    }

    #[test]
    fn coordinator_ranking_empty_nodes() {
        let zone = test_zone();
        let epoch = test_epoch();
        let nodes: Vec<TailscaleNodeId> = vec![];
        let ranked = rank_checkpoint_coordinators(&zone, &epoch, &nodes);
        assert!(ranked.is_empty());
    }

    #[test]
    fn coordinator_selection_single_node() {
        let zone = test_zone();
        let epoch = test_epoch();
        let nodes = vec![test_node("solo")];
        let coord = select_checkpoint_coordinator(&zone, &epoch, &nodes);
        assert_eq!(coord.unwrap().as_str(), "solo");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden Vector Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn golden_fork_evidence_serialization() {
        let evidence = ForkEvidence {
            zone_id: "z:work".parse().unwrap(),
            conflicting_seq: 42,
            checkpoint_a: ObjectId::from_bytes([0xAA; 32]),
            checkpoint_b: ObjectId::from_bytes([0xBB; 32]),
            detected_at: 1_700_000_000,
            detected_by: TailscaleNodeId::new("detector-node"),
            signers_a: ["alice".to_string(), "bob".to_string()]
                .into_iter()
                .collect(),
            signers_b: ["bob".to_string(), "charlie".to_string()]
                .into_iter()
                .collect(),
        };

        let json = serde_json::to_string(&evidence).unwrap();
        let decoded: ForkEvidence = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.conflicting_seq, 42);
        assert_eq!(
            decoded.double_signers(),
            std::iter::once("bob".to_string()).collect()
        );
    }
}
