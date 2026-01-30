//! Distributed lease coordination (NORMATIVE).
//!
//! Implements the lease semantics defined in `FCP_Specification_V2.md` §10.
//!
//! # Core Concepts
//!
//! - **Lease**: Exclusive, timed ownership of a (zone, subject) pair.
//! - **Fencing Token**: `lease_seq` ensures monotonicity and fencing of stale writes.
//! - **Granularity**: Leases are per-object or per-singleton-role.
//!
//! # Invariants
//!
//! - `ConnectorState` writes (`singleton_writer` fencing)
//! - `ZoneCheckpoint` advancement (coordinator election)
//! - Exclusive resource access (e.g., specific hardware)
use fcp_cbor::SchemaId;
use serde::{Deserialize, Serialize};

use crate::{ObjectHeader, ObjectId, SignatureSet, TailscaleNodeId, ZoneId};

/// Get current Unix timestamp in seconds.
///
/// # Panics
/// Panics if system time is before Unix epoch (should be impossible).
#[must_use]
pub fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs()
}

// ─────────────────────────────────────────────────────────────────────────────
// Lease Purpose (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// Lease purpose discriminant (NORMATIVE).
///
/// Defines what a lease authorizes. Each purpose has specific semantics:
///
/// - `OperationExecution`: Prevents duplicate execution of operations with side effects.
///   Used by the exactly-once semantics system (see §15 OperationIntent/Receipt).
///
/// - `ConnectorStateWrite`: Serializes writes to `SingleWriter` connector state.
///   Only the lease holder may write to the associated state object.
///
/// - `ComputationMigration`: Coordinates computation migration between nodes.
///   Ensures safe handoffs during device changes or load balancing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeasePurpose {
    /// Prevents duplicate execution of operations with side effects.
    OperationExecution,
    /// Serializes writes to `SingleWriter` connector state.
    ConnectorStateWrite,
    /// Coordinates computation migration between nodes.
    ComputationMigration,
    /// Elects a coordinator for a zone.
    CoordinatorElection,
    /// Locks a computation for migration.
    Migration,
    /// Exclusive access to a resource.
    ResourceAccess,
}

impl std::fmt::Display for LeasePurpose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OperationExecution => write!(f, "operation_execution"),
            Self::ConnectorStateWrite => write!(f, "connector_state_write"),
            Self::ComputationMigration => write!(f, "computation_migration"),
            Self::CoordinatorElection => write!(f, "coordinator_election"),
            Self::Migration => write!(f, "migration"),
            Self::ResourceAccess => write!(f, "resource_access"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lease (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// Generic lease primitive (NORMATIVE).
///
/// A short-lived, renewable lock that says:
/// "node X owns subject S for purpose P until time T."
///
/// # Fencing Token Semantics
///
/// The `lease_seq` is critical for safety:
/// - Monotonically increases per (`zone_id`, `subject_object_id`)
/// - Higher `lease_seq` wins deterministically, regardless of wall-clock expiry
/// - Prevents "zombie lease" problems
///
/// # Coordinator Selection
///
/// The coordinator is selected via HRW/Rendezvous hashing over
/// `(zone_id, subject_object_id)`. This ensures deterministic, consistent
/// selection without a central coordinator.
///
/// # Quorum Requirements
///
/// - Safe ops: Single coordinator signature may be sufficient
/// - Risky ops: Require f+1 signatures
/// - Dangerous ops: Require n-f signatures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    /// Object header (includes zone, schema, etc).
    pub header: ObjectHeader,

    /// Node holding the lease.
    pub holder: TailscaleNodeId,

    /// Lease sequence number (monotonic).
    ///
    /// - Monotonically increases per (`zone_id`, `subject_object_id`)
    /// - Higher `lease_seq` wins deterministically, regardless of wall-clock expiry
    pub lease_seq: u64,

    /// Expiration timestamp (Unix seconds).
    pub exp: u64,

    /// Subject being leased (e.g., connector state ID).
    pub subject_object_id: ObjectId,

    /// What this lease authorizes.
    pub purpose: LeasePurpose,

    /// Quorum signatures (NORMATIVE for Risky/Dangerous).
    pub quorum_signatures: SignatureSet,
}

/// Input parameters for creating a new lease.
#[derive(Debug, Clone)]
pub struct LeaseParams {
    pub schema: SchemaId,
    pub zone_id: ZoneId,
    pub holder: TailscaleNodeId,
    pub lease_seq: u64,
    pub ttl_secs: u32,
    pub subject_object_id: ObjectId,
    pub provenance: crate::Provenance,
    pub purpose: LeasePurpose,
    pub quorum_signatures: SignatureSet,
}

impl Lease {
    /// Create a new lease.
    #[must_use]
    pub fn new(params: LeaseParams) -> Self {
        let created_at = current_timestamp();
        let exp = created_at + u64::from(params.ttl_secs);

        Self {
            header: ObjectHeader {
                schema: params.schema,
                zone_id: params.zone_id,
                created_at,
                provenance: params.provenance,
                refs: vec![params.subject_object_id], // Lease implicitly refs subject
                foreign_refs: vec![],
                ttl_secs: Some(u64::from(params.ttl_secs)),
                placement: None,
            },
            holder: params.holder,
            lease_seq: params.lease_seq,
            exp,
            subject_object_id: params.subject_object_id,
            purpose: params.purpose,
            quorum_signatures: params.quorum_signatures,
        }
    }

    /// Fencing token (NORMATIVE): monotonically increases per (`zone_id`, `subject_object_id`).
    #[must_use]
    pub const fn fencing_token(&self) -> u64 {
        self.lease_seq
    }

    /// Check if expired.
    #[must_use]
    pub const fn is_expired(&self, now: u64) -> bool {
        now >= self.exp
    }

    /// Get the zone ID.
    #[must_use]
    pub const fn zone_id(&self) -> &ZoneId {
        &self.header.zone_id
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lease Request
// ─────────────────────────────────────────────────────────────────────────────

/// Request to acquire or renew a lease.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseRequest {
    /// Subject to lease.
    pub subject_object_id: ObjectId,

    /// Zone ID.
    pub zone_id: ZoneId,

    /// Requesting node.
    pub requester: TailscaleNodeId,

    /// Requested TTL in seconds.
    pub requested_ttl: u32,

    /// If renewing, the current `lease_seq` being held.
    pub renew_seq: Option<u64>,
}

/// Response to a lease request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LeaseResponse {
    /// Lease granted.
    Granted(Box<Lease>),

    /// Lease denied (held by another or stale renew).
    Denied {
        /// Current lease holder.
        current_holder: TailscaleNodeId,
        /// When the current lease expires.
        expires_at: u64,
        /// Current `lease_seq` (for information).
        current_seq: u64,
    },

    /// Request invalid (e.g., wrong zone).
    Invalid { reason: String },
}

// ─────────────────────────────────────────────────────────────────────────────
// HRW Coordinator Selection (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// Compute HRW (Highest Random Weight) hash for coordinator selection.
///
/// This provides deterministic, consistent coordinator selection without
/// a central coordinator.
fn hrw_hash(zone_id: &ZoneId, subject_id: &ObjectId, node_id: &TailscaleNodeId) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"FCP2-HRW-V1");
    hasher.update(zone_id.as_bytes());
    hasher.update(subject_id.as_bytes());
    hasher.update(node_id.as_str().as_bytes());

    let hash = hasher.finalize();
    let bytes = hash.as_bytes();

    // Take the first 8 bytes as a u64 for comparison
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

/// Select the coordinator for a lease using HRW/Rendezvous hashing.
///
/// # Arguments
///
/// * `zone_id` - The zone context
/// * `subject_id` - The object being leased
/// * `nodes` - List of eligible nodes
///
/// # Returns
///
/// The node with the highest HRW hash, or `None` if no nodes are available.
///
/// # Determinism
///
/// This function is fully deterministic - given the same inputs, all nodes
/// will select the same coordinator. This is essential for distributed
/// coordination without explicit communication.
#[must_use]
pub fn select_coordinator(
    zone_id: &ZoneId,
    subject_id: &ObjectId,
    nodes: &[TailscaleNodeId],
) -> Option<TailscaleNodeId> {
    nodes
        .iter()
        .max_by_key(|n| hrw_hash(zone_id, subject_id, n))
        .cloned()
}

/// Get all nodes ranked by HRW score for a subject.
///
/// This is useful for determining failover order when the primary
/// coordinator is unavailable.
#[must_use]
pub fn rank_nodes_by_hrw(
    zone_id: &ZoneId,
    subject_id: &ObjectId,
    nodes: &[TailscaleNodeId],
) -> Vec<TailscaleNodeId> {
    let mut scored: Vec<_> = nodes
        .iter()
        .map(|n| (hrw_hash(zone_id, subject_id, n), n.clone()))
        .collect();
    // Sort descending by score
    scored.sort_by_key(|item| std::cmp::Reverse(item.0));
    scored.into_iter().map(|(_, n)| n).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Lease Validation
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned when lease validation fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseValidationError {
    /// Lease has expired.
    Expired { expired_at: u64, now: u64 },

    /// Lease is for wrong subject.
    SubjectMismatch { expected: ObjectId, got: ObjectId },

    /// Lease is for wrong zone.
    ZoneMismatch { expected: ZoneId, got: ZoneId },

    /// Lease is for wrong purpose.
    PurposeMismatch {
        expected: LeasePurpose,
        got: LeasePurpose,
    },

    /// Lease has been superseded by a newer lease.
    Superseded { held_seq: u64, current_seq: u64 },

    /// Coordinator mismatch (wrong coordinator signed).
    CoordinatorMismatch {
        expected: TailscaleNodeId,
        got: TailscaleNodeId,
    },

    /// Insufficient quorum signatures.
    InsufficientQuorum { required: usize, got: usize },
}

impl std::fmt::Display for LeaseValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Expired { expired_at, now } => {
                write!(f, "lease expired at {expired_at}, current time is {now}")
            }
            Self::SubjectMismatch { expected, got } => {
                write!(f, "subject mismatch: expected {expected}, got {got}")
            }
            Self::ZoneMismatch { expected, got } => {
                write!(f, "zone mismatch: expected {expected}, got {got}")
            }
            Self::PurposeMismatch { expected, got } => {
                write!(f, "purpose mismatch: expected {expected}, got {got}")
            }
            Self::Superseded {
                held_seq,
                current_seq,
            } => {
                write!(
                    f,
                    "lease superseded: held seq {held_seq}, current seq {current_seq}"
                )
            }
            Self::CoordinatorMismatch { expected, got } => {
                write!(
                    f,
                    "coordinator mismatch: expected {}, got {}",
                    expected.as_str(),
                    got.as_str()
                )
            }
            Self::InsufficientQuorum { required, got } => {
                write!(
                    f,
                    "insufficient quorum: required {required} signatures, got {got}"
                )
            }
        }
    }
}

impl std::error::Error for LeaseValidationError {}

/// Validate a lease for use.
///
/// # Arguments
///
/// * `lease` - The lease to validate
/// * `expected_subject` - Expected subject object ID
/// * `expected_zone` - Expected zone ID
/// * `expected_purpose` - Expected purpose
/// * `current_known_seq` - The highest `lease_seq` known for this subject
/// * `now` - Current timestamp
/// * `required_signatures` - Minimum required quorum signatures
///
/// # Errors
///
/// Returns an error if validation fails.
pub fn validate_lease(
    lease: &Lease,
    expected_subject: &ObjectId,
    expected_zone: &ZoneId,
    expected_purpose: LeasePurpose,
    current_known_seq: u64,
    now: u64,
    required_signatures: usize,
) -> Result<(), LeaseValidationError> {
    // Check expiry
    if lease.is_expired(now) {
        return Err(LeaseValidationError::Expired {
            expired_at: lease.exp,
            now,
        });
    }

    // Check subject
    if &lease.subject_object_id != expected_subject {
        return Err(LeaseValidationError::SubjectMismatch {
            expected: *expected_subject,
            got: lease.subject_object_id,
        });
    }

    // Check zone
    if lease.zone_id() != expected_zone {
        return Err(LeaseValidationError::ZoneMismatch {
            expected: expected_zone.clone(),
            got: lease.zone_id().clone(),
        });
    }

    // Check purpose
    if lease.purpose != expected_purpose {
        return Err(LeaseValidationError::PurposeMismatch {
            expected: expected_purpose,
            got: lease.purpose,
        });
    }

    // Check if superseded (NORMATIVE: higher seq wins)
    if lease.lease_seq < current_known_seq {
        return Err(LeaseValidationError::Superseded {
            held_seq: lease.lease_seq,
            current_seq: current_known_seq,
        });
    }

    // Check quorum
    let sig_count = lease.quorum_signatures.len();
    if sig_count < required_signatures {
        return Err(LeaseValidationError::InsufficientQuorum {
            required: required_signatures,
            got: sig_count,
        });
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_node(name: &str) -> TailscaleNodeId {
        TailscaleNodeId::new(name)
    }

    fn test_zone() -> ZoneId {
        ZoneId::work()
    }

    fn test_object_id(name: &str) -> ObjectId {
        ObjectId::from_unscoped_bytes(name.as_bytes())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HRW Coordinator Selection Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_hrw_deterministic() {
        let zone = test_zone();
        let subject = test_object_id("test-subject");
        let nodes = vec![
            test_node("node-a"),
            test_node("node-b"),
            test_node("node-c"),
        ];

        // Same inputs should always produce same output
        let coord1 = select_coordinator(&zone, &subject, &nodes);
        let coord2 = select_coordinator(&zone, &subject, &nodes);
        assert_eq!(coord1, coord2);

        // Should not be None with non-empty nodes
        assert!(coord1.is_some());
    }

    #[test]
    fn test_hrw_empty_nodes() {
        let zone = test_zone();
        let subject = test_object_id("test-subject");
        let nodes: Vec<TailscaleNodeId> = vec![];

        assert!(select_coordinator(&zone, &subject, &nodes).is_none());
    }

    #[test]
    fn test_hrw_single_node() {
        let zone = test_zone();
        let subject = test_object_id("test-subject");
        let nodes = vec![test_node("only-node")];

        let coord = select_coordinator(&zone, &subject, &nodes);
        assert_eq!(coord, Some(test_node("only-node")));
    }

    #[test]
    fn test_hrw_different_subjects_different_coordinators() {
        let zone = test_zone();
        let nodes = vec![
            test_node("node-a"),
            test_node("node-b"),
            test_node("node-c"),
            test_node("node-d"),
            test_node("node-e"),
        ];

        // Different subjects may (probabilistically) get different coordinators
        let subjects: Vec<_> = (0..20)
            .map(|i| test_object_id(&format!("subject-{i}")))
            .collect();

        let coords: Vec<_> = subjects
            .iter()
            .map(|s| select_coordinator(&zone, s, &nodes))
            .collect();

        // Not all coordinators should be the same (with high probability)
        let first = &coords[0];
        let all_same = coords.iter().all(|c| c == first);

        // This is probabilistic but should pass with overwhelming probability
        assert!(!all_same, "HRW should distribute load across nodes");
    }

    #[test]
    fn test_rank_nodes_ordering() {
        let zone = test_zone();
        let subject = test_object_id("test-subject");
        let nodes = vec![
            test_node("node-a"),
            test_node("node-b"),
            test_node("node-c"),
        ];

        let ranked = rank_nodes_by_hrw(&zone, &subject, &nodes);

        // Ranked should have same length as input
        assert_eq!(ranked.len(), nodes.len());

        // First ranked node should be the coordinator
        let coord = select_coordinator(&zone, &subject, &nodes);
        assert_eq!(Some(&ranked[0]), coord.as_ref());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Lease Fencing Token Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_lease_fencing_token_higher_wins() {
        let lease1 = create_test_lease(10);
        let lease2 = create_test_lease(20);

        // Higher fencing token wins
        assert!(lease2.fencing_token() > lease1.fencing_token());
    }

    #[test]
    fn test_lease_fencing_token_equal() {
        let lease1 = create_test_lease(10);
        let lease2 = create_test_lease(10);

        // Same fencing token
        assert_eq!(lease1.fencing_token(), lease2.fencing_token());
    }

    #[test]
    fn test_lease_expiry() {
        let lease = create_test_lease_with_exp(1, 2000);

        // Before expiry
        assert!(!lease.is_expired(1500));

        // At expiry
        assert!(lease.is_expired(2000));

        // After expiry
        assert!(lease.is_expired(2500));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Lease Validation Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_validate_lease_success() {
        let subject = test_object_id("subject");
        let zone = test_zone();
        let lease = create_test_lease_with_subject(5, 2000, subject);

        let result = validate_lease(
            &lease,
            &subject,
            &zone,
            LeasePurpose::OperationExecution,
            5,    // current_known_seq
            1500, // now (before expiry)
            0,    // no signatures required
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_lease_expired() {
        let subject = test_object_id("subject");
        let zone = test_zone();
        let lease = create_test_lease_with_subject(5, 2000, subject);

        let result = validate_lease(
            &lease,
            &subject,
            &zone,
            LeasePurpose::OperationExecution,
            5,
            2500, // now > exp
            0,
        );

        assert!(matches!(result, Err(LeaseValidationError::Expired { .. })));
    }

    #[test]
    fn test_validate_lease_superseded() {
        let subject = test_object_id("subject");
        let zone = test_zone();
        let lease = create_test_lease_with_subject(5, 2000, subject);

        let result = validate_lease(
            &lease,
            &subject,
            &zone,
            LeasePurpose::OperationExecution,
            10, // current_known_seq > lease.lease_seq
            1500,
            0,
        );

        assert!(matches!(
            result,
            Err(LeaseValidationError::Superseded { .. })
        ));
    }

    #[test]
    fn test_validate_lease_purpose_mismatch() {
        let subject = test_object_id("subject");
        let zone = test_zone();
        let lease = create_test_lease_with_subject(5, 2000, subject);

        let result = validate_lease(
            &lease,
            &subject,
            &zone,
            LeasePurpose::ConnectorStateWrite, // Wrong purpose
            5,
            1500,
            0,
        );

        assert!(matches!(
            result,
            Err(LeaseValidationError::PurposeMismatch { .. })
        ));
    }

    #[test]
    fn test_validate_lease_subject_mismatch() {
        let subject = test_object_id("subject");
        let wrong_subject = test_object_id("wrong-subject");
        let zone = test_zone();
        let lease = create_test_lease_with_subject(5, 2000, subject);

        let result = validate_lease(
            &lease,
            &wrong_subject,
            &zone,
            LeasePurpose::OperationExecution,
            5,
            1500,
            0,
        );

        assert!(matches!(
            result,
            Err(LeaseValidationError::SubjectMismatch { .. })
        ));
    }

    #[test]
    fn test_validate_lease_zone_mismatch() {
        let subject = test_object_id("subject");
        // Lease is created with test_zone() (work), but we validate against private
        let wrong_zone = ZoneId::private();
        let lease = create_test_lease_with_subject(5, 2000, subject);

        let result = validate_lease(
            &lease,
            &subject,
            &wrong_zone,
            LeasePurpose::OperationExecution,
            5,
            1500,
            0,
        );

        assert!(matches!(
            result,
            Err(LeaseValidationError::ZoneMismatch { .. })
        ));
    }

    #[test]
    fn test_validate_lease_insufficient_quorum() {
        let subject = test_object_id("subject");
        let zone = test_zone();
        let lease = create_test_lease_with_subject(5, 2000, subject);

        let result = validate_lease(
            &lease,
            &subject,
            &zone,
            LeasePurpose::OperationExecution,
            5,
            1500,
            3, // requires 3 signatures, but lease has none
        );

        assert!(matches!(
            result,
            Err(LeaseValidationError::InsufficientQuorum {
                required: 3,
                got: 0
            })
        ));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LeaseValidationError Display Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_lease_validation_error_display() {
        let err = LeaseValidationError::Expired {
            expired_at: 1000,
            now: 2000,
        };
        assert!(err.to_string().contains("expired"));

        let err = LeaseValidationError::Superseded {
            held_seq: 5,
            current_seq: 10,
        };
        assert!(err.to_string().contains("superseded"));

        let err = LeaseValidationError::InsufficientQuorum {
            required: 3,
            got: 1,
        };
        assert!(err.to_string().contains("quorum"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HRW Coordinator Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_hrw_node_addition_minimal_disruption() {
        let zone = test_zone();
        let subject = test_object_id("test-subject");

        let original_nodes = vec![
            test_node("node-a"),
            test_node("node-b"),
            test_node("node-c"),
        ];

        let coord_before = select_coordinator(&zone, &subject, &original_nodes);

        // Add a new node
        let mut nodes_with_new = original_nodes;
        nodes_with_new.push(test_node("node-d"));

        let coord_after = select_coordinator(&zone, &subject, &nodes_with_new);

        // Either coordinator is the same OR it's the new node
        // (HRW provides minimal disruption on node addition)
        assert!(
            coord_before == coord_after || coord_after == Some(test_node("node-d")),
            "HRW should provide minimal disruption on node addition"
        );
    }

    #[test]
    fn test_hrw_failover_ordering() {
        let zone = test_zone();
        let subject = test_object_id("test-subject");
        let nodes = vec![
            test_node("node-a"),
            test_node("node-b"),
            test_node("node-c"),
        ];

        let ranked = rank_nodes_by_hrw(&zone, &subject, &nodes);
        assert_eq!(ranked.len(), 3);

        // If primary (ranked[0]) fails, secondary (ranked[1]) should be next
        let remaining_nodes: Vec<_> = nodes.iter().filter(|n| *n != &ranked[0]).cloned().collect();

        let new_coord = select_coordinator(&zone, &subject, &remaining_nodes);
        assert_eq!(new_coord, Some(ranked[1].clone()));
    }

    #[test]
    fn test_hrw_stable_across_node_order() {
        let zone = test_zone();
        let subject = test_object_id("test-subject");

        let nodes1 = vec![
            test_node("node-a"),
            test_node("node-b"),
            test_node("node-c"),
        ];

        // Same nodes, different order
        let nodes2 = vec![
            test_node("node-c"),
            test_node("node-a"),
            test_node("node-b"),
        ];

        let coord1 = select_coordinator(&zone, &subject, &nodes1);
        let coord2 = select_coordinator(&zone, &subject, &nodes2);

        assert_eq!(
            coord1, coord2,
            "HRW should be stable regardless of input order"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LeasePurpose Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_lease_purpose_display() {
        assert_eq!(
            LeasePurpose::OperationExecution.to_string(),
            "operation_execution"
        );
        assert_eq!(
            LeasePurpose::ConnectorStateWrite.to_string(),
            "connector_state_write"
        );
        assert_eq!(
            LeasePurpose::ComputationMigration.to_string(),
            "computation_migration"
        );
    }

    #[test]
    fn test_lease_purpose_serde() {
        let purposes = [
            LeasePurpose::OperationExecution,
            LeasePurpose::ConnectorStateWrite,
            LeasePurpose::ComputationMigration,
            LeasePurpose::CoordinatorElection,
            LeasePurpose::Migration,
            LeasePurpose::ResourceAccess,
        ];

        for purpose in purposes {
            let json = serde_json::to_string(&purpose).unwrap();
            let deserialized: LeasePurpose = serde_json::from_str(&json).unwrap();
            assert_eq!(purpose, deserialized);
        }
    }

    #[test]
    fn test_lease_purpose_all_variants_display() {
        // Test all LeasePurpose variants have correct Display output
        assert_eq!(
            LeasePurpose::CoordinatorElection.to_string(),
            "coordinator_election"
        );
        assert_eq!(LeasePurpose::Migration.to_string(), "migration");
        assert_eq!(LeasePurpose::ResourceAccess.to_string(), "resource_access");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Lease Serde Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_lease_serde_roundtrip() {
        let lease = create_test_lease(42);

        let json = serde_json::to_string(&lease).unwrap();
        let deserialized: Lease = serde_json::from_str(&json).unwrap();

        assert_eq!(lease.holder, deserialized.holder);
        assert_eq!(lease.lease_seq, deserialized.lease_seq);
        assert_eq!(lease.exp, deserialized.exp);
        assert_eq!(lease.subject_object_id, deserialized.subject_object_id);
        assert_eq!(lease.purpose, deserialized.purpose);
    }

    #[test]
    fn test_lease_serde_preserves_all_fields() {
        let subject = test_object_id("specific-subject");
        let lease = create_test_lease_with_subject(100, 9999, subject);

        let json = serde_json::to_string_pretty(&lease).unwrap();

        // Verify JSON contains expected fields
        assert!(json.contains("holder"));
        assert!(json.contains("lease_seq"));
        assert!(json.contains("exp"));
        assert!(json.contains("subject_object_id"));
        assert!(json.contains("purpose"));
        assert!(json.contains("quorum_signatures"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LeaseRequest Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_lease_request_creation() {
        let request = LeaseRequest {
            subject_object_id: test_object_id("subject"),
            zone_id: test_zone(),
            requester: test_node("requester"),
            requested_ttl: 300,
            renew_seq: None,
        };

        assert_eq!(request.requester.as_str(), "requester");
        assert_eq!(request.requested_ttl, 300);
        assert!(request.renew_seq.is_none());
    }

    #[test]
    fn test_lease_request_renewal() {
        let request = LeaseRequest {
            subject_object_id: test_object_id("subject"),
            zone_id: test_zone(),
            requester: test_node("requester"),
            requested_ttl: 300,
            renew_seq: Some(42),
        };

        assert_eq!(request.renew_seq, Some(42));
    }

    #[test]
    fn test_lease_request_serde_roundtrip() {
        let request = LeaseRequest {
            subject_object_id: test_object_id("subject"),
            zone_id: test_zone(),
            requester: test_node("requester"),
            requested_ttl: 600,
            renew_seq: Some(10),
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: LeaseRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(request.subject_object_id, deserialized.subject_object_id);
        assert_eq!(request.zone_id, deserialized.zone_id);
        assert_eq!(request.requester, deserialized.requester);
        assert_eq!(request.requested_ttl, deserialized.requested_ttl);
        assert_eq!(request.renew_seq, deserialized.renew_seq);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LeaseResponse Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_lease_response_granted() {
        let lease = create_test_lease(1);
        let response = LeaseResponse::Granted(Box::new(lease.clone()));

        assert!(
            matches!(&response, LeaseResponse::Granted(l) if l.lease_seq == lease.lease_seq),
            "Expected Granted variant, got {response:?}"
        );
    }

    #[test]
    fn test_lease_response_denied() {
        let response = LeaseResponse::Denied {
            current_holder: test_node("holder"),
            expires_at: 3000,
            current_seq: 5,
        };

        assert!(
            matches!(
                &response,
                LeaseResponse::Denied { current_holder, expires_at, current_seq }
                    if current_holder.as_str() == "holder" && *expires_at == 3000 && *current_seq == 5
            ),
            "Expected Denied variant, got {response:?}"
        );
    }

    #[test]
    fn test_lease_response_invalid() {
        let response = LeaseResponse::Invalid {
            reason: "wrong zone".to_string(),
        };

        assert!(
            matches!(&response, LeaseResponse::Invalid { reason } if reason == "wrong zone"),
            "Expected Invalid variant, got {response:?}"
        );
    }

    #[test]
    fn test_lease_response_serde_granted() {
        let lease = create_test_lease(42);
        let response = LeaseResponse::Granted(Box::new(lease));

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: LeaseResponse = serde_json::from_str(&json).unwrap();

        assert!(matches!(deserialized, LeaseResponse::Granted(_)));
    }

    #[test]
    fn test_lease_response_serde_denied() {
        let response = LeaseResponse::Denied {
            current_holder: test_node("holder"),
            expires_at: 5000,
            current_seq: 10,
        };

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: LeaseResponse = serde_json::from_str(&json).unwrap();

        assert!(
            matches!(
                &deserialized,
                LeaseResponse::Denied { current_holder, expires_at, current_seq }
                    if current_holder.as_str() == "holder" && *expires_at == 5000 && *current_seq == 10
            ),
            "Expected Denied variant after deserialization, got {deserialized:?}"
        );
    }

    #[test]
    fn test_lease_response_serde_invalid() {
        let response = LeaseResponse::Invalid {
            reason: "test reason".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: LeaseResponse = serde_json::from_str(&json).unwrap();

        assert!(
            matches!(&deserialized, LeaseResponse::Invalid { reason } if reason == "test reason"),
            "Expected Invalid variant after deserialization, got {deserialized:?}"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Lease Conflict Resolution Tests (Fencing Token Semantics)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_fencing_token_prevents_zombie_lease() {
        // Scenario: Node A has lease seq 10, but node B acquired seq 15
        // Node A's lease should be rejected even if not expired
        let subject = test_object_id("shared-resource");
        let zone = test_zone();

        let zombie_lease = create_test_lease_with_subject(10, 5000, subject);

        // Current known seq is 15 (someone else got a newer lease)
        let result = validate_lease(
            &zombie_lease,
            &subject,
            &zone,
            LeasePurpose::OperationExecution,
            15, // current_known_seq > zombie_lease.lease_seq
            1000,
            0,
        );

        assert!(matches!(
            result,
            Err(LeaseValidationError::Superseded {
                held_seq: 10,
                current_seq: 15
            })
        ));
    }

    #[test]
    fn test_higher_seq_wins_regardless_of_expiry() {
        // Even if old lease hasn't expired, higher seq wins
        let subject = test_object_id("resource");
        let zone = test_zone();

        // Old lease: seq 5, expires far in future
        let old_lease = create_test_lease_with_subject(5, 99999, subject);

        // New lease: seq 10
        let new_lease = create_test_lease_with_subject(10, 2000, subject);

        // Old lease should fail validation
        let old_result = validate_lease(
            &old_lease,
            &subject,
            &zone,
            LeasePurpose::OperationExecution,
            10, // current known is new lease's seq
            1000,
            0,
        );
        assert!(old_result.is_err());

        // New lease should pass
        let new_result = validate_lease(
            &new_lease,
            &subject,
            &zone,
            LeasePurpose::OperationExecution,
            10,
            1000,
            0,
        );
        assert!(new_result.is_ok());
    }

    #[test]
    fn test_lease_at_exact_seq_is_valid() {
        // Lease with seq == current_known_seq should be valid
        let subject = test_object_id("resource");
        let zone = test_zone();
        let lease = create_test_lease_with_subject(10, 2000, subject);

        let result = validate_lease(
            &lease,
            &subject,
            &zone,
            LeasePurpose::OperationExecution,
            10, // exact match
            1000,
            0,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_lease_ahead_of_known_seq_is_valid() {
        // Lease with seq > current_known_seq should be valid
        // (node might have received newer lease info)
        let subject = test_object_id("resource");
        let zone = test_zone();
        let lease = create_test_lease_with_subject(15, 2000, subject);

        let result = validate_lease(
            &lease,
            &subject,
            &zone,
            LeasePurpose::OperationExecution,
            10, // lease.seq > current_known
            1000,
            0,
        );

        assert!(result.is_ok());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Lease::new Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_lease_new_sets_expiry_correctly() {
        use crate::Provenance;
        use fcp_cbor::SchemaId;
        use semver::Version;

        let zone = test_zone();
        let subject = test_object_id("subject");
        let ttl_secs = 300;

        let params = LeaseParams {
            schema: SchemaId::new("fcp.lease", "lease", Version::new(1, 0, 0)),
            zone_id: zone.clone(),
            holder: test_node("holder"),
            lease_seq: 1,
            ttl_secs,
            subject_object_id: subject,
            provenance: Provenance::new(zone),
            purpose: LeasePurpose::OperationExecution,
            quorum_signatures: SignatureSet::default(),
        };

        let lease = Lease::new(params);

        // exp should be created_at + ttl_secs
        assert_eq!(lease.exp, lease.header.created_at + u64::from(ttl_secs));

        // subject should be in refs
        assert!(lease.header.refs.contains(&subject));

        // ttl_secs should be set in header
        assert_eq!(lease.header.ttl_secs, Some(u64::from(ttl_secs)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helper Functions
    // ─────────────────────────────────────────────────────────────────────────

    fn create_test_lease(lease_seq: u64) -> Lease {
        create_test_lease_with_exp(lease_seq, 2000)
    }

    fn create_test_lease_with_exp(lease_seq: u64, exp: u64) -> Lease {
        create_test_lease_with_subject(lease_seq, exp, test_object_id("subject"))
    }

    fn create_test_lease_with_subject(lease_seq: u64, exp: u64, subject: ObjectId) -> Lease {
        use crate::Provenance;
        use fcp_cbor::SchemaId;
        use semver::Version;

        let zone = test_zone();
        Lease {
            header: ObjectHeader {
                schema: SchemaId::new("fcp.lease", "lease", Version::new(1, 0, 0)),
                zone_id: zone.clone(),
                created_at: 1000,
                provenance: Provenance::new(zone),
                refs: vec![subject],
                foreign_refs: vec![],
                ttl_secs: None,
                placement: None,
            },
            holder: test_node("holder-node"),
            lease_seq,
            exp,
            subject_object_id: subject,
            purpose: LeasePurpose::OperationExecution,
            quorum_signatures: SignatureSet::default(),
        }
    }
}
