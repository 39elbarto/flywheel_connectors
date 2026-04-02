//! Lease coordinator for multi-node execution authority.
//!
//! Implements the lease acquisition, renewal, conflict detection, and
//! coordinator election protocol from `FCP_Specification_V3.md` §11.3
//! (Leases), §11.3.1 (Distributed Lease Issuance), and §11.3.2
//! (Lease Conflict Handling).
//!
//! # Design
//!
//! The coordinator manages the lifecycle of execution leases across
//! mesh nodes. It ensures:
//!
//! 1. **Exclusive ownership**: Only one node holds authority for a
//!    given subject/purpose at any time.
//! 2. **Fencing**: Higher `lease_seq` always wins, preventing stale
//!    holders from executing after authority transfer.
//! 3. **Deterministic election**: HRW (rendezvous hashing) selects
//!    the coordinator without central coordination.
//! 4. **Conflict detection**: Overlapping leases are detected and
//!    escalated based on risk tier.
//! 5. **Audit trail**: Every authority change produces a durable
//!    timeline event for post-incident analysis.

use std::cmp::Ordering;

use fcp_core::{ObjectId, TailscaleNodeId, ZoneId, select_coordinator};
use serde::{Deserialize, Serialize};

use crate::authority::{AuthorityReasonCode, AuthorityTimelineEvent, ObservedLeaseAuthority};
use crate::planner::{HeldLease, LeasePurpose};

// ── Configuration ───────────────────────────────────────────────────────

/// Lease coordinator configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseCoordinatorConfig {
    /// Default TTL for new leases (seconds).
    pub default_ttl_secs: u32,
    /// Minimum TTL (prevents excessively short leases).
    pub min_ttl_secs: u32,
    /// Maximum TTL (prevents excessively long leases).
    pub max_ttl_secs: u32,
    /// Renew when this fraction of TTL remains (basis points, 0-10000).
    pub renew_threshold_bps: u16,
    /// Maximum concurrent leases per node.
    pub max_leases_per_node: usize,
    /// Whether to escalate conflicts for dangerous operations.
    pub escalate_dangerous_conflicts: bool,
}

impl Default for LeaseCoordinatorConfig {
    fn default() -> Self {
        Self {
            default_ttl_secs: 300,     // 5 minutes
            min_ttl_secs: 10,          // 10 seconds minimum
            max_ttl_secs: 3600,        // 1 hour maximum
            renew_threshold_bps: 2000, // renew at 20% remaining
            max_leases_per_node: 64,
            escalate_dangerous_conflicts: true,
        }
    }
}

// ── Lease Coordinator ───────────────────────────────────────────────────

/// Outcome of a lease acquisition attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum AcquireOutcome {
    /// Lease granted to the requester.
    Granted { fencing_token: u64, expires_at: u64 },
    /// Lease denied because another node holds it.
    Denied {
        current_holder: TailscaleNodeId,
        current_fencing_token: u64,
        expires_at: u64,
        reason: String,
    },
    /// Lease conflict detected (overlapping active leases).
    Conflict {
        holders: Vec<TailscaleNodeId>,
        fencing_tokens: Vec<u64>,
        reason: String,
    },
}

/// Outcome of a lease renewal attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum RenewOutcome {
    /// Lease renewed with same fencing token, new expiry.
    Renewed { expires_at: u64 },
    /// Renewal denied (lease expired or superseded).
    Denied { reason: String },
}

/// Outcome of a lease release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ReleaseOutcome {
    /// Lease released successfully.
    Released,
    /// Release failed (not the holder or already expired).
    NotHeld { reason: String },
}

/// Conflict severity for escalation decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictSeverity {
    /// Informational — lower-fencing-token holder should yield.
    Info,
    /// Warning — overlapping leases detected but resolvable.
    Warning,
    /// Critical — dangerous operation with split-brain risk.
    Critical,
}

/// A detected lease conflict with evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseConflict {
    /// Zone where conflict occurred.
    pub zone_id: ZoneId,
    /// Subject with conflicting leases.
    pub subject_id: ObjectId,
    /// Purpose of the conflicting leases.
    pub purpose: LeasePurpose,
    /// Severity of the conflict.
    pub severity: ConflictSeverity,
    /// Competing lease holders.
    pub holders: Vec<ConflictingHolder>,
    /// When the conflict was detected (Unix ms).
    pub detected_at_ms: u64,
    /// Resolution recommendation.
    pub resolution: String,
}

/// A holder involved in a lease conflict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictingHolder {
    /// Node holding the lease.
    pub node_id: TailscaleNodeId,
    /// Fencing token for the lease.
    pub fencing_token: u64,
    /// Expiration of the lease.
    pub expires_at: u64,
}

/// Lease coordinator for managing execution authority across mesh nodes.
///
/// The coordinator computes outcomes from observed lease state and returns
/// decisions. It keeps a local next-token cursor, but rebases that cursor
/// against observed fencing tokens before issuing a new lease. Actual lease
/// storage is managed by the caller (mesh node or host).
#[derive(Debug, Clone)]
pub struct LeaseCoordinator {
    config: LeaseCoordinatorConfig,
    /// Monotonic sequence counter for fencing tokens.
    next_seq: u64,
}

impl LeaseCoordinator {
    /// Create a new lease coordinator with the given configuration.
    #[must_use]
    pub fn new(config: LeaseCoordinatorConfig) -> Self {
        Self {
            config,
            next_seq: 1,
        }
    }

    /// Create a coordinator with the default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(LeaseCoordinatorConfig::default())
    }

    /// Attempt to acquire a lease for a subject.
    ///
    /// The coordinator checks existing leases for the subject/purpose
    /// and grants or denies based on fencing token ordering.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub fn acquire(
        &mut self,
        requester: &TailscaleNodeId,
        zone_id: &ZoneId,
        subject_id: &ObjectId,
        purpose: &LeasePurpose,
        existing_leases: &[ObservedLeaseAuthority],
        eligible_nodes: &[TailscaleNodeId],
        now_secs: u64,
        requested_ttl: Option<u32>,
    ) -> (AcquireOutcome, Vec<AuthorityTimelineEvent>) {
        let mut timeline = Vec::new();
        let ttl = self.clamp_ttl(requested_ttl.unwrap_or(self.config.default_ttl_secs));
        self.rebase_next_seq(existing_leases);

        // Filter to active leases for this subject/purpose
        let active: Vec<&ObservedLeaseAuthority> = existing_leases
            .iter()
            .filter(|obs| {
                obs.lease.subject_id == *subject_id
                    && obs.lease.purpose == *purpose
                    && obs.lease.is_active(now_secs)
            })
            .collect();

        // No active leases — grant immediately
        if active.is_empty() {
            let token = self.next_fencing_token();
            let expires_at = now_secs + u64::from(ttl);

            timeline.push(AuthorityTimelineEvent {
                observed_at_ms: now_secs * 1000,
                operation: "lease.acquired".into(),
                subject_id: *subject_id,
                purpose: purpose.clone(),
                holder: Some(requester.clone()),
                coordinator: select_coordinator(zone_id, subject_id, eligible_nodes),
                reason_code: AuthorityReasonCode::ActiveAuthority,
                fencing_token: Some(token),
                expires_at: Some(expires_at),
                explanation: format!(
                    "Lease granted to {} (no competing holders)",
                    requester.as_str()
                ),
            });

            return (
                AcquireOutcome::Granted {
                    fencing_token: token,
                    expires_at,
                },
                timeline,
            );
        }

        // Check for conflicts
        if active.len() > 1 {
            let severity = if self.config.escalate_dangerous_conflicts {
                ConflictSeverity::Critical
            } else {
                ConflictSeverity::Warning
            };

            let holders: Vec<TailscaleNodeId> = active.iter().map(|o| o.holder.clone()).collect();
            let tokens: Vec<u64> = active.iter().map(|o| o.lease.fencing_token).collect();

            timeline.push(AuthorityTimelineEvent {
                observed_at_ms: now_secs * 1000,
                operation: "lease.conflict_detected".into(),
                subject_id: *subject_id,
                purpose: purpose.clone(),
                holder: None,
                coordinator: select_coordinator(zone_id, subject_id, eligible_nodes),
                reason_code: AuthorityReasonCode::LeaseConflictDetected,
                fencing_token: None,
                expires_at: None,
                explanation: format!(
                    "Conflict: {} active leases for subject (severity: {severity:?})",
                    active.len()
                ),
            });

            return (
                AcquireOutcome::Conflict {
                    holders,
                    fencing_tokens: tokens,
                    reason: "Multiple active leases detected for subject/purpose".into(),
                },
                timeline,
            );
        }

        // Single active lease — check if requester is the holder
        let current = &active[0];
        if current.holder == *requester {
            // Already holds it — treat as renewal
            let (renew_outcome, renew_events) = self.renew(
                requester,
                subject_id,
                purpose,
                current.lease.fencing_token,
                now_secs,
                Some(ttl),
            );
            timeline.extend(renew_events);
            match renew_outcome {
                RenewOutcome::Renewed { expires_at } => {
                    return (
                        AcquireOutcome::Granted {
                            fencing_token: current.lease.fencing_token,
                            expires_at,
                        },
                        timeline,
                    );
                }
                RenewOutcome::Denied { reason } => {
                    return (
                        AcquireOutcome::Denied {
                            current_holder: current.holder.clone(),
                            current_fencing_token: current.lease.fencing_token,
                            expires_at: current.lease.expires_at,
                            reason,
                        },
                        timeline,
                    );
                }
            }
        }

        // Different holder — deny
        timeline.push(AuthorityTimelineEvent {
            observed_at_ms: now_secs * 1000,
            operation: "lease.denied".into(),
            subject_id: *subject_id,
            purpose: purpose.clone(),
            holder: Some(current.holder.clone()),
            coordinator: select_coordinator(zone_id, subject_id, eligible_nodes),
            reason_code: AuthorityReasonCode::SupersededByPreferredLease,
            fencing_token: Some(current.lease.fencing_token),
            expires_at: Some(current.lease.expires_at),
            explanation: format!(
                "Denied: {} holds active lease (fencing_token={}, expires={})",
                current.holder.as_str(),
                current.lease.fencing_token,
                current.lease.expires_at
            ),
        });

        (
            AcquireOutcome::Denied {
                current_holder: current.holder.clone(),
                current_fencing_token: current.lease.fencing_token,
                expires_at: current.lease.expires_at,
                reason: format!("Active lease held by {}", current.holder.as_str()),
            },
            timeline,
        )
    }

    /// Renew an existing lease.
    pub fn renew(
        &self,
        requester: &TailscaleNodeId,
        subject_id: &ObjectId,
        purpose: &LeasePurpose,
        held_fencing_token: u64,
        now_secs: u64,
        requested_ttl: Option<u32>,
    ) -> (RenewOutcome, Vec<AuthorityTimelineEvent>) {
        let mut timeline = Vec::new();
        let ttl = self.clamp_ttl(requested_ttl.unwrap_or(self.config.default_ttl_secs));
        let new_expires = now_secs + u64::from(ttl);

        timeline.push(AuthorityTimelineEvent {
            observed_at_ms: now_secs * 1000,
            operation: "lease.renewed".into(),
            subject_id: *subject_id,
            purpose: purpose.clone(),
            holder: Some(requester.clone()),
            coordinator: None,
            reason_code: AuthorityReasonCode::ActiveAuthority,
            fencing_token: Some(held_fencing_token),
            expires_at: Some(new_expires),
            explanation: format!(
                "Lease renewed for {} (fencing_token={held_fencing_token}, new_expires={new_expires})",
                requester.as_str()
            ),
        });

        (
            RenewOutcome::Renewed {
                expires_at: new_expires,
            },
            timeline,
        )
    }

    /// Release a lease voluntarily.
    pub fn release(
        &self,
        requester: &TailscaleNodeId,
        subject_id: &ObjectId,
        purpose: &LeasePurpose,
        held_fencing_token: u64,
        existing_leases: &[ObservedLeaseAuthority],
        now_secs: u64,
    ) -> (ReleaseOutcome, Vec<AuthorityTimelineEvent>) {
        let mut timeline = Vec::new();

        let held = existing_leases.iter().find(|obs| {
            obs.holder == *requester
                && obs.lease.subject_id == *subject_id
                && obs.lease.purpose == *purpose
                && obs.lease.fencing_token == held_fencing_token
                && obs.lease.is_active(now_secs)
        });

        let holder = requester.as_str();
        if held.is_some() {
            timeline.push(AuthorityTimelineEvent {
                observed_at_ms: now_secs * 1000,
                operation: "lease.released".into(),
                subject_id: *subject_id,
                purpose: purpose.clone(),
                holder: Some(requester.clone()),
                coordinator: None,
                reason_code: AuthorityReasonCode::LeaseReleased,
                fencing_token: Some(held_fencing_token),
                expires_at: None,
                explanation: format!(
                    "Lease released by {holder} (fencing_token={held_fencing_token})"
                ),
            });
            (ReleaseOutcome::Released, timeline)
        } else {
            timeline.push(AuthorityTimelineEvent {
                observed_at_ms: now_secs * 1000,
                operation: "lease.release_failed".into(),
                subject_id: *subject_id,
                purpose: purpose.clone(),
                holder: Some(requester.clone()),
                coordinator: None,
                reason_code: AuthorityReasonCode::LeaseNotHeld,
                fencing_token: Some(held_fencing_token),
                expires_at: None,
                explanation: format!("Release failed: {holder} does not hold matching lease"),
            });
            (
                ReleaseOutcome::NotHeld {
                    reason: "No matching active lease found".into(),
                },
                timeline,
            )
        }
    }

    /// Detect conflicts among observed leases for a subject.
    ///
    /// # Panics
    ///
    /// Panics if the active lease set is non-empty but has no maximum fencing
    /// token, which should be impossible for a non-empty iterator.
    #[must_use]
    pub fn detect_conflicts(
        &self,
        zone_id: &ZoneId,
        subject_id: &ObjectId,
        purpose: &LeasePurpose,
        observed: &[ObservedLeaseAuthority],
        now_secs: u64,
    ) -> Option<LeaseConflict> {
        let active: Vec<&ObservedLeaseAuthority> = observed
            .iter()
            .filter(|obs| {
                obs.lease.subject_id == *subject_id
                    && obs.lease.purpose == *purpose
                    && obs.lease.is_active(now_secs)
            })
            .collect();

        if active.len() <= 1 {
            return None;
        }

        let severity = if self.config.escalate_dangerous_conflicts {
            ConflictSeverity::Critical
        } else {
            ConflictSeverity::Warning
        };

        let holders: Vec<ConflictingHolder> = active
            .iter()
            .map(|obs| ConflictingHolder {
                node_id: obs.holder.clone(),
                fencing_token: obs.lease.fencing_token,
                expires_at: obs.lease.expires_at,
            })
            .collect();

        // Resolution: highest fencing token wins
        let winner = active
            .iter()
            .max_by(|left, right| compare_conflicting_leases(left, right))
            .unwrap();

        Some(LeaseConflict {
            zone_id: zone_id.clone(),
            subject_id: *subject_id,
            purpose: purpose.clone(),
            severity,
            holders,
            detected_at_ms: now_secs * 1000,
            resolution: format!(
                "Highest fencing token wins: {} (token={})",
                winner.holder.as_str(),
                winner.lease.fencing_token
            ),
        })
    }

    /// Check whether a lease should be renewed based on remaining TTL.
    #[must_use]
    pub fn should_renew(&self, lease: &HeldLease, now_secs: u64) -> bool {
        if !lease.is_active(now_secs) {
            return false;
        }
        let remaining = lease.expires_at.saturating_sub(now_secs);
        // Compare remaining time against the configured TTL to decide
        // whether renewal is needed. Use the default TTL as the reference
        // since we don't track the original grant TTL.
        let reference_ttl = u64::from(self.config.default_ttl_secs);
        if reference_ttl == 0 {
            return true;
        }
        let remaining_bps = (remaining * 10_000) / reference_ttl;
        remaining_bps <= u64::from(self.config.renew_threshold_bps)
    }

    /// Get the current configuration.
    #[must_use]
    pub const fn config(&self) -> &LeaseCoordinatorConfig {
        &self.config
    }

    // ── Internal ────────────────────────────────────────────────────

    fn next_fencing_token(&mut self) -> u64 {
        let token = self.next_seq;
        self.next_seq = self
            .next_seq
            .checked_add(1)
            .expect("fencing token space exhausted");
        token
    }

    fn rebase_next_seq(&mut self, existing_leases: &[ObservedLeaseAuthority]) {
        if let Some(max_observed) = existing_leases
            .iter()
            .map(|observed| observed.lease.fencing_token)
            .max()
        {
            self.next_seq = self.next_seq.max(
                max_observed
                    .checked_add(1)
                    .expect("fencing token space exhausted"),
            );
        }
    }

    fn clamp_ttl(&self, ttl: u32) -> u32 {
        ttl.clamp(self.config.min_ttl_secs, self.config.max_ttl_secs)
    }
}

fn compare_conflicting_leases(
    left: &&ObservedLeaseAuthority,
    right: &&ObservedLeaseAuthority,
) -> Ordering {
    left.lease
        .fencing_token
        .cmp(&right.lease.fencing_token)
        .then_with(|| left.lease.expires_at.cmp(&right.lease.expires_at))
        .then_with(|| right.holder.as_str().cmp(left.holder.as_str()))
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str) -> TailscaleNodeId {
        TailscaleNodeId::new(name)
    }

    fn zone() -> ZoneId {
        "z:coordinator-test".parse().unwrap()
    }

    fn subject() -> ObjectId {
        ObjectId::from_bytes([0xCC; 32])
    }

    fn purpose() -> LeasePurpose {
        LeasePurpose::SingletonWriter
    }

    fn held_lease(holder: &str, token: u64, expires: u64) -> ObservedLeaseAuthority {
        ObservedLeaseAuthority::new(
            node(holder),
            HeldLease {
                subject_id: subject(),
                purpose: purpose(),
                expires_at: expires,
                fencing_token: token,
            },
        )
    }

    // ── Acquire ──────────────────────────────────────────────────

    #[test]
    fn acquire_grants_when_no_existing_leases() {
        let mut coord = LeaseCoordinator::with_defaults();
        let eligible = vec![node("a"), node("b"), node("c")];

        let (outcome, timeline) = coord.acquire(
            &node("a"),
            &zone(),
            &subject(),
            &purpose(),
            &[],
            &eligible,
            1000,
            None,
        );

        assert!(matches!(outcome, AcquireOutcome::Granted { .. }));
        if let AcquireOutcome::Granted {
            fencing_token,
            expires_at,
        } = outcome
        {
            assert!(fencing_token > 0);
            assert!(expires_at > 1000);
        }
        assert_eq!(timeline.len(), 1);
        assert_eq!(timeline[0].operation, "lease.acquired");
    }

    #[test]
    fn acquire_denies_when_different_holder() {
        let mut coord = LeaseCoordinator::with_defaults();
        let eligible = vec![node("a"), node("b")];
        let existing = vec![held_lease("a", 1, 2000)];

        let (outcome, timeline) = coord.acquire(
            &node("b"),
            &zone(),
            &subject(),
            &purpose(),
            &existing,
            &eligible,
            1000,
            None,
        );

        assert!(matches!(outcome, AcquireOutcome::Denied { .. }));
        if let AcquireOutcome::Denied { current_holder, .. } = &outcome {
            assert_eq!(current_holder, &node("a"));
        }
        assert!(!timeline.is_empty());
    }

    #[test]
    fn acquire_grants_when_existing_lease_expired() {
        let mut coord = LeaseCoordinator::with_defaults();
        let eligible = vec![node("a"), node("b")];
        let existing = vec![held_lease("a", 1, 500)]; // expired at 500

        let (outcome, _timeline) = coord.acquire(
            &node("b"),
            &zone(),
            &subject(),
            &purpose(),
            &existing,
            &eligible,
            1000, // now > 500
            None,
        );

        assert!(matches!(outcome, AcquireOutcome::Granted { .. }));
    }

    #[test]
    fn acquire_detects_conflict_with_multiple_holders() {
        let mut coord = LeaseCoordinator::with_defaults();
        let eligible = vec![node("a"), node("b"), node("c")];
        let existing = vec![held_lease("a", 1, 2000), held_lease("b", 2, 2000)];

        let (outcome, timeline) = coord.acquire(
            &node("c"),
            &zone(),
            &subject(),
            &purpose(),
            &existing,
            &eligible,
            1000,
            None,
        );

        assert!(matches!(outcome, AcquireOutcome::Conflict { .. }));
        assert!(
            timeline
                .iter()
                .any(|e| e.operation == "lease.conflict_detected")
        );
        assert!(
            timeline
                .iter()
                .any(|e| e.reason_code == AuthorityReasonCode::LeaseConflictDetected)
        );
    }

    #[test]
    fn acquire_rebases_fencing_token_above_observed_history() {
        let mut coord = LeaseCoordinator::with_defaults();
        let eligible = vec![node("a"), node("b")];
        let existing = vec![held_lease("a", 99, 500)]; // expired but still observed

        let (outcome, _) = coord.acquire(
            &node("b"),
            &zone(),
            &subject(),
            &purpose(),
            &existing,
            &eligible,
            1000,
            None,
        );

        assert!(matches!(
            outcome,
            AcquireOutcome::Granted {
                fencing_token: 100,
                ..
            }
        ));
    }

    #[test]
    fn acquire_renews_when_requester_already_holds() {
        let mut coord = LeaseCoordinator::with_defaults();
        let eligible = vec![node("a")];
        let existing = vec![held_lease("a", 5, 2000)];

        let (outcome, timeline) = coord.acquire(
            &node("a"),
            &zone(),
            &subject(),
            &purpose(),
            &existing,
            &eligible,
            1000,
            None,
        );

        assert!(matches!(
            outcome,
            AcquireOutcome::Granted {
                fencing_token: 5,
                ..
            }
        ));
        assert!(timeline.iter().any(|e| e.operation == "lease.renewed"));
    }

    // ── Fencing Token Monotonicity ───────────────────────────────

    #[test]
    fn fencing_tokens_are_strictly_monotonic() {
        let mut coord = LeaseCoordinator::with_defaults();
        let eligible = vec![node("a")];

        let mut prev_token = 0;
        for _ in 0..10 {
            let (outcome, _) = coord.acquire(
                &node("a"),
                &zone(),
                &subject(),
                &purpose(),
                &[],
                &eligible,
                1000,
                None,
            );
            if let AcquireOutcome::Granted { fencing_token, .. } = outcome {
                assert!(
                    fencing_token > prev_token,
                    "fencing tokens must be monotonic"
                );
                prev_token = fencing_token;
            }
        }
    }

    // ── Renewal ─────────────────────────────────────────────────

    #[test]
    fn renew_extends_expiry() {
        let coord = LeaseCoordinator::with_defaults();
        let (outcome, timeline) =
            coord.renew(&node("a"), &subject(), &purpose(), 42, 1000, Some(300));

        if let RenewOutcome::Renewed { expires_at } = outcome {
            assert_eq!(expires_at, 1300);
        } else {
            panic!("expected Renewed");
        }
        assert_eq!(timeline.len(), 1);
        assert_eq!(timeline[0].operation, "lease.renewed");
    }

    // ── Release ─────────────────────────────────────────────────

    #[test]
    fn release_succeeds_for_matching_holder() {
        let coord = LeaseCoordinator::with_defaults();
        let existing = vec![held_lease("a", 1, 2000)];

        let (outcome, timeline) =
            coord.release(&node("a"), &subject(), &purpose(), 1, &existing, 1000);

        assert!(matches!(outcome, ReleaseOutcome::Released));
        assert!(timeline.iter().any(|e| e.operation == "lease.released"));
        assert!(
            timeline
                .iter()
                .any(|e| e.reason_code == AuthorityReasonCode::LeaseReleased)
        );
    }

    #[test]
    fn release_fails_for_non_holder() {
        let coord = LeaseCoordinator::with_defaults();
        let existing = vec![held_lease("a", 1, 2000)];

        let (outcome, timeline) =
            coord.release(&node("b"), &subject(), &purpose(), 1, &existing, 1000);

        assert!(matches!(outcome, ReleaseOutcome::NotHeld { .. }));
        assert!(
            timeline
                .iter()
                .any(|e| e.reason_code == AuthorityReasonCode::LeaseNotHeld)
        );
    }

    #[test]
    fn release_fails_for_expired_lease() {
        let coord = LeaseCoordinator::with_defaults();
        let existing = vec![held_lease("a", 1, 500)];

        let (outcome, timeline) =
            coord.release(&node("a"), &subject(), &purpose(), 1, &existing, 1000);

        assert!(matches!(outcome, ReleaseOutcome::NotHeld { .. }));
        assert!(
            timeline
                .iter()
                .any(|e| e.reason_code == AuthorityReasonCode::LeaseNotHeld)
        );
    }

    // ── Conflict Detection ──────────────────────────────────────

    #[test]
    fn detect_conflicts_returns_none_for_single_holder() {
        let coord = LeaseCoordinator::with_defaults();
        let existing = vec![held_lease("a", 1, 2000)];

        let conflict = coord.detect_conflicts(&zone(), &subject(), &purpose(), &existing, 1000);

        assert!(conflict.is_none());
    }

    #[test]
    fn detect_conflicts_finds_overlapping_leases() {
        let coord = LeaseCoordinator::with_defaults();
        let existing = vec![held_lease("a", 1, 2000), held_lease("b", 2, 2000)];

        let conflict = coord.detect_conflicts(&zone(), &subject(), &purpose(), &existing, 1000);

        assert!(conflict.is_some());
        let conflict = conflict.unwrap();
        assert_eq!(conflict.holders.len(), 2);
        assert_eq!(conflict.severity, ConflictSeverity::Critical);
        assert!(conflict.resolution.contains("b")); // higher token wins
    }

    #[test]
    fn detect_conflicts_breaks_ties_deterministically() {
        let coord = LeaseCoordinator::with_defaults();
        let existing = vec![held_lease("b", 7, 2000), held_lease("a", 7, 2000)];

        let conflict = coord
            .detect_conflicts(&zone(), &subject(), &purpose(), &existing, 1000)
            .expect("conflict should be detected");

        assert!(conflict.resolution.contains("a"));
    }

    #[test]
    fn detect_conflicts_ignores_expired_leases() {
        let coord = LeaseCoordinator::with_defaults();
        let existing = vec![
            held_lease("a", 1, 500),  // expired
            held_lease("b", 2, 2000), // active
        ];

        let conflict = coord.detect_conflicts(&zone(), &subject(), &purpose(), &existing, 1000);

        assert!(conflict.is_none());
    }

    // ── Should Renew ────────────────────────────────────────────

    #[test]
    fn should_renew_true_when_near_expiry() {
        let coord = LeaseCoordinator::with_defaults(); // 20% threshold
        let lease = HeldLease {
            subject_id: subject(),
            purpose: purpose(),
            expires_at: 1050, // 50 seconds remaining at now=1000
            fencing_token: 1,
        };
        // 50/1050 remaining ≈ 4.7% < 20% threshold
        assert!(coord.should_renew(&lease, 1000));
    }

    #[test]
    fn should_renew_false_when_plenty_remaining() {
        let coord = LeaseCoordinator::with_defaults();
        let lease = HeldLease {
            subject_id: subject(),
            purpose: purpose(),
            expires_at: 5000, // plenty remaining
            fencing_token: 1,
        };
        assert!(!coord.should_renew(&lease, 1000));
    }

    #[test]
    fn should_renew_false_when_expired() {
        let coord = LeaseCoordinator::with_defaults();
        let lease = HeldLease {
            subject_id: subject(),
            purpose: purpose(),
            expires_at: 500, // already expired
            fencing_token: 1,
        };
        assert!(!coord.should_renew(&lease, 1000));
    }

    // ── Config ──────────────────────────────────────────────────

    #[test]
    fn config_default_values() {
        let config = LeaseCoordinatorConfig::default();
        assert_eq!(config.default_ttl_secs, 300);
        assert_eq!(config.min_ttl_secs, 10);
        assert_eq!(config.max_ttl_secs, 3600);
        assert_eq!(config.renew_threshold_bps, 2000);
        assert!(config.escalate_dangerous_conflicts);
    }

    #[test]
    fn config_serialization_roundtrip() {
        let config = LeaseCoordinatorConfig::default();
        let json = serde_json::to_value(&config).unwrap();
        let rt: LeaseCoordinatorConfig = serde_json::from_value(json).unwrap();
        assert_eq!(config, rt);
    }

    #[test]
    fn ttl_clamped_to_bounds() {
        let coord = LeaseCoordinator::with_defaults();
        assert_eq!(coord.clamp_ttl(5), 10); // below min
        assert_eq!(coord.clamp_ttl(300), 300); // within range
        assert_eq!(coord.clamp_ttl(9999), 3600); // above max
    }

    // ── Conflict Serialization ──────────────────────────────────

    #[test]
    fn lease_conflict_serialization_roundtrip() {
        let conflict = LeaseConflict {
            zone_id: zone(),
            subject_id: subject(),
            purpose: purpose(),
            severity: ConflictSeverity::Critical,
            holders: vec![
                ConflictingHolder {
                    node_id: node("a"),
                    fencing_token: 1,
                    expires_at: 2000,
                },
                ConflictingHolder {
                    node_id: node("b"),
                    fencing_token: 2,
                    expires_at: 2000,
                },
            ],
            detected_at_ms: 1_000_000,
            resolution: "highest fencing token wins".into(),
        };

        let json = serde_json::to_value(&conflict).unwrap();
        let rt: LeaseConflict = serde_json::from_value(json).unwrap();
        assert_eq!(rt.holders.len(), 2);
        assert_eq!(rt.severity, ConflictSeverity::Critical);
    }
}
