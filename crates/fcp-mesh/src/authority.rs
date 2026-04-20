//! Mesh authority resolution for execution leases and coordinator selection.
//!
//! This module turns observed mesh lease state into deterministic, serializable
//! authority records that higher layers can inspect or persist.

use std::cmp::Ordering;

use fcp_core::{ObjectId, TailscaleNodeId, ZoneId, rank_nodes_by_hrw, select_coordinator};
use serde::{Deserialize, Serialize};

use crate::planner::{HeldLease, LeasePurpose};

/// A lease observation tied to the node that currently reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedLeaseAuthority {
    /// Node that claims to hold the lease.
    pub holder: TailscaleNodeId,
    /// The observed lease details.
    pub lease: HeldLease,
}

impl ObservedLeaseAuthority {
    /// Build a new observed lease authority.
    #[must_use]
    pub const fn new(holder: TailscaleNodeId, lease: HeldLease) -> Self {
        Self { holder, lease }
    }
}

/// Authority state for an observed lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityStatus {
    /// This lease currently holds authority.
    Active,
    /// This lease lost authority to a better candidate.
    Superseded,
    /// This lease has already expired.
    Expired,
}

/// Explainable reason for an authority decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityReasonCode {
    /// The authority winner for the observed subject/purpose.
    ActiveAuthority,
    /// Lost authority to a preferred active lease.
    SupersededByPreferredLease,
    /// Lease lifetime already elapsed.
    LeaseExpired,
    /// Multiple active leases were detected for the same subject/purpose.
    LeaseConflictDetected,
    /// Lease acquisition rejected by local coordinator admission rules.
    LeaseAcquisitionRejected,
    /// A holder voluntarily released its lease.
    LeaseReleased,
    /// A release request did not match any active held lease.
    LeaseNotHeld,
    /// HRW selected the coordinator for this subject.
    CoordinatorSelected,
    /// No eligible nodes existed for coordinator selection.
    NoEligibleCoordinator,
}

/// Durable summary of current authority for a single observed lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityRecord {
    /// Zone in which the authority applies.
    pub zone_id: ZoneId,
    /// Subject covered by the authority.
    pub subject_id: ObjectId,
    /// Lease purpose.
    pub purpose: LeasePurpose,
    /// Node claiming the authority.
    pub holder: TailscaleNodeId,
    /// Deterministically selected coordinator for the subject.
    pub coordinator: Option<TailscaleNodeId>,
    /// Active/superseded/expired state.
    pub status: AuthorityStatus,
    /// Explanation category.
    pub reason_code: AuthorityReasonCode,
    /// Monotonic fencing token used to break conflicts.
    pub fencing_token: u64,
    /// Expiration timestamp in seconds since epoch.
    pub expires_at: u64,
    /// Observation timestamp in milliseconds since epoch.
    pub observed_at_ms: u64,
    /// Human-readable explanation.
    pub explanation: String,
}

/// Timeline event describing how authority was resolved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityTimelineEvent {
    /// Observation timestamp in milliseconds since epoch.
    pub observed_at_ms: u64,
    /// Event operation label.
    pub operation: String,
    /// Subject covered by the authority.
    pub subject_id: ObjectId,
    /// Lease purpose.
    pub purpose: LeasePurpose,
    /// Node associated with the event when applicable.
    pub holder: Option<TailscaleNodeId>,
    /// Coordinator associated with the event when applicable.
    pub coordinator: Option<TailscaleNodeId>,
    /// Explanation category.
    pub reason_code: AuthorityReasonCode,
    /// Fencing token for the event when applicable.
    pub fencing_token: Option<u64>,
    /// Expiration timestamp in seconds since epoch when applicable.
    pub expires_at: Option<u64>,
    /// Human-readable explanation.
    pub explanation: String,
}

/// Deterministic authority snapshot for one subject/purpose pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityView {
    /// Zone in which the authority applies.
    pub zone_id: ZoneId,
    /// Subject covered by the authority.
    pub subject_id: ObjectId,
    /// Lease purpose.
    pub purpose: LeasePurpose,
    /// Deterministically selected coordinator.
    pub coordinator: Option<TailscaleNodeId>,
    /// Ranked failover order from HRW.
    pub failover_order: Vec<TailscaleNodeId>,
    /// Current authority holder if any active lease exists.
    pub active_holder: Option<TailscaleNodeId>,
    /// Current winning fencing token if any active lease exists.
    pub active_fencing_token: Option<u64>,
    /// Per-lease authority records.
    pub records: Vec<AuthorityRecord>,
    /// Explainable timeline for authority resolution.
    pub timeline: Vec<AuthorityTimelineEvent>,
}

fn compare_observed_leases(
    left: &ObservedLeaseAuthority,
    right: &ObservedLeaseAuthority,
) -> Ordering {
    right
        .lease
        .fencing_token
        .cmp(&left.lease.fencing_token)
        .then_with(|| right.lease.expires_at.cmp(&left.lease.expires_at))
        .then_with(|| left.holder.as_str().cmp(right.holder.as_str()))
}

fn is_winner_record(winner: &ObservedLeaseAuthority, candidate: &ObservedLeaseAuthority) -> bool {
    winner.holder == candidate.holder
        && winner.lease.subject_id == candidate.lease.subject_id
        && winner.lease.purpose == candidate.lease.purpose
        && winner.lease.fencing_token == candidate.lease.fencing_token
        && winner.lease.expires_at == candidate.lease.expires_at
}

impl AuthorityView {
    /// Build a deterministic authority view for one subject/purpose pair.
    ///
    /// # Panics
    ///
    /// Panics if coordinator selection produces an inconsistent state.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn from_observed(
        zone_id: &ZoneId,
        subject_id: &ObjectId,
        purpose: LeasePurpose,
        eligible_nodes: &[TailscaleNodeId],
        observed: &[ObservedLeaseAuthority],
        now_secs: u64,
        observed_at_ms: u64,
    ) -> Self {
        let coordinator = select_coordinator(zone_id, subject_id, eligible_nodes);
        let failover_order = rank_nodes_by_hrw(zone_id, subject_id, eligible_nodes);

        let mut relevant = observed
            .iter()
            .filter(|entry| entry.lease.subject_id == *subject_id && entry.lease.purpose == purpose)
            .cloned()
            .collect::<Vec<_>>();
        relevant.sort_by(compare_observed_leases);

        let winner = relevant
            .iter()
            .find(|entry| entry.lease.is_active(now_secs))
            .cloned();
        let active_holder = winner.as_ref().map(|entry| entry.holder.clone());
        let active_fencing_token = winner.as_ref().map(|entry| entry.lease.fencing_token);

        let mut records = Vec::with_capacity(relevant.len());
        let mut timeline = Vec::with_capacity(relevant.len() + 1);

        let coordinator_reason = if coordinator.is_some() {
            AuthorityReasonCode::CoordinatorSelected
        } else {
            AuthorityReasonCode::NoEligibleCoordinator
        };
        timeline.push(AuthorityTimelineEvent {
            observed_at_ms,
            operation: "coordinator_selected".to_string(),
            subject_id: *subject_id,
            purpose,
            holder: None,
            coordinator: coordinator.clone(),
            reason_code: coordinator_reason,
            fencing_token: None,
            expires_at: None,
            explanation: match &coordinator {
                Some(node) => {
                    let n = node.as_str();
                    format!("HRW selected coordinator {n} for {subject_id}")
                }
                None => format!("no eligible coordinator available for {subject_id}"),
            },
        });

        for entry in relevant {
            let (status, reason_code, operation, explanation) = if !entry.lease.is_active(now_secs)
            {
                (
                    AuthorityStatus::Expired,
                    AuthorityReasonCode::LeaseExpired,
                    "lease_expired",
                    format!(
                        "lease held by {} expired at {}",
                        entry.holder.as_str(),
                        entry.lease.expires_at
                    ),
                )
            } else if winner
                .as_ref()
                .is_some_and(|winner| is_winner_record(winner, &entry))
            {
                (
                    AuthorityStatus::Active,
                    AuthorityReasonCode::ActiveAuthority,
                    "authority_active",
                    {
                        let holder = entry.holder.as_str();
                        let token = entry.lease.fencing_token;
                        format!("authority held by {holder} with fencing token {token}")
                    },
                )
            } else {
                let winner = winner
                    .as_ref()
                    .expect("active winner exists for superseded record");
                (
                    AuthorityStatus::Superseded,
                    AuthorityReasonCode::SupersededByPreferredLease,
                    "authority_superseded",
                    format!(
                        "superseded by {} with fencing token {}",
                        winner.holder.as_str(),
                        winner.lease.fencing_token
                    ),
                )
            };

            timeline.push(AuthorityTimelineEvent {
                observed_at_ms,
                operation: operation.to_string(),
                subject_id: *subject_id,
                purpose,
                holder: Some(entry.holder.clone()),
                coordinator: coordinator.clone(),
                reason_code,
                fencing_token: Some(entry.lease.fencing_token),
                expires_at: Some(entry.lease.expires_at),
                explanation: explanation.clone(),
            });
            records.push(AuthorityRecord {
                zone_id: zone_id.clone(),
                subject_id: *subject_id,
                purpose,
                holder: entry.holder,
                coordinator: coordinator.clone(),
                status,
                reason_code,
                fencing_token: entry.lease.fencing_token,
                expires_at: entry.lease.expires_at,
                observed_at_ms,
                explanation,
            });
        }

        Self {
            zone_id: zone_id.clone(),
            subject_id: *subject_id,
            purpose,
            coordinator,
            failover_order,
            active_holder,
            active_fencing_token,
            records,
            timeline,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_zone() -> ZoneId {
        ZoneId::work()
    }

    fn test_subject(name: &str) -> ObjectId {
        ObjectId::from_unscoped_bytes(name.as_bytes())
    }

    fn test_node(name: &str) -> TailscaleNodeId {
        TailscaleNodeId::new(name)
    }

    fn observed(
        holder: &str,
        subject: ObjectId,
        purpose: LeasePurpose,
        expires_at: u64,
        fencing_token: u64,
    ) -> ObservedLeaseAuthority {
        ObservedLeaseAuthority::new(
            test_node(holder),
            HeldLease {
                subject_id: subject,
                purpose,
                expires_at,
                fencing_token,
            },
        )
    }

    #[test]
    fn authority_view_prefers_highest_fencing_token() {
        let zone = test_zone();
        let subject = test_subject("authority-subject");
        let eligible = vec![test_node("node-a"), test_node("node-b")];
        let observed = vec![
            observed("node-a", subject, LeasePurpose::SingletonWriter, 100, 7),
            observed("node-b", subject, LeasePurpose::SingletonWriter, 100, 9),
        ];

        let view = AuthorityView::from_observed(
            &zone,
            &subject,
            LeasePurpose::SingletonWriter,
            &eligible,
            &observed,
            50,
            50_000,
        );

        assert_eq!(
            view.active_holder.as_ref().map(TailscaleNodeId::as_str),
            Some("node-b")
        );
        assert_eq!(view.active_fencing_token, Some(9));
        assert_eq!(view.records[0].status, AuthorityStatus::Active);
        assert_eq!(view.records[1].status, AuthorityStatus::Superseded);
    }

    #[test]
    fn authority_view_marks_expired_records() {
        let zone = test_zone();
        let subject = test_subject("expired-subject");
        let eligible = vec![test_node("node-a")];
        let observed = vec![observed(
            "node-a",
            subject,
            LeasePurpose::OperationExecution,
            10,
            3,
        )];

        let view = AuthorityView::from_observed(
            &zone,
            &subject,
            LeasePurpose::OperationExecution,
            &eligible,
            &observed,
            10,
            10_000,
        );

        assert!(view.active_holder.is_none());
        assert_eq!(view.records.len(), 1);
        assert_eq!(view.records[0].status, AuthorityStatus::Expired);
    }

    #[test]
    fn authority_view_roundtrips_json() {
        let zone = test_zone();
        let subject = test_subject("json-subject");
        let eligible = vec![test_node("node-a"), test_node("node-b")];
        let observed = vec![observed(
            "node-a",
            subject,
            LeasePurpose::CoordinatorElection,
            100,
            11,
        )];

        let view = AuthorityView::from_observed(
            &zone,
            &subject,
            LeasePurpose::CoordinatorElection,
            &eligible,
            &observed,
            1,
            1_000,
        );

        let json = serde_json::to_value(&view).expect("serialize authority view");
        let roundtrip: AuthorityView =
            serde_json::from_value(json).expect("deserialize authority view");
        assert_eq!(roundtrip, view);
    }

    #[test]
    fn authority_view_only_marks_exact_winner_active() {
        let zone = test_zone();
        let subject = test_subject("duplicate-subject");
        let eligible = vec![test_node("node-a")];
        let observed = vec![
            observed("node-a", subject, LeasePurpose::SingletonWriter, 100, 7),
            observed("node-a", subject, LeasePurpose::SingletonWriter, 90, 7),
        ];

        let view = AuthorityView::from_observed(
            &zone,
            &subject,
            LeasePurpose::SingletonWriter,
            &eligible,
            &observed,
            50,
            50_000,
        );

        assert_eq!(view.records.len(), 2);
        assert_eq!(view.records[0].status, AuthorityStatus::Active);
        assert_eq!(view.records[0].expires_at, 100);
        assert_eq!(view.records[1].status, AuthorityStatus::Superseded);
        assert_eq!(view.records[1].expires_at, 90);
        assert_eq!(
            view.timeline
                .iter()
                .map(|event| event.operation.as_str())
                .collect::<Vec<_>>(),
            vec![
                "coordinator_selected",
                "authority_active",
                "authority_superseded"
            ]
        );
    }
}
