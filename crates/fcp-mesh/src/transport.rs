//! Transport path selection and deterministic multipath routing.
//!
//! This module provides a deterministic ordering of candidate transport paths
//! based on spec-aligned priority and zone policy. It also supports a
//! deterministic multipath selection strategy for symbol delivery.

#![forbid(unsafe_code)]

use blake3::Hasher;
use fcp_core::{DecisionReasonCode, ObjectId, TransportMode, ZoneTransportPolicy};
use fcp_tailscale::NodeId;
use std::cmp::Reverse;

/// Transport path kinds observed by MeshNode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportPathKind {
    /// Direct LAN transport.
    Direct,
    /// NAT-traversed mesh transport.
    Mesh,
    /// DERP relay transport.
    Derp,
    /// Funnel/public ingress transport.
    Funnel,
}

impl TransportPathKind {
    const fn priority(self) -> u8 {
        match self {
            Self::Direct => 4,
            Self::Mesh => 3,
            Self::Derp => 2,
            Self::Funnel => 1,
        }
    }

    const fn transport_mode(self) -> TransportMode {
        match self {
            Self::Direct | Self::Mesh => TransportMode::Lan,
            Self::Derp => TransportMode::Derp,
            Self::Funnel => TransportMode::Funnel,
        }
    }
}

/// A candidate transport path to a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportPath {
    /// Transport kind (priority class).
    pub kind: TransportPathKind,
    /// Peer node for this path.
    pub peer: NodeId,
    /// Stable identifier for deterministic ordering.
    pub path_id: String,
    /// Estimated round-trip time in milliseconds (if known).
    pub estimated_rtt_ms: Option<u32>,
}

impl TransportPath {
    /// Construct a new transport path.
    #[must_use]
    pub fn new(
        kind: TransportPathKind,
        peer: NodeId,
        path_id: impl Into<String>,
        estimated_rtt_ms: Option<u32>,
    ) -> Self {
        Self {
            kind,
            peer,
            path_id: path_id.into(),
            estimated_rtt_ms,
        }
    }
}

/// Ranked path with eligibility and policy reason.
#[derive(Debug, Clone)]
pub struct RankedPath {
    pub path: TransportPath,
    pub priority: u8,
    pub eligible: bool,
    pub reason: Option<DecisionReasonCode>,
}

/// Transport selector for MeshNode routing decisions.
#[derive(Debug, Default)]
pub struct TransportSelector;

impl TransportSelector {
    /// Rank candidate paths by priority and policy.
    #[must_use]
    pub fn rank_paths(paths: &[TransportPath], policy: &ZoneTransportPolicy) -> Vec<RankedPath> {
        let mut ranked: Vec<RankedPath> = paths
            .iter()
            .cloned()
            .map(|path| {
                let reason = policy_reason(policy, path.kind);
                RankedPath {
                    priority: path.kind.priority(),
                    eligible: reason.is_none(),
                    reason,
                    path,
                }
            })
            .collect();

        ranked.sort_by(|a, b| {
            let eligible_cmp = b.eligible.cmp(&a.eligible);
            if eligible_cmp != std::cmp::Ordering::Equal {
                return eligible_cmp;
            }

            let priority_cmp = b.priority.cmp(&a.priority);
            if priority_cmp != std::cmp::Ordering::Equal {
                return priority_cmp;
            }

            let rtt_a = a.path.estimated_rtt_ms.unwrap_or(u32::MAX);
            let rtt_b = b.path.estimated_rtt_ms.unwrap_or(u32::MAX);
            let rtt_cmp = rtt_a.cmp(&rtt_b);
            if rtt_cmp != std::cmp::Ordering::Equal {
                return rtt_cmp;
            }

            let id_cmp = a.path.path_id.cmp(&b.path.path_id);
            if id_cmp != std::cmp::Ordering::Equal {
                return id_cmp;
            }

            a.path.peer.as_str().cmp(b.path.peer.as_str())
        });

        ranked
    }

    /// Select the best eligible path according to policy and priority.
    #[must_use]
    pub fn best_path(paths: &[TransportPath], policy: &ZoneTransportPolicy) -> Option<RankedPath> {
        Self::rank_paths(paths, policy)
            .into_iter()
            .find(|path| path.eligible)
    }

    /// Select deterministic multipath routes for a symbol.
    #[must_use]
    pub fn select_multipath(
        paths: &[TransportPath],
        policy: &ZoneTransportPolicy,
        object_id: &ObjectId,
        symbol_index: u32,
        fanout: usize,
    ) -> Vec<TransportPath> {
        if fanout == 0 {
            return Vec::new();
        }

        let ranked = Self::rank_paths(paths, policy);
        let mut eligible: Vec<RankedPath> = ranked.into_iter().filter(|p| p.eligible).collect();
        if eligible.is_empty() {
            return Vec::new();
        }

        eligible.sort_by_key(|entry| Reverse(entry.priority));

        let mut selected = Vec::new();
        let mut idx = 0;
        while idx < eligible.len() && selected.len() < fanout {
            let current_priority = eligible[idx].priority;
            let mut group = Vec::new();
            while idx < eligible.len() && eligible[idx].priority == current_priority {
                group.push(eligible[idx].path.clone());
                idx += 1;
            }

            group.sort_by(|a, b| {
                let ha = path_weight(object_id, symbol_index, &a.path_id);
                let hb = path_weight(object_id, symbol_index, &b.path_id);
                ha.cmp(&hb)
            });

            for path in group {
                if selected.len() >= fanout {
                    break;
                }
                selected.push(path);
            }
        }

        selected
    }
}

fn policy_reason(
    policy: &ZoneTransportPolicy,
    kind: TransportPathKind,
) -> Option<DecisionReasonCode> {
    let mode = kind.transport_mode();
    if policy.allows(mode) {
        None
    } else {
        Some(match mode {
            TransportMode::Lan => DecisionReasonCode::TransportLanForbidden,
            TransportMode::Derp => DecisionReasonCode::TransportDerpForbidden,
            TransportMode::Funnel => DecisionReasonCode::TransportFunnelForbidden,
        })
    }
}

fn path_weight(object_id: &ObjectId, symbol_index: u32, path_id: &str) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(object_id.as_bytes());
    hasher.update(&symbol_index.to_le_bytes());
    hasher.update(path_id.as_bytes());
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(name: &str) -> NodeId {
        NodeId::new(name)
    }

    #[test]
    fn rank_paths_orders_by_priority_then_rtt() {
        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: true,
        };

        let paths = vec![
            TransportPath::new(TransportPathKind::Funnel, peer("p4"), "funnel", Some(5)),
            TransportPath::new(TransportPathKind::Derp, peer("p3"), "derp", Some(5)),
            TransportPath::new(TransportPathKind::Mesh, peer("p2"), "mesh", Some(10)),
            TransportPath::new(TransportPathKind::Direct, peer("p1"), "direct", Some(20)),
        ];

        let ranked = TransportSelector::rank_paths(&paths, &policy);
        let kinds: Vec<TransportPathKind> = ranked.iter().map(|r| r.path.kind).collect();
        assert_eq!(
            kinds,
            vec![
                TransportPathKind::Direct,
                TransportPathKind::Mesh,
                TransportPathKind::Derp,
                TransportPathKind::Funnel
            ]
        );
    }

    #[test]
    fn rank_paths_respects_policy() {
        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: false,
            allow_funnel: false,
        };

        let paths = vec![
            TransportPath::new(TransportPathKind::Direct, peer("p1"), "direct", None),
            TransportPath::new(TransportPathKind::Derp, peer("p2"), "derp", None),
            TransportPath::new(TransportPathKind::Funnel, peer("p3"), "funnel", None),
        ];

        let ranked = TransportSelector::rank_paths(&paths, &policy);
        let mut found_derp = None;
        let mut found_funnel = None;
        let mut found_direct = None;
        for entry in ranked {
            match entry.path.kind {
                TransportPathKind::Derp => found_derp = Some(entry),
                TransportPathKind::Funnel => found_funnel = Some(entry),
                TransportPathKind::Direct => found_direct = Some(entry),
                TransportPathKind::Mesh => {}
            }
        }

        let direct = found_direct.expect("direct path missing");
        assert!(direct.eligible);
        assert!(direct.reason.is_none());

        let derp = found_derp.expect("derp path missing");
        assert!(!derp.eligible);
        assert_eq!(
            derp.reason,
            Some(DecisionReasonCode::TransportDerpForbidden)
        );

        let funnel = found_funnel.expect("funnel path missing");
        assert!(!funnel.eligible);
        assert_eq!(
            funnel.reason,
            Some(DecisionReasonCode::TransportFunnelForbidden)
        );
    }

    #[test]
    fn multipath_selection_is_deterministic_and_prioritized() {
        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: true,
        };

        let paths = vec![
            TransportPath::new(TransportPathKind::Direct, peer("p1"), "direct-a", None),
            TransportPath::new(TransportPathKind::Direct, peer("p2"), "direct-b", None),
            TransportPath::new(TransportPathKind::Mesh, peer("p3"), "mesh-a", None),
            TransportPath::new(TransportPathKind::Derp, peer("p4"), "derp-a", None),
        ];

        let object_id = ObjectId::from_unscoped_bytes(b"object-1");
        let selection_a = TransportSelector::select_multipath(&paths, &policy, &object_id, 7, 2);
        let selection_b = TransportSelector::select_multipath(&paths, &policy, &object_id, 7, 2);

        assert_eq!(selection_a.len(), 2);
        assert_eq!(selection_a, selection_b);
        assert!(
            selection_a
                .iter()
                .all(|path| path.kind == TransportPathKind::Direct)
        );
    }

    #[test]
    fn best_path_selects_highest_priority() {
        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: true,
        };

        let paths = vec![
            TransportPath::new(TransportPathKind::Derp, peer("p3"), "derp", None),
            TransportPath::new(TransportPathKind::Mesh, peer("p2"), "mesh", None),
            TransportPath::new(TransportPathKind::Direct, peer("p1"), "direct", None),
        ];

        let best = TransportSelector::best_path(&paths, &policy).expect("best path");
        assert_eq!(best.path.kind, TransportPathKind::Direct);
    }

    #[test]
    fn best_path_none_when_forbidden() {
        let policy = ZoneTransportPolicy {
            allow_lan: false,
            allow_derp: false,
            allow_funnel: false,
        };

        let paths = vec![
            TransportPath::new(TransportPathKind::Direct, peer("p1"), "direct", None),
            TransportPath::new(TransportPathKind::Derp, peer("p2"), "derp", None),
        ];

        let best = TransportSelector::best_path(&paths, &policy);
        assert!(best.is_none());
    }

    #[test]
    fn best_path_prefers_lower_rtt_when_same_priority() {
        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: true,
        };

        let paths = vec![
            TransportPath::new(
                TransportPathKind::Direct,
                peer("p1"),
                "direct-high",
                Some(50),
            ),
            TransportPath::new(TransportPathKind::Direct, peer("p2"), "direct-low", Some(5)),
        ];

        let best = TransportSelector::best_path(&paths, &policy).expect("best path");
        assert_eq!(best.path.path_id, "direct-low");
    }
}
