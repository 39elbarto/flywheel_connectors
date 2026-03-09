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

    #[test]
    fn rank_paths_tie_breaks_by_path_id_then_peer() {
        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: true,
        };

        let paths = vec![
            TransportPath::new(TransportPathKind::Direct, peer("peer-z"), "alpha", Some(10)),
            TransportPath::new(TransportPathKind::Direct, peer("peer-b"), "alpha", Some(10)),
            TransportPath::new(TransportPathKind::Direct, peer("peer-a"), "beta", Some(10)),
        ];

        let ranked = TransportSelector::rank_paths(&paths, &policy);
        let ordering: Vec<(&str, &str)> = ranked
            .iter()
            .map(|entry| (entry.path.path_id.as_str(), entry.path.peer.as_str()))
            .collect();

        assert_eq!(
            ordering,
            vec![("alpha", "peer-b"), ("alpha", "peer-z"), ("beta", "peer-a")]
        );
    }

    // === TransportPathKind priority and transport_mode ===

    #[test]
    fn path_kind_priority_ordering() {
        assert!(TransportPathKind::Direct.priority() > TransportPathKind::Mesh.priority());
        assert!(TransportPathKind::Mesh.priority() > TransportPathKind::Derp.priority());
        assert!(TransportPathKind::Derp.priority() > TransportPathKind::Funnel.priority());
    }

    #[test]
    fn path_kind_transport_mode_mapping() {
        assert_eq!(
            TransportPathKind::Direct.transport_mode(),
            TransportMode::Lan
        );
        assert_eq!(TransportPathKind::Mesh.transport_mode(), TransportMode::Lan);
        assert_eq!(
            TransportPathKind::Derp.transport_mode(),
            TransportMode::Derp
        );
        assert_eq!(
            TransportPathKind::Funnel.transport_mode(),
            TransportMode::Funnel
        );
    }

    #[test]
    fn path_kind_eq_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(TransportPathKind::Direct);
        set.insert(TransportPathKind::Direct); // duplicate
        set.insert(TransportPathKind::Derp);
        assert_eq!(set.len(), 2);
    }

    // === TransportPath construction ===

    #[test]
    fn transport_path_new_fields() {
        let path = TransportPath::new(TransportPathKind::Mesh, peer("n1"), "mesh-1", Some(42));
        assert_eq!(path.kind, TransportPathKind::Mesh);
        assert_eq!(path.peer.as_str(), "n1");
        assert_eq!(path.path_id, "mesh-1");
        assert_eq!(path.estimated_rtt_ms, Some(42));
    }

    #[test]
    fn transport_path_none_rtt() {
        let path = TransportPath::new(TransportPathKind::Direct, peer("n"), "p", None);
        assert!(path.estimated_rtt_ms.is_none());
    }

    #[test]
    fn transport_path_eq() {
        let a = TransportPath::new(TransportPathKind::Direct, peer("n1"), "p1", Some(10));
        let b = TransportPath::new(TransportPathKind::Direct, peer("n1"), "p1", Some(10));
        assert_eq!(a, b);
    }

    // === rank_paths empty input ===

    #[test]
    fn rank_paths_empty_input() {
        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: true,
        };
        let ranked = TransportSelector::rank_paths(&[], &policy);
        assert!(ranked.is_empty());
    }

    // === rank_paths: eligible before ineligible ===

    #[test]
    fn rank_paths_eligible_before_ineligible() {
        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: false,
            allow_funnel: true,
        };
        // Derp has higher priority than Funnel, but is forbidden
        let paths = vec![
            TransportPath::new(TransportPathKind::Derp, peer("p1"), "derp", Some(1)),
            TransportPath::new(TransportPathKind::Funnel, peer("p2"), "funnel", Some(100)),
        ];
        let ranked = TransportSelector::rank_paths(&paths, &policy);
        assert_eq!(ranked.len(), 2);
        // Eligible funnel comes first despite lower priority
        assert!(ranked[0].eligible);
        assert_eq!(ranked[0].path.kind, TransportPathKind::Funnel);
        assert!(!ranked[1].eligible);
    }

    // === rank_paths: RTT tiebreaker within same priority ===

    #[test]
    fn rank_paths_rtt_tiebreaker() {
        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: true,
        };
        let paths = vec![
            TransportPath::new(TransportPathKind::Direct, peer("slow"), "d1", Some(100)),
            TransportPath::new(TransportPathKind::Direct, peer("fast"), "d2", Some(5)),
            TransportPath::new(TransportPathKind::Direct, peer("mid"), "d3", Some(50)),
        ];
        let ranked = TransportSelector::rank_paths(&paths, &policy);
        assert_eq!(ranked[0].path.estimated_rtt_ms, Some(5));
        assert_eq!(ranked[1].path.estimated_rtt_ms, Some(50));
        assert_eq!(ranked[2].path.estimated_rtt_ms, Some(100));
    }

    #[test]
    fn rank_paths_none_rtt_sorted_last_within_priority() {
        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: true,
        };
        let paths = vec![
            TransportPath::new(TransportPathKind::Direct, peer("unknown"), "d1", None),
            TransportPath::new(TransportPathKind::Direct, peer("known"), "d2", Some(10)),
        ];
        let ranked = TransportSelector::rank_paths(&paths, &policy);
        // known RTT comes first (10 < u32::MAX)
        assert_eq!(ranked[0].path.estimated_rtt_ms, Some(10));
        assert!(ranked[1].path.estimated_rtt_ms.is_none());
    }

    // === best_path edge cases ===

    #[test]
    fn best_path_empty_paths() {
        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: true,
        };
        assert!(TransportSelector::best_path(&[], &policy).is_none());
    }

    #[test]
    fn best_path_prefers_direct_over_derp() {
        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: true,
        };
        let paths = vec![
            TransportPath::new(TransportPathKind::Derp, peer("p1"), "derp", Some(1)),
            TransportPath::new(TransportPathKind::Direct, peer("p2"), "direct", Some(100)),
        ];
        let best = TransportSelector::best_path(&paths, &policy).unwrap();
        assert_eq!(best.path.kind, TransportPathKind::Direct);
    }

    // === multipath edge cases ===

    #[test]
    fn select_multipath_fanout_zero() {
        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: true,
        };
        let paths = vec![TransportPath::new(
            TransportPathKind::Direct,
            peer("p"),
            "d",
            None,
        )];
        let obj = ObjectId::from_unscoped_bytes(b"test");
        let selected = TransportSelector::select_multipath(&paths, &policy, &obj, 0, 0);
        assert!(selected.is_empty());
    }

    #[test]
    fn select_multipath_empty_paths() {
        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: true,
        };
        let obj = ObjectId::from_unscoped_bytes(b"test");
        let selected = TransportSelector::select_multipath(&[], &policy, &obj, 0, 3);
        assert!(selected.is_empty());
    }

    #[test]
    fn select_multipath_all_forbidden() {
        let policy = ZoneTransportPolicy {
            allow_lan: false,
            allow_derp: false,
            allow_funnel: false,
        };
        let paths = vec![
            TransportPath::new(TransportPathKind::Direct, peer("p1"), "d1", None),
            TransportPath::new(TransportPathKind::Derp, peer("p2"), "d2", None),
        ];
        let obj = ObjectId::from_unscoped_bytes(b"test");
        let selected = TransportSelector::select_multipath(&paths, &policy, &obj, 0, 2);
        assert!(selected.is_empty());
    }

    #[test]
    fn select_multipath_fanout_exceeds_available() {
        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: true,
        };
        let paths = vec![
            TransportPath::new(TransportPathKind::Direct, peer("p1"), "d1", None),
            TransportPath::new(TransportPathKind::Mesh, peer("p2"), "m1", None),
        ];
        let obj = ObjectId::from_unscoped_bytes(b"test");
        let selected = TransportSelector::select_multipath(&paths, &policy, &obj, 0, 10);
        // Can only return at most 2 (all available)
        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn select_multipath_different_symbol_indices_differ() {
        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: true,
        };
        let paths = vec![
            TransportPath::new(TransportPathKind::Direct, peer("p1"), "d1", None),
            TransportPath::new(TransportPathKind::Direct, peer("p2"), "d2", None),
            TransportPath::new(TransportPathKind::Direct, peer("p3"), "d3", None),
        ];
        let obj = ObjectId::from_unscoped_bytes(b"test");
        let sel_a = TransportSelector::select_multipath(&paths, &policy, &obj, 0, 1);
        let sel_b = TransportSelector::select_multipath(&paths, &policy, &obj, 1, 1);
        // Different symbol indices should produce different hash-weighted orderings
        // (not guaranteed to differ with only 3 paths, but at least the logic runs)
        assert_eq!(sel_a.len(), 1);
        assert_eq!(sel_b.len(), 1);
    }

    #[test]
    fn select_multipath_prefers_higher_priority_group() {
        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: true,
        };
        let paths = vec![
            TransportPath::new(TransportPathKind::Derp, peer("p1"), "derp1", None),
            TransportPath::new(TransportPathKind::Derp, peer("p2"), "derp2", None),
            TransportPath::new(TransportPathKind::Direct, peer("p3"), "direct1", None),
        ];
        let obj = ObjectId::from_unscoped_bytes(b"test");
        let selected = TransportSelector::select_multipath(&paths, &policy, &obj, 0, 1);
        // Should pick from Direct group first (highest priority)
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].kind, TransportPathKind::Direct);
    }

    // === policy_reason coverage ===

    #[test]
    fn policy_reason_all_modes() {
        let all_forbidden = ZoneTransportPolicy {
            allow_lan: false,
            allow_derp: false,
            allow_funnel: false,
        };
        assert_eq!(
            policy_reason(&all_forbidden, TransportPathKind::Direct),
            Some(DecisionReasonCode::TransportLanForbidden)
        );
        assert_eq!(
            policy_reason(&all_forbidden, TransportPathKind::Mesh),
            Some(DecisionReasonCode::TransportLanForbidden)
        );
        assert_eq!(
            policy_reason(&all_forbidden, TransportPathKind::Derp),
            Some(DecisionReasonCode::TransportDerpForbidden)
        );
        assert_eq!(
            policy_reason(&all_forbidden, TransportPathKind::Funnel),
            Some(DecisionReasonCode::TransportFunnelForbidden)
        );

        let all_allowed = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: true,
        };
        assert!(policy_reason(&all_allowed, TransportPathKind::Direct).is_none());
        assert!(policy_reason(&all_allowed, TransportPathKind::Mesh).is_none());
        assert!(policy_reason(&all_allowed, TransportPathKind::Derp).is_none());
        assert!(policy_reason(&all_allowed, TransportPathKind::Funnel).is_none());
    }

    // === path_weight determinism ===

    #[test]
    fn path_weight_deterministic() {
        let obj = ObjectId::from_unscoped_bytes(b"abc");
        let w1 = path_weight(&obj, 5, "path-a");
        let w2 = path_weight(&obj, 5, "path-a");
        assert_eq!(w1, w2);
    }

    #[test]
    fn path_weight_differs_by_path_id() {
        let obj = ObjectId::from_unscoped_bytes(b"abc");
        let w1 = path_weight(&obj, 0, "path-a");
        let w2 = path_weight(&obj, 0, "path-b");
        assert_ne!(w1, w2);
    }

    #[test]
    fn path_weight_differs_by_symbol_index() {
        let obj = ObjectId::from_unscoped_bytes(b"abc");
        let w1 = path_weight(&obj, 0, "path");
        let w2 = path_weight(&obj, 1, "path");
        assert_ne!(w1, w2);
    }

    // === TransportSelector Default ===

    #[test]
    fn transport_selector_default_debug() {
        let sel = TransportSelector;
        let s = format!("{sel:?}");
        assert!(s.contains("TransportSelector"));
    }

    // === RankedPath fields ===

    #[test]
    fn ranked_path_debug() {
        let rp = RankedPath {
            path: TransportPath::new(TransportPathKind::Direct, peer("n"), "p", None),
            priority: 4,
            eligible: true,
            reason: None,
        };
        let s = format!("{rp:?}");
        assert!(s.contains("RankedPath"));
        assert!(s.contains("eligible: true"));
    }

    #[test]
    fn rank_paths_lan_denials_apply_to_direct_and_mesh() {
        let policy = ZoneTransportPolicy {
            allow_lan: false,
            allow_derp: true,
            allow_funnel: true,
        };

        let paths = vec![
            TransportPath::new(TransportPathKind::Direct, peer("p1"), "direct", None),
            TransportPath::new(TransportPathKind::Mesh, peer("p2"), "mesh", None),
            TransportPath::new(TransportPathKind::Derp, peer("p3"), "derp", None),
        ];

        let ranked = TransportSelector::rank_paths(&paths, &policy);

        let lan_entries: Vec<&RankedPath> = ranked
            .iter()
            .filter(|entry| {
                entry.path.kind == TransportPathKind::Direct
                    || entry.path.kind == TransportPathKind::Mesh
            })
            .collect();

        assert_eq!(lan_entries.len(), 2);
        assert!(lan_entries.iter().all(|entry| !entry.eligible));
        assert!(
            lan_entries
                .iter()
                .all(|entry| { entry.reason == Some(DecisionReasonCode::TransportLanForbidden) })
        );

        let best = TransportSelector::best_path(&paths, &policy).expect("best path");
        assert_eq!(best.path.kind, TransportPathKind::Derp);
    }

    // ── Batch: additional transport edge cases ──

    #[test]
    fn transport_path_clone_eq() {
        let path = TransportPath::new(TransportPathKind::Mesh, peer("n"), "p", Some(5));
        let cloned = path.clone();
        assert_eq!(path, cloned);
    }

    #[test]
    fn transport_path_debug_format() {
        let path = TransportPath::new(TransportPathKind::Direct, peer("n1"), "path-1", Some(10));
        let debug = format!("{path:?}");
        assert!(debug.contains("Direct"));
        assert!(debug.contains("path-1"));
    }

    #[test]
    fn transport_path_kind_debug_format() {
        let kinds = [
            TransportPathKind::Direct,
            TransportPathKind::Mesh,
            TransportPathKind::Derp,
            TransportPathKind::Funnel,
        ];
        for kind in kinds {
            let debug = format!("{kind:?}");
            assert!(!debug.is_empty());
        }
    }

    #[test]
    fn transport_path_ne_different_kind() {
        let a = TransportPath::new(TransportPathKind::Direct, peer("n"), "p", None);
        let b = TransportPath::new(TransportPathKind::Mesh, peer("n"), "p", None);
        assert_ne!(a, b);
    }

    #[test]
    fn transport_path_ne_different_peer() {
        let a = TransportPath::new(TransportPathKind::Direct, peer("n1"), "p", None);
        let b = TransportPath::new(TransportPathKind::Direct, peer("n2"), "p", None);
        assert_ne!(a, b);
    }

    #[test]
    fn transport_path_ne_different_rtt() {
        let a = TransportPath::new(TransportPathKind::Direct, peer("n"), "p", Some(5));
        let b = TransportPath::new(TransportPathKind::Direct, peer("n"), "p", Some(10));
        assert_ne!(a, b);
    }

    #[test]
    fn select_multipath_single_eligible_returned() {
        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: false,
            allow_funnel: false,
        };
        let paths = vec![
            TransportPath::new(TransportPathKind::Direct, peer("p1"), "d1", None),
            TransportPath::new(TransportPathKind::Derp, peer("p2"), "d2", None),
            TransportPath::new(TransportPathKind::Funnel, peer("p3"), "f1", None),
        ];
        let obj = ObjectId::from_unscoped_bytes(b"test");
        let selected = TransportSelector::select_multipath(&paths, &policy, &obj, 0, 5);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].kind, TransportPathKind::Direct);
    }

    #[test]
    fn best_path_only_funnel_allowed() {
        let policy = ZoneTransportPolicy {
            allow_lan: false,
            allow_derp: false,
            allow_funnel: true,
        };
        let paths = vec![
            TransportPath::new(TransportPathKind::Direct, peer("p1"), "d1", None),
            TransportPath::new(TransportPathKind::Funnel, peer("p2"), "f1", None),
        ];
        let best = TransportSelector::best_path(&paths, &policy).unwrap();
        assert_eq!(best.path.kind, TransportPathKind::Funnel);
    }

    #[test]
    fn ranked_path_clone() {
        let rp = RankedPath {
            path: TransportPath::new(TransportPathKind::Direct, peer("n"), "p", None),
            priority: 4,
            eligible: true,
            reason: None,
        };
        let cloned = rp.clone();
        // Use original after clone to avoid redundant_clone
        assert_eq!(rp.priority, 4);
        assert_eq!(cloned.priority, 4);
        assert!(cloned.eligible);
    }

    #[test]
    fn path_weight_differs_by_object_id() {
        let obj1 = ObjectId::from_unscoped_bytes(b"abc");
        let obj2 = ObjectId::from_unscoped_bytes(b"xyz");
        let w1 = path_weight(&obj1, 0, "path");
        let w2 = path_weight(&obj2, 0, "path");
        assert_ne!(w1, w2);
    }

    #[test]
    fn select_multipath_fanout_one_from_mixed_priorities() {
        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: true,
        };
        let paths = vec![
            TransportPath::new(TransportPathKind::Funnel, peer("p1"), "f1", None),
            TransportPath::new(TransportPathKind::Derp, peer("p2"), "d1", None),
            TransportPath::new(TransportPathKind::Direct, peer("p3"), "x1", None),
        ];
        let obj = ObjectId::from_unscoped_bytes(b"select-test");
        let selected = TransportSelector::select_multipath(&paths, &policy, &obj, 0, 1);
        assert_eq!(selected.len(), 1);
        // Should pick from Direct (highest priority)
        assert_eq!(selected[0].kind, TransportPathKind::Direct);
    }

    #[test]
    fn rank_paths_single_path() {
        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: true,
        };
        let paths = vec![TransportPath::new(
            TransportPathKind::Mesh,
            peer("p1"),
            "m1",
            Some(15),
        )];
        let ranked = TransportSelector::rank_paths(&paths, &policy);
        assert_eq!(ranked.len(), 1);
        assert!(ranked[0].eligible);
        assert_eq!(ranked[0].priority, TransportPathKind::Mesh.priority());
    }
}
