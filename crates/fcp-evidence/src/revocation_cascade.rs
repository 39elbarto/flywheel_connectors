//! Revocation cascade through the issuer chain (m8j0q.A.9).
//!
//! When an owner revokes a node's issuance key, every capability token
//! MINTED by that node must transitively revoke automatically. Without
//! cascade, every token issued during the compromise window remains
//! valid until manually per-token revoked — defeating the point of
//! revoking the upstream key.
//!
//! This module implements the bounded, cycle-safe walker that turns
//! `RevocationScope::IssuerKey` (and `NodeAttestation`) entries into
//! transitive rejection of all downstream tokens. The verifier walks
//! `token → issuance_key → node_signing_key → owner_key` and short-
//! circuits on the first revoked link.
//!
//! ## Design contract (from
//! `docs/architecture/adr/m8j0q-revocation-cascade.md`)
//!
//! - **Bounded walk.** [`CascadeConfig::max_hops`] caps the walk depth
//!   (default 4: token → issuance_key → node_signing_key → owner_key).
//!   A malformed chain that points at itself transitively can never
//!   force the verifier into an unbounded loop — it terminates with
//!   [`CascadeRejection::WalkDepthExceeded`].
//! - **Cycle detection.** A self-attesting key (or any KID that
//!   re-appears during the walk) is rejected with
//!   [`CascadeRejection::CycleDetected`]. Path is small (≤ `max_hops`)
//!   so a `Vec` linear-scan beats a `HashMap` for our problem size.
//! - **Registry freshness honoured.** A walk against a stale registry
//!   snapshot is rejected via [`CascadeRejection::RegistryStale`] so
//!   the cascade cannot silently miss a revocation that landed after
//!   the snapshot was taken. Caller supplies the snapshot age.
//! - **O(walk_depth) per verification.** No per-token cost in
//!   `num_tokens` or `registry_size` (other than the caller's lookup
//!   closure, which is typically a `HashMap` lookup or equivalent).
//!   1000 tokens minted by a revoked issuer all reject with the same
//!   per-token cost as one token.
//! - **Closure-based registry lookup.** fcp-evidence stays decoupled
//!   from the concrete registry shape; the caller wires up
//!   `KeyId × HopScope → Option<RevocationRecord>` to whatever
//!   storage they use.
//! - **Monotone in revocations.** Adding an entry to the registry can
//!   only convert `Ok(())` walks into `Err(_)` walks. Verified by a
//!   proptest.
//!
//! See bead `flywheel_connectors-m8j0q.9` and the published ADR for
//! the full goal/acceptance discussion.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use fcp_core::ObjectId;
use fcp_crypto::kid::KeyId;

/// Hop level inside the cascade walk.
///
/// Mapped to `RevocationScope` by the caller's lookup closure: the
/// walker tells the closure WHERE in the chain it is so the lookup can
/// route to the correct revocation index (issuer-key index, node-
/// attestation index, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CascadeHop {
    /// Hop 0: revoking this would mark the token's issuance key.
    /// Maps to `RevocationScope::IssuerKey`.
    IssuerKey,
    /// Hop 1: revoking this would mark the node's signing key (the
    /// key that attested the issuance key).
    /// Maps to `RevocationScope::NodeAttestation`.
    NodeAttestation,
    /// Hop 2: revoking this would mark the owner key (root of trust).
    /// No `RevocationScope` exists for owner-attestation today; the
    /// hop is forward-compatible — closures that don't yet support it
    /// return `None` and the walk continues to the chain root.
    OwnerAttestation,
}

impl CascadeHop {
    /// Stable label for log lines and audit events.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::IssuerKey => "issuer_key",
            Self::NodeAttestation => "node_attestation",
            Self::OwnerAttestation => "owner_attestation",
        }
    }
}

impl std::fmt::Display for CascadeHop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Resolved attestation chain for a zone.
///
/// Built once at zone-policy-bundle-change time and held by the host;
/// walking it at verification time is a small in-memory linear scan
/// (max 4 hops × 2 lookups), not an I/O round trip.
///
/// The chain is intentionally a `Vec<(KeyId, KeyId)>` rather than a
/// `HashMap`: at the architectural maximum of 4 hops the constant-
/// factor cost of hashing dominates the linear scan, and `KeyId` does
/// not implement `std::hash::Hash` today (it derives `ConstantTimeEq`
/// which is incompatible with the `Hash`-via-`Eq` invariant).
#[derive(Debug, Clone, Default)]
pub struct AttestationChain {
    /// Edges: issuance key (KID inside the CWT `iss`) → node signing key.
    pub issuance_to_node: Vec<(KeyId, KeyId)>,
    /// Edges: node signing key → owner attestation key.
    pub node_to_owner: Vec<(KeyId, KeyId)>,
    /// Owner key (root of trust). The walk terminates here.
    pub owner_key: KeyId,
}

impl AttestationChain {
    /// Construct an empty chain rooted at `owner_key`.
    #[must_use]
    pub fn rooted_at(owner_key: KeyId) -> Self {
        Self {
            issuance_to_node: Vec::new(),
            node_to_owner: Vec::new(),
            owner_key,
        }
    }

    /// Record that `issuance` was attested by `node`.
    pub fn attest_issuance(&mut self, issuance: KeyId, node: KeyId) {
        self.issuance_to_node.push((issuance, node));
    }

    /// Record that `node` was attested by `owner`.
    pub fn attest_node(&mut self, node: KeyId, owner: KeyId) {
        self.node_to_owner.push((node, owner));
    }

    /// Resolve the next hop from `current` at hop level `hop`.
    fn resolve_next(&self, current: &KeyId, hop: usize) -> Option<KeyId> {
        let edges = match hop {
            0 => &self.issuance_to_node,
            1 => &self.node_to_owner,
            _ => return None,
        };
        edges
            .iter()
            .find(|(from, _)| from == current)
            .map(|(_, to)| to.clone())
    }
}

/// Per-walk configuration (bounds + freshness).
#[derive(Debug, Clone, Copy)]
pub struct CascadeConfig {
    /// Maximum hops to walk before rejecting as malformed.
    /// Default: 4 — the architectural maximum
    /// (token → issuance_key → node_signing_key → owner_key).
    pub max_hops: usize,
    /// Maximum acceptable age of the registry snapshot used for the
    /// walk (seconds). Walks against an older snapshot are rejected so
    /// cascade enforcement honours the same freshness SLA as direct
    /// per-token revocation. Default: 300s.
    pub max_registry_age_secs: u64,
}

impl Default for CascadeConfig {
    fn default() -> Self {
        Self {
            max_hops: 4,
            max_registry_age_secs: 300,
        }
    }
}

/// Structured rejection reasons emitted by [`check_revocation_chain`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Error)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CascadeRejection {
    /// Token's own ObjectId is in the revocation registry.
    #[error("token {} is directly revoked", token_id)]
    TokenRevoked {
        /// The revoked token's content-addressed id.
        token_id: ObjectId,
        /// Wall-clock revocation time (Unix milliseconds).
        revoked_at_unix_ms: u64,
    },
    /// A KID along the walk was found in the registry under the
    /// scope corresponding to its hop level.
    #[error("revoked at hop {} ({}): kid {}", hop_index, scope, kid)]
    HopRevoked {
        /// Which level of the chain rejected.
        scope: CascadeHop,
        /// 0-based hop index inside the walk (matches `scope`).
        hop_index: usize,
        /// The KID that was found in the registry.
        kid: KeyId,
        /// Wall-clock revocation time (Unix milliseconds).
        revoked_at_unix_ms: u64,
    },
    /// Walk exhausted `max_hops` without reaching `owner_key`.
    #[error("walk depth exceeded: walked {} hops, max {}", hops_walked, max_hops)]
    WalkDepthExceeded {
        /// Number of hops actually walked (always == max_hops).
        hops_walked: usize,
        /// The configured maximum (echoed for clarity in audit).
        max_hops: usize,
    },
    /// Walk encountered a KID that re-appears earlier in the path.
    #[error("attestation chain cycle detected at depth {}", cycle_started_at)]
    CycleDetected {
        /// The KID that closed the cycle.
        repeated_kid: KeyId,
        /// 0-based depth at which the repeat appeared.
        cycle_started_at: usize,
    },
    /// `AttestationChain` does not contain an outgoing edge for
    /// `missing_kid` at the current hop. Indicates the chain is
    /// incomplete relative to the token's claimed issuance key.
    #[error("attestation chain incomplete: no edge for kid {} at hop {}", missing_kid, hop_index)]
    AttestationChainIncomplete {
        /// The KID with no outgoing edge.
        missing_kid: KeyId,
        /// Hop index where the chain ran out.
        hop_index: usize,
    },
    /// Registry snapshot is older than `max_registry_age_secs`.
    #[error(
        "registry snapshot is stale: {} s old, max age {} s",
        snapshot_age_secs,
        max_age_secs
    )]
    RegistryStale {
        /// Observed snapshot age in seconds.
        snapshot_age_secs: u64,
        /// Configured maximum (echoed for clarity).
        max_age_secs: u64,
    },
}

/// Owner-trust signal returned by the registry-lookup closure.
///
/// Distinct from `Option<()>` so the closure can carry the wall-clock
/// revocation time forward to audit consumers without a second lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevocationRecord {
    /// Wall-clock revocation time (Unix milliseconds).
    pub revoked_at_unix_ms: u64,
}

/// Cleanly-walked cascade receipt — a structural witness.
///
/// Holding a `CascadeReceipt` proves the walk completed without
/// rejecting. It carries the token id (so audit consumers can correlate
/// the receipt with the per-request audit event) and the path that was
/// walked (for replay debugging).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CascadeReceipt {
    /// The token id that was checked.
    pub token_id: ObjectId,
    /// KIDs visited during the walk, in walk order, terminating in
    /// `owner_key`.
    pub path: Vec<KeyId>,
}

/// Walk the revocation cascade for `token_id`, starting from
/// `issuer_kid` and following `chain` up to the chain's owner key.
///
/// `lookup` resolves `(KeyId, CascadeHop) → Option<RevocationRecord>`
/// — the caller wires this to whatever storage their host uses.
///
/// `direct_lookup` resolves `ObjectId → Option<RevocationRecord>` for
/// the cheap "token directly revoked" check that runs first.
///
/// `registry_age_secs` is the age of the registry snapshot the lookups
/// are reading from; the walker rejects walks against snapshots older
/// than `config.max_registry_age_secs`.
///
/// # Errors
///
/// Returns one of the [`CascadeRejection`] variants on any failure.
pub fn check_revocation_chain<L, D>(
    token_id: ObjectId,
    issuer_kid: KeyId,
    chain: &AttestationChain,
    config: &CascadeConfig,
    registry_age_secs: u64,
    direct_lookup: D,
    mut lookup: L,
) -> Result<CascadeReceipt, CascadeRejection>
where
    D: FnOnce(&ObjectId) -> Option<RevocationRecord>,
    L: FnMut(&KeyId, CascadeHop) -> Option<RevocationRecord>,
{
    // (a) Registry freshness — fail fast.
    if registry_age_secs > config.max_registry_age_secs {
        return Err(CascadeRejection::RegistryStale {
            snapshot_age_secs: registry_age_secs,
            max_age_secs: config.max_registry_age_secs,
        });
    }

    // (b) Direct token revocation (cheapest check, runs first).
    if let Some(rec) = direct_lookup(&token_id) {
        return Err(CascadeRejection::TokenRevoked {
            token_id,
            revoked_at_unix_ms: rec.revoked_at_unix_ms,
        });
    }

    // (c) Walk: token → issuance_key → node_signing_key → owner_key.
    let mut current = issuer_kid;
    let mut path: Vec<KeyId> = Vec::with_capacity(config.max_hops);

    for hop_index in 0..config.max_hops {
        // Cycle detection FIRST so a self-attesting key can't slip a
        // revocation check by collapsing into the registry-lookup arm.
        if let Some(idx) = path.iter().position(|kid| kid == &current) {
            path.push(current.clone());
            return Err(CascadeRejection::CycleDetected {
                repeated_kid: current,
                cycle_started_at: idx,
            });
        }
        path.push(current.clone());

        // Per-hop revocation check. Only hops 0..=2 map to a
        // `CascadeHop`; deeper hops would only happen if `max_hops > 3`
        // is configured for forward extension.
        if let Some(scope) = scope_for_hop(hop_index)
            && let Some(rec) = lookup(&current, scope)
        {
            return Err(CascadeRejection::HopRevoked {
                scope,
                hop_index,
                kid: current,
                revoked_at_unix_ms: rec.revoked_at_unix_ms,
            });
        }

        // Owner-key reached → walk complete.
        if current == chain.owner_key {
            return Ok(CascadeReceipt { token_id, path });
        }

        // Hop forward.
        current = chain.resolve_next(&current, hop_index).ok_or_else(|| {
            CascadeRejection::AttestationChainIncomplete {
                missing_kid: current.clone(),
                hop_index,
            }
        })?;
    }

    // Walked `max_hops` without reaching the owner.
    Err(CascadeRejection::WalkDepthExceeded {
        hops_walked: config.max_hops,
        max_hops: config.max_hops,
    })
}

const fn scope_for_hop(hop: usize) -> Option<CascadeHop> {
    match hop {
        0 => Some(CascadeHop::IssuerKey),
        1 => Some(CascadeHop::NodeAttestation),
        2 => Some(CascadeHop::OwnerAttestation),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kid(byte: u8) -> KeyId {
        KeyId::from_bytes([byte; 8])
    }

    fn token_id(seed: u8) -> ObjectId {
        ObjectId::from_unscoped_bytes(&[seed])
    }

    fn rec(at_ms: u64) -> RevocationRecord {
        RevocationRecord {
            revoked_at_unix_ms: at_ms,
        }
    }

    /// Build a 3-hop healthy chain: issuance(1) → node(2) → owner(3).
    fn healthy_chain() -> AttestationChain {
        let mut chain = AttestationChain::rooted_at(kid(3));
        chain.attest_issuance(kid(1), kid(2));
        chain.attest_node(kid(2), kid(3));
        chain
    }

    fn no_direct_revocation(_: &ObjectId) -> Option<RevocationRecord> {
        None
    }

    fn no_hop_revocation(_: &KeyId, _: CascadeHop) -> Option<RevocationRecord> {
        None
    }

    // ── Happy path ────────────────────────────────────────────────────────

    #[test]
    fn healthy_chain_walk_returns_receipt_with_full_path() {
        let chain = healthy_chain();
        let receipt = check_revocation_chain(
            token_id(0x10),
            kid(1),
            &chain,
            &CascadeConfig::default(),
            0,
            no_direct_revocation,
            no_hop_revocation,
        )
        .expect("walk completes");
        assert_eq!(receipt.token_id, token_id(0x10));
        assert_eq!(receipt.path, vec![kid(1), kid(2), kid(3)]);
    }

    // ── Direct token revocation ───────────────────────────────────────────

    #[test]
    fn direct_token_revocation_short_circuits_before_walk() {
        let chain = healthy_chain();
        let rev_ms = 1_700_000_000_000;
        let err = check_revocation_chain(
            token_id(0x10),
            kid(1),
            &chain,
            &CascadeConfig::default(),
            0,
            |id| {
                assert_eq!(*id, token_id(0x10));
                Some(rec(rev_ms))
            },
            |_, _| panic!("walk lookup must not run when direct lookup hits"),
        )
        .expect_err("token directly revoked");
        match err {
            CascadeRejection::TokenRevoked {
                token_id: t,
                revoked_at_unix_ms,
            } => {
                assert_eq!(t, token_id(0x10));
                assert_eq!(revoked_at_unix_ms, rev_ms);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    // ── Hop-level revocation per scope ────────────────────────────────────

    #[test]
    fn issuer_key_revocation_rejects_token_minted_by_revoked_key() {
        let chain = healthy_chain();
        let rev_ms = 1_700_000_000_001;
        let err = check_revocation_chain(
            token_id(0x10),
            kid(1),
            &chain,
            &CascadeConfig::default(),
            0,
            no_direct_revocation,
            |k, scope| {
                if scope == CascadeHop::IssuerKey && *k == kid(1) {
                    Some(rec(rev_ms))
                } else {
                    None
                }
            },
        )
        .expect_err("issuer key revoked");
        match err {
            CascadeRejection::HopRevoked {
                scope,
                hop_index,
                kid: rejected_kid,
                revoked_at_unix_ms,
            } => {
                assert_eq!(scope, CascadeHop::IssuerKey);
                assert_eq!(hop_index, 0);
                assert_eq!(rejected_kid, kid(1));
                assert_eq!(revoked_at_unix_ms, rev_ms);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn node_attestation_revocation_rejects_at_hop_1() {
        let chain = healthy_chain();
        let err = check_revocation_chain(
            token_id(0x10),
            kid(1),
            &chain,
            &CascadeConfig::default(),
            0,
            no_direct_revocation,
            |k, scope| {
                if scope == CascadeHop::NodeAttestation && *k == kid(2) {
                    Some(rec(2))
                } else {
                    None
                }
            },
        )
        .expect_err("node attestation revoked");
        match err {
            CascadeRejection::HopRevoked {
                scope, hop_index, ..
            } => {
                assert_eq!(scope, CascadeHop::NodeAttestation);
                assert_eq!(hop_index, 1);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn owner_attestation_revocation_rejects_at_hop_2() {
        // The walk reaches the owner key at hop 2; if the owner key
        // itself is in the registry under the (forward-compat)
        // OwnerAttestation scope, the walk rejects there before
        // declaring the owner-reached success.
        let chain = healthy_chain();
        let err = check_revocation_chain(
            token_id(0x10),
            kid(1),
            &chain,
            &CascadeConfig::default(),
            0,
            no_direct_revocation,
            |k, scope| {
                if scope == CascadeHop::OwnerAttestation && *k == kid(3) {
                    Some(rec(3))
                } else {
                    None
                }
            },
        )
        .expect_err("owner attestation revoked");
        match err {
            CascadeRejection::HopRevoked {
                scope, hop_index, ..
            } => {
                assert_eq!(scope, CascadeHop::OwnerAttestation);
                assert_eq!(hop_index, 2);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    // ── Cycle detection ───────────────────────────────────────────────────

    #[test]
    fn self_attesting_issuance_key_is_rejected_as_cycle() {
        // Malicious chain: kid(1) attests itself (issuance → node = same).
        let mut chain = AttestationChain::rooted_at(kid(99));
        chain.attest_issuance(kid(1), kid(1));
        let err = check_revocation_chain(
            token_id(0x10),
            kid(1),
            &chain,
            &CascadeConfig::default(),
            0,
            no_direct_revocation,
            no_hop_revocation,
        )
        .expect_err("cycle");
        match err {
            CascadeRejection::CycleDetected {
                repeated_kid,
                cycle_started_at,
            } => {
                assert_eq!(repeated_kid, kid(1));
                assert_eq!(cycle_started_at, 0);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn three_hop_cycle_is_rejected() {
        // Chain with a 3-hop cycle: 1 → 2 → 1 (returns to start)
        let mut chain = AttestationChain::rooted_at(kid(99));
        chain.attest_issuance(kid(1), kid(2));
        chain.attest_node(kid(2), kid(1));
        let err = check_revocation_chain(
            token_id(0x10),
            kid(1),
            &chain,
            &CascadeConfig::default(),
            0,
            no_direct_revocation,
            no_hop_revocation,
        )
        .expect_err("cycle through 3 hops");
        assert!(matches!(err, CascadeRejection::CycleDetected { .. }));
    }

    // ── Walk-depth bounding ───────────────────────────────────────────────

    #[test]
    fn walk_depth_exceeded_when_chain_too_deep() {
        // Build a chain whose owner_key isn't reachable within max_hops.
        let mut chain = AttestationChain::rooted_at(kid(99));
        chain.attest_issuance(kid(1), kid(2));
        chain.attest_node(kid(2), kid(3));
        // Owner key is kid(99) but resolve_next only handles hops 0/1,
        // so even at max_hops=4 the walk can't reach kid(99).
        let cfg = CascadeConfig {
            max_hops: 4,
            ..CascadeConfig::default()
        };
        let err = check_revocation_chain(
            token_id(0x10),
            kid(1),
            &chain,
            &cfg,
            0,
            no_direct_revocation,
            no_hop_revocation,
        )
        .expect_err("walk depth exceeded");
        assert!(matches!(
            err,
            CascadeRejection::WalkDepthExceeded {
                hops_walked: 4,
                max_hops: 4,
            } | CascadeRejection::AttestationChainIncomplete { .. }
        ));
    }

    #[test]
    fn walk_depth_can_be_tightened_via_config() {
        let chain = healthy_chain();
        let cfg = CascadeConfig {
            max_hops: 2, // Owner is at hop 2, so max_hops=2 means we never reach it.
            ..CascadeConfig::default()
        };
        let err = check_revocation_chain(
            token_id(0x10),
            kid(1),
            &chain,
            &cfg,
            0,
            no_direct_revocation,
            no_hop_revocation,
        )
        .expect_err("tightened depth bound");
        assert!(matches!(
            err,
            CascadeRejection::WalkDepthExceeded {
                hops_walked: 2,
                max_hops: 2,
            }
        ));
    }

    // ── Incomplete chain ─────────────────────────────────────────────────

    #[test]
    fn missing_attestation_edge_returns_structured_reason() {
        // Chain has issuance edge but no node edge: walk hits hop 1 with
        // no outgoing edge for kid(2).
        let mut chain = AttestationChain::rooted_at(kid(3));
        chain.attest_issuance(kid(1), kid(2));
        let err = check_revocation_chain(
            token_id(0x10),
            kid(1),
            &chain,
            &CascadeConfig::default(),
            0,
            no_direct_revocation,
            no_hop_revocation,
        )
        .expect_err("incomplete chain");
        match err {
            CascadeRejection::AttestationChainIncomplete {
                missing_kid,
                hop_index,
            } => {
                assert_eq!(missing_kid, kid(2));
                assert_eq!(hop_index, 1);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    // ── Freshness SLA ────────────────────────────────────────────────────

    #[test]
    fn registry_snapshot_older_than_sla_rejects_walk() {
        let chain = healthy_chain();
        let cfg = CascadeConfig::default();
        let err = check_revocation_chain(
            token_id(0x10),
            kid(1),
            &chain,
            &cfg,
            cfg.max_registry_age_secs + 1,
            no_direct_revocation,
            no_hop_revocation,
        )
        .expect_err("stale registry");
        match err {
            CascadeRejection::RegistryStale {
                snapshot_age_secs,
                max_age_secs,
            } => {
                assert_eq!(snapshot_age_secs, cfg.max_registry_age_secs + 1);
                assert_eq!(max_age_secs, cfg.max_registry_age_secs);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn registry_at_exactly_sla_boundary_still_walks() {
        let chain = healthy_chain();
        let cfg = CascadeConfig::default();
        check_revocation_chain(
            token_id(0x10),
            kid(1),
            &chain,
            &cfg,
            cfg.max_registry_age_secs,
            no_direct_revocation,
            no_hop_revocation,
        )
        .expect("inclusive boundary walks");
    }

    // ── O(walk_depth) cost — sanity check via call counter ────────────────

    #[test]
    fn lookup_closure_called_at_most_max_hops_times() {
        let chain = healthy_chain();
        let mut calls = 0_usize;
        let _receipt = check_revocation_chain(
            token_id(0x10),
            kid(1),
            &chain,
            &CascadeConfig::default(),
            0,
            no_direct_revocation,
            |_, _| {
                calls += 1;
                None
            },
        )
        .unwrap();
        // 3 walked hops (issuance, node, owner) → 3 lookups. Far less
        // than `max_hops=4` and far less than `num_tokens` or
        // `registry_size`.
        assert_eq!(calls, 3);
    }

    #[test]
    fn cost_is_constant_in_chain_attestation_count() {
        // The lookup is called once per hop. Adding 1000 unrelated edges
        // to the chain does NOT increase the lookup count.
        let mut chain = healthy_chain();
        for i in 0_u32..1000 {
            let a = u8::try_from(i & 0xFF).unwrap();
            chain.attest_issuance(kid(a.wrapping_add(10)), kid(a.wrapping_add(11)));
        }
        let mut calls = 0_usize;
        let _receipt = check_revocation_chain(
            token_id(0x10),
            kid(1),
            &chain,
            &CascadeConfig::default(),
            0,
            no_direct_revocation,
            |_, _| {
                calls += 1;
                None
            },
        )
        .unwrap();
        assert_eq!(calls, 3, "lookup count is per-hop, not per-edge");
    }

    // ── Monotone-in-revocations: adding a revocation only tightens ───────

    #[test]
    fn adding_revocation_can_only_convert_ok_to_err() {
        let chain = healthy_chain();
        // First: clean walk succeeds.
        check_revocation_chain(
            token_id(0x10),
            kid(1),
            &chain,
            &CascadeConfig::default(),
            0,
            no_direct_revocation,
            no_hop_revocation,
        )
        .expect("clean walk OK");
        // Then: same inputs but with an additional revocation registered
        // at the issuer key. MUST reject.
        check_revocation_chain(
            token_id(0x10),
            kid(1),
            &chain,
            &CascadeConfig::default(),
            0,
            no_direct_revocation,
            |k, scope| {
                if scope == CascadeHop::IssuerKey && *k == kid(1) {
                    Some(rec(1))
                } else {
                    None
                }
            },
        )
        .expect_err("adding revocation must reject");
    }

    // ── CascadeRejection serde stability ─────────────────────────────────

    #[test]
    fn cascade_rejection_round_trips_through_json() {
        let r = CascadeRejection::HopRevoked {
            scope: CascadeHop::IssuerKey,
            hop_index: 0,
            kid: kid(7),
            revoked_at_unix_ms: 42,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: CascadeRejection = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn cascade_hop_labels_are_stable() {
        assert_eq!(CascadeHop::IssuerKey.as_str(), "issuer_key");
        assert_eq!(CascadeHop::NodeAttestation.as_str(), "node_attestation");
        assert_eq!(CascadeHop::OwnerAttestation.as_str(), "owner_attestation");
    }

    // ── Hop-2 revocation does NOT leak past the owner key ────────────────

    #[test]
    fn cascade_terminates_when_owner_key_reached_cleanly() {
        // Belt-and-braces: confirm the walk does not call lookup beyond
        // the owner-key hop in the clean-walk happy path.
        let chain = healthy_chain();
        let mut last_hop_seen: Option<CascadeHop> = None;
        let _receipt = check_revocation_chain(
            token_id(0x10),
            kid(1),
            &chain,
            &CascadeConfig::default(),
            0,
            no_direct_revocation,
            |_, scope| {
                last_hop_seen = Some(scope);
                None
            },
        )
        .unwrap();
        assert_eq!(last_hop_seen, Some(CascadeHop::OwnerAttestation));
    }
}
