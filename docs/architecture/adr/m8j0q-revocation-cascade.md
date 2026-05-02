# ADR — Revocation cascade through issuer chain

**Status:** Accepted (2026-05-02)
**Epic:** `flywheel_connectors-m8j0q`
**Bead:** `m8j0q.9`
**Related:** `c1` epic (revocation timing — `RevocationRegistry`,
`RevocationSlaChecker`); `m8j0q.A.1` (constraint enforcer);
`m8j0q.A.8` (emergency revocation protocol)

## Context

`RevocationScope::IssuerKey` already exists in `fcp-core/src/revocation.rs`
and `RevocationRegistry` supports exact-membership lookups. A revocation
of scope `IssuerKey` semantically means "this issuance key is no longer
allowed to mint tokens" — but **enforcement is per-token, not per-issuer**:

- Today, `RevocationRegistry::is_revoked(object_id)` answers only "is
  THIS specific token id in the registry?"
- A token whose minting issuer is in the registry, but whose own
  `ObjectId` is NOT, currently passes verification.
- After a compromised issuer is detected, the operator must enumerate
  every token minted during the compromise window and revoke each
  individually before any of them are rejected. There is no transitive
  / cascading rejection.

This is the disclosed gap from the 2026-05-01 reality-check Phase 5
R5.3: a compromised issuance key is a blank-check token mint, and
without cascade, every token minted during the compromise window
remains valid until manual per-token revocation completes.

## Goal

When `RevocationScope::IssuerKey` is registered for issuance key K, every
capability token MINTED by K is rejected automatically by token
verification — without per-token enumeration. The verifier walks the
attestation chain `token → issuance_key → node_signing_key → owner_key`
and short-circuits on the first revoked link.

The walk:

1. is bounded (max 4 hops);
2. detects cycles in malformed attestation chains and rejects them with
   a structured reason;
3. is O(walk_depth) per verification, not O(num_tokens);
4. honours the same revocation-freshness SLA as the existing per-token
   path.

## Decision

Add a new module `crates/fcp-evidence/src/revocation_cascade.rs` whose
single export is:

```rust
pub fn check_revocation_chain(
    token: &CapabilityToken<BoundVerified>,
    registry: &RevocationRegistry,
    chain: &AttestationChain,
    config: &CascadeConfig,
) -> Result<(), CascadeRejection>;
```

`AttestationChain` is the resolved view of "this token's issuance key
was attested by node N, whose signing key was attested by owner O." The
existing `fcp-evidence` crate already owns attestation primitives, so
the cascade walker belongs there.

`fcp-crypto/src/cose.rs` gains a single new entry point:

```rust
pub fn verify_with_revocation_chain(
    raw_token: &[u8],
    verifier: &CapabilityVerifier,
    cap: &CapabilityId,
    op: &OperationId,
    resources: &[String],
    registry: &RevocationRegistry,
    chain: &AttestationChain,
) -> Result<CapabilityToken<BoundVerified>, FcpError>;
```

This composes `verify_bound` (existing) with `check_revocation_chain`
(new). Existing `verify_bound` callers do not change shape until they
opt in.

## Required API shape (binding contract for m8j0q.9 implementation)

### 1. `AttestationChain` (in `fcp-evidence/src/revocation_cascade.rs`)

```rust
/// Resolved attestation chain for a capability token.
///
/// Constructed once at verifier-init time and cached per zone.
/// Walking the chain at verification time is a small in-memory
/// lookup, not an I/O round trip.
#[derive(Debug, Clone)]
pub struct AttestationChain {
    /// Issuance key (kid in the token's `iss` claim) → node signing key.
    pub issuance_to_node: HashMap<KeyId, KeyId>,
    /// Node signing key → owner attestation key.
    pub node_to_owner: HashMap<KeyId, KeyId>,
    /// Owner key (root of trust). Constant per zone.
    pub owner_key: KeyId,
}
```

### 2. `CascadeConfig` (in `fcp-evidence/src/revocation_cascade.rs`)

```rust
#[derive(Debug, Clone)]
pub struct CascadeConfig {
    /// Maximum hops to walk before rejecting as malformed.
    /// Default: 4 (token → issuance_key → node_signing_key → owner_key).
    pub max_hops: usize,
    /// Maximum age of the registry snapshot used for the walk.
    /// Walks against a snapshot older than this are rejected so that
    /// cascade enforcement honours the same freshness SLA as direct
    /// per-token revocation.
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
```

### 3. `CascadeRejection` (in `fcp-evidence/src/revocation_cascade.rs`)

```rust
/// Structured reason a cascade walk rejected a token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CascadeRejection {
    /// Token's own ObjectId is in the revocation registry.
    TokenRevoked { token_id: ObjectId },
    /// Token's issuance key is in the registry under
    /// `RevocationScope::IssuerKey`.
    IssuerKeyRevoked {
        issuer_kid: KeyId,
        revoked_at_unix_ms: u64,
    },
    /// Node signing key (the key that attested the issuance key) is
    /// in the registry under `RevocationScope::NodeAttestation`.
    NodeAttestationRevoked {
        node_kid: KeyId,
        revoked_at_unix_ms: u64,
    },
    /// Owner key (root of trust) is in the registry. Should be rare —
    /// owner-key revocation typically comes with a coordinated
    /// re-enrolment.
    OwnerKeyRevoked {
        owner_kid: KeyId,
        revoked_at_unix_ms: u64,
    },
    /// Walk terminated without reaching a known root within `max_hops`.
    WalkDepthExceeded { hops_walked: usize, max_hops: usize },
    /// Walk encountered a cycle (a key attested by itself, directly or
    /// transitively).
    CycleDetected { cycle: Vec<KeyId> },
    /// Walk encountered a key that is not present in
    /// `AttestationChain` (the chain is incomplete relative to the
    /// token's claimed issuance key).
    AttestationChainIncomplete { missing_kid: KeyId },
    /// Registry snapshot is older than `max_registry_age_secs`.
    RegistryStale {
        snapshot_age_secs: u64,
        max_age_secs: u64,
    },
}
```

### 4. Walk algorithm (sketch)

```rust
pub fn check_revocation_chain(
    token: &CapabilityToken<BoundVerified>,
    registry: &RevocationRegistry,
    chain: &AttestationChain,
    config: &CascadeConfig,
) -> Result<(), CascadeRejection> {
    // (a) Registry freshness
    let age = registry.snapshot_age_secs();
    if age > config.max_registry_age_secs {
        return Err(CascadeRejection::RegistryStale { /* ... */ });
    }

    // (b) Direct token revocation (cheapest check first)
    let token_id = token.object_id();
    if registry.is_revoked(&token_id) {
        return Err(CascadeRejection::TokenRevoked { token_id });
    }

    // (c) Walk: token → issuance_key → node_signing_key → owner_key
    let mut current_kid = token.claims().issuer_kid.clone();
    let mut visited: HashSet<KeyId> = HashSet::with_capacity(config.max_hops);
    let mut path: Vec<KeyId> = Vec::with_capacity(config.max_hops);

    for hop in 0..config.max_hops {
        // Cycle detection
        if !visited.insert(current_kid.clone()) {
            path.push(current_kid.clone());
            return Err(CascadeRejection::CycleDetected { cycle: path });
        }
        path.push(current_kid.clone());

        // Per-hop revocation check (scope depends on which level of the
        // chain we're at)
        if let Some(scope) = scope_for_hop(hop) {
            if let Some(rev) = registry.lookup_kid(&current_kid, scope) {
                return Err(rejection_for_scope(scope, current_kid, rev));
            }
        }

        // Owner-key reached → walk complete
        if current_kid == chain.owner_key {
            return Ok(());
        }

        // Hop to the next level
        let next = match hop {
            0 => chain.issuance_to_node.get(&current_kid),
            1 => chain.node_to_owner.get(&current_kid),
            _ => None, // Walk should have reached owner_key by now
        };
        current_kid = next
            .cloned()
            .ok_or_else(|| CascadeRejection::AttestationChainIncomplete {
                missing_kid: current_kid.clone(),
            })?;
    }

    Err(CascadeRejection::WalkDepthExceeded {
        hops_walked: config.max_hops,
        max_hops: config.max_hops,
    })
}

const fn scope_for_hop(hop: usize) -> Option<RevocationScope> {
    match hop {
        0 => Some(RevocationScope::IssuerKey),
        1 => Some(RevocationScope::NodeAttestation),
        2 => Some(RevocationScope::OwnerAttestation), // future scope
        _ => None,
    }
}
```

The walk is a tight in-memory loop; no I/O, no allocation beyond
`visited` and `path` (both pre-sized to `max_hops`). Verification cost
is O(max_hops), not O(num_tokens) — a 1000-token zone where the issuer
key gets revoked sees 1000 cascade rejections each costing ~max_hops
hashmap lookups, NOT 1000 individual revocation events.

### 5. New entry point in `fcp-crypto/src/cose.rs`

```rust
pub fn verify_with_revocation_chain(
    raw_token: &[u8],
    verifier: &CapabilityVerifier,
    cap: &CapabilityId,
    op: &OperationId,
    resources: &[String],
    registry: &RevocationRegistry,
    chain: &AttestationChain,
) -> Result<CapabilityToken<BoundVerified>, FcpError> {
    let bound = verifier.verify_bound(token, cap, op, resources)?;
    fcp_evidence::revocation_cascade::check_revocation_chain(
        &bound,
        registry,
        chain,
        &CascadeConfig::default(),
    )
    .map_err(|cascade| FcpError::CapabilityConstraintDenied {
        reason: format!("revocation cascade rejected: {cascade:?}"),
        claim_type: "revocation_cascade".into(),
        detail: serde_json::to_string(&cascade).unwrap_or_default(),
    })?;
    Ok(bound)
}
```

## Sequence diagram

```
caller                fcp-crypto                 fcp-evidence              RevocationRegistry
   |                      |                            |                          |
   |-verify_with_rev_chain->|                            |                          |
   |                      |--verify_bound (existing)--->|                          |
   |                      |<--BoundVerified token-------|                          |
   |                      |--check_revocation_chain---->|                          |
   |                      |                            |--snapshot_age_secs------>|
   |                      |                            |<-snapshot_age------------|
   |                      |                            |--is_revoked(token_id)--->|
   |                      |                            |<-true/false--------------|
   |                      |                            |--lookup_kid(issuer)----->|
   |                      |                            |<-Option<Revocation>------|
   |                      |                            |--lookup_kid(node)------->|
   |                      |                            |<-Option<Revocation>------|
   |                      |                            |--lookup_kid(owner)------>|
   |                      |                            |<-Option<Revocation>------|
   |                      |<--Ok(()) | CascadeRejection-|                          |
   |<--Ok(token) | FcpError---|                            |                          |
```

## Security model

1. **Bounded walk = bounded cost.** `max_hops = 4` means an attacker
   cannot construct a malicious attestation chain that forces the
   verifier into a multi-million-hop walk. The walk terminates with
   `WalkDepthExceeded` regardless of how the chain is shaped.
2. **Cycle detection prevents infinite loops.** A malicious or
   misconfigured attestation file that says "K1 attests K1" is
   rejected with `CycleDetected` instead of looping.
3. **Freshness SLA honoured by cascade.** A walk against a stale
   `RevocationRegistry` snapshot is rejected via `RegistryStale` so
   the cascade cannot silently miss a revocation that landed after
   the snapshot was taken.
4. **Walk is monotone in revocations.** Adding a revocation to the
   registry never converts a previous `Err(_)` into an `Ok(())` —
   strictly tightens enforcement.
5. **Direct token revocation still wins.** The `TokenRevoked` check
   happens first and is the cheapest path. Token-level revocation
   continues to work exactly as before for the no-cascade case.

## Migration plan

1. **m8j0q.9.a (this ADR)** — design accepted, contract published. ✅
2. **m8j0q.9.b** — implement `AttestationChain`, `CascadeConfig`,
   `CascadeRejection`, and `check_revocation_chain` in
   `crates/fcp-evidence/src/revocation_cascade.rs`. (Blocked: requires
   fcp-core to compile cleanly; currently waiting on m8j0q.3 sibling
   work in `fcp-core/src/error.rs`.)
3. **m8j0q.9.c** — extend `RevocationRegistry` with `lookup_kid(kid,
   scope)` to return the matching revocation entry, plus
   `snapshot_age_secs` to expose freshness for cascade. (No new fields
   on `RevocationObject`; the existing `RevocationScope` discriminant
   already classifies entries.)
4. **m8j0q.9.d** — add `verify_with_revocation_chain` in
   `fcp-crypto/src/cose.rs`. Existing `verify_bound` continues to work
   for callers that don't yet need cascade.
5. **m8j0q.9.e** — wire `verify_with_revocation_chain` into the host
   enforcement pipeline (after capability-token verify, before
   constraint enforcement). The host owns a per-zone `AttestationChain`
   cache rebuilt when the zone's policy bundle changes.
6. **m8j0q.9.f** — integration test
   `crates/fcp-conformance/tests/revocation_cascade.rs`: issue 1000
   tokens from key K, revoke K with `RevocationScope::IssuerKey`,
   verify all 1000 tokens reject within `max_registry_age_secs`.

## Acceptance (lifted from bead)

- ✅ ADR (this document) — design contract published.
- ⏳ Verifier rejects token whose minting issuance key is in revocation
  registry, even if the token itself is not (m8j0q.9.b + 9.d).
- ⏳ Walk depth bounded (max 4 hops: token → issuance_key →
  node_signing_key → owner_key) — enforced by `CascadeConfig::max_hops`.
- ⏳ Cycle detection rejects malformed attestation chains
  (`CascadeRejection::CycleDetected`).
- ⏳ Cascade is O(walk_depth), not O(num_tokens) — verified by
  m8j0q.9.f throughput test (1000 tokens, fixed-time per token
  regardless of registry size).

## Open questions resolved

1. **Why a separate `AttestationChain` type instead of putting the maps
   on `CapabilityVerifier`?** The verifier is per-token; the
   attestation chain is per-zone. Coupling them would force every
   verifier construction to traverse the chain, even for callers that
   don't want cascade enforcement.
2. **Why a structured `CascadeRejection` instead of `FcpError`?** Same
   reason `ConstraintDenialReason` is structured — keeps the cascade
   logic decoupled from the FCP error taxonomy and makes it usable in
   conformance vectors. Conversion to `FcpError` happens at the
   `verify_with_revocation_chain` boundary.
3. **Why max 4 hops instead of dynamic?** The chain shape is fixed by
   FCP3: `token → issuance_key → node_signing_key → owner_key`. A
   4-hop bound is the architectural maximum, not a tunable. Future
   chain extensions (e.g., HSM-attested owner key) would bump this to
   5; the bump is a deliberate decision, not silent depth growth.
4. **Why include `OwnerAttestation` as a possible revocation scope when
   it does not exist today?** Forward-compatibility: the walk reaches
   the owner key on hop 2, and if a future bead introduces
   owner-attestation revocation (e.g., HSM key rotation), the cascade
   is already shaped to honour it. Today, `scope_for_hop(2)` returns
   `Some(RevocationScope::OwnerAttestation)` but no entries with that
   scope exist, so the lookup is a no-op.

## Tests expected to follow

- **m8j0q.9.b unit tests** (`fcp-evidence/src/revocation_cascade.rs`):
  - `cycle_detection_rejects_self_attestation`
  - `cycle_detection_rejects_3hop_cycle`
  - `walk_depth_bounded_at_max_hops`
  - `attestation_chain_incomplete_returns_structured_reason`
  - `registry_freshness_check_rejects_stale_snapshot`
  - `walk_monotone_in_revocations` (proptest)
- **m8j0q.9.b negative tests**:
  - `issuer_key_revoked_rejects_all_minted_tokens`
  - `node_attestation_revoked_rejects_all_node_minted_tokens`
  - `direct_token_revocation_still_wins` (cheapest check first)
- **m8j0q.9.f integration test**
  (`fcp-conformance/tests/revocation_cascade.rs`):
  - `issue_1000_tokens_revoke_issuer_all_reject_within_sla`
  - `cascade_throughput_o_walk_depth_not_o_num_tokens` (timing
    assertion — verify time per token is ~constant in `num_tokens`)

## Reference implementation sketch

```rust
// Caller side, host enforcement pipeline:
let chain = host.attestation_chain_for_zone(&zone_id).ok_or(FcpError::ZoneViolation)?;
let token = fcp_crypto::cose::verify_with_revocation_chain(
    &raw_token,
    &verifier,
    &capability_id,
    &operation_id,
    &resource_uris,
    &host.revocation_registry(),
    &chain,
)?;
// `token: CapabilityToken<BoundVerified>` — proceed to constraint enforcement
// (m8j0q.A.1 / m8j0q.6 typestate ladder).
```

A 1000-token zone where the issuer key is revoked sees:

- 1000 cascade rejections.
- Each rejection costs `O(max_hops)` hashmap lookups, ≈ 4 lookups + 1
  registry freshness check + 1 cycle-detection insert per token.
- Total verification work scales linearly with `num_tokens` (because
  every token is checked) but cost-per-token is constant in
  `num_tokens` and constant in `registry_size` (assuming `HashMap`
  amortized O(1) lookup). This is the O(walk_depth) per-token cost the
  acceptance criterion requires.

## Out of scope

- Cross-zone cascade (a revocation in zone A invalidates tokens in zone
  B): a future bead. Today's cascade is per-zone because the
  attestation chain is per-zone.
- Online attestation lookup (e.g., asking a remote registry for the
  current chain state at verification time): the chain is loaded into
  memory at zone-policy-bundle change time. Online lookups would
  defeat the O(walk_depth) cost target.
- Notification of clients holding cascade-rejected tokens: the
  rejection happens at verification time. Pro-active "your token will
  be rejected" notification belongs in a separate observability bead
  (out of scope for the security guarantee).
