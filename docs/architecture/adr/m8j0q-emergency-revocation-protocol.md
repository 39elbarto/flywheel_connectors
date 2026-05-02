# ADR — Emergency Revocation Protocol (kill-switch / panic button)

**Status:** Accepted (2026-05-02)
**Epic:** `flywheel_connectors-m8j0q`
**Bead:** `m8j0q.8`
**Related:** `m8j0q.A.1` (constraint enforcer), `c1` epic (revocation
timing — `RevocationSlaChecker`, `RevocationPushMessage`,
`PriorityGossipPolicy`)

## Context

The current revocation flow is owner-signed and propagates via the
standard gossip cadence with the priority-push policy from epic `c1`:

- `PriorityGossipPolicy::DirectPush` pushes a `RevocationPushMessage` to
  up to `GossipConfig::max_revocation_push_peers` immediately, then
  relies on standard gossip to fill in.
- `RevocationSlaChecker` verifies that every zone's revocation snapshot
  is within `revocation_freshness_sla_secs` (default 300s).
- Recipients verify both the peer signature and the zone-owner signature
  before applying any revocation (`uxsnk` — two-layer signing).

This is correct under normal-operations failure models: a bounded
fraction of peers are offline, gossip eventually converges, the
freshness SLA bounds the worst-case staleness.

It is **not** sufficient for incident response. The disclosed mesh-attack
scenarios require:

- **Bounded propagation under adversarial conditions.** A
  compromised-but-not-yet-detected peer that drops priority pushes
  silently can stall propagation across the segment of the mesh that
  routes through it. With standard `DirectPush`, the worst-case is
  bounded by the freshness SLA (300s) — too slow for an incident where
  every minute of delay equals more compromised operations.
- **Quorum proof.** The owner must be able to demonstrate "this
  revocation was witnessed by quorum within N seconds" for after-action
  audit. Today there is no per-revocation witness aggregation.
- **Operator ergonomics.** A human operator dealing with an active
  incident needs a single command (`fwc emergency revoke --zone z:work`)
  that does not require them to pre-stage every mesh-coordination flag
  correctly.

## Goal

An operator-invokable instant-revoke for an entire zone (or a specific
connector across all zones) that:

1. Completes propagation within a hard upper bound (target: 5 seconds
   p99 across the local mesh) regardless of normal gossip cadence.
2. Carries quorum-witness signatures so the owner can prove "≥ N peers
   acknowledged this revocation by timestamp T."
3. Cancels in-flight invocations to the revoked zone with a structured
   `OperationCancelled { reason: EmergencyRevocation }` instead of
   letting them complete naturally.
4. Survives adversarial conditions: simulated 50% packet loss, one peer
   dropping its forwarder duties mid-burst, and rate-limit attempts to
   amplify denial-of-service via repeated emergency revokes.

## Decision

Add a fourth `PriorityGossipPolicy` variant — `Emergency` — that:

1. **Burst push** to *all* known peers (not bounded by
   `max_revocation_push_peers`) with up to `EMERGENCY_BURST_FANOUT = 64`
   parallel send paths.
2. **Per-burst-slot retry** with exponential backoff (50ms, 200ms,
   500ms) for unacknowledged peers, capped at three retries, capped at
   `EMERGENCY_PROPAGATION_DEADLINE_MS = 5000` total.
3. **Quorum-witness aggregation**: every peer that applies the
   revocation signs a `RevocationWitness` over the (zone_id, head_seq,
   revoked_ids_hash, timestamp) transcript and returns it. The
   originator collects ≥ `EMERGENCY_QUORUM_WITNESSES = 3` witnesses (or
   majority of online peers, whichever is smaller) before considering
   propagation complete.
4. **In-flight cancellation hook**: every host that applies an emergency
   revocation walks its in-flight invocation table and synthesizes
   `OperationCancelled { reason: EmergencyRevocation { revocation_seq }
   }` for any operation targeting the revoked zone or connector.

Rate limit on the originator: **1 emergency revoke per 60s per zone**,
enforced by a per-zone token bucket in `fcp-host/src/admin_state.rs`.
Replay protection: every `EmergencyRevocationRequest` carries a fresh
`nonce` and `not_before` / `not_after` window; the host rejects requests
outside the window or with a previously-seen nonce.

## Required API shape (binding contract for m8j0q.8 implementation)

### 1. New `PriorityGossipPolicy::Emergency` (in `fcp-mesh/src/gossip.rs`)

```rust
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum PriorityGossipPolicy {
    #[default]
    DirectPush,
    PriorityInterval,
    Standard,
    /// Operator-invoked instant-revoke. Pushes to ALL known peers with
    /// quorum-witness collection, retry, and 5-second deadline. Used
    /// only for `fwc emergency revoke` and equivalent admin RPCs.
    Emergency,
}

impl PriorityGossipPolicy {
    pub const EMERGENCY_BURST_FANOUT: usize = 64;
    pub const EMERGENCY_PROPAGATION_DEADLINE_MS: u64 = 5_000;
    pub const EMERGENCY_QUORUM_WITNESSES: usize = 3;
    pub const EMERGENCY_RATE_LIMIT_PER_ZONE_SECS: u64 = 60;

    #[must_use]
    pub const fn is_emergency(&self) -> bool {
        matches!(self, Self::Emergency)
    }
}
```

### 2. `RevocationWitness` (in `fcp-mesh/src/gossip.rs`, new type)

```rust
/// A witness signature confirming that a peer has applied an
/// emergency revocation. Used by the originator to prove quorum
/// acknowledgement after the fact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationWitness {
    pub witnessing_node: TailscaleNodeId,
    pub zone_id: ZoneId,
    pub revocation_head_seq: u64,
    pub revoked_ids_hash: [u8; 32], // BLAKE3 of sorted ObjectId concat
    pub witnessed_at_unix_ms: u64,
    pub signature: NodeSignature, // Over witness_signing_bytes()
}

impl RevocationWitness {
    /// Transcript for peer signature: includes everything except the
    /// signature itself.
    pub fn witness_signing_bytes(&self) -> Vec<u8>;
}
```

### 3. `EmergencyRevocationRequest` (in `fcp-host/src/admin_state.rs`, new type)

```rust
/// POST /admin/emergency_revoke body — owner-signed, replay-protected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyRevocationRequest {
    pub zone_id: ZoneId,
    /// Optional connector restriction (revoke connector across all zones
    /// of the named scope; if `None`, revokes the entire zone).
    pub connector: Option<ConnectorId>,
    pub reason: String,
    pub nonce: [u8; 16],
    pub not_before_unix_ms: u64,
    pub not_after_unix_ms: u64,
    /// Owner signature over `signing_bytes()`. The host's owner-key
    /// registry is the only place that can produce a valid signature.
    pub owner_signature: NodeSignature,
}

impl EmergencyRevocationRequest {
    pub fn signing_bytes(&self) -> Vec<u8>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyRevocationResponse {
    pub revocation_head_seq: u64,
    pub propagation_started_at_unix_ms: u64,
    pub propagation_deadline_unix_ms: u64,
    pub witnesses_collected: usize,
    pub witnesses_target: usize,
    /// Stable correlation id for audit + log indexing.
    pub emergency_revoke_id: [u8; 16],
}
```

### 4. Audit event (in `fcp-audit`)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EmergencyRevocationOutcome {
    QuorumReached {
        witnesses: usize,
        elapsed_ms: u64,
    },
    QuorumNotReached {
        witnesses: usize,
        target: usize,
        elapsed_ms: u64,
    },
    Refused {
        reason: EmergencyRevocationRefusal,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EmergencyRevocationRefusal {
    InvalidOwnerSignature,
    NonceReplay,
    OutsideValidityWindow,
    RateLimited { retry_after_secs: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyRevocationAuditEvent {
    pub emergency_revoke_id: [u8; 16],
    pub invoker_principal: PrincipalId,
    pub zone_id: ZoneId,
    pub connector: Option<ConnectorId>,
    pub reason: String,
    pub revocation_head_seq: u64,
    pub started_at_unix_ms: u64,
    pub outcome: EmergencyRevocationOutcome,
    pub witnesses: Vec<RevocationWitness>,
}
```

### 5. fwc subcommand (in `crates/fwc/src/main.rs`)

```rust
// Under `fwc emergency` subcommand group:
EmergencyCmd::Revoke {
    /// Zone to revoke (e.g., `z:work`).
    #[arg(long)]
    zone: String,
    /// Optional connector restriction.
    #[arg(long)]
    connector: Option<String>,
    /// Operator-supplied reason (logged + carried in audit event).
    #[arg(long)]
    reason: String,
    /// Skip the interactive confirmation prompt.
    #[arg(long, default_value_t = false)]
    yes: bool,
}
```

The handler:

1. Loads the operator's owner-key from the configured key store.
2. Constructs `EmergencyRevocationRequest`, signs it.
3. Confirms with operator (unless `--yes`): "EMERGENCY REVOKE will
   forcibly cancel in-flight operations targeting `{zone_id}` and push
   revocation to all peers within {deadline}ms. Continue? [y/N]"
4. POSTs to `/admin/emergency_revoke`, streams the response.
5. Exits 0 on `QuorumReached`, 1 on `QuorumNotReached` or `Refused` with
   structured stderr output.

## Sequence diagram

```
operator                fwc                  fcp-host                  fcp-mesh                       peers (N)
   |                     |                       |                         |                              |
   |---emergency revoke->|                       |                         |                              |
   |<--confirm prompt----|                       |                         |                              |
   |---y----------------->|                       |                         |                              |
   |                     |--POST /admin/emergency_revoke (owner-signed)->|                              |
   |                     |                       |--validate owner sig + nonce + window + rate-limit-->|
   |                     |                       |--enqueue RevocationPushMessage with policy=Emergency->|
   |                     |                       |                         |--burst push to all peers (≤64 parallel)->>|
   |                     |                       |                         |<<--RevocationWitness from each peer------|
   |                     |                       |                         |--retry unacked at 50/200/500ms----------->>|
   |                     |                       |<--collected≥quorum OR  deadline reached-------|
   |                     |                       |--emit EmergencyRevocationAuditEvent              |
   |                     |<--EmergencyRevocationResponse (witnesses, elapsed_ms)|                       |
   |<-stdout: outcome----|                       |                         |                              |
```

## Security model

1. **Owner-signature is the only authorization.** Compromise of the
   admin RPC endpoint (e.g., a stolen API token) does not grant the
   ability to invoke emergency revoke — the request must additionally
   carry a valid signature from the zone's owner key, which lives in
   the offline key store. The RPC token authenticates the *transport*,
   not the *authorization*.
2. **Replay protection via nonce + validity window.** Even a stolen
   owner signature for one revocation cannot be replayed: the nonce
   is rejected on second use, and the validity window bounds how long
   any signed request remains usable.
3. **Rate limit prevents revocation-as-DoS.** A compromised owner key
   could flood emergency revokes; the per-zone 60s rate limit ensures
   the pace is bounded. Defense-in-depth: the audit event for every
   refused-rate-limited request is recorded for offline review.
4. **Quorum-witness prevents silent suppression.** A compromised peer
   that drops the priority push silently is detectable: the
   `QuorumNotReached` outcome makes failed propagation visible to the
   operator and to audit, instead of appearing as a successful
   revocation.
5. **Burst cap prevents amplification attacks.** `EMERGENCY_BURST_FANOUT
   = 64` bounds the number of concurrent push paths; a compromised peer
   that forwards an emergency push (legitimate behavior under gossip)
   cannot use it to amplify outbound traffic beyond this cap.

## Migration plan

1. **m8j0q.8.a (this ADR)** — design accepted, contract published. ✅
2. **m8j0q.8.b** — implement `PriorityGossipPolicy::Emergency`,
   `RevocationWitness`, witness-collection loop, and burst-push
   plumbing in `fcp-mesh/src/gossip.rs`. (Blocked: requires fcp-core
   to compile cleanly; currently waiting on m8j0q.3 sibling work in
   `fcp-core/src/error.rs`.)
3. **m8j0q.8.c** — implement `EmergencyRevocationRequest`,
   `/admin/emergency_revoke` handler, owner-signature validation,
   nonce-replay store, and per-zone token bucket in
   `fcp-host/src/admin_state.rs`.
4. **m8j0q.8.d** — implement in-flight invocation cancellation hook in
   `fcp-host/src/enforcement.rs` (coordinates with m8j0q.A.2 wiring
   agent).
5. **m8j0q.8.e** — add `fwc emergency revoke` subcommand in
   `crates/fwc/src/main.rs`.
6. **m8j0q.8.f** — emit `EmergencyRevocationAuditEvent` in `fcp-audit`,
   wire into existing audit log.
7. **m8j0q.8.g** — integration test
   `crates/fcp-e2e/tests/emergency_revoke.rs` with 3-node mesh, seeded
   partition + heal, simulated 50% packet loss; chaos test with random
   peer kill mid-propagation.

## Acceptance (lifted from bead)

- ✅ ADR (this document) — design contract published.
- ⏳ Emergency revoke completes propagation across a 3-node test mesh
  in < 5s under simulated 50% packet loss (m8j0q.8.g).
- ⏳ Audit event `EmergencyRevocation` carries reason, invoker, scope,
  and quorum-witness signatures (m8j0q.8.f).
- ⏳ Refuses if owner-signature missing OR if rate-limited (m8j0q.8.c).
- ⏳ All in-flight invocations to the revoked zone get
  `OperationCancelled { reason: EmergencyRevocation }` within
  propagation window (m8j0q.8.d).

## Open questions resolved

1. **Why a separate `PriorityGossipPolicy` variant instead of overloading
   `DirectPush`?** The retry, witness collection, and amplification
   policies are different enough that an `if policy.is_emergency()`
   check in every site would be more error-prone than a separate
   variant. The variant keeps the call-site discipline visible.
2. **Why quorum of 3 (or majority of online peers)?** Three is the
   smallest number that survives one peer being compromised and one
   being offline simultaneously. Majority-of-online handles the small-
   mesh case (e.g., 2-node test deployments) where requiring 3 would
   never pass.
3. **Why exclude the connector restriction from the emergency burst
   filter?** The first-pass implementation propagates the full
   revocation set per push; per-connector filtering would require
   schema changes to `RevocationPushMessage` that aren't justified by
   the threat model (the size cost of "revoke connector X across all
   zones" is bounded by the number of (connector × zone) pairs, which
   is small for the operator who needs an emergency lever).
4. **Why no public TUI for emergency revoke?** Same reason
   destruction-class CLI commands need explicit `--yes` confirmation:
   the lever should be hard to pull by accident. A future TUI can wrap
   the same RPC.

## Tests expected to follow

- **m8j0q.8.b unit tests** (`fcp-mesh/src/gossip.rs`):
  - `emergency_policy_uses_full_fanout` — burst-push selects all peers
    up to `EMERGENCY_BURST_FANOUT`
  - `emergency_policy_uses_priority_interval` — interval falls back to
    `priority_gossip_interval_ms`
  - `revocation_witness_signature_round_trip` — owner verifies witness
    signatures via `witness_signing_bytes`
- **m8j0q.8.c unit tests** (`fcp-host/src/admin_state.rs`):
  - `emergency_request_rejects_invalid_owner_signature`
  - `emergency_request_rejects_replayed_nonce`
  - `emergency_request_rate_limit_token_bucket`
  - `emergency_request_outside_validity_window_rejected`
- **m8j0q.8.d unit tests** (`fcp-host/src/enforcement.rs`):
  - `inflight_cancellation_walks_correct_zone`
  - `inflight_cancellation_emits_structured_reason`
- **m8j0q.8.g integration tests** (`fcp-e2e/tests/emergency_revoke.rs`):
  - `three_node_mesh_emergency_revoke_completes_under_deadline`
  - `emergency_revoke_with_50pct_packet_loss_still_quorum`
  - `chaos_random_peer_kill_mid_propagation_completes_on_remaining`
  - `emergency_revoke_rate_limited_after_first_within_60s`

## Reference implementation sketch

```rust
// fwc/src/main.rs handler (sketch):
async fn emergency_revoke(args: EmergencyRevokeArgs) -> Result<()> {
    let owner_key = OwnerKeyStore::load(&args.key_path)?;
    let request = EmergencyRevocationRequest::new(
        ZoneId::try_from(args.zone)?,
        args.connector.map(ConnectorId::try_from).transpose()?,
        args.reason.clone(),
    )
    .with_validity_window(now_ms(), now_ms() + 60_000)
    .signed_by(&owner_key);

    if !args.yes {
        confirm_with_operator(&request)?;
    }

    let response: EmergencyRevocationResponse = host_client
        .post("/admin/emergency_revoke")
        .json(&request)
        .send()
        .await?
        .json()
        .await?;

    println!(
        "emergency revoke {}: witnesses {}/{}, head_seq {}",
        hex::encode(response.emergency_revoke_id),
        response.witnesses_collected,
        response.witnesses_target,
        response.revocation_head_seq,
    );
    if response.witnesses_collected < response.witnesses_target {
        bail!("propagation incomplete — quorum not reached within deadline");
    }
    Ok(())
}
```

## Out of scope

- Cross-mesh-segment revocation (separate clusters connected by a
  bridge): a future bead will extend `EmergencyRevocationRequest` with
  a `target_clusters` field and require per-cluster owner signatures.
- Self-destructing keys (e.g., HSM-backed owner key that auto-revokes
  after N emergency uses): a hardware-token integration story belongs
  with `fcp-bootstrap` not this bead.
- Automatic emergency revoke triggered by anomaly detection: the
  operator-in-the-loop confirmation requirement is part of the threat
  model. Automation belongs in a separate detector that surfaces an
  alert; the operator pulls the lever.
