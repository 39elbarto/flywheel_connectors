# V3/V4 Compatibility Ledger

**Bead:** `flywheel_connectors-kyopb.1.4` (J.5.4)
**Status:** DESIGN ONLY - no runtime implementation in this commit.
**Author:** VioletPine
**Date:** 2026-05-02
**Scope:** Coexistence of V3 (`Ed25519` identity/signatures plus `X25519`
zone-key sealing) and V4 (`ML-DSA` owner/node signatures plus hybrid
`X25519 + ML-KEM-768` sealing) on the same mesh during migration.

## 1. Motivation

FCP V3 nodes authenticate mesh identity and owner actions with Ed25519 and
seal zone-key material through an X25519-based HPKE path. That remains the
fast, deployed baseline, but it is quantum-vulnerable. V4 introduces:

- **ML-DSA** for post-quantum signatures. NIST FIPS 204 specifies ML-DSA
  and notes it is intended for digital signature generation and
  verification under a post-quantum threat model.
- **ML-KEM** for post-quantum key encapsulation. NIST FIPS 203 specifies
  ML-KEM and the ML-KEM-512, ML-KEM-768, and ML-KEM-1024 parameter sets.
- **Hybrid KEM operation** for the zone-key path. The current V4 design
  target is X-Wing, an IETF CFRG draft that combines X25519 and
  ML-KEM-768 into a post-quantum/traditional hybrid KEM.

The migration cannot be a flag day. Operators will have meshes where some
nodes only understand V3, some can speak both versions, and some are
configured as V4-only. A compatibility ledger is the source of truth that
lets those nodes coexist without silently downgrading safety-critical
operations.

## 2. Design Goals

- Track each node's verified protocol and algorithm capabilities by epoch.
- Make downgrade decisions deterministic and auditable.
- Permit mixed-version service continuity for safe/read-only traffic during
  migration.
- Refuse V3 fallback for Risky, Dangerous, and Critical operations whenever a
  V4 path is required by policy.
- Give V3 nodes a view they can safely ignore or verify with their Ed25519
  trust anchor, while giving V4 nodes stronger ML-DSA-backed evidence.
- Avoid wall-clock-only cutovers. Every deprecation phase is keyed to ledger
  epochs plus explicit operator policy.

## 3. Non-Goals

- This doc does not define the ML-DSA owner-key migration ceremony; that is
  `flywheel_connectors-kyopb.1.1`.
- This doc does not define the X-Wing sealed-box wire format; that is
  `flywheel_connectors-kyopb.1.2`.
- This doc does not implement lattice-trapdoor capability delegation; that is
  `flywheel_connectors-kyopb.1.3`.
- This doc does not promise indefinite V3 compatibility. V3 support has an
  explicit deprecation schedule and can be disabled per mesh.

## 4. Terms

| Term | Meaning |
| ---- | ------- |
| V3 node | Node that can verify Ed25519 attestations and use X25519/HPKE zone-key wraps. |
| V4-capable node | Node that supports V3 and at least one V4 signature/KEM suite. |
| V4-only node | Node whose local policy rejects V3 fallback. |
| Ledger epoch | Monotonic compatibility-ledger version for a mesh. |
| Claim | A node's signed advertisement of supported protocol versions and algorithms. |
| Observation | A peer's record of what another node advertised in a live handshake. |
| Effective capability | Capability accepted after checking the claim, ledger policy, freshness, and revocation state. |

## 5. Ledger Model

The ledger is append-only at the logical level. A new epoch replaces node
entries by writing a new canonical ledger object whose `previous_hash`
points to the prior accepted epoch. Nodes reject rollback to an older epoch
unless the rollback is itself signed as an emergency recovery event by the
owner quorum.

```rust
struct MeshCompatibilityLedger {
    ledger_version: u16,              // starts at 1 for this design
    mesh_id: MeshId,
    epoch: u64,                       // strictly increasing per mesh
    previous_hash: Option<[u8; 32]>,
    valid_from_ms: u64,
    expires_at_ms: u64,
    phase: MigrationPhase,
    entries: BTreeMap<NodeId, NodeCompatibilityEntry>,
    tombstones: BTreeMap<NodeId, NodeTombstone>,
    policy: CompatibilityPolicy,
    signatures: LedgerSignatures,
}

struct NodeCompatibilityEntry {
    node_id: NodeId,
    node_attestation_hash: [u8; 32],
    claim_epoch: u64,
    claim_issued_at_ms: u64,
    claim_expires_at_ms: u64,
    supported_protocols: BTreeSet<ProtocolVersion>,
    signature_suites: BTreeSet<SignatureSuite>,
    kem_suites: BTreeSet<KemSuite>,
    fallback_policy: NodeFallbackPolicy,
    state: EntryState,
    evidence: EntryEvidence,
}

enum ProtocolVersion {
    V3,
    V4,
}

enum SignatureSuite {
    Ed25519V3,
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

enum KemSuite {
    HpkeX25519V3,
    XWingMlKem768X25519,
    HpkeMlKem768X25519,
}

enum EntryState {
    Advertised,
    Verified,
    Quarantined,
    Revoked,
    Expired,
}
```

### 5.1 Canonicalization

The ledger MUST be encoded with deterministic CBOR:

- map keys sorted by numeric field id;
- entries sorted by canonical `NodeId`;
- no omitted-default ambiguity in signed bytes;
- explicit enum discriminants for protocol, signature, and KEM suites;
- `signatures` excluded from the ledger digest and signing payload.

The canonical payload is:

```text
FCP4-COMPAT-LEDGER-V1 || cbor_without_signatures(ledger)
```

The ledger content hash is `BLAKE3(canonical_payload)`.

### 5.2 Signatures

During coexistence, the ledger is dual-signed:

```rust
struct LedgerSignatures {
    v3_owner_ed25519: Option<SignatureEnvelope>,
    v4_owner_ml_dsa: Option<SignatureEnvelope>,
    quorum_witnesses: Vec<SignatureEnvelope>,
}
```

Rules:

- In `Observe` and `DualAdvertise`, V3 nodes accept the ledger if the
  Ed25519 owner signature verifies and the epoch is not rolled back.
- In `DualSignRequired` and later phases, V4-capable nodes require both the
  Ed25519 and ML-DSA owner signatures until V3 receive-only mode starts.
- In `V4Only`, V4 nodes require only the ML-DSA owner signature, but may keep
  the Ed25519 signature for audit continuity.
- A V4 node MUST NOT treat a peer as V4-capable solely because the peer says
  so in a live handshake. The live claim has to match a verified ledger entry
  or be recorded as an untrusted observation.

## 6. Node Capability Claims

Each node signs a compact `NodeProtocolClaim` and includes its hash in the
ledger entry.

```rust
struct NodeProtocolClaim {
    node_id: NodeId,
    mesh_id: MeshId,
    claim_epoch: u64,
    issued_at_ms: u64,
    expires_at_ms: u64,
    supported_protocols: Vec<ProtocolVersion>,
    signature_suites: Vec<SignatureSuite>,
    kem_suites: Vec<KemSuite>,
    v3_identity_key_id: Option<KeyId>,
    v4_identity_key_id: Option<KeyId>,
    v3_encryption_key_id: Option<KeyId>,
    v4_kem_key_id: Option<KeyId>,
    min_accepted_ledger_epoch: u64,
    fallback_policy: NodeFallbackPolicy,
    transcript_binding_nonce: [u8; 32],
    signatures: ClaimSignatures,
}
```

The claim is signed by every identity suite it advertises. A node advertising
`V4` without an ML-DSA claim signature is only `V3` effective until the next
accepted ledger epoch says otherwise.

## 7. Peer Capability Advertisement

Peer advertisement happens in three places:

1. **Node attestation:** durable identity and encryption/KEM key material.
2. **Session handshake:** live protocol capabilities bound to the session
   transcript.
3. **Mesh gossip:** observed peer capabilities and the latest ledger hash.

The session handshake gains an optional extension:

```rust
struct ProtocolCapabilitiesExtension {
    ledger_hash: [u8; 32],
    ledger_epoch: u64,
    claim_hash: [u8; 32],
    supported_protocols: Vec<ProtocolVersion>,
    signature_suites: Vec<SignatureSuite>,
    kem_suites: Vec<KemSuite>,
    operation_policy_floor: OperationPolicyFloor,
}
```

V3 peers that do not understand the extension continue the V3 session path.
V4 peers treat a missing extension as `V3 only` and consult the ledger before
choosing fallback. If the live extension contradicts the ledger, the peer is
quarantined for V4 operations until a fresh ledger epoch resolves the
conflict.

## 8. Effective Negotiation Algorithm

Inputs:

- sender and receiver node ids;
- latest accepted ledger;
- live capability advertisements;
- operation safety tier;
- local node fallback policy;
- mesh phase.

Algorithm:

```text
1. Load ledger entries for sender and receiver.
2. Reject if either entry is Revoked, Expired, or Quarantined.
3. Intersect ledger capabilities with live advertisements.
4. Pick the strongest mutually supported protocol:
   a. V4 if both effective entries support V4.
   b. V3 only if both support V3 and fallback is allowed.
   c. otherwise reject with ProtocolNegotiationFailed.
5. Apply operation safety floor:
   a. Safe/read-only MAY use V3 fallback before V3ReceiveOnly.
   b. Risky/Dangerous/Critical MUST use V4 if either participant is
      V4-capable.
   c. V4-only nodes MUST reject V3 fallback for every operation.
6. Bind the selected protocol version, signature suite, KEM suite, ledger
   hash, and ledger epoch into the session transcript.
7. Emit a CompatibilityDecisionReceipt.
```

### 8.1 Compatibility Matrix

| Sender effective | Receiver effective | Safe/read-only | Risky/Dangerous/Critical |
| ---------------- | ------------------ | -------------- | ------------------------ |
| V3 only | V3 only | V3 allowed before V3ReceiveOnly | V3 allowed only before V4Preferred |
| V3 only | V4 capable | V3 fallback allowed before V3ReceiveOnly | reject; receiver is V4-capable |
| V4 capable | V3 only | V3 fallback allowed before V3ReceiveOnly | reject unless explicit emergency exception |
| V4 capable | V4 capable | V4 required | V4 required |
| V4 only | any V3-only peer | reject | reject |

The "either participant is V4-capable" rule is intentionally strict for
mutating or safety-critical work. It prevents a V4 peer from accepting a
weaker V3 path for operations that create durable receipts, change state, or
carry sensitive zone material.

## 9. Downgrade Resistance

Downgrade resistance relies on three independent bindings:

- The ledger is signed and epoch-chained. An attacker cannot remove V4
  capability from the ledger without invalidating signatures or rolling back
  the epoch.
- The live capability extension is transcript-bound. A relay cannot strip V4
  advertisement from one side without making the negotiated transcript
  diverge.
- Operation receipts include `ledger_hash`, `ledger_epoch`,
  `selected_protocol`, and `fallback_reason`. Auditors can distinguish "peer
  was V3-only" from "sender chose V3 despite V4 being available."

Receipts for fallback decisions use:

```rust
struct CompatibilityDecisionReceipt {
    operation_id: OperationId,
    sender: NodeId,
    receiver: NodeId,
    safety_tier: SafetyTier,
    ledger_hash: [u8; 32],
    ledger_epoch: u64,
    selected_protocol: ProtocolVersion,
    selected_signature_suite: SignatureSuite,
    selected_kem_suite: KemSuite,
    fallback_reason: Option<FallbackReason>,
    decision: CompatibilityDecision,
    signed_at_ms: u64,
}
```

## 10. Deprecation Timeline

This is a phase model, not a wall-clock-only plan. Operators may attach
calendar deadlines, but enforcement is driven by ledger epoch and phase.

| Phase | Ledger phase | Behavior | Exit criteria |
| ----- | ------------ | -------- | ------------- |
| 0 | `Observe` | Nodes publish observed V3/V4 support. V3 behavior unchanged. | Every active node appears in ledger for two consecutive epochs. |
| 1 | `DualAdvertise` | V4-capable nodes publish ML-DSA and hybrid KEM keys. V3 fallback allowed. | At least quorum of mesh controllers dual-signs ledger. |
| 2 | `DualSignRequired` | V4-capable nodes require dual-signed ledger. V3-only peers still served. | All owner/quorum authorities have V4 keys and attestations. |
| 3 | `V4Preferred` | V4 is mandatory when both peers are V4-capable. V3 fallback emits receipts. | No unexplained V3 fallback receipts for one full operator-defined window. |
| 4 | `V4RequiredForSensitive` | Risky, Dangerous, and Critical operations require V4 if either peer is V4-capable. | All safety-critical routes have V4-capable peers or explicit exceptions. |
| 5 | `V3ReceiveOnly` | V3 nodes can receive safe/read-only traffic only; no new V3 mutating sessions. | Last V3-only node is upgraded, removed, or quarantined. |
| 6 | `V4Only` | V3 fallback disabled except signed emergency recovery ledger. | Permanent steady state. |

Emergency rollback to an earlier phase requires a new ledger epoch with:

- `phase_rollback: true`;
- owner quorum signatures;
- expiry no longer than one operator-defined maintenance window;
- an audit reason linked to an incident id.

## 11. Five-Node Migration Playbook

Example mesh: `n1`, `n2`, `n3`, `n4`, `n5`.

1. **Epoch 100, Observe:** all five nodes are V3. Ledger records V3-only
   entries. No behavior change.
2. **Epoch 101, DualAdvertise:** upgrade `n1` and `n2`. They advertise V3 and
   V4, publish ML-DSA claim signatures, and still accept V3 fallback.
3. **Epoch 102, DualSignRequired:** owner quorum dual-signs ledger. `n1` and
   `n2` use V4 between themselves; they fall back to V3 for `n3`-`n5` safe
   traffic.
4. **Epoch 103, V4Preferred:** upgrade `n3` and `n4`. V4 is now used for all
   traffic except routes involving `n5`. Risky/Dangerous operations involving
   upgraded nodes refuse V3 fallback.
5. **Epoch 104, V4RequiredForSensitive:** `n5` is still V3-only. It can serve
   safe/read-only requests; mutating operations are rerouted to upgraded nodes
   or rejected with `UpgradeRequired`.
6. **Epoch 105, V3ReceiveOnly:** `n5` either upgrades or is marked
   `Quarantined` for writes. No new V3 mutating sessions are created.
7. **Epoch 106, V4Only:** V3 fallback disabled. Historical V3 attestations
   remain verifiable for audit, but no live sessions negotiate V3.

## 12. Logging and Metrics

Every negotiation emits structured fields:

- `compat.ledger_epoch`
- `compat.ledger_hash`
- `compat.sender_protocols`
- `compat.receiver_protocols`
- `compat.selected_protocol`
- `compat.selected_signature_suite`
- `compat.selected_kem_suite`
- `compat.fallback_reason`
- `compat.phase`
- `compat.decision`

Required counters:

- `fcp_compat_negotiation_total{decision, selected_protocol}`
- `fcp_compat_fallback_total{reason, safety_tier}`
- `fcp_compat_quarantine_total{reason}`
- `fcp_compat_ledger_rollback_rejected_total`

## 13. Implementation Slices

The implementation work should land in three sub-beads:

1. `flywheel_connectors-kyopb.1.4.1` - ledger schema, deterministic CBOR,
   epoch-chain verification, dual-signature verification, and durable local
   store.
2. `flywheel_connectors-kyopb.1.4.2` - peer capability advertisement in node
   attestation, FCPC/session handshake extension, gossip observation, and
   effective negotiation policy.
3. `flywheel_connectors-kyopb.1.4.3` - mixed-version E2E harness,
   downgrade-refusal tests, five-node migration playbook test, metrics, and
   operator CLI/readiness output.

## 14. Acceptance Tests for Implementation

- Unit test deterministic ledger signing bytes and hash stability.
- Unit test epoch rollback rejection.
- Unit test stale/expired/quarantined entry rejection.
- Matrix-test all sender/receiver pairs: V3-only, V4-capable, V4-only.
- Matrix-test safety tiers: Safe, Risky, Dangerous, Critical.
- E2E test a five-node migration through phases 0-6 with no downtime for
  safe/read-only traffic.
- E2E test that a V4-capable receiver refuses Risky/Dangerous/Critical
  traffic when the only proposed path is V3 fallback.
- Receipt test that every fallback records ledger hash, epoch, selected
  protocol, and fallback reason.

## 15. References

- NIST FIPS 203, "Module-Lattice-Based Key-Encapsulation Mechanism Standard"
  (ML-KEM), final publication page:
  https://csrc.nist.gov/pubs/fips/203/final
- NIST FIPS 204, "Module-Lattice-Based Digital Signature Standard" (ML-DSA),
  final publication page:
  https://csrc.nist.gov/pubs/fips/204/final
- NIST SP 800-227, "Recommendations for Key-Encapsulation Mechanisms":
  https://csrc.nist.gov/pubs/sp/800/227/final
- IETF CFRG draft-connolly-cfrg-xwing-kem-10, "X-Wing: general-purpose
  hybrid post-quantum KEM":
  https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/
- IETF draft-ietf-hpke-pq-04, "Post-Quantum and Post-Quantum/Traditional
  Hybrid Algorithms for HPKE":
  https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/
- RFC 9180, "Hybrid Public Key Encryption":
  https://datatracker.ietf.org/doc/html/rfc9180
