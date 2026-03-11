# Flywheel Connector Protocol (FCP) Specification V3

Status: Draft

## Abstract

FCP is the secure operating model for external-service access in the Flywheel ecosystem.
It defines how a host compiles zone policy, capability grants, provenance rules, manifests,
placement constraints, and supply-chain evidence into supervised connector applications that
run with explicit authority and produce durable, inspectable evidence.

FCP is mesh-native, but it is not defined solely by object distribution. The protocol is built
from three mutually reinforcing layers:

1. **Execution semantics**: capability-scoped, region-owned, budgeted execution that closes to quiescence.
2. **Authority and evidence semantics**: zones, provenance, capability tokens, receipts, checkpoints, and audit chains.
3. **Placement and transport semantics**: authenticated device mesh, durable object distribution, low-latency framed control/data exchange, repair, failover, and offline recovery.

The execution model is Asupersync-native. The reference semantic vocabulary in this document uses
`Cx`, `Scope`, `Budget`, `Outcome`, and `AppSpec` because those names already describe the required
runtime invariants precisely. Equivalent implementations MAY wrap those surfaces, but MUST preserve
the semantics defined here.

## Conformance Language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**,
**SHOULD NOT**, **RECOMMENDED**, **NOT RECOMMENDED**, **MAY**, and **OPTIONAL** in this
document are to be interpreted as described in RFC 2119 and RFC 8174.

## Table of Contents

1. Introduction
2. Foundational Axioms
3. Foundational Semantics and Primitives
4. Execution Model
5. Authority, Zones, and Provenance
6. Durable Object and Evidence Model
7. Host Model
8. Connector Application Model
9. Control, Data, and Evidence Plane
10. Manifest, Provisioning, and Isolation
11. Placement, Mobility, and Mesh Operation
12. Registry and Supply Chain
13. Observability, Explainability, and Errors
14. Conformance and Verification
15. Appendices
16. Summary

## 1. Introduction

### 1.1 Vision

FCP allows AI systems to interact with external services without collapsing trust boundaries.
It does this by treating connector execution as an operating-system problem rather than a prompt
discipline problem. Every operation runs inside an explicit authority context. Every connector is
bound to exactly one zone. Every privileged action is justified by durable evidence. Every long-lived
worker belongs to a supervision tree. Every cancellation path is bounded and inspectable. Every
durable state transition is fenced, checkpointed, or auditable.

The result is a system that can:

- run on the user's own device mesh,
- automate real-world service setup and operation,
- survive restarts, failovers, and partial disconnection,
- explain why an action was allowed or denied,
- prove what happened after the fact.

### 1.2 Design Principles

1. **No ambient authority**: authority is always explicit, narrowable, and inspectable.
2. **Zone-first isolation**: every connector instance and every durable artifact belong to exactly one zone.
3. **Execution is a security boundary**: budget, cancellation, drain, restart, and quiescence semantics are normative, not implementation trivia.
4. **Durability is explicit**: state, receipts, checkpoints, revocations, and audit chains are content-addressed artifacts, not hidden process memory.
5. **Transport serves semantics**: live framed exchange exists for speed; durable object distribution exists for replay, repair, placement, and offline recovery.
6. **Portable execution matters**: native binaries, WASI modules, and remotely placed instances are all execution forms of the same connector model.
7. **Automation over ceremony**: provisioning, credential injection, rotation, replay, diagnosis, and repair SHOULD be mechanized wherever possible.
8. **Conformance includes failure behavior**: cancellation, stale leases, replay, restart policy, checkpoint resume, and hostile-input handling are part of the contract.

### 1.3 Terminology

| Term | Meaning |
|------|---------|
| **Host** | The root FCP application responsible for policy compilation, placement, supervision, and evidence surfaces |
| **Connector** | A supervised application instance that bridges an external system into FCP |
| **Zone** | A cryptographic and policy boundary defining confidentiality, integrity, and capability ceilings |
| **Capability** | A specific permission that may be narrowed into runtime and connector scopes |
| **Cx** | The explicit execution context carrying authority, budget, provenance, correlation, cancellation, and effects |
| **Scope** | A region-owned concurrency boundary; spawned work in a scope cannot orphan |
| **Budget** | The execution envelope governing deadline, poll quota, cost quota, and priority |
| **Outcome** | The normalized result class for execution: success, error, cancellation, or panic |
| **AppSpec** | A supervision topology describing a long-lived application and its child services |
| **DecisionReceipt** | A durable artifact capturing allow/deny outcome, reason code, and evidence references |
| **ZoneCheckpoint** | A quorum-signed checkpoint summarizing the enforceable heads of zone state |
| **Lease** | A fenced, renewable grant of exclusive or quorum-sensitive execution rights |
| **FCPC** | The low-latency framed control/data/evidence plane |
| **FCPS** | The durable object and symbol plane used for distribution, replay, repair, and offline recovery |
| **ResourceObject** | A zone-bound handle to an external resource, used instead of ambient raw identifiers where feasible |

## 2. Foundational Axioms

### 2.1 Universal Fungibility

All durable FCP artifacts are represented as content-addressed objects. Objects MAY be transferred
directly, chunked, mirrored, or symbolized. If a durable artifact participates in audit, replay,
failover, or policy justification, the canonical representation MUST be an object with a stable
identifier. No byte stream that matters for security or resumability may exist only as ephemeral
transport state.

### 2.2 Authenticated Mesh

The device mesh provides both connectivity and machine identity. Tailscale is the reference identity
and routing substrate. Every participating node possesses an authenticated device identity and an
owner-trusted attestation binding device identity to its issuance and encryption roles. Placement,
lease coordination, object repair, and checkpoint propagation all rely on authenticated node identity.

### 2.2.1 Mesh Identity and Node Attestation

Every node participating in FCP MUST present a mesh identity record and an owner-trusted attestation
that binds the tailnet identity to the cryptographic roles the node is allowed to perform.

```rust
pub struct MeshIdentity {
    pub node_id: NodeId,
    pub hostname: String,
    pub ips: Vec<IpAddr>,
    pub tags: Vec<String>,
    pub owner_pubkey: PublicKey,
    pub node_sig_pubkey: PublicKey,
    pub node_sig_kid: [u8; 8],
    pub node_enc_pubkey: X25519PublicKey,
    pub node_enc_kid: [u8; 8],
    pub node_iss_pubkey: PublicKey,
    pub node_iss_kid: [u8; 8],
    pub node_attestation: NodeKeyAttestation,
}

pub struct NodeKeyAttestation {
    pub header: ObjectHeader,
    pub node_id: NodeId,
    pub owner_pubkey: PublicKey,
    pub node_sig_pubkey: PublicKey,
    pub node_sig_kid: [u8; 8],
    pub node_enc_pubkey: X25519PublicKey,
    pub node_enc_kid: [u8; 8],
    pub node_iss_pubkey: PublicKey,
    pub node_iss_kid: [u8; 8],
    pub tags: Vec<String>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub attestation_nonce: [u8; 32],
    pub device_posture: Option<DevicePostureAttestation>,
    pub signature: Signature,
}

pub struct DevicePostureAttestation {
    pub kind: DevicePostureKind,
    pub payload: Vec<u8>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: [u8; 32],
}

pub enum DevicePostureKind {
    TpmQuote,
    SecureEnclave,
    AndroidKeystore,
    Custom(String),
}
```

Normative validation requirements:

1. `NodeKeyAttestation.signature` MUST verify under `owner_pubkey`.
2. `expires_at` MUST be present and MUST be strictly greater than `issued_at`.
3. Implementations MUST reject attestations that are expired or outside tolerated clock-skew policy.
4. `tags` MUST use canonical identifier syntax and MUST be validated before policy application.
5. All `*_kid` values MUST be derived from the corresponding public key via explicit domain-separated hash.
6. If `device_posture` is required by zone or host policy, absence or expiry of the posture evidence MUST cause rejection.
7. The attestation MUST bind all three node key roles together so that signing, encryption, and issuance functions can be revoked independently while still being attributable to the same device identity.

Recommended operational guidance:

- Posture attestations SHOULD have short lifetimes.
- Node issuance keys SHOULD rotate more frequently than node signing keys.
- High-trust zones SHOULD require stronger posture evidence and shorter attestation freshness windows.

### 2.2.2 Threshold Owner Signing

The owner public key is the root trust anchor for zone definitions, policy, device attestation,
revocation authority, and supply-chain trust policy. Implementations SHOULD support threshold
production of signatures so that no single device is required to hold the complete owner private key.

```rust
pub struct OwnerKeyPolicy {
    pub scheme: OwnerKeyScheme,
    pub threshold_k: u8,
    pub total_n: u8,
    pub participants: Vec<NodeId>,
    pub max_skew_secs: u64,
}

pub enum OwnerKeyScheme {
    Single,
    Threshold,
}

pub struct OwnerKeyShare {
    pub header: ObjectHeader,
    pub share_id: u8,
    pub node_id: NodeId,
    pub sealed_share: HpkeSealedBox,
    pub issued_at: u64,
    pub signature: Signature,
}
```

Threshold production is RECOMMENDED because it materially improves:

- compromise resistance,
- device-loss tolerance,
- revocation and recovery workflows,
- consistency of incident response across the mesh.

The verification surface remains an ordinary owner signature. The mechanism used to produce the
signature MUST NOT affect the verifiability or canonical encoding of the signed object.

### 2.2.3 Key Role Separation and Rotation

FCP distinguishes the following key roles:

1. owner signing key,
2. node signing key,
3. node encryption key,
4. node issuance key,
5. zone encryption keys,
6. object-identifier privacy keying material where deployed.

Normative rules:

1. Owner signing keys MUST NOT be used as online node keys.
2. Node issuance keys MUST be independently revocable from node signing keys.
3. Node encryption keys MUST be used only for sealed distribution of secrets, zone keys, or other wrapped material.
4. Zone encryption keys MUST be replaceable without changing owner or node identities.
5. Rotation events MUST be represented as durable objects referenced by checkpoints or revocation heads.
6. Key-role confusion MUST be treated as a security incident.

### 2.3 Explicit Authority

No connector, worker, or handler runs with ambient authority. The only authority available to code is
the authority present in the `Cx` passed into it, plus any capability narrowing or evidence references
derived from that `Cx` under the rules of this specification.

### 2.4 Quiescent Execution

Structured execution is a normative security and correctness invariant. Every spawned task belongs to a
region. Every region belongs to a tree. Close of a region implies quiescence:

- no live child tasks,
- no pending finalizers,
- no unresolved graded obligations,
- no hidden background work continuing after the region claims to be done.

This axiom forbids “best-effort shutdown” as the default lifecycle model for FCP components.

## 3. Foundational Semantics and Primitives

### 3.1 Canonical Identifiers

The following identifiers are foundational:

```rust
pub struct ObjectId([u8; 32]);
pub struct EpochId(u64);
pub struct SchemaId(String);
pub struct ZoneId(String);
pub struct ConnectorId(String);
pub struct OperationId(String);
pub struct InstanceId([u8; 16]);
pub struct SecretId([u8; 16]);
```

#### 3.1.1 Canonical Forms

- `ObjectId` MUST be derived from canonical bytes under a domain-separated hash.
- `ZoneId`, `ConnectorId`, and `OperationId` MUST use canonical, case-sensitive identifier syntax.
- Identifiers that appear in signed or hashed structures MUST be serialized canonically.
- Lexical comparison of version strings is forbidden; semantic version comparison MUST use SemVer rules.

#### 3.1.2 Canonical Identifier Formats (NORMATIVE)

To prevent confusion attacks and cross-implementation drift, the following identifiers MUST be:

- ASCII only,
- lowercase only,
- length `<= 128` bytes,
- matched against `^[a-z0-9][a-z0-9._:-]*$`.

Identifiers covered by this rule include:

- `PrincipalId`
- `ConnectorId`
- `CapabilityId`
- `OperationId`
- `RoleId`
- `SecretId`
- `CredentialId`
- `InstanceId`

Silent normalization is forbidden. Implementations MUST reject non-canonical forms because:

1. Unicode confusables create policy bypass vectors.
2. Case-folding behavior diverges across languages and runtimes.
3. Delimiter ambiguity breaks deterministic policy evaluation.
4. Hashing and signature verification require one stable lexical representation.

```rust
pub fn validate_canonical_id(id: &str) -> Result<(), IdValidationError> {
    if id.len() > 128 {
        return Err(IdValidationError::TooLong);
    }
    if !id.is_ascii() {
        return Err(IdValidationError::NonAscii);
    }
    if id.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(IdValidationError::UppercaseNotAllowed);
    }

    let mut chars = id.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => {}
        _ => return Err(IdValidationError::InvalidFormat),
    }

    for c in chars {
        if !(c.is_ascii_lowercase()
            || c.is_ascii_digit()
            || c == '.'
            || c == '_'
            || c == ':'
            || c == '-')
        {
            return Err(IdValidationError::InvalidFormat);
        }
    }

    Ok(())
}
```

### 3.2 Canonical Serialization

Normative durable objects and FCPC frames MUST use deterministic CBOR encoding. Any hash, signature,
or interface digest defined by this specification MUST be computed from the deterministic encoding.

#### 3.2.1 Deterministic CBOR Requirements (NORMATIVE)

To ensure cross-language determinism and prevent signature ambiguity, canonical CBOR MUST follow
all of the following rules:

1. Arrays, maps, byte strings, and text strings MUST use definite-length encoding.
2. Integers MUST use the shortest possible encoding.
3. Map keys MUST be sorted in bytewise lexicographic order of their canonical encoding.
4. Duplicate map keys MUST be rejected.
5. Floating-point values SHOULD be avoided in durable objects. If a schema explicitly allows them,
   NaN values MUST be rejected and canonical shortest-form encoding MUST be used.
6. Non-canonical encodings MUST be rejected for any object that is persisted, audited, mirrored,
   pinned, or used in signature verification.

#### 3.2.2 Signature Canonicalization (NORMATIVE)

Whenever an object contains a `signature` field or a vector of quorum signatures, verification MUST
follow one deterministic procedure:

1. Compute an unsigned view of the object with `signature` or `quorum_signatures` removed.
2. Serialize the unsigned view using deterministic CBOR.
3. Prefix the bytes with the schema hash or other domain-separated type-binding bytes required by
   that object family.
4. Verify Ed25519 signatures over those bytes.

For multi-signature objects, signature vectors MUST be sorted lexicographically by signer identity
before hashing, signing, or verifying.

#### 3.2.3 Canonical Serializer Reference Shape

```rust
pub struct CanonicalSerializer;

impl CanonicalSerializer {
    pub fn serialize<T: Serialize>(value: &T, schema: &SchemaId) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(schema_hash(schema).as_bytes());
        deterministic_cbor_serialize(value, &mut buf).expect("valid schema-bound type");
        buf
    }

    pub fn deserialize<T: DeserializeOwned>(
        data: &[u8],
        expected_schema: &SchemaId,
    ) -> Result<T, SerializationError> {
        if data.len() < 32 {
            return Err(SerializationError::SchemaMismatch);
        }
        if &data[0..32] != schema_hash(expected_schema).as_bytes() {
            return Err(SerializationError::SchemaMismatch);
        }
        deterministic_cbor_deserialize(&data[32..]).map_err(SerializationError::Cbor)
    }
}
```

### 3.3 Object Header

All durable objects MUST include a canonical header:

```rust
pub struct ObjectHeader {
    pub object_id: ObjectId,
    pub schema_id: SchemaId,
    pub zone_id: ZoneId,
    pub created_at: u64,
    pub refs: Vec<ObjectId>,
    pub retention: RetentionClass,
    pub provenance: Option<Provenance>,
}

pub enum RetentionClass {
    Ephemeral,
    Lease,
    Session,
    Durable,
    Policy,
    Audit,
}
```

Retention classes define minimum expected lifetime and garbage-collection behavior; they do not
override explicit pins or policy requirements.

#### 3.3.1 Object Placement Policy (NORMATIVE)

Objects MAY carry explicit placement policy:

```rust
pub struct ObjectPlacementPolicy {
    pub min_nodes: u8,
    pub max_node_fraction_bps: u16,
    pub preferred_devices: Vec<DeviceSelector>,
    pub excluded_devices: Vec<DeviceSelector>,
    pub target_coverage_bps: u32,
}

pub enum DeviceSelector {
    Tag(String),
    Class(String),
    NodeId(NodeId),
    Zone(ZoneId),
    HasCapability(String),
}
```

Normative rules:

1. `max_node_fraction_bps` and `target_coverage_bps` use basis points to avoid floating-point drift.
2. Preferred and excluded device selectors MUST use typed grammar, not free-form expressions.
3. Objects with placement policy SHOULD participate in background repair and coverage evaluation.

#### 3.3.2 HPKE Sealed Boxes (NORMATIVE)

Whenever this specification says a payload is sealed to a node or recipient, the sealed form MUST use HPKE.

Baseline required profile:

- KEM: `DHKEM(X25519, HKDF-SHA256)`
- KDF: `HKDF-SHA256`
- AEAD: `ChaCha20-Poly1305`

```rust
pub struct HpkeSealedBox {
    pub kem_id: u16,
    pub kdf_id: u16,
    pub aead_id: u16,
    pub enc: Vec<u8>,
    pub ct: Vec<u8>,
}
```

Associated data for seal operations MUST bind the payload to:

- zone identity,
- recipient node identity,
- purpose string,
- issuance time or epoch.

#### 3.3.3 Garbage Collection and Pinning

Nodes MUST implement reachability-based garbage collection per zone.

The root set for a zone MUST include:

- the latest validated `ZoneCheckpoint`,
- all explicitly pinned objects,
- any still-live lease or session roots required by policy.

Cross-zone references MUST NOT create implicit retention in the foreign zone. If a foreign-zone
object must remain live, that retention MUST be established by the foreign zone's own checkpoint,
pins, leases, or policy.

#### 3.3.4 ZoneCheckpoint as Root Pointer (NORMATIVE)

`ZoneCheckpoint` is both:

- the enforceable summary of current zone heads,
- the canonical durable root for zone reachability and freshness comparisons.

Checkpoint comparison MUST allow O(1) freshness reasoning through monotonic sequence numbers.

#### 3.3.5 Stored Object Reference Shape

```rust
pub struct StoredObject {
    pub object_id: ObjectId,
    pub header: ObjectHeader,
    pub body: Vec<u8>,
    pub retention: RetentionClass,
}

impl StoredObject {
    pub fn canonical_bytes(header: &ObjectHeader, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"FCP3-OBJECT-V1");
        deterministic_cbor_serialize(header, &mut out).expect("header serializes");
        out.extend_from_slice(body);
        out
    }
}
```

### 3.4 Budget

Execution MUST be budgeted. The reference model is:

```rust
pub struct Budget {
    pub deadline: Option<u64>,
    pub poll_quota: Option<u64>,
    pub cost_quota: Option<u64>,
    pub priority: Priority,
}

pub enum Priority {
    Background,
    Normal,
    Interactive,
    Critical,
}
```

Normative rules:

1. Budget narrowing is monotone; child scopes MUST NOT gain more budget than their parent.
2. Deadline expiry MUST be observable as a distinct outcome from ordinary application error.
3. Cost and poll quotas MAY be infinite, but any finite quota MUST be enforced.
4. Placement and restart policy MUST consider remaining budget before work begins or is resumed.

### 3.5 Outcome

Execution outcomes are normalized:

```rust
pub enum Outcome<T, E> {
    Ok(T),
    Err(E),
    Cancelled(CancelReason),
    Panicked(String),
}
```

The severity ordering is:

`Ok < Err < Cancelled < Panicked`

Aggregating combinators, supervisors, and explain surfaces MUST preserve severity monotonicity.

### 3.6 Trace and Correlation Context

Every externally visible request, stream, or lifecycle action MUST carry correlation data:

```rust
pub struct TraceContext {
    pub correlation_id: [u8; 16],
    pub trace_id: [u8; 16],
    pub parent_span_id: Option<[u8; 8]>,
    pub request_object_id: Option<ObjectId>,
}
```

The host MUST propagate trace context across connector boundaries, durable receipts, audit events,
and operator evidence surfaces.

### 3.7 Safety, Approval, and Idempotency Classes

Operations and lifecycle actions MUST declare safety and approval semantics:

```rust
pub enum SafetyTier {
    Safe,
    Risky,
    Dangerous,
}

pub enum ApprovalMode {
    Never,
    Policy,
    Always,
}

pub enum IdempotencyClass {
    None,
    BestEffort,
    Strong,
}
```

Normative rules:

1. `Dangerous` operations MUST be explainable and auditable.
2. `Risky` and `Dangerous` operations MUST produce an `OperationReceipt`.
3. If an operation is declared `Strong` idempotent, the host and connector MUST agree on the
   idempotency key surface and resume behavior.
4. Approval requirements MUST be machine-checkable and MUST NOT rely on prose alone.

## 4. Execution Model

### 4.1 The `Cx` Contract

`Cx` is the normative execution context token. Implementations MAY wrap it, but the wrapped form MUST
preserve the same semantics.

```rust
pub struct Cx {
    pub zone_id: ZoneId,
    pub budget: Budget,
    pub trace: TraceContext,
    pub provenance: ProvenanceContext,
    pub capability_scope: CapabilityScope,
    pub cancellation: CancellationState,
}
```

The `Cx` contract requires:

1. **Authority carriage**: all effectful operations are mediated by `Cx`.
2. **Cancellation visibility**: tasks can observe cancellation via explicit checkpoints.
3. **Budget visibility**: time and quota checks are explicit rather than ambient.
4. **Provenance visibility**: origin and taint state travel with the request context.
5. **Narrowability**: service boundaries SHOULD narrow capabilities and MAY narrow budget.
6. **Effect discipline**: time, spawn, network, storage, randomness, and external I/O MUST flow
   through the authority and policy visible from `Cx`.

### 4.2 Regions and Scopes

All concurrency is region-owned. Detached fire-and-forget tasks are forbidden for FCP-owned logic.

```rust
pub trait Scope {
    fn spawn(&self, task: impl SpawnableTask);
    fn child_region(&self, budget: Budget) -> ChildRegion;
}
```

Normative rules:

1. Work spawned from a request MUST live inside a request-owned region or child region.
2. Losing branches of races MUST be cancelled and drained when semantics require cleanup.
3. A scope MUST NOT report completion until all owned work and finalizers have resolved.
4. Handler-local background tasks with unclear ownership are non-conformant.

### 4.3 Cancellation, Drain, and Finalization

Cancellation is a protocol:

`Running -> CancelRequested -> Draining -> Finalizing -> Completed(Cancelled)`

Normative requirements:

1. Cancellation MUST be explicit and observable.
2. Long-running loops, retry loops, and streaming handlers MUST contain checkpoints.
3. Finalizers MUST run under bounded, masked cleanup semantics.
4. Drain progress SHOULD be reportable over operator surfaces for long-lived or critical work.
5. Silent data loss due to cancellation is forbidden for FCP-defined primitives.

### 4.4 Two-Phase Effects

If cancellation between “intent” and “commit” can cause data loss or protocol corruption, the effect
MUST use a two-phase pattern such as reserve/commit, prepare/finalize, or checkpoint/activate.

Examples:

- channel send: reserve -> send,
- checkpointed migration: checkpoint -> distribute -> transfer lease -> activate,
- durable receipt emission: prepare evidence -> persist object -> advance head.

### 4.5 Supervision and `AppSpec`

The host and long-lived connectors are specified as supervised applications.

```rust
pub struct AppSpec {
    pub name: String,
    pub budget: Option<Budget>,
    pub children: Vec<ChildSpec>,
    pub restart_policy: RestartPolicy,
}
```

Normative rules:

1. The FCP host MUST be modeled as a root application with supervised child services.
2. Long-lived connectors SHOULD be modeled as supervised applications rather than ad hoc task bundles.
3. Restart policy MUST consume budget and MUST respect minimum remaining time where configured.
4. Startup and shutdown order MUST be deterministic.
5. A dropped application handle that has not been explicitly stopped or joined is a correctness fault.

### 4.6 Deterministic Verification

The execution model MUST support deterministic testing of:

- cancellation,
- restart policy,
- drain progress,
- deadline behavior,
- lease fencing,
- checkpoint resume,
- evidence emission,
- region quiescence.

Reference implementations SHOULD use a deterministic lab runtime with virtual time and replayable traces.

### 4.7 Time Semantics

Time is not ambient. Implementations SHOULD make logical or virtual time available to deterministic
test environments while preserving wall-clock bindings for production where required.

Normative expectations:

1. Retry loops MUST be expressible against explicit deadline or sleep primitives rather than
   implicitly reading global clocks.
2. Deadline expiry, timeout, and cancellation MUST remain distinguishable in logs and outcomes.
3. Leases, token expiry, checkpoint freshness, and revocation freshness MUST all use explicit time
   comparison policy with bounded skew assumptions.

### 4.8 Supervision Strategies

Representative supervision strategies include:

```rust
pub enum SupervisionStrategy {
    Stop,
    Restart(RestartConfig),
    Escalate,
}

pub struct RestartConfig {
    pub max_restarts: u32,
    pub window_ms: u64,
    pub restart_cost: u64,
    pub min_remaining_for_restart_ms: Option<u64>,
}
```

Supervision decisions MUST be trace-visible and MUST NOT silently downgrade a worse outcome.

## 5. Authority, Zones, and Provenance

### 5.1 Zone Hierarchy

Zones define both confidentiality and integrity boundaries.

Reference hierarchy:

```text
z:owner
z:private
z:work
z:project:<name>
z:community
z:public
```

Normative rules:

1. Every connector instance MUST bind to exactly one zone for its lifetime.
2. Every durable object MUST declare exactly one zone.
3. Cross-zone effects require explicit policy and, where relevant, approval or sanitization evidence.
4. A host MUST refuse to run a connector if manifest or placement requirements cannot be satisfied inside the target zone.

#### 5.1.1 Zone-to-Tailscale ACL Mapping (NORMATIVE)

Tailscale ACL generation provides defense-in-depth port-gating for zone traffic. It does not replace
cryptographic policy enforcement.

```rust
pub struct AclGenerator {
    pub zones: Vec<ZoneConfig>,
}

pub struct ZoneConfig {
    pub zone_id: ZoneId,
    pub tailscale_tag: String,
    pub symbol_port: u16,
    pub control_port: u16,
}
```

Normative rules:

1. Mesh nodes MUST expose per-zone ports for symbol and control traffic.
2. Generated ACLs MUST restrict zone ports to nodes tagged for that zone.
3. Connector allow/deny semantics MUST be enforced by FCP policy and capability checks, not by
   inventing connector-specific Tailscale ACL destinations.
4. Funnel or public ingress MUST be restricted to low-trust zone ports only.

#### 5.1.2 Zone Group Key Agreement

The baseline zone-key model is manifest-distributed symmetric material sealed to eligible nodes.
Implementations MAY additionally support MLS/TreeKEM-style group key agreement for highly sensitive
zones requiring post-compromise security.

```rust
pub enum ZoneKeyMode {
    ManifestDistributed,
    MlsTreeKem,
}

pub struct ZoneSecurityProfile {
    pub zone_id: ZoneId,
    pub key_mode: ZoneKeyMode,
    pub require_pcs: bool,
    pub max_epoch_secs: u64,
}
```

If MLS/TreeKEM is supported, it MUST be selectable per zone and MUST produce explicit epoch transitions
that remain compatible with checkpoint and audit semantics.

### 5.2 Zone Definitions and Policy Objects

Zone policy is object-based and durable:

```rust
pub struct ZoneDefinitionObject {
    pub header: ObjectHeader,
    pub zone_id: ZoneId,
    pub allowed_connectors: Vec<ConnectorId>,
    pub default_placement: PlacementPolicy,
    pub policy_object_id: ObjectId,
    pub signature: Signature,
}

pub struct ZonePolicyObject {
    pub header: ObjectHeader,
    pub zone_id: ZoneId,
    pub capability_ceiling: Vec<CapabilityId>,
    pub egress_policy: EgressPolicy,
    pub approval_policy: ApprovalPolicy,
    pub audit_policy: AuditPolicy,
    pub signature: Signature,
}
```

Zone policy changes MUST be durable, signed, and checkpointed.

#### 5.2.1 Zone Structure and Transport Policy

Zone definitions SHOULD carry enough structure for hosts, planners, and repair logic to make
deterministic decisions without consulting ad hoc side channels.

```rust
pub struct ZoneDefinitionObjectV3 {
    pub header: ObjectHeader,
    pub zone_id: ZoneId,
    pub name: String,
    pub integrity_level: u8,
    pub confidentiality_level: u8,
    pub symbol_port: u16,
    pub control_port: u16,
    pub transport_policy: Option<ZoneTransportPolicy>,
    pub policy_object_id: ObjectId,
    pub prev: Option<ObjectId>,
    pub signature: Signature,
}

pub struct ZoneTransportPolicy {
    pub allow_derp: bool,
    pub allow_funnel: bool,
    pub allow_lan_broadcast: bool,
}
```

Normative rules:

1. Zone semantics MUST be enforced using explicit numeric and object-based policy, not only zone names.
2. Child zones MUST NOT exceed their parent zone's integrity or confidentiality ceilings.
3. Transport policy MUST be treated as defense-in-depth; it supplements but does not replace capability and provenance enforcement.
4. Policy objects referenced by a zone definition MUST be checkpoint-visible so rollback and staleness are detectable.

#### 5.2.2 Zone Key Manifests and Rotation

Zone encryption keys and object-identifier privacy keying material SHOULD be distributed through
explicit manifests rather than hidden runtime state.

```rust
pub struct ZoneKeyManifest {
    pub header: ObjectHeader,
    pub zone_id: ZoneId,
    pub zone_key_id: [u8; 8],
    pub valid_from: u64,
    pub valid_until: Option<u64>,
    pub prev_zone_key_id: Option<[u8; 8]>,
    pub wrapped_keys: Vec<WrappedZoneKey>,
    pub signature: Signature,
}

pub struct WrappedZoneKey {
    pub node_id: NodeId,
    pub node_enc_kid: [u8; 8],
    pub sealed_key: HpkeSealedBox,
}
```

Normative rules:

1. Zone key rotation MUST be representable as durable state so it can participate in replay, repair, and incident response.
2. Manifest overlap windows MUST be bounded.
3. Device removal SHOULD trigger zone key rotation for affected zones.

### 5.3 Provenance Model

Every request and every durable output MAY carry provenance. Risky and dangerous operations MUST carry it.

```rust
pub struct Provenance {
    pub origin_zone: ZoneId,
    pub current_zone: ZoneId,
    pub integrity_label: u32,
    pub confidentiality_label: u32,
    pub taints: Vec<Taint>,
    pub adjustments: Vec<LabelAdjustmentRef>,
}

pub enum Taint {
    PublicInput,
    ExternalInput,
    PromptSurface,
    UntrustedAttachment,
    HostileHtml,
    RemoteCodeMetadata,
}
```

```rust
pub struct LabelAdjustmentRef {
    pub approval_object_id: ObjectId,
    pub applied_at: u64,
}

bitflags! {
    pub struct TaintFlags: u32 {
        const NONE = 0;
        const PUBLIC_INPUT = 1 << 0;
        const EXTERNAL_INPUT = 1 << 1;
        const UNVERIFIED_LINK = 1 << 2;
        const USER_SUPPLIED = 1 << 3;
        const PROMPT_SURFACE = 1 << 4;
    }
}

pub struct TaintReduction {
    pub clears: TaintFlags,
    pub by_receipt: ObjectId,
    pub applied_at: u64,
}
```

Merge rule:

- resulting integrity = `MIN(all integrity labels)`
- resulting confidentiality = `MAX(all confidentiality labels)`
- resulting taints = union of taints minus any explicitly evidenced reductions

#### 5.3.1 Resource Objects and External Sink Classification

Where external resources can be represented durably, the preferred form is a `ResourceObject`.

```rust
pub struct ResourceObject {
    pub header: ObjectHeader,
    pub resource_uri: String,
    pub resource_digest: Option<[u8; 32]>,
    pub resource_digest_alg: Option<String>,
    pub resource_size_bytes: Option<u64>,
    pub resource_content_type: Option<String>,
    pub retrieved_at: Option<u64>,
    pub expires_at: Option<u64>,
    pub resource_integrity_level: u8,
    pub resource_confidentiality_level: u8,
    pub resource_taint: TaintFlags,
    pub signature: Signature,
}
```

Normative rules:

1. Persisted, mirrored, audited, or pinned resources MUST include a content digest.
2. Cached resource bytes MUST NOT be served past `expires_at` without revalidation when expiry is present.
3. External writes to lower-confidentiality sinks MUST require declassification evidence.

#### 5.3.2 Taint Propagation Rules

Implementations MUST expose deterministic provenance merge behavior:

1. integrity = minimum effective integrity across inputs,
2. confidentiality = maximum effective confidentiality across inputs,
3. taint = OR of input taints minus only those reductions justified by verified sanitizer receipts,
4. zone crossings MUST be recorded in order.

#### 5.3.3 Effective Label Resolution and Zone-Crossing Decisions

Implementations SHOULD make effective provenance resolution explicit rather than embedding it in ad hoc
policy code.

```rust
pub struct ZoneCrossing {
    pub from_zone: ZoneId,
    pub to_zone: ZoneId,
    pub crossed_at: u64,
    pub authorized_by: Option<ObjectId>,
}

pub enum ProvenanceDecision {
    Allow,
    RequireElevation { reason_code: String },
    RequireDeclassification { reason_code: String },
    Deny { reason_code: String },
}
```

Recommended effective-value rules:

1. effective integrity starts at the base label and MAY be raised only by verified approval evidence,
2. effective confidentiality starts at the base label and MAY be lowered only by verified declassification evidence,
3. effective taint starts as the accumulated union and MAY be reduced only by verified sanitizer receipts that cover the relevant objects.

Recommended decision procedure for zone or sink crossing:

1. compare effective integrity of the data against the target integrity requirement,
2. compare effective confidentiality of the data against the target confidentiality ceiling,
3. evaluate effective taint against operation safety tier,
4. determine whether approval or sanitization evidence already satisfies the required adjustment,
5. emit an explicit allow, elevation-required, declassification-required, or deny outcome.

Illustrative cases:

- `z:public` text driving a dangerous connector action SHOULD deny unless a specific elevation path exists.
- `z:private` content being posted into `z:community` SHOULD require declassification even if the connector otherwise has write capability.
- content with `UNVERIFIED_LINK` taint MAY flow into a safe archival connector but SHOULD NOT drive a dangerous external write without verified sanitization.

#### 5.3.4 External Sink Classification and Write Rules

The most important confidentiality and integrity failures often happen at the boundary between the FCP
mesh and external systems. Implementations SHOULD treat writes to external resources as writes into
classified sinks, not merely network operations.

Normative guidance:

1. a connector writing to an external destination MUST classify the destination or associated `ResourceObject`,
2. if target confidentiality is lower than the effective confidentiality of the input, declassification evidence is required,
3. if target integrity is higher than the effective integrity of the input and the action is risky or dangerous, elevation evidence is required,
4. if the destination classification cannot be determined and policy does not specify a safe default, the operation SHOULD fail closed.

Representative low-confidentiality sinks:

- public social posts,
- external email recipients outside the trusted zone,
- community chat channels,
- issue comments on public repositories.

Representative higher-integrity sinks:

- deployment systems,
- finance or billing systems,
- repository mutation surfaces,
- destructive administrative APIs.

#### 5.3.5 Worked Provenance Merge Cases

The following cases illustrate how the normative merge rules are intended to behave.

Case 1: trusted private draft + public attachment summary

- input A: `z:private`, integrity `80`, confidentiality `90`, taint `NONE`
- input B: `z:public`, integrity `20`, confidentiality `10`, taint `PUBLIC_INPUT | UNVERIFIED_LINK`
- merged result:
  - integrity `20`
  - confidentiality `90`
  - taint includes `PUBLIC_INPUT | UNVERIFIED_LINK`

Implication:

- the merged object may remain stored inside `z:private`,
- it SHOULD NOT drive a dangerous external action without explicit elevation and likely sanitization.

Case 2: malware scan clears one taint but not all

- input carries `PUBLIC_INPUT | UNVERIFIED_LINK | PROMPT_SURFACE`
- sanitizer receipt clears `UNVERIFIED_LINK`
- effective taint after verification:
  - `PUBLIC_INPUT | PROMPT_SURFACE`

Implication:

- clearing one taint MUST NOT erase unrelated taint flags,
- policy should still treat the object as unsafe for high-risk autonomous action.

Case 3: declassification to community output

- input confidentiality `90`
- target zone confidentiality `40`
- valid declassification approval lowers effective confidentiality to the target or policy-approved level

Implication:

- the derived object can now flow inside the lower-confidentiality target zone,
- but the chain of custody remains visible through approval and crossing records.

#### 5.3.6 Reference Merge and Decision Algorithm

Implementations MAY vary internally, but the externally visible result SHOULD be equivalent to the
following conceptual algorithm:

```text
merge(inputs):
  effective_integrity       = min(input.effective_integrity)
  effective_confidentiality = max(input.effective_confidentiality)
  effective_taint           = OR(input.effective_taint)
  crossings                 = concatenation(input.zone_crossings)

decide(target):
  if target.integrity > effective_integrity and operation is risky_or_dangerous:
    require elevation
  if target.confidentiality < effective_confidentiality:
    require declassification
  if effective_taint includes public_or_untrusted and operation is dangerous:
    deny unless explicit reviewed path exists
  else allow
```

The important property is not the literal code shape. It is that:

- integrity never silently rises,
- confidentiality never silently falls,
- taint never silently disappears,
- every exception is backed by durable evidence.

### 5.4 Approval and Sanitization Evidence

Elevations, declassifications, and taint reductions MUST be evidenced by durable objects:

```rust
pub struct ApprovalToken {
    pub header: ObjectHeader,
    pub zone_id: ZoneId,
    pub reason: String,
    pub approved_by: PrincipalId,
    pub request_object_id: ObjectId,
    pub signature: Signature,
}

pub struct SanitizerReceipt {
    pub header: ObjectHeader,
    pub sanitizer_capability: CapabilityId,
    pub input_object_id: ObjectId,
    pub output_object_id: ObjectId,
    pub taints_cleared: Vec<Taint>,
    pub signature: Signature,
}
```

#### 5.4.1 Elevation and Declassification Protocol

Approvals MUST be encoded as durable objects and referenced by object identifier, not treated as
ambient runtime flags. Elevation, declassification, and execution override SHOULD reuse one durable
approval object family with distinct scopes rather than multiplying bespoke token types.

#### 5.4.2 Approval Scopes and Constraint Grammar

Approval objects SHOULD use a structured scope model so that operators and agents can reason about
exactly what was approved.

```rust
pub enum ApprovalScope {
    Elevation {
        operation: OperationId,
        original_provenance: Provenance,
    },
    Declassification {
        from_zone: ZoneId,
        to_zone: ZoneId,
        object_ids: Vec<ObjectId>,
    },
    Execution {
        connector_id: ConnectorId,
        method_pattern: String,
        request_object_id: Option<ObjectId>,
        input_hash: Option<[u8; 32]>,
        input_constraints: Vec<InputConstraint>,
    },
}

pub struct InputConstraint {
    pub json_pointer: String,
    pub op: ConstraintOp,
    pub value: CborValue,
}

pub enum ConstraintOp {
    Eq,
    Neq,
    In,
    NotIn,
    Prefix,
    Suffix,
    Contains,
}
```

Normative rules:

1. Interactive approval for risky or dangerous execution SHOULD bind to a specific request object whenever feasible.
2. `method_pattern` MUST use a restricted anchored glob grammar rather than general regular expressions.
3. `json_pointer` MUST follow RFC 6901 semantics strictly.
4. If `input_hash` is absent, `input_constraints` MUST be non-empty.
5. Approval objects MUST be bounded in size and complexity to resist approval-surface DoS.

#### 5.4.3 Sanitizer Verification

Sanitizer receipts MUST be verifiable against both the sanitizer capability and the transformed data.

Recommended verification steps:

1. verify sanitizer capability and token freshness,
2. verify input and output object references,
3. verify declared taints cleared are a subset of what the sanitizer is trusted to clear,
4. retain the receipt in evidence bundles when a high-risk action depends on it.

#### 5.4.4 Approval Lifecycle, Freshness, and Coverage

Approvals SHOULD be treated as short-lived, reviewable authority artifacts rather than generic
"permission slips."

Recommended lifecycle:

1. request creation with exact target operation or data objects,
2. human or policy review,
3. issuance as a durable approval object,
4. consumption by one or more operations within the allowed scope,
5. expiry, replacement, or explicit revocation.

Normative guidance:

1. approval objects SHOULD have short validity windows for risky and dangerous operations,
2. approval scope MUST cover the actual request, object set, or method pattern being exercised,
3. stale approvals MUST fail in the same way as stale capability or checkpoint evidence,
4. if approval is reused across multiple actions, the scope and audit policy MUST make that reuse explicit.

#### 5.4.5 Approval Verification Order

Implementations SHOULD verify approvals in a stable order:

1. signature and approver identity,
2. temporal validity,
3. scope match against request or object set,
4. zone and connector compatibility,
5. any input-hash or input-constraint coverage,
6. any dependent checkpoint or revocation freshness requirements.

This keeps explainability stable and prevents one implementation from blaming a different failure
cause than another for the same invalid approval.

#### 5.4.6 Approval Examples and Failure Modes

Representative approval outcomes:

1. exact-match execution approval for one risky request:
   - valid if request id, input hash, and connector all match,
   - invalid if the same approval is replayed against a different request body.
2. declassification approval for a specific object set:
   - valid only for the enumerated objects,
   - invalid if additional objects are attached later without new approval.
3. broad method-pattern approval:
   - acceptable for safe or low-risk operational convenience,
   - NOT RECOMMENDED for dangerous operations unless policy makes the blast radius explicit.

Common failure modes:

- approval scope too broad for the action attempted,
- input constraints fail to cover the actual request body,
- approval expired but the user interface still displayed it as current,
- approval valid in one zone but presented from another.

#### 5.4.7 Rich Approval Object Shape

Approval implementations SHOULD preserve enough detail to stand alone as durable evidence:

```rust
pub struct ApprovalTokenV3 {
    pub header: ObjectHeader,
    pub scope: ApprovalScope,
    pub justification: String,
    pub approved_by: PrincipalId,
    pub approved_at: u64,
    pub expires_at: u64,
    pub signature: Signature,
}
```

Recommended properties:

1. justification SHOULD capture why the approver believed the action was acceptable,
2. expiry SHOULD be explicit rather than implied,
3. approval objects SHOULD be independently explainable without consulting ephemeral UI state,
4. the object SHOULD be suitable for inclusion in evidence bundles and audit chains.

### 5.5 Capabilities and Tokens

Capabilities are explicit and composable:

```rust
pub struct CapabilityToken {
    pub jti: [u8; 16],
    pub zone_id: ZoneId,
    pub connector_id: ConnectorId,
    pub operations: Vec<OperationId>,
    pub grant_object_ids: Vec<ObjectId>,
    pub not_before: u64,
    pub expires_at: u64,
    pub signature: Signature,
}
```

Normative rules:

1. If a capability is not present, the operation MUST be impossible to invoke.
2. Capability tokens MUST be time-bounded.
3. Revocation MUST be checked before use.
4. Grant chains and referenced policy objects MUST be mechanically verifiable.

#### 5.5.1 Capability Taxonomy

Capabilities SHOULD be organized hierarchically. Representative families include:

- `fcp.*` for protocol and meta operations,
- `network.*` and `network.tls.*` for egress and identity constraints,
- `storage.*` for persistence semantics,
- `ipc.*` for host and agent communication,
- `system.*` for privileged local operations,
- service-specific namespaces such as `slack.*`, `telegram.*`, `gmail.*`, `postgresql.*`.

Host restrictions MUST NOT be encoded in capability IDs. Host and TLS constraints belong in
network constraints or manifest-declared operation policy.

#### 5.5.1.1 Capability Definition Metadata

Capability catalogs SHOULD include more than a bare identifier. A first-class capability definition
helps hosts, agents, and operator surfaces reason about blast radius, approval expectations, and
idempotency requirements.

```rust
pub struct CapabilityDefinition {
    pub capability_id: CapabilityId,
    pub name: String,
    pub description: String,
    pub safety_tier: SafetyTier,
    pub risk_level: RiskLevel,
    pub parent: Option<CapabilityId>,
    pub implies: Vec<CapabilityId>,
    pub conflicts_with: Vec<CapabilityId>,
    pub idempotency: IdempotencyClass,
    pub requires_approval: ApprovalMode,
    pub audit_level: AuditLevel,
}

pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

pub enum AuditLevel {
    Minimal,
    Standard,
    High,
    Always,
}
```

Normative guidance:

1. dangerous capabilities SHOULD declare `Strict` idempotency unless impossible,
2. `implies` relationships MUST NOT silently grant capabilities outside the current zone ceiling,
3. conflicting capabilities SHOULD be surfaced during manifest compilation rather than at first runtime use.

#### 5.5.2 Capability Objects and Constraints

```rust
pub struct CapabilityObject {
    pub header: ObjectHeader,
    pub capability_id: CapabilityId,
    pub grantee: Grantee,
    pub constraints: CapabilityConstraints,
    pub placement: PlacementPolicy,
    pub valid_from: u64,
    pub valid_until: u64,
    pub signature: Signature,
}

pub enum Grantee {
    Principal(PrincipalId),
    Zone(ZoneId),
    Tag(String),
    Bearer,
}

pub struct CapabilityConstraints {
    pub resource_allow: Vec<String>,
    pub resource_deny: Vec<String>,
    pub max_calls: Option<u32>,
    pub max_bytes: Option<u64>,
    pub idempotency_scope: Option<String>,
    pub network: Option<NetworkConstraints>,
    pub credential_allow: Vec<CredentialId>,
}
```

```rust
pub struct NetworkConstraints {
    pub host_allow: Vec<String>,
    pub port_allow: Vec<u16>,
    pub ip_allow: Vec<IpAddr>,
    pub cidr_deny: Vec<String>,
    pub deny_localhost: bool,
    pub deny_private_ranges: bool,
    pub deny_tailnet_ranges: bool,
    pub require_sni: bool,
    pub spki_pins: Vec<String>,
    pub deny_ip_literals: bool,
    pub require_host_canonicalization: bool,
    pub dns_max_ips: u16,
    pub max_redirects: u8,
    pub connect_timeout_ms: u32,
    pub total_timeout_ms: u32,
    pub max_response_bytes: u64,
}
```

#### 5.5.2.1 Constraint Monotonicity and Grant Resolution

Capability attenuation is monotone: issued tokens and derived scopes MAY reduce authority but MUST
NOT expand it beyond what the referenced grants allow.

Recommended grant-resolution procedure:

1. fetch all referenced `CapabilityObject`s,
2. verify signature, validity window, and revocation state for each object,
3. compute the union of granted capabilities,
4. intersect that union with zone ceilings and manifest constraints,
5. apply attenuation by intersection or minimum bounds, never by union,
6. reject the token if any requested grant falls outside the resolved authority.

Constraint monotonicity rules:

1. `resource_allow` narrows by intersection,
2. `resource_deny` narrows by union,
3. `max_calls` and `max_bytes` narrow by minimum,
4. placement narrows by intersection of eligible devices and zones,
5. credential allow-lists narrow by intersection.

If two constraints cannot be combined without ambiguity, the safer result is denial rather than
guessing the intended composite rule.

#### 5.5.2.2 Placement Policy in Capability Objects

Placement policy is part of authority, not only scheduling. If a capability may execute only on
certain devices or under certain locality assumptions, that restriction belongs in the capability
object and must survive token issuance.

```rust
pub struct PlacementPolicy {
    pub requires: Vec<DeviceRequirement>,
    pub prefers: Vec<DevicePreference>,
    pub excludes: Vec<DevicePattern>,
    pub zones: Vec<ZoneId>,
}

pub enum DeviceRequirement {
    Gpu { min_vram_mb: u32 },
    Memory { min_mb: u32 },
    OnPower,
    Software { name: String, version: Option<String> },
    Network { min_bandwidth_mbps: Option<u32> },
    TailscaleTag(String),
    ConnectorAvailable { connector_id: ConnectorId, min_version: Option<String> },
    SecretReconstructable { secret_id: SecretId, min_nodes: u8 },
    ZoneQuotaHeadroom { zone_id: ZoneId, min_free_mb: u32 },
}

pub enum DevicePreference {
    LowLatency { max_ms: u32, weight_bps: u16 },
    HighResources { weight_bps: u16 },
    SpecificDevice { node_id: NodeId, weight_bps: u16 },
    DataLocality { object_ids: Vec<ObjectId>, weight_bps: u16 },
}
```

Normative rules:

1. token issuance MUST NOT erase placement restrictions present in the granting capability,
2. dangerous execution SHOULD reject if required placement properties cannot be satisfied,
3. placement preferences MAY influence scheduling but MUST NOT override hard requirements.

#### 5.5.3 Role Objects

Roles are named capability bundles that simplify policy administration.

```rust
pub struct RoleObject {
    pub header: ObjectHeader,
    pub role_id: RoleId,
    pub name: String,
    pub description: String,
    pub grants: Vec<RoleGrant>,
    pub inherits: Vec<RoleId>,
    pub zone_id: ZoneId,
    pub valid_from: u64,
    pub valid_until: u64,
    pub signature: Signature,
}

pub struct RoleGrant {
    pub capability_id: CapabilityId,
    pub operation_id: Option<OperationId>,
}
```

Role inheritance is additive only unless an explicit deny mechanism is introduced by policy.

#### 5.5.3.1 Role Assignments and Resolution

Roles SHOULD be assigned explicitly and resolved deterministically.

```rust
pub struct RoleAssignment {
    pub header: ObjectHeader,
    pub role_object_id: ObjectId,
    pub grantee: PrincipalId,
    pub attenuation: Option<CapabilityConstraints>,
    pub valid_from: u64,
    pub valid_until: u64,
    pub signature: Signature,
}
```

Normative rules:

1. role inheritance MUST form a DAG,
2. assignment attenuation applies to inherited grants as well as direct grants,
3. role resolution MUST happen before token issuance so the token can cite concrete grant objects or role-derived authority,
4. cycles in role inheritance MUST be rejected at policy load time.

#### 5.5.4 CapabilityToken Extended Binding Fields

For risky and dangerous operations, tokens SHOULD carry additional binding material:

```rust
pub struct CapabilityTokenV3 {
    pub jti: [u8; 16],
    pub sub: PrincipalId,
    pub iss_zone: ZoneId,
    pub iss_node: NodeId,
    pub kid: [u8; 8],
    pub aud: ConnectorId,
    pub aud_binary: Option<ObjectId>,
    pub instance: Option<InstanceId>,
    pub iat: u64,
    pub exp: u64,
    pub grant_object_ids: Vec<ObjectId>,
    pub caps: Vec<CapabilityGrant>,
    pub attenuation: Option<CapabilityConstraints>,
    pub holder_node: Option<NodeId>,
    pub checkpoint_id: ObjectId,
    pub checkpoint_seq: u64,
    pub signature: Signature,
}
```

Normative guidance:

1. `aud_binary` SHOULD be required for risky and dangerous operations so tokens cannot be replayed
   across swapped binaries sharing the same connector identifier.
2. `holder_node` SHOULD be present when proof-of-possession is required.
3. `checkpoint_id` / `checkpoint_seq` SHOULD bind token freshness to the verified zone frontier.

#### 5.5.4.1 Proof-of-Possession and Holder Binding

When `holder_node` is present, privileged requests SHOULD carry proof that the designated node is
actually presenting the token.

Recommended transcript ingredients:

- token identifier,
- request object identifier,
- nonce or verifier challenge,
- connector audience,
- optional binary audience.

Normative rules:

1. risky and dangerous operations SHOULD require holder binding unless a stronger authenticated session binding already provides equivalent guarantees,
2. proof-of-possession checks MUST be performed before expensive provider-side work,
3. failed holder proofs SHOULD emit distinct reason codes from ordinary signature failures.

#### 5.5.5 CapabilityToken Encoding

Capability tokens SHOULD use deterministic CBOR and COSE-style signing structures rather than ad hoc
JSON encodings. Private claims MAY be used for FCP-specific fields such as `grant_object_ids`,
checkpoint binding, and binary audience binding, provided the encoding remains deterministic and
interoperable.

#### 5.5.5.1 COSE Protected Header Requirements

Implementations SHOULD standardize the protected header set for capability tokens:

- `alg`,
- `kid`,
- optional content-type or schema hint when needed for interoperability.

Duplicate or unexpected protected-header encodings MUST be rejected for signed tokens used in
policy enforcement.

#### 5.5.6 CapabilityToken Claim Map and Verification

Capability tokens SHOULD use a stable claim map so that cross-language verifiers can interoperate.

Recommended claim mapping:

| Claim | Meaning |
|-------|---------|
| `iss` | issuing zone |
| `sub` | principal subject |
| `aud` | connector audience |
| `iat` | issued-at time |
| `exp` | expiry time |
| `cti` | token identifier |
| `fcp.iss_node` | issuing node |
| `fcp.grant_object_ids` | referenced capability grants |
| `fcp.attenuation` | optional further constraints |
| `fcp.holder_node` | proof-of-possession holder |
| `fcp.checkpoint_id` | zone-checkpoint binding |
| `fcp.checkpoint_seq` | checkpoint sequence binding |
| `fcp.aud_binary` | optional artifact or binary audience |

Recommended verification order:

1. verify protected headers and signing key identity,
2. verify token signature,
3. verify temporal validity with skew policy,
4. verify audience and, where present, binary audience,
5. verify referenced grant objects and attenuation monotonicity,
6. verify checkpoint or revocation freshness constraints,
7. verify proof-of-possession requirements if `holder_node` is present.

#### 5.5.6.1 Validation Failure Ordering and Evidence

Token validation SHOULD fail in a stable order so that explain surfaces remain reproducible.

Recommended failure ordering:

1. malformed or non-canonical encoding,
2. signature or key resolution failure,
3. temporal validity failure,
4. audience mismatch,
5. grant-resolution or attenuation failure,
6. checkpoint or revocation freshness failure,
7. holder-proof failure.

Validation evidence SHOULD cite:

- token object id,
- referenced grant object ids,
- checkpoint or revocation heads consulted,
- exact reason code chosen as decisive.

#### 5.5.6.2 COSE/CWT Example and Claim Semantics

Implementations SHOULD document one canonical token shape so that new implementations do not invent
subtly incompatible claim encodings.

Illustrative payload fields:

```text
iss = z:work
sub = principal:agent.example
aud = fcp.github
iat = 1770000000
exp = 1770000300
cti = 00112233445566778899aabbccddeeff
fcp.iss_node = node:abc
fcp.grant_object_ids = [obj.grant.1, obj.grant.2]
fcp.checkpoint_id = obj.chk.5
fcp.checkpoint_seq = 105
fcp.aud_binary = obj.bin.9
```

Semantics:

- `iss` binds the issuing zone rather than a generic service name,
- `aud` binds the connector family,
- `aud_binary`, when present, binds the concrete artifact identity,
- `grant_object_ids` are the real authority roots the verifier can inspect,
- checkpoint binding prevents tokens from floating free of the enforceable zone frontier.

#### 5.5.6.3 Capability Resolution Examples

Example 1: direct grant

- one `CapabilityObject` grants `github.issue.comment`
- token requests only that operation
- attenuation narrows host set to `api.github.com`
- result: valid if the zone ceiling and connector manifest both allow it

Example 2: role-derived grant plus attenuation

- role grants `slack.read` and `slack.write`
- assignment attenuation restricts writes to one workspace
- issued token requests only `slack.write` for `send_message`
- result: valid only if the token keeps the workspace restriction

Example 3: invalid expansion

- grant allows 10 MiB responses
- token attenuation tries to omit the response-size cap entirely
- result: invalid, because omission would expand authority rather than narrow it

### 5.6 Network Guard and Secret Use

Connectors SHOULD receive secrets through mediated injection rather than raw persistent credentials.

```rust
pub enum EgressRequest {
    Http(EgressHttpRequest),
    TcpConnect(EgressTcpConnectRequest),
}
```

The Network Guard MUST:

1. validate host, port, DNS, TLS, and policy constraints,
2. enforce deny-by-default on private, localhost, and tailnet targets unless explicitly allowed,
3. inject credentials without disclosing raw secret material when policy allows,
4. emit stable reason codes on denial.

#### 5.6.1 Network Constraint Evaluation Order (NORMATIVE)

To prevent SSRF, DNS rebinding, and host confusion attacks, implementations MUST evaluate outbound
requests in this order:

1. reject IP literals when `deny_ip_literals` is true,
2. canonicalize hostnames using lowercase IDNA2008 form with trailing dots removed,
3. enforce host allow rules before DNS resolution,
4. enforce port allow rules before connection,
5. resolve DNS with a bounded number of answers,
6. reject any resolved address in denied ranges,
7. re-validate redirects under the same rules,
8. enforce SNI and SPKI pinning when configured.

Absence of timeout limits for connect, total request budget, or response size MUST be treated as
configuration error for policy-constrained egress.

#### 5.6.2 Threshold Secrets and Access Tokens

High-value secrets SHOULD use threshold sharing rather than ordinary replication.

```rust
pub struct SecretObject {
    pub header: ObjectHeader,
    pub secret_id: SecretId,
    pub zone_id: ZoneId,
    pub k: u8,
    pub n: u8,
    pub wrapped_shares: Vec<(NodeId, Vec<u8>)>,
    pub rotation: SecretRotationPolicy,
}

pub struct SecretRotationPolicy {
    pub rotate_after_secs: u64,
    pub overlap_secs: u64,
}

pub struct SecretAccessToken {
    pub jti: [u8; 16],
    pub secret_id: SecretId,
    pub purpose: String,
    pub requested_by: PrincipalId,
    pub iat: u64,
    pub exp: u64,
    pub signature: Signature,
}
```

Normative rules:

1. RaptorQ symbolization is not a secret-sharing mechanism and MUST NOT be treated as one.
2. Secret reconstruction MUST be short-lived and auditable.
3. Secret material MUST be zeroized promptly after use.

Secrets MUST NOT be persisted to disk by default. If a connector requires durable secret storage,
the storage class and zeroization strategy MUST be declared in the manifest and permitted by policy.

#### 5.6.3 Credential Injection and Zero-Persistence Rules

Credential delivery SHOULD prefer mediated application of credentials over disclosure of raw secret bytes.

Normative rules:

1. Connectors MUST NOT persist injected credentials unless explicit policy and storage class allow it.
2. Secret material SHOULD be materialized only for the shortest feasible duration and zeroized promptly after use.
3. Network Guard or equivalent mediation SHOULD support host-side injection for HTTP headers, OAuth bearer tokens, or mTLS material without revealing the underlying secret to connector logs or state snapshots.
4. Test harnesses MUST include cases that prove secrets are absent from logs, evidence bundles, and crash artifacts by default.

## 6. Durable Object and Evidence Model

### 6.1 Receipts

Every risky or dangerous operation MUST produce durable evidence.

For strict-idempotency risky or dangerous operations, the host SHOULD persist an `OperationIntent`
before the external side effect begins. This closes the crash window between “effect happened” and
“receipt stored”.

```rust
pub struct OperationIntent {
    pub header: ObjectHeader,
    pub request_object_id: ObjectId,
    pub capability_token_jti: [u8; 16],
    pub idempotency_key: Option<String>,
    pub planned_at: u64,
    pub planned_by: NodeId,
    pub lease_seq: Option<u64>,
    pub upstream_idempotency: Option<String>,
    pub signature: Signature,
}
```

```rust
pub struct OperationReceipt {
    pub header: ObjectHeader,
    pub request_object_id: ObjectId,
    pub connector_id: ConnectorId,
    pub operation_id: OperationId,
    pub zone_id: ZoneId,
    pub outcome: ReceiptOutcome,
    pub result_object_id: Option<ObjectId>,
    pub evidence: Vec<ObjectId>,
    pub executed_at: u64,
    pub signature: Signature,
}

pub enum ReceiptOutcome {
    Succeeded,
    Denied,
    Cancelled,
    Failed,
}
```

#### 6.1.1 Exactly-Once Spine for Strict Operations

For operations declared `IdempotencyClass::Strong` or otherwise marked as strict by policy:

1. `OperationIntent` MUST be stored before the external side effect begins.
2. The intent SHOULD reference the execution lease used for the attempt.
3. `OperationReceipt` MUST reference the intent.
4. Crash recovery MUST examine intent-without-receipt cases before re-executing.
5. Retrying with the same idempotency key MUST return the prior committed result when one exists.

### 6.2 Decision Receipts

Allow/deny decisions for risky and dangerous operations MUST be explainable:

```rust
pub struct DecisionReceipt {
    pub header: ObjectHeader,
    pub request_object_id: ObjectId,
    pub decision: Decision,
    pub reason_code: String,
    pub message: Option<String>,
    pub evidence: Vec<ObjectId>,
    pub decided_at: u64,
    pub decided_by: NodeId,
    pub signature: Signature,
}

pub enum Decision {
    Allow,
    Deny,
}
```

### 6.3 Audit Chain

Audit is the normative tamper-evidence system for every zone. It is not an optional observability
feed. The audit chain is the durable record that closes the loop between decision, execution,
checkpoint movement, repair, and incident review. Every zone therefore has exactly one accepted
audit lineage at a given `head_seq`, even if competing candidates were observed and quarantined
during fork handling.

```rust
pub struct AuditEvent {
    pub header: ObjectHeader,
    pub correlation_id: [u8; 16],
    pub trace: TraceContext,
    pub zone_id: ZoneId,
    pub actor: PrincipalId,
    pub connector_id: Option<ConnectorId>,
    pub operation_id: Option<OperationId>,
    pub event_class: AuditEventClass,
    pub event_type: String,
    pub disposition: AuditDisposition,
    pub subject_refs: Vec<AuditSubjectRef>,
    pub decision_receipt_id: Option<ObjectId>,
    pub operation_receipt_id: Option<ObjectId>,
    pub checkpoint_id: Option<ObjectId>,
    pub lease_id: Option<ObjectId>,
    pub revocation_head_id: Option<ObjectId>,
    pub summary: AuditSummary,
    pub prev: Option<ObjectId>,
    pub seq: u64,
    pub occurred_at: u64,
    pub degraded_mode: bool,
    pub signature: Signature,
}

pub enum AuditEventClass {
    Decision,
    Execution,
    SecretUse,
    Approval,
    ZoneTransfer,
    Lease,
    Checkpoint,
    Revocation,
    SupplyChain,
    Repair,
    Incident,
}

pub enum AuditDisposition {
    Attempted,
    Allowed,
    Denied,
    Succeeded,
    Failed,
    Canceled,
    Recovered,
}

pub struct AuditSubjectRef {
    pub kind: String,
    pub object_id: ObjectId,
}

pub struct AuditSummary {
    pub reason_code: Option<String>,
    pub coverage_bps: Option<u16>,
    pub quorum_met: Option<bool>,
    pub external_target: Option<String>,
}

pub struct AuditHead {
    pub header: ObjectHeader,
    pub zone_id: ZoneId,
    pub prev_head: Option<ObjectId>,
    pub head_event: ObjectId,
    pub head_seq: u64,
    pub tail_seq: u64,
    pub event_count: u64,
    pub coverage_bps: u16,
    pub quorum_required: u16,
    pub quorum_achieved: u16,
    pub status: AuditHeadStatus,
    pub as_of_epoch: EpochId,
    pub quorum_signatures: Vec<(NodeId, Signature)>,
}

pub enum AuditHeadStatus {
    PendingCoverage,
    QuorumSatisfied,
    CoverageSatisfied,
    Degraded,
    Forked,
}
```

Normative rules:

1. `AuditEvent.seq` MUST be strictly monotonic per zone and MUST increment by exactly `1` from
   `prev` unless the event is the zone's genesis audit event.
2. `AuditEvent.prev` MUST reference the immediately preceding accepted event in the same zone.
3. `AuditHead.head_event` MUST reference the event whose `seq == head_seq`.
4. `AuditHead.tail_seq` MUST identify the earliest event still covered by the currently published
   head material; implementations MAY compact older events only after policy permits and only if
   retained evidence remains verifiable.
5. `coverage_bps` MUST be computed over the set of audit-eligible nodes for the zone, not merely
   the set of nodes currently online.
6. `quorum_signatures` MUST be sorted lexicographically by signer identity before hashing or
   verification.
7. Checkpoints MAY reference only an `AuditHead` whose `status` is acceptable under the zone's
   degraded-mode policy.
8. Audit events retained for replay, forensics, or repair MUST preserve the full object, not merely
   a rendered log projection.

#### 6.3.1 Required Event Families and Emission Coverage

The following event families are normative:

- `decision.*` for allow or deny decisions tied to `DecisionReceipt`
- `execution.*` for operation start, completion, failure, cancellation, and failover
- `secret.*` for secret release, reconstruction, or proxy-mediated credential use
- `approval.*` for approval consumption, rejection, expiry, and supersession
- `zone.*` for integrity elevation, confidentiality declassification, or cross-zone writes
- `lease.*` for grant, renew, conflict, expiration takeover, and release
- `checkpoint.*` for checkpoint acceptance, rejection, rollback refusal, and publication
- `revocation.*` for stale-frontier denial, degraded-mode entry, and degraded-mode recovery
- `artifact.*` for manifest or binary activation, rejection, and policy failure
- `repair.*` for repair start, completion, failure, or policy-mandated rebalance
- `incident.*` for fork detection, key-role confusion, or audit-chain anomaly

The following emissions are REQUIRED:

1. A deny event MUST be emitted before returning a deny result for:
   - risky or dangerous operation denials,
   - revocation freshness denials,
   - approval or declassification denials,
   - lease-conflict denials,
   - placement or policy denials once evaluation is complete.
2. For risky and dangerous allows, a decision event referencing the `DecisionReceipt` MUST be
   emitted before the first irreversible external side effect.
3. A secret-use event MUST be emitted when plaintext secret material is first released to process
   memory or to a capability-gated proxy boundary, not merely when the request was queued.
4. An approval event MUST be emitted when an approval is consumed or rejected, not only when the
   approval object was issued.
5. A zone-transfer event MUST be emitted when data is elevated, declassified, or written to an
   external sink whose confidentiality or integrity classification differs from the current zone.
6. A checkpoint event MUST be emitted on both acceptance and rejection of candidate checkpoints,
   including rollback or stale-frontier refusal.
7. A revocation event MUST be emitted whenever the node enters or exits degraded mode because the
   revocation frontier or checkpoint frontier is stale.

Safe operations MAY be sampled or aggregated, but sampling MUST NOT suppress any event class listed
above when the action is risky, dangerous, degraded, or incident-related.

#### 6.3.2 Chain Advancement, Head Publication, and Fork Handling

Audit-chain advancement MUST follow one deterministic procedure:

1. Validate the candidate event's signature, zone binding, canonical encoding, and `prev`.
2. Confirm that `seq` is exactly the current accepted `head_seq + 1`, or `1` for genesis.
3. Persist the candidate event locally with `RetentionClass::Audit`.
4. Gossip the candidate and collect coverage and, where required, quorum attestations.
5. Publish a new `AuditHead` only after the zone policy's required `coverage_bps` and quorum
   conditions are satisfied, unless degraded-mode policy explicitly permits publication with
   `status = Degraded`.
6. Advance `ZoneCheckpoint.audit_head` only to a published `AuditHead`.

Fork handling is normative:

1. If two different events claim the same `(zone_id, seq)`, the node MUST treat this as an audit
   fork even if one event appears locally preferable.
2. On fork detection, the node MUST:
   - stop advancing the accepted `AuditHead`,
   - emit an `incident.audit_fork_detected` event in local operator evidence,
   - retain all competing events and heads for inspection,
   - refuse to checkpoint past the disputed sequence unless explicit degraded-mode policy and
     operator approval allow continued local execution without head advancement.
3. Resolution MUST occur by one of:
   - a quorum-signed canonical `AuditHead`,
   - a later `ZoneCheckpoint` that explicitly names the winning head,
   - operator-directed incident resolution recorded as a durable policy or incident object.
4. Losing branches MUST remain inspectable as incident evidence until retention policy explicitly
   allows disposal.

#### 6.3.3 Emission Timing, Retention, and Stream Semantics

Emission timing matters:

1. `DecisionReceipt` and the corresponding `decision.*` audit event MUST be durable before a risky
   or dangerous allow can produce irreversible provider-side effects.
2. `OperationReceipt` and the corresponding terminal `execution.*` event MUST be durable before a
   request is reported as committed.
3. Streamed or long-running operations MUST emit:
   - a start event,
   - a terminal event,
   - a resume or failover event whenever execution site or checkpoint lineage changes.
4. Lease events MUST be emitted at every grant, renewal, conflict, forced takeover, and release.
5. Repair events MUST be emitted when repair materially changes availability or concentration
   relative to object or zone policy.

Retention rules:

1. Audit events and heads MUST use `RetentionClass::Audit`.
2. An implementation MUST NOT garbage-collect an audit event if it is still referenced by:
   - an `AuditHead`,
   - a `ZoneCheckpoint`,
   - a `DecisionReceipt` or `OperationReceipt`,
   - an incident bundle or conformance fixture under retention.
3. Compaction MAY replace older per-event scans with summarized segments, but only if the summary is
   itself content-addressed, signed, and preserves chain verifiability.

### 6.4 Revocation

Revocations are first-class durable objects:

```rust
pub struct RevocationObject {
    pub header: ObjectHeader,
    pub zone_id: ZoneId,
    pub revoked: Vec<ObjectId>,
    pub scope: RevocationScope,
    pub reason_code: String,
    pub effective_at: u64,
    pub expires_at: Option<u64>,
    pub reason: String,
    pub issued_by: PrincipalId,
    pub signature: Signature,
}

pub enum RevocationScope {
    Capability,
    IssuerKey,
    NodeAttestation,
    ZoneKey,
    ConnectorArtifact,
    PolicyObject,
}
```

No token, lease, checkpoint, or supply-chain artifact may be used without consulting current revocation state.

#### 6.4.1 Revocation Event Chain and Freshness

Revocation freshness MUST be cheap to reason about. Implementations SHOULD maintain:

```rust
pub struct RevocationEvent {
    pub header: ObjectHeader,
    pub revocation_object_id: ObjectId,
    pub prev: Option<ObjectId>,
    pub seq: u64,
    pub occurred_at: u64,
    pub signature: Signature,
}

pub struct RevocationHead {
    pub header: ObjectHeader,
    pub zone_id: ZoneId,
    pub head_event: ObjectId,
    pub head_seq: u64,
    pub epoch_id: EpochId,
    pub quorum_signatures: Vec<(NodeId, Signature)>,
}
```

Tokens, checkpoints, and high-safety operations SHOULD bind to revocation freshness through
checkpoint sequence or revocation-head sequence. Dangerous operations MUST NOT proceed when
revocation state is known stale beyond policy tolerance.

#### 6.4.2 Revocation Enforcement Order

Implementations SHOULD enforce revocations in a deterministic order so that the same stale or revoked
artifact produces the same denial evidence everywhere.

Recommended order:

1. direct token or lease revocation,
2. issuer-key or attestation revocation,
3. connector artifact or manifest revocation,
4. zone-policy or checkpoint freshness failure causing effective revocation of stale authority.

If multiple revocations apply, the evidence surface SHOULD identify the first decisive revocation plus
additional corroborating revocation objects.

#### 6.4.3 Revocation Freshness Policy

Revocation freshness is its own doctrine, not a side effect of generic cache invalidation. Every
implementation MUST evaluate whether its current zone frontier is fresh enough for the safety class
of the requested action.

```rust
pub struct RevocationFreshnessPolicy {
    pub max_head_age_secs: u64,
    pub max_checkpoint_age_secs: u64,
    pub max_safe_staleness_secs: u64,
    pub allow_safe_ops_in_degraded_mode: bool,
    pub allow_risky_ops_with_interactive_override: bool,
    pub required_override_scope: String,
}

pub struct FreshnessFrontier {
    pub zone_id: ZoneId,
    pub checkpoint_seq: u64,
    pub rev_head_seq: u64,
    pub observed_at: u64,
}
```

Normative freshness rules:

1. Dangerous operations MUST require:
   - a locally known `FreshnessFrontier`,
   - `rev_head_seq` at least as new as any minimum revocation sequence bound into the token,
     checkpoint, or request policy,
   - `observed_at` within both `max_head_age_secs` and `max_checkpoint_age_secs`.
2. Risky operations MUST follow the dangerous-operation rule by default.
3. A risky operation MAY proceed with an interactive override only if:
   - `allow_risky_ops_with_interactive_override` is true,
   - the override approval is bound to the exact request or idempotency key,
   - the approval references the stale frontier that is being overridden,
   - the override is itself fresh and unrevoked.
4. Safe operations MAY proceed in degraded mode only if
   `allow_safe_ops_in_degraded_mode == true` and the frontier age does not exceed
   `max_safe_staleness_secs`.
5. If freshness is insufficient, the deny reason code MUST distinguish:
   - `revocation.unknown_frontier`,
   - `revocation.stale_head`,
   - `revocation.stale_checkpoint`,
   - `revocation.override_required`,
   - `revocation.override_invalid`.
6. Entering degraded mode MUST emit `revocation.degraded_mode`; leaving degraded mode MUST emit
   `revocation.recovered`.
7. Implementations MUST fail closed if policy requires quorum-backed revocation heads and the known
   head cannot be verified.

### 6.5 Zone Checkpoints

The enforceable state of a zone is summarized by checkpoints:

```rust
pub struct ZoneCheckpoint {
    pub header: ObjectHeader,
    pub zone_id: ZoneId,
    pub prev_checkpoint: Option<ObjectId>,
    pub revocation_head: ObjectId,
    pub revocation_seq: u64,
    pub audit_head: ObjectId,
    pub audit_seq: u64,
    pub zone_definition_head: ObjectId,
    pub zone_policy_head: ObjectId,
    pub checkpoint_seq: u64,
    pub quorum_signatures: Vec<(NodeId, Signature)>,
}
```

Zone checkpoints MUST be used for sync, rollback detection, and failover safety.

#### 6.5.1 Checkpoint Comparison and Fork Detection

Checkpoint comparison SHOULD support fast freshness reasoning plus explicit fork detection.

Normative rules:

1. A higher `checkpoint_seq` MUST dominate a lower sequence only if the checkpoint also validates under current trust and revocation rules.
2. If two distinct checkpoints claim the same `checkpoint_seq` for a zone, the implementation MUST treat that as a fork until reconciled.
3. Forks MUST be visible to operators and SHOULD block dangerous execution unless policy explicitly allows degraded operation.
4. Sync protocols SHOULD compare checkpoint summaries before attempting larger object reconciliation.

## 7. Host Model

### 7.1 Host as Root Application

The host is a supervised root application, not merely a request router.

At minimum, the host application SHOULD contain child services for:

- policy compilation,
- placement planning,
- connector registry and inventory,
- lease coordination,
- checkpoint and evidence persistence,
- streaming fanout and backpressure tracking,
- operator surfaces (`explain`, `doctor`, `dry-run`, `replay`, live tails),
- provisioning and credential rotation,
- repair and background integrity tasks.

### 7.2 Host Responsibilities

The host MUST:

1. compile manifest + zone policy + supply-chain policy + placement policy into a runnable connector plan,
2. narrow authority into connector launch contexts,
3. supervise connector lifecycles,
4. enforce budgets, placement decisions, and restart policy,
5. persist receipts, decisions, checkpoints, and audit artifacts,
6. expose operator and developer evidence surfaces,
7. enforce conformance-critical transport semantics such as cancellation and backpressure.
8. prevent direct connector-to-connector authority bypass; composition goes through host policy,
   placement, and evidence surfaces.

### 7.3 Host Lifecycle

The host lifecycle is:

`Discover -> Verify -> Compile -> Place -> Start -> Supervise -> Drain -> Checkpoint -> Stop`

Normative rules:

1. Start order MUST be deterministic.
2. Host shutdown MUST drain or explicitly cancel child applications according to declared policy.
3. A connector crash loop MUST be surfaced as health degradation and MAY trigger rollback or demotion.
4. Repairs, replay, and revocation updates MAY continue in background host regions, but only as supervised child services.

### 7.3.1 Activation Requirements

Before a connector may transition into `Active`, the host MUST confirm:

1. manifest extraction succeeded without executing the connector,
2. interface hash matches the signed and policy-pinned expectation,
3. supply-chain policy is satisfied,
4. required provisioning steps have completed successfully,
5. required zone and capability policy objects are fresh enough,
6. any mandatory secrets or wrapped credentials are available in the required execution environment,
7. placement policy produced an admissible target with required storage, network, and isolation properties,
8. the chosen execution form is compatible with the local platform and policy.

The host SHOULD materialize an activation-plan object or equivalent evidence record summarizing the
inputs that justified activation. When activation fails, the host MUST emit a denial or failure artifact
with stable reason codes rather than only ephemeral logs.

### 7.3.2 Updates, Rollback, and Demotion

Connector updates are ordinary lifecycle events and MUST be policy-governed. The host SHOULD support:

- staged rollout by connector family or zone,
- health-gated promotion,
- automatic rollback on crash-loop or policy regression,
- demotion to a less privileged or less preferred placement when a full rollback is unnecessary.

Normative rules:

1. A new connector artifact MUST pass the same activation checks as a first install.
2. Rollback MUST refer to a previously verified artifact and manifest pair; ad hoc fallback binaries are forbidden.
3. Rollback or demotion decisions MUST be explainable to operators and retain evidence linking observed failure to the chosen remediation.
4. In-flight work MUST be drained, cancelled, checkpointed, or explicitly failed according to operation policy before replacement.
5. Risky and dangerous connectors SHOULD default to staged rollout with health observation before wide activation.

### 7.4 Operator Surfaces

The host MUST support user-facing and developer-facing control surfaces for:

- `simulate` / dry-run,
- `explain` with DecisionReceipt rendering,
- `doctor` with structured failure diagnosis,
- evidence retrieval for requests, streams, and checkpoints,
- live logs and trace tails with redaction,
- replay of captured transcripts where policy permits,
- repair and recheck initiation.

These surfaces are part of the operational model, not optional CLI sugar.

### 7.4.1 Host Admin-Plane Truth

The host is the source of truth for admin-plane and operator-plane connector state. Tooling such as
`fcp-cli`, `fwc`, MCP adapters, and dashboards SHOULD project host-backed truth rather than
recomputing lifecycle or invoke semantics from manifests, local caches, or direct low-level crate
reads.

The minimum host-admin surface SHOULD include:

- discovery and connector inventory,
- connector introspection and schema catalog access,
- preflight evaluation for invoke requests,
- invoke and bounded batch execution,
- health and self-check aggregation,
- lifecycle, pin, rollout, promotion, rollback, and demotion controls,
- explain, doctor, evidence retrieval, and replay entry points.

Normative rules:

1. Inventory, lifecycle state, rollout state, and active health MUST be reported by the host, not
   inferred by clients from static artifacts alone.
2. Host-admin preflight MUST be able to report policy, capability, freshness, approval, placement,
   and supply-chain blockers before irreversible execution begins.
3. Batch execution MAY share transport, scheduling, or evidence envelopes, but each member
   operation MUST still retain individually explainable admission and outcome state.
4. Tooling layers MUST NOT become competing semantic authorities for connector lifecycle or invoke
   policy. They are consumers of host truth.

## 8. Connector Application Model

### 8.1 Connector Identity and Forms

A connector is a supervised application instance with one of the following execution forms:

```rust
pub enum ConnectorExecutionForm {
    NativeBinary,
    WasiModule,
    RemotePlacedInstance,
}
```

All three forms share the same contract for authority, lifecycle, evidence, and operator surfaces.

#### 8.1.1 Execution Form Guidance

`WasiModule` SHOULD be preferred for high-risk connectors unless there is a clear performance or
platform constraint. Benefits include:

- capability-gated host calls,
- consistent cross-platform isolation semantics,
- reduced memory-corruption blast radius,
- simpler deterministic testing.

`NativeBinary` MAY be preferred for:

- GPU-accelerated work,
- very high-throughput processing,
- OS-specific facilities not yet available through the WASI surface.

`RemotePlacedInstance` is not a weaker form. It is the same connector model materialized on a
different node under the same authority, checkpoint, and evidence rules.

### 8.2 Connector Archetypes

Connectors MAY implement one or more archetypes:

- Request-response
- Streaming
- Bidirectional
- Polling
- Webhook
- Queue / pub-sub
- File / blob
- Database
- CLI / process
- Browser / remote-control

Archetypes affect lifecycle, state model, lease needs, and backpressure semantics.

### 8.3 Connector Application Contract

A conformant connector application MUST declare:

- connector identity and version,
- operations, events, and resources,
- safety tiers and approval modes,
- durable state model,
- network and storage requirements,
- provisioning surfaces,
- restart and drain expectations,
- evidence expectations,
- placement constraints.

The connector contract MUST be explicit enough for the host to compile and supervise it without
guessing hidden behavior.

### 8.3.1 Operation, Event, and Resource Declarations

```rust
pub struct OperationDeclaration {
    pub operation_id: OperationId,
    pub capability: CapabilityId,
    pub safety_tier: SafetyTier,
    pub approval_mode: ApprovalMode,
    pub idempotency: IdempotencyClass,
    pub input_schema: SchemaId,
    pub output_schema: SchemaId,
    pub recovery_hints: Vec<String>,
}

pub struct EventDeclaration {
    pub event_type: String,
    pub replayable: bool,
    pub requires_ack: bool,
    pub ordering_scope: OrderingScope,
}

pub struct ResourceDeclaration {
    pub resource_type: String,
    pub visibility: ResourceVisibility,
    pub mutability: ResourceMutability,
}
```

Normative rules:

1. Operations MUST declare capability, safety, approval, and idempotency properties explicitly.
2. Replayable events MUST expose ordering and cursor semantics.
3. Resource declarations SHOULD be used wherever external resources can be referenced durably.
4. Recovery hints MAY assist operator surfaces, but MUST NOT replace structured reason codes.

### 8.3.2 `simulate` and Introspection Contracts

Connectors SHOULD expose a meaningful `simulate` surface for any operation that is risky, dangerous,
externally expensive, or likely to fail due to policy or provider conditions.

Recommended `simulate` guarantees:

1. no externally visible writes,
2. bounded remote reads only when necessary,
3. explicit reporting of missing capability, approval, credential, or provider-availability preconditions,
4. optional cost, size, or latency estimates.

The `introspect` surface SHOULD report:

- operation schemas,
- safety tier,
- approval mode,
- idempotency class,
- replay semantics,
- provider-specific limits and hints,
- whether checkpoint or resume is supported.

### 8.4 Connector State

Canonical connector state is durable and externalized:

```rust
pub enum ConnectorStateModel {
    Stateless,
    SingletonWriter,
    Crdt { crdt_type: CrdtType },
}

pub enum CrdtType {
    LwwMap,
    OrSet,
    GCounter,
    PnCounter,
}
```

For singleton writers:

```rust
pub struct ConnectorStateObject {
    pub header: ObjectHeader,
    pub connector_id: ConnectorId,
    pub zone_id: ZoneId,
    pub prev: Option<ObjectId>,
    pub seq: u64,
    pub state_cbor: Vec<u8>,
    pub lease_seq: u64,
    pub lease_object_id: ObjectId,
    pub signature: Signature,
}
```

For multi-writer state:

```rust
pub struct ConnectorStateDelta {
    pub header: ObjectHeader,
    pub connector_id: ConnectorId,
    pub zone_id: ZoneId,
    pub crdt_type: CrdtType,
    pub delta_cbor: Vec<u8>,
    pub applied_at: u64,
    pub applied_by: NodeId,
    pub signature: Signature,
}

pub struct ConnectorStateSnapshot {
    pub header: ObjectHeader,
    pub connector_id: ConnectorId,
    pub zone_id: ZoneId,
    pub covers_head: ObjectId,
    pub covers_seq: u64,
    pub state_cbor: Vec<u8>,
    pub signature: Signature,
}
```

Normative rules:

1. Durable state relevant to failover or deduplication MUST NOT live only in process memory.
2. Singleton-writer state updates MUST be fenced by a valid lease.
3. State snapshots SHOULD be taken to bound replay cost.
4. Competing writes with stale or conflicting lease sequence values MUST be treated as safety incidents.
5. CRDT connectors MUST define merge semantics that are deterministic under canonical serialization.

### 8.4.1 Operation Intent and Receipt Objects

Operations with strong idempotency or externally visible risky effects SHOULD externalize intent before
the side effect and receipt after completion.

```rust
pub struct OperationIntentV3 {
    pub header: ObjectHeader,
    pub request_object_id: ObjectId,
    pub connector_id: ConnectorId,
    pub operation_id: OperationId,
    pub capability_token_jti: [u8; 16],
    pub idempotency_key: Option<String>,
    pub planned_at: u64,
    pub planned_by: NodeId,
    pub lease_seq: Option<u64>,
    pub upstream_idempotency: Option<String>,
    pub signature: Signature,
}

pub struct OperationReceiptV3 {
    pub header: ObjectHeader,
    pub request_object_id: ObjectId,
    pub connector_id: ConnectorId,
    pub operation_id: OperationId,
    pub zone_id: ZoneId,
    pub outcome: ReceiptOutcome,
    pub result_object_id: Option<ObjectId>,
    pub resource_object_ids: Vec<ObjectId>,
    pub executed_at: u64,
    pub executed_by: NodeId,
    pub signature: Signature,
}
```

Normative rules:

1. Dangerous operations MUST externalize intent before side effects when the operation is restartable or retryable.
2. The receipt MUST reference enough evidence to prove whether the side effect committed.
3. Crash recovery MUST check for intents without receipts and treat them as potentially incomplete work rather than blindly retrying.

### 8.4.2 Stream Cursors and Replay Positions

Streaming, polling, queue, and webhook connectors SHOULD externalize cursor or replay state if loss
or duplication would materially affect correctness.

```rust
pub struct CursorStateObject {
    pub header: ObjectHeader,
    pub connector_id: ConnectorId,
    pub stream_id: String,
    pub ordering_scope: OrderingScope,
    pub last_acknowledged_seq: u64,
    pub opaque_cursor: Option<Vec<u8>>,
    pub updated_at: u64,
    pub signature: Signature,
}
```

Normative rules:

1. Replayable connectors MUST define what constitutes the cursor and how it composes with sequence identity.
2. Cursor updates relevant to failover MUST be durable.
3. Resume logic MUST NOT guess a cursor from logs when a durable cursor object is required by the connector contract.

### 8.5 Connector Resources and Handles

Where an external resource can be represented durably, connectors SHOULD use `ResourceObject`
references instead of ambient raw identifiers. This improves auditability, provenance handling,
and approval targeting.

### 8.6 Connector Lifecycle

Connector lifecycle states:

`Resolved -> Verified -> Configured -> Active -> Draining -> Paused -> Failed -> Stopped`

A connector MUST expose health and introspection surfaces while active. Long-lived connectors SHOULD
also expose checkpoint, replay, and state-summary surfaces.

#### 8.6.1 Standard Connector Methods

The standard connector surface includes:

| Method | Purpose |
|--------|---------|
| `handshake` | Bind to host session, zone, and protocol expectations |
| `describe` | Return manifest and execution-form metadata |
| `introspect` | Return operations, events, resources, schemas, and hints |
| `capabilities` | Return capability catalog and declared policy assumptions |
| `configure` | Apply configuration or provisioning results |
| `simulate` | Perform bounded preflight evaluation without side effects |
| `self_check` | Run connector-local readiness and dependency diagnostics |
| `invoke` | Execute one operation under the supplied authority context |
| `subscribe` | Open a streaming or replayable event surface |
| `ack` / `nack` | Advance replay state and delivery guarantees |
| `health` | Return readiness and degradation details |
| `checkpoint` | Externalize resumable state where supported |
| `shutdown` | Begin bounded drain and termination |

Connectors MAY expose additional domain-specific methods, but the host MUST be able to supervise the
application using the standard lifecycle surface alone.

### 8.6.2 Health and Introspection Payloads

Health surfaces SHOULD be rich enough for both automation and human diagnosis.

```rust
pub struct ConnectorHealth {
    pub connector_id: ConnectorId,
    pub state: String,
    pub reason_code: Option<String>,
    pub last_checkpoint: Option<ObjectId>,
    pub last_success_at: Option<u64>,
    pub inflight_requests: u32,
    pub degraded_mode: bool,
}
```

The host SHOULD be able to distinguish:

- ready but idle,
- active and healthy,
- degraded but serving,
- draining,
- failed with retry planned,
- failed permanently pending operator intervention.

### 8.6.3 Shutdown and Drain Semantics

`shutdown` MUST begin a bounded drain protocol rather than best-effort process termination.

Normative rules:

1. New externally visible work MUST stop being admitted once drain begins unless explicit takeover policy says otherwise.
2. In-flight work MUST either complete, checkpoint, or fail with durable evidence.
3. Long-lived streams MUST surface progress toward quiescence.
4. Host and connector MUST agree on when a drain has reached safe handoff or safe termination.

## 9. Control, Data, and Evidence Plane

### 9.1 Overview

FCP defines two transport surfaces:

1. **FCPC**: a low-latency framed CBOR plane for invocation, streaming, flow control, cancellation, health, checkpoint requests, and evidence queries.
2. **FCPS**: a durable object plane used for object fetch, mirrored distribution, symbol repair, chunked payload transfer, replay, and offline recovery.

These surfaces are complementary. FCPC is used for live interaction. FCPS is used where durability,
repairability, or replay matters.

### 9.1.1 Protocol Modes

FCP3 defines one canonical operational mode with two coupled planes:

| Plane | Purpose | Required |
|-------|---------|----------|
| `FCPC` | Live framed control/data/evidence exchange | Yes |
| `FCPS` | Durable object, chunk, symbol, replay, and repair distribution | Yes |

Backwards-compatibility translators are intentionally out of scope.

### 9.1.2 Message Families

Representative FCPC message families include:

| Family | Direction | Purpose |
|--------|-----------|---------|
| `discovery` | Operator ↔ Host | Enumerate connectors, lifecycle state, health, and cacheable inventory metadata |
| `introspect` | Operator ↔ Host | Retrieve host-backed connector catalog, schemas, safety tiers, and replay hints |
| `preflight` | Operator ↔ Host | Evaluate invoke viability before execution and report blockers deterministically |
| `handshake` | Host ↔ Connector | Establish authenticated live session |
| `configure` | Host → Connector | Apply configuration or provisioning result |
| `simulate` | Host → Connector | Bounded preflight without side effects |
| `self_check` | Host ↔ Connector | Probe connector-local readiness, dependencies, and remediation hints |
| `invoke` | Host → Connector | Execute operation |
| `batch` | Operator ↔ Host | Submit bounded multi-operation work under one host scheduling/evidence context |
| `result` | Connector → Host | Return result or outcome |
| `subscribe` | Host → Connector | Open event stream |
| `event` | Connector → Host | Deliver replayable or ephemeral events |
| `ack` / `nack` | Host → Connector | Advance or reject replay state |
| `health` | Host ↔ Connector | Health and degradation surface |
| `checkpoint` | Host ↔ Connector | Externalize or probe resumable state |
| `lifecycle` / `rollout` | Operator ↔ Host | Pin, promote, demote, rollback, and inspect staged activation state |
| `explain` / `evidence` | Host ↔ Connector | Retrieve explanation and durable evidence |
| `doctor` / `replay` | Operator ↔ Host | Diagnostics and replay surfaces |

FCPS message families include object fetch, chunk fetch, symbol request, symbol delivery, and repair coordination.

Transport packaging MAY vary across subprocess stdio, local sockets, or remote links, but the
semantic message families above remain the stable contract the host and connector must implement.

### 9.1.3 Symbol Request Bounding (NORMATIVE)

Symbol retrieval is a major amplification and decode-DoS surface. Requests MUST be bounded.

```rust
pub struct SymbolRequest {
    pub object_id: ObjectId,
    pub zone_id: ZoneId,
    pub max_symbols: u32,
    pub want_esi: Option<Vec<u32>>,
    pub requested_at: u64,
    pub requester: NodeId,
    pub signature: Signature,
}
```

Normative rules:

1. A responder MUST NOT exceed `max_symbols`.
2. Unauthenticated or low-trust requests MUST be subject to stricter caps.
3. Symbol processing MUST count against peer budget and decode budget.
4. Targeted repair requests MAY ask for specific symbol indices, but those asks MUST still be bounded.

### 9.2 FCPC Design Requirements

FCPC MUST:

1. use typed framed messages,
2. preserve request identity and correlation,
3. support streaming backpressure and explicit credits,
4. support cancellation and drain status,
5. support health, explain, checkpoint, and evidence queries,
6. avoid reliance on newline-delimited textual envelopes as the normative connector ABI.

### 9.2.1 Control-Plane Object Model (NORMATIVE)

Control-plane semantics MUST have canonical object forms for audit, replay, and deduplication.

```rust
pub struct ControlPlaneObject {
    pub header: ObjectHeader,
    pub body: Vec<u8>,
}

pub enum ControlPlaneRetention {
    Required,
    Ephemeral,
}
```

Retention guidance:

| Must Be Stored | May Be Ephemeral |
|----------------|------------------|
| invoke, results, receipts | health pings |
| approvals | transient backpressure signals |
| revocations | flow-control acknowledgements |
| audit events and heads | local-only liveness hints |

### 9.2.2 FCPC Framing Requirements

FCPC SHOULD run over QUIC streams and MAY run over TCP when required by environment or deployment policy.

Conceptual frame shape:

```text
magic = "FCPC"
version = u16
session_id = [16]
seq = u64
flags = u16
len = u32
payload = AEAD(ciphertext, aad = session_id || seq || flags)
```

Replay protection rules:

1. Sequence numbers MUST be monotonic per authenticated direction.
2. Receivers MUST maintain a bounded replay window.
3. Out-of-window or duplicated frames MUST be rejected with stable reason codes.

### 9.3 FCPC Envelope

```rust
pub struct FcpcEnvelope {
    pub version: u16,
    pub stream_id: u32,
    pub message: FcpcMessage,
}

pub enum FcpcMessage {
    Invoke(InvokeFrame),
    InvokeResult(InvokeResultFrame),
    StreamOpen(StreamOpenFrame),
    StreamClose(StreamCloseFrame),
    Event(EventFrame),
    Ack(AckFrame),
    Nack(NackFrame),
    Credit(CreditFrame),
    Cancel(CancelFrame),
    DrainStatus(DrainStatusFrame),
    Health(HealthFrame),
    Checkpoint(CheckpointFrame),
    Explain(ExplainFrame),
    Doctor(DoctorFrame),
    Replay(ReplayFrame),
    Evidence(EvidenceFrame),
    Error(ErrorFrame),
}
```

### 9.4 Invoke Frames

```rust
pub struct InvokeFrame {
    pub request_object_id: ObjectId,
    pub trace: TraceContext,
    pub connector_id: ConnectorId,
    pub operation_id: OperationId,
    pub zone_id: ZoneId,
    pub capability_token: ObjectId,
    pub provenance: Option<Provenance>,
    pub input: Vec<u8>,
    pub budget: Budget,
    pub idempotency_key: Option<[u8; 16]>,
}
```

The input MAY be inlined when small or MAY reference FCPS objects when large. The host and connector
MUST agree on size thresholds via manifest and ABI negotiation.

```rust
pub struct InvokeResultFrame {
    pub request_object_id: ObjectId,
    pub outcome: ReceiptOutcome,
    pub result_inline: Option<Vec<u8>>,
    pub result_object_id: Option<ObjectId>,
    pub operation_receipt: Option<ObjectId>,
}
```

```rust
pub struct SimulateFrame {
    pub request_object_id: ObjectId,
    pub connector_id: ConnectorId,
    pub operation_id: OperationId,
    pub input: Vec<u8>,
    pub capability_token: ObjectId,
    pub estimate_cost: bool,
    pub check_availability: bool,
}

pub struct SimulateResultFrame {
    pub request_object_id: ObjectId,
    pub would_succeed: bool,
    pub failure_reason_code: Option<String>,
    pub missing_capabilities: Vec<CapabilityId>,
    pub estimated_duration_ms: Option<u64>,
    pub estimated_bytes: Option<u64>,
}
```

`simulate` MUST remain side-effect free. It MAY read bounded remote state when necessary, but MUST
never perform externally visible writes.

### 9.5 Streaming and Backpressure

Streaming connectors MUST use explicit credit-based flow control:

```rust
pub struct StreamOpenFrame {
    pub request_object_id: ObjectId,
    pub topic: String,
    pub replay_from: Option<ObjectId>,
    pub initial_credit: u32,
}

pub struct EventFrame {
    pub event_object_id: ObjectId,
    pub seq: u64,
    pub requires_ack: bool,
    pub payload: Vec<u8>,
}

pub struct CreditFrame {
    pub additional_credit: u32,
}

pub struct AckFrame {
    pub event_object_id: ObjectId,
    pub seq: u64,
}

pub struct NackFrame {
    pub event_object_id: ObjectId,
    pub seq: u64,
    pub reason_code: String,
}

pub struct StreamCloseFrame {
    pub request_object_id: ObjectId,
    pub final_seq: Option<u64>,
}
```

Normative rules:

1. A sender MUST NOT exceed available credit.
2. If `requires_ack` is true, replay and deduplication semantics MUST be explicit.
3. Event streams MUST carry sequence identity sufficient for replay and resume.
4. Stream cancellation MUST trigger bounded drain behavior.
5. `Nack` semantics MUST NOT silently duplicate committed side effects.
6. Stream close MUST be explicit for orderly shutdown where the transport remains alive.

Replayable event streams SHOULD define cursor or sequence semantics sufficient to resume after
disconnect without guessing.

### 9.5.1 Epoch-Buffered Replayable Streams

High-throughput or bursty event sources SHOULD support epoch-buffered replay artifacts so that
resumption and forensic replay do not depend only on hot in-memory queues.

```rust
pub struct EventEpochBuffer {
    pub epoch_id: EpochId,
    pub topic: String,
    pub first_seq: u64,
    pub last_seq: u64,
    pub event_object_ids: Vec<ObjectId>,
    pub finalized_at: u64,
}
```

Recommended behavior:

1. batch replayable events into bounded epoch artifacts,
2. checkpoint the last durable epoch reference for resumable connectors,
3. prefer epoch fetch and selective replay over unbounded raw log scanning.

### 9.6 Cancellation and Drain Frames

```rust
pub struct CancelFrame {
    pub request_object_id: ObjectId,
    pub reason: CancelReason,
}

pub struct DrainStatusFrame {
    pub request_object_id: ObjectId,
    pub phase: DrainPhase,
    pub pending_tasks: u32,
    pub pending_finalizers: u32,
    pub confidence_bps: Option<u16>,
}

pub enum DrainPhase {
    Running,
    CancelRequested,
    Draining,
    Finalizing,
    Quiescent,
}
```

```rust
pub struct HealthFrame {
    pub connector_id: ConnectorId,
    pub state: String,
    pub reason_code: Option<String>,
    pub last_checkpoint: Option<ObjectId>,
}

pub struct CheckpointFrame {
    pub request_object_id: Option<ObjectId>,
    pub checkpoint_object_id: Option<ObjectId>,
    pub mode: CheckpointMode,
}

pub enum CheckpointMode {
    Snapshot,
    ResumeProbe,
    ForceCheckpoint,
}
```

`ResumeProbe` allows a host to ask whether resumable state exists before attempting failover or migration.

### 9.7 Explain and Evidence Frames

```rust
pub struct ExplainFrame {
    pub request_object_id: ObjectId,
}

pub struct DoctorFrame {
    pub target: DoctorTarget,
    pub include_evidence: bool,
}

pub enum DoctorTarget {
    Host,
    Connector(ConnectorId),
    Request(ObjectId),
}

pub struct ReplayFrame {
    pub request_object_id: ObjectId,
    pub include_transcript: bool,
}

pub struct EvidenceFrame {
    pub request_object_id: ObjectId,
    pub decision_receipt: Option<ObjectId>,
    pub operation_receipt: Option<ObjectId>,
    pub audit_event_ids: Vec<ObjectId>,
}

pub struct ErrorFrame {
    pub request_object_id: Option<ObjectId>,
    pub error: FcpError,
}
```

These frames allow a client or operator surface to explain allow/deny decisions and execution outcomes
without scraping logs or inferring policy.

### 9.7.1 Handshake and Session Establishment

Live sessions MUST establish:

- protocol version compatibility,
- connector identity,
- execution-form identity where relevant,
- maximum inline payload sizes,
- stream and backpressure capabilities,
- diagnostic feature availability.

A connector MUST reject a live session if host-declared expectations exceed manifest or policy limits.

### 9.7.2 Mesh Session Authentication

FCPS datagrams and FCPC streams MUST be bound to an authenticated session. Per-frame signatures are
permitted for bootstrap and degraded mode, but the normative high-throughput path uses a signed
handshake plus derived directional session keys.

```rust
pub enum SessionCryptoSuite {
    X25519HkdfHmacSha256,
    X25519HkdfBlake3,
}

pub struct MeshSessionHello {
    pub from: NodeId,
    pub to: NodeId,
    pub eph_pubkey: X25519PublicKey,
    pub nonce: [u8; 16],
    pub cookie: Option<[u8; 32]>,
    pub timestamp: u64,
    pub suites: Vec<SessionCryptoSuite>,
    pub transport_limits: Option<TransportLimits>,
    pub signature: Signature,
}

pub struct TransportLimits {
    pub max_datagram_bytes: u16,
    pub max_fcpc_inline_bytes: u32,
}

pub struct MeshSessionAck {
    pub from: NodeId,
    pub to: NodeId,
    pub eph_pubkey: X25519PublicKey,
    pub nonce: [u8; 16],
    pub session_id: [u8; 16],
    pub suite: SessionCryptoSuite,
    pub timestamp: u64,
    pub signature: Signature,
}

pub struct MeshSessionHelloRetry {
    pub from: NodeId,
    pub to: NodeId,
    pub cookie: [u8; 32],
    pub timestamp: u64,
}
```

Normative rules:

1. `MeshSessionHello` and `MeshSessionAck` MUST be signed by the node signing key attested for the corresponding node.
2. `cookie` support SHOULD be implemented to resist handshake floods and resource exhaustion.
3. Derived directional keys MUST bind both node identities, both nonces, the selected suite, and the session identifier.
4. Session establishment MUST enforce time-skew policy and replay resistance.
5. A node MUST refuse to complete handshake if the peer attestation or enrollment state is revoked or stale beyond policy.
6. Transport limits negotiated during handshake MUST be treated as hard ceilings for subsequent live traffic.

### 9.7.3 Session Replay and Rekey Policy

Implementations MUST define explicit replay and rekey policy for live sessions.

```rust
pub struct SessionReplayPolicy {
    pub max_reorder_window: u64,
    pub rekey_after_frames: u64,
    pub rekey_after_seconds: u64,
    pub rekey_after_bytes: u64,
}

pub struct TimeSkewPolicy {
    pub max_skew_secs: u64,
    pub log_skew_events: bool,
}
```

Normative defaults SHOULD be conservative enough to prevent silent drift while tolerating real-world
clock skew and mobile-device churn. Long-lived sessions SHOULD rekey proactively rather than waiting
for transport failure.

### 9.7.4 FCPS Datagrams on the Wire

The authenticated FCPS datagram envelope is the on-wire carrier for object-plane traffic:

```text
Bytes 0-15:   session_id [16]
Bytes 16-23:  seq (u64 LE)
Bytes 24-39:  mac [16]
Bytes 40..:   fcps_frame_bytes
```

The message authentication code MUST be computed over:

```text
session_id || direction || seq || fcps_frame_bytes
```

where `direction` is a one-byte constant distinguishing initiator-to-responder from responder-to-initiator traffic.

Normative rules:

1. The complete datagram, not only the FCPS payload, MUST fit within negotiated transport limits.
2. Replay protection MUST operate on authenticated session state, not merely frame-local counters.
3. Sessions MUST reject datagrams whose authenticated direction or sequence cannot be validated.
4. Degraded-mode signed datagrams MUST be rate-limited more aggressively than session-authenticated traffic.

### 9.8 FCPS Object and Symbol Plane

FCPS exists for:

- mirrored connector distribution,
- large payload transfer,
- replay and forensic retention,
- checkpoint distribution,
- offline pre-staging,
- repair and rebalancing.

RaptorQ symbolization is RECOMMENDED for large or lossy transfers. Small objects MAY be distributed
directly without symbolization when policy and transport conditions make that more efficient.

### 9.8.1 Symbol Envelope

The first-class record on the symbol plane is the `SymbolEnvelope`. FCPS datagrams and streams are
transport packaging; the envelope is the authenticated, replay-aware record for one symbol slot of
one durable object or chunk object.

```rust
pub struct SymbolEnvelope {
    pub object_id: ObjectId,
    pub esi: u32,
    pub k: u16,
    pub symbol_len: u16,
    pub zone_id: ZoneId,
    pub zone_key_id: [u8; 8],
    pub epoch_id: EpochId,
    pub source_node: NodeId,
    pub sender_instance_id: u64,
    pub frame_seq: u64,
    pub ciphertext: Vec<u8>,
    pub auth_tag: [u8; 16],
}
```

Normative mental model:

1. The canonical durable unit is the object identified by `object_id`.
2. A `SymbolEnvelope` binds one symbol slot, identified by `esi`, into that object's encoding set.
3. `(object_id, esi)` identifies a semantic symbol slot. Retransmissions MAY repeat a slot, but they
   MUST NOT silently change `k`, `zone_id`, or `zone_key_id`.
4. For chunked objects, symbolization applies to the chunk object's `object_id`, not to the parent
   chunk manifest's `object_id`.
5. Any retained symbol store MUST preserve envelope metadata, not merely raw ciphertext bytes.

#### 9.8.1.1 Symbol-Set Identity and Object Binding

Implementations MUST treat the following tuple as the encoding-set identity:

```text
(object_id, zone_id, zone_key_id)
```

Within one encoding set:

1. `k` MUST be constant.
2. `symbol_len` SHOULD be constant except where the final source symbol requires a shorter payload by
   construction.
3. A node MUST reject an envelope if its binding conflicts with a previously accepted object
   descriptor, chunk manifest, or other accepted envelope for the same encoding set.
4. A node MUST NOT merge envelopes across different `zone_key_id` values, even if `object_id`
   matches, because key rotation changes the authenticated context.

#### 9.8.1.2 Per-Symbol Authentication and Acceptance Rules

Per-symbol authentication is normative:

1. Key selection MUST be driven by `zone_id` and `zone_key_id`.
2. Sender-specific subkeys MUST be derived from `(source_node, sender_instance_id)`.
3. Nonces MUST be derived deterministically from `(frame_seq, esi)` under the selected algorithm.
4. AEAD associated data MUST bind at minimum:
   - `object_id`,
   - `esi`,
   - `k`,
   - the canonical zone hash,
   - `zone_key_id`,
   - `epoch_id`.
5. A node MUST reject the envelope if:
   - the zone binding is unknown,
   - `zone_key_id` is not present in the relevant keyring,
   - the AEAD authentication check fails,
   - the encoding-set identity conflicts with accepted state,
   - the surrounding session or replay window rejects `frame_seq`.

### 9.8.2 FCPS Frame Format

An FCPS frame carries one or more symbol envelopes plus frame-level replay and authentication state.

```rust
pub struct FcpsFrame {
    pub version: u16,
    pub flags: u16,
    pub zone_id_hash: [u8; 32],
    pub session_id: [u8; 16],
    pub seq: u64,
    pub record_count: u16,
    pub records: Vec<SymbolEnvelope>,
    pub session_auth_tag: [u8; 16],
}
```

Normative rules:

1. Frame-level authentication data MUST bind `version`, `flags`, `zone_id_hash`, `session_id`,
   `seq`, and `record_count`.
2. Replay windows MUST be enforced per authenticated session.
3. `record_count` MUST match the number of encoded envelopes.
4. Payload sizes MUST be bounded to stay within negotiated transport limits.

#### 9.8.2.1 MTU Safety and Frame Size Limits

FCP MUST avoid IP fragmentation in normal operation.

Baseline requirements:

- Implementations MUST support FCPS datagrams that fit within a UDP payload of `<= 1200` bytes.
- Senders SHOULD default to one symbol record per datagram unless negotiated limits safely permit more.
- Receivers MUST reject frames whose declared sizes would require allocation beyond configured safety bounds.

Recommended interoperability defaults:

| Field | Default |
|-------|---------|
| `max_datagram_bytes` | `1200` |
| `symbol_size` | `1024` |
| `max_symbol_count_per_frame` | `1` |
| `max_frame_bytes` | `4 MiB` |

The sender MUST choose `symbol_size`, `symbol_count`, and envelope overhead such that the fully
authenticated datagram remains within the negotiated maximum.

#### 9.8.2.2 Decode Status and Symbol Acknowledgement

Receivers SHOULD provide bounded feedback so that senders can stop early, target repairs, and avoid
unnecessary symbol flood.

```rust
pub struct DecodeStatus {
    pub object_id: ObjectId,
    pub zone_id: ZoneId,
    pub received_unique: u32,
    pub required: u32,
    pub missing_hint: Option<Vec<u8>>,
}

pub struct SymbolAck {
    pub object_id: ObjectId,
    pub zone_id: ZoneId,
    pub reconstructed_object_id: Option<ObjectId>,
}
```

Normative rules:

1. Feedback objects MUST be bounded and subject to the same admission and replay protections as other live traffic.
2. `missing_hint`, if present, MUST NOT exceed the responder's configured bound.
3. Senders SHOULD stop transmitting once a valid `SymbolAck` or equivalent completion proof is received.

### 9.8.3 Frame Flags

Representative flags include:

- `CONTROL_PLANE`
- `CHUNKED_PAYLOAD`
- `REPAIR_SYMBOL`
- `REPLAY_ARTIFACT`
- `CHECKPOINT_ARTIFACT`

Unknown critical flags MUST cause rejection.

#### 9.8.3.1 Flag Handling and Parsing Limits

Normative parsing rules:

1. Reserved flags MUST be zero on transmit and MUST cause rejection if received as set unless explicitly designated ignorable by future specification revision.
2. Unknown critical flags MUST fail closed.
3. `CONTROL_PLANE` and `CHECKPOINT_ARTIFACT` MUST NOT be set together unless the encapsulated object is itself a checkpoint-control artifact defined by schema.
4. `REPAIR_SYMBOL` MUST NOT be used to bypass normal peer-budget accounting.

### 9.8.4 Multipath Delivery and Source Diversity

FCPS delivery MAY aggregate symbols or chunks from multiple peers. Implementations SHOULD:

- avoid over-concentration on one source,
- prefer direct paths when possible,
- stop delivery when reconstruction or requested budget is satisfied,
- record repair or rebalance actions when they materially affect availability policy.

Convergence guidance:

1. Multipath selection SHOULD prefer symbol sets that improve both coverage and source diversity.
2. A sender MUST stop sending once a valid completion proof is received or the agreed budget is
   exhausted.
3. A repair planner MUST treat diversity and concentration policy as separate from raw
   reconstructability; an object can be available but still in violation of distribution policy.

### 9.8.5 Symbol-Plane Admission Control

The symbol plane is a major amplification and resource-exhaustion surface. Implementations MUST bound:

- inbound bytes per peer,
- symbol decode attempts per peer,
- failed authentication or decryption counts,
- concurrent object reconstructions,
- reconciliation or repair work induced by remote hints.

```rust
pub struct PeerBudget {
    pub max_bytes_per_min: u64,
    pub max_symbols_per_min: u32,
    pub max_failed_auth_per_min: u32,
    pub max_inflight_decodes: u32,
    pub max_decode_cpu_ms_per_min: u64,
}

pub struct AdmissionPolicy {
    pub per_peer: PeerBudget,
    pub require_authenticated_requests: bool,
}
```

Normative anti-amplification rule:

1. A node MUST NOT send more symbols in response to a repair or symbol request than the request explicitly allows.
2. Unauthenticated or low-trust requests MUST be subject to lower caps.
3. Expensive decode work MUST be accounted against the requester's budget or rejected.

### 9.8.6 Connector Artifact Distribution

FCPS SHOULD be usable for durable distribution of connector binaries, WASI modules, manifests, and
attestation bundles once they are admitted into trusted registry or mirror state.

Benefits include:

- resumable multi-source transfer,
- offline installation after mirroring,
- targeted repair instead of full re-download,
- one durable object model for both operational payloads and connector artifacts.

## 10. Manifest, Provisioning, and Isolation

### 10.1 Manifest Structure

The manifest is an operational compilation artifact. It MUST be extractable without executing the connector.

```toml
[manifest]
format = "fcp-connector-manifest"
schema_version = "3.0"
min_protocol = "fcp3/fcpc-cbor"
interface_hash = "blake3-256:fcp.interface.v3:..."

[connector]
id = "fcp.slack"
name = "Slack Connector"
version = "2026.3.0"
execution_form = "native"      # native | wasi | remote_eligible
archetypes = ["bidirectional", "streaming"]

[connector.state]
model = "singleton_writer"
state_schema_version = "1"
snapshot_every_updates = 5000

[execution]
root_budget = { deadline_ms = 30000, cost_quota = 50000, priority = "interactive" }
restart_policy = { strategy = "restart", max_restarts = 3, window_ms = 60000 }
drain_policy = { soft_timeout_ms = 2000, hard_timeout_ms = 10000 }

[placement]
eligible_zones = ["z:community"]
prefers = ["data_locality", "direct_path", "healthy_node"]
requires = ["network.egress", "storage.durable"]
remote_execution = true

[capabilities]
required = ["slack.read", "slack.write", "network.egress"]
optional = ["media.upload"]
forbidden = ["system.exec", "network.inbound"]

[provides.operations.send_message]
capability = "slack.write"
safety_tier = "risky"
requires_approval = "policy"
idempotency = "best_effort"
input_schema = { type = "object", required = ["channel", "text"] }
output_schema = { type = "object", required = ["message_id"] }

[provides.events.message_posted]
replayable = true
requires_ack = true
ordering_scope = "channel"

[provides.resources.channel]
visibility = "zone_bound"
mutability = "append"

[provisioning]
recipe = "slack/install"
supports_rotation = true
zero_persist_secrets = true

[sandbox]
profile = "strict"
memory_mb = 256
deny_exec = true

[supply_chain]
require_transparency_log = true
require_attestation_types = ["in-toto", "sbom"]
```

### 10.2 Manifest Requirements

The manifest MUST declare:

- interface identity and compatibility floor,
- connector execution form and archetypes,
- state model and schema versioning,
- budgets and lifecycle policy,
- placement eligibility and remote execution policy,
- capability declarations,
- operation/event/resource surfaces,
- idempotency and replay semantics,
- provisioning and credential behavior,
- sandbox and storage requirements,
- supply-chain verification expectations.

### 10.3 Interface Hash

The interface hash MUST cover the externally relevant contract:

- connector identity,
- archetypes,
- state model,
- operations/events/resources,
- capability declarations,
- network constraints,
- input/output schema,
- safety and approval metadata.

Supply-chain attestations and publisher signatures MUST NOT perturb the interface hash.

### 10.3.1 Manifest Negotiation Requirements (NORMATIVE)

1. `min_protocol` MUST include an explicit major protocol identity and version floor.
2. Unsupported major protocol versions MUST be rejected.
3. Unknown required protocol features MUST be treated as unsatisfied.
4. Transport-size expectations declared by the connector MUST be enforced or the connector is incompatible.
5. Interface hashes MUST use explicit domain separation.

### 10.4 Provisioning and Automation Recipes

Provisioning recipes are deterministic, machine-executable step graphs. They MAY include:

- user prompts,
- browser or approval actions,
- OAuth or API key exchange,
- webhook registration,
- bootstrap credential injection,
- validation checks,
- rollback/cleanup steps.

Provisioning surfaces MUST support:

- start,
- poll,
- complete,
- abort,
- rotate,
- revalidate.

### 10.4.1 Recipe Model

Provisioning recipes SHOULD be explicit step graphs rather than free-form imperative scripts.

```rust
pub struct ProvisioningRecipe {
    pub recipe_id: String,
    pub version: String,
    pub steps: Vec<ProvisioningStep>,
    pub rollback_steps: Vec<ProvisioningStep>,
}

pub enum ProvisioningStep {
    Prompt { prompt_id: String, fields: Vec<String> },
    BrowserAction { action_id: String, url: String },
    OAuthExchange { provider: String, scopes: Vec<String> },
    ApiCall { operation: String, input_schema: SchemaId },
    SecretInject { secret_id: SecretId, target: String },
    Validation { check_id: String },
}
```

Normative rules:

1. Recipe steps MUST be bounded, typed, and replayable enough for diagnostics.
2. Browser or prompt steps MUST be explicit in evidence so operators can tell which human action was required.
3. Rollback or cleanup steps SHOULD be declared whenever the external system may have been partially configured.

### 10.4.2 Provisioning Sessions

Long-running setup flows SHOULD expose a session model:

```rust
pub struct ProvisioningSession {
    pub session_id: [u8; 16],
    pub connector_id: ConnectorId,
    pub recipe_id: String,
    pub state: ProvisioningState,
    pub started_at: u64,
    pub updated_at: u64,
}

pub enum ProvisioningState {
    Pending,
    WaitingForUser,
    WaitingForRemote,
    Validating,
    Completed,
    Aborted,
    Failed,
}
```

Provisioning evidence SHOULD retain:

- the recipe identifier and version,
- which steps completed,
- any generated external identifiers,
- any cleanup steps performed after failure.

### 10.5 Isolation and Storage Classes

The manifest MUST declare storage intent:

```rust
pub enum StorageClass {
    MemoryOnly,
    LocalCache,
    ZoneDurable,
    ZoneDurableMirrored,
}
```

Normative rules:

1. Canonical connector state relevant to failover MUST use a durable storage class.
2. `LocalCache` is not authoritative.
3. Secret persistence defaults to forbidden.
4. WASI SHOULD be preferred for higher-risk connectors unless a justified performance constraint requires native execution.

### 10.5.1 Sandbox Profiles (NORMATIVE)

```rust
pub struct SandboxConfig {
    pub profile: SandboxProfile,
    pub memory_mb: u32,
    pub cpu_percent: u8,
    pub wall_clock_timeout_ms: u64,
    pub fs_readonly_paths: Vec<String>,
    pub fs_writable_paths: Vec<String>,
    pub deny_exec: bool,
    pub deny_ptrace: bool,
}

pub enum SandboxProfile {
    Strict,
    StrictPlus,
    Moderate,
    Permissive,
}
```

Normative enforcement expectations:

- `Strict` and `Moderate` MUST route outbound networking through Network Guard rather than raw sockets.
- `StrictPlus` SHOULD use stronger isolation such as microVM or equivalent where available.
- Filesystem access MUST be scoped to declared paths.
- Child process execution MUST be denied when `deny_exec` is true.
- Clock and randomness access SHOULD be explicit through the execution context where feasible.

### 10.5.2 Manifest Embedding

Connector manifests MUST be extractable without execution:

- ELF: dedicated manifest section,
- Mach-O: dedicated segment/section,
- PE: dedicated manifest section,
- WASI module: custom section or sidecar object declared by policy.

## 11. Placement, Mobility, and Mesh Operation

### 11.1 Device Profiles

Placement decisions are made over device profiles:

```rust
pub struct DeviceProfile {
    pub node_id: NodeId,
    pub device_class: DeviceClass,
    pub cpu_cores: u8,
    pub memory_mb: u32,
    pub network_state: NetworkState,
    pub health: HealthState,
    pub local_objects: Vec<ObjectId>,
}
```

Representative device classes include desktop, laptop, phone, tablet, server, and browser-controlled runtime.

### 11.2 Placement Planning

The placement planner MUST consider:

- zone eligibility,
- manifest requirements,
- capability and egress needs,
- remaining budget,
- locality of required objects and checkpoints,
- secret reconstruction cost,
- direct-path preference over relay paths,
- health and crash-loop state,
- lease availability,
- operator policy.

Placement MUST be explainable. For a denied or changed placement decision, the host SHOULD emit
a DecisionReceipt or equivalent planner evidence.

#### 11.2.1 Execution Planner Scoring

Implementations SHOULD consider:

- latency,
- available memory and CPU,
- local object coverage,
- secret reconstruction round-trip cost,
- direct-path vs relay-path penalty,
- current health and crash-loop state,
- zone-store quota headroom.

#### 11.2.2 Planner Evidence and Explainability

Placement outcomes MUST be explainable with durable or reconstructable evidence. A planner decision
SHOULD be able to answer:

- why a node was eligible,
- why competing nodes were rejected or scored lower,
- whether degraded mode influenced the result,
- whether secret reconstruction, data locality, or health pressure dominated the outcome.

Representative evidence surface:

```rust
pub struct PlacementDecisionEvidence {
    pub request_object_id: Option<ObjectId>,
    pub connector_id: ConnectorId,
    pub chosen_node: Option<NodeId>,
    pub candidate_scores: Vec<(NodeId, i64)>,
    pub degraded_mode: bool,
    pub limiting_factors: Vec<String>,
    pub reason_code: Option<String>,
}
```

#### 11.2.3 Degraded Placement

The planner MAY operate in degraded mode during partition, relay-only connectivity, or reduced
coverage, but it MUST do so explicitly.

Normative rules:

1. Dangerous operations SHOULD default to deny in degraded mode unless policy says otherwise.
2. Degraded placement MUST be visible to operators and evidence surfaces.
3. The planner MUST distinguish between "no eligible placement exists" and "placement exists only under degraded assumptions."

### 11.3 Leases

Leases fence exclusive or quorum-sensitive work:

```rust
pub struct Lease {
    pub header: ObjectHeader,
    pub subject_object_id: ObjectId,
    pub purpose: LeasePurpose,
    pub lease_seq: u64,
    pub owner_node: NodeId,
    pub expires_at: u64,
    pub coordinator: NodeId,
    pub quorum_signatures: Vec<(NodeId, Signature)>,
}

pub enum LeasePurpose {
    OperationExecution,
    ConnectorStateWrite,
    ComputationMigration,
}
```

Normative rules:

1. Singleton-writer state updates MUST cite the current lease.
2. Risky and dangerous side effects MAY require an execution lease.
3. Higher `lease_seq` fences lower ones; stale lease holders MUST be rejected even if their wall-clock expiry has not yet elapsed.
4. Conflicting leases MUST surface as incidents, not silently resolve.

### 11.3.1 Distributed Lease Issuance

Lease issuance SHOULD use deterministic coordinator selection so that any peer can explain why a given
coordinator had authority to assemble or witness the lease.

```rust
pub struct LeaseRequest {
    pub header: ObjectHeader,
    pub subject_object_id: ObjectId,
    pub purpose: LeasePurpose,
    pub desired_owner: NodeId,
    pub requested_at: u64,
    pub expires_at: u64,
    pub signature: Signature,
}
```

Recommended coordinator selection:

- rendezvous or HRW hashing over `zone_id || subject_object_id`,
- constrained to currently eligible coordinators for the relevant zone and purpose,
- stable within a checkpoint epoch unless the coordinator is unavailable or revoked.

Quorum guidance:

- safe operations MAY accept single-coordinator leases,
- risky operations SHOULD require `f + 1` witnesses where a Byzantine model is claimed,
- dangerous operations SHOULD require stronger quorum matching the zone's configured critical-write policy.

### 11.3.2 Lease Conflict Handling

Conflicting leases are not normal retries. They are evidence-worthy coordination faults.

Normative rules:

1. If two overlapping valid leases are observed for the same subject and purpose, dangerous execution MUST halt until resolved.
2. Risky execution MAY resolve according to explicit policy only if the conflict can be fenced deterministically and surfaced to operators.
3. Conflict detection MUST emit structured evidence identifying all competing lease objects and the coordinator or quorum that produced them.

### 11.4 Checkpoint, Failover, and Resume

Long-lived or stateful work SHOULD support checkpoint and resume:

```rust
pub struct ComputationCheckpoint {
    pub header: ObjectHeader,
    pub request_object_id: ObjectId,
    pub connector_id: ConnectorId,
    pub state_object_id: Option<ObjectId>,
    pub receipt_head: Option<ObjectId>,
    pub progress: CheckpointProgress,
    pub signature: Signature,
}
```

Resume safety requires:

1. current lease validation,
2. checkpoint freshness validation,
3. receipt consistency validation,
4. replay protection against already-committed side effects.

If a prior `OperationReceipt` exists with a committed disposition and matching strong idempotency key,
resume MUST attach to that committed result rather than replay the external side effect.

### 11.4.1 Migration Protocol

Migration of resumable computation SHOULD proceed as:

1. checkpoint current state,
2. persist or distribute checkpoint artifact,
3. transfer or reacquire execution lease on target node,
4. verify receipt consistency and replay boundaries,
5. resume under a fresh but compatible execution context,
6. emit audit and evidence artifacts linking old and new execution sites.

### 11.5 Offline and Repair Behavior

Implementations SHOULD support:

- predictive pre-staging of required objects,
- mirrored connector binaries and manifests,
- background repair of object coverage,
- checkpoint-aware resumption after disconnection,
- eventual audit and revocation convergence.

Repair is not cosmetic. It is part of the availability contract.

#### 11.5.1 Offline Capability

Implementations SHOULD be able to evaluate whether a node can reconstruct a required object set from
locally available chunks or symbols. This evaluation SHOULD be surfaced to operator tooling.

#### 11.5.2 Background Repair Controller

```rust
pub struct RepairController {
    pub interval_ms: u64,
    pub max_repairs_per_cycle: u32,
}

pub struct CoverageEvaluation {
    pub object_id: ObjectId,
    pub distinct_nodes: usize,
    pub max_node_fraction_bps: u16,
    pub coverage_bps: u32,
    pub is_available: bool,
}
```

Nodes SHOULD evaluate placement-policy objects periodically and initiate targeted repair or rebalance
when coverage falls below policy.

#### 11.5.3 Predictive Pre-Staging

Implementations SHOULD support predictive pre-staging of:

- connector binaries or modules,
- manifests and attestation chains,
- likely-needed checkpoints,
- large referenced inputs,
- secret shares or wrapped key material where policy permits local preparation.

Pre-staging MUST remain policy-constrained. It MUST NOT materialize secrets or durable artifacts on
nodes that are not eligible for the relevant zone or execution policy.

#### 11.5.4 Distributed State Mechanics

Coverage and repair decisions MUST be made against a concrete distributed-state view rather than raw
byte counts or a single optimistic availability bit.

```rust
pub struct DistributedState {
    pub object_id: ObjectId,
    pub k: u32,
    pub unique_symbols: u32,
    pub node_symbols: HashMap<NodeId, BTreeSet<u32>>,
    pub coverage_bps: u32,
    pub distinct_nodes: u16,
    pub max_node_fraction_bps: u16,
    pub is_available: bool,
    pub repair_consequence: RepairConsequence,
}

pub enum RepairConsequence {
    None,
    RebalanceRecommended,
    RepairRequired,
    PlacementViolation,
    EmergencyUnavailable,
}
```

Normative rules:

1. `coverage_bps` MUST be computed as:

```text
min(unique_symbols, k) * 10000 / k
```

2. `is_available` MUST be true only if:
   - `coverage_bps >= 10000`, and
   - any required checkpoint or policy metadata needed to use the object is also available.
3. `max_node_fraction_bps` MUST be computed from the largest single-node contribution divided by the
   total distinct accepted symbols contributing to the current view.
4. An object MAY be available while still violating placement policy because concentration or source
   diversity is too poor. This MUST map to `RebalanceRecommended` or `PlacementViolation`, not to a
   false claim of health.
5. If `coverage_bps < 10000`, the result MUST be either `RepairRequired` or `EmergencyUnavailable`
   depending on whether policy-eligible repair sources remain.

Representative outcomes:

| `coverage_bps` | `max_node_fraction_bps` | Interpretation | Consequence |
|----------------|-------------------------|----------------|-------------|
| `9500` | `7000` | not reconstructable | `RepairRequired` |
| `12000` | `9200` | reconstructable but dangerously concentrated | `RebalanceRecommended` |
| `16000` | `4200` | reconstructable and well distributed | `None` |
| `10000` | `10000` after peer revocation | technically reconstructable on one node only | `PlacementViolation` |

### 11.6 Tailscale Integration

Tailscale is the reference substrate for:

- node identity,
- authenticated peer discovery,
- ACL-enforced reachability,
- direct-path vs relay-path distinction,
- local API integration for device and peer status,
- deterministic placement input.

#### 11.6.1 Tailscale Client

```rust
pub struct TailscaleClient {
    pub socket_path: String,
}

impl TailscaleClient {
    pub async fn status(&self) -> Result<TailscaleStatus, TailscaleError> { todo!() }
    pub async fn peers(&self) -> Result<Vec<TailscalePeer>, TailscaleError> { todo!() }
    pub async fn whois(&self, ip: IpAddr) -> Result<NodeIdentity, TailscaleError> { todo!() }
}
```

#### 11.6.1.1 Status Model and Path Classification

Placement and routing surfaces SHOULD distinguish at least:

- direct path,
- direct path via NAT traversal,
- relay/DERP path,
- disconnected or unknown status.

The client surface SHOULD provide enough information for:

- latency-aware placement,
- degraded-mode explanation,
- repair prioritization,
- source-diversity evaluation.

#### 11.6.2 Symbol Routing

```rust
pub struct TailscaleSymbolRouter {
    pub peers: Vec<NodeId>,
}

impl TailscaleSymbolRouter {
    pub async fn distribute(
        &self,
        object_id: ObjectId,
        symbols: Vec<EncodedSymbol>,
        zone: &ZoneId,
    ) -> Result<SymbolDistribution, RoutingError> {
        todo!()
    }
}
```

Routing implementations SHOULD prefer direct paths, respect zone eligibility, and track repair or
rebalancing decisions as auditable events where they affect availability policy.

#### 11.6.2.1 Routing Heuristics and Source Selection

Recommended routing order:

1. direct eligible peers with low latency,
2. local node when sufficient for current durability policy,
3. multiple direct peers to improve diversity,
4. relay paths only when direct paths are unavailable or policy permits degraded mode.

Routing SHOULD account for:

- current coverage deficit,
- zone eligibility,
- peer health,
- whether a peer already holds too large a fraction of the object's symbols.

#### 11.6.3 Device Enrollment and Removal

```rust
pub struct DeviceEnrollment {
    pub header: ObjectHeader,
    pub node_id: NodeId,
    pub node_sig_pubkey: PublicKey,
    pub allowed_zones: Vec<ZoneId>,
    pub storage_permissions: Vec<StoragePermission>,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
    pub signature: Signature,
}

pub enum StoragePermission {
    StoreSymbols { zones: Vec<ZoneId> },
    StoreSecretShares,
    StoreAuditEvents,
}
```

Removal of a device SHOULD trigger:

1. revocation of enrollment and attestation artifacts,
2. issuer-key revocation where relevant,
3. zone-key rotation for affected zones,
4. secret resharing excluding the removed device.

#### 11.6.3.1 Enrollment and Removal Workflow

Recommended enrollment flow:

1. device joins the tailnet,
2. owner issues `DeviceEnrollment`,
3. owner issues or refreshes `NodeKeyAttestation`,
4. device receives zone and key material allowed by policy,
5. peers accept the device only after both enrollment and attestation verify.

Recommended removal flow:

1. revoke enrollment,
2. revoke node attestation or issuer keys where relevant,
3. rotate affected zone keys,
4. re-share threshold secrets excluding the removed device,
5. refresh checkpoints so the removal becomes part of the enforceable frontier.

#### 11.6.4 Funnel Gateway

If public ingress is required, Tailscale Funnel or equivalent public gateway support MUST be
restricted by zone policy.

```rust
pub struct FunnelPolicy {
    pub allowed_zones: Vec<ZoneId>,
    pub blocked_zones: Vec<ZoneId>,
    pub rate_limit_per_minute: u32,
}
```

Normative rules:

1. `z:owner` and similarly high-confidentiality zones SHOULD default to funnel denial.
2. Public ingress MUST increase taint or trust sensitivity of the resulting inputs unless stronger provenance evidence is attached.
3. Funnel-backed connectors SHOULD surface public-ingress state in explain and operator health output.

#### 11.6.5 Mesh Gossip and Discovery

The mesh SHOULD support bounded anti-entropy for object and symbol discovery.

```rust
pub struct GossipSummary {
    pub from: NodeId,
    pub epoch_id: EpochId,
    pub object_filter_digest: [u8; 32],
    pub symbol_filter_digest: [u8; 32],
    pub iblt: Vec<u8>,
    pub timestamp: u64,
    pub signature: Signature,
}
```

Recommended design characteristics:

- fast approximate membership filters for discovery,
- precise reconciliation structures for reducing redundant repair,
- signed summaries so gossip participates in attribution and peer budgeting,
- bounded per-peer reconciliation cost.

#### 11.6.5.2 Approximate Membership and Reconciliation Structures

Implementations MAY choose different concrete data structures, but the intended roles are:

- one compact summary for "might have object",
- one compact summary for "might have symbol or chunk",
- one reconciliation structure for precise delta exchange when peers disagree.

Representative shapes:

```rust
pub struct ObjectFilterSummary {
    pub digest: [u8; 32],
    pub approx_entries: u32,
}

pub struct SymbolFilterSummary {
    pub digest: [u8; 32],
    pub approx_entries: u32,
}

pub struct ReconciliationDelta {
    pub encoded: Vec<u8>,
    pub object_count_hint: u32,
    pub symbol_count_hint: u32,
}
```

Normative guidance:

1. summaries MUST be bounded,
2. precise reconciliation work MUST remain budgeted,
3. a peer claiming possible possession is not yet proof of usable availability.

#### 11.6.5.1 Peer State and Anti-Entropy

Implementations SHOULD maintain explicit peer state for repair and discovery:

```rust
pub struct PeerGossipState {
    pub peer_id: NodeId,
    pub last_summary_at: u64,
    pub object_filter_digest: [u8; 32],
    pub symbol_filter_digest: [u8; 32],
    pub estimated_latency_ms: Option<u32>,
    pub direct_path: bool,
    pub health: String,
}
```

Recommended behavior:

1. anti-entropy cycles SHOULD be bounded and incremental,
2. peers with stale summaries SHOULD be deprioritized for critical repair decisions,
3. reconciliation work SHOULD count against peer budgets,
4. repair decisions SHOULD distinguish "peer claims object presence" from "peer proved usable coverage."

#### 11.6.6 Distributed State and Coverage

Object availability SHOULD be evaluated as a coverage property, not only as presence on one node.

```rust
pub struct DistributedState {
    pub object_id: ObjectId,
    pub coverage_bps: u32,
    pub distinct_nodes: u16,
    pub max_node_fraction_bps: u16,
    pub is_available: bool,
}
```

Coverage reasoning SHOULD inform:

- repair priority,
- planner scoring,
- degraded-mode decisions,
- offline-availability claims.

#### 11.6.6.1 Coverage SLOs and Repair Triggers

Coverage evaluation SHOULD feed explicit service objectives:

- minimum distinct-node count,
- maximum single-node concentration,
- minimum reconstructable coverage,
- target redundancy for pinned or critical artifacts.

Repair SHOULD trigger when:

1. the object is no longer reconstructable,
2. concentration exceeds policy,
3. diversity falls below zone or object requirements,
4. offline-availability promises would be violated without intervention.

### 11.6.7 MeshNode Model

The combined host-plus-mesh implementation SHOULD maintain a concrete conceptual `MeshNode` surface
even if the runtime is split across crates or services.

```rust
pub struct FrontierRef {
    pub object_id: ObjectId,
    pub seq: u64,
    pub observed_at: u64,
}

pub struct MeshNode {
    pub identity: MeshIdentity,
    pub trust_anchors: TrustAnchors,
    pub zone_keyrings: HashMap<ZoneId, ZoneKeyRing>,
    pub checkpoint_frontier: HashMap<ZoneId, FrontierRef>,
    pub revocation_frontier: HashMap<ZoneId, FrontierRef>,
    pub audit_frontier: HashMap<ZoneId, FrontierRef>,
    pub object_store: ObjectStore,
    pub symbol_store: SymbolStore,
    pub gossip: MeshGossip,
    pub lease_coordinator: LeaseCoordinator,
    pub planner: PlacementPlanner,
    pub connector_supervisor: ConnectorSupervisor,
}
```

Normative responsibilities of the conceptual `MeshNode`:

1. Own the locally enforced trust anchors, zone keyrings, and frontier state for the zones it is
   eligible to serve.
2. Verify every token, holder proof, attestation, checkpoint, revocation head, and delegated invoke
   before local execution or further delegation.
3. Admit objects and symbols only through bounded, authenticated, policy-aware paths.
4. Maintain the node-local storage and repair view used to satisfy placement and offline-availability
   promises.
5. Execute locally only under an explicit narrowed context; delegated requests MUST be re-verified by
   the recipient node and MUST NOT inherit ambient trust from the sender.

### 11.6.8 Gossip and Anti-Entropy Mechanics

Gossip is a bounded anti-entropy protocol, not a blind rebroadcast fabric.

```rust
pub struct PeerSummary {
    pub from: NodeId,
    pub as_of_epoch: EpochId,
    pub checkpoint_heads: HashMap<ZoneId, u64>,
    pub audit_heads: HashMap<ZoneId, u64>,
    pub revocation_heads: HashMap<ZoneId, u64>,
    pub object_filter_digest: [u8; 32],
    pub symbol_filter_digest: [u8; 32],
    pub iblt: Vec<u8>,
    pub coverage_digest: [u8; 32],
    pub signature: Signature,
}

pub enum PeerLiveness {
    Unknown,
    Warm,
    Healthy,
    Suspect,
    Quarantined,
}
```

Normative anti-entropy procedure:

1. Peers MUST exchange signed summaries containing frontier sequences before requesting bulk object or
   symbol repair.
2. If frontier sequences differ, nodes MUST reconcile in this order:
   - checkpoint heads,
   - revocation heads,
   - audit heads,
   - referenced policy objects,
   - ordinary objects and symbol gaps.
3. XOR-filter or IBLT output is only a hint. It MUST NOT override signed frontier objects.
4. Peer state MUST degrade from `Healthy` to `Suspect` or `Quarantined` if summaries are invalid,
   inconsistent, or budget-abusive.
5. Reconciliation work MUST be charged against peer budgets and MUST be interruptible.

Convergence expectations:

1. Under eventual authenticated connectivity among honest nodes, accepted frontier sequences SHOULD
   converge before full symbol coverage converges.
2. A node MUST prefer frontier convergence over aggressive payload repair when budgets are tight.
3. Nodes SHOULD back off from peers that repeatedly advertise stale or conflicting summaries until a
   newer signed summary appears.

### 11.6.9 MeshNode Responsibilities

Representative responsibilities:

- verify incoming token, attestation, and revocation evidence,
- evaluate provenance and approval requirements,
- select or confirm execution target,
- coordinate lease acquisition and renewal,
- manage object admission, repair, and checkpoint interaction,
- delegate to local or remote connector execution,
- emit receipts, audit events, and operator-facing evidence,
- surface degraded-mode, fork, and concentration problems to operator tooling.

### 11.6.10 MeshNode Request Flow

The following conceptual flow captures the intended order of mesh-side enforcement:

```text
1. verify token, holder proof, and caller binding
2. verify revocation frontier and checkpoint frontier freshness
3. evaluate provenance, taint, resource-sink classification, and approval requirements
4. acquire or validate lease if required
5. run placement logic or confirm current placement
6. emit required pre-effect decision evidence for risky or dangerous work
7. execute locally or delegate to chosen node
8. persist operation receipt, checkpoint movement, and terminal audit evidence
```

This order matters because:

- expensive provider-side work should not happen before token, freshness, and approval checks,
- placement should not occur before we know the action is actually authorized,
- pre-effect evidence must exist before irreversible external effects,
- receipts and audit artifacts should close the loop immediately after execution.

### 11.7 Threat Model, Diversity, and Degraded Operation

Implementations MUST assume the following are possible:

- compromised device,
- malicious peer,
- replay attack,
- symbol injection,
- stale checkpoint or revocation state,
- DNS or egress policy bypass attempt,
- operator-visible service degradation caused by partitions or relay-only reachability.

Where source diversity or quorum-sensitive behavior is claimed, the implementation SHOULD expose
policy objects describing minimum diversity and acceptable degraded modes.

```rust
pub struct DiversityPolicy {
    pub min_nodes: u8,
    pub min_zones: u8,
    pub max_node_fraction_bps: u16,
}
```

Dangerous operations SHOULD refuse to proceed in degraded mode unless explicit policy allows it.

### 11.7.3 Byzantine and Quorum Guidance

Deployments claiming stronger distributed guarantees SHOULD document an explicit Byzantine model.

```rust
pub struct ByzantineModel {
    pub n: u8,
    pub f: u8,
}

pub enum OperationClass {
    ReadOnly,
    NormalWrite,
    CriticalWrite,
    Unanimous,
}
```

Recommended guidance:

1. `ReadOnly` operations MAY rely on single-node execution with ordinary freshness checks.
2. `NormalWrite` operations SHOULD use the weakest quorum consistent with availability and safety goals.
3. `CriticalWrite` and similar dangerous operations SHOULD use stronger quorum and lease-witness policy.
4. If a deployment cannot justify a Byzantine model, it SHOULD avoid making claims that depend on one.

### 11.7.4 Source Diversity Enforcement

Source diversity claims SHOULD be enforced mechanically where they matter for correctness or trust.

Recommended enforcement points:

1. checkpoint acceptance for highly sensitive zones,
2. repair completion for objects with explicit diversity policy,
3. dangerous execution that depends on multi-node evidence or quorum-backed lease issuance,
4. mirror promotion when artifacts are expected to be retained across multiple failure domains.

If source diversity is not presently satisfiable, the operator surface SHOULD explain whether the
system is still safe, merely degraded, or fully blocked for the attempted action.

### 11.7.1 Admission Control and DoS Resistance

Meshes MUST protect themselves against:

- symbol floods,
- bogus object identifiers,
- expensive decode requests,
- gossip reconciliation abuse,
- replay storms during partition healing,
- public-ingress amplification through low-trust zones.

Every implementation MUST define:

- per-peer rate limits,
- per-zone quarantine limits,
- decode-work budgets,
- repair-work budgets,
- bounded reconciliation state.

#### 11.7.1.1 Peer Budgets and Anti-Amplification

Representative peer budget model:

```rust
pub struct PeerBudget {
    pub max_bytes_per_min: u64,
    pub max_symbols_per_min: u32,
    pub max_failed_auth_per_min: u32,
    pub max_inflight_decodes: u32,
    pub max_decode_cpu_ms_per_min: u64,
}
```

Anti-amplification guidance:

1. responses to repair or symbol requests MUST be explicitly bounded,
2. unauthenticated or low-trust requesters SHOULD have much smaller caps,
3. replay or auth failure storms SHOULD quickly exhaust the offender's budget rather than the node's.

### 11.7.2 Unreferenced Object Quarantine

Unreferenced or unprovenanced objects MUST enter a bounded quarantine store before they are admitted
into normal gossip or retention classes.

```rust
pub enum ObjectAdmissionClass {
    Quarantined,
    Admitted,
}

pub struct ObjectAdmissionPolicy {
    pub max_quarantine_bytes_per_zone: u64,
    pub max_quarantine_objects_per_zone: u32,
    pub quarantine_ttl_secs: u64,
    pub require_schema_validation: bool,
}
```

Normative rules:

1. Quarantined objects MUST NOT be inserted into primary gossip summaries.
2. Promotion from quarantine MUST require either checkpoint reachability, authenticated explicit request, or local policy pinning.
3. Promotion SHOULD include schema validation before the object becomes visible for ordinary repair or placement reasoning.
4. Eviction order SHOULD prefer removing oldest, lowest-reputation, or largest quarantined objects first.

#### 11.7.2.1 Promotion and Eviction Procedure

Recommended promotion procedure:

1. reconstruct enough of the object to validate schema and header,
2. determine whether it is reachable from the current checkpoint frontier or explicitly requested,
3. verify any required signatures or object references,
4. move the object from quarantine to admitted storage,
5. only then allow it to influence gossip, repair, or placement.

Recommended eviction order when pressure is high:

1. oldest quarantined objects,
2. largest quarantined objects,
3. objects sourced from low-reputation or repeatedly failing peers.

### 11.8 Threshold Secret Use and Reconstruction Cost

Placement and execution planning SHOULD consider the cost of reconstructing threshold-protected
secret material:

- local shares already present,
- number of peers required,
- latency to those peers,
- whether policy allows proxy-only reconstruction instead of exposing reconstructed bytes to the connector.

## 12. Registry and Supply Chain

### 12.1 Registry Sources

Registries are sources, not dependencies:

```rust
pub enum RegistrySource {
    RemoteHttp { url: String, trusted_keys: Vec<PublicKey>, threshold: u8 },
    SelfHosted { url: String, trusted_keys: Vec<PublicKey>, threshold: u8 },
    MeshMirror { zone_id: ZoneId, index_object_id: ObjectId },
}
```

### 12.1.1 Registry Index and Mirror Objects

Registry and mirror sources SHOULD expose index objects so that the mesh can pin and compare the exact
artifact sets it trusts.

```rust
pub struct RegistryIndexObject {
    pub header: ObjectHeader,
    pub source_name: String,
    pub connectors: Vec<RegistryConnectorEntry>,
    pub generated_at: u64,
    pub signature: Signature,
}

pub struct RegistryConnectorEntry {
    pub connector_id: ConnectorId,
    pub version: String,
    pub manifest_object_id: ObjectId,
    pub artifact_object_id: ObjectId,
    pub attestation_object_ids: Vec<ObjectId>,
}
```

### 12.1.2 Source Selection, Pinning, and Promotion

Source selection SHOULD be policy-driven rather than first-success-wins.

Recommended order:

1. pinned local or sovereign mirror source,
2. trusted direct mirror on the mesh,
3. remote or self-hosted registry if policy allows and freshness checks pass.

Normative guidance:

1. once an artifact is pinned for a zone or deployment, subsequent activation SHOULD prefer the pinned source unless an explicit update policy says otherwise,
2. promotion from remote source to mirror SHOULD retain the exact manifest, digest, and attestation references used for verification,
3. operator surfaces SHOULD be able to explain why one source was preferred over another.

### 12.1.3 Install and Update Fetch Flow

A typical verified install or update flow SHOULD look like:

1. choose source according to pinning and sovereignty policy,
2. fetch source index or manifest,
3. verify signatures and freshness,
4. fetch artifact and attestation set,
5. verify artifact digest, interface hash, and execution-form compatibility,
6. optionally promote to mirror,
7. activate or stage for rollout.

Install and update flows SHOULD retain enough evidence that an operator can later answer:

- which source was used,
- which exact artifact and manifest were accepted,
- why a newer or different candidate was rejected,
- whether the accepted artifact was mirrored afterward.

### 12.2 Verification Chain

Before activation, a host MUST verify:

1. manifest integrity and signature threshold,
2. interface hash consistency,
3. binary or module digest,
4. execution-form compatibility,
5. manifest capability requests against zone ceilings,
6. transparency log requirements,
7. required attestation types,
8. builder/publisher trust policy,
9. revocation state for relevant keys or artifacts.

### 12.2.2 Verification Order and Failure Handling

Verification SHOULD proceed in a fail-closed order that maximizes safety and explainability:

1. fetch and authenticate index or manifest source,
2. verify manifest signatures and format,
3. verify digest and interface identity,
4. verify artifact execution-form compatibility,
5. verify attestations and transparency requirements,
6. verify revocation state and freshness,
7. evaluate zone and supply-chain policy compatibility.

Failures MUST produce stable reason codes and SHOULD identify the first failing stage plus any
additional dependent stages skipped because the prior stage failed.

### 12.2.3 Attestation Evaluation and Builder Trust

Attestations SHOULD be evaluated as a typed set rather than opaque attachments.

Recommended checks:

1. subject artifact matches the manifest or binary under verification,
2. attestation signature chains to a trusted builder or attestor,
3. required attestation types are all present,
4. builder identity matches policy,
5. optional vulnerability or review claims satisfy configured thresholds.

If multiple attestations of the same type are present, the verifier SHOULD define whether policy
requires all of them to pass or only a quorum or best-match subset.

### 12.2.4 Transparency, Freeze, and Rollback Detection

Supply-chain verification SHOULD explicitly defend against:

- freeze attacks serving stale metadata,
- rollback attacks serving older signed artifacts,
- equivocation attacks serving different artifacts to different nodes.

Recommended mitigations:

1. metadata freshness limits,
2. append-only transparency or mirror history,
3. explicit comparison against already pinned or installed versions,
4. evidence emission whenever a lower or different version is proposed than the one currently trusted.

### 12.2.1 Registry Security Profile

```rust
pub struct RegistrySecurityProfile {
    pub tuf_root_object_id: Option<ObjectId>,
    pub tuf_required: bool,
    pub signature_threshold: u8,
    pub max_metadata_age_secs: u64,
    pub require_sigstore: bool,
}
```

Freshness enforcement is mandatory for remote registries to resist freeze and rollback attacks.

### 12.3 Attestations

Supported attestation categories include:

- in-toto provenance,
- reproducible build attestation,
- SBOM,
- vulnerability scan,
- code review attestation,
- owner-local policy attestations.

Policy MAY require any subset of these.

### 12.3.1 Transparency Log Entries

```rust
pub struct ConnectorTransparencyLogEntry {
    pub header: ObjectHeader,
    pub connector_id: ConnectorId,
    pub version: String,
    pub manifest_object_id: ObjectId,
    pub binary_object_id: ObjectId,
    pub prev: Option<ObjectId>,
    pub published_at: u64,
    pub signature: Signature,
}
```

Transparency logs help detect downgrade and equivocation attacks.

### 12.3.2 Supply-Chain Policy Object

```rust
pub struct SupplyChainPolicy {
    pub require_transparency_log: bool,
    pub require_attestation_types: Vec<String>,
    pub min_slsa_level: u8,
    pub require_sbom: bool,
    pub max_allowed_vuln_severity: Option<String>,
    pub trusted_builders: Vec<String>,
    pub trusted_publishers: Vec<[u8; 32]>,
}
```

This policy MAY be global, per-zone, or per-connector family.

### 12.4 Mirroring and Sovereignty

Meshes SHOULD be able to mirror manifests, binaries, modules, and attestations as durable objects.
Offline installation and failover MUST NOT depend on continued upstream availability once artifacts
have been mirrored and policy-pinned.

### 12.4.1 Mirror Indexes and Sovereignty Policy

Meshes operating under sovereignty or offline-first requirements SHOULD maintain their own signed
mirror indexes:

```rust
pub struct MirrorIndexObject {
    pub header: ObjectHeader,
    pub zone_id: ZoneId,
    pub upstream_sources: Vec<String>,
    pub mirrored_entries: Vec<RegistryConnectorEntry>,
    pub published_at: u64,
    pub signature: Signature,
}
```

Normative rules:

1. A mirror MUST preserve enough metadata to re-run verification without consulting the upstream source.
2. Mirror policy MAY restrict which builders, publishers, or attestation classes are admitted into a sovereign mirror.
3. Offline activation MUST rely only on already mirrored and policy-pinned objects.

### 12.4.2 Offline Installation and Mirror Promotion

Offline installation SHOULD be a first-class outcome of successful mirroring, not a degraded accident.

Recommended flow:

1. verify the upstream or source artifact once,
2. mirror manifest, artifact, attestations, and transparency references as durable objects,
3. publish or update a mirror index,
4. pin the chosen version according to zone or deployment policy,
5. install from the mirror without depending on upstream availability.

Mirror promotion SHOULD be auditable and SHOULD emit evidence identifying:

- original source,
- verified manifest and artifact ids,
- attestation set accepted,
- policy version used for promotion.

### 12.4.3 Mirror Retention and Garbage-Collection Expectations

Mirrors SHOULD distinguish:

- pinned artifacts required for current operation,
- rollback candidates retained for safety,
- stale superseded artifacts eligible for ordinary garbage collection.

Mirror GC MUST NOT discard:

1. active pinned versions,
2. explicitly retained rollback targets,
3. artifacts still referenced by evidence bundles or conformance fixtures under retention policy.

## 13. Observability, Explainability, and Errors

### 13.1 Metrics

Implementations MUST expose, at minimum:

- invocation counts and error rates,
- p50 / p95 / p99 latency,
- restart counts and crash-loop indicators,
- stream credit utilization and lag,
- lease acquisition and conflict counts,
- checkpoint and resume counts,
- revocation freshness lag,
- repair activity,
- egress allow/deny counts,
- zone and capability denial counts.

Layer-specific metrics SHOULD additionally include:

- FCPC frame receive/send totals,
- FCPC replay-drop totals,
- FCPS symbol decode failures,
- checkpoint accept/reject counts,
- stream replay counts,
- intent-without-receipt recovery counts.

#### 13.1.1 Required Metric Families

Implementations SHOULD expose metrics in families rather than ad hoc counters so operators can compare
behavior across connectors and hosts.

Recommended minimum families:

| Family | Representative Metrics |
|--------|-------------------------|
| `fcpc_*` | `fcpc_frames_rx_total`, `fcpc_frames_tx_total`, `fcpc_replay_drop_total`, `fcpc_backpressure_wait_ms_total` |
| `fcps_*` | `fcps_datagrams_rx_total`, `fcps_mac_fail_total`, `fcps_decode_fail_total`, `fcps_quarantine_drop_total` |
| `lease_*` | `lease_acquire_total`, `lease_conflict_total`, `lease_stale_reject_total` |
| `checkpoint_*` | `checkpoint_written_total`, `checkpoint_resume_accept_total`, `checkpoint_resume_reject_total` |
| `placement_*` | `placement_decision_total`, `placement_degraded_total`, `placement_denied_total` |
| `repair_*` | `repair_cycle_total`, `repair_objects_total`, `repair_rebalance_total` |
| `secret_*` | `secret_access_total`, `secret_reconstruct_total`, `secret_access_deny_total` |

### 13.2 Structured Logs

Structured logs MUST:

- be machine-parseable,
- carry stable identifiers (`zone_id`, `connector_id`, `request_object_id`, `jti`, `trace_id`),
- use stable reason codes,
- avoid logging secrets or decrypted sensitive payloads by default,
- support a diagnostic mode with stronger detail and explicit redaction.

### 13.2.1 Log Event Shape

Structured logs SHOULD use a stable event shape so that automated tooling can correlate logs, receipts,
and transcripts without connector-specific parsers.

```rust
pub struct LogEvent {
    pub ts: u64,
    pub level: String,
    pub component: String,
    pub event_type: String,
    pub zone_id: Option<ZoneId>,
    pub connector_id: Option<ConnectorId>,
    pub request_object_id: Option<ObjectId>,
    pub trace_id: Option<[u8; 16]>,
    pub reason_code: Option<String>,
    pub fields: Vec<(String, String)>,
}
```

Required characteristics:

1. logs MUST be machine-parseable,
2. correlation identifiers MUST be stable across a request lifetime,
3. redaction state SHOULD be explicit when sensitive fields are omitted or transformed,
4. operator tooling SHOULD be able to pivot from a log event to a receipt or evidence bundle.

### 13.3 Explainability

The operator surface MUST be able to answer:

- why an action was denied,
- why a connector was placed on a given node,
- why a connector restarted or drained,
- why a checkpoint was accepted or rejected,
- why a stream stalled or was cancelled.

Preferred evidence order:

1. DecisionReceipt,
2. OperationReceipt,
3. audit chain references,
4. structured logs and traces,
5. replay transcript or evidence bundle when available.

### 13.3.1 Explain Response Structure

`explain` and `doctor` surfaces SHOULD return structured responses rather than plain-text only:

```rust
pub struct ExplainResponse {
    pub request_object_id: ObjectId,
    pub decision: Option<ObjectId>,
    pub summary: String,
    pub reason_code: Option<String>,
    pub degraded_mode: bool,
    pub evidence: Vec<ObjectId>,
    pub suggested_next_actions: Vec<String>,
}
```

Operator-facing prose is valuable, but it MUST be derived from structured reason and evidence objects
so that the same outcome remains machine-actionable.

### 13.4 Stable Error Taxonomy

The error taxonomy MUST distinguish at least:

- protocol / framing,
- identity / attestation,
- capability / policy,
- zone / provenance,
- lifecycle / drain / quiescence,
- lease / checkpoint / resume,
- external service,
- supply chain,
- internal runtime.

Error payloads SHOULD include:

```rust
pub struct FcpError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
    pub retry_after_ms: Option<u64>,
    pub details: Option<Vec<u8>>,
    pub reason_code: Option<String>,
    pub evidence: Vec<ObjectId>,
}
```

#### 13.4.1 Stable Reason Codes

Implementations MUST use stable reason codes suitable for alerting and replay analysis. Recommended
baseline codes include:

| Code | Description |
|------|-------------|
| `FCP_ERR_UNSUPPORTED_VERSION` | Unsupported frame or protocol version |
| `FCP_ERR_BAD_FLAGS` | Invalid framing flags |
| `FCP_ERR_REPLAY` | Replay detected |
| `FCP_ERR_TOKEN_EXPIRED` | Token expired |
| `FCP_ERR_TOKEN_SIG_INVALID` | Token signature invalid |
| `FCP_ERR_CAPABILITY_DENIED` | Capability missing or insufficient |
| `FCP_ERR_EGRESS_DENIED` | Network policy denied egress |
| `FCP_ERR_EGRESS_TIMEOUT` | Egress timed out |
| `FCP_ERR_CHECKPOINT_STALE` | Checkpoint too old or inconsistent |
| `FCP_ERR_LEASE_STALE` | Lease sequence stale |
| `FCP_ERR_ZONE_POLICY_VIOLATION` | Zone policy violation |
| `FCP_ERR_SUPPLY_CHAIN_POLICY` | Supply-chain policy rejection |

#### 13.4.2 Error Code Ranges

Implementations SHOULD reserve stable numeric or lexical ranges for broad error domains:

| Range | Domain |
|-------|--------|
| `FCP-1000..1999` | protocol and framing |
| `FCP-2000..2999` | identity and attestation |
| `FCP-3000..3999` | capability and policy |
| `FCP-4000..4999` | zone, provenance, and taint |
| `FCP-5000..5999` | lifecycle, drain, quiescence, and health |
| `FCP-6000..6999` | leases, checkpoints, migration, and resume |
| `FCP-7000..7999` | external service and provider failures |
| `FCP-8000..8999` | supply chain and artifact verification |
| `FCP-9000..9999` | internal runtime |

#### 13.4.3 Error Response Contract

Error responses SHOULD be structured for both humans and automation.

Recommended response fields:

- stable code,
- stable reason code,
- retryability,
- retry delay if applicable,
- evidence object identifiers,
- short human summary,
- optional machine-readable recovery hints.

The recovery hint MUST NOT encourage bypassing security checks. It SHOULD point toward legitimate
remediation such as refreshing revocation state, acquiring approval, or fixing manifest incompatibility.

### 13.5 Evidence Bundles

Implementations SHOULD support evidence bundles for postmortem and replay:

```rust
pub struct EvidenceBundle {
    pub request_object_id: ObjectId,
    pub trace: TraceContext,
    pub decision_receipt: Option<ObjectId>,
    pub operation_receipt: Option<ObjectId>,
    pub audit_events: Vec<ObjectId>,
    pub checkpoint: Option<ObjectId>,
    pub transcript_objects: Vec<ObjectId>,
}
```

Evidence bundles are the preferred artifact for debugging, conformance review, and operator trust.

### 13.5.1 Evidence Retention and Replay

Evidence bundles SHOULD preserve enough material to:

- reconstruct why a decision was made,
- prove which connector artifact and policy heads were in force,
- replay transport transcripts where policy allows,
- compare pre- and post-failover behavior,
- satisfy conformance review for difficult bug classes.

High-risk bundles SHOULD be retained longer than ordinary success bundles, subject to zone policy.

### 13.6 Audit Chain Requirements

Section 6.3 defines the audit object model. This section defines the minimum operator-visible and
conformance-visible contract around that model.

Audit surfaces MUST expose, per zone:

- current `audit_head` object id and `head_seq`,
- `AuditHead.status`,
- `coverage_bps`,
- quorum required vs achieved,
- last observed degraded-mode transition,
- whether an unresolved fork is present.

Audit chains MUST capture at minimum:

- secret access,
- high-risk capability use,
- approvals and declassifications,
- zone crossings,
- checkpoint acceptance and rejection,
- lease conflicts,
- revocation degraded-mode entry and recovery,
- supply-chain policy failures,
- repair or rebalance operations that materially affect availability policy.

Standard event-type prefixes SHOULD be used for interoperability and operator familiarity:

- `decision.*`
- `execution.*`
- `secret.*`
- `approval.*`
- `zone.*`
- `lease.*`
- `checkpoint.*`
- `revocation.*`
- `artifact.*`
- `repair.*`
- `incident.*`

For zones using quorum-backed audit heads, implementations MUST refuse to advance the head when
required quorum is absent unless explicit degraded-mode policy says otherwise.

If the head is advanced in degraded mode, operator surfaces MUST say why and MUST name the missing
coverage or quorum condition.

### 13.6.1 Decision Receipt Emission Rules

Implementations MUST emit `DecisionReceipt` for:

- denied risky operations,
- denied dangerous operations,
- dangerous allows,
- risky allows when audit policy requires high evidence.

Implementations SHOULD emit `DecisionReceipt` for:

- placement denial,
- degraded-mode placement acceptance,
- checkpoint rejection,
- lease conflict resolution,
- revocation stale-frontier denial,
- repair refusal caused by policy ceilings.

### 13.7 Security Model

Defense in depth in FCP spans multiple layers:

1. authenticated tailnet identity and ACLs,
2. zone-bound cryptographic policy and keying,
3. explicit capability and provenance enforcement,
4. supervised and budgeted execution,
5. supply-chain verification before activation,
6. durable receipts, checkpoints, and audit artifacts after execution.

High-value zones SHOULD additionally consider:

- stronger key-rotation cadence,
- MLS/TreeKEM group keying where available,
- stricter degraded-mode denial,
- stronger execution-form isolation requirements.

### 13.7.1 Defense-in-Depth Responsibilities by Layer

Each security layer SHOULD have a distinct operational role:

1. tailnet identity and ACLs restrict who can even reach the relevant surfaces,
2. zone keying and manifests restrict who can decrypt or use zone-bound artifacts,
3. capability and provenance enforcement restrict which actions can be attempted,
4. supervision, budgets, and drains restrict the blast radius of runtime failure,
5. receipts, checkpoints, and audit artifacts restrict ambiguity after the fact.

If one layer weakens temporarily, operators SHOULD be able to see which remaining layers still hold.

### 13.7.2 Source Diversity and Threshold-Secret Operational Guidance

High-value deployments SHOULD define:

- required source diversity for object reconstruction,
- when threshold-secret reconstruction is permitted locally versus proxy-mediated,
- which operations require stronger quorum, witness, or lease policy,
- what degraded behavior is acceptable when diversity is temporarily lost.

Operational doctrine matters here because availability pressure is where many systems silently give
up their security model.

### 13.7.3 Degraded-Mode Guardrails

Degraded mode MUST NOT become an invisible alternate security model.

Recommended guardrails:

1. dangerous operations default to deny unless policy explicitly opts them in,
2. degraded placement, stale checkpoint tolerance, or reduced source diversity MUST be surfaced in explain and health outputs,
3. degraded-mode decisions SHOULD emit evidence identifying exactly which guarantees were unavailable,
4. recovery from degraded mode SHOULD be explicit and auditable.

### 13.7.4 Threshold-Secret Operating Model

Threshold secrets are only valuable if their operational handling preserves the intended blast-radius reduction.

Recommended rules:

1. reconstruction SHOULD be demand-driven rather than eager,
2. reconstructed bytes SHOULD stay in the smallest feasible trusted boundary,
3. proxy-mediated use SHOULD be preferred when the connector does not genuinely need raw secret material,
4. device removal or compromise SHOULD trigger re-sharing and, where appropriate, rotation.

### 13.7.5 Security-Incident Response Expectations

A conformant operational model SHOULD make the following incident responses mechanically possible:

1. revoke a node or issuer key,
2. rotate affected zone keys,
3. refresh checkpoints and revocation heads,
4. re-share threshold secrets,
5. explain which in-flight or recently completed actions may have been affected.

Security features that cannot be exercised in incident response are only half implemented.

### 13.8 Threat and Trust Assumptions

Trusted assumptions:

- modern cryptographic primitives are sound,
- owner root trust configuration is correct,
- tailnet identity is authentic at the transport level.

Adversarial assumptions the system MUST tolerate or explicitly bound:

- one or more compromised devices,
- malicious or replaying peers,
- stale checkpoints or stale revocation state,
- hostile external services returning malformed or adversarial content,
- partitions that force relay-only paths or temporary degraded mode,
- supply-chain compromise attempts against connector artifacts.

Where quorum-sensitive claims are made, implementations SHOULD document the assumed `n` / `f` model
for the relevant zone or deployment.

### 13.8.1 Threat Table

Recommended operator-facing threat framing:

| Threat | Primary Control Layers |
|--------|------------------------|
| compromised device | attestation, revocation, zone-key rotation, lease fencing |
| malicious peer | session auth, admission control, quarantine, diversity policy |
| replayed authority | token freshness, holder proof, checkpoint binding |
| stale artifact | registry freshness, transparency, mirror pinning |
| hostile external service | taint, network guard, bounded execution, evidence emission |

### 13.8.2 Trust Reduction Paths

Implementations SHOULD define what happens when a previously trusted component becomes less trusted.

Examples:

- a direct path falls back to relay,
- a node loses posture attestation freshness,
- registry freshness checks fail,
- diversity requirements are no longer met,
- a provider begins returning malformed or adversarial responses.

These trust-reduction paths SHOULD map to explicit behavior:

- continue safely,
- continue in degraded mode,
- require operator approval,
- deny outright.

### 13.9 Agent Integration

FCP is designed to expose safe, explainable surfaces to agentic clients.

Agent-facing integrations SHOULD support:

- operation introspection including schemas, safety tier, approval mode, and recovery hints,
- dry-run and cost estimation where available,
- explain and doctor surfaces for denied or degraded actions,
- replayable event streams with explicit cursor semantics,
- stable reason codes that agents can surface or act upon mechanically.

When mapping FCP operations into MCP or equivalent tool ecosystems, the exported tool metadata SHOULD
preserve risk annotations, approval expectations, and idempotency or replay semantics.

## 14. Conformance and Verification

### 14.1 General Rule

Conformance is not satisfied by happy-path interop alone. An implementation is conformant only if it
behaves correctly under failure, cancellation, replay, stale state, policy denial, and hostile input.

### 14.2 Required Test Categories

Every reference implementation MUST include:

1. **Unit tests** for local rule systems:
   - manifest parsing and validation,
   - interface hash calculation,
   - capability token validation,
   - provenance propagation,
   - decision receipt generation,
   - stable error formatting,
   - lease and checkpoint validation.
2. **Property tests** for invariants:
   - canonical serialization,
   - identifier derivation,
   - monotone budget narrowing,
   - severity monotonicity of `Outcome`,
   - stale lease rejection.
3. **Fuzz and adversarial tests** for:
   - FCPC frame parsing,
   - durable object parsing,
   - chunk and symbol decode,
   - token and revocation verification,
   - malformed checkpoint and evidence artifacts.
4. **Deterministic runtime tests** for:
   - cancellation,
   - loser-drain,
   - quiescence,
   - restart policy,
   - deadline and cost exhaustion,
   - checkpoint/resume correctness.
5. **Replayable end-to-end scripts** for:
   - provision -> configure -> invoke,
   - stream -> credit -> cancel -> drain,
   - checkpoint -> failover -> resume,
   - explain -> doctor -> repair,
   - operator journey from first provision through diagnosis and recovery,
   - revoke -> reject -> revalidate,
   - hostile-service and hostile-peer scenarios.

### 14.2.1 Interoperability Minimums

Conformant implementations MUST interoperate on:

1. canonical object encoding,
2. capability token validation,
3. FCPC framing and replay behavior,
4. checkpoint freshness reasoning,
5. lease fencing behavior,
6. evidence retrieval for explained denials and successful risky actions.

### 14.2.2 Test Depth and Artifact Expectations

The test program MUST be deep enough that a future maintainer does not need to rediscover basic
runtime or protocol intent.

Required expectations:

1. Unit tests MUST cover happy paths, boundary cases, and explicit failure conditions for every normative parser, validator, and policy evaluator.
2. Runtime tests MUST use deterministic clocks where time semantics affect outcome.
3. E2E scripts MUST be replayable, documented, and produce retained evidence bundles or transcript identifiers.
4. Hostile-input tests MUST include malformed wire objects, stale checkpoints, replay attempts, and adversarial service responses.
5. Test fixtures MUST identify which stable reason codes and evidence objects are expected.

### 14.3 Logging and Evidence Requirements for Tests

Conformance e2e and adversarial tests MUST emit detailed structured logs with:

- correlation identifiers,
- stable reason codes,
- placement decision context,
- drain and restart phases,
- evidence object identifiers,
- any retained transcript object identifiers.

Tests that validate policy, replay, cancellation, or failover MUST retain sufficient evidence to
reconstruct the causal chain after the run completes.

### 14.3.1 E2E Script Logging Contract

Replayable end-to-end scripts MUST log, at minimum:

- scenario name and version,
- start and end timestamps,
- participating nodes and connectors,
- placement outcome,
- issued request identifiers,
- explicit cancellation, drain, or replay steps,
- evidence bundle identifiers,
- pass/fail verdict plus mismatch explanation on failure.

Logs SHOULD be emitted in both human-readable and machine-readable form so that operators can inspect
them directly while automated tooling can diff them across runs.

### 14.3.2 Test Harness Expectations

The reference harness SHOULD provide reusable facilities for:

- deterministic clocks,
- transcript capture,
- evidence-bundle export,
- structured log collection,
- mock external services,
- fault injection for transport, time, storage, and provider failures.

Harness output SHOULD make it obvious which objects, logs, and reason codes were expected versus observed.

### 14.4 Golden Vectors and Schemas

The project MUST ship a literal interoperability artifact set. At minimum, that set includes:

- deterministic CDDL or equivalent schemas for normative durable objects and FCPC or FCPS frames,
- JSON Schema inventory for adjunct artifacts such as FZPF and structured log records,
- golden byte vectors for canonical object encoding, identifier derivation, and signature
  verification,
- golden decision, receipt, audit-event, revocation-head, and checkpoint vectors,
- replay fixtures for checkpoint, failover, and stale-frontier semantics,
- transcript fixtures for FCPC sessions and FCPS symbol exchange.

Every shipped artifact MUST round-trip through the reference implementation such that:

1. it parses successfully,
2. canonical re-encoding reproduces identical bytes,
3. documented object identifiers and signatures verify,
4. reason-code or explain projections match the golden expectation.

Detailed appendix material MAY define these vectors out-of-line, but the requirement to ship them
is normative.

### 14.4.1 Conformance Profiles

An implementation MAY describe itself as:

- `Core`: execution, authority, FCPC, manifests, supply chain, and basic durability,
- `Full`: adds mobility, advanced repair, threshold secrets, and stronger diversity or quorum features.

Any such profile claims MUST be explicit and test-backed.

### 14.4.2 Minimum Shipped Test Artifacts

The reference implementation SHOULD ship:

- schema or CDDL files for normative objects,
- fixture corpora for identifiers, tokens, checkpoints, audit heads, and leases,
- FCPS `SymbolEnvelope` and decode-status fixtures,
- replayable FCPC/FCPS transcript fixtures,
- adversarial fixture sets for malformed, stale, forked, or quota-abusive objects,
- end-to-end scripts with expected evidence outputs,
- structured-log golden samples for key lifecycle and error paths,
- explain-output golden samples for major deny families.

### 14.4.3 Reference Testkit Expectations

The project SHOULD ship shared testkit utilities for:

- synthetic connector fixtures,
- mock capability and approval issuance,
- fake registry and mirror sources,
- deterministic FCPC/FCPS transcript builders,
- deterministic audit-head and revocation-frontier builders,
- evidence-bundle assertions,
- structured-log assertions with stable reason codes.

### 14.5 Conformance Claims

An implementation claiming FCP3 conformance MUST declare which optional execution forms and archetypes
it supports. It MUST NOT claim conformance if:

- it relies on ambient authority,
- it cannot explain risky or dangerous allow/deny decisions,
- it cannot bound cancellation/drain behavior,
- it cannot externalize canonical durable state where required,
- it cannot verify revocation and supply-chain policy before activation.

## 15. Appendices

### Appendix A: Chunked Objects and Large Payload Strategy

Large objects SHOULD be represented as chunk manifests rather than monolithic all-or-nothing payloads
once they exceed implementation-defined thresholds.

```rust
pub struct ChunkedObjectManifest {
    pub header: ObjectHeader,
    pub total_len: u64,
    pub chunk_size: u32,
    pub chunks: Vec<ObjectId>,
    pub payload_hash: [u8; 32],
}

pub struct RawChunk {
    pub header: ObjectHeader,
    pub bytes: Vec<u8>,
}
```

Benefits:

- partial retrieval,
- targeted repair,
- bounded memory reconstruction,
- chunk-level deduplication across versions,
- better UX for large binaries, attachments, and replay artifacts.

Fast-path guidance:

1. Small control-plane exchanges should avoid unnecessary symbolization.
2. Large durable artifacts should prefer chunking with targeted repair.

### Appendix B: RaptorQ and Symbol Transport Notes

RaptorQ remains valuable where:

- the transport is lossy,
- multipath aggregation is useful,
- offline repair matters,
- the object is naturally durable and replayable.

Representative configuration surface:

```rust
pub struct RaptorQConfig {
    pub symbol_size: u16,
    pub repair_ratio_bps: u16,
    pub max_object_size: u32,
    pub decode_timeout_ms: u64,
    pub max_chunk_threshold: u32,
    pub chunk_size: u32,
    pub max_symbols_per_object: u32,
    pub max_parallel_decodes: u16,
}
```

RaptorQ is not the right default for every control-plane interaction. FCP3 explicitly keeps the live
FCPC plane for low-latency interaction while reserving symbol and chunk machinery for durable transport.

Recommended interoperability defaults:

| Field | Recommended Default | Meaning |
|-------|---------------------|---------|
| `symbol_size` | `1024` | fit within the baseline `1200`-byte datagram budget once envelope overhead is included |
| `repair_ratio_bps` | `2500` | start with 25% repair overhead before targeted re-requesting |
| `max_object_size` | `268_435_456` | 256 MiB single-object ceiling before higher-level chunk strategies are required |
| `decode_timeout_ms` | `30000` | per-object bounded decode budget |
| `max_chunk_threshold` | `4_194_304` | prefer chunk manifests once payloads exceed 4 MiB |
| `chunk_size` | `1_048_576` | 1 MiB chunk size for large durable artifacts |
| `max_symbols_per_object` | `262144` | upper bound for admission and memory planning |
| `max_parallel_decodes` | `4` | default anti-DoS cap for concurrent decode work |

Operational notes:

1. Small control-plane artifacts SHOULD avoid symbolization unless lossy transport or resumability
   clearly justify it.
2. Large artifacts SHOULD be chunked before symbolization so repair can target only the missing
   chunk objects.
3. `repair_ratio_bps` SHOULD be treated as a starting point, not as permission to flood the mesh
   once decode feedback becomes available.

### Appendix C: Reference Connector Patterns

Representative patterns:

| Pattern | Description | Examples |
|---------|-------------|----------|
| Unified Messaging | Maps chats, channels, or threads into zone-bound resources and replayable event streams | Slack, Telegram, Discord |
| Workspace | High-read, moderate-write service with caching, approval gates, and provenance-sensitive actions | Gmail, Calendar, Notion |
| Knowledge | File or document surfaces with search, watch, and resumable indexing | Obsidian, Drive, Logseq |
| DevOps | Typed wrapper over dangerous external systems with strict explainability and idempotency rules | GitHub, kubectl, Terraform |
| Data / DB | Query and mutation surface where network and secret policy are critical | PostgreSQL, Elasticsearch, Vector DB |
| Browser | Remote-control or automation connector with high sandbox pressure and strong evidence needs | Browser/CDP connectors |

### Appendix D: SDK Surface Expectations

The reference SDK stack SHOULD separate:

- core types and schemas,
- Asupersync-native execution/context surfaces,
- manifest and interface-hash tooling,
- state/checkpoint helpers,
- FCPC/FCPS transport helpers,
- conformance fixtures and replay harnesses,
- operator-surface helpers for explain, doctor, and evidence retrieval.

Representative reference-surface inventory:

| Surface | Expected Responsibilities |
|---------|---------------------------|
| `fcp-kernel` | execution context, budgets, outcomes, cancellation, drain, restart, and supervision vocabulary |
| `fcp-policy` | zone model, provenance, capability narrowing, approvals, secret-use rules, and decision evaluation |
| `fcp-evidence` | receipts, checkpoints, revocation, audit-chain artifacts, and evidence-bundle schemas |
| `fcp-crypto` | canonical hashing, Ed25519, X25519, HPKE, COSE, key-id derivation, zeroization helpers |
| `fcp-cbor` | deterministic CBOR encode or decode and schema binding helpers |
| `fcp-manifest` | connector declarations, interface-hash inputs, provisioning-recipe schemas, isolation intent |
| `fcp-protocol` | FCPC, FCPS, session negotiation, replay windows, `SymbolEnvelope` encode or decode |
| `fcp-sdk` | connector app contract, archetype helpers, state adapters, operation and resource declarations |
| `fcp-host` | activation planning, supervision, admin or control-plane truth, operator-facing evidence retrieval |
| `fcp-conformance` | schemas, interop harnesses, vectors, transcript fixtures, explain assertions |
| `fcp-testkit` | deterministic mocks, approval or token builders, replay fixtures, evidence assertions |
| `fcp-cli` | `explain`, `doctor`, audit views, repair and verification operator workflows |

Connector-facing SDK surfaces MUST NOT require direct reach-through into host internals or legacy
compatibility buckets in order to express steady-state FCP3 behavior. The reference stack SHOULD
expose the FCP3-native concepts directly and treat any temporary compatibility scaffolding as
quarantined cutover machinery rather than part of the long-term authoring contract.

### Appendix E: Conformance Checklist

**Connector implementation checklist:**

- [ ] Manifest is extractable without execution.
- [ ] Operations, events, and resources are declared explicitly.
- [ ] Safety tier, approval mode, and idempotency are declared per operation.
- [ ] Long-lived work is modeled as a supervised connector app, not an ad-hoc background task.
- [ ] No canonical durable state required for failover is hidden in process memory.
- [ ] Health, introspection, and shutdown surfaces are implemented.
- [ ] Secrets are not logged or persisted by default.
- [ ] Provisioning flows declare human prompts, resumability, and evidence outputs explicitly.
- [ ] Replayable streams define cursor or sequence semantics.
- [ ] Connector examples and docs do not assume newline-delimited JSON-RPC or stdio-only ABI semantics.
- [ ] Risky and dangerous decisions are explainable by durable evidence.

**Host implementation checklist:**

- [ ] Authority is narrowed into connector launch contexts.
- [ ] Connectors are supervised rather than detached.
- [ ] FCPC framing, replay, cancellation, and drain semantics are enforced.
- [ ] Supply-chain policy is verified before activation.
- [ ] Leases and checkpoints are validated before failover or resume.
- [ ] Admin/control surfaces are the source of truth for operator CLIs and automation.
- [ ] Evidence bundles can be retrieved for risky and dangerous actions.
- [ ] Structured logs and stable reason codes are emitted.
- [ ] No steady-state conformance claim depends on compatibility shims or translator paths.
- [ ] Deterministic and replayable conformance tests exist.

**Conformance packaging checklist:**

- [ ] Conformance profiles and supported execution forms are declared explicitly.
- [ ] Golden vectors, transcript fixtures, and evidence-bundle examples ship with the implementation.
- [ ] Operator-facing `explain`, `doctor`, and replay surfaces are covered by stable schemas or snapshots.
- [ ] Reference examples reinforce FCP3-only behavior instead of compatibility-era host/connector relationships.

### Appendix F: Golden Vector Categories

At minimum, the project SHOULD ship golden vectors for:

- canonical object encoding,
- object identifier derivation,
- capability token encoding and verification,
- HPKE sealed boxes,
- audit-event and audit-head publication,
- revocation-head freshness decisions,
- `SymbolEnvelope` encoding, authentication, and replay rejection,
- FCPC frame parsing and replay rejection,
- lease fencing decisions,
- checkpoint freshness and resume acceptance/rejection,
- decision receipt rendering.

Representative vector families:

| Family | Required Cases |
|--------|----------------|
| Canonical objects | `ObjectHeader`, `DecisionReceipt`, `AuditEvent`, `AuditHead`, `RevocationHead`, `ZoneCheckpoint` |
| Authority | allow, deny, override-required, stale-frontier, declassification-required |
| Symbol plane | valid envelope, bad key id, bad auth tag, inconsistent `k`, replayed `frame_seq` |
| FCPC | valid invoke, malformed frame, replayed frame, wrong session binding |
| Leases | grant, renewal, stale fence, takeover after expiry |
| Resume | resume accepted, resume denied because receipt already committed, checkpoint rollback rejection |
| Explain | stable human-readable projections for the main deny families |

### Appendix G: Transport Priority and Placement Hints

Representative transport preference order:

```text
Priority 1: Tailnet direct path on local or low-latency route
Priority 2: Tailnet direct path via NAT traversal
Priority 3: Tailnet relay / DERP path
Priority 4: Public ingress path for low-trust zones only
```

High-trust or high-confidentiality work SHOULD prefer direct authenticated paths and SHOULD avoid
public ingress or relay-heavy execution where policy forbids it.

### Appendix H: Worked Flow - Risky Invoke

Representative flow:

1. Host validates manifest, placement policy, and supply-chain policy.
2. Host chooses a placement target and narrows a `Cx`.
3. Host materializes or references the `CapabilityToken`.
4. Host persists request object and, where required, `OperationIntent`.
5. Host sends `InvokeFrame` over FCPC.
6. Connector performs bounded execution under narrowed authority.
7. Connector returns inline result or result object reference.
8. Host persists `OperationReceipt`, `DecisionReceipt` when needed, and audit events.
9. Operator can later retrieve an `EvidenceBundle`.

### Appendix I: Worked Flow - Stream, Cancel, Drain, Resume

Representative flow:

1. Host opens a replayable stream with explicit initial credit.
2. Connector emits events with monotonically increasing sequence identifiers.
3. Host acknowledges or negatively acknowledges events according to delivery semantics.
4. Host issues `CancelFrame`.
5. Connector reports `DrainStatusFrame` progress until quiescent.
6. Host requests or verifies checkpoint state if the stream is resumable.
7. On resume, host reopens from explicit cursor or checkpoint evidence, not from guesswork.

### Appendix J: Worked Flow - Failover and Resume

Representative failover procedure:

1. Source node writes checkpoint artifact.
2. Checkpoint is distributed through FCPS if needed.
3. Lease is transferred or reacquired on the target node.
4. Target verifies checkpoint freshness and receipt consistency.
5. Target resumes under a fresh execution region with bounded budget.
6. Audit events link the old and new execution locations.

### Appendix K: Threat and Degraded-Mode Matrix

| Situation | Safe | Risky | Dangerous |
|-----------|------|-------|-----------|
| Stale revocation state | MAY proceed if policy allows degraded mode | SHOULD deny unless explicit override policy exists | MUST deny |
| Stale checkpoint | MAY attempt refresh and retry | SHOULD deny or require interactive override | MUST deny |
| Relay-only path | MAY proceed if confidentiality policy allows | Policy dependent | Often deny |
| Lease conflict | Retry or reconcile | Escalate and explain | Halt and require resolution |
| Missing attestation | Deny | Deny | Deny |

### Appendix L: Extended Reference Type Catalog

The following pseudo-definitions summarize the major object families that an implementation is expected
to model explicitly.

```rust
pub struct ZoneDefinitionObject {
    pub header: ObjectHeader,
    pub zone_id: ZoneId,
    pub allowed_connectors: Vec<ConnectorId>,
    pub default_placement: PlacementPolicy,
    pub policy_object_id: ObjectId,
    pub signature: Signature,
}

pub struct ZonePolicyObject {
    pub header: ObjectHeader,
    pub zone_id: ZoneId,
    pub capability_ceiling: Vec<CapabilityId>,
    pub egress_policy: EgressPolicy,
    pub approval_policy: ApprovalPolicy,
    pub audit_policy: AuditPolicy,
    pub signature: Signature,
}

pub struct CapabilityObject {
    pub header: ObjectHeader,
    pub capability_id: CapabilityId,
    pub grantee: Grantee,
    pub constraints: CapabilityConstraints,
    pub placement: PlacementPolicy,
    pub valid_from: u64,
    pub valid_until: u64,
    pub signature: Signature,
}

pub struct CredentialObject {
    pub header: ObjectHeader,
    pub credential_id: CredentialId,
    pub secret_id: SecretId,
    pub apply: CredentialApply,
    pub host_allow: Vec<String>,
    pub created_at: u64,
    pub signature: Signature,
}

pub struct ConnectorStateRoot {
    pub header: ObjectHeader,
    pub connector_id: ConnectorId,
    pub instance_id: Option<InstanceId>,
    pub zone_id: ZoneId,
    pub model: ConnectorStateModel,
    pub head: Option<ObjectId>,
}

pub struct Lease {
    pub header: ObjectHeader,
    pub subject_object_id: ObjectId,
    pub purpose: LeasePurpose,
    pub lease_seq: u64,
    pub owner_node: NodeId,
    pub iat: u64,
    pub exp: u64,
    pub coordinator: NodeId,
    pub quorum_signatures: Vec<(NodeId, Signature)>,
}

pub struct OperationIntent {
    pub header: ObjectHeader,
    pub request_object_id: ObjectId,
    pub capability_token_jti: [u8; 16],
    pub idempotency_key: Option<String>,
    pub planned_at: u64,
    pub planned_by: NodeId,
    pub lease_seq: Option<u64>,
    pub upstream_idempotency: Option<String>,
    pub signature: Signature,
}

pub struct OperationReceipt {
    pub header: ObjectHeader,
    pub request_object_id: ObjectId,
    pub connector_id: ConnectorId,
    pub operation_id: OperationId,
    pub zone_id: ZoneId,
    pub outcome: ReceiptOutcome,
    pub result_object_id: Option<ObjectId>,
    pub evidence: Vec<ObjectId>,
    pub executed_at: u64,
    pub signature: Signature,
}

pub struct AuditEvent {
    pub header: ObjectHeader,
    pub correlation_id: [u8; 16],
    pub trace: TraceContext,
    pub zone_id: ZoneId,
    pub actor: PrincipalId,
    pub connector_id: Option<ConnectorId>,
    pub operation_id: Option<OperationId>,
    pub event_class: AuditEventClass,
    pub event_type: String,
    pub disposition: AuditDisposition,
    pub subject_refs: Vec<AuditSubjectRef>,
    pub decision_receipt_id: Option<ObjectId>,
    pub operation_receipt_id: Option<ObjectId>,
    pub checkpoint_id: Option<ObjectId>,
    pub lease_id: Option<ObjectId>,
    pub revocation_head_id: Option<ObjectId>,
    pub summary: AuditSummary,
    pub prev: Option<ObjectId>,
    pub seq: u64,
    pub occurred_at: u64,
    pub degraded_mode: bool,
    pub signature: Signature,
}

pub struct ZoneCheckpoint {
    pub header: ObjectHeader,
    pub zone_id: ZoneId,
    pub prev_checkpoint: Option<ObjectId>,
    pub revocation_head: ObjectId,
    pub revocation_seq: u64,
    pub audit_head: ObjectId,
    pub audit_seq: u64,
    pub zone_definition_head: ObjectId,
    pub zone_policy_head: ObjectId,
    pub checkpoint_seq: u64,
    pub quorum_signatures: Vec<(NodeId, Signature)>,
}
```

This appendix is intentionally redundant with the main body. Its purpose is to give implementers one
place where the major type families can be reviewed together.

### Appendix M: Full Example Manifest

```toml
[manifest]
format = "fcp-connector-manifest"
schema_version = "3.0"
min_protocol = "fcp3/fcpc-cbor"
protocol_features = [
  "fcpc.aead.chacha20poly1305",
  "fcps.chunked-objects",
  "fcps.repair",
  "egress.dns_rebind_protection",
]
interface_hash = "blake3-256:fcp.interface.v3:exampledigest"

[connector]
id = "fcp.telegram"
name = "Telegram Connector"
version = "2026.3.0"
description = "Zone-bound Telegram Bot API connector"
execution_form = "wasi"
archetypes = ["bidirectional", "streaming"]

[connector.state]
model = "singleton_writer"
state_schema_version = "2"
snapshot_every_updates = 5000
snapshot_every_bytes = 1048576

[execution]
root_budget = { deadline_ms = 30000, cost_quota = 50000, priority = "interactive" }
restart_policy = { strategy = "restart", max_restarts = 3, window_ms = 60000 }
drain_policy = { soft_timeout_ms = 2000, hard_timeout_ms = 15000 }

[placement]
eligible_zones = ["z:community"]
prefers = ["data_locality", "direct_path", "healthy_node"]
requires = ["network.egress", "storage.durable"]
remote_execution = true

[capabilities]
required = [
  "telegram.read",
  "telegram.write",
  "network.egress",
  "network.tls.sni",
  "network.tls.spki_pin",
]
optional = ["media.download", "media.upload"]
forbidden = ["system.exec", "network.inbound"]

[provides.operations.send_message]
description = "Send a message to an approved Telegram chat"
capability = "telegram.write"
safety_tier = "risky"
requires_approval = "policy"
idempotency = "best_effort"
input_schema = { type = "object", required = ["chat_resource", "text"] }
output_schema = { type = "object", required = ["message_id"] }
network_constraints = { host_allow = ["api.telegram.org"], port_allow = [443], require_sni = true, spki_pins = ["base64:example"] }

[provides.events.message_received]
replayable = true
requires_ack = true
ordering_scope = "chat"

[provides.resources.chat]
visibility = "zone_bound"
mutability = "append"

[provisioning]
recipe = "telegram/install"
supports_rotation = true
zero_persist_secrets = true

[sandbox]
profile = "strict"
memory_mb = 256
cpu_percent = 50
wall_clock_timeout_ms = 30000
fs_readonly_paths = ["/usr", "/lib"]
fs_writable_paths = ["$CONNECTOR_STATE"]
deny_exec = true
deny_ptrace = true

[signatures]
publisher_signatures = [
  { kid = "pubkey1", sig = "base64:example1" },
  { kid = "pubkey2", sig = "base64:example2" },
]
publisher_threshold = "2-of-3"
registry_signature = { kid = "registry1", sig = "base64:example3" }
transparency_log_entry = "objectid:example"

[supply_chain]
attestations = [
  { type = "in-toto", object_id = "objectid:att1" },
  { type = "sbom", object_id = "objectid:att2" },
  { type = "reproducible-build", object_id = "objectid:att3" },
]

[policy]
require_transparency_log = true
require_attestation_types = ["in-toto", "sbom"]
min_slsa_level = 2
trusted_builders = ["github-actions", "internal-ci"]
```

### Appendix N: Expanded Conformance Matrix

| Area | Minimum Requirement | Evidence |
|------|---------------------|----------|
| Canonical encoding | Deterministic CBOR for normative objects | Golden vectors |
| Authority | No ambient authority in execution surfaces | API review + tests |
| Cancellation | Explicit checkpointed cancellation | Deterministic runtime tests |
| Quiescence | Region close implies no live owned work | Quiescence oracles / tests |
| Risky invoke | Decision and operation receipts | Evidence bundle |
| Dangerous invoke | Lease or equivalent exclusive control where required | Logs + receipts + lease objects |
| Replayable streams | Ack/nack and resume semantics | E2E transcript |
| Failover | Checkpoint + resume with replay safety | E2E transcript + receipts |
| Supervision | Restart, drain, and finalize behavior are explicit and bounded | Runtime harness + evidence transcript |
| Connector ABI | Framed FCPC/FCPS surfaces, not newline JSON-RPC fallback | Transcript fixtures + parser tests |
| Provisioning | Host-mediated, resumable, auditable setup flows | Mock OAuth/webhook E2E + audit bundle |
| Revocation | Freshness checked before high-safety actions | Adversarial tests |
| Supply chain | Manifest, digest, attestations, transparency policy | Verification logs |
| Admin-plane truth | `explain`, `doctor`, and repair views reflect host-owned state | CLI snapshot + host integration tests |
| Compatibility-free surface | No required steady-state translator or shim path | Architecture review + negative tests |
| Explainability | Stable reason codes and evidence retrieval | Explain surface tests |
| Offline behavior | Repair and pre-staging policy where claimed | Coverage evaluation logs |

### Appendix O: Example Evidence Bundle Walkthrough

For a denied risky invoke, a well-formed evidence bundle SHOULD let an operator answer:

1. What request was made?
2. Which zone and connector were involved?
3. Which capability token was presented?
4. Which policy or provenance rule denied the action?
5. Which receipt or audit artifacts corroborate that denial?

Representative bundle contents:

```text
request_object_id = objectid:req123
decision_receipt = objectid:dec456
operation_receipt = none
audit_events = [objectid:a1, objectid:a2]
checkpoint = objectid:chk789
transcript_objects = [objectid:fcpc1, objectid:fcpc2]
```

This should be sufficient for both human review and automated replay tooling.

### Appendix P: Connector Archetype Expectations

| Archetype | Typical State Model | Replay / Cursor | Lease Need | Special Notes |
|-----------|---------------------|-----------------|------------|---------------|
| Request-response | Stateless or local cache | Usually no | Sometimes for dangerous external writes | Strong idempotency strongly encouraged for risky writes |
| Streaming | Often durable cursor | Yes | Rare for read-only streams | Credit, ack/nack, and drain semantics are critical |
| Bidirectional | Durable session or cursor | Usually yes | Sometimes | Requires careful cancellation and backpressure handling |
| Polling | Singleton writer common | Yes | Common | Poll cursors and dedup state MUST survive failover |
| Webhook | Stateless ingress + durable replay buffer | Often yes | Usually no | Public ingress pressure increases taint and verification burden |
| Queue / pub-sub | Durable consumer position | Yes | Common | Delivery guarantees and resume semantics must be explicit |
| File / blob | Local cache + durable resource metadata | Optional | Rare | Digesting and chunking often matter |
| Database | Often stateless query + durable migration state | Optional | Sometimes | Network Guard and credential policy are especially important |
| CLI / process | Usually stateless | Optional | Sometimes | Native execution increases isolation burden |
| Browser | Durable session or checkpoint | Often yes | Common | Strong sandboxing and evidence requirements are recommended |

### Appendix Q: Stable Reason Code Catalog

Recommended baseline reason codes:

| Reason Code | Meaning |
|-------------|---------|
| `capability.insufficient` | Required capability not present |
| `capability.grant_missing` | Token references insufficient grant objects |
| `capability.audience_mismatch` | Token audience does not match target |
| `capability.binary_mismatch` | Token bound to different binary |
| `provenance.integrity_uphill` | Integrity elevation required |
| `provenance.declassification_required` | Declassification required before lower-confidentiality write |
| `taint.public_input_dangerous` | Public-tainted data attempted dangerous action |
| `taint.unsanitized` | Taint reduction evidence missing |
| `zone.connector_denied` | Connector not allowed in zone |
| `zone.policy_violation` | Zone policy rejected action |
| `egress.host_denied` | Hostname denied by NetworkConstraints |
| `egress.ip_denied` | Resolved IP denied by policy |
| `egress.spki_mismatch` | TLS SPKI pin mismatch |
| `lease.stale` | Lease sequence stale |
| `lease.conflict` | Conflicting lease detected |
| `checkpoint.stale` | Checkpoint too old |
| `checkpoint.inconsistent` | Checkpoint or receipt chain inconsistent |
| `revocation.stale_frontier` | Revocation or checkpoint freshness insufficient |
| `supply_chain.attestation_missing` | Required attestation missing |
| `supply_chain.transparency_missing` | Transparency log requirement unsatisfied |
| `runtime.deadline_exceeded` | Budget deadline exceeded |
| `runtime.cancelled` | Cancellation observed and honored |
| `runtime.quiescence_timeout` | Drain/finalize did not complete in required budget |

### Appendix R: Example FCPC Transcript

Illustrative successful risky invoke:

```text
1. handshake(version=3, connector=fcp.telegram, features=[fcpc, replay, explain])
2. handshake_ack(version=3, max_inline_bytes=65536)
3. invoke(request_object_id=req123, operation=send_message, token=tok456, budget=...)
4. invoke_result(request_object_id=req123, outcome=Succeeded, result_object_id=res789, receipt=rcpt111)
5. evidence(request_object_id=req123, decision_receipt=dec222, operation_receipt=rcpt111, audit=[a1,a2])
```

Illustrative cancelled replayable stream:

```text
1. stream_open(request_object_id=req200, topic=chat:123, replay_from=evt090, initial_credit=100)
2. event(event_object_id=evt091, seq=91)
3. ack(event_object_id=evt091, seq=91)
4. event(event_object_id=evt092, seq=92)
5. cancel(request_object_id=req200, reason=operator_requested)
6. drain_status(request_object_id=req200, phase=Draining)
7. drain_status(request_object_id=req200, phase=Finalizing)
8. stream_close(request_object_id=req200, final_seq=92)
```

### Appendix S: Operator Surface Expectations

`explain` SHOULD return:

- decision outcome,
- stable reason code,
- human-readable summary,
- evidence object identifiers,
- whether degraded mode was involved.

`doctor` SHOULD return:

- target component,
- health state,
- likely failure class,
- recommended next actions,
- relevant evidence bundle references.

`replay` SHOULD return or reconstruct:

- request framing,
- decision and operation receipts,
- audit linkage,
- checkpoint references when applicable.

### Appendix T: Mesh Session Transcript and Key Derivation

Illustrative handshake transcript:

```text
1. hello(from=node-a, to=node-b, eph_pubkey=..., nonce=a1, suites=[suite1,suite2], limits=...)
2. hello_retry(cookie=...)
3. hello(from=node-a, to=node-b, eph_pubkey=..., nonce=a2, cookie=..., suites=[suite1,suite2], limits=...)
4. ack(from=node-b, to=node-a, eph_pubkey=..., nonce=b1, session_id=s123, suite=suite2)
5. both sides derive directional keys from session_id, node ids, and both nonces
```

Recommended derivation pattern:

```text
prk = HKDF-SHA256(
  ikm  = X25519(initiator_eph, responder_eph),
  salt = session_id,
  info = "fcp.session.v3" || initiator_node_id || responder_node_id || hello_nonce || ack_nonce
)

expand(prk, "fcp.session.keys.v3", 96) ->
  k_mac_i2r || k_mac_r2i || k_ctx
```

Security rationale:

- binds derived keys to a single authenticated handshake,
- prevents session splicing,
- allows explicit directionality,
- leaves room for future envelope or control-plane AEAD evolution.

### Appendix U: Activation, Update, and Rollback Checklist

**Activation checklist:**

- [ ] manifest extracted without execution
- [ ] interface hash verified
- [ ] artifact digest matches signed expectation
- [ ] attestations and transparency policy satisfied
- [ ] zone and revocation heads fresh enough
- [ ] provisioning and credential injection complete
- [ ] placement decision recorded
- [ ] sandbox or execution-form policy satisfied

**Update checklist:**

- [ ] new artifact passes activation checks
- [ ] staged rollout or canary plan selected where required
- [ ] rollback target already verified and retained
- [ ] evidence plan for observing rollout health exists

**Rollback checklist:**

- [ ] trigger reason recorded with stable reason code
- [ ] inflight work drained, cancelled, or checkpointed
- [ ] replacement artifact verified before cutover
- [ ] post-rollback health observation window started

### Appendix V: Structured Log Event Catalog

Recommended event types include:

| Event Type | Purpose |
|------------|---------|
| `activation.started` | connector activation began |
| `activation.denied` | activation failed due to policy or verification |
| `placement.chosen` | planner selected a node |
| `placement.degraded` | placement proceeded in degraded mode |
| `lease.acquired` | lease became active |
| `lease.conflict` | conflicting lease observed |
| `checkpoint.accepted` | checkpoint accepted for resume |
| `checkpoint.rejected` | checkpoint rejected as stale or inconsistent |
| `stream.credit_exhausted` | sender blocked waiting for credit |
| `runtime.cancel_honored` | connector observed and honored cancellation |
| `repair.promoted` | quarantined object admitted |
| `repair.rebalanced` | object coverage redistributed |
| `supply_chain.denied` | artifact rejected by verification policy |

Recommended common fields:

- `trace_id`
- `request_object_id`
- `connector_id`
- `zone_id`
- `reason_code`
- `evidence_object_ids`
- `degraded_mode`

### Appendix W: Required E2E Scenarios and Logging Contract

The reference end-to-end suite SHOULD include at least:

1. first-run provisioning of a connector with expected prompts and resulting manifests,
2. safe invoke with ordinary success evidence,
3. risky invoke that emits decision and operation receipts,
4. dangerous invoke denied by policy with stable reason code,
5. replayable stream with credit, ack, cancel, drain, and resume,
6. checkpointed failover between two nodes,
7. stale revocation or stale checkpoint rejection,
8. hostile-peer symbol request and quarantine behavior,
9. supply-chain rejection on attestation or digest mismatch,
10. operator journey covering explain, doctor, replay, and repair.

Each scenario SHOULD retain:

- scenario transcript identifier,
- involved object ids,
- expected reason codes,
- expected log event types,
- pass/fail summary.

### Appendix X: Capability Token Claim and Header Example

Illustrative deterministic claim map:

```cbor
{
  1: "z:community",
  2: "principal:agent.example",
  3: "fcp.telegram",
  4: 1770000000,
  6: 1769999700,
  7: h'00112233445566778899aabbccddeeff',
  "fcp.iss_node": h'...',
  "fcp.grant_object_ids": [h'...', h'...'],
  "fcp.checkpoint_seq": 42,
  "fcp.checkpoint_id": h'...',
  "fcp.aud_binary": h'...'
}
```

Illustrative protected header:

```cbor
{
  1: -8,
  4: h'0123456789abcdef'
}
```

Verification notes:

- protected headers MUST be included in the signature structure,
- private claim names or labels MUST be stable and documented,
- duplicate map keys MUST be rejected.

### Appendix Y: Approval Scope Examples

Example execution approval:

```text
scope = Execution
connector_id = fcp.telegram
method_pattern = send_message
request_object_id = req123
input_constraints = [
  { json_pointer = "/chat_resource/resource_uri", op = Eq, value = "telegram://chat/123" },
  { json_pointer = "/text", op = Prefix, value = "[approved]" }
]
```

Example declassification approval:

```text
scope = Declassification
from_zone = z:private
to_zone = z:community
object_ids = [obj111, obj222]
```

These examples are illustrative. Real deployments SHOULD use the most specific practical scope rather
than broad wildcard approvals.

### Appendix Z: Coverage and Repair Playbook

Recommended repair loop:

1. evaluate coverage for pinned or policy-relevant objects,
2. detect over-concentration or under-replication,
3. prefer direct eligible peers for rebalance,
4. emit repair evidence when placement policy materially changes,
5. update planner and offline-availability views after repair.

Suggested threshold interpretation:

| Condition | Meaning | Recommended Action |
|-----------|---------|--------------------|
| `coverage_bps < 10000` | object not reconstructable | targeted repair immediately |
| `coverage_bps >= 10000` and `max_node_fraction_bps` exceeds policy | available but dangerously concentrated | rebalance before next risky placement decision |
| diversity below zone minimum | availability claim is too fragile | prefer new eligible nodes over additional symbols on existing nodes |
| repair source set exhausted | no policy-eligible repair path remains | surface `EmergencyUnavailable` and operator intervention |

Suggested operator questions:

- is the object reconstructable now,
- is coverage too concentrated on one node,
- which zone or device class is under-covered,
- did a recent device removal or revocation create the deficit,
- does the planner now have enough locality to avoid degraded placement.

### Appendix AA: Example Provisioning Recipe

Illustrative machine-readable recipe:

```text
recipe_id = telegram/install
steps = [
  prompt(account_choice),
  browser_action(oauth_login, https://example.invalid/oauth/start),
  oauth_exchange(telegram, scopes=[bot.write, bot.read]),
  api_call(register_webhook),
  secret_inject(bot_token, network_guard.header.telegram),
  validation(send_self_test_message)
]
rollback_steps = [
  api_call(delete_webhook),
  validation(confirm_remote_cleanup)
]
```

### Appendix AB: Example Mirror Index

Illustrative mirror entry:

```text
zone_id = z:work
connector_id = fcp.telegram
version = 2026.3.0
manifest_object_id = obj.manifest.123
artifact_object_id = obj.binary.456
attestation_object_ids = [obj.sbom.1, obj.provenance.2]
```

### Appendix AC: Verification Decision Checklist

Operator or harness checklist:

- [ ] source index authenticated
- [ ] manifest signature threshold satisfied
- [ ] digest matched artifact
- [ ] interface hash matched expectation
- [ ] attestations satisfied policy
- [ ] transparency requirement satisfied
- [ ] revocation state fresh
- [ ] execution form supported
- [ ] zone policy accepted requested capabilities

### Appendix AD: Checkpoint and Revocation Triage Questions

Recommended operator triage questions:

- is the presented checkpoint newer, older, or conflicting,
- is revocation state stale because of network partition or verification failure,
- are multiple peers disagreeing about the zone frontier,
- did a recent device removal trigger expected key rotation and checkpoint advance,
- does the denial trace back to one decisive stale artifact or many?

### Appendix AE: Example Operator Evidence Walkthrough

Illustrative debugging chain for a denied dangerous operation:

1. open the `DecisionReceipt`,
2. inspect `reason_code = checkpoint.stale`,
3. follow evidence to the last accepted `ZoneCheckpoint`,
4. compare with current `RevocationHead`,
5. inspect logs for `placement.degraded` or `revocation.refresh_failed`,
6. decide whether to refresh, repair, or deny until quorum is restored.

### Appendix AF: Suggested Test Matrix by Connector Archetype

| Archetype | Unit Focus | E2E Focus |
|-----------|------------|-----------|
| Request-response | input validation, idempotency, receipts | risky invoke, retry, explain |
| Streaming | cursor state, credit accounting | subscribe, ack/nack, cancel, resume |
| Polling | cursor durability, checkpoint freshness | failover with preserved cursor |
| Webhook | taint/provenance, public ingress policy | ingress, deny, replay, repair |
| Queue / pub-sub | delivery semantics, resume position | nack, redelivery, drain |
| Browser | sandbox policy, secret mediation | interactive setup, risky action, evidence retrieval |

### Appendix AG: Source Diversity and Quorum Questions

Recommended design questions:

- how many distinct nodes are required for a claim of availability,
- what fraction of symbols may safely reside on one node,
- which operations need stronger witness or quorum policy,
- what is the acceptable degraded behavior when quorum is temporarily unavailable,
- which operator surfaces expose those assumptions clearly.

### Appendix AH: Event Buffer Example

Illustrative buffered stream progression:

```text
epoch e100 -> events 1000..1099 -> finalized object obj.epoch.100
epoch e101 -> events 1100..1199 -> finalized object obj.epoch.101
cursor state points to (epoch=e101, seq=1142)
resume fetches obj.epoch.101 and replays 1143..
```

### Appendix AI: Artifact Distribution Notes

Recommended artifact-transfer preference order:

1. local pinned artifact already present,
2. trusted mirror on direct tailnet path,
3. multiple trusted peers contributing chunks or symbols,
4. upstream registry fetch only if still required by policy.

### Appendix AJ: Reference Crate Graph and Ownership Boundaries

This appendix is not a wire-format contract, but it is the reference architectural boundary for the
FCP3 workspace. The point is to prevent FCP3 from collapsing back into a convenience-driven
monolith where the same concept is half-owned by `fcp-core`, half-owned by the host, and partially
redeclared in the SDK. A concept gets one long-term owner. Re-exports are fine; duplicate authority is not.

#### AJ.1 Dependency Law

The reference workspace SHOULD follow these rules:

1. Production dependencies point inward toward narrower semantic ownership. Outward or sideways convenience dependencies are architecture debt.
2. Connector crates in `connectors/*` depend on `fcp-sdk`, connector-specific support crates, and leaf utility crates; they MUST NOT depend on `fcp-host`.
3. `fcp-host` depends on execution, policy, evidence, transport, manifest, storage, mesh, verification, and sandbox crates; it MUST NOT become the place where protocol semantics are redefined.
4. `fcp-sdk` depends on the same semantic core crates needed to author connectors, but it MUST NOT own host-only lifecycle or admin-plane concepts.
5. Test and fixture crates (`fcp-conformance`, `fcp-testkit`) may depend outward on the full stack; production crates MUST NOT depend back on test harnesses.
6. Temporary quarantine crates MAY exist during cutover, but each one MUST have an explicit deletion target and MUST NOT become the new semantic center.

#### AJ.2 Target Reference Graph

The long-term workspace decomposition SHOULD converge toward the following graph:

```text
fcp-crypto
    │
    ├── fcp-kernel      (Cx, Scope, Budget, Outcome, effect staging, drain, supervision contracts)
    ├── fcp-policy      (zones, provenance, capability narrowing, approvals, decision evaluation)
    └── fcp-evidence    (receipts, audit chain, revocation, checkpoints, explainable artifacts)

fcp-kernel + fcp-policy + fcp-evidence
    │
    ├── fcp-protocol    (FCPC/FCPS framing, session auth, ABI envelopes, replay/rekey rules)
    ├── fcp-manifest    (connector declarations, interface hash, provisioning recipes, isolation intent)
    ├── fcp-store       (object store, symbol store, quarantine, repair, retention)
    ├── fcp-mesh        (node identity, placement planning, leases, failover, repair coordination)
    ├── fcp-registry    (artifact source selection, verification, mirroring, promotion)
    └── fcp-sandbox     (execution-form enforcement, WASI/native isolation, egress mediation)

those runtime/service crates
    │
    ├── fcp-host        (root application, activation planning, orchestration, admin/control surfaces)
    ├── fcp-sdk         (connector authoring APIs, archetype helpers, checkpoint/state adapters)
    ├── fcp-cli         (operator-oriented platform CLI)
    ├── fwc             (connector/operator UX built on host truth)
    ├── fcp-conformance (profiles, vectors, property/e2e harnesses)
    └── fcp-testkit     (fixture and mock support for connectors and host tests)

leaf support and domain crates
    │
    ├── fcp-oauth
    ├── fcp-google-discovery
    ├── provider-specific helper crates
    └── connectors/*
```

This graph is intentionally opinionated:

- execution semantics are not owned by transport code,
- policy semantics are not owned by the host,
- evidence semantics are not hidden inside storage or logging crates,
- manifest semantics are not spread across host and connector implementations,
- connectors see the SDK surface, not host internals.

#### AJ.3 Ownership Matrix

| Crate | Owns | Must not own | Why |
|-------|------|--------------|-----|
| `fcp-crypto` | Key types, signatures, HPKE, canonical crypto helpers | zone policy, manifests, connector runtime state | Crypto should stay reusable and semantically narrow. |
| `fcp-kernel` | `Cx`, `Scope`, `Budget`, `Outcome`, cancellation, drain, effect staging, supervision vocabulary | FCPC/FCPS codecs, manifest parsing, supply-chain logic | The execution contract is the stable center of FCP3. |
| `fcp-policy` | zones, provenance, capability narrowing, approval/sanitizer rules, decision evaluation | audit persistence, object storage, host lifecycle | Policy needs one home so allow/deny semantics do not drift. |
| `fcp-evidence` | decision receipts, operation receipts, audit chain, revocation, checkpoints, evidence-bundle schemas | live transport state, connector business logic | Durable proof artifacts should not be mixed with execution or storage plumbing. |
| `fcp-protocol` | FCPC/FCPS frames, session handshake/auth, ABI envelopes, replay/rekey mechanics | policy decisions, manifests, connector archetype helpers | Byte-level interoperability belongs here and nowhere else. |
| `fcp-manifest` | connector declarations, interface hash inputs, provisioning recipe schema, isolation/storage intent | host admin RPCs, transport sessions, connector runtime context | Manifests are compile-time/activation contracts, not runtime orchestration. |
| `fcp-store` | object store, symbol store, quarantine, retention, repair, coverage accounting | supply-chain trust policy, zone evaluation, connector SDK ergonomics | Storage must stay durable and mechanical rather than policy-aware. |
| `fcp-mesh` | mesh identity, placement planning, leases, mobility/failover coordination, repair orchestration | connector authoring helpers, host admin UX | Placement and topology logic should not leak into connector code. |
| `fcp-registry` | registry source model, verification pipeline, mirror promotion, artifact trust reports | host lifecycle transitions, generic object-store semantics | Artifact trust and acquisition are distinct from activation. |
| `fcp-sandbox` | native/WASI execution-form enforcement, egress mediation, credential injection boundaries | connector business operations, policy evaluation | Isolation is an enforcement mechanism, not a semantics crate. |
| `fcp-host` | root application, activation planning, supervision, lifecycle orchestration, admin/control surfaces | foundational protocol or policy truth | The host composes lower layers; it must not redefine them. |
| `fcp-sdk` | connector-facing authoring surface, archetype helpers, checkpoint/state adapters, testable ergonomics | host-only admin workflows, registry policy, mesh placement | Connector authors need a stable, host-independent surface. |
| `fcp-conformance` / `fcp-testkit` | vectors, fixtures, replay harnesses, property/e2e support | production runtime dependencies | Verification should be powerful but non-invasive. |
| `fcp-cli` / `fwc` | operator and agent UX over host/platform truth | duplicated host semantics or connector-local hacks | CLIs should project the system, not fork it. |

#### AJ.4 Workspace Evidence Snapshot

The current workspace still exhibits the ownership blur this appendix is trying to eliminate.
As of the repository state reflected by the current `Cargo.toml` files and crate roots:

- `fcp-host`, `fcp-sdk`, `fcp-protocol`, `fcp-manifest`, `fcp-store`, and `fwc` all depend directly on `fcp-core`.
- `fcp-host`, `fcp-sdk`, and `fcp-store` still depend on `fcp-async-core`, which is acceptable only as temporary migration scaffolding.
- `fcp-core` currently re-exports audit, capability, checkpoint, connector, connector state, credential, enrollment, error, event, health, lease, lifecycle, object, operation, policy, posture, protocol, provenance, provisioning, quorum, rate limiting, release, revocation, secret, supply-chain, telemetry, and zone-key surfaces from one bucket.
- `fwc` currently depends on `fcp-core` and `fcp-manifest` directly instead of projecting host truth through stable host-backed schemas and RPC surfaces.

This is exactly the pattern FCP3 must remove: too many crates reach into one omnibus semantic crate,
which makes it easy for policy, evidence, execution, and UX concerns to drift back into duplicated
or convenience-driven ownership.

#### AJ.5 Current Module Migration Map

The crate graph above is only useful if contributors can map today's modules into tomorrow's owners.
The following table is the reference migration map for the current workspace:

| Current surface | FCP3 owner | Migration note |
|-----------------|------------|----------------|
| `fcp-core::{error, health, lifecycle}` | `fcp-kernel` | Failure classes, liveness/readiness vocabulary, and lifecycle state belong with execution semantics rather than a generic core bucket. |
| `fcp-core::{capability, policy, provenance, credential, secret, zone_keys, provisioning}` | `fcp-policy` | These modules define authority, approval, taint, zone, and secret-access rules. Provisioning recipes may be described by `fcp-manifest`, but allow/deny and secret-use semantics belong in policy. |
| `fcp-core::{audit, revocation, checkpoint, operation}` | `fcp-evidence` | Audit chain, revocation heads, checkpoints, `OperationIntent`, and `OperationReceipt` are durable proof surfaces and must share one evidence owner. |
| `fcp-core::{protocol, event}` | `fcp-protocol` | Live ABI envelopes, stream/event message shapes, and transport-facing request/response projections belong with FCPC/FCPS semantics. |
| `fcp-core::{connector, connector_descriptors, tool_schema}` | split between `fcp-sdk` and `fcp-manifest` | Connector author contracts and runtime-facing helper types belong in `fcp-sdk`; declarative descriptor and schema inputs used for activation/interface hashing belong in `fcp-manifest`. |
| `fcp-core::{connector_state, crdt}` | split between `fcp-store` and `fcp-sdk` | Durable state object semantics, snapshots, and merge rules belong with storage/state machinery; author ergonomics and adapters belong in the SDK. |
| `fcp-core::{lease, enrollment, posture, quorum}` | `fcp-mesh` | Device attestation, lease fencing, quorum assumptions, and mesh enrollment are topology and coordination concerns, not generic core helpers. |
| `fcp-core::{object}` | split between `fcp-store`, `fcp-policy`, and `fcp-evidence` | The current `object.rs` is a mixed abstraction. Object materialization/retention belongs in storage, while typed policy/evidence payload contracts belong to their semantic owners. |
| `fcp-core::{ratelimit, telemetry}` | leaf helper crates or true semantic owners | Keep these only if they remain sharply scoped. Otherwise move execution-budget semantics into `fcp-kernel` and observability schemas into `fcp-evidence`/`fcp-host`, with export helpers staying leaf-level. |
| `fcp-core::{release, supply_chain}` | split between `fcp-registry` and `fcp-evidence` | Artifact trust, promotion, and attestation verification belong in registry flow; durable attestation/report object shapes belong in evidence. |
| `fcp-async-core`, `fcp-async-core-macros` | temporary quarantine on the path to `fcp-kernel` | Treat these as migration shims only. Any semantic contract worth keeping must be re-homed under the FCP3 kernel vocabulary and the compatibility layer then deleted. |
| `fcp-host::{budget, cancellation}` | `fcp-kernel` if semantics are generic; otherwise `fcp-host` | Budget and cancellation semantics should live below the host only when they define platform-wide execution rules. Host-specific policy application and orchestration stay in `fcp-host`. |
| `fcp-host::{rollout, resilience, progress, discovery, doctor, supply_chain}` | `fcp-host` | These are root-application orchestration and admin/control-plane surfaces. The host may compose lower-layer semantics here, but it must not become their source of truth. |
| `fcp-sdk::{runtime, streaming, retry}` | `fcp-sdk` | These are connector-author ergonomics and should remain there, provided they stay host-independent and do not smuggle in admin-plane or mesh-placement ownership. |
| `fcp-sdk::migration` | temporary quarantine, then delete | Migration helpers are useful only during cutover. They are not part of the steady-state FCP3 SDK contract. |
| `fwc` direct semantic dependencies on `fcp-core` | replace with host-backed contracts | `fwc` should consume host/admin truth, generated catalogs, and stable RPC/schema projections rather than reaching into low-level semantic crates. |

Two rules follow from this map:

1. If a current module has to be split across two owners, that split must happen explicitly before new features accumulate on top of the old bucket.
2. Re-export convenience is acceptable only after single-owner semantics are established underneath.

#### AJ.6 Current Workspace Disposition

FCP3 SHOULD treat the current workspace as follows:

| Current crate | FCP3 disposition | Reason |
|---------------|------------------|--------|
| `fcp-core` | split, then delete as a top-level semantic bucket | It currently mixes execution, policy, evidence, lifecycle, connector contracts, and support types. That is exactly the ownership blur FCP3 is trying to remove. |
| `fcp-protocol` | survive, but narrow to wire/session/ABI responsibilities | Frame and session logic are real long-term concepts, but they should not absorb manifest or policy semantics. |
| `fcp-store` | survive, but stay purely about durability, quarantine, retention, and repair | Storage is a durable substrate, not a control-plane semantics crate. |
| `fcp-mesh` | survive and become the single owner of placement/mobility/lease coordination, with `fcp-tailscale` as an adapter layer | Mesh topology and placement must have one owner. |
| `fcp-registry` | survive only if it stays focused on source selection, verification, mirroring, and promotion; otherwise split along that boundary | Registry trust and artifact acquisition are real, but must not become another catch-all utility crate. |
| `fcp-sandbox` | survive | Execution-form enforcement remains a first-class boundary in FCP3. |
| `fcp-sdk` | survive | Connector authors still need a stable FCP-facing surface. |
| `fcp-host` | survive | The root supervised application remains fundamental. |
| `fcp-conformance`, `fcp-testkit`, `fcp-cli`, `fwc` | survive | These are product/test surfaces, not accidental architecture. |
| `fcp-oauth`, `fcp-google-discovery`, similar domain crates | survive only as narrow leaf support crates | They are useful when they encode domain specifics rather than generic platform semantics. |
| `fcp-async-core`, `fcp-async-core-macros` | temporary quarantine, then delete | FCP3 is Asupersync-native; compatibility shims must not become permanent architecture. |
| `fcp-streaming`, `fcp-ratelimit`, `fcp-webhook`, `fcp-telemetry` | either narrow to leaf helpers or dissolve into the true owners above | These concepts are real, but top-level crates are justified only if they remain sharply scoped and do not duplicate kernel/host/SDK authority. |
| `fcp-bootstrap`, `fcp-graphql`, other optional surfaces | keep only if they remain clearly outside the semantic core | Optional product surfaces should not dictate the kernel layout. |

#### AJ.7 Litmus Test

A contributor should be able to answer the following without guessing:

- If a concept changes execution semantics, it lives in `fcp-kernel`.
- If it changes allow/deny, taint, approval, or provenance semantics, it lives in `fcp-policy`.
- If it changes what durable proof exists after the fact, it lives in `fcp-evidence`.
- If it changes bytes on the wire, it lives in `fcp-protocol`.
- If it changes connector declarations or provisioning contracts, it lives in `fcp-manifest`.
- If it changes durable object/symbol/quarantine/repair behavior, it lives in `fcp-store`.
- If it changes placement, lease, failover, or mesh topology behavior, it lives in `fcp-mesh`.
- If it changes artifact trust and promotion, it lives in `fcp-registry`.
- If it changes connector supervision or admin orchestration, it lives in `fcp-host`.
- If it changes connector author ergonomics, it lives in `fcp-sdk`.

If the honest answer is "this concept belongs to two crates because it is convenient," the boundary
is wrong and the design should be corrected before more code is written.

### Appendix AK: Interoperability Artifact Inventory and FZPF Schema Surface

The reference distribution SHOULD publish an explicit artifact inventory rather than forcing
implementers to infer conformance surfaces from prose.

At minimum, the inventory SHOULD name files equivalent to:

- `FCP_CDDL_V3.cddl` for canonical durable objects and frame-bound structures,
- `crates/fcp-conformance/src/schemas/FZPF_v0.1.schema.json` for the FZPF schema surface,
- schema files for structured logs, release manifests, traces, and policy bundles,
- golden vectors for decisions, checkpoints, audit heads, revocation heads, FCPC sessions, and FCPS
  symbol envelopes,
- replay transcripts for failover, repair, and stale-frontier denial.

Round-trip requirements:

1. Every listed artifact MUST parse under the reference implementation.
2. Canonical artifacts MUST re-encode to byte-for-byte identical output.
3. Documented object identifiers, signatures, and reason-code projections MUST match the published
   golden expectation.
4. The inventory SHOULD make it obvious which artifacts are normative interoperability surfaces and
   which are informative examples.

### Appendix AL: V3-Only Implementation Phases

These phases are guidance for building the FCP3 platform without drifting back toward dual-stack or
compatibility-first execution. Each phase SHOULD leave the repository in a state where new work can
land on the FCP3 surface directly.

| Phase | Primary Goal | Expected Outputs | Exit Criteria |
|-------|--------------|------------------|---------------|
| 1. Semantic Lock | Freeze the execution, policy, evidence, and crate-boundary vocabulary | stable section terminology, crate graph appendix, conformance artifact inventory | contributors can place a concept in one long-term owner without guessing |
| 2. Durable/Wire Realignment | Align protocol, manifest, store, mesh, and registry contracts to the locked vocabulary | FCPC/FCPS schemas, manifest examples, artifact verification and mirror contracts, replay semantics | no new feature work needs to be expressed through legacy runtime abstractions |
| 3. Host/SDK Convergence | Make host orchestration and connector-author surfaces describe the same reality | host admin/control schemas, SDK app contract, archetype helpers, provisioning session flows | a connector author and an operator can describe one execution without translating mental models |
| 4. Connector/Operator Adoption | Move connector families, CLIs, and evidence tooling onto the host-backed FCP3 surfaces | migrated connector examples, operator transcripts, replay/debug bundles, updated reference workflows | examples and docs no longer teach compatibility-era behavior as normal |
| 5. Cutover and Proof | Delete temporary quarantine surfaces and ship the final conformance story | removed shims, final profiles, golden vectors, interoperability artifacts, aligned docs | the implementation can claim FCP3 without requiring translators, compatibility buckets, or migration-only scaffolding |

Phase rules:

1. A phase is not complete if its examples still teach superseded behavior as if it were a valid
   long-term pattern.
2. Temporary quarantine crates or helpers MUST have an explicit deletion target before the next
   phase begins.
3. Verification artifacts, example transcripts, and operator evidence SHOULD evolve alongside the
   phase outputs rather than being deferred to the end.

## 16. Summary

FCP is a secure connector operating model built from:

- explicit execution authority (`Cx`, regions, budgets, supervision, quiescence),
- zone and provenance enforcement,
- durable receipts, checkpoints, and audit artifacts,
- a typed live control/data/evidence plane,
- durable object distribution and repair across an authenticated mesh,
- a reference crate graph with single-owner boundaries for kernel, policy, evidence, wire, manifest, storage, verification, host, SDK, and connector surfaces,
- mechanized provisioning, placement, and supply-chain verification,
- strong conformance requirements that treat failure behavior as first-class.

The system is designed to be fast, automatable, explainable, and robust under failure without giving up
the strict security boundaries required for real-world AI agent operation.
