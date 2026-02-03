# FCP Model Connectors (Rust) - V2

## Canonical, Spec-Accurate Reference for FCP V2 Connectors

> Purpose: Provide a Rust-focused connector guide aligned exactly to FCP Specification V2.
> Version: 2.0.0
> Status: Draft
> Last Updated: 2026-01-15
> License: MIT
> Canonical Spec: FCP_Specification_V2.md

---

## Table of Contents

1. Scope and Alignment
2. Connector Model and Lifecycle (V2)
   - 2.2 Connector State (NORMATIVE)
3. Control-Plane Protocol (FCP2-SYM)
   - 3.5 Session Authentication (NORMATIVE)
   - 3.6 Control Plane Retention Classes (NORMATIVE)
   - 3.7 Admission Control (NORMATIVE)
4. Canonical Types and Serialization
   - 4.4 ZoneKeyManifest and ObjectIdKey Distribution
5. Zones, Approval Tokens, Provenance, and Taint
   - 5.2 Unified Approval Token
   - 5.3 Provenance and Taint (with taint_reductions)
6. Capability System
   - 6.3 Network Constraints (with CIDR deny, Egress Proxy)
7. Invoke, Receipts, and Event Envelopes
8. Streaming, Replay, and Acks
9. Error Taxonomy
10. Agent Integration (Introspection + MCP)
11. Connector Manifest (TOML) and Embedding
12. Sandbox Profiles and Enforcement
13. Automation Recipes and Provisioning Interface
14. Registry and Supply Chain
    - 14.3 Supply Chain Attestations
15. Lifecycle Management and Revocation
    - 15.3 Revocation (RevocationEvent, RevocationHead, RevocationRegistry)
16. Device-Aware Execution and Execution Leases
    - 16.1 Execution Leases (NORMATIVE)
    - 16.2 Device Profiles and Execution Planner
    - 16.3 Device Requirements and Preferences
17. Observability and Audit
    - 17.1 Metrics (NORMATIVE)
    - 17.2 Structured Logs
    - 17.3 Audit Chain (AuditEvent, AuditHead, ZoneCheckpoint)
18. Connector Archetypes (V2) and Patterns
19. Rust Connector Skeleton (SDK-aligned)
20. Conformance Checklist (Connector)

---

## 1. Scope and Alignment

- This document covers connector-facing requirements from FCP Specification V2.
- Canonical protocol mode is FCP2-SYM (FCPS frames + RaptorQ). Backwards compatibility with FCP1/JSON-RPC is explicitly out of scope.
- All normative language uses MUST/SHOULD/MAY in the RFC 2119 sense.

---

## 2. Connector Model and Lifecycle (V2)

Connectors are sandboxed binaries that bridge external services to FCP:

```rust
/// Connector definition (NORMATIVE)
pub struct Connector {
    /// Unique identifier
    pub id: ConnectorId,

    /// Human-readable name
    pub name: String,

    /// Version
    pub version: Version,

    /// Runtime format
    pub format: ConnectorFormat,

    /// Connector archetypes
    pub archetypes: Vec<ConnectorArchetype>,

    /// Operations provided
    pub operations: Vec<Operation>,

    /// Events emitted
    pub events: Vec<EventType>,

    /// Required capabilities
    pub required_caps: Vec<CapabilityId>,

    /// Optional capabilities
    pub optional_caps: Vec<CapabilityId>,

    /// Forbidden capabilities
    pub forbidden_caps: Vec<CapabilityId>,
}

pub enum ConnectorArchetype {
    /// Sends and receives messages
    Bidirectional,
    /// Emits events (read-only)
    Streaming,
    /// Executes operations (write)
    Operational,
    /// Stores/retrieves data
    Storage,
    /// Provides knowledge/search
    Knowledge,
}

/// Connector runtime format (NORMATIVE)
pub enum ConnectorFormat {
    /// Native executable (ELF/Mach-O/PE)
    /// Requires OS-level sandboxing (seccomp, landlock, AppArmor).
    Native,
    /// WASI module (WASM) executed under a WASI runtime with hostcalls gated by capabilities.
    /// Provides portable, capability-based sandbox consistent across OSes.
    /// RECOMMENDED for high-risk connectors (financial, credential-handling, external API).
    Wasi,
}

/// WASI Format Guidance (NORMATIVE for risk classification):
///
/// Connectors handling SafetyTier::Dangerous operations or high-value secrets
/// SHOULD use WASI format unless performance requirements preclude it.
///
/// Benefits:
/// - Memory isolation: WASM linear memory prevents buffer overflow exploits
/// - Capability-gated hostcalls: All syscalls are explicit capability grants
/// - Cross-platform consistency: Same binary, same sandbox semantics everywhere
///
/// WASI Runtime Requirements (NORMATIVE):
/// - Runtime MUST implement WASI preview2 or later
/// - Network operations MUST be gated by NetworkConstraints
/// - File operations MUST be scoped to granted directory capabilities
```

Connector lifecycle:

```
DISCOVERED -> VERIFIED -> INSTALLED -> CONFIGURED -> ACTIVE
         -> rejected                      -> FAILED
                                          -> PAUSED
                                          -> STOPPED
```

### 2.2 Connector State (NORMATIVE)

Connectors with polling/cursors/dedup caches MUST externalize their canonical state into the mesh.
Local `$CONNECTOR_STATE` is a **cache only** — the authoritative state lives as mesh objects.

This enables:
- **Safe failover**: Another node can resume from the last committed state
- **Resumable polling**: Cursors survive node restarts and migrations
- **Deterministic migration semantics**: State is explicit, not implicit in process memory

```rust
/// Connector state model (NORMATIVE)
pub enum ConnectorStateModel {
    /// No mesh-persisted state required
    Stateless,
    /// Exactly one writer enforced via Lease (ConnectorStateWrite purpose)
    SingletonWriter,
    /// Multi-writer state using CRDT deltas + periodic snapshots
    Crdt { crdt_type: CrdtType },
}

/// CRDT type for multi-writer state (NORMATIVE)
pub enum CrdtType {
    LwwMap,      // Last-write-wins map
    OrSet,       // Observed-remove set
    GCounter,    // Grow-only counter
    PnCounter,   // PN-Counter
}

/// Stable root for connector state (NORMATIVE)
pub struct ConnectorStateRoot {
    pub header: ObjectHeader,
    pub connector_id: ConnectorId,
    pub instance_id: Option<InstanceId>,
    pub zone_id: ZoneId,
    /// State model for this connector (NORMATIVE)
    pub model: ConnectorStateModel,
    /// Latest ConnectorStateObject (or None if no state yet)
    pub head: Option<ObjectId>,
}

/// Append-only connector state update (NORMATIVE)
pub struct ConnectorStateObject {
    pub header: ObjectHeader,
    pub connector_id: ConnectorId,
    pub instance_id: Option<InstanceId>,
    pub zone_id: ZoneId,
    pub prev: Option<ObjectId>,
    /// Monotonic sequence for ordering
    pub seq: u64,
    /// Canonical connector-specific state blob
    pub state_cbor: Vec<u8>,
    pub updated_at: u64,
    /// Signature by executing node
    pub signature: Signature,
}

/// CRDT delta update (NORMATIVE when ConnectorStateModel::Crdt)
pub struct ConnectorStateDelta {
    pub header: ObjectHeader,
    pub connector_id: ConnectorId,
    pub instance_id: Option<InstanceId>,
    pub zone_id: ZoneId,
    pub crdt_type: CrdtType,
    /// Delta payload (canonical CBOR; type depends on crdt_type)
    pub delta_cbor: Vec<u8>,
    pub applied_at: u64,
    pub applied_by: TailscaleNodeId,
    pub signature: Signature,
}
```

**Cursor State Schema (NORMATIVE for polling connectors):**

Polling connectors SHOULD store cursor/offset state in `ConnectorStateObject.state_cbor` using
canonical CBOR (no schema hash prefix). The canonical schema is:

```rust
/// Canonical cursor state payload (stored in ConnectorStateObject.state_cbor)
pub struct CursorState {
    pub offset: Option<i64>,        // e.g., update_id + 1
    pub last_seen_id: Option<String>,
    pub watermark: Option<u64>,     // Unix seconds
}
```

**Monotonicity rules:**
- `offset` MUST be non-decreasing.
- `watermark` MUST be non-decreasing if present.
- `last_seen_id` SHOULD only move forward per connector-specific ordering.

**Single-Writer Semantics (NORMATIVE):**

For any connector declaring `singleton_writer = true` in its manifest, the MeshNode MUST ensure
only one node writes `ConnectorStateObject` updates at a time. This is enforced using
`Lease` (with `LeasePurpose::ConnectorStateWrite`) over `ConnectorStateRoot.object_id`.

```toml
# In connector manifest
[connector]
singleton_writer = true  # Legacy: equivalent to model = "singleton_writer"

[connector.state]
# "stateless" | "singleton_writer" | "crdt"
model = "singleton_writer"
# NORMATIVE: State schema versioning for safe upgrades
state_schema_version = "1"
# Optional migration hint (command or script reference)
# migration_hint = "telegram/state_migrate_v0_to_v1"
# For CRDT models:
# crdt_type = "lww_map"
# snapshot_every_updates = 5000
# snapshot_every_bytes = 1048576
```

This prevents:
- Double-polling the same messages
- Duplicate event processing
- Cursor conflicts during migration

**State Snapshots (NORMATIVE when state chains exceed thresholds):**

Append-only state chains grow forever and become a performance drag for cold start, migration,
GC traversal, and debugging. Periodic snapshots bound replay cost.

```rust
/// Periodic snapshot to bound replay cost (NORMATIVE when chains exceed thresholds)
pub struct ConnectorStateSnapshot {
    pub header: ObjectHeader,
    pub connector_id: ConnectorId,
    pub instance_id: Option<InstanceId>,
    pub zone_id: ZoneId,
    /// Latest state object included in this snapshot
    pub covers_head: ObjectId,
    pub covers_seq: u64,
    /// Full canonical state at covers_head
    pub state_cbor: Vec<u8>,
    pub snapshotted_at: u64,
    pub signature: Signature,
}
```

**Compaction Rule (NORMATIVE):**
- MeshNode SHOULD create a snapshot every N updates or M bytes (configurable).
- After the snapshot is replicated to placement targets, MeshNode MAY GC older state objects
  strictly before `covers_head`, unless required by audit/policy pins.

**Fork Detection (NORMATIVE for singleton_writer):** If two different `ConnectorStateObject` share the
same `prev` (competing seq), nodes MUST treat this as a safety incident:
1. Pause connector execution
2. Require manual resolution OR automated "choose-by-lease" recovery
3. Log the fork event for audit

---

## 3. Control-Plane Protocol (FCP2-SYM)

### 3.1 Protocol Modes

| Mode | Encoding | Use Case |
|------|----------|----------|
| FCP2-SYM (Canonical) | FCPS frames + RaptorQ | Production mesh-native |

### 3.2 Message Types (Wire Protocol)

| Type | Direction | Purpose |
|------|-----------|---------|
| `handshake` | Hub -> Connector | Establish connection |
| `handshake_ack` | Connector -> Hub | Confirm connection |
| `introspect` | Hub -> Connector | Query operations |
| `configure` | Hub -> Connector | Apply configuration |
| `invoke` | Hub -> Connector | Execute operation |
| `response` | Connector -> Hub | Operation result |
| `subscribe` | Hub -> Connector | Subscribe to events |
| `event` | Connector -> Hub | Async event |
| `health` | Hub <-> Connector | Health check |
| `shutdown` | Hub -> Connector | Graceful shutdown |
| `symbol_request` | Any -> Any | Request symbols (mesh) |
| `symbol_delivery` | Any -> Any | Deliver symbols (mesh) |
| `decode_status` | Any -> Any | Feedback: received/needed symbols |
| `symbol_ack` | Any -> Any | Stop condition for delivery |

**FCPS Frame Format (114-byte header):**

```
Bytes 0-3:    Magic (0x46 0x43 0x50 0x53 = "FCPS")
Bytes 4-5:    Version (u16 LE)
Bytes 6-7:    Flags (u16 LE)
Bytes 8-11:   Symbol Count (u32 LE)
Bytes 12-15:  Total Payload Length (u32 LE)
Bytes 16-47:  Object ID (32 bytes)
Bytes 48-49:  Symbol Size (u16 LE, default 1024)
Bytes 50-57:  Zone Key ID (8 bytes, for rotation)
Bytes 58-89:  Zone ID hash (32 bytes, BLAKE3; see ZoneIdHash)
Bytes 90-97:  Epoch ID (u64 LE)
Bytes 98-105: Sender Instance ID (u64 LE, reboot-safety for deterministic nonces)
Bytes 106-113: Frame Seq (u64 LE, per-sender monotonic counter)
Bytes 114+:   Symbol payloads (concatenated)
NOTE: No separate checksum. Integrity provided by per-symbol AEAD tags + per-frame session MAC.
```

**Symbol Envelope (NORMATIVE):**

```rust
/// Full symbol envelope with encryption (NORMATIVE)
pub struct SymbolEnvelope {
    /// Content address of complete object
    pub object_id: ObjectId,
    /// Encoding Symbol ID
    pub esi: u32,
    /// Source symbols needed (K)
    pub k: u16,
    /// Symbol payload (encrypted)
    pub data: Vec<u8>,
    /// Zone for key derivation
    pub zone_id: ZoneId,
    /// Zone key ID (for key rotation - enables deterministic decryption)
    pub zone_key_id: [u8; 8],
    /// Epoch for replay protection
    pub epoch_id: EpochId,
    /// Sender node id (NORMATIVE for per-sender subkeys)
    pub source_id: TailscaleNodeId,
    /// Sender instance ID (NORMATIVE for reboot safety - deterministic nonces)
    pub sender_instance_id: u64,
    /// Per-sender monotonic frame sequence (NORMATIVE)
    pub frame_seq: u64,
    /// AEAD authentication tag
    pub auth_tag: [u8; 16],
}
```

NORMATIVE: per-symbol nonce is `frame_seq_le || esi_le`. Encrypt/decrypt uses a per-sender subkey
derived from the zone key and `source_id`.

**Per-Sender Subkeys and Deterministic Nonces (NORMATIVE):**

Each sender MUST maintain a monotonic `frame_seq` per (zone_id, zone_key_id) and MUST NOT reuse it.
Combined with per-sender subkeys derived from the zone key, this eliminates nonce-collision risk:

```rust
/// Derive AEAD nonce deterministically (NORMATIVE).
///
/// - ChaCha20-Poly1305 (12-byte): nonce12 = frame_seq_le || esi_le
/// - XChaCha20-Poly1305 (24-byte): nonce24 = sender_instance_id_le || frame_seq_le || esi_le || 0u32
fn derive_nonce12(frame_seq: u64, esi: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..8].copy_from_slice(&frame_seq.to_le_bytes());
    nonce[8..12].copy_from_slice(&esi.to_le_bytes());
    nonce
}

fn derive_nonce24(sender_instance_id: u64, frame_seq: u64, esi: u32) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[0..8].copy_from_slice(&sender_instance_id.to_le_bytes());
    nonce[8..16].copy_from_slice(&frame_seq.to_le_bytes());
    nonce[16..20].copy_from_slice(&esi.to_le_bytes());
    nonce[20..24].copy_from_slice(&0u32.to_le_bytes());
    nonce
}

impl ZoneKey {
    /// Derive per-sender subkey (NORMATIVE)
    ///
    /// sender_key = HKDF-SHA256(
    ///     ikm = zone_symmetric_key,
    ///     salt = zone_key_id,
    ///     info = "FCP2-SENDER-KEY-V1" || sender_node_id || sender_instance_id_le
    /// )
    /// The sender_instance_id ensures that if a sender reboots and resets frame_seq,
    /// it will derive a fresh subkey, preventing nonce reuse across reboots.
    pub fn derive_sender_subkey(&self, sender: &TailscaleNodeId, sender_instance_id: u64) -> [u8; 32];
}
```

**Why per-sender subkeys + deterministic nonces:**
- 64-bit random nonces have birthday collision risk over long-running systems with many senders
- Per-sender subkeys eliminate cross-sender nonce collision (keys differ per sender)
- `sender_instance_id` (random u64 at startup) makes subkeys reboot-safe: if a sender restarts
  and frame_seq resets to 0, the new instance_id yields a different subkey, preventing nonce reuse
- Deterministic `frame_seq` avoids RNG dependence and is testable
- No per-frame random generation overhead

### 3.3 Standard Methods

Connectors MUST implement:

| Method | Purpose |
|--------|---------|
| `handshake` | Bind to zone, negotiate protocol |
| `describe` | Return manifest metadata |
| `introspect` | Return operations, events, resources |
| `capabilities` | Return full catalog |
| `configure` | Apply configuration |
| `invoke` | Execute operation |
| `health` | Report readiness |
| `shutdown` | Graceful termination |

Connectors that emit events are expected to support `subscribe` and `event` control-plane objects.

### 3.4 Control-Plane as Objects (NORMATIVE)

All control-plane messages (handshake/introspect/configure/invoke/response/subscribe/event/health/shutdown)
MUST be represented as canonical CBOR objects with SchemaId and ObjectId.

```rust
/// Control plane object wrapper (NORMATIVE)
pub struct ControlPlaneObject {
    pub header: ObjectHeader,
    pub body: Vec<u8>, // canonical CBOR (schema-prefixed)
}

/// Retention class for control plane messages (NORMATIVE)
pub enum ControlPlaneRetention {
    /// Must be stored (invoke, response, receipts, approvals, audit)
    Required,
    /// May be ephemeral (health, decode_status, symbol_ack)
    Ephemeral,
}
```

Transport options:

1. Local/IPC: canonical CBOR bytes over the connector transport.
2. Mesh: encoded to symbols and sent inside FCPS frames with `FrameFlags::CONTROL_PLANE`.

When `FrameFlags::CONTROL_PLANE` is set, receivers MUST:
1. Verify checksum
2. Decrypt symbols
3. Reconstruct the object payload (RAW chunking or RaptorQ)
4. Verify schema
5. Store the object if retention class is Required; otherwise MAY discard after processing

**FCPC Control Plane Framing (NORMATIVE):**

While FCPS handles high-throughput symbol delivery, FCPC provides reliable, ordered, backpressured framing for control-plane objects. FCPC uses the session's negotiated `k_ctx` symmetric key for AEAD encryption/authentication:

```rust
/// FCPC frame (control plane) (NORMATIVE)
pub struct FcpcFrame {
    pub seq: u64,           // Monotonic for ordering and ack
    pub ack: Option<u64>,   // Piggyback ack for received frames
    pub payload: Vec<u8>,   // AEAD-encrypted control plane object
    pub tag: [u8; 16],      // ChaCha20-Poly1305 tag (k_ctx, nonce=seq)
}
```

This enables secure invoke/response/receipt exchanges without per-message Ed25519 signatures.

### 3.5 Session Authentication (NORMATIVE)

Ed25519 signatures per data-plane frame are too expensive when frames are near MTU (often ~1 symbol/frame).
FCP authenticates data-plane FCPS frames via a **session**:

1. A one-time handshake authenticated by attested node signing keys
2. Session-key derivation (X25519 ECDH + HKDF) producing directional MAC keys
3. Per-frame MAC (HMAC-SHA256 or BLAKE3, negotiated) + monotonic sequence for anti-replay

**SECURITY NOTE (NORMATIVE):** Poly1305 is a one-time authenticator; using one Poly1305 key across
multiple frames is cryptographically insecure. FCP V2 therefore uses HMAC-SHA256 or BLAKE3-keyed
for session MACs and reserves Poly1305 for AEAD contexts only (where nonce uniqueness is enforced).

```rust
/// Session crypto suite negotiation (NORMATIVE)
pub enum SessionCryptoSuite {
    /// X25519 + HKDF-SHA256 + HMAC-SHA256 (tag truncated to 16 bytes)
    Suite1,
    /// X25519 + HKDF-SHA256 + BLAKE3-keyed (tag truncated to 16 bytes)
    Suite2,
}

/// Session handshake: initiator → responder
pub struct MeshSessionHello {
    pub from: TailscaleNodeId,
    pub to: TailscaleNodeId,
    pub eph_pubkey: X25519PublicKey,
    /// Random nonce for replay protection (NORMATIVE)
    pub nonce: [u8; 16],
    pub timestamp: u64,
    /// Supported crypto suites (ordered by preference)
    pub suites: Vec<SessionCryptoSuite>,
    /// Node signature over transcript (NORMATIVE)
    /// transcript = "FCP2-HELLO-V1" || from || to || eph_pubkey || nonce || timestamp || suites
    pub signature: Signature,
}

/// Session handshake: responder → initiator
pub struct MeshSessionAck {
    pub from: TailscaleNodeId,
    pub to: TailscaleNodeId,
    pub eph_pubkey: X25519PublicKey,
    /// Random nonce for replay protection (NORMATIVE)
    pub nonce: [u8; 16],
    pub session_id: [u8; 16],
    /// Selected crypto suite
    pub suite: SessionCryptoSuite,
    pub timestamp: u64,
    /// Node signature over full handshake transcript (NORMATIVE)
    /// transcript = "FCP2-ACK-V1" || from || to || eph_pubkey || nonce || session_id ||
    ///              suite || timestamp || hello.eph_pubkey || hello.nonce
    pub signature: Signature,
}

/// Session key derivation (NORMATIVE)
///
/// prk = HKDF-SHA256(
///     ikm = ECDH(initiator_eph, responder_eph),
///     salt = session_id,
///     info = "FCP2-SESSION-V1" || initiator_node_id || responder_node_id ||
///            hello_nonce || ack_nonce
/// )
/// Including both nonces binds derived keys to this specific handshake.
///
/// keys = HKDF-Expand(prk, info="FCP2-SESSION-KEYS-V1", L=96) split as:
/// - k_mac_i2r (32 bytes): MAC key for initiator → responder
/// - k_mac_r2i (32 bytes): MAC key for responder → initiator
/// - k_ctx     (32 bytes): reserved for future header/control-plane AEAD

/// Authenticated FCPS frame (NORMATIVE)
pub struct AuthenticatedFcpsFrame {
    pub frame: FcpsFrame,
    pub source_id: TailscaleNodeId,
    pub session_id: [u8; 16],
    /// Monotonic sequence for anti-replay
    pub seq: u64,
    /// MAC over: session_id || direction || seq || frame_bytes
    /// - Suite1: HMAC-SHA256(k_mac_dir, ...) truncated to 16 bytes
    /// - Suite2: BLAKE3(keyed=k_mac_dir, ...) truncated to 16 bytes
    pub mac: [u8; 16],
}

/// Replay protection policy (NORMATIVE defaults)
pub struct SessionReplayPolicy {
    /// Allow limited reordering; MUST be bounded
    pub max_reorder_window: u64,       // default: 128
    /// Rekey periodically for operational hygiene and suite agility
    pub rekey_after_frames: u64,       // default: 1_000_000_000
    /// Rekey after elapsed time to avoid pathological long-lived sessions
    pub rekey_after_seconds: u64,      // default: 86400 (24 hours)
    /// Rekey after cumulative bytes to bound key exposure
    pub rekey_after_bytes: u64,        // default: 1_099_511_627_776 (1 TiB)
}
```

**Why session MACs instead of per-frame signatures:**
- Ed25519 signing is expensive at scale (especially mobile)
- AEAD already provides per-symbol cryptographic integrity
- Session establishment amortizes signature cost over many frames
- Preserves "cryptographic attribution independent of transport" goal

Signed frames MAY still be used for bootstrap/degraded mode, but high-throughput delivery MUST support session MACs.

### 3.6 Control Plane Retention Classes (NORMATIVE)

| Must Be Stored | May Be Ephemeral |
|----------------|------------------|
| invoke, response | health |
| receipts | handshake, handshake_ack |
| approvals (elevation, declassification) | decode_status |
| secret access | symbol_ack |
| revocations | introspect |
| audit events/heads | configure |

### 3.7 Admission Control (NORMATIVE)

MeshNodes MUST implement admission control to prevent DoS:
- Per-peer inbound bytes/symbols
- Failed decrypt/MAC counters
- Bounded concurrent decodes
- Bounded gossip reconciliation work

```rust
/// Per-peer resource budget (NORMATIVE)
pub struct PeerBudget {
    pub max_bytes_per_min: u64,         // default: 64MB/min
    pub max_symbols_per_min: u32,       // default: 200_000/min
    pub max_failed_auth_per_min: u32,   // default: 100/min
    pub max_inflight_decodes: u32,      // default: 32
    pub max_decode_cpu_ms_per_min: u64, // default: 5_000ms/min
}

/// Admission policy (NORMATIVE)
pub struct AdmissionPolicy {
    pub per_peer: PeerBudget,
    /// If true, unauthenticated SymbolRequest is rejected
    /// (default: true except z:public ingress)
    pub require_authenticated_requests: bool,
}

impl MeshNode {
    /// Check peer budget before processing (NORMATIVE)
    fn check_admission(&self, peer: &TailscaleNodeId, bytes: u64) -> Result<(), AdmissionError> {
        let budget = self.peer_budgets.get_or_default(peer);
        budget.check_bytes(bytes)?;
        budget.check_rate_limits()?;
        Ok(())
    }
}
```

**Anti-Amplification Rule (NORMATIVE):** MeshNodes MUST NOT send more than N symbols in response
unless the requester is authenticated (session MAC or node signature) AND the request includes a
bounded missing-hint (e.g., `DecodeStatus.missing_hint`) or comparable proof-of-need.

---

## 4. Canonical Types and Serialization

### 4.1 ObjectId and SchemaId

```rust
/// Content-addressed identifier (NORMATIVE)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectId([u8; 32]);

/// Secret per-zone object-id key (NORMATIVE)
pub struct ObjectIdKey(pub [u8; 32]);

impl ObjectId {
    /// Create ObjectId from content, zone, and schema (NORMATIVE for security objects)
    pub fn new(content: &[u8], zone: &ZoneId, schema: &SchemaId, key: &ObjectIdKey) -> Self {
        let mut h = blake3::Hasher::new_keyed(&key.0);
        h.update(b"FCP2-OBJECT-V2");
        h.update(zone.as_bytes());
        h.update(schema.hash().as_bytes());
        h.update(content);
        Self(*h.finalize().as_bytes())
    }

    /// Unscoped content hash (NON-NORMATIVE; MUST NOT be used for security objects)
    pub fn from_unscoped_bytes(content: &[u8]) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(b"FCP2-CONTENT-V2");
        h.update(content);
        Self(*h.finalize().as_bytes())
    }
}
```

Security objects MUST use `ObjectId::new(content, zone, schema, key)`:

- CapabilityObject, CapabilityToken, PolicyObject, RevocationObject
- AuditEvent, AuditHead, SecretObject, ZoneKeyManifest
- DeviceEnrollment, NodeKeyAttestation
- Any object used as an authority anchor or enforcement input

`ObjectIdKey` is distributed to zone members via `ZoneKeyManifest` and remains stable across
routine zone_key rotations.

### 4.2 Canonical CBOR Serialization

```rust
/// Canonical CBOR serialization (NORMATIVE)
pub struct CanonicalSerializer;

impl CanonicalSerializer {
    pub fn serialize<T: Serialize>(value: &T, schema: &SchemaId) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(schema.hash().as_bytes());
        ciborium::ser::into_writer_canonical(value, &mut buf)
            .expect("Serialization cannot fail for valid types");
        buf
    }

    pub fn deserialize<T: DeserializeOwned>(
        data: &[u8],
        expected_schema: &SchemaId,
    ) -> Result<T, SerializationError> {
        if data.len() < 32 {
            return Err(SerializationError::SchemaMismatch);
        }
        let got = &data[0..32];
        if got != expected_schema.hash().as_bytes() {
            return Err(SerializationError::SchemaMismatch);
        }
        ciborium::de::from_reader(&data[32..])
            .map_err(SerializationError::CborError)
    }
}
```

### 4.3 Object Header and Placement

```rust
/// Universal object header (NORMATIVE)
///
/// ObjectId is derived from the canonical encoding of (header, body).
/// The header MUST NOT embed `object_id`.
pub struct ObjectHeader {
    pub schema: SchemaId,
    pub zone_id: ZoneId,
    pub created_at: u64,
    pub provenance: Provenance,
    /// Same-zone refs (participate in GC reachability)
    pub refs: Vec<ObjectId>,
    /// Cross-zone refs (audit/provenance only, no GC effect)
    pub foreign_refs: Vec<ObjectId>,
    pub ttl_secs: Option<u64>,
    /// Optional placement policy for symbol distribution (NORMATIVE when present)
    pub placement: Option<ObjectPlacementPolicy>,
}

/// Object placement policy (NORMATIVE when used)
///
/// Uses fixed-point basis points (bps) instead of floating-point to avoid
/// float parsing differences across languages and policy comparison bugs.
pub struct ObjectPlacementPolicy {
    pub min_nodes: u8,
    /// Maximum fraction of symbols any single node may hold (0..=10000 bps)
    pub max_node_fraction_bps: u16,
    /// Preferred device selectors (typed to prevent implementation divergence)
    pub preferred_devices: Vec<DeviceSelector>,
    /// Hard exclusions (typed to prevent implementation divergence)
    pub excluded_devices: Vec<DeviceSelector>,
    /// Target coverage ratio in basis points (10000 = 1.0x, 15000 = 1.5x)
    pub target_coverage_bps: u32,
}

/// Typed device selector for placement policies (NORMATIVE)
pub enum DeviceSelector {
    /// Match devices by tag (e.g., Tag("fcp-private"))
    Tag(String),
    /// Match devices by class (e.g., Class("desktop"))
    Class(String),
    /// Match specific node by Tailscale ID
    NodeId(NodeId),
    /// Match by zone membership
    Zone(ZoneId),
    /// Match devices with specific capability
    HasCapability(String),
}
```

**GC Invariant (NORMATIVE):** Objects reachable via `refs` from any GC root are retained. `foreign_refs` do NOT create GC edges—they enable cross-zone provenance and audit trails without coupling zone lifecycles.

Retention is node-local storage metadata and is not part of the content-addressed header.
Mesh nodes periodically evaluate symbol coverage against `ObjectPlacementPolicy` and perform
background repair to maintain target coverage.

### 4.4 ZoneKeyManifest and ObjectIdKey Distribution

ZoneKey manifests distribute both the active zone key and the zone's ObjectIdKey.

```rust
/// Zone key manifest (NORMATIVE)
pub struct ZoneKeyManifest {
    pub header: ObjectHeader,
    pub zone_id: ZoneId,
    pub zone_key_id: [u8; 8],
    pub algorithm: ZoneKeyAlgorithm,
    pub valid_from: u64,
    pub valid_until: Option<u64>,
    pub prev_zone_key_id: Option<[u8; 8]>,
    /// ObjectIdKey material for this zone (NORMATIVE)
    pub object_id_key_id: [u8; 8],
    pub wrapped_object_id_keys: Vec<WrappedObjectIdKey>,
    /// Optional rekey policy for zone key rotation and past secrecy
    pub rekey_policy: Option<ZoneRekeyPolicy>,
    pub wrapped_keys: Vec<WrappedZoneKey>,
    pub signature: Signature,
}

pub enum ZoneKeyAlgorithm {
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

/// HPKE sealed box per RFC 9180 (NORMATIVE; see FCP Specification §3.6.1)
///
/// All wrapped keys in FCP use HPKE single-shot seal with AAD = canonical CBOR of
/// context (e.g., the containing struct without sealed_key). This provides
/// algorithm agility and explicit algorithm identifiers for future-proofing.
pub struct HpkeSealedBox {
    /// RFC 9180 identifiers for algorithm agility
    pub kem_id: u16,  // e.g., 0x0020 for X25519
    pub kdf_id: u16,  // e.g., 0x0001 for HKDF-SHA256
    pub aead_id: u16, // e.g., 0x0001 for AES-128-GCM
    /// HPKE encapsulated key (enc)
    pub enc: Vec<u8>,
    /// AEAD ciphertext (includes auth tag per HPKE)
    pub ct: Vec<u8>,
}

pub struct WrappedZoneKey {
    pub node_id: TailscaleNodeId,
    /// Which node_enc_pubkey was used (supports node key rotation)
    pub node_enc_kid: [u8; 8],
    /// HPKE sealed box containing the 32-byte zone symmetric key (NORMATIVE; see §3.6.1)
    pub sealed_key: HpkeSealedBox,
}

pub struct WrappedObjectIdKey {
    pub node_id: TailscaleNodeId,
    pub node_enc_kid: [u8; 8],
    /// HPKE sealed box containing the 32-byte ObjectIdKey (NORMATIVE; see §3.6.1)
    pub sealed_key: HpkeSealedBox,
}

/// Zone rekey policy for rotation and past secrecy (NORMATIVE when present)
pub struct ZoneRekeyPolicy {
    /// If true, nodes MUST derive and delete epoch keys per policy
    pub epoch_ratchet_enabled: bool,
    /// Number of seconds of overlap to tolerate clock skew and delayed frames
    pub overlap_secs: u64,
    /// Max epochs to retain for delayed/offline peers (bounded memory)
    pub retain_epochs: u32,
    /// If true, automatically rotate zone_key and rewrap to current members when
    /// any node is removed from the zone
    pub rewrap_on_membership_change: bool,
}

/// Zone key distribution mode (NORMATIVE when MLS supported)
///
/// Zone keys are **randomly generated** symmetric keys, NOT derived from owner secret material.
/// HKDF is used for **subkey derivation** (per-sender subkeys), not for deriving zone keys.
pub enum ZoneKeyMode {
    /// Baseline: symmetric keys distributed via owner-signed manifests
    /// Keys are randomly generated and sealed to each node's X25519 key
    ManifestDistributed,

    /// Optional upgrade: MLS/TreeKEM group key agreement for post-compromise security
    /// Epoch secrets rotate on membership changes
    MlsTreeKem,
}

/// Zone security profile (NORMATIVE when present)
///
/// Controls zone key distribution mode and post-compromise security requirements.
pub struct ZoneSecurityProfile {
    pub zone_id: ZoneId,
    pub key_mode: ZoneKeyMode,
    /// Require PCS for this zone (default true for z:owner if MLS enabled)
    pub require_pcs: bool,
    /// Maximum epoch duration in seconds (bounds exposure window)
    pub max_epoch_secs: u64,
}

impl Default for ZoneSecurityProfile {
    fn default() -> Self {
        Self {
            zone_id: ZoneId::private(),
            key_mode: ZoneKeyMode::ManifestDistributed,
            require_pcs: false,
            max_epoch_secs: 86400, // 24 hours
        }
    }
}
```

---

## 5. Zones, Approval Tokens, Provenance, and Taint

### 5.1 Zone

```rust
/// Zone with cryptographic properties (NORMATIVE)
pub struct Zone {
    pub id: ZoneId,
    pub name: String,
    pub integrity_level: u8,
    pub confidentiality_level: u8,
    pub active_zone_key_id: [u8; 8],
    pub tailscale_tag: String,
    pub parent: Option<ZoneId>,
    pub policy: ZonePolicy,
    /// UDP/TCP port for symbol frames in this zone (NORMATIVE for port-gating)
    pub symbol_port: u16,
    /// UDP/TCP port for gossip/control-plane objects in this zone (NORMATIVE for port-gating)
    pub control_port: u16,
}
```

**Zone Port-Gating (NORMATIVE):**

MeshNode MUST expose per-zone ports for symbol and control traffic. Tailscale ACLs gate zone
membership to those ports, providing defense-in-depth without encoding the full lattice in ACLs.

### 5.2 Unified Approval Token

The unified ApprovalToken replaces separate elevation and declassification tokens with a single type.
ApprovalToken is a first-class mesh object with ObjectHeader, enabling graph-based audit trails
and GC integration. This simplifies: UI prompting, audit, verification code paths, and policy.

```rust
/// Unified approval token (NORMATIVE)
pub struct ApprovalToken {
    /// Standard mesh object header (NORMATIVE)
    /// ObjectId is derived from (header, body) per mesh object rules.
    pub header: ObjectHeader,
    pub scope: ApprovalScope,
    /// Human-readable justification (UI + audit)
    pub justification: String,
    pub approved_by: PrincipalId,
    pub approved_at: u64,
    pub expires_at: u64,
    pub signature: Signature,
}

/// Approval scope (NORMATIVE)
pub enum ApprovalScope {
    /// Integrity elevation for a specific operation + provenance
    Elevation {
        operation: OperationId,
        original_provenance: Provenance,
    },
    /// Confidentiality downgrade for specific objects
    Declassification {
        from_zone: ZoneId,
        to_zone: ZoneId,
        object_ids: Vec<ObjectId>,
    },
    /// Scoped execution context for connector operations
    Execution {
        connector_id: ConnectorId,
        method_pattern: String,
        /// NORMATIVE: For Interactive approvals on Risky/Dangerous ops, this MUST be set
        request_object_id: Option<ObjectId>,
        /// NORMATIVE: BLAKE3 hash of canonical input bytes (schema-prefixed CBOR)
        input_hash: Option<[u8; 32]>,
        /// Typed constraints (interop-safe); replaces free-form string
        input_constraints: Vec<InputConstraint>,
    },
}

/// Input constraint (NORMATIVE)
/// JSON Pointer (RFC 6901) only; JSONPath/regex are forbidden for interop stability.
pub struct InputConstraint {
    pub json_pointer: String,
    pub op: ConstraintOp,
    pub value: Value,
}

/// Constraint operators for input validation
pub enum ConstraintOp {
    Eq, Neq, In, NotIn, Prefix, Suffix, Contains,
}

impl ApprovalToken {
    /// Default TTL: 5 minutes
    pub const DEFAULT_TTL_SECS: u64 = 300;

    /// Verify token is valid
    pub fn verify(&self, trust_anchors: &TrustAnchors) -> Result<(), VerifyError> {
        // Check expiry
        if current_timestamp() > self.expires_at {
            return Err(VerifyError::Expired);
        }

        // Verify approver authority
        let approver_key = trust_anchors.get_principal_key(&self.approved_by)?;
        approver_key.verify(&self.signable_bytes(), &self.signature)?;

        // Verify approver has appropriate authority for the scope
        match &self.scope {
            ApprovalScope::Elevation { .. } => {
                if !trust_anchors.can_approve_elevation(&self.approved_by) {
                    return Err(VerifyError::InsufficientAuthority);
                }
            }
            ApprovalScope::Declassification { from_zone, to_zone, .. } => {
                if !trust_anchors.can_approve_declassification(&self.approved_by, from_zone, to_zone) {
                    return Err(VerifyError::InsufficientAuthority);
                }
            }
            ApprovalScope::Execution { connector_id, .. } => {
                if !trust_anchors.can_approve_execution(&self.approved_by, connector_id) {
                    return Err(VerifyError::InsufficientAuthority);
                }
            }
        }

        Ok(())
    }

    /// Create an elevation approval
    pub fn create_elevation(
        operation: OperationId,
        provenance: &Provenance,
        approver: &Identity,
        justification: &str,
        ttl: Option<u64>,
    ) -> Self;

    /// Create a declassification approval
    pub fn create_declassification(
        from_zone: ZoneId,
        to_zone: ZoneId,
        object_ids: Vec<ObjectId>,
        approver: &Identity,
        justification: &str,
        ttl: Option<u64>,
    ) -> Self;
}
```

### 5.3 Provenance and Taint

```rust
/// Provenance tracking (NORMATIVE)
#[derive(Clone)]
pub struct Provenance {
    pub origin_zone: ZoneId,
    /// Current zone (updated on every zone crossing)
    pub current_zone: ZoneId,
    /// Integrity level (higher = more trusted source)
    pub integrity_label: u8,
    /// Confidentiality level (higher = more sensitive)
    pub confidentiality_label: u8,
    /// Proof-carrying label adjustments (elevation, declassification)
    pub label_adjustments: Vec<LabelAdjustment>,
    pub origin_principal: Option<PrincipalId>,
    /// Taint flags (compositional: merged via OR across inputs)
    pub taint: TaintFlags,
    /// Taint reductions, each justified by a SanitizerReceipt (NORMATIVE)
    /// Allows specific taints to be cleared with proof (e.g., URL scan, malware check)
    pub taint_reductions: Vec<TaintReduction>,
    pub zone_crossings: Vec<ZoneCrossing>,
    pub created_at: u64,
}

/// Proof-carrying label adjustment (NORMATIVE)
#[derive(Clone)]
pub enum LabelAdjustment {
    /// Human-approved integrity elevation (e.g., reviewed content)
    IntegrityElevated { to: u8, by_approval: ObjectId, applied_at: u64 },
    /// Human-approved declassification (lower secrecy)
    ConfidentialityDeclassified { to: u8, by_approval: ObjectId, applied_at: u64 },
}

/// Proof-carrying taint reduction (NORMATIVE)
///
/// Allows clearing specific taints when you can point to a verifiable SanitizerReceipt.
/// Examples:
/// - URL scanning cleared UNVERIFIED_LINK
/// - Malware scan cleared UNVERIFIED_LINK
/// - Strict schema validation cleared PROMPT_SURFACE for that field
#[derive(Clone)]
pub struct TaintReduction {
    /// Which taints are cleared
    pub clears: TaintFlags,
    /// SanitizerReceipt ObjectId that justifies the reduction
    pub by_receipt: ObjectId,
    /// When the reduction was applied
    pub applied_at: u64,
}

/// Machine-verifiable proof of sanitization (NORMATIVE)
///
/// Turns "I trust this connector did the right thing" into "I can verify
/// this connector ran, with what inputs, using what version."
pub struct SanitizerReceipt {
    pub header: ObjectHeader,
    /// Which sanitizer capability was invoked
    pub sanitizer_id: CapabilityId,
    /// Input object(s) that were scanned
    pub input_object_ids: Vec<ObjectId>,
    /// Sanitizer connector version (for CVE tracking)
    pub sanitizer_version: String,
    /// Which taints this receipt clears
    pub clears: TaintFlags,
    /// When the sanitization occurred
    pub sanitized_at: u64,
    /// Sanitizer node signature
    pub signature: Signature,
}

bitflags! {
    /// Taint flags (NORMATIVE)
    pub struct TaintFlags: u32 {
        const NONE            = 0;
        const PUBLIC_INPUT    = 1 << 0;  // e.g. z:public messages, web
        const EXTERNAL_INPUT  = 1 << 1;  // e.g. paired external identities
        const UNVERIFIED_LINK = 1 << 2;  // URLs / attachments not scanned
        const USER_SUPPLIED   = 1 << 3;  // direct human input
        const PROMPT_SURFACE  = 1 << 4;  // content interpreted by an LLM
    }
}

#[derive(Clone)]
pub struct ZoneCrossing {
    pub from_zone: ZoneId,
    pub to_zone: ZoneId,
    pub crossed_at: u64,
    pub authorized_by: Option<ObjectId>,
}

impl Provenance {
    /// Effective integrity after applying adjustments (NORMATIVE)
    pub fn effective_integrity(&self) -> u8 {
        let mut v = self.integrity_label;
        for a in &self.label_adjustments {
            if let LabelAdjustment::IntegrityElevated { to, .. } = a {
                v = v.max(*to);
            }
        }
        v
    }

    /// Effective confidentiality after applying adjustments (NORMATIVE)
    pub fn effective_confidentiality(&self) -> u8 {
        let mut v = self.confidentiality_label;
        for a in &self.label_adjustments {
            if let LabelAdjustment::ConfidentialityDeclassified { to, .. } = a {
                v = v.min(*to);
            }
        }
        v
    }

    /// Effective taint after applying reductions (NORMATIVE)
    ///
    /// Taint reductions allow specific taints to be cleared with proof.
    /// Without this, taint-only-accumulates leads to "approve everything" fatigue.
    pub fn effective_taint(&self) -> TaintFlags {
        let mut t = self.taint;
        for r in &self.taint_reductions {
            t.remove(r.clears);
        }
        t
    }

    /// Merge provenances from multiple inputs (NORMATIVE, SECURITY-CRITICAL)
    ///
    /// INVARIANT: MIN(integrity), MAX(confidentiality)
    /// This ensures compromised inputs cannot elevate trust and
    /// sensitive outputs cannot be inadvertently exposed.
    pub fn merge(inputs: &[Provenance]) -> Provenance {
        let mut out = inputs[0].clone();
        out.integrity_label = inputs.iter().map(|p| p.effective_integrity()).min().unwrap_or(0);
        out.confidentiality_label = inputs.iter().map(|p| p.effective_confidentiality()).max().unwrap_or(0);
        for p in inputs.iter().skip(1) {
            out.taint |= p.taint;
            out.label_adjustments.extend(p.label_adjustments.clone());
            out.taint_reductions.extend(p.taint_reductions.clone());
            out.zone_crossings.extend(p.zone_crossings.clone());
        }
        out
    }
}
```

Taint decisions are enforced before invocation using `effective_taint()`:

- Public-tainted input cannot directly drive Dangerous operations.
- If `effective_taint() != NONE` and `operation.safety_tier >= Risky` and `target_zone.integrity_level > origin_integrity`,
  an ApprovalToken with `ApprovalScope::Elevation` is required.
- Otherwise, the operation is allowed.

Cross-zone movement updates `current_zone` and records zone crossings.

### 5.4 Connector Implications

- Objects stored in the mesh MUST include an `ObjectHeader`, which includes provenance.
- When a connector creates objects, it must supply provenance as part of the header and compute
  `ObjectId` from the canonical encoding of `(header, body)`.
- Elevation is handled by `ApprovalToken` with `ApprovalScope::Elevation` (see §5.2).
- Declassification is handled by `ApprovalToken` with `ApprovalScope::Declassification` (see §5.2).

---

## 6. Capability System

### 6.1 Capability Taxonomy (Non-exhaustive)

```
fcp.*                    Protocol/meta operations
├── fcp.connect          Establish connection
├── fcp.handshake        Complete handshake
└── fcp.introspect       Query capabilities

network.*                Network operations
├── network.egress       Outbound access via MeshNode egress proxy (DEFAULT in strict/moderate sandboxes)
├── network.raw_outbound:* Direct sockets (RARE; permissive sandbox only)
├── network.inbound:*    Listen for connections
└── network.dns          DNS resolution (explicit capability; policy surface)

network.tls.*            TLS identity constraints (NORMATIVE for sensitive connectors)
├── network.tls.sni       Enforce SNI hostname match
└── network.tls.spki_pin  Enforce SPKI pin(s) for target host(s)

storage.*                Data persistence
├── storage.persistent   Durable storage
├── storage.ephemeral    Temporary storage
└── storage.encrypted    Encrypted storage

ipc.*                    Inter-process communication
├── ipc.gateway          Gateway communication
└── ipc.agent            Agent communication

system.*                 System operations (restricted)
├── system.info          System information (readonly)
├── system.exec          Execute commands (dangerous)
└── system.env           Environment variables

[service].*              Service-specific capabilities
├── telegram.*           Telegram operations
├── discord.*            Discord operations
├── gmail.*              Gmail operations
├── calendar.*           Calendar operations
└── ...                  Other services
```

### 6.2 Capability Definition

```rust
pub struct Capability {
    pub id: CapabilityId,
    pub name: String,
    pub description: String,
    pub risk_level: RiskLevel,
    pub safety_tier: SafetyTier,
    pub parent: Option<CapabilityId>,
    pub implies: Vec<CapabilityId>,
    pub conflicts_with: Vec<CapabilityId>,
    pub idempotency: IdempotencyClass,
    pub rate_limit: Option<RateLimit>,
    pub requires_approval: ApprovalMode,
    pub audit_level: AuditLevel,
    pub agent_hint: AgentHint,
}

pub enum RiskLevel { Low, Medium, High, Critical }

pub enum SafetyTier { Safe, Risky, Dangerous, Forbidden }

pub enum IdempotencyClass { None, BestEffort, Strict }

pub enum ApprovalMode {
    /// No approval needed
    None,
    /// Policy-based auto-approval
    Policy,
    /// Interactive human approval
    Interactive,
    /// Requires ApprovalToken (elevation or other scope)
    ApprovalRequired,
}

pub struct AgentHint {
    pub when_to_use: String,
    pub common_mistakes: Vec<String>,
    pub examples: Vec<String>,
    pub related: Vec<CapabilityId>,
}
```

### 6.3 Capability Object and Constraints

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
    /// Optional credential bindings (NORMATIVE when present)
    /// If set, the connector may only use the listed credentials via the egress proxy.
    /// Enables "secretless connectors" where raw secrets never enter connector memory.
    pub credential_allow: Vec<CredentialId>,
}

/// Network/TLS constraints (NORMATIVE for sensitive connectors)
///
/// Prevents DNS pivot, SSRF, and host confusion attacks.
pub struct NetworkConstraints {
    /// Allowed hostnames (exact or suffix match)
    pub host_allow: Vec<String>,
    /// Allowed ports
    pub port_allow: Vec<u16>,
    /// Optional explicit IP allow-list
    pub ip_allow: Vec<IpAddr>,
    /// CIDR blocks denied by policy
    /// NORMATIVE default includes: localhost (127.0.0.0/8, ::1), link-local (169.254.0.0/16),
    /// RFC1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), and tailnet ranges (100.64.0.0/10)
    pub cidr_deny: Vec<String>,
    /// Deny localhost unless explicitly allowed (NORMATIVE default: true)
    pub deny_localhost: bool,
    /// Deny private ranges unless explicitly allowed (NORMATIVE default: true)
    pub deny_private_ranges: bool,
    /// Deny tailnet address ranges unless explicitly allowed (NORMATIVE default: true)
    pub deny_tailnet_ranges: bool,
    /// Require SNI hostname match
    pub require_sni: bool,
    /// Optional SPKI pins (base64-encoded SHA256 of SubjectPublicKeyInfo)
    pub spki_pins: Vec<String>,
    /// Deny IP literals unless explicitly allowed (NORMATIVE default: true)
    pub deny_ip_literals: bool,
    /// Hostnames MUST be canonicalized (lowercase, IDNA2008, no trailing dot) (NORMATIVE default: true)
    pub require_host_canonicalization: bool,

    // DNS rebinding defense (NORMATIVE)
    /// Max IPs per DNS response (prevents rebinding flood)
    pub dns_max_ips: u16,
    /// Max HTTP redirects (prevents infinite redirect loops)
    pub max_redirects: u8,
    /// TCP connect timeout in milliseconds
    pub connect_timeout_ms: u32,
    /// Total request timeout in milliseconds
    pub total_timeout_ms: u32,
    /// Max response body size in bytes
    pub max_response_bytes: u64,
}
```

**Egress Proxy (NORMATIVE for strict/moderate sandboxes):**

In Strict and Moderate sandbox profiles, connectors MUST NOT be granted raw socket syscalls.
Network capabilities are implemented by a MeshNode-owned **egress proxy** enforcing NetworkConstraints:

- Connectors talk to the proxy over capability-gated IPC (`network.egress` capability)
- Proxy enforces `host_allow`, `port_allow`, `cidr_deny`, SNI, and SPKI pins
- No SSRF into localhost/tailnet/RFC1918 unless explicitly allowed
- DNS resolution goes through proxy with policy checks

Network/TLS constraints are NORMATIVE for sensitive connectors and include host/port
allow-lists, SNI enforcement, CIDR deny-lists, and optional SPKI pins.

**Egress Proxy Credential Injection (NORMATIVE):**

The egress proxy supports "secretless connectors" where raw API keys/tokens never enter
connector memory. Instead, credentials are injected by the proxy at the network boundary:

```rust
/// Credential identifier (NORMATIVE)
pub struct CredentialId(pub String); // e.g., "cred:telegram.bot_token"

/// Credential object (NORMATIVE)
/// A zone-bound, auditable handle describing how to apply a SecretObject to outbound requests.
pub struct CredentialObject {
    pub header: ObjectHeader,
    pub credential_id: CredentialId,
    pub secret_id: SecretId,
    pub apply: CredentialApply,
    /// Optional host binding for defense-in-depth (NORMATIVE when present)
    pub host_allow: Vec<String>,
    pub created_at: u64,
    pub signature: Signature,
}

pub enum CredentialApply {
    /// Set an HTTP header (e.g., Authorization: Bearer <secret>)
    HttpHeader { name: String, format: CredentialFormat },
    /// Set query parameter (rare; discouraged)
    QueryParam { name: String, format: CredentialFormat },
}

pub enum CredentialFormat {
    Raw,                          // Use secret bytes as UTF-8
    Prefix { prefix: String },    // Prefix + secret (e.g., "Bearer " + token)
}

/// Connector egress request with optional credential injection (NORMATIVE)
pub struct EgressHttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// If set, proxy injects this credential (NORMATIVE)
    pub credential: Option<CredentialId>,
}

/// General egress request (NORMATIVE) - supports HTTP and raw TCP
pub enum EgressRequest {
    Http(EgressHttpRequest),
    TcpConnect(EgressTcpConnectRequest),
}

/// TCP connect request for database/queue connectors (NORMATIVE)
pub struct EgressTcpConnectRequest {
    pub host: String,
    pub port: u16,
    pub use_tls: bool,
    pub sni: Option<String>,
    pub spki_pins: Vec<String>,
    pub credential: Option<CredentialId>,
}
```

Connectors declare allowed credentials via `credential_allow` in `CapabilityConstraints` (see §6.3).

When `credential` is set on an `EgressHttpRequest`, the egress proxy:
1. Verifies `credential` ∈ `CapabilityConstraints.credential_allow`
2. Fetches and validates the referenced `CredentialObject` and `SecretObject`
3. Injects the credential only for allowed hosts and logs an audit event

This pattern is recommended for API-heavy connectors (Telegram, Slack, etc.) to minimize
secret exposure and simplify credential rotation.

### 6.4 Placement Policy

```rust
pub struct PlacementPolicy {
    pub requires: Vec<DeviceRequirement>,
    pub prefers: Vec<DevicePreference>,
    pub excludes: Vec<DevicePattern>,
    pub zones: Vec<ZoneId>,
}
```

### 6.5 Capability Token (FCT)

```rust
/// Capability Token for operation invocation (NORMATIVE)
pub struct CapabilityToken {
    /// Unique token identifier
    pub jti: Uuid,
    /// Principal identifier
    pub sub: PrincipalId,
    /// Issuing zone
    pub iss_zone: ZoneId,
    /// Issuing node (signer) - the node that minted this token
    pub iss_node: TailscaleNodeId,
    /// Issuer key id (for rotation)
    pub kid: [u8; 8],
    /// Intended audience (connector)
    pub aud: ConnectorId,
    /// Bind token to a specific connector binary or manifest (NORMATIVE for Risky/Dangerous)
    /// Prevents replay across upgrades or swapped binaries with the same ConnectorId.
    pub aud_binary: Option<ObjectId>,
    /// Optional connector instance binding
    pub instance: Option<InstanceId>,
    /// Issued at (Unix timestamp)
    pub iat: u64,
    /// Expires at (Unix timestamp)
    pub exp: u64,
    /// CapabilityObjects that authorize this token (NORMATIVE)
    /// Verifiers MUST fetch/verify these objects and ensure token grants ⊆ object grants.
    /// This makes authority mechanically verifiable, not "trust the issuer".
    pub grant_object_ids: Vec<ObjectId>,
    /// Granted capabilities (MUST be subset of union of grant_object_ids)
    pub caps: Vec<CapabilityGrant>,
    /// Optional attenuation applied by the issuer (MUST ONLY RESTRICT, never expand)
    pub attenuation: Option<CapabilityConstraints>,
    /// The only node allowed to present this token (sender-constrained)
    pub holder_node: TailscaleNodeId,
    /// Revocation head the issuer considered (NORMATIVE)
    /// Verifiers MUST have revocation state >= this head or fetch before acceptance.
    pub rev_head: ObjectId,
    /// Monotonic revocation sequence at rev_head (NORMATIVE)
    /// Enables O(1) freshness checks: verifier compares rev_seq, not chain traversal.
    pub rev_seq: u64,
    /// Ed25519 signature (by iss_node's issuance key)
    pub sig: [u8; 64],
}

pub struct CapabilityGrant {
    /// Granted capability
    pub capability: CapabilityId,
    /// Optional operation-level restriction
    pub operation: Option<OperationId>,
}

impl CapabilityToken {
    /// Default TTL: 5 minutes
    pub const DEFAULT_TTL_SECS: u64 = 300;

    /// Verify token validity (NORMATIVE)
    pub fn verify(&self, trust_anchors: &TrustAnchors) -> Result<(), TokenError> {
        // Check expiry
        if current_timestamp() > self.exp {
            return Err(TokenError::Expired);
        }

        // Verify signature using node issuance pubkey (NOT signing key, NOT zone key)
        // The issuing node must have a valid NodeKeyAttestation from owner
        let issuer_pubkey = trust_anchors.get_node_iss_pubkey(&self.iss_node, &self.kid)?;
        issuer_pubkey.verify(&self.signable_bytes(), &self.sig)?;

        // Enforce that issuing node is authorized to mint tokens for this zone
        trust_anchors.enforce_token_issuer_policy(&self.iss_zone, &self.iss_node)?;

        // NORMATIVE: Verify provable authority via grant_object_ids
        trust_anchors.verify_token_grants(self)?;

        Ok(())
    }
}
```

**Provable Authority (NORMATIVE):**

The `grant_object_ids` field enables mechanical verification of token authority:
1. Verifier fetches each CapabilityObject in `grant_object_ids`
2. Verifier confirms `caps` ⊆ union of grants from those objects
3. Verifier confirms the issuer node was authorized to issue from those objects

This eliminates "trust the issuer" ambiguity—authority is traceable to specific capability objects.

Token verification MUST use the node issuance public key (not the node signing key). Issuance keys are
separately revocable. Verifiers compare `rev_seq` for O(1) freshness checks; full chain traversal is
only needed on seq mismatch. Verifiers MUST have revocation state >= `rev_head` (or fetch revocations)
before accepting a token.

---

## 7. Invoke, Receipts, and Event Envelopes

### 7.1 Invoke Request/Response

```rust
/// Distributed trace context for end-to-end observability (NORMATIVE when present)
pub struct TraceContext {
    /// 16-byte trace id (unique per logical request)
    pub trace_id: [u8; 16],
    /// 8-byte span id (unique per span within trace)
    pub span_id: [u8; 8],
    /// Sampling/flags (W3C Trace Context compatible)
    pub flags: u8,
}

/// Invoke request (NORMATIVE)
pub struct InvokeRequest {
    pub id: String,
    pub operation: OperationId,
    pub input: Value,
    pub capability_token: CapabilityToken,
    pub provenance: Provenance,
    /// Unified approval tokens for elevation and/or declassification
    pub approval_tokens: Vec<ApprovalToken>,
    pub idempotency_key: Option<String>,

    /// Distributed trace context (NORMATIVE when present)
    /// Enables end-to-end correlation across MeshNodes, connectors, receipts, and audit.
    pub trace_context: Option<TraceContext>,

    /// Holder proof (NORMATIVE): binds presentation to holder_node in CapabilityToken
    /// Prevents token replay by anyone other than the designated holder.
    pub holder_proof: Signature,
}

impl InvokeRequest {
    /// Verify holder proof (NORMATIVE)
    pub fn verify_holder_proof(&self, trust_anchors: &TrustAnchors) -> Result<(), VerifyError> {
        let holder = &self.capability_token.holder_node;
        let holder_pubkey = trust_anchors.get_node_sig_pubkey(holder)?;
        holder_pubkey.verify(&self.holder_signable_bytes(), &self.holder_proof)
    }

    fn holder_signable_bytes(&self) -> Vec<u8> {
        // Include request id, operation, and token jti to bind holder proof to specific request
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.id.as_bytes());
        bytes.extend_from_slice(self.operation.as_bytes());
        bytes.extend_from_slice(self.capability_token.jti.as_bytes());
        bytes
    }
}

/// Invoke response (NORMATIVE)
pub struct InvokeResponse {
    pub id: String,
    pub result: Value,
    /// Resource handles returned (zone-bound, auditable)
    pub resource_object_ids: Vec<ObjectId>,
    pub next_cursor: Option<String>,
    /// Receipt ObjectId (for operations with side effects)
    pub receipt: Option<ObjectId>,
}

/// Zone-bound external resource handle (NORMATIVE)
///
/// Replaces free-form URI strings with zone-bound, auditable mesh objects.
/// Enables access control and audit trails for external resources.
pub struct ResourceObject {
    pub header: ObjectHeader,
    /// Original external URI (for human readability)
    pub uri: String,
    /// External resource type
    pub resource_type: String,
    /// External resource integrity level (NORMATIVE for information flow)
    pub resource_integrity_level: u8,
    /// External resource confidentiality level (NORMATIVE for information flow)
    pub resource_confidentiality_level: u8,
    /// Resource taint flags for external resource classification
    pub resource_taint: TaintFlags,
    /// Additional metadata (JSON)
    pub metadata: Option<Value>,
    /// Connector signature over resource metadata
    pub signature: Signature,

    // TOCTOU prevention and caching (NORMATIVE)
    /// Optional BLAKE3-256 digest of resource content at fetch time
    /// Enables TOCTOU (time-of-check-time-of-use) attack prevention
    pub content_digest: Option<[u8; 32]>,
    /// Optional caching hints for resource freshness
    pub cache_policy: Option<CachePolicy>,
}

/// Cache policy hints for ResourceObject (NORMATIVE)
pub struct CachePolicy {
    /// Maximum age in seconds before revalidation
    pub max_age_secs: u32,
    /// Whether the resource is immutable (never changes)
    pub immutable: bool,
    /// Optional ETag for conditional requests
    pub etag: Option<String>,
}

/// Simulate request for preflight checks (NORMATIVE)
///
/// Allows callers to check if an operation would succeed without executing it.
/// Connectors SHOULD implement simulate for expensive or dangerous operations.
pub struct SimulateRequest {
    pub id: String,
    pub operation: OperationId,
    pub input: Value,
    pub capability_token: CapabilityToken,
    /// Request cost estimate
    pub estimate_cost: bool,
    /// Check resource availability
    pub check_availability: bool,
}

/// Simulate response (NORMATIVE)
pub struct SimulateResponse {
    pub id: String,
    /// Would the operation succeed with current capabilities/state?
    pub would_succeed: bool,
    /// If would_succeed is false, why not?
    pub failure_reason: Option<String>,
    /// Missing capabilities needed (if any)
    pub missing_capabilities: Vec<String>,
    /// Estimated cost (if estimate_cost was true)
    pub estimated_cost: Option<CostEstimate>,
    /// Resource availability check result
    pub availability: Option<ResourceAvailability>,
}
```

The holder proof prevents token replay by anyone other than the designated holder. The signable bytes
bind the request to the specific `id`, `operation`, and token `jti`.

**Enforcement before execution:**
- If `effective_taint() != NONE` and operation requires elevation, the `approval_tokens` MUST contain
  an `ApprovalToken` with `ApprovalScope::Elevation`.
- If an operation writes outputs into a zone with lower confidentiality than the data label,
  `approval_tokens` MUST contain an `ApprovalToken` with `ApprovalScope::Declassification`.

### 7.2 Operation Receipt

```rust
/// Operation receipt object (NORMATIVE)
pub struct OperationReceipt {
    pub header: ObjectHeader,
    pub request_object_id: ObjectId,
    pub idempotency_key: Option<String>,
    pub outcome_object_ids: Vec<ObjectId>,
    /// Resource handles produced (zone-bound, auditable)
    pub resource_object_ids: Vec<ObjectId>,
    pub executed_at: u64,
    pub executed_by: TailscaleNodeId,
    pub signature: Signature,
}
```

Operations with `SafetyTier::Dangerous` MUST be `IdempotencyClass::Strict`.
Operations with `SafetyTier::Risky` SHOULD be `Strict` unless there is a clear reason.

**OperationIntent Pre-commit (NORMATIVE for Strict + Risky/Dangerous):**

Closes the crash window between "side effect happened" and "receipt stored".
Written BEFORE executing an external side effect.

```rust
/// Operation intent - pre-commit for exactly-once semantics (NORMATIVE for Strict + Risky/Dangerous)
pub struct OperationIntent {
    pub header: ObjectHeader,
    pub request_object_id: ObjectId,
    pub capability_token_jti: Uuid,
    pub idempotency_key: Option<String>,
    pub planned_at: u64,
    pub planned_by: TailscaleNodeId,
    /// Optional upstream idempotency handle (e.g., Stripe idempotency key)
    pub upstream_idempotency: Option<String>,
    pub signature: Signature,
}
```

**Execution Rule for Strict/Risky/Dangerous Operations (NORMATIVE):**
1. MeshNode MUST store OperationIntent (Required retention) BEFORE invoking the connector operation
2. OperationReceipt MUST reference the OperationIntent via `ObjectHeader.refs`
3. On crash recovery, check for intents without corresponding receipts to detect incomplete operations

### 7.3 Event Envelope

```rust
pub struct EventEnvelope {
    pub topic: String,
    pub timestamp: DateTime<Utc>,
    pub seq: u64,
    pub cursor: String,
    pub requires_ack: bool,
    pub data: EventData,
}

pub struct EventData {
    pub connector_id: ConnectorId,
    pub instance_id: InstanceId,
    pub zone_id: ZoneId,
    pub principal: Principal,
    pub payload: Value,
    pub correlation_id: Option<CorrelationId>,
    pub resource_uris: Vec<String>,
    pub thread_info: Option<ThreadInfo>,
}

pub struct ThreadInfo {
    pub thread_id: String,
    pub parent_id: Option<String>,
    pub kind: ThreadKind,
}

pub enum ThreadKind {
    Thread,
    ForumTopic,
    Channel,
    Reply,
}
```

Threading is optional metadata. Use `thread_info` to normalize forum topics (Telegram), platform-native threads (Discord/Slack), or reply chains across connectors.

---

## 8. Streaming, Replay, and Acks

Event streaming requirements:

- Event envelopes include `topic`, `seq`, `cursor`, and `requires_ack` fields.
- If `requires_ack` is true, consumers are expected to ack; connectors can track delivery state.
- When `event_caps.replay = true`, connectors MUST support replay from a cursor.
- `event_caps.min_buffer_events` sets the minimum replay buffer size.

---

## 9. Error Taxonomy

```rust
pub struct FcpError {
    pub code: String,              // e.g., "FCP-4002"
    pub message: String,
    pub retryable: bool,
    pub retry_after_ms: Option<u64>,
    pub details: Option<Value>,
    pub ai_recovery_hint: Option<String>,
}
```

Error ranges:

```
FCP-1000..1999  Protocol errors
FCP-2000..2999  Auth/Identity errors
FCP-3000..3999  Capability errors
FCP-4000..4999  Zone/Provenance errors
FCP-5000..5999  Lifecycle/health errors
FCP-6000..6999  Resource errors
FCP-7000..7999  External service errors
FCP-9000..9999  Internal errors
```

### 9.1 Standard Error Codes (NORMATIVE)

| Code | Description | Category |
|------|-------------|----------|
| `FCP_ERR_UNSUPPORTED_VERSION` | Frame version not supported | Protocol |
| `FCP_ERR_MAC_INVALID` | Session MAC verification failed | Auth |
| `FCP_ERR_REPLAY` | Frame sequence indicates replay | Protocol |
| `FCP_ERR_TOKEN_EXPIRED` | Capability token has expired | Capability |
| `FCP_ERR_EGRESS_DENIED` | Egress blocked by NetworkConstraints | Network |
| `FCP_ERR_ZONE_VIOLATION` | Operation crossed zone boundary illegally | Zone |
| `FCP_ERR_CAPABILITY_MISSING` | Required capability not present | Capability |
| `FCP_ERR_SCHEMA_MISMATCH` | Input/output schema validation failed | Protocol |
| `FCP_ERR_RATE_EXCEEDED` | Rate limit exceeded | Resource |
| `FCP_ERR_ATTESTATION_INVALID` | Node/device attestation failed validation | Auth |

**Error Logging (NORMATIVE):** All errors MUST be logged with structured context including:
- Error code and message
- Operation ID and connector ID
- Zone context
- Timestamp (monotonic and wall-clock)

---

## 10. Agent Integration (Introspection + MCP)

Agents MUST be able to query:

- Operations (schemas, risk levels)
- Approval requirements
- Rate limits
- Recovery hints

Map connector operations to MCP-compatible tools with:

- Schemas
- Risk annotations
- Examples
- Rate limits

---

## 11. Connector Manifest (TOML) and Embedding

### 11.1 Manifest Structure (NORMATIVE)

```toml
[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"
min_mesh_version = "2.0.0"              # NORMATIVE: minimum compatible mesh version
min_protocol = "fcp2-sym/2.0"           # NORMATIVE: required protocol version (SemVer)
# NORMATIVE: required protocol features (explicit capability negotiation)
protocol_features = [
  "fcps.aead.xchacha20poly1305",
  "fcps.session_mac.hmacsha256.trunc16",
  "egress.dns_rebind_protection",
]
interface_hash = "blake3-256:fcp.interface.v2:..."  # NORMATIVE: hash of API surface (ops + schemas + caps)
max_datagram_bytes = 1200               # NORMATIVE: for MTU-constrained paths

[connector]
id = "fcp.telegram"
name = "Telegram Connector"
version = "2026.1.0"
description = "Secure Telegram Bot API integration"
archetypes = ["bidirectional", "streaming", "operational"]
format = "native"  # "native" | "wasi"

[zones]
home = "z:community"
allowed_sources = ["z:owner", "z:private", "z:work", "z:community"]
allowed_targets = ["z:community"]
forbidden = ["z:public"]

[capabilities]
required = [
  "ipc.gateway",
  "network.dns",
  "network.outbound",
  "network.tls.sni",
  "network.tls.spki_pin",
  "storage.persistent:encrypted",
]
optional = ["media.download", "media.upload"]
forbidden = ["system.exec", "network.inbound"]

[provides.operations."telegram.send_message"]
description = "Send a message to a Telegram chat"
capability = "telegram.messages.send"
risk_level = "medium"
safety_tier = "risky"
requires_approval = "policy"
rate_limit = "60/min"
idempotency = "best_effort"
input_schema = { type = "object", required = ["chat_id", "text"], properties = { chat_id = { type = "string" }, text = { type = "string" }, parse_mode = { type = "string" }, reply_to_message_id = { type = "integer" } } }
output_schema = { type = "object", required = ["message_id", "chat_id"], properties = { message_id = { type = "integer" }, chat_id = { type = "string" } } }
network_constraints = { host_allow = ["api.telegram.org"], port_allow = [443], require_sni = true, deny_ip_literals = true, max_redirects = 0, connect_timeout_ms = 5000, total_timeout_ms = 60000, max_response_bytes = 1048576 }

[provides.operations."telegram.send_message".ai_hints]
when_to_use = "Use to post updates to approved chats."
common_mistakes = ["Sending secrets", "Responding to tainted inputs"]

[provides.operations."telegram.get_file"]
description = "Fetch Telegram file metadata and download URL"
capability = "telegram.media.read"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
rate_limit = "120/min"
idempotency = "idempotent"
input_schema = { type = "object", required = ["file_id"], properties = { file_id = { type = "string" } } }
output_schema = { type = "object", required = ["file_id"], properties = { file_id = { type = "string" }, file_unique_id = { type = "string" }, file_size = { type = "integer" }, file_path = { type = "string" }, download_url = { type = "string" } } }
network_constraints = { host_allow = ["api.telegram.org"], port_allow = [443], require_sni = true, deny_ip_literals = true, max_redirects = 0, connect_timeout_ms = 5000, total_timeout_ms = 60000, max_response_bytes = 1048576 }

[provides.operations."telegram.answer_callback_query"]
description = "Acknowledge a callback query (button press)"
capability = "telegram.messages.send"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
rate_limit = "120/min"
idempotency = "idempotent"
input_schema = { type = "object", required = ["callback_query_id"], properties = { callback_query_id = { type = "string" }, text = { type = "string" } } }
output_schema = { type = "object", required = ["success"], properties = { success = { type = "boolean" } } }
network_constraints = { host_allow = ["api.telegram.org"], port_allow = [443], require_sni = true, deny_ip_literals = true, max_redirects = 0, connect_timeout_ms = 5000, total_timeout_ms = 60000, max_response_bytes = 1048576 }

[event_caps]
streaming = true
replay = false
min_buffer_events = 1000

[sandbox]
profile = "strict"            # "strict", "strict_plus", "moderate", or "permissive"
memory_mb = 256
cpu_percent = 50
wall_clock_timeout_ms = 30000
fs_readonly_paths = ["/usr", "/lib"]
fs_writable_paths = ["$CONNECTOR_STATE"]
deny_exec = true
deny_ptrace = true

[signatures]
publisher_signatures = [
  { kid = "pubkey1", sig = "base64:..." },
  { kid = "pubkey2", sig = "base64:..." },
]
publisher_threshold = "2-of-3"
registry_signature = { kid = "registry1", sig = "base64:..." }
transparency_log_entry = "objectid:..."
```

**Telegram manifest contract (accepted):** the example above is the canonical "good" manifest.

**Rejected examples (should fail validation):**

```toml
# BAD: network capability encodes host:port (must use network_constraints)
[capabilities]
required = ["network.outbound:api.telegram.org:443"]
```

```toml
# BAD: streaming enabled but min_buffer_events = 0
[event_caps]
streaming = true
replay = false
min_buffer_events = 0
```

```toml
# BAD: IP literal allowed and redirect policy too loose for Telegram
[provides.operations."telegram.send_message"]
network_constraints = { host_allow = ["1.2.3.4"], port_allow = [443], deny_ip_literals = false, max_redirects = 10 }
```

**Telegram event topics (contract):**
- `telegram.message.new`
- `telegram.message.edited`
- `telegram.channel_post.new`
- `telegram.channel_post.edited`
- `telegram.callback_query`

**Telegram event payload schema (JSON shape):**
- `telegram.message.*` / `telegram.channel_post.*` payload:
  - `message_id` (integer), `chat` (object), `from` (object), `date` (integer epoch seconds)
  - `text` (string, optional), `caption` (string, optional)
  - `has_photo` / `has_document` / `has_audio` / `has_video` / `has_voice` (boolean)
  - `reply_to_message_id` (integer, optional), `message_thread_id` (integer, optional)
- `telegram.callback_query` payload:
  - `id` (string), `from` (object), `data` (string, optional), `chat_instance` (string)

**Cursor semantics:** `update_id` is the monotonic cursor/seq source; replay is currently `false` and acks are not required.

**Telegram capability families (contract):**
- `telegram.messages.read` (Safe) — inbound updates / polling
- `telegram.messages.send` (Risky) — send messages, answer callback queries
- `telegram.media.read` (Safe) — fetch file metadata / download URL
- `telegram.media.send` (Risky) — upload/send media
- `telegram.chats.read` (Safe) — chat metadata
- `telegram.members.read` (Safe) — member lists
- `telegram.webhooks.manage` (Dangerous) — webhook configuration

### 11.2 Manifest Embedding (NORMATIVE)

Manifests MUST be extractable without execution:

- ELF: `.fcp_manifest`
- Mach-O: `__FCP,__manifest`
- PE: `.fcpmanifest`

Connectors MUST implement `--manifest` to print the embedded manifest.

---

## 12. Sandbox Profiles and Enforcement

```rust
/// Sandbox configuration from manifest (NORMATIVE)
pub struct SandboxConfig {
    pub profile: SandboxProfile,
    pub memory_mb: u32,
    pub cpu_percent: u8,
    pub wall_clock_timeout_ms: u64,
    pub fs_readonly_paths: Vec<PathBuf>,
    pub fs_writable_paths: Vec<PathBuf>,
    pub deny_exec: bool,
    pub deny_ptrace: bool,
}

pub enum SandboxProfile {
    /// Maximum restrictions (recommended for untrusted connectors)
    Strict,
    /// Maximum isolation (Linux): microVM-backed sandbox for high-risk connectors (NORMATIVE where available)
    StrictPlus,
    /// Balanced restrictions (default)
    Moderate,
    /// Minimal restrictions (only for highly trusted connectors)
    Permissive,
}
```

Enforcement:

- Resource limits (memory, CPU, time) are enforced by the OS sandbox.
- Filesystem access is limited to declared paths.
- Network access is limited to declared capabilities and constraints.
- Child process spawning and debugging/tracing can be denied.

---

## 13. Automation Recipes and Provisioning Interface

### 13.1 Recipe Model

Recipes are deterministic step lists for connector setup:

```toml
[recipe]
id = "telegram/setup"
version = "1"
description = "Set up Telegram bot integration"

[[steps]]
type = "prompt_user"
id = "bot_name"
message = "Choose a Telegram bot name"

[[steps]]
type = "open_url"
requires_approval = true
url = "https://t.me/BotFather"

[[steps]]
type = "prompt_secret"
id = "bot_token"
message = "Paste the Telegram bot token"

[[steps]]
type = "store_secret"
key = "telegram.bot_token"
value_from = "bot_token"
scope = "connector:fcp.telegram"
```

Implementation note: core recipe/types live in `fcp_core::ProvisioningRecipe`,
`ProvisioningStep`, and `ProvisioningStepType`.

### 13.2 Provisioning Interface

| Operation | Purpose |
|-----------|---------|
| `fcp.provision.start` | Begin auth flow |
| `fcp.provision.poll` | Check status |
| `fcp.provision.complete` | Finalize credentials |
| `fcp.provision.abort` | Cancel and cleanup |

Implementation note: the connector-facing interface is defined as
`fcp_core::ProvisioningInterface`, with `ProvisioningState` and
`ProvisioningStepResult` used for status reporting.

---

## 14. Registry and Supply Chain

### 14.1 Registry Sources (NORMATIVE)

Registries are sources, not dependencies. Implementations MUST support at least one of:

1. Remote registry (HTTP) - public registry like registry.flywheel.dev
2. Self-hosted registry (HTTP) - enterprise/private registry
3. Mesh mirror registry - connectors pinned as objects in z:owner or z:private

Connector binaries MUST be content-addressed objects and MAY be distributed via the symbol layer.

```rust
/// Registry source configuration (NORMATIVE)
pub enum RegistrySource {
    Remote { url: Url, trusted_keys: Vec<Ed25519PublicKey> },
    SelfHosted { url: Url, trusted_keys: Vec<Ed25519PublicKey> },
    MeshMirror { zone: ZoneId, index_object_id: ObjectId },
}

/// Optional registry security profile (NORMATIVE when configured)
///
/// Provides additional protections against distribution attacks:
/// - TUF (The Update Framework) prevents freeze/rollback and mix-and-match attacks
/// - Sigstore/cosign adds supply-chain provenance verification
pub struct RegistrySecurityProfile {
    /// If present, registry clients MUST enforce TUF snapshot/timestamp semantics.
    /// The referenced object contains TUF root metadata pinned in z:owner.
    pub tuf_root_object_id: Option<ObjectId>,
    /// If true, verify Sigstore/cosign signatures in addition to publisher/registry keys.
    pub require_sigstore: bool,
}
```

### 14.2 Transparency Log (Optional, NORMATIVE if enabled)

```rust
pub struct ConnectorTransparencyLogEntry {
    pub header: ObjectHeader,
    pub connector_id: ConnectorId,
    pub version: Version,
    pub manifest_object_id: ObjectId,
    pub binary_object_id: ObjectId,
    pub prev: Option<ObjectId>,
    pub published_at: u64,
    pub signature: Signature,
}
```

### 14.3 Supply Chain Attestations (RECOMMENDED)

First-class provenance attestations make supply chain verification machine-checkable, not just "signature valid".

```rust
/// Supply chain attestation (NORMATIVE when present)
///
/// First-class, machine-checkable provenance statement.
/// Makes "built from repo X at commit Y under workflow Z" enforceable.
pub struct SupplyChainAttestation {
    pub header: ObjectHeader,
    pub attestation_type: AttestationType,
    /// The connector binary this attestation covers
    pub subject_binary: ObjectId,
    /// Raw attestation payload (e.g., in-toto statement JSON)
    pub payload: Vec<u8>,
    /// Signature by builder/attestor
    pub signature: Signature,
}

pub enum AttestationType {
    /// in-toto statement with SLSA provenance predicate
    InToto,
    /// Reproducible build attestation
    ReproducibleBuild,
    /// Code review attestation
    CodeReview,
    /// Custom attestation type
    Custom(String),
}

/// Owner policy for supply chain verification (NORMATIVE)
pub struct SupplyChainPolicy {
    /// Require transparency log entry
    pub require_transparency_log: bool,
    /// Required attestation types (all must be present)
    pub require_attestation_types: Vec<AttestationType>,
    /// Minimum SLSA level (0-4)
    pub min_slsa_level: u8,
    /// Trusted builder identities
    pub trusted_builders: Vec<String>,
    /// Trusted publisher key fingerprints
    pub trusted_publishers: Vec<[u8; 32]>,
}
```

Manifest declares attestations:

```toml
[supply_chain]
attestations = [
  { type = "in-toto", object_id = "objectid:..." },
  { type = "reproducible-build", object_id = "objectid:..." },
]

[policy]
require_transparency_log = true
require_attestation_types = ["in-toto"]
min_slsa_level = 2
trusted_builders = ["github-actions", "internal-ci"]
```

### 14.4 Verification Chain

Before execution, verify:

1. Manifest signature (registry or trusted publisher quorum)
2. Binary checksum matches manifest
3. Binary signature matches trusted key
4. Platform/arch match
5. Requested capabilities are within zone ceilings
6. Optional: release present in transparency log (if enabled)
7. **Supply chain attestations** (if policy requires): verify all required attestation types present,
   SLSA level >= min_slsa_level, builder identity in trusted_builders list

---

## 15. Lifecycle Management and Revocation

### 15.1 Activation Requirements

On activation:

1. Create sandbox
2. Inject secrets ephemerally
3. Negotiate handshake
4. Issue capability tokens
5. Start health checks

### 15.2 Updates and Rollback

- Staged updates
- Automatic rollback on crash loops
- Explicit pinning to known-good versions

### 15.3 Revocation (NORMATIVE)

Revocations are mesh objects and MUST be enforced before use.
Without revocation, "compromised device" recovery is mostly imaginary.

```rust
/// Revocation object (NORMATIVE)
pub struct RevocationObject {
    pub header: ObjectHeader,
    /// ObjectIds being revoked
    pub revoked: Vec<ObjectId>,
    /// Scope of revocation
    pub scope: RevocationScope,
    /// Human-readable reason
    pub reason: String,
    /// When revocation becomes effective
    pub effective_at: u64,
    /// Optional expiry (None = permanent)
    pub expires_at: Option<u64>,
    /// Owner signature (revocations MUST be owner-signed)
    pub signature: Signature,
}

/// Revocation event chain node (NORMATIVE)
///
/// Hash-linked chain for revocation freshness.
pub struct RevocationEvent {
    pub header: ObjectHeader,
    pub revocation_object_id: ObjectId,
    pub prev: Option<ObjectId>,
    /// Monotonic chain sequence number (NORMATIVE)
    /// Enables O(1) freshness comparison: seq_a > seq_b ⟹ a is fresher than b.
    pub seq: u64,
    pub occurred_at: u64,
    pub signature: Signature,
}

/// Revocation head checkpoint (NORMATIVE)
///
/// Enables freshness semantics: tokens bound to a rev_head, verifiers MUST
/// have revocation state >= that head before accepting the token.
pub struct RevocationHead {
    pub header: ObjectHeader,
    pub zone_id: ZoneId,
    pub head_event: ObjectId,
    /// Sequence number of head_event (NORMATIVE)
    /// Enables O(1) freshness comparison without chain traversal.
    pub head_seq: u64,
    pub epoch_id: EpochId,
    pub quorum_signatures: Vec<(TailscaleNodeId, Signature)>,
}

pub enum RevocationScope {
    /// Revoke capability objects/tokens
    Capability,
    /// Revoke issuer keys (node can no longer mint tokens)
    IssuerKey,
    /// Revoke node attestation (removes device from mesh)
    NodeAttestation,
    /// Revoke zone key (forces rotation)
    ZoneKey,
    /// Revoke connector binary (supply chain response)
    ConnectorBinary,
}

/// Revocation registry (NORMATIVE)
pub struct RevocationRegistry {
    revocations: HashMap<ObjectId, RevocationObject>,
    bloom_filter: BloomFilter, // Fast negative lookup
    /// Latest revocation head known for this zone
    pub head: Option<ObjectId>,
}

impl RevocationRegistry {
    /// Check if object is revoked (MUST be called before use)
    pub fn is_revoked(&self, object_id: &ObjectId) -> bool {
        if !self.bloom_filter.might_contain(object_id.as_bytes()) {
            return false; // Fast path: definitely not revoked
        }
        self.revocations.contains_key(object_id)
    }
}
```

**Enforcement points (NORMATIVE):**

1. Before accepting a capability token
2. Before executing an operation
3. Before accepting symbols for audit head updates
4. Before using zone keys
5. On connector startup

**Revocation Freshness Policy (NORMATIVE):**

Tiered behavior for offline/degraded scenarios when revocation checks cannot reach the network:

```rust
/// Policy for handling revocation checks when offline/degraded (NORMATIVE)
pub enum RevocationFreshnessPolicy {
    /// Require fresh revocation check or abort (default for Risky/Dangerous)
    Strict,
    /// Log warning but proceed if cached list is within max_age
    Warn { max_age_seconds: u64 },
    /// Use stale cache if offline, log degraded state
    BestEffort,
}
```

---

## 16. Device-Aware Execution and Execution Leases

### 16.1 Leases (NORMATIVE)

Leases are a generic primitive for distributed coordination, preventing duplicate
side effects and stabilizing migration. FCP unifies execution leases, state-write
leases, and computation-migration leases under a single `Lease` struct with a
`LeasePurpose` discriminant:

```rust
/// Generic lease primitive (NORMATIVE; see FCP Specification §16.1)
///
/// A short-lived, renewable lock that says "node X owns subject S for purpose P until time T."
/// Used for: operation execution, connector state writes, computation migration.
pub struct Lease {
    pub header: ObjectHeader,
    /// The subject being leased (request, state object, computation)
    pub subject_object_id: ObjectId,
    /// What this lease authorizes
    pub purpose: LeasePurpose,
    /// Fencing token (NORMATIVE): monotonically increases per (zone_id, subject_object_id)
    /// The highest lease_seq wins deterministically, regardless of wall-clock exp.
    pub lease_seq: u64,
    /// Which node currently owns execution/write
    pub owner_node: TailscaleNodeId,
    /// Lease issued at
    pub iat: u64,
    /// Lease expires at (short-lived; renewable)
    pub exp: u64,
    /// Deterministic coordinator for this lease (NORMATIVE)
    /// Selected via HRW/Rendezvous hashing over (zone_id, subject_object_id).
    pub coordinator: TailscaleNodeId,
    /// Quorum signatures (NORMATIVE for Risky/Dangerous)
    pub quorum_signatures: Vec<(TailscaleNodeId, Signature)>,
}

/// Lease purpose discriminant (NORMATIVE)
pub enum LeasePurpose {
    /// Prevents duplicate execution of operations with side effects
    OperationExecution,
    /// Serializes writes to SingleWriter connector state
    ConnectorStateWrite,
    /// Coordinates computation migration between nodes
    ComputationMigration,
}

/// Lease acquisition request (NORMATIVE)
pub struct LeaseRequest {
    pub header: ObjectHeader,
    pub subject_object_id: ObjectId,
    pub purpose: LeasePurpose,
    pub desired_owner: TailscaleNodeId,
    pub requested_at: u64,
    pub exp: u64,
    /// Signature by requester node signing key
    pub signature: Signature,
}
```

**Distributed Lease Issuance (NORMATIVE):**

Coordinator selection uses HRW (Rendezvous) hashing:
```rust
fn select_coordinator(zone_id: &ZoneId, request_id: &ObjectId, nodes: &[TailscaleNodeId]) -> TailscaleNodeId {
    nodes.iter()
        .max_by_key(|n| hrw_hash(zone_id, request_id, n))
        .cloned()
        .unwrap()
}
```

**Quorum Rules (NORMATIVE):**
- **Safe ops:** Single coordinator signature MAY be sufficient
- **Risky ops:** Require f+1 signatures (prevents 1 compromised node from unilaterally leasing)
- **Dangerous ops:** Require n-f signatures (matches CriticalWrite default)

**Conflict Rule (NORMATIVE):**
If two valid leases overlap for the same `request_object_id`, nodes MUST:
1. For **Dangerous ops:** Refuse execution and alert owner for manual resolution
2. For **Risky ops:** Pick the lease with higher `(exp, coordinator_id)` and log the fork

**Lease Semantics:**
- For Risky/Dangerous operations, execution MUST require a valid lease.
- The executing node MUST present the lease to run the connector operation.
- If the node dies, the lease expires and another node can acquire.
- This is a mesh-native way to coordinate without a central coordinator.

---

### 16.2 Device Profiles and Execution Planner

Device-aware execution uses profiles and placement policies to choose the best node:

```rust
/// Device profile (NORMATIVE)
pub struct DeviceProfile {
    pub node_id: TailscaleNodeId,
    pub hostname: String,
    pub device_class: DeviceClass,
    pub capabilities: DeviceCapabilities,
    pub current_state: DeviceState,
}

pub enum DeviceClass {
    Desktop { os: String },
    Laptop { os: String, battery: bool },
    Phone { os: String },
    Tablet { os: String },
    Server,
    Browser,
}

pub struct DeviceCapabilities {
    pub cpu_cores: u8,
    pub memory_mb: u32,
    pub gpu: Option<GpuInfo>,
    pub storage_mb: u64,
    pub network: NetworkCapability,
}

/// Execution planner (NORMATIVE)
pub struct ExecutionPlanner {
    pub devices: Vec<DeviceProfile>,
}
```

### 16.3 Device Requirements and Preferences

The placement policy uses requirements and preferences to guide device selection:

```rust
/// Device requirements (NORMATIVE)
pub enum DeviceRequirement {
    /// Must have GPU
    Gpu { min_vram_mb: u32 },
    /// Must have minimum memory
    Memory { min_mb: u32 },
    /// Must be on power (not battery)
    OnPower,
    /// Must have specific software
    Software { name: String, version: Option<String> },
    /// Must have network connectivity
    Network { min_bandwidth_mbps: Option<u32> },
    /// Must have specific Tailscale tag
    TailscaleTag(String),
    /// Required connector must be available (installed or fetchable)
    ConnectorAvailable { connector_id: ConnectorId, min_version: Option<Version> },
    /// Secret must be reconstructable under current policy
    SecretReconstructable { secret_id: SecretId, min_nodes: u8 },
    /// Must have sufficient quota headroom in the target zone store
    ZoneQuotaHeadroom { zone_id: ZoneId, min_free_mb: u32 },
}

/// Device preferences (NORMATIVE)
pub enum DevicePreference {
    /// Prefer devices with lower latency
    LowLatency { max_ms: u32, weight: f32 },
    /// Prefer devices with more resources
    HighResources { weight: f32 },
    /// Prefer specific device
    SpecificDevice { node_id: TailscaleNodeId, weight: f32 },
    /// Prefer devices where data is local
    DataLocality { object_ids: Vec<ObjectId>, weight: f32 },
}
```

The planner filters devices by `PlacementPolicy.requires` and scores them by `prefers`,
including latency, resources, data locality, secret reconstruction cost, and DERP penalties.

---

## 17. Observability and Audit

### 17.1 Metrics (NORMATIVE)

Required metrics:

- Request counts, latencies, error rates
- Resource usage
- Rate-limit denials
- Zone/taint denials

### 17.2 Structured Logs

Structured logs MUST:

- Be JSON
- Redact secrets
- Include `correlation_id`, `zone_id`, and `connector_id`

### 17.3 Audit Chain (NORMATIVE)

Audit is an append-only, hash-linked object chain per zone. This makes "tamper-evident by construction"
a testable, interoperable mechanism.

Audit events MUST be recorded for:

- Secret access
- High-risk capability use
- Approvals/elevations
- Zone transitions
- Security violations

```rust
/// Audit event (NORMATIVE)
pub struct AuditEvent {
    pub header: ObjectHeader,
    /// Correlation ID for request tracing
    pub correlation_id: [u8; 16],
    /// Optional full trace context (NORMATIVE when present in InvokeRequest)
    /// Enables stitching mesh routing, connector execution, receipts, and audit together.
    pub trace_context: Option<TraceContext>,
    /// Event type (e.g., "secret.access", "capability.invoke", "elevation.granted")
    pub event_type: String,
    /// Actor who triggered the event
    pub actor: PrincipalId,
    /// Zone where event occurred
    pub zone_id: ZoneId,
    /// Connector ID (if applicable)
    pub connector_id: Option<ConnectorId>,
    /// Operation ID (if applicable)
    pub operation: Option<OperationId>,
    /// Capability token JTI (if applicable)
    pub capability_token_jti: Option<Uuid>,
    /// Request object ID (if applicable)
    pub request_object_id: Option<ObjectId>,
    /// Result object ID (if applicable)
    pub result_object_id: Option<ObjectId>,
    /// Previous event in chain (hash link)
    pub prev: Option<ObjectId>,
    /// Monotonic chain sequence number (NORMATIVE)
    pub seq: u64,
    /// When event occurred
    pub occurred_at: u64,
    /// Signature by executing node
    pub signature: Signature,
}

/// Audit head checkpoint (NORMATIVE)
pub struct AuditHead {
    pub header: ObjectHeader,
    /// Zone this head covers
    pub zone_id: ZoneId,
    /// Head event ObjectId
    pub head_event: ObjectId,
    /// Sequence number of head_event (NORMATIVE)
    pub head_seq: u64,
    /// Fraction of expected nodes contributing
    pub coverage: f64,
    /// Epoch this head was checkpointed
    pub epoch_id: EpochId,
    /// Quorum signatures from nodes
    pub quorum_signatures: Vec<(TailscaleNodeId, Signature)>,
}

/// Structured quorum signature with explicit signer attribution (NORMATIVE)
///
/// Each signature in a quorum-signed checkpoint MUST include:
/// - The signing node's identity
/// - The key ID used for this signature
/// - The signature itself
pub struct QuorumSignature {
    /// Tailscale node ID of the signer
    pub signer_node: TailscaleNodeId,
    /// Key ID (first 8 bytes of BLAKE3-256("fcp.kid.v2" || pubkey))
    pub signer_kid: [u8; 8],
    /// Ed25519 signature over checkpoint content
    pub sig: Signature,
}

/// Zone checkpoint for fast sync (NORMATIVE)
///
/// Quorum-signed checkpoint of zone state for efficient synchronization.
/// Nodes can compare checkpoints to quickly determine staleness.
/// Acts as the single GC root (so reachability GC is well-defined).
pub struct ZoneCheckpoint {
    pub header: ObjectHeader,
    pub zone_id: ZoneId,
    /// Optional backpointer for chain validation and fork detection (NORMATIVE)
    /// If Some, the signer attests that prev_checkpoint was their prior tip.
    pub prev_checkpoint: Option<ObjectId>,
    /// Enforceable heads (NORMATIVE):
    pub rev_head: ObjectId,
    pub rev_seq: u64,
    pub audit_head: ObjectId,
    pub audit_seq: u64,
    /// Policy/config heads (NORMATIVE):
    pub zone_definition_head: ObjectId,
    pub zone_policy_head: ObjectId,
    pub active_zone_key_manifest: ObjectId,
    /// Monotonic checkpoint sequence (NORMATIVE; per-zone)
    pub checkpoint_seq: u64,
    pub as_of_epoch: EpochId,
    /// Quorum-signed (Byzantine-resilient under n/f model)
    pub quorum_signatures: Vec<QuorumSignature>,
}
```

**Quorum Rule (default):** CriticalWrite requires n - f signatures (see V2 spec §18).
Nodes MUST refuse to advance AuditHead if quorum is not satisfied, unless in explicit degraded mode.

**Fork Detection (NORMATIVE):** Nodes discovering multiple heads for the same epoch MUST:
1. Log the fork event
2. Refuse to advance until reconciled
3. Alert owner for manual resolution

---

## 18. Connector Archetypes (V2) and Patterns

### 18.1 V2 Archetypes (Manifest `archetypes`)

- Bidirectional: send and receive messages
- Streaming: emit events (read-only)
- Operational: execute operations (request/response)
- Storage: store/retrieve data
- Knowledge: search/index/answer

Only these values are valid in `connector.archetypes`.

### 18.2 Interaction Pattern Mapping (Non-archetype)

These patterns map to V2 archetypes in the manifest:

- Request/Response -> Operational
- Polling -> Operational (often paired with Streaming events)
- Webhook -> Streaming (and/or Operational for acknowledgments)
- Queue/Pub-Sub -> Bidirectional or Streaming depending on API

### 18.3 Reference Connector Patterns (Appendix C)

| Pattern | Description | Examples |
|---------|-------------|----------|
| Unified Messaging | Maps channels to zones | Telegram, Discord |
| Workspace | Local caching, write gating | Gmail, Calendar |
| Knowledge | Filesystem watch + search | Obsidian, Notion |
| DevOps | Typed CLI wrappers | gh, kubectl |

---

## 19. Rust Connector Skeleton (SDK-aligned)

### 19.1 Toolchain Requirements

- Rust edition: 2024 (nightly required)
- Cargo only
- `#![forbid(unsafe_code)]`

### 19.2 Minimal Skeleton (Control-Plane Object Dispatch)

```rust
#![forbid(unsafe_code)]

use async_trait::async_trait;
use fcp_core::{
    Connector, ControlPlaneObject, FcpError,
};

#[async_trait]
pub trait FcpConnector {
    fn metadata(&self) -> Connector;
    async fn handle_control_plane(&self, obj: ControlPlaneObject) -> Result<ControlPlaneObject, FcpError>;
}

pub struct MyConnector {
    // clients, config, caches
}

#[async_trait]
impl FcpConnector for MyConnector {
    fn metadata(&self) -> Connector {
        // Return Connector metadata consistent with manifest
        unimplemented!()
    }

    async fn handle_control_plane(&self, obj: ControlPlaneObject) -> Result<ControlPlaneObject, FcpError> {
        // Dispatch by SchemaId from obj.header.schema:
        // handshake | describe | introspect | capabilities | configure | invoke | subscribe | health | shutdown
        unimplemented!()
    }
}
```

Implementation notes:

- Dispatch on SchemaId, not JSON method strings.
- Validate inputs against the manifest schemas.
- Enforce Strict idempotency when required; return prior receipts on duplicate idempotency_key.
- When producing mesh objects, include `ObjectHeader` with provenance.

---

## 20. Conformance Checklist (Connector)

**Per-Sender Nonce/Subkey Summary (Connector-Facing):**
For every zone, maintain a per-sender monotonic `frame_seq` per `(zone_id, zone_key_id)` and
derive nonces as `frame_seq_le || esi_le`. Encrypt/decrypt symbols with a per-sender subkey
derived from the zone key and `source_id`. Never reuse a `frame_seq` for the same zone key.

Connector MUST:

**Protocol:**
- Implement `--manifest` flag.
- Implement standard methods: `handshake`, `describe`, `introspect`, `capabilities`, `configure`, `invoke`, `health`, `shutdown`.
- Support event cursors and replay when streaming.
- Support session authentication for high-throughput data plane.

**Capability & Security:**
- Declare required/optional/forbidden capabilities in the manifest.
- Use `network.egress` capability through MeshNode proxy (not raw sockets) in strict/moderate sandboxes.
- Validate inputs against manifest schemas.
- Never log secrets.

**State & Provenance:**
- Include `ObjectHeader` with provenance when producing mesh objects.
- Use `effective_taint()` for taint checks (respecting `taint_reductions`).
- Externalize state to `ConnectorStateObject` (authoritative state lives in mesh, not local cache).
- Use `singleton_writer = true` in manifest if connector requires single-writer semantics.

**Approval & Authorization:**
- Use unified `ApprovalToken` with `ApprovalScope::Elevation` or `ApprovalScope::Declassification`.
- Support `approval_tokens: Vec<ApprovalToken>` in `InvokeRequest`.
- Verify `rev_seq` for O(1) freshness checks on capability tokens.

**Supply Chain (RECOMMENDED):**
- Include supply chain attestations in manifest (`[supply_chain]` section).
- Support transparency log entries.
- Include AI hints for operations.

**Session and Transport (NORMATIVE):**
- Use HMAC-SHA256 or BLAKE3 for session MACs (NOT Poly1305 across multiple frames).
- Negotiate crypto suite via `MeshSessionHello`/`MeshSessionAck`.
- Derive directional MAC keys (k_mac_i2r, k_mac_r2i) from session PRK.
- Maintain per-sender monotonic `frame_seq`; encrypt via per-sender subkeys.

**Provable Authority (NORMATIVE):**
- Verify `grant_object_ids` in CapabilityToken to confirm token grants ⊆ object grants.
- Bind tokens to specific connector binaries via `aud_binary` for Risky/Dangerous ops.

**Exactly-Once Semantics (NORMATIVE for Strict + Risky/Dangerous):**
- Store `OperationIntent` BEFORE executing external side effects.
- Reference intent from `OperationReceipt` via `ObjectHeader.refs`.

**Observability (NORMATIVE when present):**
- Propagate `TraceContext` from `InvokeRequest` to `AuditEvent` for end-to-end tracing.

**Fuzzing and Adversarial Tests (NORMATIVE for reference implementation):**

The `fcp-conformance` crate MUST include fuzz targets for:
1. FCPS frame parsing (invalid lengths, malformed symbol counts, checksum edge cases)
2. Session handshake transcript verification (replay, splicing, nonce reuse)
3. CapabilityToken verification (`grant_object_ids` inconsistencies, revocation staleness)
4. ZoneKeyManifest parsing and sealed key unwrap behavior

At least one corpus MUST include "decode DoS" adversarial inputs designed to maximize decode CPU.

---

## Notes

- This document is V2-only; backwards compatibility with FCP1 is not a goal.
- For mesh, symbol, audit, and trust-anchor details, refer to `FCP_Specification_V2.md`.
- All normative structures in this document are aligned with FCP Specification V2.
