# Flywheel Connector Protocol (FCP)

<div align="center">
  <img src="fcp_illustration.webp" alt="FCP - Secure connectors for AI agents with zone-based isolation and capability tokens">
</div>

> **Specification note:** `FCP_Specification_V2.md` is the *authoritative* interoperability contract.
> This README is a high-level overview; when diagrams conflict, implement the Spec.

A mesh-native protocol for secure, distributed AI assistant operations across personal device meshes — plus a growing library of production-ready Rust connectors implementing that protocol.

---

## TL;DR

**This project is two things:**

1. **The FCP Protocol** — A mesh-native specification for how AI agents securely interact with external services through zone-isolated, capability-gated connectors distributed across your personal device mesh

2. **Connector Implementations** — Production Rust binaries for Twitter, Linear, Stripe, Telegram, Discord, Gmail, GitHub, browser automation, and more

**The Vision**: Your personal AI runs on YOUR devices. Your data exists as symbols across YOUR mesh. Any subset of YOUR devices can reconstruct anything. Computation happens wherever optimal. Secrets are never complete anywhere. History is tamper-evident by construction.

**This is not a cloud alternative. This is digital sovereignty.**

**Registry Note**: Registries are just sources of signed manifests/binaries. Your mesh can mirror and pin connectors as content-addressed objects so installs/updates work offline and without upstream dependency.

### Three Foundational Axioms

| Axiom | Principle |
|-------|-----------|
| **Universal Fungibility** | All durable mesh objects are symbol-addressable: any K' symbols reconstruct the canonical object bytes. Control-plane messages MAY travel over FCPC streams for efficiency, but the canonical representation is still a content-addressed mesh object. |
| **Authenticated Mesh** | Tailscale IS the transport AND the identity layer. Every node has unforgeable WireGuard keys. |
| **Explicit Authority** | No ambient authority. All capabilities flow from owner key through cryptographic chains. |

### Why Use FCP?

| Feature | What It Does |
|---------|--------------|
| **Mesh-Native Architecture** | Every device IS the Hub. No central coordinator. |
| **Symbol-First Protocol** | RaptorQ fountain codes enable multipath aggregation and offline resilience |
| **Zone Isolation** | Cryptographic namespaces with integrity/confidentiality axes and Tailscale ACL enforcement |
| **Mesh-Stored Policy Objects** | Zone definitions + policies are owner-signed mesh objects (auditable + rollbackable) |
| **Capability Tokens (CWT/COSE)** | Provable authority with grant_object_ids; tokens are canonically CBOR-encoded and COSE-signed for interoperability |
| **Threshold Owner Key** | FROST signing so no single device holds the complete owner private key |
| **Threshold Secrets** | Shamir secret sharing with k-of-n across devices—never complete anywhere |
| **Secretless Connectors** | Egress proxy can inject credentials so connectors never see raw API keys by default |
| **Computation Migration** | Operations execute on the optimal device automatically |
| **Offline Access** | Measurable availability SLOs via ObjectPlacementPolicy and background repair |
| **Tamper-Evident Audit** | Hash-linked audit chain with monotonic seq and quorum-signed checkpoints |
| **Revocation** | First-class revocation objects with O(1) freshness checks |
| **Egress Proxy** | Connector network access via capability-gated proxy with CIDR deny defaults |
| **Supply Chain Attestations** | in-toto/SLSA provenance + SBOM + vulnerability-scan attestations, transparency logging |

### Quick Example

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           PERSONAL MESH                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   ┌──────────┐      ┌──────────┐      ┌──────────┐                      │
│   │ Desktop  │◄────►│  Laptop  │◄────►│  Phone   │  ← Tailscale mesh    │
│   │ MeshNode │      │ MeshNode │      │ MeshNode │                      │
│   └────┬─────┘      └────┬─────┘      └────┬─────┘                      │
│        │                 │                 │                             │
│        ▼                 ▼                 ▼                             │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │                    SYMBOL DISTRIBUTION                           │   │
│   │  Object: gmail-inbox-2026-01   K=100 symbols distributed        │   │
│   │  Desktop: [1,5,12,23,...]  Laptop: [2,8,15,...]  Phone: [3,9,...]│   │
│   │  Any 100 symbols → full reconstruction                          │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│   Agent Request                                                          │
│       │                                                                  │
│       ▼                                                                  │
│   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐               │
│   │ Zone Check  │────►│  Cap Check  │────►│  Connector  │               │
│   │ z:private?  │     │ gmail.read? │     │   Gmail     │               │
│   │ (crypto+ACL)│     │ (signed)    │     │ (sandboxed) │               │
│   └─────────────┘     └─────────────┘     └─────────────┘               │
│         │                   │                   │                        │
│         ▼                   ▼                   ▼                        │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │  Revocation Check → Receipt Generation → Audit Event Logged     │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                  │                       │
│                                                  ▼                       │
│                                           Gmail API                      │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Origins & Motivation

This project emerged from the Agent Flywheel ecosystem, where AI coding agents coordinate across multiple external services. Existing approaches to multi-service integration suffer from critical security flaws:

1. **Trust Commingling**: A message from a public Discord channel could trigger operations on private Gmail
2. **Prompt-Based Security**: "Don't read private emails" is trivially bypassed by prompt injection
3. **Centralized Architecture**: Single points of failure, cloud dependency, vendor lock-in
4. **Binary Offline**: No connectivity = no access

FCP addresses these through:
- **Zones as cryptographic universes**—if the Gmail-read capability doesn't exist in a zone, it cannot be invoked, regardless of what an agent says
- **Mesh-native architecture**—your devices collectively ARE the system
- **Symbol-first protocol**—data availability is probabilistic, not binary
- **Revocation as first-class primitive**—compromised devices can be removed and keys rotated

---

## Core Concepts

### Terminology

| Term | Definition |
|------|------------|
| **Symbol** | A RaptorQ-encoded fragment; any K' symbols reconstruct the original |
| **Object** | Content-addressed data with ObjectHeader (refs, retention, provenance) |
| **Zone** | A cryptographic namespace with its own symmetric encryption key |
| **Epoch** | A logical time unit; no ordering within, ordering between |
| **MeshNode** | A device participating in the FCP mesh |
| **Capability** | An authorized operation with cryptographic proof; grant_object_ids enable mechanical verification |
| **Role** | Named bundle of capabilities (RoleObject) for simplified policy administration |
| **ResourceObject** | Zone-bound handle for external resources (files, repos, APIs) enabling auditable access control |
| **Resource Visibility** | ResourceObjects carry public/private classification; MeshNode enforces declassification when writing higher-confidentiality data to lower-confidentiality external resources |
| **Connector** | A sandboxed binary or WASI module that bridges external services to FCP |
| **Receipt** | Signed proof of operation execution for idempotency |
| **Revocation** | First-class object that invalidates tokens, keys, or devices |

### Key Architecture

FCP uses five distinct cryptographic key roles:

| Key Type | Algorithm | Purpose |
|----------|-----------|---------|
| **Owner Key** | Ed25519 | Root trust anchor; signs attestations and revocations. SHOULD use threshold signing (FROST) so no single device holds the complete private key. |
| **Node Signing Key** | Ed25519 | Per-device; signs frames, gossip, receipts |
| **Node Encryption Key** | X25519 | Per-device; receives sealed zone keys and secret shares |
| **Node Issuance Key** | Ed25519 | Per-device; mints capability tokens (separately revocable) |
| **Zone Encryption Key** | ChaCha20-Poly1305 | Per-zone symmetric key; encrypts zone data via AEAD |

Every node has a **NodeKeyAttestation** signed by the owner, binding the Tailscale node ID to all three node key types plus their Key IDs (KIDs) for rotation tracking. Issuance keys are separately revocable so token minting can be disabled without affecting other node functions.

**Threshold Owner Key (Recommended):** The owner key produces standard Ed25519 signatures, but implementations SHOULD use FROST (k-of-n threshold signing) so no single device ever holds the complete owner private key. This provides catastrophic compromise resistance and loss tolerance.

### Security Invariants

These are **hard requirements** that FCP enforces mechanically:

1. **Single-Zone Binding**: A connector instance MUST bind to exactly one zone for its lifetime
2. **Default Deny**: If a capability is not explicitly granted to a zone, it MUST be impossible to invoke
3. **No Cross-Connector Calling**: Connectors MUST NOT call other connectors directly; all composition happens through the mesh
4. **Threshold Secret Distribution**: Secrets use Shamir sharing—never complete on any single device
5. **Revocation Enforcement**: Tokens, keys, and operations MUST check revocation before use
6. **Auditable Everything**: Every operation produces a signed receipt and audit event
7. **Cryptographic Authority Chain**: All authority flows from owner key through verifiable signature chains

---

## Zone Architecture

Zones are **cryptographic boundaries**, not labels. Each zone has its own randomly generated symmetric encryption key, distributed to eligible nodes via owner-signed `ZoneKeyManifest` objects. HKDF is used for subkey derivation (e.g., per-sender subkeys incorporating sender_instance_id for reboot safety), not for deriving zone keys from owner secret material.

### Zone Hierarchy with Tailscale Mapping

```
z:owner        [Trust: 100]  Direct owner control, most privileged
    │                        Tailscale tag: tag:fcp-owner
    ▼
z:private      [Trust: 80]   Personal data, high sensitivity
    │                        Tailscale tag: tag:fcp-private
    ▼
z:work         [Trust: 60]   Professional context, medium sensitivity
    │                        Tailscale tag: tag:fcp-work
    ▼
z:community    [Trust: 40]   Trusted external (paired users)
    │                        Tailscale tag: tag:fcp-community
    ▼
z:public       [Trust: 20]   Public/anonymous inputs
                             Tailscale tag: tag:fcp-public

INVARIANTS:
  Integrity: Data can flow DOWN (higher → lower) freely.
             Data flowing UP requires explicit ApprovalToken (elevation).
  Confidentiality: Data can flow UP (lower → higher) freely.
                   Data flowing DOWN requires ApprovalToken (declassification).
```

### Provenance and Taint

Every piece of data carries provenance tracking:

| Field | Purpose |
|-------|---------|
| `origin_zone` | Where data originated |
| `current_zone` | Updated on every zone crossing |
| `integrity_label` | Numeric integrity level (higher = more trusted source) |
| `confidentiality_label` | Numeric confidentiality level (higher = more sensitive) |
| `label_adjustments` | Proof-carrying label changes (elevation, declassification) with ApprovalToken references |
| `taint` | Compositional flags (PUBLIC_INPUT, EXTERNAL_INPUT, PROMPT_SURFACE, etc.) |
| `taint_reductions` | Proof-carrying reductions via SanitizerReceipt references |

**Security-Critical Merge Rule**: When combining data from multiple sources, the result inherits `MIN(integrity)` and `MAX(confidentiality)`. This ensures compromised inputs can't elevate trust and sensitive outputs can't be inadvertently exposed.

**Taint Reduction**: Instead of taint only ever accumulating (which leads to "approve everything" fatigue), specific taints can be cleared when you have a verifiable `SanitizerReceipt` from a sanitizer capability (URL scanner, malware scanner, schema validator). The receipt is a first-class mesh object that proves the sanitization happened.

### Defense-in-Depth

```
Layer 1: Tailscale ACLs     → Network-level isolation
Layer 2: Zone Encryption    → Cryptographic isolation (per-zone symmetric keys)
Layer 3: Policy Objects     → Authority isolation
Layer 4: Capability Signing → Operation isolation (node-signed tokens)
Layer 5: Revocation Check   → Continuous validity enforcement
```

---

## Symbol Layer

All data in FCP flows as RaptorQ fountain-coded symbols.

### Why Symbols?

```
Traditional Approach:
  File: 100KB → Must transfer complete file
  Lost packet → Retransmit specific data
  Single path → Bandwidth limited

Symbol Approach:
  File: 100KB → 100 symbols (1KB each)
  Any 100 symbols → Full reconstruction
  No symbol is special → No retransmit coordination
  Multipath aggregation → Symbols from any source contribute equally
```

### Symbol Properties

| Property | Benefit |
|----------|---------|
| **Fungibility** | Any K' symbols reconstruct; no coordination needed |
| **Multipath** | Aggregate bandwidth across all network paths |
| **Resumable** | No bookkeeping; just collect more symbols |
| **DoS Resistant** | Attackers can't target "important" symbols |
| **Offline Resilient** | Partial availability = partial reconstruction |
| **Key Rotation Safe** | zone_key_id in each symbol enables seamless rotation |
| **Chunked Objects** | Large payloads split via ChunkedObjectManifest for partial retrieval and targeted repair |

### Frame Format (FCPS)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       FCPS FRAME FORMAT (Symbol-Native)                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Bytes 0-3:    Magic (0x46 0x43 0x50 0x53 = "FCPS")                         │
│  Bytes 4-5:    Version (u16 LE)                                             │
│  Bytes 6-7:    Flags (u16 LE)                                               │
│  Bytes 8-11:   Symbol Count (u32 LE)                                        │
│  Bytes 12-15:  Total Payload Length (u32 LE)                                │
│  Bytes 16-47:  Object ID (32 bytes)                                         │
│  Bytes 48-49:  Symbol Size (u16 LE, default 1024)                           │
│  Bytes 50-57:  Zone Key ID (8 bytes, for rotation)                          │
│  Bytes 58-89:  Zone ID hash (32 bytes, BLAKE3; fixed-size)                  │
│  Bytes 90-97:  Epoch ID (u64 LE)                                            │
│  Bytes 98-105: Sender Instance ID (u64 LE, reboot-safety)                   │
│  Bytes 106-113: Frame Seq (u64 LE, per-sender monotonic counter)            │
│  Bytes 114+:   Symbol payloads (encrypted, concatenated)                    │
│                                                                             │
│  Fixed header: 114 bytes                                                    │
│  NOTE: No separate checksum. Integrity provided by per-symbol AEAD tags     │
│        and per-frame session MAC (AuthenticatedFcpsFrame).                  │
│  Per-symbol nonce: derived as frame_seq || esi_le (deterministic)           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Session Authentication

High-throughput symbol delivery uses per-session authentication (not per-frame signatures):

1. **Handshake**: X25519 ECDH authenticated by attested node signing keys, with per-party nonces for replay protection and crypto suite negotiation
2. **Session keys**: HKDF-derived directional MAC keys (k_mac_i2r, k_mac_r2i) from ECDH shared secret, bound to both handshake nonces
3. **Per-sender subkeys**: Each sender derives a unique subkey via HKDF including sender_instance_id, eliminating cross-sender and cross-reboot nonce collision risk
4. **Per-frame MAC**: HMAC-SHA256 or BLAKE3 (negotiated) with per-sender monotonic frame_seq for anti-replay

**Crypto Suite Negotiation**: Initiator proposes supported suites; responder selects. Suite1 uses HMAC-SHA256 (broad compatibility), Suite2 uses BLAKE3 (performance). This avoids Poly1305 single-use constraints while enabling future algorithm agility.

**Session Rekey Triggers**: Sessions automatically rekey after configurable thresholds—frames (default: 1B), elapsed time (default: 24h), or cumulative bytes (default: 1 TiB)—to bound key exposure and avoid pathological long-lived sessions.

This amortizes Ed25519 signature cost over many frames while preserving cryptographic attribution and preventing nonce reuse across senders.

### Control Plane Framing (FCPC)

While FCPS handles high-throughput symbol delivery, FCPC provides reliable, ordered, backpressured framing for control-plane objects (invoke, response, receipts, approvals, audit events). FCPC uses the session's negotiated `k_ctx` symmetric key for AEAD encryption/authentication, enabling secure control messages without per-message Ed25519 signatures.

---

## Mesh Architecture

Every device is a MeshNode—collectively, they ARE the Hub.

### MeshNode Components

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              MESHNODE                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Tailscale Identity                                                  │    │
│  │  • Stable node ID (unforgeable WireGuard keys)                      │    │
│  │  • Node signing/encryption/issuance keys with owner attestation     │    │
│  │  • ACL tags for zone mapping                                         │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Symbol Store                                                        │    │
│  │  • Local symbol storage with node-local retention classes            │    │
│  │  • Quarantine store for unreferenced objects (bounded; not gossiped) │    │
│  │  • XOR filters + IBLT for efficient gossip reconciliation           │    │
│  │  • Reachability-based garbage collection                             │    │
│  │  • ObjectPlacementPolicy enforcement for availability SLOs          │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Capability & Revocation Registry                                    │    │
│  │  • Zone keyrings for deterministic key selection by zone_key_id     │    │
│  │  • Trust anchors (owner key, attested node keys)                    │    │
│  │  • Monotonic seq numbers for O(1) freshness checks                  │    │
│  │  • ZoneCheckpoint checkpoints for fast sync                           │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Connector State Manager                                             │    │
│  │  • Externalized connector state as mesh objects                     │    │
│  │  • Single-writer semantics via execution leases with fencing tokens │    │
│  │  • Multi-writer CRDT support (LWW-Map, OR-Set, counters)            │    │
│  │  • Safe failover and migration for stateful connectors              │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Execution Planner                                                   │    │
│  │  • Device profiles (CPU, GPU, memory, battery)                       │    │
│  │  • Connector availability and version requirements                   │    │
│  │  • Secret reconstruction cost estimation                             │    │
│  │  • Symbol locality scoring, DERP penalty                            │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Repair Controller                                                   │    │
│  │  • Background symbol coverage evaluation                            │    │
│  │  • Automatic repair toward ObjectPlacementPolicy targets            │    │
│  │  • Rebalancing after device churn or offline periods                │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Egress Proxy                                                        │    │
│  │  • Connector network access via capability-gated IPC                │    │
│  │  • CIDR deny defaults (localhost, private, tailnet ranges)          │    │
│  │  • SNI enforcement, SPKI pinning                                    │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Audit Chain                                                         │    │
│  │  • Hash-linked audit events per zone with monotonic seq             │    │
│  │  • Quorum-signed audit heads for tamper evidence                    │    │
│  │  • Operation receipts for idempotency                                │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Transport Priority

```
Priority 1: Tailscale Direct (same LAN)
Priority 2: Tailscale Mesh (NAT traversal)
Priority 3: Tailscale DERP Relay            (policy-controlled per zone)
Priority 4: Tailscale Funnel (public)       (policy-controlled; low-trust zones only by default)
```

Zones configure transport policy via `ZoneTransportPolicy` to control DERP/Funnel availability.

### Device Enrollment

New devices join the mesh through owner-signed enrollment:

1. Device joins Tailscale tailnet
2. Owner issues `DeviceEnrollment` object (signed)
3. Owner issues `NodeKeyAttestation` binding node to signing key (optionally with `DevicePostureAttestation` for hardware-backed key requirements)
4. Device receives enrollment via mesh gossip
5. Other nodes accept the new device as peer

Sensitive zones (e.g., z:owner) may require hardware-backed keys via `DevicePostureAttestation` (TPM, Secure Enclave, Android Keystore) to prevent software-only device compromise from accessing high-value secrets.

Device removal triggers revocation + zone key rotation + secret resharing.

---

## Connector Binary Structure

Every FCP connector is a single executable with embedded metadata:

```
┌────────────────────────────────────────────────────────────────┐
│                        FCP BINARY                               │
├────────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    MANIFEST SECTION                       │  │
│  │  ┌─────────────────┐  ┌─────────────────┐                │  │
│  │  │  Metadata       │  │  Capabilities   │                │  │
│  │  │  - Name         │  │  - Required     │                │  │
│  │  │  - Version      │  │  - Optional     │                │  │
│  │  │  - Author       │  │  - Forbidden    │                │  │
│  │  └─────────────────┘  └─────────────────┘                │  │
│  │  ┌─────────────────┐  ┌─────────────────┐                │  │
│  │  │  Zone Policy    │  │  Sandbox Config │                │  │
│  │  │  - Home zone    │  │  - Memory limit │                │  │
│  │  │  - Allowed      │  │  - CPU limit    │                │  │
│  │  │  - Tailscale tag│  │  - FS access    │                │  │
│  │  └─────────────────┘  └─────────────────┘                │  │
│  │  ┌─────────────────┐                                      │  │
│  │  │  AI Hints       │  ← Agent-readable operation docs     │  │
│  │  │  - Operations   │                                      │  │
│  │  │  - Examples     │                                      │  │
│  │  │  - Safety notes │                                      │  │
│  │  └─────────────────┘                                      │  │
│  └──────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    CODE SECTION                           │  │
│  │  - FCP protocol implementation                            │  │
│  │  - Capability negotiation                                 │  │
│  │  - External API clients                                   │  │
│  │  - State management                                       │  │
│  └──────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                   SIGNATURE SECTION                       │  │
│  │  - Ed25519 signature over manifest + code                 │  │
│  │  - Reproducible build attestation                         │  │
│  │  - Registry provenance chain                              │  │
│  └──────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────┘
```

### Sandbox Enforcement

Connectors support two sandbox models:

**Native (ELF/Mach-O/PE)**: OS-level sandboxes (seccomp/seatbelt/AppContainer)

**WASI (WebAssembly)**: WASM-based isolation with capability-gated hostcalls. Recommended for high-risk connectors (financial, credential-handling) due to memory isolation and cross-platform consistency.

| Constraint | Purpose |
|------------|---------|
| Memory limit | Prevent resource exhaustion |
| CPU limit | Prevent runaway computation |
| Wall clock timeout | Bound operation duration |
| FS readonly paths | Limit filesystem access |
| FS writable paths | Explicit state directory |
| deny_exec | Prevent child process spawning |
| deny_ptrace | Prevent debugging/tracing |
| NetworkConstraints | Explicit host/port/TLS requirements |

### Connector State

Connectors with polling/cursors/dedup caches externalize their canonical state into the mesh:

```
ConnectorStateRoot {
  connector_id     → Which connector
  zone_id          → Which zone
  head             → Latest ConnectorStateObject
}

ConnectorStateObject {
  prev             → Hash link to previous state
  seq              → Monotonic sequence
  state_cbor       → Canonical connector-specific state
  signature        → Node signature
}
```

**Periodic Snapshots**: Connectors emit `ConnectorStateSnapshot` objects at configurable intervals, enabling compaction of the state chain while preserving fork detection for singleton_writer connectors.

**Local `$CONNECTOR_STATE` is a cache only**—the authoritative state lives as mesh objects. This enables:

- **Safe failover**: Another node can resume from last committed state
- **Resumable polling**: Cursors survive node restarts and migrations
- **Deterministic migration**: State is explicit, not implicit in process memory

**Single-Writer Semantics**: Connectors declaring `singleton_writer = true` use execution leases to ensure only one node writes state at a time. Leases are coordinated via HRW (rendezvous hashing) to deterministically select a coordinator from online nodes, with quorum signatures for distributed issuance. This prevents double-polling and cursor conflicts while surviving coordinator failures.

---

## Security Model

### Threat Model

FCP defends against:

| Threat | Mitigation |
|--------|------------|
| Compromised device | Threshold owner key (FROST), threshold secrets (Shamir), revocation, zone key rotation |
| Malicious connector binary | Ed25519 signature verification, OS sandboxing, supply chain attestations (in-toto/SLSA) |
| Compromised external service | Zone isolation, capability limits |
| SSRF / localhost attacks | Egress proxy with CIDR deny defaults (localhost, private, tailnet ranges) |
| Prompt injection via messages | Protocol-level filtering, taint tracking with proof-carrying reductions, no code execution |
| Privilege escalation | Static capability allocation, no runtime grants, unified ApprovalToken for elevation/declassification |
| Replay attacks | Session MACs with monotonic seq, epoch binding, receipts |
| DoS / resource exhaustion | Admission control with PeerBudget, anti-amplification rules, per-peer rate limiting |
| Key compromise | Revocation objects with monotonic seq for O(1) freshness, key rotation with zone_key_id |
| Supply chain attacks | in-toto attestations, SLSA provenance, reproducible builds, transparency log, mesh mirroring |

### Threshold Secrets

Secrets use **Shamir's Secret Sharing** (not RaptorQ symbols—those can leak structure):

```
Secret: API_KEY
Scheme: Shamir over GF(2^8), k=3, n=5

Distribution:
  Desktop: share_1 (wrapped for Desktop's public key)
  Laptop:  share_2 (wrapped for Laptop's public key)
  Phone:   share_3 (wrapped for Phone's public key)
  Tablet:  share_4 (wrapped for Tablet's public key)
  Server:  share_5 (wrapped for Server's public key)

To use secret:
  1. Obtain SecretAccessToken (signed by approver)
  2. Collect any 3 wrapped shares
  3. Unwrap and reconstruct using Shamir
  4. Use in memory only
  5. Zeroize immediately after use
  6. Log audit event

No single device ever has the complete secret.
A node cannot decrypt other nodes' shares.
```

### Operation Receipts

Operations with side effects produce signed receipts:

```
OperationReceipt {
  request_object_id    → What was requested
  idempotency_key      → For deduplication
  outcome_object_ids   → What was produced
  executed_at          → When
  executed_by          → Which node
  signature            → Node's signing key
}
```

On retry with same idempotency key, mesh returns prior receipt instead of re-executing.

**OperationIntent Pre-commit**: For Strict or Risky operations, callers first write an `OperationIntent` object containing the idempotency key, then invoke. Executors check that the intent exists, preventing accidental re-execution during retries. This provides exactly-once semantics for operations with external side effects.

### Revocation

First-class revocation objects can invalidate:

| Scope | Effect |
|-------|--------|
| Capability | Token becomes invalid |
| IssuerKey | Node can no longer mint tokens |
| NodeAttestation | Device removed from mesh |
| ZoneKey | Forces key rotation |
| ConnectorBinary | Supply chain incident response |

Revocations are owner-signed and enforced before every operation.

**Revocation Freshness Policy**: Tiered behavior for offline/degraded scenarios:
- **Strict**: Requires fresh revocation check or abort (default for Risky/Dangerous operations)
- **Warn**: Log warning but proceed if cached revocation list is within max_age
- **BestEffort**: Use stale cache if offline, log degraded state

### Admission Control

Nodes enforce per-peer resource budgets to prevent DoS:

| Mechanism | Purpose |
|-----------|---------|
| **PeerBudget** | Per-peer limits on bytes/sec, frames/sec, pending requests |
| **Anti-amplification** | Response size ≤ N × request size until peer authenticated |
| **Rate limiting** | Sliding window enforcement with configurable burst |
| **Backpressure** | Reject new requests when budget exhausted |

### Audit Chain

Every zone maintains a hash-linked audit chain with monotonic sequence numbers:

```
AuditEvent_1 → AuditEvent_2 → AuditEvent_3 → ... → AuditHead
  seq=1          seq=2          seq=3              head_seq=N
     ↑              ↑              ↑                   ↑
  signed         signed         signed         quorum-signed

ZoneCheckpoint {
  rev_head, rev_seq      → Revocation chain state
  audit_head, audit_seq  → Audit chain state
}
```

- Events are hash-linked (tamper-evident) with monotonic seq for O(1) freshness checks
- AuditHead checkpoints are quorum-signed (n-f nodes)
- ZoneCheckpoint enables fast sync without chain traversal
- Fork detection triggers alerts
- Required events: secret access, risky operations, approvals, zone transitions
- **TraceContext propagation**: W3C-compatible trace_id/span_id flow through InvokeRequest and AuditEvent for end-to-end distributed tracing

---

## Connectors

### Tier 1: Critical Infrastructure (Build First)

These unlock entire categories of autonomous agent work.

| Connector | Value | Archetype | Why Critical |
|-----------|-------|-----------|--------------|
| `fcp.twitter` | 98 | Request-Response + Streaming | Real-time information layer; social listening, posting, DMs |
| `fcp.linear` | 97 | Request-Response + Webhook | Human↔agent task handoff; bi-directional Beads sync |
| `fcp.stripe` | 96 | Request-Response + Webhook | Financial operations; invoicing, subscriptions, analytics |
| `fcp.youtube` | 95 | Request-Response | Video transcripts, channel analytics, content research |
| `fcp.browser` | 95 | Browser Automation | Universal adapter for any web service without API |
| `fcp.telegram` | 94 | Bidirectional + Webhook | Real-time messaging, bot automation |
| `fcp.discord` | 93 | Bidirectional + Webhook | Community management, server automation |

### Tier 2: Productivity & Workspace

| Connector | Archetype | Use Case |
|-----------|-----------|----------|
| `fcp.gmail` | Polling + Request-Response | Email automation, inbox management |
| `fcp.google_calendar` | Request-Response + Polling | Scheduling, availability |
| `fcp.notion` | Request-Response | Knowledge base, documentation |
| `fcp.github` | Request-Response + Webhook | Code review, issue management, CI/CD |
| `fcp.slack` | Bidirectional | Team communication |

### Tier 3: Infrastructure & Data

| Connector | Archetype | Use Case |
|-----------|-----------|----------|
| `fcp.s3` | File/Blob | Cloud storage operations |
| `fcp.postgresql` | Database | Direct database queries |
| `fcp.elasticsearch` | Database | Search and analytics |
| `fcp.redis` | Queue/Pub-Sub | Caching, message queues |
| `fcp.whisper` | CLI/Process | Voice transcription |

---

## Registry Architecture

Registries are **sources, not dependencies**:

| Type | Description |
|------|-------------|
| **Remote Registry** | Public (registry.flywheel.dev) or private HTTP registry |
| **Self-Hosted Registry** | Enterprise internal registry |
| **Mesh Mirror** | Connectors as pinned objects in z:owner (recommended) |

Connector binaries are content-addressed objects distributed via the symbol layer.
Your mesh can install/update connectors fully offline from mirrored objects.

### Supply Chain Verification

Before execution, FCP verifies:

1. Manifest signature (registry or trusted publisher quorum)
2. Binary checksum matches manifest
3. Binary signature matches trusted key
4. Platform/arch match
5. Requested capabilities ⊆ zone ceilings
6. **If policy requires**: Transparency log entry present
7. **If policy requires**: in-toto/SLSA attestations valid
8. **If policy requires**: SLSA provenance meets minimum level
9. **If policy requires**: Attestation from trusted builder

Owner policy can enforce:
- `require_transparency_log = true`
- `require_attestation_types = ["in-toto"]`
- `min_slsa_level = 2`
- `trusted_builders = ["github-actions", "internal-ci"]`

**Optional Enhanced Security:** Registries can use a `RegistrySecurityProfile` with:
- **TUF root pinning** (prevents freeze/rollback and mix-and-match attacks)
- **Sigstore/cosign verification** (adds supply-chain provenance beyond publisher keys)

---

## Performance Targets

| Metric | Target (p50/p99) | How Measured |
|--------|------------------|--------------|
| Cold start (connector activate) | < 100ms / < 500ms | `fcp bench connector-activate` |
| Local invoke latency (same node) | < 2ms / < 10ms | `fcp bench invoke-local` |
| Tailnet invoke latency (LAN) | < 20ms / < 100ms | `fcp bench invoke-mesh --path=direct` |
| Tailnet invoke latency (DERP) | < 150ms / < 500ms | `fcp bench invoke-mesh --path=derp` |
| Symbol reconstruction (1MB) | < 50ms / < 250ms | `fcp bench raptorq --size=1mb` |
| Secret reconstruction (k-of-n) | < 150ms / < 750ms | `fcp bench secrets --k=3 --n=5` |
| Memory overhead | < 10MB per connector | Sandbox limits |
| CPU overhead | < 1% idle | Event-driven architecture |

### Benchmarks

The reference implementation ships a `fcp bench` suite that produces machine-readable results (JSON) for regression tracking.

---

## Ops & Debugging

FCP is designed to be *operable* without disabling security. The CLI exposes the core safety/availability loops:

```bash
# Explain why an operation was denied (DecisionReceipt-backed)
fcp explain --request <objectid>

# Show revocation/checkpoint freshness and degraded mode state
fcp doctor --zone z:private

# Show offline availability SLOs and symbol coverage by placement policy
fcp repair status --zone z:work

# Fix manifest interface hash + lint defaults
fcp manifest fix ./connectors/myconnector/manifest.toml --check

# Tail audit events (per zone) with trace correlation
fcp audit tail --zone z:owner
```

Key principle: **if you can't explain a denial or quantify offline availability, the system isn't finished.**

---

## Profiles and Roadmap

### MVP Profile (Ship First)

Delivers the core safety story ("zones + explicit authority + auditable operations") with minimal moving parts.

- FCPC over QUIC for control plane
- CapabilityToken (COSE/CWT) + grant_object_ids verification
- ZoneKeyManifest (HPKE sealing) + per-zone encryption
- Egress proxy with NetworkConstraints + CIDR deny defaults
- OperationIntent + OperationReceipt for Risky/Dangerous
- Revocation objects + freshness policy
- Basic symbol store + object reconstruction

### Full Profile (Iterate Toward)

- XOR filter + IBLT gossip optimization
- MLS/TreeKEM for post-compromise security in sensitive zones
- Computation migration + device-aware planner
- Advanced repair + predictive pre-staging
- Threshold secrets with k-of-n recovery

---

## Platform Support

| Platform | Architecture | Status |
|----------|--------------|--------|
| Linux | x86_64, aarch64 | Tier 1 |
| macOS | x86_64, aarch64 | Tier 1 |
| Windows | x86_64 | Tier 2 |
| FreeBSD | x86_64 | Tier 3 |

---

## Project Structure

```
flywheel_connectors/
├── crates/
│   ├── fcp-core/          # Core types: zones, capabilities, provenance, errors
│   ├── fcp-protocol/      # Wire protocol: FCPS framing, symbol encoding
│   ├── fcp-mesh/          # Mesh implementation: MeshNode, gossip, routing
│   ├── fcp-raptorq/       # RaptorQ integration: encoding, decoding, distribution
│   ├── fcp-tailscale/     # Tailscale integration: identity, ACLs, routing
│   ├── fcp-secrets/       # Shamir secret sharing, SecretAccessToken
│   ├── fcp-audit/         # Audit chain, receipts, quorum signing
│   ├── fcp-manifest/      # Manifest parsing and validation
│   ├── fcp-sandbox/       # OS sandbox integration (seccomp, seatbelt, AppContainer)
│   ├── fcp-sdk/           # SDK for building connectors
│   ├── fcp-conformance/   # Interop tests, golden vectors, property tests, fuzz harness
│   └── fcp-cli/           # CLI tools (fcp install, fcp doctor, fcp explain, fcp bench, etc.)
│
├── connectors/            # Individual connector implementations
│   ├── twitter/
│   ├── linear/
│   ├── stripe/
│   ├── telegram/
│   ├── discord/
│   └── ...
│
├── FCP_Specification_V2.md   # Protocol specification
├── AGENTS.md                 # AI coding agent guidelines
└── README.md
```

---

## Related Flywheel Components

FCP integrates with the broader Agent Flywheel ecosystem:

| Component | Purpose | Interaction |
|-----------|---------|-------------|
| **Tailscale** | Mesh networking, identity | Transport and ACL layer |
| **MCP Agent Mail** | Inter-agent messaging | Coordinate connector operations |
| **Beads (bd/bv)** | Issue tracking | Track connector development |
| **CASS** | Memory/context system | Store connector interaction history |
| **UBS** | Bug scanning | Validate connector code |
| **dcg** | Command guard | Protect during development |

---

## Development

### Prerequisites

- Rust nightly (2024 edition)
- Cargo
- Tailscale (for mesh features)

### Building

```bash
# Build all connectors
cargo build --release

# Build specific connector
cargo build --release -p fcp-telegram

# Run tests
cargo test

# Run clippy
cargo clippy --all-targets -- -D warnings
```

### Creating a New Connector

1. Create connector crate: `cargo new connectors/myservice --lib`
2. Add FCP SDK dependency
3. Implement `FcpConnector` trait
4. Define manifest with capabilities, zone policy, and sandbox config
5. Add archetype-specific traits
6. Write tests with mocked external service
7. Document AI hints for each operation

---

## Specification Refinement with APR

The FCP specification is refined iteratively using [APR (Automated Plan Reviser Pro)](https://github.com/Dicklesworthstone/automated_plan_reviser_pro), which automates multi-round reviews with GPT Pro 5.2 Extended Reasoning.

### Why Iterative Refinement?

Complex protocol specifications benefit from multiple rounds of AI review. Like gradient descent converging on a minimum, each round focuses on finer details as major issues are resolved:

```
Round 1-3:   Security gaps, architectural flaws
Round 4-7:   Interface refinements, edge cases
Round 8-12:  Nuanced optimizations, abstractions
Round 13+:   Converging on stable design
```

### Setup

Install APR:

```bash
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/automated_plan_reviser_pro/main/install.sh" | bash
```

Install Oracle (GPT Pro browser automation):

```bash
npm install -g @steipete/oracle
```

The workflow is already configured in `.apr/workflows/fcp.yaml`:

```yaml
documents:
  readme: README.md
  spec: FCP_Specification_V2.md
  implementation: docs/fcp_model_connectors_rust.md
```

### Running Revision Rounds

```bash
# First round (requires manual ChatGPT login)
apr run 1 --login --wait

# Subsequent rounds
apr run 2
apr run 3 --include-impl  # Include implementation doc every 3-4 rounds

# Check status
apr status

# View round output
apr show 5
```

### Remote/SSH Setup (Oracle Serve Mode)

If running on a remote server via SSH (no local browser), use Oracle's serve mode:

**On your local machine (with browser):**
```bash
oracle serve --port 9333 --token "your-secret-token"
```

**On the remote server:**
```bash
export ORACLE_REMOTE_HOST="100.x.x.x:9333"  # Local machine's Tailscale IP
export ORACLE_REMOTE_TOKEN="your-secret-token"

# Test connection
oracle -p "test" -e browser -m "5.2 Thinking"

# Now APR works normally
apr run 1
```

**Important:** Use port 9333 (not 9222) to avoid conflict with Chrome's DevTools Protocol.

### Integration Workflow

After GPT Pro completes a round, integrate the feedback:

1. **Prime Claude Code** with full context:
   ```
   Read ALL of AGENTS.md and README.md. Use your code investigation agent
   to understand the project. Read FCP_Specification_V2.md and
   docs/fcp_model_connectors_rust.md.
   ```

2. **Integrate feedback** from GPT Pro:
   ```
   Integrate this feedback from GPT 5.2 (evaluate each suggestion):
   <paste apr show N output>
   ```

3. **Harmonize documents**: Update README, then implementation doc

4. **Commit changes** in logical groupings with detailed messages

### Useful Commands

```bash
apr status          # Check Oracle sessions
apr list            # List workflows
apr history         # Show revision history
apr diff 4 5        # Compare rounds 4 and 5
apr stats           # Convergence analytics
apr integrate 5 -c  # Copy integration prompt to clipboard
```

### Key Files

| File | Purpose |
|------|---------|
| `FCP_Specification_V2.md` | Main protocol specification |
| `docs/fcp_model_connectors_rust.md` | Rust implementation guide |
| `.apr/workflows/fcp.yaml` | APR workflow configuration |
| `.apr/rounds/fcp/round_N.md` | GPT Pro output for each round |

---

## Contributing

> *About Contributions:* Please don't take this the wrong way, but I do not accept outside contributions for any of my projects. I simply don't have the mental bandwidth to review anything, and it's my name on the thing, so I'm responsible for any problems it causes; thus, the risk-reward is highly asymmetric from my perspective. I'd also have to worry about other "stakeholders," which seems unwise for tools I mostly make for myself for free. Feel free to submit issues, and even PRs if you want to illustrate a proposed fix, but know I won't merge them directly. Instead, I'll have Claude or Codex review submissions via `gh` and independently decide whether and how to address them. Bug reports in particular are welcome. Sorry if this offends, but I want to avoid wasted time and hurt feelings. I understand this isn't in sync with the prevailing open-source ethos that seeks community contributions, but it's the only way I can move at this velocity and keep my sanity.

---

## License

MIT
