# Flywheel Connector Protocol (FCP)

<div align="center">
  <img src="fcp_illustration.webp" alt="FCP - Secure connectors for AI agents with zone-based isolation and capability tokens">
</div>

> **Specification note:** `FCP_Specification_V3.md` is the current architectural and conformance
> target. `FCP_Specification_V2.md` is retained as historical / legacy-interoperability context.
> When descriptions conflict, trust V3 for intended semantics and the code for current behavior.

A secure connector protocol and Rust platform for AI agent operations across zones, hosts, and personal device meshes. The current tree includes **34 platform crates** under `crates/`, **150 connector crates** under `connectors/`, and a single agent-first CLI (`fwc`) that refuses to fabricate runtime state. Connector maturity is intentionally described as uneven: all 150 currently ship a `manifest.toml` and tests, 138 follow the full `src/client.rs` + `src/connector.rs` + `src/types.rs` layout, 147 publish explicit `OperationInfo` structs, and a smaller set remain thinner or explicitly incubating/quarantined.

---

## TL;DR

**Operational truth hierarchy:** `fwc` classifies every answer by its truth source — **mesh-backed > host-backed > node-local > offline** — instead of collapsing everything into a single fake "live" state. The mesh-native architecture is the intended steady state; host-first operation is the current transitional boundary while the mesh cutover completes.

**Current provisioning path (V1 — Host-First, transitional):** the way to bring systems online today is `fwc -> fcp-host HTTP admin API -> connector subprocesses over supervised stdio/JSON-RPC`. This path is proven and operational, but it is a stepping stone — not the permanent design.

**This repository spans three layers:**

1. **A transitional host-first control plane converging toward mesh-native operation**: `fwc` (the sole CLI) talks to `fcp-host` (node-local supervisor) which manages connector subprocesses. This is the current provisioning and operational boundary. The mesh-backed truth resolver (`crates/fwc/src/truth.rs`) already supports mesh-backed, host-backed, node-local, and offline resolution strategies; the cutover to mesh-backed as the default highest-confidence source is in progress.

2. **FCP specifications and the mesh-native ownership split**: the protocol model, security invariants, and the FCP3 owner crates (`fcp-kernel`, `fcp-policy`, `fcp-evidence`) that will own canonical semantics post-cutover. These crates currently re-export from `fcp-core` during the transition.

3. **A broad but uneven connector workspace**: 150 connector crates covering messaging, cloud, databases, AI providers, dev tools, productivity, local-device control, and Google service integrations; all 150 currently ship manifests, tests, and `ConnectorErrorMapping`, while the depth of typed operation metadata and runtime proof still varies by connector.

**Target steady state (V2 — Mesh-Native, converging):** personal-device sovereignty, mesh durability, and capability-gated execution across your own infrastructure. In the target model, mesh-backed answers are the highest-confidence runtime truth. The mesh infrastructure (gossip, IBLT, XOR filters, symbol-first object distribution, LiveTruthResolver, KnowledgeState taxonomy) is built and tested; the remaining work is production evidence and cutover gating. See `docs/FCP3_Transition_Scorecard.md` for progress.

**Registry Note**: Registries are just sources of signed manifests/binaries. Your mesh can mirror and pin connectors as content-addressed objects so installs/updates work offline and without upstream dependency.

### Three Foundational Axioms

| Axiom | Principle |
|-------|-----------|
| **Universal Fungibility** | All durable mesh objects are symbol-addressable: any K' symbols reconstruct the canonical object bytes. Control-plane messages MAY travel over FCPC streams for efficiency, but the canonical representation is still a content-addressed mesh object. |
| **Authenticated Mesh** | Tailscale IS the transport AND the identity layer. Every node has unforgeable WireGuard keys. |
| **Explicit Authority** | No ambient authority. All capabilities flow from owner key through cryptographic chains. |

### Why Use FCP?

The table below starts with the current operational surface (what works today), then lists the security and protocol features, and finally the target architecture features that are designed but not yet operational.

Status legend: `PROVEN` = backed by direct proof in the current repo, `IMPLEMENTED` = code and tests exist but wider end-to-end proof or production hardening is incomplete, `LIMITED` = functional at the stated scope but narrower than the mature target (e.g. threshold-gated rather than adaptive), `DESIGNED` = architectural target or type-level/runtime scaffolding exists but the operational story is not yet complete, `PLANNED` = intended direction with little or no built surface yet. `PROVEN` is repository evidence, not a claim that the feature has been deployed in a live production mesh.

| Feature | Status | What It Does | Evidence |
|---------|--------|--------------|----------|
| **Host-First Control Plane** | `PROVEN` | **Current transitional operator path.** `fwc` + `fcp-host` is the proven provisioning boundary. Operators use this path today while mesh-backed truth converges to steady state. | `fcp-host/src/{supervisor,enforcement,health}.rs`, `crates/fcp-conformance/tests/host_invoke_loop_conformance.rs`, `crates/fcp-e2e/tests/capability_enforcement_concurrent_e2e.rs` |
| **Truthful Runtime Resolution** | `PROVEN` | `fwc` resolves runtime mode explicitly and classifies answers as mesh-backed, host-backed, node-local, or offline instead of fabricating a single "live" answer. | `fwc/src/{truth,catalog}.rs`, `fwc/tests/{cual_integration,readme_status_pinning}.rs` |
| **Zone Isolation** | `LIMITED` | Core cryptographic namespaces are proven; host-side connector zone binding is enforced when operators configure `allowed_zones`. | `fcp-core/src/{zone_keys,pcs,policy}.rs`, `fcp-host/src/bin/fcp-host.rs` (420+ tests, E2E enforcement) |
| **Capability Tokens (CWT/COSE)** | `PROVEN` | COSE/CWT signing, canonical CBOR, constraints, typestate enforcement, and bound instance semantics are covered by core, host-runtime, and conformance tests. | `fcp-crypto/src/cose.rs`, `fcp-core/src/capability.rs`, `crates/fcp-core/tests/capability_verifier_predicate_matrix.rs`, `crates/fcp-host/tests/capability_token_typestate_runtime.rs`, `crates/fcp-conformance/tests/capability_*.rs` |
| **Tamper-Evident Audit** | `PROVEN` | Hash-linked audit chain with monotonic sequence numbers and quorum-signed checkpoints. | `fcp-audit/`, `fcp-core/src/audit.rs` (473+ tests, golden vectors) |
| **Revocation** | `PROVEN` | First-class revocation objects and O(1)-style freshness checks exist in the current evidence/core surfaces. | `fcp-core/src/revocation.rs`, `crates/fcp-e2e/tests/{revocation_cascade,capability_enforcement_concurrent}_e2e.rs` |
| **Egress Proxy** | `PROVEN` | Connector network access is routed through manifest-aware guardrails with CIDR deny defaults and denial audit evidence. | `fcp-sandbox/src/egress.rs`, `crates/fcp-e2e/tests/egress_proxy_e2e.rs` |
| **Secretless Connectors** | `IMPLEMENTED` | Egress proxy and `credential_id` flows exist so connectors can rely on host-side credential injection; broader proof work is still open. | `fcp-sandbox/src/egress.rs` (credential_id injection path) |
| **Threshold Owner Key** | `PROVEN` | FROST ceremony/signing support exists in `fcp-bootstrap`, but it is not yet the universal operational default. | `fcp-bootstrap/src/ceremony.rs`, `crates/fcp-e2e/tests/threshold_owner_key_e2e.rs` |
| **Threshold Secrets** | `PROVEN` | Shamir secret sharing exists for device-distributed recovery so raw secret material need not live on one machine. | `fcp-core/src/secret.rs`, `crates/fcp-e2e/tests/threshold_secrets_e2e.rs` |
| **Supply Chain Attestations** | `PROVEN` | Registry-side attestation schemas, signature checks, TUF/cosign verification adapters, and host gate proof exist; release-distribution proof remains outside this repo. | `fcp-registry/src/lib.rs`, `crates/fcp-e2e/tests/supply_chain_attestation_e2e.rs` |
| **Offline Access** | `PROVEN` | `ObjectPlacementPolicy`, repair controllers, cache-while-offline, queued writes, and drain-on-restore are covered by E2E proof. | `fcp-store/src/offline.rs`, `crates/fcp-e2e/tests/{offline_access,offline_repair}_e2e.rs` |
| **Mesh-Stored Policy Objects** | `PROVEN` | Zone definitions and policy bundles exist as owner-signed objects with mesh gossip, verification, policy evaluation, and revocation proof; the wider mesh-backed invoke cutover remains in progress. | `fcp-core/src/policy.rs`, `crates/fcp-e2e/tests/mesh_policy_object_e2e.rs` |
| **Symbol-First Protocol** | `PROVEN` | RaptorQ/object-symbol framing, reconstruction, and repair machinery exist in-tree for multipath aggregation and offline resilience. | `fcp-raptorq/`, `crates/fcp-e2e/tests/symbol_first_protocol_e2e.rs`, golden vectors |
| **Mesh-Native Architecture** | `STEADY-STATE TARGET (NOT YET OPERATIONAL)` | Gossip, IBLT, XOR filters, and LiveTruthResolver are built and tested as building blocks, but the production `fwc → fcp-host → connector subprocess` invoke path remains host-first (see [Operational Model Versions](#operational-model-versions) — V1, the only operational model today). The mesh-native cutover is the target steady state and has zero production evidence. Pinned by `crates/fwc/tests/readme_status_pinning.rs` (br-lvz4t). | `fcp-mesh/src/` (259+ tests, gossip/IBLT/XOR), `fwc/src/truth.rs` (78 tests) |
| **Computation Migration** | `PROVEN` | Reference migrate-and-resume proof exists for a connector operation, including CRIU-format checkpoint handoff, lease transfer, replay, and byte-equivalent completion; automatic optimal-device execution is still hardening. | `fcp-kernel/src/computation_migration.rs`, `crates/fcp-e2e/tests/computation_migration_reference.rs` |

_Audit note:_ In the current host-backed path, `allowed_zones` is opt-in. An empty set preserves a back-compat permissive branch in `crates/fcp-host/src/bin/fcp-host.rs` (`allowed_zones()` and `verify_live_request()`).

> **Audit status**: All 16 feature status labels were reconciled 2026-05-03. A 2026-05-05 follow-up resolved the Capability Tokens instance-binding finding (`flywheel_connectors-01yaq`) and restored that row to `PROVEN`; the other rows remain from the 2026-05-03 pass. See [docs/quarterly/2026-Q2-claims-vs-reality.md](docs/quarterly/2026-Q2-claims-vs-reality.md).

### Quick Example: Current Provisioning Path (Host-First, transitional)

This is the current operational entry point. The `fwc` CLI talks to `fcp-host`, which
supervises connector subprocesses via stdio/JSON-RPC. This path is proven and operational;
the mesh-native steady state will supersede it as the default truth source once cutover completes.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        CURRENT OPERATOR PATH (V1)                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   Operator / AI Agent                                                       │
│       │                                                                     │
│       ▼                                                                     │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │  fwc (CLI)                                                          │  │
│   │  --host http://127.0.0.1:8787                                      │  │
│   │  Classifies answers: host-backed | node-local | offline             │  │
│   └────────────────────────────┬────────────────────────────────────────┘  │
│                                │  HTTP Admin API                           │
│                                ▼                                            │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │  fcp-host (Supervisor)                                              │  │
│   │  Zone check → Capability check → Revocation check                  │  │
│   │  Connector lifecycle, health, rollout, sandboxing                   │  │
│   └────────────────────────────┬────────────────────────────────────────┘  │
│                                │  stdio / JSON-RPC                         │
│                                ▼                                            │
│   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐                  │
│   │  Connector  │     │  Connector  │     │  Connector  │                  │
│   │   Gmail     │     │   GitHub    │     │   Slack     │                  │
│   │ (sandboxed) │     │ (sandboxed) │     │ (sandboxed) │                  │
│   └──────┬──────┘     └──────┬──────┘     └──────┬──────┘                  │
│          │                   │                   │                          │
│          ▼                   ▼                   ▼                          │
│     Gmail API          GitHub API           Slack API                       │
│                                                                             │
│   Every operation: Receipt generated → Audit event logged                   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Target Architecture: Mesh-Native (Steady State — Converging)

This is the intended steady-state architecture. Every device becomes a peer in
a personal mesh, with symbol-based data distribution and mesh-backed answers as
the highest-confidence truth source. The mesh infrastructure is built and tested;
the remaining work is production evidence and cutover gating.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PERSONAL MESH (TARGET ARCHITECTURE)                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌──────────┐      ┌──────────┐      ┌──────────┐                         │
│   │ Desktop  │◄────►│  Laptop  │◄────►│  Phone   │  ← Tailscale mesh      │
│   │ MeshNode │      │ MeshNode │      │ MeshNode │                         │
│   └────┬─────┘      └────┬─────┘      └────┬─────┘                         │
│        │                 │                 │                                │
│        ▼                 ▼                 ▼                                │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │                    SYMBOL DISTRIBUTION                              │  │
│   │  Object: gmail-inbox-2026-01   K=100 symbols distributed           │  │
│   │  Desktop: [1,5,12,23,...]  Laptop: [2,8,15,...]  Phone: [3,9,...] │  │
│   │  Any 100 symbols → full reconstruction                             │  │
│   └─────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│   Agent Request                                                             │
│       │                                                                     │
│       ▼                                                                     │
│   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐                  │
│   │ Zone Check  │────►│  Cap Check  │────►│  Connector  │                  │
│   │ z:private?  │     │ gmail.read? │     │   Gmail     │                  │
│   │ (crypto+ACL)│     │ (signed)    │     │ (sandboxed) │                  │
│   └─────────────┘     └─────────────┘     └─────────────┘                  │
│         │                   │                   │                           │
│         ▼                   ▼                   ▼                           │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │  Revocation Check → Receipt Generation → Audit Event Logged        │  │
│   └─────────────────────────────────────────────────────────────────────┘  │
│                                                  │                          │
│                                                  ▼                          │
│                                           Gmail API                         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Origins & Motivation

This project emerged from the Agent Flywheel ecosystem, where AI coding agents coordinate across multiple external services. Existing approaches to multi-service integration suffer from critical security flaws:

1. **Trust Commingling**: A message from a public Discord channel could trigger operations on private Gmail
2. **Prompt-Based Security**: "Don't read private emails" is trivially bypassed by prompt injection
3. **Centralized Architecture**: Single points of failure, cloud dependency, vendor lock-in
4. **Binary Offline**: No connectivity = no access

FCP addresses these through:
- **Zones as cryptographic universes**: if the Gmail-read capability doesn't exist in a zone, it cannot be invoked, regardless of what an agent says
- **Mesh-native architecture**: your devices collectively ARE the system
- **Symbol-first protocol**: data availability is probabilistic, not binary
- **Revocation as first-class primitive**: compromised devices can be removed and keys rotated

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

These are the protocol invariants FCP is built to enforce mechanically. The
feature-status table above is the current proof ledger: today, zone isolation is
`LIMITED` in the host-backed path because `allowed_zones` is opt-in.

1. **Single-Zone Binding**: A connector instance MUST bind to exactly one zone for its lifetime
2. **Default Deny**: If a capability is not explicitly granted to a zone, it MUST be impossible to invoke
3. **No Cross-Connector Calling**: Connectors MUST NOT call other connectors directly; all composition happens through the mesh
4. **Threshold Secret Distribution**: Secrets use Shamir sharing; never complete on any single device
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
┌──────────────────────────────────────────────────────────────────────────┐
│                    FCPS FRAME FORMAT (Symbol-Native)                      │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Bytes 0-3:     Magic (0x46 0x43 0x50 0x53 = "FCPS")                    │
│  Bytes 4-5:     Version (u16 LE)                                         │
│  Bytes 6-7:     Flags (u16 LE)                                           │
│  Bytes 8-11:    Symbol Count (u32 LE)                                    │
│  Bytes 12-15:   Total Payload Length (u32 LE)                            │
│  Bytes 16-47:   Object ID (32 bytes)                                     │
│  Bytes 48-49:   Symbol Size (u16 LE, default 1024)                       │
│  Bytes 50-57:   Zone Key ID (8 bytes, for rotation)                      │
│  Bytes 58-89:   Zone ID hash (32 bytes, BLAKE3; fixed-size)              │
│  Bytes 90-97:   Epoch ID (u64 LE)                                        │
│  Bytes 98-105:  Sender Instance ID (u64 LE, reboot-safety)               │
│  Bytes 106-113: Frame Seq (u64 LE, per-sender monotonic counter)         │
│  Bytes 114+:    Symbol payloads (encrypted, concatenated)                │
│                                                                          │
│  Fixed header: 114 bytes                                                 │
│  NOTE: No separate checksum. Integrity via per-symbol AEAD tags          │
│        and per-frame session MAC (AuthenticatedFcpsFrame).               │
│  Per-symbol nonce: derived as frame_seq || esi_le (deterministic)        │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

### Session Authentication

High-throughput symbol delivery uses per-session authentication (not per-frame signatures):

1. **Handshake**: X25519 ECDH authenticated by attested node signing keys, with per-party nonces for replay protection and crypto suite negotiation
2. **Session keys**: HKDF-derived directional MAC keys (k_mac_i2r, k_mac_r2i) from ECDH shared secret, bound to the selected suite and both handshake nonces
3. **Per-sender subkeys**: Each sender derives a unique subkey via HKDF including sender_instance_id, eliminating cross-sender and cross-reboot nonce collision risk
4. **Per-frame MAC**: HMAC-SHA256 or BLAKE3 (negotiated) with per-sender monotonic frame_seq for anti-replay

**Crypto Suite Negotiation**: Initiator proposes supported suites; responder selects. Suite1 uses HMAC-SHA256 (broad compatibility), Suite2 uses BLAKE3 (performance). This avoids Poly1305 single-use constraints while enabling future algorithm agility.

**Session Rekey Triggers**: Sessions automatically rekey after configurable thresholds: frames (default: 1B), elapsed time (default: 24h), or cumulative bytes (default: 1 TiB). This bounds key exposure and prevents pathological long-lived sessions.

This amortizes Ed25519 signature cost over many frames while preserving cryptographic attribution and preventing nonce reuse across senders.

### Control Plane Framing (FCPC)

While FCPS handles high-throughput symbol delivery, FCPC provides reliable, ordered, backpressured framing for control-plane objects (invoke, response, receipts, approvals, audit events). FCPC uses the session's negotiated `k_ctx` symmetric key for AEAD encryption/authentication, enabling secure control messages without per-message Ed25519 signatures.

---

## Mesh Architecture (STEADY-STATE TARGET — NOT YET OPERATIONAL)

In the target architecture, every device is a MeshNode. Collectively, they ARE the Hub. Today the proven operator path is host-first (`fwc -> fcp-host`); the mesh layer below is designed and partially implemented but not yet the operational default.

### MeshNode Components

```
┌──────────────────────────────────────────────────────────────────────────┐
│                               MESHNODE                                   │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Tailscale Identity                                                │  │
│  │  • Stable node ID (unforgeable WireGuard keys)                    │  │
│  │  • Node signing/encryption/issuance keys with owner attestation   │  │
│  │  • ACL tags for zone mapping                                      │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Symbol Store                                                      │  │
│  │  • Local symbol storage with node-local retention classes          │  │
│  │  • Quarantine store for unreferenced objects (bounded)             │  │
│  │  • XOR filters + IBLT for efficient gossip reconciliation         │  │
│  │  • Reachability-based garbage collection                          │  │
│  │  • ObjectPlacementPolicy enforcement for availability SLOs        │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Capability & Revocation Registry                                  │  │
│  │  • Zone keyrings for deterministic key selection by zone_key_id   │  │
│  │  • Trust anchors (owner key, attested node keys)                  │  │
│  │  • Monotonic seq numbers for O(1) freshness checks                │  │
│  │  • ZoneCheckpoint checkpoints for fast sync                       │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Connector State Manager                                           │  │
│  │  • Externalized connector state as mesh objects                   │  │
│  │  • Single-writer semantics via execution leases + fencing tokens  │  │
│  │  • Multi-writer CRDT support (LWW-Map, OR-Set, counters)          │  │
│  │  • Safe failover and migration for stateful connectors            │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Execution Planner                                                 │  │
│  │  • Device profiles (CPU, GPU, memory, battery)                    │  │
│  │  • Connector availability and version requirements                │  │
│  │  • Secret reconstruction cost estimation                          │  │
│  │  • Symbol locality scoring, DERP penalty                          │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Repair Controller                                                 │  │
│  │  • Background symbol coverage evaluation                          │  │
│  │  • Automatic repair toward ObjectPlacementPolicy targets          │  │
│  │  • Rebalancing after device churn or offline periods              │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Egress Proxy                                                      │  │
│  │  • Connector network access via capability-gated IPC              │  │
│  │  • CIDR deny defaults (localhost, private, tailnet ranges)        │  │
│  │  • SNI enforcement, SPKI pinning                                  │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Audit Chain                                                       │  │
│  │  • Hash-linked audit events per zone with monotonic seq           │  │
│  │  • Quorum-signed audit heads for tamper evidence                  │  │
│  │  • Operation receipts for idempotency                             │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
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
┌──────────────────────────────────────────────────────────────┐
│                          FCP BINARY                          │
├──────────────────────────────────────────────────────────────┤
│  ┌────────────────────────────────────────────────────────┐  │
│  │  MANIFEST SECTION                                      │  │
│  │  ┌─────────────────┐  ┌─────────────────┐              │  │
│  │  │  Metadata       │  │  Capabilities   │              │  │
│  │  │  - Name         │  │  - Required     │              │  │
│  │  │  - Version      │  │  - Optional     │              │  │
│  │  │  - Author       │  │  - Forbidden    │              │  │
│  │  └─────────────────┘  └─────────────────┘              │  │
│  │  ┌─────────────────┐  ┌─────────────────┐              │  │
│  │  │  Zone Policy    │  │  Sandbox Config │              │  │
│  │  │  - Home zone    │  │  - Memory limit │              │  │
│  │  │  - Allowed      │  │  - CPU limit    │              │  │
│  │  │  - Tailscale tag│  │  - FS access    │              │  │
│  │  └─────────────────┘  └─────────────────┘              │  │
│  │  ┌─────────────────┐                                   │  │
│  │  │  AI Hints       │  ← Agent-readable operation docs  │  │
│  │  │  - Operations   │                                   │  │
│  │  │  - Examples     │                                   │  │
│  │  │  - Safety notes │                                   │  │
│  │  └─────────────────┘                                   │  │
│  └────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  CODE SECTION                                          │  │
│  │  - FCP protocol implementation                         │  │
│  │  - Capability negotiation                              │  │
│  │  - External API clients                                │  │
│  │  - State management                                    │  │
│  └────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  SIGNATURE SECTION                                     │  │
│  │  - Ed25519 signature over manifest + code              │  │
│  │  - Reproducible build attestation                      │  │
│  │  - Registry provenance chain                           │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
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

**Local `$CONNECTOR_STATE` is a cache only.** The authoritative state lives as mesh objects. This enables:

- **Safe failover**: Another node can resume from last committed state
- **Resumable polling**: Cursors survive node restarts and migrations
- **Deterministic migration**: State is explicit, not implicit in process memory

**Single-Writer Semantics**: Connectors declaring `singleton_writer = true` use execution leases to ensure only one node writes state at a time. Leases are coordinated via HRW (rendezvous hashing) to deterministically select a coordinator from online nodes, with quorum signatures for distributed issuance. This prevents double-polling and cursor conflicts while surviving coordinator failures.

### Agent API Caching

`fcp-host` exposes cache metadata on agent-facing discovery surfaces so clients can avoid refetching unchanged connector metadata:

- `GET /rpc/discover`
- `GET /rpc/introspect/{connector_id}`

Responses include standard HTTP validators:

- `ETag`
- `Last-Modified`
- `Cache-Control`
- `Vary: If-None-Match, If-Modified-Since`

Clients can revalidate with either transport headers (`If-None-Match`, `If-Modified-Since`) or the JSON-RPC-style `_cache` object carried in the request payload. When the cached view is still valid, the host returns the normal JSON body shape with `meta.status = 304` and refreshed cache metadata instead of switching the HTTP transport status away from `200 OK`. This keeps the agent API JSON-RPC-friendly while still giving agents deterministic cache validation semantics.

`ETag` values are strong validators derived from canonical response content. They change when discovery or introspection content changes and remain stable across repeated reads of unchanged registry state. `Cache-Control` currently advertises both `max-age` and `stale-while-revalidate`, so agents can serve a warm cache immediately while refreshing metadata in the background.

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

Secrets use **Shamir's Secret Sharing** (not RaptorQ symbols, which can leak structure):

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
| **Rate limiting** | Token bucket, sliding-window, and leaky-bucket enforcement; burst applies to token buckets |
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

### Connector Inventory (150 connector crates)

The live tree currently contains 150 connector crates. All 150 ship a `manifest.toml`, tests, and `ConnectorErrorMapping`; 138 currently follow the full `src/client.rs` + `src/connector.rs` + `src/types.rs` layout, and 147 currently publish explicit `OperationInfo` structs. That means the workspace is broad, but the connector surface is not perfectly uniform.

The authoritative inventory is the `connectors/` directory or manifest-backed `fwc list --offline`, not a handwritten static table. The older audits in [`docs/connector_census_v3.md`](docs/connector_census_v3.md) and [`docs/V3_Connector_Audit_Matrix.md`](docs/V3_Connector_Audit_Matrix.md) are useful historical snapshots, but they only cover an earlier 89-connector window and should not be treated as the live inventory. Recent additions in the current wave include BlueBubbles, Synology Chat, Google Places, Email Generic, Sonos, Hue, Apple Notes, and Apple Reminders.

Inventory presence also does not mean end-to-end proof. A few connectors are explicitly non-live today, including `huggingface` and `tlon` (`status = "incubating"`) plus `zalouser` (`status = "quarantined"`), and the representative category table below should be read as workspace coverage rather than a supervised-flow integration pass list.

| Category | Representative Connectors |
|----------|---------------------------|
| **AI & LLM** | Anthropic, OpenAI, Google AI (Gemini), LLM Router, Whisper |
| **Google Services** | Gmail, Calendar, Drive, Docs, Sheets, Chat, Places, YouTube, People, Workspace Events, Admin Reports, BigQuery, Google AI |
| **Messaging & Collaboration** | Slack, Discord, Telegram, Twitter/X, Synology Chat, BlueBubbles |
| **Dev Tools** | GitHub, GitLab, Bitbucket, Linear, Jira, ClickUp, Todoist, Trello, Asana |
| **Databases** | PostgreSQL, Redis, MongoDB, Elasticsearch, DuckDB, Snowflake, Qdrant, Pinecone, VectorDB |
| **Cloud & Infra** | S3, Kubernetes, Terraform, Pulumi, Datadog, Grafana, Sentry |
| **Productivity & Personal** | Notion, Airtable, Figma, DocuSign, Pandadoc, Evernote, Logseq, Roam, Apple Notes, Apple Reminders, Email Generic |
| **Communication** | SendGrid, Twilio, Mailchimp, HubSpot, Intercom, Zendesk |
| **Finance** | Stripe, Plaid |
| **Analytics** | Mixpanel, Amplitude, PostHog, Segment, Metabase |
| **Security** | 1Password, Bitwarden |
| **Automation** | Zapier, Make, n8n, Retool, Cron, Webhook Receiver |
| **Content** | Reddit, LinkedIn, Spotify, Anna's Archive, Arxiv, Semantic Scholar |
| **Home & Local Devices** | Sonos, Hue, Home Assistant |
| **Other** | Browser, MCP Bridge, Microsoft 365, Salesforce, Box, Dropbox |

### Google Workspace Platform

The 13 Google service connectors share a discovery-pinned substrate (`fcp-google-discovery`) that provides:

- **`GoogleAuthSelection`**: unified config parsing for `access_token`, `credential_id`, or OAuth refresh
- **`GoogleMaterializedAuth`**: materialized auth with `BearerToken` and `CredentialReference` variants
- **`GoogleRestExecutor`**: shared HTTP executor with retry loops and structured error extraction
- **Migration acceptance tests**: `migration_acceptance.rs` for Gmail, Calendar, and YouTube validates substrate integration

All Google connectors use the same auth flow: `GoogleAuthSelection::from_connector_config()` -> `.materialize()` -> `Client::new_with_auth()`. This eliminates per-connector OAuth boilerplate and ensures consistent credential handling across the family.

### Connector SDK & Migration Framework

The `fcp-sdk` crate provides the migration framework used across the connector workspace:

```rust
// Every connector implements this trait for unified error handling
pub trait ConnectorErrorMapping: Display + Debug + Send + Sync {
    fn from_async_error(error: AsyncError) -> Self where Self: Sized;
    fn to_fcp_error(&self) -> FcpError;
    fn is_retryable(&self) -> bool;
    fn retry_after(&self) -> Option<Duration> { None }
}
```

Supporting infrastructure:

| Component | Purpose |
|-----------|---------|
| `ConnectorRuntime` | Lifecycle wrapper with request contexts and graceful shutdown |
| `RetryLoop` | Generic retry executor with exponential backoff and jitter |
| `HttpRetryConfig` | Serializable retry config (max retries, initial/max delay, jitter) |
| `AttemptOutcome<T, E>` | Enum for retry decisions: `Success`, `Retryable`, `Terminal` |

### Streaming Health Model

`fcp-streaming` provides a state machine for long-lived connection health:

```
Connected ──(missed heartbeat)──> Degraded
Connected ──(connection lost)───> Reconnecting
Degraded  ──(heartbeat received)─> Connected
Degraded  ──(zombie timeout)────> Unhealthy
Reconnecting ──(connected)──────> Connected
Reconnecting ──(max retries)────> Unhealthy
```

`StreamHealthTracker` drives these transitions and produces `StreamHealthSnapshot` structs with `last_heartbeat_ms_ago`, `last_ack_ms_ago`, `reconnect_count`, `messages_received`, and `uptime_ms`. The tracker maps to `fcp_core::ConnectorHealth` for external reporting.

---

## FWC: The Agent-First CLI

`fwc` is the sole supported CLI for the Flywheel connector workspace. It provides 50+ commands across discovery, lifecycle, invocation, intent compilation, and workflow management. Output defaults to TOON, a token-efficient format optimized for AI agent consumption.

### Quick Start

```bash
# Install from source
cargo build -p fwc --bin fwc --release
cp target/release/fwc ~/.local/bin/

# Current provisioning path (transitional): fwc talks to fcp-host via --host flag.
fwc --host http://127.0.0.1:8787 status github
fwc --host http://127.0.0.1:8787 list
fwc --host http://127.0.0.1:8787 invoke github issues.create --file payload.json
fwc --host http://127.0.0.1:8787 simulate github issues.create --file payload.json

# Truth source hierarchy: mesh-backed > host-backed > node-local > offline.
# Use mesh explain-availability to see which truth source backs your answers:
fwc --host http://127.0.0.1:8787 mesh explain-availability github

# Offline mode: artifact-backed data without a running host or mesh.
fwc list --offline
fwc search "send message" --offline
fwc show github --offline
fwc ops github --offline
fwc schema github issues.create --offline

# History and audit trail
fwc history --connector github --limit 20
```

### Command Families

| Family | Commands | Purpose |
|--------|----------|---------|
| **Discovery** | `list`, `search`, `show`, `ops`, `schema`, `examples`, `zones` | Find connectors and understand their operations |
| **Lifecycle** | `doctor`, `status`, `health`, `install`, `update`, `pin`, `rollout` | Manage connector health and deployment |
| **Execution** | `invoke`, `simulate`, `preflight`, `cancel` | Run operations with safety gates |
| **Workflow** | `task`, `plan`, `explain`, `do` | Intent-first workflow compilation and safe-by-default materialization |
| **Composition** | `pipe`, `pipeline`, `recipe`, `map`, `batch-file` | Chain and parallelize operations |
| **History** | `history`, `replay`, `compare`, `undo`, `approvals` | Audit trail and reversal guidance |
| **Auth** | `auth`, `config` | Credential and configuration management |
| **Export** | `export-tools`, `serve-mcp` | Expose connectors as MCP tools |
| **Evidence** | `supply-chain`, `audit`, `manifest`, `net`, `trace`, `policy` | Verify security posture |

### Workflow Commands

`fwc plan`, `fwc explain`, and `fwc do` are implemented today; they are not placeholder UX. The local intent compiler in `crates/fwc/src/intent.rs` is nearly 5.9k lines with 258 inline tests and compiles natural-language goals into concrete `fwc` primitives plus workflow-truth metadata, ambiguity reporting, missing-information prompts, and suggested next actions.

Resolution is strongest for the current curated connector profile set, which is currently two dozen connectors with explicit aliases and domain keywords layered on top of manifest-derived operation metadata. Connectors outside that curated set still participate through generic alias/keyword matching plus the manifest-backed operation index loaded from the discovery catalog, but the match quality is weaker and may require `--connector` or more explicit literals in the intent.

`fwc do` is also safe by default: it materializes the compiled workflow in simulation mode unless you explicitly pass `--approve` for side-effecting execution. Manifest-backed resolution is already part of the current compiler, but broader ranking and refinement improvements are still in progress.

### Output Formats

`fwc` defaults to TOON, a token-efficient structured format designed for AI agents. Other formats are available:

```bash
fwc list --offline                    # TOON (default, compact)
fwc list --offline --json             # Full JSON
fwc list --offline --format table     # ASCII table
fwc list --offline --format csv       # CSV export
fwc list --offline --format markdown  # Markdown table
```

---

## Algorithms & Design Principles

### RaptorQ Fountain Codes

FCP uses RaptorQ (RFC 6330) for all data distribution. The key insight: instead of coordinating which specific packets to retransmit, generate an infinite stream of symbols where **any K' symbols reconstruct the original**. This eliminates retransmit coordination, enables multipath aggregation, and provides natural offline resilience.

Implementation details in `fcp-raptorq`:
- Symbol sizes from 1 to 65,535 bytes (configurable per object)
- Chunked objects via `ChunkedObjectManifest` for large payloads
- BLAKE3 hash verification on reconstructed chunks
- Admission control: concurrent decode limit (16), memory limits, duplicate rejection, timeouts
- All arithmetic uses `checked_*` / `saturating_*` operations; no integer overflow panics

### Deterministic CBOR Serialization

`fcp-cbor` enforces RFC 8949 Section 4.2 canonical encoding:
- Map keys sorted by canonical CBOR bytes (length-first, then lexicographic)
- Minimal integer encoding
- Duplicate key detection and rejection
- Depth limit (128 levels) and size limit (64 MiB) for DoS protection
- Round-trip verification: `deserialize()` re-encodes and compares bytes

All capability tokens, zone manifests, and signed objects use this canonical form to ensure signatures are deterministic.

### COSE/CWT Capability Tokens

Capability tokens use CBOR Object Signing and Encryption (RFC 9052) with CWT claims (RFC 8392):
- Ed25519 signatures over deterministic CBOR payloads
- Standard claims: `iss`, `sub`, `exp`, `nbf`, `iat`
- FCP-specific claims: operation scope, capability constraints, zone binding
- Signature verified **before** claims are parsed (defense-in-depth)
- Revocation checked via monotonic sequence numbers (O(1) freshness)

### Gossip Protocol

`fcp-mesh` uses an IBLT-based gossip protocol for efficient state reconciliation:
- XOR filters for set membership with false-positive-only semantics
- Invertible Bloom Lookup Tables (IBLTs) for set difference
- Bounded gossip: `MAX_OBJECT_IDS_PER_REQUEST = 100`
- Admitted vs. Quarantined object classification
- Per-peer admission budgets with anti-amplification rules

### Repair Controller

`fcp-store` implements an SLO-driven repair controller:
- Coverage evaluation in basis points (bps, 0-10000 = 0-100%)
- Per-object placement policies with coverage, diversity, and concentration targets
- Deterministic repair prioritization: SLO deficit x object hotness x cost estimate
- Bounded repair plans: max repairs, max bytes, max decode budget per cycle
- Power-aware deferral (`LIMITED`): `RepairController::set_power_state`
  accepts a `PowerState::Battery { percent }` signal from the runtime
  layer. When the reported percent falls below
  `RepairControllerConfig::battery_defer_threshold_percent` (default 20%,
  matching `fcp_mesh::device::DeviceProfile::is_low_battery`),
  `next_repair()` returns `None`, increments `RepairStats::power_deferred`,
  and emits a `tracing::info!` event with the
  `repair.deferred_power_budget` reason code. In-flight repairs are not
  interrupted; only newly-dequeued repairs are gated. Gate is
  threshold-based (not ML-driven); callers that never invoke
  `set_power_state` default to `PowerState::Ac` and see the legacy
  no-deferral behaviour. Landed under bead `flywheel_connectors-qyv8n`.

---

## Test Infrastructure

The workspace has a very large crate-local and end-to-end test surface across several categories:

| Category | Where | What It Covers |
|----------|-------|----------------|
| **Unit tests** | `#[cfg(test)]` in every crate | Individual function correctness, edge cases |
| **Integration tests** | `connectors/*/tests/` | Connector lifecycle with wiremock HTTP mocking |
| **Conformance** | `crates/fcp-conformance/tests/` | Protocol golden vectors, capability verification |
| **E2E** | `crates/fcp-e2e/tests/` | Host-backed compliance scenarios |
| **Connector proof scripts** | `scripts/e2e/*_verification.sh` | Operator replay bundles and redaction-safe JSONL evidence |
| **Mesh scenarios** | `crates/fcp-conformance/tests/integration_scenarios.rs` | Network partition recovery, gossip convergence |
| **Benchmarks** | `crates/fwc/benches/`, `crates/fcp-core/benches/` | Search, schema, pipeline, PCS performance |

Key testing patterns:
- **No real API calls in tests**: all external services are mocked via `wiremock`
- **Deterministic test logging**: structured JSON log output with correlation IDs
- **RFC test vectors**: Ed25519 (RFC 8032), HKDF (RFC 5869), X25519 (RFC 7748)
- **Golden vector snapshots**: canonical CBOR, manifest hashes, protocol frames

Voice-call provider parity has a dedicated operator proof script:
`scripts/e2e/voice_call_multi_provider_verification.sh` runs the Twilio, Telnyx,
and Plivo no-live-credential loopback suites through their production connector
boundaries, then normalizes their provider JSONL into one redaction-checked
multi-provider evidence log.

### Deadlock detection (mesh + store runtime audits)

Static lock-order audits catch most cycles, but a future gossip or
repair pass that wraps `MeshNode` in an outer lock and re-enters the
store through a handler is exactly the "fourth-instance" hazard that
only a runtime backstop can expose. `parking_lot` ships a built-in
cycle detector that we expose through an opt-in feature flag on both
`fcp-store` (the primitive holder) and `fcp-mesh` (the forwarder).

Enable the feature on any crate in the mesh+store dependency graph:

```bash
# Run the fcp-mesh suite under the detector
CARGO_TARGET_DIR=/tmp/fcp-audit cargo test -p fcp-mesh --features deadlock-detection

# Or scope it to fcp-store
CARGO_TARGET_DIR=/tmp/fcp-audit cargo test -p fcp-store --features deadlock-detection
```

The feature flips `parking_lot`'s `Mutex` and `RwLock` implementations
to track lock ownership globally, which has non-trivial overhead and
MUST NOT be enabled in release builds. To surface cycles from a test
binary or dev harness, spawn a background watchdog once at startup:

```rust
#[cfg(feature = "deadlock-detection")]
fn spawn_deadlock_watchdog() {
    use std::thread;
    use std::time::Duration;
    thread::spawn(|| loop {
        thread::sleep(Duration::from_secs(10));
        let deadlocks = parking_lot::deadlock::check_deadlock();
        if !deadlocks.is_empty() {
            eprintln!("DEADLOCK DETECTED: {} cycle(s)", deadlocks.len());
            for (i, threads) in deadlocks.iter().enumerate() {
                eprintln!("Cycle #{i}");
                for t in threads {
                    eprintln!("  Thread {:?}:\n{:?}", t.thread_id(), t.backtrace());
                }
            }
            std::process::abort();
        }
    });
}
```

---

## End-to-End Request Flow

When an AI agent invokes a connector operation, this is the exact sequence:

```
Agent ──"search my Gmail for invoices"──> fwc plan
                                            │
                                            ▼
                                    Intent Compiler
                                    ├─ Resolve connector: gmail
                                    ├─ Resolve operation: gmail.search_messages
                                    ├─ Check capability: gmail.read
                                    └─ Build: fwc invoke gmail search_messages --file payload.json
                                            │
                                            ▼
                                    fwc invoke (CLI)
                                    ├─ Resolve host context
                                    ├─ Preflight: risk check + approval gate
                                    └─ HTTP POST to fcp-host admin API
                                            │
                                            ▼
                                    fcp-host (orchestrator)
                                    ├─ 1. Verify capability token (COSE signature)
                                    ├─ 2. Check token expiry (CWT nbf/exp)
                                    ├─ 3. Check revocation (monotonic seq, O(1))
                                    ├─ 4. Enforce zone policy (zone binding)
                                    ├─ 5. Check rate limits (token bucket)
                                    ├─ 6. Record audit event (hash-linked chain)
                                    └─ 7. Dispatch to connector subprocess
                                            │
                                            ▼
                                    Gmail Connector (sandboxed)
                                    ├─ Validate input against JSON Schema
                                    ├─ Acquire bearer token (from materialized auth)
                                    ├─ HTTP GET via egress proxy
                                    │   └─ Egress proxy enforces: HTTPS, gmail.googleapis.com, port 443
                                    ├─ Parse response, map errors to FcpError
                                    └─ Return result + operation receipt
                                            │
                                            ▼
                                    fcp-host
                                    ├─ Record receipt (idempotency key)
                                    ├─ Append audit event with trace context
                                    └─ Return structured result to fwc
                                            │
                                            ▼
                                    fwc → TOON output → Agent
```

Every step is logged with W3C trace context (trace_id, span_id) for end-to-end distributed tracing.

---

## Connector Authoring API

Building a new connector requires implementing the FCP connector contract. The `fwc new` scaffold generator creates the complete structure:

```bash
fwc new myservice --archetype request-response
```

This generates:

```
connectors/myservice/
├── Cargo.toml          # Workspace member with fcp-sdk, fcp-core, fcp-async-core
├── manifest.toml       # Capabilities, zones, rate limits, network constraints, sandbox
├── src/
│   ├── main.rs         # JSON-RPC stdin/stdout protocol loop
│   ├── lib.rs          # Module declarations
│   ├── connector.rs    # FCP lifecycle: configure, handshake, health, doctor, invoke
│   ├── client.rs       # HTTP client with retry loops and auth handling
│   ├── error.rs        # Error types + ConnectorErrorMapping impl
│   ├── types.rs        # API request/response structs (serde)
│   └── limits.rs       # Named constants for rate limits and validation bounds
└── tests/
    └── integration.rs  # Wiremock-based lifecycle and operation tests
```

### The Connector Lifecycle

Every connector implements the same protocol loop via `main.rs`:

```rust
// Simplified — actual code uses the full JSON-RPC 2.0 envelope
let result = match method {
    "configure"  => connector.handle_configure(params).await,
    "handshake"  => connector.handle_handshake(params).await,
    "health"     => connector.handle_health().await,
    "doctor"     => connector.handle_doctor().await,
    "self_check" => connector.handle_self_check().await,
    "introspect" => connector.handle_introspect().await,
    "invoke"     => connector.handle_invoke(params).await,
    "simulate"   => connector.handle_simulate(params).await,
    "shutdown"   => connector.handle_shutdown(params).await,
    _ => Err(FcpError::InvalidRequest { .. }),
};
```

### Error Mapping Contract

Every connector error type bridges to the FCP error taxonomy:

```rust
#[derive(Error, Debug)]
pub enum MyServiceError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("API error ({status_code}): {message}")]
    Api { status_code: u16, message: String },

    #[error("Rate limited")]
    RateLimited { retry_after_ms: u64 },
}

impl ConnectorErrorMapping for MyServiceError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => Self::Api {
                status_code: 408,
                message: format!("deadline exceeded after {timeout_ms}ms"),
            },
            AsyncError::Cancelled => Self::Api {
                status_code: 0,
                message: "request cancelled".into(),
            },
            other => Self::Api {
                status_code: 0,
                message: other.to_string(),
            },
        }
    }

    fn to_fcp_error(&self) -> FcpError { /* map each variant */ }
    fn is_retryable(&self) -> bool { /* 429, 5xx = true */ }
    fn retry_after(&self) -> Option<Duration> { /* from RateLimited */ }
}
```

### Manifest Declaration

Each connector's `manifest.toml` declares its security boundary:

```toml
[connector]
id = "fcp.myservice"
name = "MyService Connector"
version = "0.1.0"
archetypes = ["request-response"]

[zones]
home = "z:work"
allowed_sources = ["z:owner", "z:private", "z:work"]
forbidden = ["z:public"]

[capabilities]
required = ["network.dns", "network.egress", "network.tls.sni"]
forbidden = ["system.exec", "network.listen"]

[sandbox]
profile = "strict"
memory_limit_mb = 128
cpu_limit_percent = 25
deny_exec = true

[[provides]]
id = "myservice.search"
summary = "Search items"
capability = "myservice.read"
risk_level = "low"
safety_tier = "safe"
idempotency = "strict"

[provides.network_constraints]
allowed_hosts = ["api.myservice.com"]
allowed_ports = [443]
require_tls = true

[provides.rate_limit]
pool_name = "myservice.read"
requests = 100
window = "60s"
```

---

## Comparison: FCP vs. Alternatives

| Feature | FCP | LangChain Tools | MCP (Model Context Protocol) | Custom API Gateway |
|---------|-----|-----------------|-----------------------------|--------------------|
| **Security model** | Zone-based cryptographic isolation with capability tokens | Trust-the-runtime (no isolation) | Server-declared capabilities (no crypto enforcement) | API key + rate limiting |
| **Connector isolation** | Per-connector sandboxes (seccomp/WASI) | Shared process memory | Separate server processes | Separate services |
| **Offline support** | Symbol-based availability with SLO repair | None | None | None |
| **Credential handling** | Secretless via egress proxy injection | In-memory, shared context | Server-managed | Vault / env vars |
| **Audit trail** | Hash-linked chain with quorum-signed heads | Logging only | Logging only | Centralized logs |
| **Multi-device** | Mesh-native with fountain code distribution | Single process | Client-server | Load balancer |
| **Revocation** | First-class objects with O(1) freshness | N/A | N/A | API key rotation |
| **Agent UX** | TOON-first CLI with intent compilation | Python SDK | JSON-RPC | REST API |
| **Connector count** | 150 connector crates in the workspace, with maturity varying per connector | ~50 community tools | Varies by server | Custom per service |
| **Supply chain** | Ed25519 signatures, in-toto/SLSA attestations | pip install | npm install | Docker images |

FCP is heavier than MCP or LangChain tools. That weight buys cryptographic isolation, mesh distribution, and auditability. For single-machine prototyping, MCP is simpler. For production agent operations where security matters, FCP provides guarantees the alternatives cannot.

---

## Cryptographic Key Derivation

FCP uses a structured key hierarchy to prevent cross-purpose key reuse:

```
Owner Key (Ed25519, threshold via FROST)
    │
    ├── sign NodeKeyAttestation (binds node_id → signing_key, encryption_key, issuance_key)
    ├── sign ZoneKeyManifest   (distributes zone symmetric keys via HPKE sealing)
    ├── sign DeviceEnrollment  (admits new nodes)
    └── sign RevocationObject  (invalidates any of the above)

Per-Node Keys:
    Node Signing Key (Ed25519)  → signs frames, gossip, receipts
    Node Encryption Key (X25519) → receives HPKE-sealed zone keys
    Node Issuance Key (Ed25519)  → mints capability tokens (separately revocable)

Per-Zone Keys:
    Zone Encryption Key (ChaCha20-Poly1305)
        │
        ├── HKDF("FCP2-ZONE-KEY" ‖ zone_id) → zone subkey
        ├── HKDF(zone_key ‖ sender_instance_id) → per-sender subkey (reboot-safe)
        └── Per-symbol nonce: frame_seq ‖ ESI (deterministic, no coordination)

Per-Session Keys (from X25519 ECDH):
    Shared secret → HKDF with both nonces
        ├── k_mac_i2r  (initiator→responder MAC key)
        ├── k_mac_r2i  (responder→initiator MAC key)
        └── k_ctx      (control plane AEAD key)
```

Key principles:
- **No key reuse across purposes**: signing, encryption, issuance, and session keys are all separate
- **Sender isolation**: per-sender subkeys incorporate `sender_instance_id`, preventing nonce collision across senders and across reboots
- **Deterministic nonces**: symbol nonces are `frame_seq ‖ ESI`, eliminating coordination overhead
- **Separate revocability**: issuance keys can be revoked without affecting a node's signing or encryption capabilities

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FWC_FORMAT` | Default output format (`toon`, `json`, `table`, `csv`, `markdown`) | `toon` |
| `FCP_HOST` | Default fcp-host endpoint URL | None (requires `--host` or context) |
| `FCP_ZONE` | Default zone for operations | None |
| `RUST_LOG` | Standard Rust logging filter | `info` |
| `FCP_CONFIG_DIR` | FCP configuration directory | `~/.fcp` |
| `FCP_CONNECTOR_STATE` | Connector state directory | `$FCP_CONFIG_DIR/state` |

---

## Acknowledgments

Built with:
- [Rust](https://www.rust-lang.org/) (nightly, 2024 edition) — the entire platform
- [ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek) + [x25519-dalek](https://github.com/dalek-cryptography/x25519-dalek) — cryptographic signatures and key exchange
- [chacha20poly1305](https://github.com/RustCrypto/AEADs) — AEAD symmetric encryption
- [blake3](https://github.com/BLAKE3-team/BLAKE3) — fast cryptographic hashing
- [coset](https://github.com/nickovs/coset) — COSE token construction and verification
- [ciborium](https://github.com/enarx/ciborium) — CBOR serialization
- [raptorq](https://github.com/cberner/raptorq) — fountain code encoding/decoding
- [reqwest](https://github.com/seanmonstar/reqwest) — HTTP client for connector API calls
- [wiremock](https://github.com/LukeMathWalker/wiremock-rs) — HTTP mocking across the workspace test suite
- [clap](https://github.com/clap-rs/clap) — CLI argument parsing for `fwc`
- [serde](https://github.com/serde-rs/serde) + [serde_json](https://github.com/serde-rs/json) — serialization throughout
- [tracing](https://github.com/tokio-rs/tracing) — structured logging and observability
- [Tailscale](https://tailscale.com/) — mesh networking, identity, and ACL enforcement
- [Asupersync](https://github.com/nickovs/asupersync) — native async runtime (replacing Tokio in production paths)

Developed using multi-agent coding swarms: Claude Code (Opus 4.6), Codex (GPT-5.2), and Gemini coordinating via [MCP Agent Mail](https://github.com/Dicklesworthstone/agent_mail_mcp), [Beads](https://github.com/Dicklesworthstone/beads_rust) issue tracking, and [NTM](https://github.com/Dicklesworthstone/named_tmux_manager) session orchestration. Specification refined through 12+ rounds of [APR](https://github.com/Dicklesworthstone/automated_plan_reviser_pro) with GPT Pro 5.2.

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

1. Manifest signature (registry or trusted publisher quorum) over the manifest signing view and binary hash
2. Binary checksum matches the signed binary hash
3. Platform/arch match
4. Requested capabilities ⊆ zone ceilings
5. **If policy requires**: Transparency log entry present
6. **If policy requires**: in-toto/SLSA attestations valid
7. **If policy requires**: SLSA provenance meets minimum level
8. **If policy requires**: Attestation from trusted builder

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
| Cold start (connector activate) | < 100ms / < 500ms | Host-backed connector activation benchmark harness |
| Local invoke latency (same node) | < 2ms / < 10ms | Host-backed local invoke scenario |
| Tailnet invoke latency (LAN) | < 20ms / < 100ms | Host-backed invoke stub benchmark with injected direct-path RTT plus `fcp-tailnet-invoke-evidence`; real records require a configured tailnet `/rpc/invoke` endpoint and LocalAPI direct-route telemetry, while automatic `fcp-tailscale`/mesh harnessing is still pending |
| Tailnet invoke latency (DERP) | < 150ms / < 500ms | Host-backed invoke stub benchmark with injected DERP RTT plus `fcp-tailnet-invoke-evidence`; real records require a configured tailnet `/rpc/invoke` endpoint and LocalAPI DERP/fallback telemetry, while automatic `fcp-tailscale`/mesh harnessing is still pending |
| Symbol reconstruction (1MB) | < 50ms / < 250ms | RaptorQ benchmark harness |
| Secret reconstruction (k-of-n) | < 150ms / < 750ms | Secret reconstruction benchmark harness |
| Memory overhead | < 10MB per connector | Host-backed RSS process-tree benchmark; current proof: `docs/perf/memory_overhead_evidence.md` |
| CPU overhead | < 1% idle | Host-backed idle CPU benchmark harness |

### Benchmarks

Benchmarking lives in host-backed scenarios and dedicated harnesses. The only supported connector CLI is `fwc`; the retired `fcp` binary is not a benchmark surface.

---

## Ops & Debugging

FCP is designed to be *operable* without disabling security. The CLI exposes the core safety/availability loops:

```bash
# Inspect the active host context and connector inventory
fwc context current
fwc list

# Inspect one connector and its operation schema
fwc show github
fwc schema github issues.create --required-only

# Run a real preflight against live host state, then invoke for real
fwc simulate github issues.create --file payload.json
fwc invoke github issues.create --file payload.json

# Check live connector status and recent execution history
fwc status github
fwc history --connector github --limit 20
```

Key principle: **if you can't explain a denial or quantify offline availability, the system isn't finished.**

---

## Operational Model Versions

FCP defines two operational model versions. **All operators should assume V1 today.**

| Version | Name | Status | Description |
|---------|------|--------|-------------|
| **V1** | Host-First | **Current, Proven** | `fwc -> fcp-host -> connector subprocesses`. Single-active-host deployment. Host-backed and node-local answers. |
| **V2** | Mesh-Native | **Target, NOT YET OPERATIONAL** | Personal device mesh, symbol-first distribution, mesh-backed answers, automatic failover. Zero production evidence. |

**V2 has no committed timeline.** See [docs/OPERATIONAL_MODEL_VERSIONS.md](docs/OPERATIONAL_MODEL_VERSIONS.md) for the full version definitions, per-command version requirements, and transition milestones.

---

## Profiles and Roadmap

### MVP Profile (Ship First)

Delivers the core safety story ("zones + explicit authority + auditable operations") with minimal moving parts.

- FCPC over QUIC for control plane
- CapabilityToken (COSE/CWT) + grant_object_ids verification — typestate
  enforcement (Unverified → UnboundVerified → BoundVerified → ConstraintsEnforced)
  is **fully adopted across connector boundaries** as of 2026-05-02:
  `LEGACY_VERIFY_ALLOWLIST.len() == 0` and
  `TYPESTATE_ENFORCED_ALLOWLIST.len() == 78`. Forward-only ratchet enforced
  by `crates/fcp-conformance/tests/capability_typestate_connector_boundary_dja9u.rs`
  (br-dja9u) — new connectors must use the typestate path; enforced
  connectors cannot regress.
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

## Canonical CLI

`fwc` is the only canonical Flywheel connectors CLI.

- `fwc` is the supported operator and agent surface for connector discovery, schema inspection, lifecycle control, simulation, invocation, batching, history, and context management.
- `fcp` is retired and no longer part of the supported workspace surface.
- Runtime-facing `fwc` commands must either hit live `fcp-host` state or fail explicitly. They must not fabricate connector execution, simulated inventory, or placeholder results.

## FWC Truth Model

`fwc` enforces a host-first control-plane truth contract. The host-backed
path (`fwc -> fcp-host`) is the current operational reality and the only
proven operator surface.

- The knowledge-state taxonomy lives in `crates/fwc/src/truth.rs` and explicitly distinguishes `mesh-backed`, `host-backed`, `node-local`, `offline`, `degraded`, and `fallback-derived` answers.
- `host-backed` is the current authoritative answer: the node-local control-plane view provided by `fwc -> fcp-host`. This is what operators should rely on today.
- `mesh-backed` is the target steady-state answer (NOT YET OPERATIONAL): when live runtime data is joined with mesh placement/durability evidence, the CLI will be able to elevate a result beyond node-local status.
- The command-source classification matrix lives in `crates/fwc/src/catalog.rs` and explicitly marks commands as `live_host`, `offline_artifact`, `hybrid`, or `passthrough`.
- Runtime resolution is performed before dispatch and yields `live`, `explicit-offline`, `degraded-offline`, or `refused` rather than allowing silent live-to-offline switching.
- User-facing result semantics are carried by `CommandAvailability` in `crates/fwc/src/readiness.rs`, with explicit states such as `live-runtime`, `offline-artifact`, `unsupported`, `planned`, `unavailable`, `denied`, and `unknown`.
- Hybrid catalog commands such as `list`, `search`, `show`, `ops`, `schema`, `examples`, `suggest`, `template`, `validate`, and `export-tools` require an explicit `--offline` opt-in for artifact-backed behavior when live host truth is unavailable or not desired.
- Offline results are useful, but they are not authoritative for current runtime state. They must carry provenance markers and stale-data caveats.
- The no-fakes invariant is part of the CLI contract: placeholder runtime data, guessed simulate support, and local file-edit side channels are bugs, not convenience features. When live truth is unavailable, `fwc` must refuse or require explicit offline mode.
- Some command families are still transitional hybrids in the current tree (`config`, `recipe`, `pipeline`, `do`, and parts of `serve-mcp` classification). The direction is command-level truthfulness rather than over-broad family labels.
- Evidence for this model is layered: local semantics in `crates/fwc/src/catalog.rs` and `crates/fwc/src/readiness.rs`, CLI integration coverage in `crates/fwc/tests/cual_integration.rs`, and replayable artifact bundles (`trace.jsonl`, `summary.json`, `environment.json`, `replay.sh`) defined by `crates/fwc/src/test_observability.rs`.

When a `fwc` run fails, the shortest trustworthy debugging loop is:

1. Read `summary.json` for availability state, provenance markers, and join keys.
2. Read `trace.jsonl` for the exact phase sequence and correlation trail.
3. Read `environment.json` for the captured working directory, git SHA, redacted environment, and replay envelope.
4. Run `replay.sh` only after the first three files agree on what should be reproduced.

Template expansion failures, context/preset/bookmark activation drift, pinned-profile mismatches, stale session resume, and replay-environment mismatches should all be debugged through that bundle contract rather than through ad hoc shell retries. The current tree does not yet expose a dedicated preset/bookmark activation CLI, so those symptoms are diagnosed through `fwc context current`, `fwc session ...`, `fwc history ...`, and connector config surfaces instead.

For operator and agent workflows, migration guidance, and evidence-bundle expectations, see [docs/FWC_Host_First_Truthfulness_Playbook.md](docs/FWC_Host_First_Truthfulness_Playbook.md). That playbook is intentionally transition-specific; the steady-state architectural target remains the mesh/object model described in `FCP_Specification_V3.md` and the surrounding mesh/data-plane crates.

## Production Mesh Deployment Runbook

This repository has a truthful deployment/runbook surface for the current
platform shape. Read it with two constraints in mind:

1. the steady-state target is mesh-native — host-first provisioning is transitional
2. the current provisioning path is `fwc -> fcp-host -> connector subprocesses`

The guide teaches how to run the current system honestly while the mesh
cutover converges. The truth hierarchy (mesh-backed > host-backed > node-local > offline)
already drives answer classification; the remaining work is making mesh-backed the
default highest-confidence source in production.

### Proof Anchors

Treat these as the evidence bundle for deployment claims:

- [docs/FWC_Host_First_Truthfulness_Playbook.md](docs/FWC_Host_First_Truthfulness_Playbook.md) for the operator truth model, replay contract, and deployment/failover checklist
- [docs/FCP3_Acceptance_Contracts.md](docs/FCP3_Acceptance_Contracts.md) for the phase-5/phase-6 proof obligations behind mesh-backed and host-backed claims
- [docs/testing/core_platform_evidence_index.md](docs/testing/core_platform_evidence_index.md) for the rerun commands that verify the platform crates backing the operator story

### Current Honest Topology

| Role | Current responsibility | What it proves |
|------|------------------------|----------------|
| **Active host node** | Runs `fcp-host`, supervises connector subprocesses, owns the live connector inventory file and lifecycle state snapshot | Authoritative live `fwc` answers for status, doctor, rollout, config, and invoke |
| **Standby host-capable peer** | Has the same connector binaries, manifests, policy objects, and deployment artifacts staged, but is not treated as authoritative until promoted | Promotion readiness, not current live truth |
| **Mesh/object peers** | Hold placement targets, policy/evidence objects, and durability context used by `mesh explain-availability` | Whether a live answer can be elevated from merely host-backed to mesh-backed |

Today the provisioning boundary is a **single-active-host** system with
deliberate promotion of a standby peer. Connector lifecycle/admin state is
still persisted locally by `fcp-host`. The mesh infrastructure for automatic
failover and state convergence is built and tested but not yet the default;
active/active claims require completing the cutover gates in
`docs/FCP3_Transition_Scorecard.md`.

### Minimum Bring-Up

Build the operator binaries with remote compilation:

```bash
rch exec -- cargo build -p fcp-host -p fwc --release
```

Start `fcp-host` with explicit operator-state paths:

```bash
export FCP_HOST_BIND=0.0.0.0:8787
export FCP_HOST_CONNECTORS_FILE=/srv/fcp/connectors.json
export FCP_HOST_LIFECYCLE_STATE_FILE=/srv/fcp/lifecycle-state.json

./target/release/fcp-host
```

Then verify the deployment from an operator shell:

```bash
fwc --host http://127.0.0.1:8787 list
fwc --host http://127.0.0.1:8787 mesh explain-availability github
fwc --host http://127.0.0.1:8787 status github
fwc --host http://127.0.0.1:8787 doctor --zone z:work --all
fwc config doctor github --host http://127.0.0.1:8787
```

Healthy interpretation:

- `list`, `status`, `doctor`, `config doctor`, and rollout/config mutations are
  authoritative only when they come from the live host
- `mesh explain-availability` is the command that can legitimately elevate a
  connector from host-backed/node-local truth to mesh-backed truth
- if `mesh explain-availability` does not report mesh-backed readiness, do not
  describe the deployment as fully mesh-backed yet

### Provisioning And Secret Flow

- Treat `FCP_HOST_CONNECTORS_FILE` as the live connector inventory source that
  `fcp-host` mutates.
- Treat `FCP_HOST_LIFECYCLE_STATE_FILE` as the local admin-state snapshot that
  must move with the active host during a controlled failover.
- Stage the same connector binaries and manifests on the standby peer before
  claiming failover readiness.
- Use `fwc config export <connector> --host ... --file baseline.json` before
  any risky config change.
- Use `fwc config import <connector> --host ... --file candidate.json` for live
  config mutation, then immediately run `fwc config doctor`.
- If `fwc config export` reports a sanitized non-replayable snapshot, move the
  affected secrets into credential references or rebuild a complete config
  document explicitly; do not assume the sanitized export is a rollback file.

### Rollout And Rollback Loop

Use the rollout surface as the operator control loop:

```bash
fwc rollout set github --canary 10 --host http://127.0.0.1:8787
fwc rollout status github --host http://127.0.0.1:8787
fwc status github --host http://127.0.0.1:8787
fwc doctor --zone z:work --all --host http://127.0.0.1:8787
fwc rollout rollback github --to 1.2.2 --host http://127.0.0.1:8787
```

Operational rules:

- `rollout set` and `rollout rollback` are truthful for the current node's live
  mutation, but they do not by themselves prove later runtime stabilization
- after every rollout or rollback, re-check `rollout status`, `status`,
  `doctor`, and `mesh explain-availability`
- if the active node degrades, promote the staged standby peer deliberately
  rather than assuming automatic lease handoff or automatic state convergence

### Failover Assumptions

The current deployment guide is intentionally narrower than the long-term mesh
vision:

- multi-node durable-object placement is part of the evidence story
- connector admin/lifecycle state is still node-local
- automatic lease handoff and multi-node connector-state replication remain
  future proof obligations, not current production promises

That means the current honest production story is **warm-standby mesh-backed
operation with supervised promotion**, not autonomous active/active mesh
control-plane failover.

## Project Structure

This is a schematic map, not an exhaustive directory dump. The current tree contains 34 crates under `crates/` and 150 connector crates under `connectors/`. All 150 connector crates currently ship manifests and tests; 138 use the full `client.rs`/`connector.rs`/`types.rs` layout, while a smaller set are thinner or explicitly incubating/quarantined. Default workspace operations focus on a curated subset of platform crates; connector crates are usually targeted explicitly.

```
flywheel_connectors/
├── crates/
│   ├── fcp-async-core/        # Transitional async/runtime substrate
│   ├── fcp-async-core-macros/ # Proc macros for async core
│   ├── fcp-audit/             # Older audit-chain primitives still used in the migration
│   ├── fcp-auth-schema/       # Shared typed auth-claim schema for capability tokens
│   ├── fcp-bootstrap/         # Provisioning and first-run ceremony flows
│   ├── fcp-core/              # Shared domain types: zones, capabilities, provenance, lifecycle
│   ├── fcp-cbor/              # Deterministic CBOR and schema hashing
│   ├── fcp-crypto/            # Signing, key exchange, AEAD, HPKE, COSE, Shamir
│   ├── fcp-evidence/          # Emerging owner for receipts, revocation, checkpoints, attestations
│   ├── fcp-kernel/            # Emerging owner for execution/lifecycle semantics
│   ├── fcp-protocol/          # FCPC/FCPS framing, sessions, control-plane encoding
│   ├── fcp-store/             # Object store, symbol store, repair, GC, offline state
│   ├── fcp-raptorq/           # RaptorQ codec, chunking, symbol envelopes
│   ├── fcp-tailscale/         # Mesh identity, peer discovery, ACL/tag integration
│   ├── fcp-mesh/              # MeshNode routing, admission, gossip, placement, leases
│   ├── fcp-manifest/          # Connector manifest parsing and validation
│   ├── fcp-policy/            # Emerging owner for zones, capabilities, provenance, approvals
│   ├── fcp-ratelimit/         # Shared token-bucket/sliding-window/leaky-bucket enforcement
│   ├── fcp-sandbox/           # OS/WASI isolation and egress guardrails
│   ├── fcp-host/              # Node-local host/orchestrator and agent-facing admin surfaces
│   ├── fcp-sdk/               # Connector authoring SDK
│   ├── fcp-streaming/         # Shared streaming substrate for connectors
│   ├── fcp-oauth/             # Shared OAuth flows and token lifecycle support
│   ├── fcp-graphql/           # Typed GraphQL client infrastructure
│   ├── fcp-google-discovery/  # Shared Google service metadata/provisioning substrate
│   ├── fcp-registry/          # Registry/install/update and verification flows
│   ├── fcp-telemetry/         # Metrics, trace capture, structured logging helpers
│   ├── fcp-webhook/           # Shared webhook delivery/runtime helpers
│   ├── fcp-conformance/       # Golden vectors, schema checks, interop tooling
│   ├── fcp-testkit/           # Shared test harnesses, fixtures, and mock infrastructure
│   ├── fcp-e2e/               # End-to-end compliance and host-backed scenarios
│   └── fwc/                   # Sole supported Flywheel connectors CLI
│
├── connectors/                # 150 connector crates at varying maturity; 138 use the full client/connector/types layout
│   ├── github/
│   ├── gmail/
│   ├── slack/
│   ├── stripe/
│   ├── telegram/
│   ├── kubernetes/
│   ├── mcp-bridge/
│   └── ...
│
├── crates/fcp-conformance/tests/ # Cross-crate conformance coverage
├── crates/fcp-e2e/tests/         # Host-backed end-to-end scenarios
├── crates/fcp-host/tests/        # Host/admin integration tests
├── FCP_Specification_V3.md       # Current architecture + conformance direction
├── FCP_Specification_V2.md       # Historical / legacy-interoperability reference
├── AGENTS.md                     # AI coding agent guidelines
└── README.md
```

In other words: the repo already contains a broad platform and connector surface, but the most important architectural seams today live in crate-local tests and the `fwc`/`fcp-host` operator stack, not in a single monolithic root `tests/` directory.

---

## Current Implementation Topology

Practically, the current implementation still exposes a host-first control plane layered over lower-level protocol, mesh, and object-store crates. The primary operator path is `fwc -> fcp-host -> connector subprocesses`, but that should be read as the current supervision and truth-reporting boundary, not as permission to teach the whole platform as permanently host-centric.

The workspace already clusters into a few clear responsibility bands:

| Band | Current Crates | What Lives There |
|------|----------------|------------------|
| **Transitional semantic bucket** | `fcp-core` | The broad shared vocabulary crate that still carries much of the current request/response, capability, provenance, receipt, lifecycle, and connector contract surface |
| **Emerging owner crates** | `fcp-kernel`, `fcp-policy`, `fcp-evidence` | The intended long-term homes for execution semantics, policy/trust semantics, and evidence/receipt/revocation semantics; today they mostly re-export from `fcp-core` while the refoundation continues |
| **Canonicalization and primitive building blocks** | `fcp-cbor`, `fcp-crypto`, `fcp-audit` | Deterministic encoding, cryptographic primitives, and older audit-chain building blocks that higher-level crates still consume |
| **Durable mesh/data plane** | `fcp-protocol`, `fcp-store`, `fcp-raptorq`, `fcp-tailscale`, `fcp-mesh` | FCPC/FCPS framing, symbol/object handling, repair, routing, admission, gossip, leases, and mesh identity |
| **Host/operator surfaces** | `fcp-host`, `fwc` | Node-local orchestration, admin/discovery/invoke/status surfaces, and the single supported operator/agent CLI |
| **Connector authoring/runtime helpers** | `fcp-sdk`, `fcp-streaming`, `fcp-oauth`, `fcp-graphql`, `fcp-google-discovery`, `fcp-ratelimit`, `fcp-bootstrap`, `fcp-telemetry`, `fcp-manifest`, `fcp-sandbox`, `fcp-registry` | Connector contracts, streaming/polling supervision, auth/provider helpers, retries, provisioning, manifests, sandboxing, registry/install flows, and observability |
| **Verification harnesses** | `fcp-conformance`, `fcp-testkit`, `fcp-e2e` | Golden vectors, schema validation, reusable fixtures, and end-to-end compliance coverage |

That split is useful because it shows what is already coherent versus what is still transitional.
`fcp-host` is already the node-local orchestration boundary. `fwc` is the canonical operational
surface. The biggest remaining transitional seam is semantic ownership: `fcp-core` still holds a
large amount of vocabulary, while `fcp-kernel`, `fcp-policy`, and `fcp-evidence` already exist as
the intended long-term owners and are being introduced through a re-export-first migration.

Two current-reality notes matter when reading the rest of this README:

- `fcp-core` still carries most of the semantic request/response, capability, provenance, receipt, and lifecycle vocabulary in the current tree.
- `fcp-kernel`, `fcp-policy`, and `fcp-evidence` are already present and document the intended ownership boundaries, but today they still re-export heavily from `fcp-core`.
- The repo’s integration burden is distributed. The most important end-to-end and conformance coverage lives in crate-local test suites such as `crates/fcp-conformance/tests`, `crates/fcp-e2e/tests`, `crates/fcp-host/tests`, and per-connector integration tests.

## FCP3 Ownership Direction

The FCP3 re-foundation is converging on a stricter "one concept, one home" rule:

| Long-term boundary | Current source material | Intended ownership rule |
|--------------------|-------------------------|-------------------------|
| **Kernel / execution semantics** | `fcp-kernel`, `fcp-core`, parts of `fcp-protocol`, parts of `fcp-host` | Runtime context, lifecycle, invocation semantics, cancellation/progress, budgets, and operator-facing execution contracts belong in the kernel boundary, not in CLIs or connector-specific helper layers |
| **Policy / trust semantics** | `fcp-policy`, `fcp-core`, `fcp-manifest` | Zone, capability, provenance, taint, approval, and policy-bundle semantics belong in the policy boundary rather than being smeared across host, CLI, and connector code |
| **Evidence / receipt semantics** | `fcp-evidence`, `fcp-core`, `fcp-audit` | Receipts, intents, revocation, checkpoints, and supply-chain evidence belong in the evidence boundary rather than in the generic semantic bucket |
| **Mesh + object substrate** | `fcp-mesh`, `fcp-store`, `fcp-raptorq`, `fcp-tailscale`, `fcp-protocol` | Placement, repair, checkpoint sync, admission, object durability, symbol transport, and session/framing mechanics stay together as the mesh/object plane rather than being re-implemented inside host or SDK code |
| **Host / supervision** | `fcp-host` | Activation, lifecycle, rollout, health, policy compilation, admin RPC, explain/doctor surfaces, and execution placement belong to the host as a supervised root application |
| **Connector SDK** | `fcp-sdk`, `fcp-streaming`, `fcp-oauth`, `fcp-graphql`, `fcp-google-discovery`, `fcp-ratelimit` | Connector-facing ergonomics, typed I/O helpers, streaming/polling/webhook utilities, shared provider tooling, and reusable runtime helpers belong in the SDK/helper layer, not in the kernel |
| **Tooling and verification surfaces** | `fwc`, `fcp-conformance`, `fcp-testkit`, `fcp-e2e`, `fcp-telemetry` | Operator UX, agent UX, conformance, replayable evidence, and harnesses stay outside the kernel and host so they can evolve without smearing core semantics |

The remaining quarantine surfaces (see `docs/FCP3_Retirement_Kill_List.md` for the full classification):

- `fcp-async-core` wraps the Asupersync runtime and retains a Tokio compatibility bridge for wiremock/reqwest test infrastructure. The bridge is quarantined with explicit removal triggers.
- `fwc/src/serve_mcp.rs` has one remaining `tokio::io` import, quarantined until `fcp-async-core::io` gains `AsyncWrite` and `lines()` support.
- Connector crates use `ConnectorErrorMapping`; the migration framework (`ConnectorRuntime`, `RetryLoop`) is proven across request-response, streaming, and polling archetypes.

The FCP3 runtime kernel uses Asupersync natively. All production transport code (including WebSocket in `fcp-streaming`) runs on the Asupersync runtime. No compatibility-first holdouts remain in production paths.

---

## Related Flywheel Components

FCP integrates with the broader Agent Flywheel ecosystem:

| Component | Purpose | Interaction |
|-----------|---------|-------------|
| **Tailscale** | Mesh networking, identity | Transport and ACL layer |
| **MCP Agent Mail** | Inter-agent messaging | Coordinate connector operations |
| **Beads (br/bv)** | Issue tracking | Track connector development |
| **CASS** | Memory/context system | Store connector interaction history |
| **UBS** | Bug scanning | Validate connector code |
| **dcg** | Command guard | Protect during development |

---

## Development

### Prerequisites

- Rust nightly (2024 edition)
- Cargo
- Tailscale (for mesh features)
- **Sibling repositories** (required for a fresh-clone build): this workspace depends on two external repos via relative `path = "../../../<sibling>"` entries in several `Cargo.toml` files, so they must be cloned as siblings at the same directory level as this repo:

  ```bash
  # Expected layout — all three repos share a parent directory:
  #   parent/
  #   ├── asupersync/          ← native async runtime (required)
  #   ├── toon_rust/           ← TOON serializer library (required)
  #   └── flywheel_connectors/ ← this repo

  git clone https://github.com/Dicklesworthstone/asupersync.git
  git clone https://github.com/Dicklesworthstone/toon_rust.git
  git clone https://github.com/Dicklesworthstone/flywheel_connectors.git
  ```

  `asupersync` is consumed by `fcp-host`, `fcp-async-core`, `fcp-graphql`, `fcp-tailscale`, `fcp-telemetry`, and the Slack/Discord connectors. `toon_rust` is consumed by `crates/fwc` (imported as `toon`, though the underlying package is named `tru`). If either sibling is missing, `cargo build` fails at the dependency-resolution step with a `failed to get <name> as a dependency` error followed by a `failed to read .../Cargo.toml` cause pointing at the missing sibling directory — that shape is the fingerprint of a missing sibling checkout rather than a code problem. The error cites package names, so a missing `toon_rust` checkout will be reported against package `tru`, not the `toon` alias.

### Building

In shared multi-agent sessions, offload CPU-heavy Cargo work through `rch` so local machines do not
turn into compilation bottlenecks. `rch` fails open to local execution if the worker fleet is unavailable; in swarm-style sessions, abort that local fallback instead of letting heavy Cargo work pile onto the workstation unexpectedly.

This repo carries both `.rchignore` and a project-level `.rch/config.toml` for `.beads` hygiene and worker git-metadata isolation. In the current upstream `rch` source, retrieval-side filtering comes from `.rchignore`, while `.rch/config.toml` keeps the same excludes visible in effective config and applied on the upload side. Older installed `rch` releases can predate that retrieval-side fix, so post-success retrieval failures may still appear even when the repo configuration is correct. Keep `.git/` excluded for this repo: allowing local refs or `packed-refs` to sync without the corresponding object database can corrupt the worker clone and surface later as `RCH-E326` / `fatal: bad object HEAD`. If `rch` prints `Remote command finished: exit=0` and only then fails during `Retrieving build artifacts...`, treat that as a tooling or worker-state problem rather than a Cargo failure; keep the retrieval stderr, then retry or continue the investigation in `rch` itself.

Treat remote toolchain drift as a separate class of failure from both repo build errors and retrieval-only problems. If remote stderr says the selected worker is missing the toolchain pinned in `rust-toolchain.toml` and `rch` then attempts to fail open locally, the root cause is worker runtime drift or worker selection, not a Cargo metadata-cycle regression inside this repo. In shared multi-agent sessions, stop the unexpected local fallback, preserve the remote stderr, and use `rch status --json` plus `rch workers capabilities --refresh --command 'cargo +<toolchain> check --lib'` to decide whether the remedy belongs in worker fleet maintenance, worker selection, or repo-local guidance.

```bash
# Build the default workspace members (core platform crates)
rch exec -- cargo build --release

# Build the full workspace, including connector crates
rch exec -- cargo build --workspace --release

# Build specific connector
rch exec -- cargo build --release -p fcp-telegram

# Run tests for the default workspace members
rch exec -- cargo test

# Run tests for the full workspace
rch exec -- cargo test --workspace

# Run clippy for the full workspace
rch exec -- cargo clippy --workspace --all-targets -- -D warnings

# Narrow crate-local compiler smoke check for fcp-core without syncing the full connector workspace
(cd .rch/probes/fcp-core && rch exec -- cargo check)

# Narrow crate-local compiler smoke check for fcp-host without syncing the full connector workspace
(cd .rch/probes/fcp-host && rch exec -- cargo check)

# ASUPERSYNC Tokio guardrail (local + CI parity)
bash scripts/ci/asupersync_tokio_guard.sh
```

The tracked `rch` probes pin their `target-dir` under `/tmp`, outside the synced
project tree. That keeps `rch` from spending most of the run syncing probe-local
`target/` artifacts back into the repo after the remote check has already
finished. Probe-local `target/` directories also stay excluded from git and
`rch` sync rules so stale worker artifacts cannot leak back into the workspace.
The probe directories also carry their own `.rchignore` files because retrieval
filtering is evaluated relative to the probe root when you run `rch exec` there.

### Creating a New Connector

1. Create connector crate: `cargo new connectors/myservice --lib`
2. Add FCP SDK dependency
3. Add `src/limits.rs` with named platform caps and TODO placeholders for limits you have not wired yet
4. Implement `FcpConnector` trait and import limits from `limits.rs` instead of inlining magic numbers in validation code
5. Define manifest with capabilities, zone policy, and sandbox config
6. Add archetype-specific traits
7. Write tests with mocked external service, including limit-boundary coverage that uses the named constants
8. Document AI hints for each operation

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
  spec: FCP_Specification_V3.md
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
   to understand the project. Read FCP_Specification_V3.md first, and only
   use docs/fcp_model_connectors_rust.md when you need to reconcile legacy
   V2-era connector assumptions.
   ```

2. **Integrate feedback** from GPT Pro:
   ```
   Integrate this feedback from GPT 5.2 (evaluate each suggestion):
   <paste apr show N output>
   ```

3. **Harmonize documents**: Update README first, then any migration/legacy-reference docs, then the canonical V3 spec if the round changes architectural truth

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
| `FCP_Specification_V3.md` | Main protocol and conformance specification |
| `FCP_Specification_V2.md` | Historical / interoperability reference only |
| `docs/fcp_model_connectors_rust.md` | Legacy Rust connector guide used for migration deltas, not canonical FCP3 truth |
| `docs/GOOGLE_Connector_Platform_Reference.md` | Developer/operator guide for the shared Google connector platform |
| `.apr/workflows/fcp.yaml` | APR workflow configuration |
| `.apr/rounds/fcp/round_N.md` | GPT Pro output for each round |

---

## Rate Limiting Architecture

`fcp-ratelimit` provides three complementary algorithms. Each connector declares rate limit pools in its manifest; the host enforces them before dispatching operations.

| Algorithm | Use Case | State | Thread Safety |
|-----------|----------|-------|---------------|
| **Token Bucket** | Steady-state rate limiting with burst tolerance | Atomic u32 + Mutex for refill timestamp | Lock-free consume via CAS loop |
| **Sliding Window** | Precise request counting over a time window | Mutex-guarded VecDeque of timestamps | Single Mutex, cleanup on access |
| **Leaky Bucket** | Smooth output rate with configurable drain | Mutex-guarded f64 level + leak rate | Leak on every access |

Operational FCP rate limits flow through `config_from_core` into `TokenBucket::from_config`, which uses a phase-preserving refill anchor: `last_refill = now - (elapsed % refill_interval)`. This avoids drift accumulation on the smooth-refill path used for manifest-backed limits. The convenience `TokenBucket::new` / `with_burst` constructors remain available for simpler whole-window buckets in tests and direct callers.

Jitter in retry backoff uses the range `[0.5x, 1.5x)` of the base delay via `random_float().mul_add(1.0, 0.5)`, preventing thundering herds when many connectors retry simultaneously.

---

## Egress Proxy

Every connector's network access passes through the egress proxy. The proxy enforces manifest-declared network constraints at the connection level. Connectors cannot reach hosts they haven't declared.

```
Connector ──HTTP request──> Egress Proxy
                              │
                              ├─ 1. CIDR deny list (localhost, private, tailnet)
                              ├─ 2. Host allowlist (from manifest network_constraints)
                              ├─ 3. Port allowlist (from manifest)
                              ├─ 4. TLS requirement enforcement
                              ├─ 5. SNI verification (hostname matches)
                              ├─ 6. Optional SPKI pinning (certificate pinning)
                              ├─ 7. DNS response limit
                              ├─ 8. Credential injection (secretless mode)
                              │     └─ X-FCP-Credential-Id header → proxy resolves to bearer token
                              └─ 9. Audit event logged
                              │
                              ▼
                         External API
```

Default CIDR deny ranges: `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10` (tailnet), `169.254.0.0/16` (link-local), `::1/128`, `fc00::/7`.

Connectors in `credential_id` mode never see raw API keys. The egress proxy resolves the credential reference and injects the bearer token into the outgoing request. If the connector process is compromised, the attacker has no credentials to exfiltrate.

---

## Webhook Delivery System

`fcp-webhook` handles inbound webhook reception from external services (GitHub, Stripe, Slack, etc.) with three layers of protection:

**Signature verification** (timing-safe):
- HMAC-SHA256 with `mac.verify_slice()` (constant-time comparison via the `hmac` crate)
- HMAC-SHA1 for legacy providers
- Ed25519 for providers that support it
- Secrets redacted in Debug output (`[REDACTED]`)

**Replay protection**:
- Deterministic event IDs: `SHA256(provider ‖ 0x00 ‖ event_type ‖ 0x00 ‖ body)`, so the same input always produces the same ID
- Atomic claim via RwLock: `claim_event()` checks and records under one write lock; the older split `check_replay()` / `record_event()` pair is deprecated because it is TOCTOU-racy
- TTL-based cleanup (default 24 hours) with periodic garbage collection

**Provider-specific parsing**:
- Slack: Unwraps `event_callback` envelope to extract inner `event.type` (e.g., `message` instead of `event_callback`)
- GitHub: Extracts `X-GitHub-Delivery` header as event ID; falls back to deterministic ID if missing
- Generic: Configurable header extraction with fallback chain

---

## Bootstrap Ceremony

First-run setup for a new FCP mesh uses a multi-phase ceremony with crash recovery:

```
Phase 1: Time Validation
    └─ NTP drift check (5-min error threshold, 30-sec warning)

Phase 2: Genesis
    ├─ Generate 256-bit entropy (OsRng)
    ├─ Derive BIP39 recovery phrase (24 words)
    ├─ Derive owner keypair from recovery phrase
    ├─ Create genesis object (canonical CBOR, signed)
    └─ Atomic file write (temp → fsync → rename)

Phase 3: Node Key Generation
    ├─ Generate node signing key (Ed25519)
    ├─ Generate node encryption key (X25519)
    ├─ Generate node issuance key (Ed25519)
    └─ Owner signs NodeKeyAttestation

Phase 4: Zone Initialization
    ├─ Generate zone symmetric keys
    ├─ Create ZoneKeyManifest (HPKE-sealed per node)
    └─ Initialize audit chain (genesis event)
```

Crash recovery: A lock file tracks the current phase. If the process crashes and restarts, it detects the lock and resumes from the last completed phase rather than re-running the ceremony.

Recovery phrases use `zeroize::ZeroizeOnDrop`, so entropy is zeroed from memory when the `RecoveryPhrase` struct is dropped. Constant-time comparison via `subtle::ConstantTimeEq` prevents timing side-channel attacks during phrase verification.

Cold recovery reconstructs the owner keypair from the recovery phrase and re-derives all zone keys. Objects created after the original genesis that haven't been replicated will be lost; the tool documents this and warns during recovery.

---

## MCP Tool Export

`fwc serve-mcp` exposes discovered connectors as MCP (Model Context Protocol) tools over stdio JSON-RPC, allowing any MCP-compatible AI agent to use FCP connectors directly:

```bash
# Serve all connectors as MCP tools (requires running fcp-host)
fwc serve-mcp --host http://127.0.0.1:8787

# Serve specific connectors only
fwc serve-mcp --host http://127.0.0.1:8787 github slack gmail

# Offline tool schema export (for agent configuration)
fwc export-tools --offline --format mcp --json
fwc export-tools --offline --format claude github
fwc export-tools --offline --format openai --risk-max medium --output tools.json
```

Export formats: `mcp` (MCP tool schema), `claude` (Claude tool_use format), `openai` (OpenAI function calling format). The `--risk-max` filter excludes operations above a risk threshold, preventing agents from accidentally invoking dangerous operations.

---

## Operational Pipelines and Recipes

`fwc` supports multi-step operation composition via pipelines and recipes:

**Pipes** chain two operations where the output of A feeds the input of B:
```bash
fwc pipe github:issues.list slack:messages.send \
    --map 'issue.title -> text' \
    --map 'issue.url -> blocks[0].url'
```

**Pipelines** are TOML-defined multi-step workflows with dependency ordering:
```bash
fwc pipeline list
fwc pipeline validate .fwc/pipelines/notify-on-new-issues.toml
fwc pipeline dry-run .fwc/pipelines/notify-on-new-issues.toml --param owner=octocat
fwc pipeline run .fwc/pipelines/notify-on-new-issues.toml --param owner=octocat
```

**Recipes** are bundled, reusable pipeline templates:
```bash
fwc recipe list
fwc recipe show github-pr-review-notify
fwc recipe dry-run github-pr-review-notify
fwc recipe export github-pr-review-notify > .fwc/pipelines/custom.toml
```

**Batch operations** execute heterogeneous operations from a JSONL file with dependency ordering:
```bash
fwc batch-file operations.jsonl --dry-run
fwc batch-file operations.jsonl
```

---

## Post-Compromise Security (PCS) Zones

Sensitive zones can use MLS/TreeKEM-based post-compromise security, where compromise of a device triggers automatic key rotation that heals the group's forward secrecy:

| Mode | Behavior | Use Case |
|------|----------|----------|
| **Static** | Zone key set once, rotated manually | Low-sensitivity zones, `z:public` |
| **Epoch-Based** | Key rotates on membership changes | Standard zones, `z:work`, `z:private` |
| **Continuous** | Key rotates on every N operations | High-sensitivity, `z:owner` |

`PcsGroupState` tracks the current epoch, member set, and key management mode. When a device is removed (revocation), the remaining members execute a TreeKEM update that produces a new epoch key the removed device cannot derive. Benchmarked at ~2.6us per epoch advance and ~3.5us per removal rekey for groups of 3-10 members.

---

## Limitations

Honest about what FCP doesn't do yet:

- **Production deployment is still single-active-host**: This repository now documents the current deployment/runbook surface, but the honest operating model is still one active `fcp-host` with staged standby peers. Connector admin state remains node-local and automatic multi-node failover is not yet a production guarantee.
- **No GUI**: `fwc` is CLI-only. The `serve-mcp` command exposes connectors as MCP tools for AI agent consumption, but there is no web dashboard.
- **Connector maturity varies**: The connector workspace compiles and passes tests, but depth of operation coverage ranges from comprehensive (GitHub: 12 ops, Gmail: 10 ops) to minimal (some connectors have 3-5 core operations).
- **No Windows sandbox**: `fcp-sandbox` implements seccomp/Landlock on Linux and basic WASI isolation. macOS uses seatbelt. Windows sandbox support is Tier 2 and not yet hardened.
- **No automatic connector updates**: `fwc install` and `fwc update` exist but automatic background updates with rollback are not yet implemented.
- **Single-node state only**: Connector state is externalized as mesh objects in the protocol spec, but the current host implementation stores state locally. Multi-node state replication is architecturally designed but not yet operational.

---

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `fwc list` returns "missing-host-endpoint" | No `fcp-host` running | Use `fwc list --offline` for workspace manifest data |
| Connector returns `NotConfigured` | `configure` not called before `invoke` | Call `fwc config schema <connector>` to see required params, then configure |
| `cargo build` OOMs on macOS | Too many parallel codegen units | Set `CARGO_TARGET_DIR=/tmp/fcp-build` to avoid Cargo lock contention; or use `rch exec -- cargo build` to offload to remote workers |
| `rch exec -- cargo ...` ends with rsync `overflow ... .beads/recovery_*` / `recv_file_entry` / code 22 | The remote Cargo command may already have succeeded, but artifact retrieval is still traversing a worker-side `.beads` recovery tree | Read the remote-command status lines first. If `rch` reports a remote `exit=0`, treat the compile/test itself as successful and the failure as tooling state. This repo mirrors the critical excludes in both `.rchignore` and `.rch/config.toml`; if retrieval still overflows, investigate `rch` client version and stale worker state rather than assuming Cargo failed. |
| `rch exec -- cargo ...` fails remotely because a worker lacks the repo-pinned nightly and then tries to continue locally | The selected worker runtime drifted from `rust-toolchain.toml`; this is a worker-image or worker-selection problem, not a repo dependency-cycle failure | Preserve the remote stderr, do not trust the local fail-open path in shared multi-agent sessions, inspect `rch status --json`, and probe worker capability with `rch workers capabilities --refresh --command 'cargo +<toolchain> check --lib'` before deciding whether to fix worker maintenance, worker routing, or repo guidance. |
| `rch exec -- cargo ...` fails during dependency planning with `RCH-E326`, or a worker clone reports `fatal: bad object HEAD` / `git cat-file: could not get object info` | The worker-side canonical clone synced git refs or shallow metadata without the matching object database | Treat it as worker clone state, not a Cargo failure. Verify `/data/projects/flywheel_connectors` on the selected worker with `git cat-file -t HEAD`. If refs are stale, refresh them without rewriting the checked-out worktree: `git fetch --force --update-shallow --deepen=64 origin +refs/heads/main:refs/remotes/origin/main`. This repo now excludes `.git/` in both `.rchignore` and `.rch/config.toml` to prevent the drift from recurring. |
| Clippy fails with `fcp-async-core` errors | Pre-existing lints in async-core test code | These are upstream; connector code is clean. Run clippy on specific crates: `cargo clippy -p fcp-<crate>` |
| OAuth token refresh fails | Token expired between materialize and use | For `credential_id` auth, the egress proxy handles refresh. For `access_token`, re-run configure with a fresh token |
| SSE stream stops without error | Connection idle timeout | The Anthropic SSE parser has a 16 MiB buffer limit and proper CRLF handling. Check network/proxy timeout settings |

## FAQ

**Q: Why 150 separate connector crates instead of a plugin system?**
Each connector is a standalone binary with its own manifest, capabilities, and sandbox policy. This eliminates shared-memory vulnerabilities, enables per-connector resource limits, and makes supply-chain verification tractable (you sign one binary, not a runtime + plugin combination).

**Q: Why RaptorQ instead of regular file transfer?**
Fountain codes eliminate retransmit coordination. Any K' symbols reconstruct the original; no packet is special. This enables multipath aggregation (symbols from any device contribute equally), natural offline resilience (partial availability = partial reconstruction), and DoS resistance (attackers can't target "important" packets).

**Q: Why Tailscale as the transport layer?**
Tailscale provides unforgeable WireGuard keys (identity), NAT traversal (connectivity), and ACLs (authorization) in one layer. FCP maps zones to Tailscale tags, giving cryptographic network isolation without managing a separate PKI.

**Q: Can I use FCP without the mesh?**
Yes. The host-first stack (`fwc` + `fcp-host`) works standalone on a single machine. The mesh layer adds multi-device distribution, offline resilience, and symbol-based data availability, but none of that is required for basic connector operation.

**Q: Why TOON output by default instead of JSON?**
TOON (Token-Optimized Output Notation) is 2-5x more token-efficient than JSON for AI agent consumption. Every `fwc` command also supports `--json` for full-fidelity structured output, plus `--format table|csv|tsv|markdown` for human consumption.

**Q: How do I add a new connector?**
Use the scaffold generator: `fwc new myservice --archetype request-response`. This creates a complete connector crate with manifest, error types, client stub, `ConnectorErrorMapping`, limits constants, and test harness. See "Creating a New Connector" below.

**Q: What happens if a connector tries to access a host outside its manifest?**
The egress proxy denies the request. Network constraints are declared per-operation in the manifest (`allowed_hosts`, `allowed_ports`, `require_tls`). The sandbox enforces CIDR deny defaults (localhost, private ranges, tailnet) and SNI verification. The denial is logged as an audit event.

---

## Contributing

> *About Contributions:* Please don't take this the wrong way, but I do not accept outside contributions for any of my projects. I simply don't have the mental bandwidth to review anything, and it's my name on the thing, so I'm responsible for any problems it causes; thus, the risk-reward is highly asymmetric from my perspective. I'd also have to worry about other "stakeholders," which seems unwise for tools I mostly make for myself for free. Feel free to submit issues, and even PRs if you want to illustrate a proposed fix, but know I won't merge them directly. Instead, I'll have Claude or Codex review submissions via `gh` and independently decide whether and how to address them. Bug reports in particular are welcome. Sorry if this offends, but I want to avoid wasted time and hurt feelings. I understand this isn't in sync with the prevailing open-source ethos that seeks community contributions, but it's the only way I can move at this velocity and keep my sanity.

---

## License

MIT License (with OpenAI/Anthropic Rider). See [LICENSE](LICENSE).
