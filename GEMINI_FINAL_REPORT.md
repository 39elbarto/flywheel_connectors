# FCP SWARM STABILIZATION: FINAL SYNTHESIS REPORT

This report synthesizes the collective findings and fixes from the multi-lane cryptographic and architectural review of the Flywheel Connector Protocol (FCP) Rust codebase.

## 1. SUMMARY OF FIXED BUGS

### LANE 1: Cryptography & Token Verification
- **[L1-01]** Low | `cose.rs:390` | `CwtClaims` now rejects duplicate CBOR keys to ensure deterministic verification.
- **[L1-02]** Low | `signature.rs:77` | HMAC prefix stripping (`sha256=`, `v1=`) is now case-insensitive for proxy interoperability.
- **[L1-04]** Med | `ed25519.rs:162` | Hardened Ed25519 key acceptance to explicitly reject all-zero and small-subgroup points.
- **[L1-05]** Low | `hpke_seal.rs:59` | `HpkeSealedBox` now enforces strict length checks for encapsulated keys to prevent junk injection.
- **[L1-07]** High | `canonicalize.rs:136` | Corrected CBOR sort order to RFC 8949 (bytewise-lexicographic) for cross-crate compatibility.
- **[L1-08]** Med | `canonicalize.rs:106` | Implemented 128-level recursion depth limit for CBOR canonicalization to mitigate DoS.
- **[L1-09]** Low | `canonicalize.rs:114` | Rejects non-finite floats (NaN/Inf) and normalizes -0.0 in all canonical signing paths.

### LANE 2: Mesh Zone-Crossing & Gossip
- **[L2-01]** Med | `node.rs:1055` | Implemented zone-aware routing storage and mandatory `NodeInfo` zone population.
- **[CL-01]** Med | `node.rs:1278` | Enforced zone authorization in gossip handlers; peers can no longer broadcast state for foreign zones.
- **[L2-03]** Med | `gossip.rs:242` | Implemented timestamp-based replay protection for peer gossip state updates.
- **[L2-10]** Med | `node.rs:1142` | Enforced per-peer concurrent decode limits for CPU-intensive RaptorQ control-plane frames.
- **[L2-11]** Low | `planner.rs:312` | Fixed semver-unsafe lexical version comparison in the mesh routing planner.
- **[L2-13]** Med | `coordinator.rs:412` | Capped lease fencing token drift to prevent adversarial "pinning" of global counters.
- **[L2-17]** Low | `supervisor.rs:342` | Fixed a race condition in the connector connection tracker during node shutdown.

### LANE 3: Revocation & Enforcement
- **[L3-01]** Critical | `enforcement.rs:1020` | Wired concrete `is_revoked()` lookups into the 11-stage host enforcement pipeline.
- **[CL-02]** Med | `revocation.rs:526` | Enforced strict sequence monotonicity in `RevocationRegistry::update_head` to prevent rollbacks.

### LANE 4: Bootstrap & Ceremonies
- **[CL-03]** High | `genesis.rs:136` | Genesis fingerprint now hashes `created_at` and `initial_zones` to ensure unique mesh identity.
- **[CL-04]** Med | `hardware_token.rs:217` | Fixed memory leak of sensitive PINs by eliminating unzeroized `String` clones.
- **[L4-04]** Med | `shamir.rs:107` | Forced `OsRng` usage for all root-of-trust derivation paths (Shamir shares, owner keys).

## 2. OPEN FINDINGS & SUGGESTED NEXT STEPS

- **[L4-01]** Critical | `workflow.rs:222` | **Bootstrap Resume Failure**: Ceremony cannot resume from partial state. *Next Step: Implement state machine checkpointing and re-entry.*
- **[L3-02]** High | `node.rs:1418` | **Gossip Dispatch Gap**: Production mesh nodes do not yet dispatch gossip to internal handlers. *Next Step: Wire the transport layer router to call `MeshNode::handle_gossip_message`.*
- **[L3-04]** Med | `fwc/zone_scope.rs:1` | **Logic Duplication**: CLI contains a parallel zone/capability implementation. *Next Step: Refactor `fwc` to use `fcp-core` primitives.*
- **[L1-06]** Low | `frost.rs:293` | **FROST Consistency**: Missing aggregate share validation on load. *Next Step: Add an optional `.validate()` method to `FrostKeyPackage`.*
- **[L2-09]** Low | `admission.rs:88` | **Burst Vulnerability**: Fixed-window rate limiting allows burst exploits. *Next Step: Migrate to a sliding window or weighted moving average.*

## 3. ARCHITECTURAL RISKS

1. **Gossip Latency vs. Pull Window**: Until **[L3-02]** is addressed, revocation propagation is pull-limited (minutes) rather than gossip-limited (milliseconds). This creates a high-severity window for revoked token usage in production.
2. **Policy Divergence**: The duplication of core logic in the CLI (**[L3-04]**) creates a risk of inconsistent enforcement across different FCP entry points (CLI vs. API).
3. **Implicit Stateless Trust**: `CapabilityToken<Verified>` denotes cryptographic validity but NOT revocation status. We recommend renaming this to `CryptographicallyVerified` or adding a mandatory `RevocationContext` to prevent stateless misuse.

---
*For detailed lane findings, see: [LANE 1](GEMINI_LANE1_CRYPTO.md), [LANE 2](GEMINI_LANE2_MESH.md), [LANE 3](GEMINI_LANE3_REVOCATION.md), [LANE 4](GEMINI_LANE4_BOOTSTRAP.md)*
