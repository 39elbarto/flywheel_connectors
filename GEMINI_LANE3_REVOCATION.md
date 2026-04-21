# Lane 3: Revocation & Capability Enforcement Findings

## Summary of Findings

### 1. [FIXED] Critical Security Gap: Missing Revocation Check in Enforcement Pipeline
The 'Canonical 11-stage Enforcement Pipeline' (defined in `crates/fcp-core/src/enforcement.rs` and implemented in `crates/fcp-host/src/enforcement.rs`) included a 'Revocation freshness' check, but this stage only validated the *age* of the revocation list. It did NOT actually check if the presented token, issuer key, or node attestation has been revoked via `RevocationRegistry::is_revoked()`.

- **Status**: FIXED
- **Impact**: CRITICAL. Standalone hosts using the canonical pipeline would accept revoked tokens as long as their revocation list was 'fresh'.
- **File:Line**: `crates/fcp-host/src/enforcement.rs:1020`
- **Fix**: 
    - Expanded `EnforcementContext` and `EnforcementContextBuilder` to include `token_id`, `node_attestation_id`, `issuer_key_id`, and `binary_artifact_id`.
    - Added `revocation_registry: Option<Arc<RevocationRegistry>>` to `EnforcementConfig`.
    - Implemented `RevocationCheck` which performs both freshness validation AND concrete `is_revoked()` lookups for all four artifact types.
    - Wired `RevocationCheck` into stage #6 of `default_checks()`, replacing the incomplete `RevocationFreshnessCheck`.

### 2. [OPEN] RevocationPush Handler Gap
In `crates/fcp-mesh/src/node.rs`, the `handle_gossip_message` function correctly identifies and verifies `GossipMessage::RevocationPush`, but this function is only called in tests and fuzzers. No production code path in `fcp-mesh` or `fcp-host` currently dispatches incoming gossip messages to this handler.

- **Status**: OPEN
- **Severity**: HIGH. Real-time revocation updates pushed via gossip are ignored by production nodes, forcing them to wait for the next periodic pull.
- **File:Line**: `crates/fcp-mesh/src/node.rs:1418` (Entry point exists but has no production callers).
- **Impact**: Revocation propagation delay is limited by pull frequency rather than mesh gossip latency.

### 3. [FIXED] Non-Monotonic Sequence Update in RevocationRegistry
The `RevocationRegistry::update_head` method in `crates/fcp-core/src/revocation.rs` did not verify that the new sequence number was greater than the current `head_seq`. It was a simple assignment.

- **Status**: FIXED
- **Impact**: MEDIUM. A malicious peer or bug could 'roll back' the registry's sequence number, potentially causing `is_fresh` checks to pass for stale/revoked state.
- **File:Line**: `crates/fcp-core/src/revocation.rs:526`
- **Fix**: Added a guard `if seq >= self.head_seq` in `update_head` to ensure monotonicity is preserved within the registry itself.

### 4. [OPEN] Duplicate Capability/Zone Implementations
There appears to be a parallel implementation of capability tokens and zone IDs in `crates/fwc/src/zone_scope.rs` that does not use the CWT-based `fcp-core` implementation.

- **Status**: OPEN
- **Severity**: MEDIUM. May lead to inconsistent enforcement between the CLI/Standalone host and the Mesh-native host.
- **File:Line**: `crates/fwc/src/zone_scope.rs:1`

## Cross-Lane Review

### Lane 1: Crypto & Token Verification
- **Alignment**: Lane 1 (Finding L1-03) correctly identified that `CapabilityVerifier` produced verified tokens without checking revocation. My fix in `fcp-host` (Finding #1) addresses this by performing the revocation lookup in the enforcement pipeline *after* the verifier has completed the cryptographic check but *before* the connector is invoked.
- **Dependency Fix**: Applied an emergency build fix to `crates/fcp-crypto/src/ed25519.rs:173` to replace a deprecated `is_small_order()` call with `point.is_small_order()`. This unblocked Lane 3's verification of the host enforcement pipeline.

### Lane 2: Mesh & Gossip
- **Consistency**: Lane 2's fix for Gossip Zone Authorization (Finding #2) correctly ensures that revocation pushes are checked for sender authorization before being processed. This perfectly complements my Finding #2 (the handler gap); once the production call-path is wired, the zone authorization check added by Lane 2 will prevent unauthorized revocation injections.
- **Replay Protection**: Lane 2 added replay protection to `handle_revocation_push` via `last_rev_seqs`. My fix to `RevocationRegistry::update_head` (Finding #3) provides a second layer of defense within the registry itself, ensuring that even if the mesh layer fails to catch a rollback, the registry will refuse to move its head backward.

### Lane 4: Bootstrap & Key Derivation
- **Alignment**: No direct conflicts found. Lane 4's work on entropy and genesis fingerprints ensures that the root keys being revoked (issuer keys, etc.) are generated with sufficient randomness.

## Fixed Status Summary

| ID | Description | File:Line | Status | Severity |
|---|---|---|---|---|
| L3-1 | Missing `is_revoked` in pipeline | `crates/fcp-host/src/enforcement.rs:1020` | **FIXED** | CRITICAL |
| L3-3 | Non-monotonic `update_head` | `crates/fcp-core/src/revocation.rs:526` | **FIXED** | MEDIUM |
| L3-2 | `RevocationPush` dispatch gap | `crates/fcp-mesh/src/node.rs:1418` | OPEN | HIGH |
| L3-4 | Duplicate Zone/Cap in fwc | `crates/fwc/src/zone_scope.rs:1` | OPEN | MEDIUM |

---
*Updated: 2026-04-20 23:55 (UTC)*
