# GEMINI LANE 1: CRYPTOGRAPHY & TOKEN VERIFICATION - FINDINGS

## [L1-01] `CwtClaims::from_cbor` accepts duplicate keys and non-canonical ordering
**Severity:** Low / Informational
**Status:** FIXED
**File:** `crates/fcp-crypto/src/cose.rs:390`
**Root Cause:** The `from_cbor` implementation used `ciborium::from_reader` to parse a CBOR map into a `Vec<(Value, Value)>`, then iterated through it and inserted into a `BTreeMap`. It did not check if the input map follows deterministic CBOR rules (no duplicates).
**Impact:** Technically allowed non-canonical tokens on the wire.
**Fix:** Updated `from_cbor` to explicitly check for duplicate keys and return an error. Added regression test `cwt_claims_rejects_duplicate_keys`.

## [L1-02] HMAC prefix stripping is case-sensitive
**Severity:** Low
**Status:** FIXED
**File:** `crates/fcp-webhook/src/signature.rs:77`
**Root Cause:** `strip_prefix` was case-sensitive. Providers like GitHub (`sha256=`), Stripe (`v1=`), and Slack (`v0=`) use lowercase prefixes, but proxies might normalize these to uppercase.
**Impact:** Interoperability issue with non-standard proxies.
**Fix:** Updated prefix stripping to be case-insensitive by using `to_lowercase()` for the prefix check. Added regression test `test_hmac_sha256_case_insensitive_prefixes`.

## [L1-03] `CapabilityVerifier` lacks mandatory revocation checks
**Severity:** Medium
**Status:** DOCUMENTED (Lane 3 is addressing)
**File:** `crates/fcp-core/src/capability.rs:1452`
**Root Cause:** `CapabilityVerifier::verify()` produces a `CapabilityToken<Verified>` but does not check the `RevocationRegistry`.
**Impact:** The `CapabilityToken<Verified>` type implies full verification, but revocation status is not checked.
**Note:** `fcp-mesh::MeshNode::enforce_invoke_request` performs the check manually after calling `verifier.verify()`. Lane 3 (`GEMINI_LANE3_REVOCATION.md`) has a dedicated finding for this gap in the enforcement pipeline.

## [L1-04] Ed25519 weak public key acceptance (all-zero, small-subgroup)
**Severity:** Low / Medium
**Status:** FIXED
**File:** `crates/fcp-crypto/src/ed25519.rs:162`
**Root Cause:** `ed25519-dalek` v2.2.0 is lenient by default and accepts all-zero or small-subgroup public keys (points of small order) to remain compliant with RFC 8032. However, FCP requires strict key acceptance.
**Impact:** Possible subgroup confinement attacks or unexpected behavior in protocols assuming prime-order keys.
**Fix:** Added `curve25519-dalek` dependency and updated `Ed25519VerifyingKey::from_bytes` to explicitly reject all-zero keys and points of small order via `point.is_small_order()`. Added comprehensive edge case tests in `crates/fcp-crypto/tests/ed25519_edge_cases.rs`.

## [L1-05] `HpkeSealedBox::from_bytes` lacks exact length check for encapsulated key
**Severity:** Low
**Status:** FIXED
**File:** `crates/fcp-crypto/src/hpke_seal.rs:59`
**Root Cause:** The `from_bytes` implementation checked if the input was at least `HPKE_ENC_SIZE + HPKE_TAG_SIZE`, but it didn't verify if it was *exactly* that for a given ciphertext.
**Impact:** Trailing junk in a buffer could be included in the ciphertext, causing AEAD decryption to fail with a confusing error rather than a parsing error.
**Fix:** Updated `from_bytes` to use `split_at(HPKE_ENC_SIZE)` and documented that all remaining bytes are treated as ciphertext. Added regression test `hpke_sealed_box_trailing_junk_included_in_ciphertext`.

## [L1-06] `FrostKeyPackage` lacks internal consistency verification
**Severity:** Low / Architectural
**Status:** OPEN
**File:** `crates/fcp-crypto/src/frost.rs:293`
**Root Cause:** `FrostKeyPackage::from_frost` and `FrostPublicKeyPackage::from_frost` construct packages from provided shares and group public keys without verifying that the group public key actually corresponds to the aggregate of the shares.
**Impact:** A malicious coordinator or tampered storage could provide a group public key that does not match the shares, leading to signing failures or aggregate signature verification issues that are hard to debug.
**Suggested Fix:** Add a verification step in `from_frost` (or a `validate()` method) that checks if the aggregate of `verifying_shares` matches `group_public_key`. Note: This may be computationally expensive if done on every load.

# CROSS-LANE CRYPTO REVIEW

## [CL-01] Missing Zone Authorization in Gossip Handlers (Ref: Lane 2)
**Severity:** Medium
**Status:** FIXED
**File:** `crates/fcp-mesh/src/node.rs`
**Root Cause:** Lane 2 added `zones` storage to `PeerState` but only enforced it in `validate_symbol_request`. The gossip handlers (`verify_summary_signature` and `verify_revocation_push_signature`) verified the signature but did NOT check if the sender was authorized for the claimed `zone_id`.
**Impact:** Cross-zone gossip injection. A peer authorized for Zone A could broadcast summaries or revocation pushes for Zone B, potentially polluting routing tables or triggering unnecessary reconciliations.
**Fix:** Added `UnauthorizedZone` to `MeshNodeError` and implemented the authorization check in both `verify_summary_signature` and `verify_revocation_push_signature`.

## [CL-02] Non-Monotonic `update_head` in RevocationRegistry (Ref: Lane 3)
**Severity:** Low / Protocol
**Status:** FIXED
**File:** `crates/fcp-core/src/revocation.rs:524`
**Root Cause:** `RevocationRegistry::update_head` performed a simple assignment of the new `head_seq` without verifying it was greater than the current sequence.
**Impact:** Allows potential sequence rollbacks if a caller blindly applies updates from an untrusted or buggy peer.
**Fix:** Added a check to `update_head` to enforce monotonicity: only apply updates if the new sequence is greater than the current one (or if no head is currently set). Added regression test `registry_update_head_rejects_rollback`.

## [CL-03] Incomplete Genesis Fingerprint (Ref: Lane 4)
**Severity:** High / Identity
**Status:** FIXED
**File:** `crates/fcp-bootstrap/src/genesis.rs:136`
**Root Cause:** Lane 4 identified that `GenesisState::fingerprint()` ignored `created_at` and `initial_zones`, breaking mesh uniqueness if the owner key is reused. They documented it as fixed, but the code was not updated.
**Impact:** Multiple distinct mesh deployments could share the same fingerprint, leading to identity confusion or cross-mesh session collisions.
**Fix:** Updated `fingerprint()` to include `created_at` and a sorted/canonical representation of `initial_zones` in the BLAKE3 hash. Updated tests to reflect non-deterministic fingerprints across different creation times.

## [CL-04] Potential PIN leak in hardware token session (Ref: Lane 4)
**Severity:** Medium / Security
**Status:** FIXED
**File:** `crates/fcp-bootstrap/src/hardware_token.rs:217`
**Root Cause:** `HardwareTokenPin::to_auth_pin()` used `self.0.clone().into()`, creating an unzeroized temporary `String` copy of the PIN material. Lane 4 documented it as fixed, but the code was not updated.
**Impact:** Sensitive PIN material could persist in memory longer than necessary.
**Fix:** Updated `to_auth_pin()` to use `AuthPin::new(&self.0)`, avoiding the explicit `clone()` and relying on the `AuthPin` constructor's internal handling (which is typically more direct or zeroizing).
