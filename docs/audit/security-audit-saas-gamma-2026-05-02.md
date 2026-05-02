# Security Audit For SaaS - Gamma Domain Sweep - 2026-05-02

Agent: SilverFox

Scope:
- `crates/fcp-store`
- `crates/fcp-raptorq`
- `crates/fcp-tailscale`
- `crates/fcp-bootstrap`

Review goals: WAL tampering, replay protection, cursor monotonicity, crash durability, decode-bomb resistance, repair-symbol forging, Tailscale handshake replay, peer identity validation, tag spoofing, hardware-token verification, certificate selection over adversarial cert lists, and soft-token harness invariants.

## Result Summary

- Confirmed vulnerabilities: 1
- Hardening findings filed: 1
- False positives / no-current-exploit findings: 8
- Highest-priority confirmed vulnerability patched: `flywheel_connectors-sfuk9`

## Findings Filed

| Bead | Classification | Summary |
| --- | --- | --- |
| `flywheel_connectors-sfuk9` | confirmed-vuln | `MeshIdentity::fcp_tags()` surfaced FCP zone tags after checking only attestation freshness, not owner signature/tag/key binding. |
| `flywheel_connectors-dgbtx` | hardening-worth-doing | `fcp-store` durable WAL/snapshot envelopes use unkeyed checksums; recomputed-checksum delete/retention/snapshot-omission tamper is not authenticated. |

## Evidence Detail

### fcp-tailscale fcp_tags unverified attestation

Classification: confirmed-vuln

Evidence:
- `crates/fcp-tailscale/src/identity.rs:217-229` routes full attestation verification through `NodeKeyAttestation::verify`.
- Before this sweep, `MeshIdentity::fcp_tags()` at `crates/fcp-tailscale/src/identity.rs:239-249` checked only `is_attestation_valid()`.
- `is_attestation_valid()` at `crates/fcp-tailscale/src/identity.rs:231-237` only checked that an attestation exists and `expires_at > Utc::now()`.
- Full signature, signer KID, node ID, key, and tag binding verification lives in `crates/fcp-tailscale/src/identity.rs:360-396` and was not reached by `fcp_tags()`.

Attack scenario: a caller that treated `MeshIdentity::fcp_tags()` as verified zone membership could deserialize or construct a `MeshIdentity` with attacker-chosen `tag:fcp-owner` / `tag:fcp-work` entries and any non-expired but invalid `NodeKeyAttestation`. The accessor returned those tags without verifying signer, signature, node ID, keys, or signed tag set.

Patch landed in this audit: `fcp_tags()` now fails closed unless `verify_attestation()` succeeds, and regression tests pin mismatched-tag and wrong-owner attestations.

### fcp-store durable envelope authentication gap

Classification: hardening-worth-doing

Evidence:
- `crates/fcp-store/src/durable.rs:110-124` defines snapshot/WAL envelopes with a `checksum` field.
- `crates/fcp-store/src/durable.rs:1220-1224` and `crates/fcp-store/src/durable.rs:1274-1279` verify checksums.
- `crates/fcp-store/src/durable.rs:1457-1460` computes the checksum as plain unkeyed BLAKE3 over serialized JSON.
- Object WAL includes `Delete` and `SetRetention` at `crates/fcp-store/src/durable.rs:139-147`; replay validation for those operations only checks object existence at `crates/fcp-store/src/durable.rs:300-305`.
- Symbol WAL includes `DeleteObject` and `DeleteSymbol` at `crates/fcp-store/src/durable.rs:195-201`; replay validation only checks matching symbol state at `crates/fcp-store/src/durable.rs:532-550`.
- `crates/fcp-store/src/durable.rs:1132-1135` explicitly notes that a WAL checksum proves a record was not torn, not that payload metadata is authentic.

Attack scenario: a stale backup restore or local tamperer with write access to durable files can recompute the unkeyed checksum and append valid-looking delete, retention-downgrade, or symbol-delete records at the next sequence, or rewrite a snapshot that omits objects and advances `last_seq`. Content-ID verification protects forged `Put` body/id bindings when a verifier is installed, but it does not authenticate omission or deletion semantics.

Recommended remediation: add a keyed MAC or signed hash-chain/high-water mark for object and symbol WAL/snapshot envelopes, reject rollback/replay across checkpoint boundaries, and add forged recomputed-checksum regression coverage.

## False Positives And No-Current-Exploit Results

### fcp-store replay monotonicity and crash durability

Classification: false-positive, aside from the authentication hardening bead above

Evidence:
- `crates/fcp-store/src/durable.rs:1240-1295` tracks WAL sequence order, rejects gaps after the snapshot sequence, and truncates invalid/torn tails.
- `crates/fcp-store/src/durable.rs:1314-1339` writes and fsyncs each WAL append before in-memory publication.
- `crates/fcp-store/src/durable.rs:1353-1388` writes snapshots through a unique temp file, fsyncs it, renames it, and fsyncs the parent directory.
- `crates/fcp-store/src/durable.rs:1434-1439` clears and fsyncs WAL after checkpoint.

Result: cursor monotonicity and crash-durability mechanics are present. The remaining gap is authenticity of recomputed-checksum envelopes.

### fcp-store forged Put replay

Classification: false-positive

Evidence:
- `crates/fcp-store/src/durable.rs:227-256` validates snapshot object structure and verifies content IDs when a verifier is installed.
- `crates/fcp-store/src/durable.rs:1077-1112` re-runs verifier and mutation validation during object WAL replay.
- `crates/fcp-store/src/durable.rs:726-750` verifies runtime `Put` records before WAL append when a verifier is installed.

Result: forged `Put` body/id substitution is rejected on verified store paths. The hardening bead is about authenticated delete/retention/omission semantics, not forged object bodies.

### fcp-raptorq max-symbol decode bomb

Classification: false-positive

Evidence:
- `crates/fcp-raptorq/src/decode.rs:51-84` derives max symbols and buffer bytes from object size, symbol size, and repair ratio.
- `crates/fcp-raptorq/src/decode.rs:628-664` rejects transfer lengths, source-symbol counts, and required buffers outside configured budgets.
- `crates/fcp-raptorq/src/decode.rs:701-742` rejects symbol buffer growth past the headroom/budget cap.
- `crates/fcp-raptorq/src/decode.rs:747-805` accounts dense fallback matrix/RHS/intermediate/pivot/bool allocations inside the same hostile-decode budget.

Result: the audited decode-bomb path has explicit caps before expensive reconstruction.

### fcp-raptorq repair-symbol forging

Classification: false-positive

Evidence:
- `crates/fcp-raptorq/src/decode.rs:280-287` rejects symbols in the virtual padding ESI range.
- `crates/fcp-raptorq/src/decode.rs:466-503` re-verifies received source rows, received repair rows, and LDPC/HDPC constraints in dense fallback.
- `crates/fcp-raptorq/src/decode.rs:565-575` verifies reconstructed payload hash when OTI carries one.
- `crates/fcp-raptorq/src/encode.rs:222-233` attaches a BLAKE3 payload hash to encoder-produced OTI.
- `crates/fcp-store/src/resume_handshake.rs:540-556` additionally checks reconstructed snapshot-manifest bytes against the announced manifest hash.

Result: forged repair symbols either fail equation/hash checks or remain bound by higher-layer manifest/object verification on the inspected store path.

### fcp-raptorq unbounded ESI work

Classification: false-positive

Evidence:
- `crates/fcp-raptorq/src/codec/rfc6330.rs:301-349` computes RFC tuple parameters from an ESI using bounded arithmetic.
- `crates/fcp-raptorq/src/codec/rfc6330.rs:380-404` emits tuple indices with capacity bounded by tuple degree.
- `crates/fcp-raptorq/src/codec/rfc6330.rs:712-721` tests degree buckets and pins max LT degree at 30.

Result: large ESI values do not create unbounded equation width in the inspected tuple path.

### fcp-tailscale peer identity validation

Classification: false-positive

Evidence:
- `crates/fcp-tailscale/src/client.rs:93-105` validates every peer-map key and embedded peer ID.
- `crates/fcp-tailscale/src/client.rs:113-127` constructs the peer map only after key/embedded ID validation.
- `crates/fcp-tailscale/src/client.rs:2518-2605` tests rejection for mismatched peer IDs and distinct peer entries aliasing the same canonical node ID.

Result: the inspected LocalAPI status conversion rejects peer-map spoofing/aliasing.

### fcp-tailscale tag-to-zone canonicalization

Classification: false-positive

Evidence:
- `crates/fcp-tailscale/src/tag.rs:206-213` converts FCP tags to zones only if the derived zone ID is valid.
- `crates/fcp-tailscale/src/tag.rs:232-251` rejects empty suffixes, reserved `proj-` collisions, uppercase, underscores, colons, and leading/trailing hyphens.
- `crates/fcp-tailscale/src/tag.rs:875-991` pins prefix-only tags like `tag:fcp-` as non-zones through `tag_to_zone`.

Result: prefix-only FCP tags can still be represented as raw tags, but canonical tag-to-zone conversion rejects them. The confirmed bug was the missing attestation verification before surfacing tags.

### fcp-bootstrap hardware-token verification and certificate selection

Classification: false-positive

Evidence:
- `crates/fcp-bootstrap/src/workflow.rs:619-648` requires a non-empty PIN, authenticates the selected token, then enumerates provisioning material.
- `crates/fcp-bootstrap/src/hardware_token.rs:1218-1283` builds an indexed certificate/key/issuer view instead of rescanning adversarial lists.
- `crates/fcp-bootstrap/src/hardware_token.rs:1305-1328` skips CA certs, empty CKA_IDs, non-matching keys, non-owner signing keys, CA leaves, and missing verified issuer chains.
- `crates/fcp-bootstrap/src/hardware_token.rs:1420-1461` verifies CA/self-signed roots, issuer signatures, and key-cert-sign constraints.
- `crates/fcp-bootstrap/src/hardware_token.rs:1467-1499` enforces validity windows, CA basic constraints, and key usage parsing.
- `crates/fcp-bootstrap/src/hardware_token.rs:3673-4148` has regression coverage for empty PIN, no certs/keys, no matching pair, non-compatible keys, deterministic tie-breaks, missing chain, expired/not-yet-valid leaves and CAs, non-CA issuer metadata, DER CA leaf mismatch, and CA issuer without `keyCertSign`.

Result: no certificate-selection bypass was found in the inspected hardware-token path.

### fcp-bootstrap soft-token harness invariants

Classification: false-positive

Evidence:
- `crates/fcp-bootstrap/src/soft_token.rs:208-232` materializes deterministic soft-token identities and implicit CA certificates from config.
- `crates/fcp-bootstrap/src/soft_token.rs:266-289` rejects empty/wrong PINs and mismatched token selectors.
- `crates/fcp-bootstrap/src/soft_token.rs:312-324` enumerates certs only after token/PIN validation.
- `crates/fcp-bootstrap/src/soft_token.rs:421-423` derives deterministic CKA_IDs from public key material, and the tests around `crates/fcp-bootstrap/src/soft_token.rs:635-693` pin deterministic identity and distinct-ID behavior.

Result: the soft-token harness is deterministic and exercises the same selection constraints; no current harness invariant bypass was found.
