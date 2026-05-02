# Security Audit For SaaS - Epsilon Domain Sweep - 2026-05-02

Agent: GoldenFinch

Scope:
- `crates/fcp-sandbox`
- `crates/fcp-manifest`
- `crates/fcp-registry`
- `crates/fcp-audit`
- `crates/fcp-ratelimit`
- `crates/fcp-telemetry`

Review goals: auth bypass via empty/null tokens, signature verification ordering, replay defense, sandbox escape paths, manifest schema drift, registry path traversal, audit log tampering surface, ratelimit bypass via clock skew, and telemetry data exposure.

## Result Summary

- Confirmed vulnerabilities: 0
- Hardening findings filed: 4
- False positives / no-current-exploit findings: 7
- Highest-priority confirmed vulnerability patched: not applicable because no confirmed vulnerabilities were found.

## Findings Filed

| Bead | Classification | Summary |
| --- | --- | --- |
| `flywheel_connectors-0lc3s` | hardening-worth-doing | `fcp-sandbox` egress silently skips malformed `cidr_deny` entries when constraints are built directly rather than manifest-validated. |
| `flywheel_connectors-n781d` | hardening-worth-doing | `CredentialInjector::is_host_allowed` defaults to allow-all at the credential host-binding boundary. |
| `flywheel_connectors-eah6j` | hardening-worth-doing | `fcp-audit::verify_chain` is integrity-only, accepts empty/no-head chains as clean, and needs a strict production verifier entrypoint. |
| `flywheel_connectors-lmp9l` | hardening-worth-doing | Mesh trace capture exposes unredacted snapshot/export paths that can leak session and object identifiers once capture is enabled. |

## Evidence Detail

### fcp-sandbox malformed cidr_deny skip

Classification: hardening-worth-doing

Evidence:
- `crates/fcp-sandbox/src/egress.rs:755-769` parses `NetworkConstraints.cidr_deny` entries but logs and skips parse errors.
- `crates/fcp-sandbox/src/wasi.rs:279-283` accepts raw `NetworkConstraints` through `WasiConfig::with_network_constraints` without a validation hook.
- `crates/fcp-manifest/src/lib.rs:2285-2290` rejects malformed CIDR only for manifest-validated constraints.

Attack scenario: a production or integration caller that constructs or deserializes `NetworkConstraints` directly can intend to deny an SSRF/exfiltration range but pass a malformed CIDR. The egress guard treats that malformed deny as absent. Manifest-sourced constraints are safe, so this is hardening rather than a confirmed production bypass.

### fcp-sandbox credential host binding default

Classification: hardening-worth-doing

Evidence:
- `crates/fcp-sandbox/src/egress.rs:415-436` authorizes a requested credential, checks `injector.is_host_allowed`, and then injects HTTP credentials.
- `crates/fcp-sandbox/src/egress.rs:475-486` performs the same host check before returning TCP auth bytes.
- `crates/fcp-sandbox/src/egress.rs:875-880` provides a default `CredentialInjector::is_host_allowed` implementation that returns allow-all.

Attack scenario: a future production credential backend can implement authorization and injection but forget to override host binding. If the manifest network policy allows a wildcard or broad SaaS host set, a connector with credential access can direct that credential to another policy-allowed host. No non-test injector implementation was found in the audited crates, so this is hardening.

### fcp-audit strict verifier gap

Classification: hardening-worth-doing

Evidence:
- `crates/fcp-audit/src/lib.rs:1540-1555` documents `verify_chain` as integrity-only and not authenticating `issuer_kid` or signatures.
- `crates/fcp-audit/src/lib.rs:1605-1616` returns `VerifyReport::ok(0)` for an empty chain when no `ChainHead` is supplied.
- `crates/fcp-audit/src/lib.rs:4079-4085` pins `verify_chain(&[], None, None)` as clean.
- `crates/fcp-audit/src/lib.rs:1878-1930` provides `verify_chain_with_signers`, but callers must opt in and can still omit a head.

Attack scenario: an operator/status path that treats a clean `VerifyReport` as proof of audit health can be fed an empty chain with no head, or an unsigned internally linked chain, and receive OK. This is not currently wired into an authorization decision in the epsilon sweep, so this is hardening.

### fcp-telemetry unredacted trace export

Classification: hardening-worth-doing

Evidence:
- `crates/fcp-telemetry/src/trace_capture.rs:337-345` stores `SessionEvent.session_id` in captured traces.
- `crates/fcp-telemetry/src/trace_capture.rs:356-364` redacts `session_id` only when a redaction policy is applied.
- `crates/fcp-telemetry/src/trace_capture.rs:746-755` exposes both `snapshot()` and `redacted_snapshot()`.
- `crates/fcp-telemetry/src/trace_capture.rs:763-778` and `crates/fcp-mesh/src/node.rs:2268-2279` let callers export with `redacted=false`.
- `crates/fcp-mesh/src/node.rs:2250-2259` exposes both trace snapshot methods.

Attack scenario: trace capture is disabled by default, but incident or operator workflows can enable it and export unredacted session IDs, object IDs, node IDs, and policy evidence. This is a data exposure hardening issue, not a confirmed externally reachable leak.

## False Positives And No-Current-Exploit Results

### Ratelimit bypass via clock skew

Classification: false-positive

Evidence:
- `crates/fcp-ratelimit/src/token_bucket.rs:33,57,99,129,136,212` uses `std::time::Instant` and `saturating_duration_since` for refill and wait calculations.
- `crates/fcp-ratelimit/src/sliding_window.rs:34,49-63,73,117,144` uses `Instant` for window state and retry timing.
- `crates/fcp-ratelimit/src/fcp.rs:255-260` uses wall-clock time only to stamp `ThrottleViolation`, not for allow/deny decisions.

Result: clock skew does not currently bypass the token bucket or sliding window paths inspected.

### Manifest schema drift

Classification: false-positive

Evidence:
- `crates/fcp-manifest/src/lib.rs:91-132` defines `ConnectorManifest` with `#[serde(deny_unknown_fields)]`, and `parse_str` validates after parsing.
- `crates/fcp-manifest/src/lib.rs:2175-2208` also denies unknown fields in `NetworkConstraints`.
- `crates/fcp-manifest/src/lib.rs:8197-8202` tests unknown-field rejection.

Result: unknown manifest fields are rejected in the audited manifest parser path.

### Registry path traversal

Classification: false-positive

Evidence:
- `crates/fcp-registry/src/lib.rs:2621-2635` rejects parent, root, prefix, and absolute components in `signature.binary_name`.
- `crates/fcp-registry/src/lib.rs:2637-2659` rejects symlinks, non-files, and hardlinks.
- `crates/fcp-registry/src/lib.rs:2660-2684` requires the canonical binary path to remain under the canonical package directory.
- `crates/fcp-registry/src/lib.rs:2685-2705` reads the canonical path and enforces the expected binary hash.

Result: the signed package loader has explicit traversal and link defenses on the audited path.

### Registry signature verification ordering

Classification: false-positive

Evidence:
- `crates/fcp-registry/src/lib.rs:1542-1605` parses the manifest, checks the expected target, computes hashes and signing bytes, requires signatures, and enforces trusted signatures before capability and supply-chain verification.
- `crates/fcp-registry/src/lib.rs:2147-2171` verifies signature entries against context-specific signing bytes.
- `crates/fcp-registry/src/lib.rs:2717-2737` verifies detached package signatures before returning signed package records.

Result: no signature-ordering bypass was found in the inspected registry verification paths.

### Sandbox filesystem escape

Classification: false-positive

Evidence:
- `crates/fcp-sandbox/src/wasi.rs:331-408` canonicalizes allowed paths and request paths, resolves missing writes through an existing ancestor, and denies reads whose canonical targets are absent.
- `crates/fcp-sandbox/src/wasi.rs:421-570` denies network operations without policy and requires constraints for HTTP, TCP, and credential-aware calls.
- `crates/fcp-sandbox/src/wasi.rs:870-940` keeps raw socket checks IP-bound and rejects hostname-only policies at the raw socket layer.

Result: the inspected filesystem and raw socket paths do not show a current sandbox escape.

### Empty/null token auth bypass

Classification: false-positive

Evidence:
- The epsilon-domain uses of token-like evidence found in `fcp-audit` are causal explanation inputs, not authorization gates.
- No epsilon-domain production verifier path was found that accepts empty/null tokens as authorization success.

Result: no empty/null token auth bypass was confirmed in this scoped sweep.

### Replay defense

Classification: false-positive

Evidence:
- `crates/fcp-audit/src/lib.rs:1946-1956` verifies chain timing against the supplied clock and emits future-timestamp errors.
- The surrounding audit-chain verifier checks sequence, previous hash, current hash, and optional head consistency.
- Registry TUF verification checks trusted root pinning, expiration, rollback, target length, and target hashes before accepting update metadata.

Result: no replay bypass was confirmed in the scoped epsilon paths. The stricter signed-head audit verifier remains worth doing as a hardening bead because integrity-only verification can be misused by future production callers.
