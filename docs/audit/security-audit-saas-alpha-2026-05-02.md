# Security Audit · Alpha Domain (fcp-policy / fcp-host / fcp-mesh) · 2026-05-02

**Auditor:** AmberLark.
**Skill:** `/security-audit-for-saas`.
**Scope:** `fcp-policy/src`, `fcp-host/src` (including
`bin/fcp-host.rs`), `fcp-mesh/src`.
**Trigger:** Followup to CrimsonWolf's beta sweep
(`docs/audit/security-audit-saas-beta-2026-05-02.md`) which covered
the post-quantum stack (`fcp-core`, `fcp-protocol`, `fcp-cbor`,
`fcp-crypto`, `fcp-crypto-pq`, `fcp-{store,evidence}::compatibility_ledger`).
This audit complements that work by scanning the alpha-domain
authorization, request-routing, and lock-handling surfaces.

## Focus areas reviewed

- (a) **Auth bypass via empty/null/missing fields** —
  `#[serde(default)]` defaults, `Option<T>::None` semantics, empty-
  vec / empty-set treated as authoritative.
- (b) **Lock-ordering risks** — already covered in the
  `/deadlock-finder-and-fixer` sweep
  (`docs/audit/deadlock-finder-2026-05-02.md`); skipped here to avoid
  duplication except where a lock interaction is also a security
  surface.
- (c) **Policy-evaluation order-dependence** — the
  `EnforcementCheckId` pipeline + the manual `verify_live_request`
  sequence; whether ordering is consistent across both surfaces.
- (d) **Mesh handshake replay defenses** — anti-replay window,
  nonce reuse prevention, sequence-number overflow.
- (e) **Host invoke-token validation paths** — every step of
  `verify_live_request` from connector binding through capability
  signature, revocation, deployment tier, holder-bound check, and
  persisted-token verification.

## Methodology

- Read `verify_live_request` (`crates/fcp-host/src/bin/fcp-host.rs:
  2894-3055`) line-by-line for each focus area, recording file:line
  evidence.
- For every `Option<T>` checked at a security boundary, traced the
  None-path to confirm it does not silently bypass the check.
- For every `Vec<T>::is_empty()` short-circuit, checked whether the
  empty case represents "no restriction" or "deny all" and whether
  the semantics are documented.
- Cross-checked the `EnforcementCheckId::*` match in
  `crates/fcp-host/src/enforcement.rs:2022-2039` against the manual
  call sequence in `verify_live_request`.
- Read `crates/fcp-mesh/src/session.rs` anti-replay primitives
  (lines 85-110, sequence overflow + recv window).
- Workspace-wide grep for `#[serde(default)]` (~219 hits across
  alpha) — surveyed but did not exhaustively audit since most are
  on optional fields with `skip_serializing_if`, not authority bits.

## Findings

### (a) Confirmed vulnerability — 1

#### `jhbk1` (P1) — `verify_live_hybrid_owner_capability` silently bypasses on missing config

**Location:** `crates/fcp-host/src/bin/fcp-host.rs:2414-2427`.

**The bug:** The function returns `Ok(())` at line 2418-2420 when
`state.hybrid_owner_verifier` is `None` — WITHOUT inspecting the
capability token to see whether the token CLAIMS to be hybrid-
owner-governed. The verifier is configured from the
`FCP_HOST_HYBRID_OWNER_CONTEXT_FILE` env var; if unset,
`resolve_hybrid_owner_production_verifier` (line 3732) returns
`Ok(None)`, and the entire hybrid-owner check becomes a no-op.

**Risk:** A host operator who deploys without setting
`FCP_HOST_HYBRID_OWNER_CONTEXT_FILE` will silently accept ALL invokes
regardless of whether the token requires hybrid-owner verification.
This bypasses the post-quantum V3-to-V4 owner-key migration check
on misconfiguration, with no startup signal to the operator.

**Why P1:** The check protects the post-quantum migration boundary
— any token claiming hybrid-owner governance is silently honored as
if it had passed verification. There's no startup warning when the
verifier is `None`. Operators have no signal that the gate is
disabled.

**Recommended fix:** Inspect token claims at the check entry; if
the token declares hybrid-owner governance (claim or evidence tag
present) AND the verifier is None, fail closed (mirror the holder-
bound fail-closed pattern at line 3044-3047). Plus a startup
`tracing::warn` when the env var is unset.

### (b) Hardening worth doing — 1

#### `v2kt4` (P3) — `allowed_zones` / `allowed_operations` empty-vec semantics inverted

**Location:** `crates/fcp-host/src/bin/fcp-host.rs:2914-2954` (the
gates) + 803-809 + 821-827 (the back-compat semantics docstrings).

**The pattern:**
```text
None (connector unknown) → NOT enforced.
Some(empty)              → NOT enforced (back-compat permissive).
Some(non-empty)          → enforced (only items in the list pass).
```

**Risk:** Defense-in-depth — primary auth gates (capability token
signature, revocation cascade, deployment tier) still run. But:
- An attacker who can WRITE to the host admin state could clear the
  allowed_X lists to empty and bypass the per-connector pinning the
  operator intended.
- A subtle config-mistake (e.g. automation that builds the connector
  entry without populating allowed_zones) silently reverts to
  permissive.
- The semantics are inverted: empty-list-means-unrestricted is the
  OPPOSITE of how most operators read "allowed list."

The doc at lines 803-809 and 821-827 explicitly describes this as
opt-in-fail-closed-when-non-empty back-compat. Behavior is
INTENTIONAL — but security ergonomics are inverted.

**Recommended fix:** Either replace `Vec<String>` with an explicit
`enum AllowList { Unrestricted, Restricted(Vec<String>) }`, or add
an `unrestricted: bool` sibling field on `ManagedConnectorConfig`
defaulting to false. Existing connector configs migrate to
`unrestricted=true` via a one-shot script + ratchet test similar to
dja9u; new configs must explicitly populate the lists or set the
flag.

### (c) False positives / already mitigated — not filed

#### `verify_live_request` ordering vs `EnforcementCheckId` pipeline

The manual sequence in `verify_live_request` (allowed_zones →
allowed_operations → CapabilityVerify → RevocationCascade →
hybrid_owner → DeploymentTier → HRW lease → HolderProof →
persisted_verify) does NOT exactly match the `EnforcementCheckId`
match-arm order in `enforcement.rs:2022-2039` (which lists 14
checks in a different sequence: CanonicalDecode, ZoneMembership,
CapabilityVerify, RevocationCascade, DeploymentTier, HolderProof,
CheckpointFreshness, RevocationFreshness, TaintApproval,
PolicyCeiling, CapabilityConstraints, ConnectorManifest, Budget,
RateLimit). A divergence test
(`crates/fcp-conformance/tests/enforcement_check_order_conformance.rs:38`)
was already failing per the deadlock-finder memo §2.5 due to a 15
vs 11 array-length mismatch — that's a build-time test failure
recorded elsewhere, not a security finding.

The relevant security observation is that `verify_live_request`'s
manual order PRESERVES the security-critical invariant: signature
verification (CapabilityVerify) happens BEFORE every authorization
check downstream. The order divergence is about WHERE convenience-
gates (allowed_zones etc.) sit relative to the canonical pipeline
— it does NOT introduce a TOCTOU between signature verification
and use.

#### Holder-bound capability tokens fail closed

Lines 3032-3047 explicitly REJECT all holder-bound tokens with a
clear error: "fcp-host does not yet verify holder_proof signatures
for live requests." Defensive — the path errors out rather than
silently allowing. Not a finding; this is the correct posture
until live holder-proof verification is wired (separate work,
tracked elsewhere).

#### Mesh session anti-replay

`crates/fcp-mesh/src/session.rs:91-104` implements anti-replay via
a recv window (`check_and_update`). Sequence-number overflow at
`u64::MAX` triggers an explicit panic with the message "FCP session
sequence number overflow: nonce reuse prevention" (line 95). At
typical send rates (~1 kHz), `u64::MAX` is reached after
~580 million years — practically unreachable. Anti-replay is
correctly implemented.

### (d) Auth bypass via empty/null/missing — not filed beyond `jhbk1` and `v2kt4`

`#[serde(default)]` was scanned across the alpha tree (~219 hits).
The vast majority are on optional metadata / collection fields
with `skip_serializing_if = "..."` patterns, not authority bits.
Spot-checked:

- `crates/fcp-host/src/admin_state.rs` — many optional fields
  (license, expires, notes, etc.) all have proper `skip_serializing_if`
  guards. None observed to be authority-flipping.
- `crates/fcp-mesh/src/gossip.rs:1277` — single `#[serde(default)]`
  on a non-authority field.
- `crates/fcp-host/src/emergency_revocation.rs:59,311` — two
  optional metadata fields with proper guards.

The two findings above (`jhbk1`, `v2kt4`) are the only auth-bypass-
via-empty-or-missing surfaces I found that warranted filing.

### (e) Skipped per audit instruction — already covered

Lock-ordering risks: covered by `/deadlock-finder-and-fixer` sweep
2026-05-02 (`docs/audit/deadlock-finder-2026-05-02.md`). One
audit-only bead `utiw3` was filed there; closed in commit
`cbac9cd4e` with a tracing-span observability landing.

## Action taken in this session

| Bead | Type | Severity | Action |
| ---- | ---- | -------: | ------ |
| `jhbk1` | (a) confirmed-vulnerability | P1 | Filed for fix in next host-binary touch. NO PATCH this round per audit-only protocol. |
| `v2kt4` | (b) hardening-worth-doing | P3 | Filed for design discussion on `AllowList` enum vs `unrestricted: bool` flag. NO PATCH this round. |

`br sync --flush-only --force` ran between each bead create after
the same import-race pattern observed in the
`/reality-check-for-project` audit; the force-flush is now standard
operating procedure for this audit shape.

## Files filed

- `flywheel_connectors-jhbk1` — verify_live_hybrid_owner_capability silent-bypass.
- `flywheel_connectors-v2kt4` — allowed_zones / allowed_operations empty-vec semantics.
- `docs/audit/security-audit-saas-alpha-2026-05-02.md` — this memo.

## Why this audit found `jhbk1` and CrimsonWolf's beta sweep didn't

The hybrid-owner verifier sits at the alpha/beta boundary: the
**verifier impl** lives in `fcp-evidence::compatibility_ledger`
(beta surface, audited by CrimsonWolf), but the **integration
point** that decides when to invoke it lives in `fcp-host/src/bin/
fcp-host.rs` (alpha surface). CrimsonWolf's beta sweep correctly
focused on the verifier's CORRECTNESS (signatures, replay, schema
validation); my alpha sweep caught the integration-point CONFIG
gap. Both are necessary — neither is sufficient alone.

This is exactly the alpha-vs-beta split the user described when
dispatching the two audits: "yours should target alpha." The
finding lives on the alpha side because the bypass is in the
host's wiring, not the verifier's logic.

## Recommendations

1. **Land `jhbk1` (P1) first.** A single-file change in fcp-host
   binary that adds (i) token-claim inspection at
   `verify_live_hybrid_owner_capability` entry and (ii) a startup
   warn when the env var is unset. ~50 lines of code + 3 tests.
2. **Discuss `v2kt4` (P3) with the operator-config team** before
   patching. The migration path (existing-configs-default-permissive
   → new-configs-default-deny) needs the same kind of ratchet test
   pattern dja9u uses, and it's worth a design doc round before
   implementation.
3. **For the next security audit on the alpha surface**, add a
   focus area: "config-time defaults that produce permissive
   runtime behavior." Both `jhbk1` and `v2kt4` exhibit the same
   shape — a missing config bit silently disables a security
   gate. The pattern is worth pinning down with a workspace-level
   regression test (similar to the `capability_typestate_connector_
   boundary_dja9u.rs` ratchet) that flags any new
   `Option<Verifier>::is_none() => Ok(())` short-circuit at a
   security boundary.
4. **Resolve the `enforcement_check_order_conformance.rs:38`
   build-time test failure** (15 vs 11 array length) before the
   next epic touches `EnforcementCheckId`. Currently surfaced in
   both this audit (§(c)) and the deadlock-finder memo as a
   pre-existing issue from another agent's work.

## Provenance

- Audit run: 2026-05-02 by AmberLark via `/security-audit-for-saas`
  user invocation. Cod was shipping `dja9u.1.d/e/f` + `gmak2` in
  parallel (not audited; out of scope).
- Beads filed: `jhbk1` (P1), `v2kt4` (P3) — both `[security-audit]
  [alpha]` tagged.
- `br sync --flush-only --force` between bead creates (concurrent-
  agent import races overwrote dirty flags; force-flush is SOP
  per the prior audit memo's process note).
- Beta-queue items (`1zlht`, `shbvv`) explicitly out of scope.
- No code edits this round per audit-only protocol.
