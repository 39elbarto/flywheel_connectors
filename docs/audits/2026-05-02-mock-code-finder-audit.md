# /mock-code-finder audit — 2026-05-02

**Auditor:** AmberLark.
**Scope:** All Rust source under `crates/` (production + test).
**Trigger:** User invocation after the kyopb.1.3.* + dja9u close-out wave.

## Summary

**Zero category (b) findings.** Every stub / placeholder / mock / "not yet
implemented" hit in production source code resolves to one of the
acceptable patterns enumerated in §3 below. Three category (a)
follow-up beads filed for intentional stubs that lacked a tracking
bead.

| Category | Count | Disposition |
| -------- | ----: | ----------- |
| (a) Intentional stubs needing follow-up bead | 3 | Beads filed (§4) |
| (b) Actual fake-code that should be deleted | 0 | None — codebase is clean |
| Already-tracked sentinels with bead reference | many | Verified existing beads (§3.1) |
| `#[cfg(test)]`-gated mocks / dummies | many | Verified test-only (§3.2) |
| Enum naming / CLI text / domain separators | many | Verified design intent (§3.3) |

## 1. Audit method

Five `ripgrep` sweeps across `crates/`:

1. `rg -n 'todo!\(|unimplemented!\('` — macro-level placeholders
2. `rg -n 'FIXME|XXX'` — informal markers
3. `rg -n 'TODO\b'` — TODO comments
4. `rg -n 'panic!\("not yet|panic!\("not implem|panic!\("stub'` — panic stubs
5. `rg -n '\bstub\b|\bplaceholder\b|\bmock\b|\bfake\b|\bdummy\b'` (production only)
6. `rg -n 'not yet wired|not yet implemented|not yet supported'` — design comments
7. `rg -n 'NotImplemented \{|NotImplemented,'` — sentinel-error returns

Each result was inspected in context. Findings classified as one of:

- **CATEGORY-A** — production stub return that needs a follow-up bead
- **CATEGORY-B** — fake-code to delete with explicit user authorization
- **TEST-FIXTURE** — `#[cfg(test)]` or inside a `#[test]` fn
- **DESIGN-INTENT** — enum variant / CLI help / domain separator / etc.
- **TRACKED-SENTINEL** — typed error variant with existing open bead

## 2. Macro-level results (sweeps 1, 2, 4)

**`todo!()` / `unimplemented!()`:** 8 hits. All non-issues:

- `crates/fwc/src/new_cmd.rs:8332-8335,8356` — STRINGS inside the
  scaffold's own stub-finder regex.
- `crates/fcp-core/tests/ui/*.rs` (3 files) — trybuild compile-fail
  tests use `unimplemented!()` to construct phantom-typed values for
  the compiler's type-error check; the code is never executed.

**`FIXME` / `XXX`:** 8 hits. All non-issues (test fixtures, doc
examples like "FCP-XXXX", strings inside the stub-finder regex).

**`panic!("not yet|stub|implem"`:** 0 hits.

**`TODO` comments:** 25 hits. 3 real (all annotated):

- `crates/fcp-core/src/object.rs:216` — `TODO(review)` code-quality
  hint about deriving `PartialEq`. Not a stub.
- `crates/fcp-prelude/src/lib.rs:49` — module doc reference to a
  one-line config flip pattern. Not a stub.
- `crates/fcp-host/src/bin/fcp-host.rs:4091` — `TODO(review)` with
  bead reference. Tracked.

The other 22 `TODO` hits are inside `crates/fwc/src/new_cmd.rs` —
either string-literal templates that get copy-pasted into NEW
connector source (instructional hints, gated by the test at
new_cmd.rs:8428 that freezes the total count), or strings inside the
stub-finder regex itself.

## 3. Production `stub` / `placeholder` / `mock` results (sweep 5)

### 3.1 Tracked sentinels (existing or newly filed beads)

| File:line | Sentinel | Bead | Status |
| --------- | -------- | ---- | ------ |
| `fcp-crypto-pq/src/lib.rs:384` `sample_pre` returns `NotImplemented` | `LatticePqError::NotImplemented` | kyopb.1.3.1.1 | Filed today |
| `fcp-crypto-pq/src/lib.rs:428` `verify` returns `NotImplemented` | (same) | kyopb.1.3.1.1 | Filed today |
| `fcp-crypto-pq/src/lib.rs:272,331` `trap_gen` / `delegate` BLAKE3-placeholder bodies | (same) | kyopb.1.3.1.1 | Filed today |
| `fcp-crypto/src/xwing.rs:606` `XWingStub` returning sentinel `HpkeFailed` | `CryptoError::HpkeFailed` | kyopb.1.2.x | Multiple subbeads, .4 still open |
| `fcp-bootstrap/src/workflow.rs:669` `HardwareTokenEnrollmentNotImplemented` | typed `BootstrapError` variant | nh2xl (closed); 24llg.4.x chain consumes it | Tracked |
| `fcp-policy/src/lattice_delegation.rs:295` `UnimplementedLatticeDelegationVerifier` | `LatticeDelegationError::NotImplemented` | kyopb.1.3.2 (closed) — `LatticeDelegationVerifierImpl` is now the production type; Unimplemented kept as the no-trust-set sentinel | OK |
| `fcp-sandbox/src/windows.rs:5-27` AppContainer / integrity / firewall layers "roadmap, not yet wired" | `FilterStrength::ProcessLimit` only | r4qcg (was 459lp) | Filed today |

### 3.2 `#[cfg(test)]` / test-fn-gated mocks (sample)

All passed inspection — confirmed test-only:

- `fcp-bootstrap/src/hardware_token.rs:1885` — `#[cfg(test)] pub mod mock { MockTokenProvider }`
- `fcp-sandbox/src/egress.rs:2036-2050` — `MockInjector` inside `#[test]` block
- `fcp-registry/src/lib.rs:5293, 11679` — `#[test] fn mock_registry_*` test names
- `fcp-e2e/src/lib.rs:1330` — `struct DummyConnector` inside `mod tests {}`
- `fcp-core/src/provenance.rs:2255-2328` — `test_object_id("fake-receipt")` test fixtures

### 3.3 Design-intent naming (sample)

All passed inspection — confirmed deliberate:

- `fcp-manifest/src/lib.rs:890` — `ConnectorStatus::Stub` enum variant (legitimate manifest status value).
- `fwc/src/main.rs:6707, 9870, 15975` — CLI `--include-hidden` help text describing connector statuses.
- `fwc/src/catalog.rs:1786, 1870, etc.` — `PackageArtifactSource::StubPlaceholder` variant (rejected at install time as unfit-for-runtime).
- `fwc/src/readiness.rs:524-545` — `CommandAvailability::Planned` variant (produces "contract preview" output rather than a real result; documented enum state).
- `fcp-google-discovery/src/executor.rs:660,670` — User-facing error messages naming "empty placeholder" inputs.
- `fcp-manifest/src/lib.rs:2835+` (~25 hits) — Test-fixture `let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));` for an all-zeros interface hash.
- `fcp-crypto-pq/src/lib.rs:272,331` — `b"trap_gen-stub-v0|"` / `b"delegate-stub-v0|"` are versioned BLAKE3 domain separators in the stub primitives' hash inputs (NOT the stub-ness itself; the *domain separator* will need to be re-versioned when the real primitive lands per kyopb.1.3.1.1, but that's expected).

## 4. Filed follow-up beads

Three filed today (2026-05-02) by this audit:

### 4.1 `kyopb.1.3.1.1` (P2) — fcp-crypto-pq lattice arithmetic

Replace the by-design stubs landed in commit 9a02326d2 with real
Micciancio-Peikert TrapGen / Cash-Hofheinz-Kiltz-Peikert basis-
shortening / Gentry-Peikert-Vaikuntanathan SamplePre. The kyopb.1.3
design+wiring+proof+bench cycle is now complete; this bead is the
ONLY remaining piece for end-to-end V4 capability verification.
Acceptance includes re-running the throughput benchmark and
augmenting the Lean 4 soundness theorem with the SIS-reduction
half. ~3-4 weeks of research-grade work.

### 4.2 `dja9u.1` (P2) — Migrate 29 connectors off legacy `verifier.verify()`

Drop the `LEGACY_VERIFY_ALLOWLIST` from 29 → 0 by migrating each
listed connector to `verifier.verify_bound(...)`. Recommended PR
shape: 5-6 sub-beads of ~5 connectors each so each diff stays
reviewable. Goal end-state: all 78 production connectors take the
typestate-enforced path. ~5h per connector × 29 = ~100h total.

### 4.3 `r4qcg` (P3) — Windows sandbox AppContainer + integrity-level enforcement

Wire AppContainer / integrity-level enforcement / firewall rules to
upgrade Windows sandbox from `FilterStrength::ProcessLimit` to
`FilterStrength::ProfileLevel`. Three layers (one per win32 surface).
~2-3 weeks. Existing mitigation today: connectors requiring strict
profile MUST run under `WasiRuntime`. Updated the windows.rs
docstring to point at the correct (newly-filed) bead id.

## 5. Why so few findings

The codebase already enforces the discipline this audit was looking
for, via three cumulative practices observed:

1. **Typed sentinel errors over magic returns.** Every "not yet
   implemented" surface returns a NAMED error variant
   (`LatticePqError::NotImplemented { primitive, bead }`,
   `BootstrapError::HardwareTokenEnrollmentNotImplemented`,
   `LatticeDelegationError::NotImplemented`). Callers can match on the
   variant; downstream dispatch can route to fall-back paths
   deterministically. Substring-matching error messages is never
   required.
2. **Bead reference in code comments.** Every intentional stub names
   the responsible follow-up bead in its docstring or adjacent
   comment. The audit's grep + cross-check against `br list`
   confirmed each was accounted for (only 3 had drifted out of the
   open-bead set, all now re-filed).
3. **`#[cfg(test)]` discipline.** Every mock / fake / dummy / test-
   helper is test-gated. Production callers literally cannot link
   against them.

## 6. Recommendations

1. **Repeat this audit quarterly** (or after every major epic close).
   The 3 stale references found today were all from older beads
   whose tracking links rotted; a 90-day cadence catches drift before
   it accumulates.
2. **Add a CI check** for typed-sentinel discipline: any new
   `unimplemented!()` / `todo!()` macro in `src/` (excluding
   `tests/ui/`) should fail the build. Could land as part of the
   existing `crates/fwc/src/new_cmd.rs:8428` total-TODO ratchet
   pattern.
3. **The `fcp-crypto-pq` BLAKE3-placeholder bodies in `trap_gen` /
   `delegate` are technically more dangerous than `NotImplemented`:**
   they return `Ok(...)` with bytes that LOOK like cryptographic
   material but aren't. `kyopb.1.3.1.1` closing this gap is the
   highest-leverage cleanup of the three filed beads.

## 7. Provenance

- Audit run: 2026-05-02 by AmberLark via `/mock-code-finder` user
  invocation.
- Beads filed: kyopb.1.3.1.1 (P2), dja9u.1 (P2), r4qcg (P3).
- Code edits: 1 line touched in `crates/fcp-sandbox/src/windows.rs`
  (corrected the bead-id reference).
- No production code stubs were deleted by this audit (none found
  that warranted deletion).
