# /review-mode audit — alpha-domain commit wave + cross-pollinate · 2026-05-02

**Auditor:** AmberLark.
**Skill:** Critical-reviewer mode.
**Scope:** 8 alpha-domain commits I authored this session + 3 cross-domain
commits the user flagged for cross-pollinate review.

## Summary

| Commit | Domain | Verdict |
| ------ | ------ | ------- |
| `c9f495544` 28nms UpgradedLatestPointer audit | alpha | **clean** |
| `cbac9cd4e` utiw3 lock-hold tracing | alpha | **doc minor only** (§5) |
| `51220ccf3` v2kt4 fail-closed flag | alpha | **DEFECT — bead `l9tt6` (P2 race)** |
| `18577d6d1` jhbk1 silent-bypass closure | alpha | **clean** |
| `b403b51b4` gtplu V3-deprecation observability | alpha | **DEFECT — bead `vkb3m` (P3 coverage gap)** |
| `540145cb7` e2e tests | alpha | **clean** (no production code) |
| `749e7a263` fuzz harnesses | alpha | **clean** (no production code) |
| `29f803b8a` golden artifacts | alpha | **clean** (no production code) |
| `1c24e6c25` InvokeAuditChain concurrent append | beta cross | **DEFECT — bead `1a73y` (P3 wrong error variant)** |
| `cf325f358` IndexedZoneKeyManifest | beta cross | **clean as-shipped, but feeds into `vkb3m` finding** |
| `824d3ffd6` canonicalize_map arena | gamma cross | **clean** |

**Headline:** 3 confirmed defects across 11 commits, 1 minor doc issue.
The most material is `l9tt6` (P2): a TOCTOU window in v2kt4's
fail-closed flag that can produce a fail-OPEN during admin updates.

## 1. Audit method

For each commit:

1. Read the diff in full (`git show <sha> -- <file>`).
2. Understand WHY the change is correct.
3. Check the seven defect categories the user enumerated:
   - (a) missing test coverage of edge cases the change introduces
   - (b) silently-swallowed errors that should typed-error
   - (c) public API breaking changes that aren't documented
   - (d) lock-ordering risks introduced by the new code
   - (e) places where Result is unwrap()ped or expect()ed in production
   - (f) places where Rc/RefCell could panic
   - (g) async cancellation safety
4. File a bead via `br create` for any GENUINE defect — no leniency.

## 2. Confirmed defects (3, beads filed)

### `l9tt6` — v2kt4 TOCTOU race (P2)

**Commit:** `51220ccf3`. **Category:** (d) lock-ordering risk + indirect
fail-open.

The two gates added by v2kt4 perform TWO separate
`state.read().await` acquisitions per request — one for the allow-list
snapshot, one for the `enforce_empty_allow_lists` flag. Between them
a writer holding the write lock briefly can interleave a config
update. The decision then mixes a STALE allow-list with a FRESH
flag.

**Fail-OPEN scenario:** initial state
`allowed_zones=['z:work'], enforce=false`. Operator updates to
`allowed_zones=[], enforce=true` (deny-all). Race window: request
reads `allowed=['z:work']` (stale) + `enforce=true` (fresh). Falls
into `else if !allowed.iter().any(...)` branch with the OLD list. If
the request's zone is `z:work`, the request is ALLOWED — but the
operator's NEW intent is deny-all. The fail-closed mechanism the
bead set out to provide silently bypasses during in-flight config
updates.

**Recommended fix:** add a registry helper that returns
`(allowed_zones, allowed_operations, enforce_empty)` under a SINGLE
read-lock acquisition. Each gate calls the helper once; the snapshot
is internally consistent.

**Severity P2** (not P1) because exploitability requires precise
timing on the boundary of an admin-state update; admin updates are
infrequent and the operator gets explicit feedback per request.

### `vkb3m` — gtplu missed `IndexedZoneKeyManifest` hot path (P3)

**Commit:** `b403b51b4`, with the missing-extension surface added in
`cf325f358`. **Category:** (a) missing test coverage of an edge case
the type-system surface introduces.

`gtplu` added `ZoneKeyManifest::resolved_wrapped_key_observable_for`
returning the `ResolvedWrappedKey { V4, V3Fallback }` enum. The
linear-scan path is observable. But `cf325f358` introduced
`IndexedZoneKeyManifest` (the O(1) production hot-path optimisation)
with its own `resolved_wrapped_key_for` at zone_keys.rs:898 — and
gtplu did NOT extend the observable variant to the indexed type.

The O(1) hot path is the one most likely to fire under load — the
exact path the V3-deprecation cutover gate needs evidence from. The
observable variant lives only on the slow-path linear scan that
production callers will increasingly stop using.

**Recommended fix:** add
`IndexedZoneKeyManifest::resolved_wrapped_key_observable_for`
mirroring the linear-scan implementation. Have the legacy method
delegate to it + strip the tag (same back-compat shape as the linear-
scan resolver). Pin with 3 unit tests in
`zone_key_manifest_indexed_lookup.rs` (V3-only, V4-only,
interop-both recipients).

**Severity P3** because the linear-scan path is still observable and
the indexed variant is the optimisation; production callers can
fall back temporarily.

### `1a73y` — InvokeAuditChain CAS exhaustion uses wrong error variant (P3)

**Commit:** `1c24e6c25`. **Category:** (b) silently-swallowed errors
that should typed-error correctly.

The br-uwlj5 optimistic-CAS retry loop bounds attempts at 64 to
defend against pathological retry storms. When the bound is exceeded
the function returns `AuditError::SerializationError("invoke audit
append: 64 CAS retries exhausted under same-zone contention")`.

The actual problem is per-zone CONTENTION, not a serialization
failure. `AuditError::SerializationError` is the variant the file
uses for ciborium / canonical-CBOR encoding errors. An operator
looking at audit-trail telemetry sees `SerializationError` and
investigates CBOR encoding bugs when the real fix is to lift the
per-zone contention budget or scale-out per-shard.

**Recommended fix:** add `AuditError::ContentionExhausted { zone_id,
attempts }` variant. Update the bail to use it. Pin with a
contention-storm regression test.

**Severity P3** because the bail itself is correct (no panic, no
chain corruption); the bug is operator-misleading taxonomy.

## 3. Clean commits (no defect found)

### `c9f495544` 28nms UpgradedLatestPointer audit

The structured `tracing::warn!` is correctly emitted at the upgrade
detection site. Reason field distinguishes legitimate-V1-upgrade
from attack-signal-replay. `#[cfg(test)]` capture sink is
production-safe. No log spam (loop iterates over mesh_count, not
pointer_count). No panic surface. Clean.

### `18577d6d1` jhbk1 silent-bypass closure

The fix correctly distinguishes "verifier missing + token claims
hybrid-owner governance" (fail closed) from "verifier missing + no
hybrid-owner intent" (legacy V3-only path). The `?` propagation on
`hybrid_owner_invoke_evidence(request)?` could surface a malformed-
tag decode error rather than the unconfigured-verifier error, but
both outcomes are rejections, and the decode error doesn't leak
information about verifier configuration state (the same error fires
either way). Clean.

### `540145cb7` e2e tests, `749e7a263` fuzz harnesses, `29f803b8a` golden artifacts

Test-only commits; no production code paths affected. Goldens use
deterministic Ed25519 fixtures + fixed UUIDs + fixed datetimes —
reproducible. Fuzz harnesses use `proptest` defaults; the `panic::
catch_unwind` wrapping in the host fuzz correctly captures any
allocator-abort or decoder panic. Tracing subscribers are per-test
scoped. Clean.

### `cf325f358` IndexedZoneKeyManifest

The new indexed type is a clean O(1) optimisation of the linear-scan
manifest. Constructor builds the index once + holds it for the
manifest's lifetime. The O(1) variant is correctly equivalent to the
linear scan (same precedence, same fallback). Clean as-shipped — but
this commit is what created the surface that gtplu missed. Filed
under `vkb3m` rather than against this commit.

### `824d3ffd6` canonicalize_map arena

The arena-based sort comparator is a clean perf optimisation. Same
RFC 8949 §4.2.1 lex order, same duplicate-detection semantics, same
canonical CBOR output bytes (golden-vector tests pin this). Pass 5's
`taken[i].take().expect(...)` is defensible: the panic path is
genuinely unreachable because `sort_idx = (0..n).collect()` followed
by `sort_by` preserves the index set, so each index appears exactly
once. Clean.

## 4. Doc-only minor finding (not bead-worthy alone)

### `cbac9cd4e` utiw3 — lock-monitor doc comment vs code mismatch

The `HandshakenZoneLockHoldMonitor` is declared at line 396, AFTER
the `handshaken_zone` lock guard at line 395. Rust drops locals in
REVERSE declaration order, so on function exit:

1. `_lock_hold_monitor` drops first (RAII Drop fires).
2. `handshaken_zone` (the MutexGuard) drops second (lock released).

The doc comment on the monitor struct says "lives on the stack
ABOVE the lock guard" — which is BACKWARDS in source order (it's
declared BELOW, dropped BEFORE). The functional behaviour is correct
(monitor's elapsed-time measurement excludes the negligible
MutexGuard::drop cost), but the doc comment misleads any future
maintainer reading it.

If the monitor were declared BEFORE the lock acquisition, its Drop
would fire AFTER the lock release and capture a more accurate
hold-time measurement. For an async Mutex (asupersync) the drop cost
is essentially zero, so this is a wash functionally.

Recommended cleanup: either re-order so the monitor IS declared
before the lock (and update the comment), or fix the comment to
state "declared after the lock guard, which means it drops BEFORE
the lock release." Not bead-worthy on its own but worth fixing in
the next host-binary touch.

## 5. Pre-existing observations not in scope

These showed up during the audit but pre-date the commit wave:

- **`fcp-host` and `fcp-streaming` placeholder benches** — both
  were patched (mine + cod's) but the placeholders themselves still
  carry "replace with real Criterion harness" notes. Not regressions
  from this wave; tracked in commit messages.

- **`proptest` filter mismatch** — the user's recurring
  `cargo test ... proptest` and `cargo test ... golden` filter
  patterns substring-match function names; my naming convention uses
  schema-type prefixes, requiring `--test '<binary>_*'` instead.
  Documented in the corresponding commit messages. Pure UX naming
  drift, no defect.

## 6. Recommendations for the next review pass

1. **Repeat after the next ratchet-style epic** (e.g. when the
   remaining 24 dja9u.1 connectors land per-batch). Per-batch reviews
   surface coverage gaps that big-bang reviews miss.
2. **Add a `clippy` lint pass for the `state.read().await` x2
   pattern.** A custom `dylint` over alpha crates that flags any
   function with two `state.read().await` calls without an
   intervening `.await` boundary that could justify the split would
   catch `l9tt6`-shaped regressions automatically. Cheap to implement
   given the alpha tree's small RwLock surface.
3. **`AuditError` variant taxonomy needs a sweep.** The
   `1a73y` finding is one specific case; a broader sweep of
   `AuditError` call sites (looking for "X is reported as Y but the
   real cause is Z") could surface other operator-misleading
   classifications. Out of scope for this audit.

## 7. Provenance

- Audit run: 2026-05-02 by AmberLark via /review-mode user invocation.
- Beads filed: `vkb3m` (P3 alpha gtplu coverage gap), `l9tt6` (P2
  alpha v2kt4 race), `1a73y` (P3 cross InvokeAuditChain error
  taxonomy).
- `br sync --flush-only --force` ran between each bead create per
  the SOP from prior memos.
- Other agents (sfuk9 SilverFox, dgbtx CrimsonWolf) hold the only
  active claims; this audit explicitly did NOT claim+fix per the
  user's "we'll dispatch separate fix-agents" instruction.
- No code edits this round per audit-only protocol.
