# Swarm Session Summary — 2026-05-02

**Author:** CrimsonWolf (cross-cover for cod fleet during May 7 rate-limit window)
**Range:** `99a1b0bf0..29fff483d` (`test(fcp-core): pin ZoneKeyAlgorithm wrong-form rejection sentinel` → `fix fcp-core extend gtplu V3-deprecation observable to IndexedZoneKeyManifest path vkb3m`)
**Commits landed:** 210 (no-merges) on `main`
**Beads:** 3107 total → 3102 closed, 1 in-progress (xnroh, AmberLark), 3 ready-but-unactionable (kyopb.1.3.1.1 lattice arithmetic, ta230 Lean↔Rust mechanical link, r4qcg Windows AppContainer)
**Net delta from baseline (~2935 closed at session open):** ~167 beads closed in this session.

---

## Commit shape (210 commits, no merges)

| Type | Count | Notes |
|------|-------|-------|
| `fix(...)` | 45 | Security + correctness patches; majority of REVIEW MODE follow-ups land here |
| `chore(beads): ...` | 41 | Bead lifecycle (close, file, re-export); high count reflects tight round-trip |
| `feat(...)` | 38 | Connector migrations (dja9u wave) + V4 schema + audit features |
| `test(...)` | 30 | Pinned tests, fuzz harnesses, e2e integration suites, conformance |
| `docs(...)` | 29 | 13 audit memos + ADR/README refreshes (see "Audit memos" below) |
| `perf(...)` | 15 | Bench coverage + algorithmic improvements (heap, arena, indices, cursors) |

`fix` + `feat` + `perf` together = **98 substantive code-landings** across `main`.

---

## P1 findings caught by REVIEW MODE — all fixed in-session

The `/review-mode` audit pass surfaced three P1 cross-domain regressions that the original feature waves missed. All three landed end-to-end (fix + regression test + bead close) inside this session window.

### P1-1: `vzn2p` — IndexedZoneKeyManifest resolved duplicate recipients silently

`9f4abf31d fix(fcp-core): IndexedZoneKeyManifest reject duplicate recipients fail-closed (vzn2p)`

br-d2oa0 (the O(1) hot-path optimisation, also in this session at `cf325f358`) used `HashMap::insert` which retains the LAST occurrence on duplicate keys, while the legacy linear-scan resolver returned the FIRST. A signed manifest with two wraps for the same recipient would let two callers derive different effective wraps from the same on-disk bytes — split-view ambiguity adjacent to `InconsistentRecipientWraps`. Fix made `IndexedZoneKeyManifest::new` reject duplicates fail-closed at construction with the existing `DuplicateRecipientInManifest` error, and added the same guard to `validate_no_recipient_split_view` so the issuer-side gate fires before publication.

### P1-2: `f69kn` — `ZoneKeyRing::apply_manifest` ignored V4-only manifest wraps

`828d44873 fix fcp-core ZoneKeyRing apply_manifest resolves V4 wraps via hybrid verifier f69kn`

The shbvv/V4 manifest wave shipped `wrapped_keys_v4` and the `migrated_to_v4` typestate, but the production `apply_manifest` still called `wrapped_key_for(node_id)` (V3 list only). A V4-only manifest passed `validate_no_recipient_split_view` but failed normal recipient application with `MissingWrappedZoneKey`. This blocked mesh-native cutover and encouraged retaining legacy V3 wraps purely to keep production `apply` working. Fix routes through `resolved_wrapped_key_for` and dispatches by KEM; new `apply_manifest_v4<K: XWingKem>` opens both HpkeX25519 and X-Wing wraps via the hybrid verifier path. New `XWingWrapRequiresV4Apply` typed error tells callers when to switch entry points.

### P1-3: `kfr9j` — Length-bypass via transparent `Deserialize` on PQ byte envelopes

`431af6c4a fix(fcp-crypto): length-invariant on Deserialize for transparent PQ byte envelopes (br-kfr9j)`

`MlDsa65SecretKeyBytes` and the X-Wing byte envelopes used `#[serde(transparent)]` over a fixed-length array, but stock serde wouldn't actually enforce the length on deserialize — peers could ship arbitrary-length byte sequences and the type would silently accept them. Patch adds a length-invariant custom `Deserialize` to every transparent PQ byte envelope, paired with proptest fuzz that asserts wrong-length inputs reject.

---

## REVIEW MODE catch rate

5 review findings filed across two `/review-mode` passes (`be0043239`, `3604ec89e`, `572e74826`):

| Finding | Severity | Status | Commit |
|---------|----------|--------|--------|
| `vzn2p` IndexedZoneKeyManifest split-view | P1 | shipped | `9f4abf31d` |
| `f69kn` apply_manifest V4 ignored | P1 | shipped | `828d44873` |
| `kfr9j` PQ length-bypass on transparent Deserialize | P1 | shipped | `431af6c4a` |
| `l9tt6` v2kt4 fail-closed flag TOCTOU race | P2 | shipped | `1d9621f93` |
| `vkb3m` gtplu observable missed IndexedZoneKeyManifest hot path | P3 | shipped | `29fff483d` |

**Catch rate: 5/5 closed in-session.** No review finding sat unfixed past its filing day.

---

## Audit memos written this session (13)

```
docs/audit/deadlock-finder-2026-05-02.md
docs/audit/modes-of-reasoning-beta-2026-05-02.md
docs/audit/profiling-beta-2026-05-02.md
docs/audit/profiling-delta-2026-05-02.md
docs/audit/profiling-gamma-2026-05-02.md
docs/audit/reality-check-alpha-2026-05-02.md
docs/audit/review-mode-alpha-2026-05-02.md
docs/audit/security-audit-saas-alpha-2026-05-02.md
docs/audit/security-audit-saas-beta-2026-05-02.md
docs/audit/security-audit-saas-delta-2026-05-02.md
docs/audit/security-audit-saas-epsilon-2026-05-02.md
docs/audit/security-audit-saas-gamma-2026-05-02.md
docs/audit/swarm-session-summary-2026-05-02.md  ← this file
```

Plus a `mock-code-finder` sweep that filed 3 follow-up beads with zero category-(b) hits.

---

## Notable architectural improvements

### Post-quantum stack hardening (br-kyopb sub-tree)

The kyopb wave landed deep PQ infrastructure across the session:

- **X-Wing KEM** (kyopb.1.2.1, kyopb.1.2.2): real implementation backed by RustCrypto draft-06, IETF KAT harness, on-the-wire `XWingSealedBox` format with `Fcp4Aad` AEAD profile lock.
- **ML-DSA-65** (kyopb.1.1.x sub-tree, mostly pre-session): randomized signing wired through `getrandom`/rand_core 0.10 adapter.
- **ZoneKeyManifest V4 schema** (kyopb.1.2.3, `79da0aae4`): mixed V3+V4 wrap lists, per-recipient KEM discriminator, safe `migrated_to_v4` promotion path.
- **Constant-time `PartialEq`** on 6 secret-bearing PQ types (`fb9ae688a`, br-1zlht): closes byte-by-byte timing-side-channel on equality checks via `subtle::ConstantTimeEq`.
- **Length-invariant `Deserialize`** on transparent byte envelopes (`431af6c4a`, br-kfr9j): closes the P1 length-bypass surfaced by REVIEW MODE.
- **Arena allocator for canonical-CBOR map encoding** (`824d3ffd6`, br-m7aoz): per-entry sort-key allocation collapsed to a single arena `Vec<u8>`, regression bench pins the post-refactor cost.
- **Zeroize on X-Wing secrets** (`bcf831f7c`, br-2ehqg).
- **Lean lattice-delegation soundness theorem** (`1ba10218c`, kyopb.1.3.3): formal proof of soundness for the lattice-trapdoor delegation chain, gated witness landed.
- **Throughput bench** Ed25519 vs ML-DSA-65 vs lattice (`7dec564fd`, kyopb.1.3.4).
- **Mixed-version V3/V4 mesh migration harness** (`b6b687fa3`, kyopb.1.4.3): proves both readers see the same effective zone-key during migration.
- **Proptest fuzz harnesses** for X-Wing, ML-DSA, lattice walker, V4 manifest (`6f46e6a13`).

The kyopb sub-tree now closes everything except `kyopb.1.3.1.1` (replace lattice-arithmetic NotImplemented stubs with real Micciancio-Peikert / CHKP / GPV — flagged unactionable: 320h research item).

### `dja9u` typestate ratchet — convergence reached

`2112fd574 docs(README): refresh dja9u status — LEGACY_VERIFY_ALLOWLIST=0, TYPESTATE_ENFORCED full count (obk7m)`

The connector typestate ratchet finished. **`LEGACY_VERIFY_ALLOWLIST = 0` across 29 connectors.** Per-wave migrations (5 connectors at a time) under dja9u.1.a / .b / .c / .d / .e / .f all closed. Production now enforces `verify_bound` typestate at every connector boundary; no connector retains the legacy permissive-verify path.

### Lock-contention removals

- **InvokeAuditChain per-zone sharding** (`1c24e6c25`, br-uwlj5): replaced single global Mutex with per-zone shards so concurrent invokes against different zones no longer serialize through one lock. Follow-up `001633dab` (br-1a73y) wired the proper `ContentionExhausted` error variant for CAS-retry exhaustion.
- **fcp-store repair queue** (`d9ab493f2`, br-u97n8): replaced sorted-`Vec` repair queue (O(n) insert) with a `BinaryHeap` (O(log n)). Removes a hot lock-hold under load.
- **fcp-store WAL/snapshot V2 envelope** (`6d8682334`, br-dgbtx): keyed BLAKE3 MAC over `(version, seq, op)` — defends against tamperer-with-FS-access who could previously recompute the unkeyed checksum to forge `Delete`/`SetRetention`/`DeleteSymbol` records.
- **fcp-host v2kt4 single-snapshot helper** (`1d9621f93`, br-l9tt6): two separate `state.read().await` acquisitions in the allow-list gate were a TOCTOU race window during admin-state updates; new `allow_list_snapshot` reads all three governance fields under one read-lock so a concurrent writer cannot interleave.
- **handshaken_zone Mutex lock-hold trace span** (`cbac9cd4e`, br-utiw3): instrumentation for the `/deadlock-finder` surfaced this finding; no algorithmic change, just observability.

### Bench coverage across all 5 domains

15 perf commits added Criterion benches and/or shipped algorithmic improvements:

| Crate | Bench / Improvement | Bead |
|-------|---------------------|------|
| fcp-cbor | canonicalize_map arena allocator | m7aoz |
| fcp-core | IndexedZoneKeyManifest O(1) lookups | d2oa0 |
| fcp-store | WAL+cursor walks, repair queue heap | ztdcm, u97n8 |
| fcp-raptorq | bench coverage, repair-tail decode coalesce | 0orhf, qmepq |
| fcp-graphql | hot-path benches | a4uf2 |
| fcp-tailscale | bench coverage, borrowed peer-tag scan | g2dfl, qfsse |
| fcp-bootstrap | bench coverage, cert-selection O(log n) index | ome5t, vkq68 |
| fcp-webhook | precomputed routing index O(1) lookup | 7j7fa |
| fcp-streaming | SSE parser cursor advance (no full rescan) | gqpn5 |
| fcp-oauth | single-flight `tokio::watch` (no Vec scan) | p36a0 |
| fcp-host | concurrent InvokeAuditChain | uwlj5 |
| fcp-crypto-pq | Ed25519 vs ML-DSA-65 vs lattice throughput | kyopb.1.3.4 |

### Other notable security fixes

- `fcp-sandbox` CredentialInjector default-deny hosts not allow-all (`9a9b3b4e6`, br-n781d).
- `fcp-sandbox` reject malformed `cidr_deny` at runtime (`a637a2396`, br-0lc3s).
- `fcp-graphql` query depth/size/alias/root-field limits (`dca242e58`, br-ziovc); fail-closed on subscription backpressure (`c7694ec1c`, br-0q8eh); reject empty bearer tokens (`22aa6e8b3`, br-nb1p2).
- `fcp-webhook` reject empty/short HMAC signing secrets (`9beb77bbb` + `f6d250525`, br-gxwsv).
- `fcp-oauth` reject empty authorization codes (`b17008c31`, br-v0wme).
- `fcp-mesh` redact trace snapshot/export defaults (`10f73bdf1`, br-lmp9l).
- `fcp-audit` reject empty signed-head in verifier (`22252ea3d`, br-eah6j).
- `fcp-store` emit `UpgradedLatestPointer` audit event on silent V1→V2 pointer upgrade (`c9f495544`, br-28nms).
- `fcp-host` close `verify_live_hybrid_owner_capability` silent-bypass path (br-jhbk1, pre-session but referenced).

---

## Operational note: 4-cod rate-limit recovery mode

The 4 cod-flavoured Claude panes (TealOtter, VioletPine, GoldenFinch, SilverFox) hit their 5-day rate limit and went dark until **May 7 16:51**. Cross-cover ran through this gap by routing dispatch to the two cc-flavoured panes (CrimsonWolf and AmberLark). The pattern that worked:

- Each cc pane took the next actionable bead off the queue without waiting for the original cod owner.
- All beads carried enough self-contained context (evidence section + acceptance section in the bead body) that a different pane could pick up mid-flight without losing fidelity.
- The user routed each claim explicitly to one pane to avoid double-claim races; cross-cover was sequential, not parallel.
- The `br update <id> --status=in_progress --force` + `br show <id>` reconnaissance opener gave each pane a clean entry point regardless of who originally owned the bead.

Result: zero blocked work during the cod blackout. The actionable queue drained from ~5 P1/P2 beads at start of recovery to 0 actionable beads at end. Only `xnroh` (AmberLark, P2 GraphQL subscription backpressure surfacing) is still open at session close.

---

## Final state

- **Open actionable:** 1 (xnroh, in-flight with AmberLark).
- **Open unactionable:** 3 (kyopb.1.3.1.1 320h research, ta230 Lean↔Rust mechanical link, r4qcg Windows AppContainer).
- **Blocked:** 0.
- **Closed since session start:** ~167 beads.
- **REVIEW MODE convergence:** all 5 filed findings closed; the queue is empty.
