# Profiling / Software-Performance Audit · Beta Domain · 2026-05-02

**Auditor:** CrimsonWolf
**Skill:** `/profiling-software-performance`
**Scope:** `fcp-core`, `fcp-protocol`, `fcp-cbor`, `fcp-crypto`, `fcp-crypto-pq`,
plus `fcp-host` (which carries the per-invoke audit hot path
introduced by mvax3) and `fcp-store::compatibility_ledger`.
**Companion to:** `docs/audit/security-audit-saas-beta-2026-05-02.md`
(security audit) and
`docs/audit/modes-of-reasoning-beta-2026-05-02.md`
(modes-of-reasoning audit). Same code paths, different question:
not "is this safe?" or "does it claim what it proves?", but
**"where does throughput / allocation / contention bite?"**

## Methodology

For each crate in scope:

- **Hot paths:** identified by tracing per-invoke cost from the
  `fcp-host::invoke_handler` entry through preflight, dispatch,
  audit-event append, receipt summarisation. CBOR encode +
  signature + lookup operations counted per request.
- **Allocations in hot paths:** `grep` for `to_vec` / `clone` /
  `to_string` / `format!` / `Vec::with_capacity` to find heap traffic
  per request. Crossed-checked against `Drop` semantics for
  zeroize-on-drop secret types.
- **Lock contention:** `grep` for `Mutex` / `RwLock` / `parking_lot`
  in shared-state types reached from the invoke path.
- **Algorithmic concerns:** `iter().find` + linear scans on Vec-backed
  lookups, recursive walks on canonical CBOR, per-call key schedules.
- **Bench coverage:** every crate's `benches/` directory inventoried
  to identify hot paths with no measurement.

Each finding triaged into `(a) confirmed-hotspot-needs-fix`,
`(b) benches-missing-add-coverage`, or `(c) false-positive`. Filed
beads only for `(a)` + `(b)` per audit rules, tagged `[profiling]`
+ `[beta]`.

## Findings

### (a) Confirmed hotspots — 3

#### A1 · InvokeAuditChain serialises every concurrent invoke through one global Mutex
- **Bead:** `flywheel_connectors-uwlj5` (P2)
- **Where:** `crates/fcp-host/src/invoke_audit.rs:174` — the
  `chains: Mutex<HashMap<String, ZoneChain>>` field plus the
  `append` function which holds the lock for the WHOLE
  canonical-CBOR encode + BLAKE3 hash + Vec push (line 199-251).
- **Cost in critical section:** zone-id String clone for HashMap
  entry lookup, AuditEntryBuilder construction, canonical-CBOR
  encode of provisional entry, BLAKE3 hash, rebuild + push.
- **Throughput impact:** N concurrent invokes targeting different
  zones bottleneck on 1× critical-section cost rather than
  N×. Particularly acute given mvax3's "every operation produces
  an audit event" promise — the audit append is on the synchronous
  invoke path.
- **Fix:** per-zone sharding + move canonical-CBOR + BLAKE3
  outside the lock (lock-free on hot path, lock only for the
  pointer-update bookkeeping).

#### A2 · canonicalize_map allocates a Vec per map entry just for sort key
- **Bead:** `flywheel_connectors-m7aoz` (P3)
- **Where:** `crates/fcp-crypto/src/canonicalize.rs:147-163` —
  `canonicalize_map` builds `with_keys` Vec by calling
  `key_buf.clone()` per entry (line 162) just to get a sortable
  byte-string for RFC 8949 §4.2.1 length-then-bytewise ordering.
- **Hot callers:** every signed-object encode path —
  `Fcp4Aad::encode` (per X-Wing seal/open),
  `HpkeSealedBox` AAD bind (per V3 zone-key wrap),
  `MeshCompatibilityLedger::to_canonical_cbor` (per signed ledger
  emit), `AuditEntry::computed_id` (per audit-chain append),
  `ZoneKeyManifest` canonical encode.
- **Fix:** single arena Vec laying out all serialized keys
  end-to-end, plus a `(usize, usize)` offset table sortable via a
  comparator that borrows out of the arena. Eliminates per-entry
  clone.

#### A3 · ZoneKeyManifest recipient lookups are O(n) linear scans
- **Bead:** `flywheel_connectors-d2oa0` (P3)
- **Where:** `crates/fcp-core/src/zone_keys.rs` —
  `wrapped_key_for`, `wrapped_object_id_key_for`,
  `wrapped_key_v4_for` all `iter().find(|e| e.recipient == *node_id)`.
  `resolved_wrapped_key_for` calls v4 then v3 → 2× O(n) on the
  fallback path.
- **Scaling concern:** typical V3 manifests have 8 recipients
  (small N → dominated by constant factor). V4 cohabitation
  manifests can carry both V3 and V4 wraps for a recipient
  (effectively 2× recipient list); design-target steady state of
  256 recipients per zone is a 256-comparison lookup per request.
- **Fix:** lazy `OnceLock<HashMap<TailscaleNodeId, usize>>` index
  built on first lookup, or pre-sorted `BTreeMap` with
  encode-time order preserved by canonicalize. Wire format must
  stay byte-identical (signature commitment).

### (b) Benches missing — 2

#### B1 · No bench coverage for InvokeAuditChain::append per-invoke overhead
- **Bead:** `flywheel_connectors-ir8cz` (P3)
- **Where:** `crates/fcp-host/` has NO benches directory; mvax3
  shipped no Criterion measurement of the audit-append cost.
- **Fix:** new `crates/fcp-host/benches/invoke_audit_benchmarks.rs`
  with single-zone (lock contention dominant), multi-zone
  (sharding wins), per-phase append latency, and Criterion plot
  output. Establishes the baseline for the uwlj5 fix to land
  against.

#### B2 · No bench coverage for ZoneKeyManifest recipient-lookup at realistic recipient counts
- **Bead:** `flywheel_connectors-nw5zb` (P3)
- **Where:** `crates/fcp-core/benches/` has `pcs_benchmarks.rs`
  but no zone-keys bench.
- **Fix:** new `crates/fcp-core/benches/zone_key_manifest_benchmarks.rs`
  measuring lookup cost at N ∈ {8, 32, 128, 256} for hit + miss,
  V4-direct + V3-fallback, plus split-view validator at realistic
  recipient counts.

### (c) False positives / no action — not filed

- **X-Wing decap upstream loop body** — runs inside the `x-wing`
  crate's audited inner loop; we can't optimise their FFT / NTT
  internals.
- **ML-DSA verify upstream loop body** — same: belongs to
  RustCrypto, not us.
- **HpkeSealedBox::from_bytes split_at + to_vec** — cold-path
  one-time decode at startup or wrap-receipt time. The two-Vec
  allocation per decode is a constant factor, not a per-request
  hot path.
- **HKDF-SHA256(IKM=ss, salt=aad, info="FCP4-XWING-AEAD") per encap**
  — necessary for security (the AAD-as-salt binding is
  load-bearing per the kyopb.1.2.2 finalisation). Cannot cache
  the derived key without losing the per-encap binding.
- **fcp-core::ZoneKeyRing's HashMap<ZoneKeyId, ZoneKey>** —
  storage is already O(1); no finding.
- **`Fcp4Aad::for_*` constructors clone zone_id / recipient_node_id /
  purpose into Vec** — three small Vec allocations per AAD build.
  Could be eliminated with `&[u8]` borrows + lifetime-tagged AAD,
  but the borrow gymnastics outweigh the perf win for typical
  AAD sizes (~100 bytes per call); marginal.
- **fcp-cbor `to_canonical_cbor` pre-allocates 256-byte capacity** —
  good baseline; over-allocation is acceptable vs reallocation
  during encode.

## Quick wins applied inline

None. Each (a) finding requires either:
- A non-trivial refactor (uwlj5 per-zone sharding ≈ 50+ LOC).
- An invariant-preserving algorithm swap (m7aoz arena-based sort
  comparator ≈ 30 LOC + golden-vector verification).
- A persistent state addition (d2oa0 OnceLock index ≈ 20 LOC + 6
  call-site updates + serde-skip pin).

None of these is a "5-line obvious patch" that should land
mid-audit. Filed beads instead so the work is scoped.

## Cross-references

- **mvax3** (security/observability) — wired the InvokeAuditChain
  that uwlj5 now scales out.
- **kyopb.1.2.2** (post-quantum) — pinned the canonicalize-CBOR
  paths that m7aoz now wants to optimise.
- **kyopb.1.2.3** (post-quantum) — landed the V4 wrapped_keys_v4
  list that d2oa0 wants to index.
- **shbvv** (security) — `split_view_recipients` validator runs
  per-recipient and would benefit directly from d2oa0's index.

## Files filed

- `flywheel_connectors-uwlj5` — A1 (P2)
- `flywheel_connectors-m7aoz` — A2 (P3)
- `flywheel_connectors-d2oa0` — A3 (P3)
- `flywheel_connectors-ir8cz` — B1 (P3)
- `flywheel_connectors-nw5zb` — B2 (P3)
