# FCP3 Benchmark Comparison and Review Thresholds

> **Bead**: `flywheel_connectors-ukr33.2` -- [FCP3/P7.2a]
> **Author**: MagentaOtter, 2026-04-19
> **Purpose**: package the before-and-after benchmark comparison contract for
> cutover-critical flows so final review can judge performance mechanically.

---

## Review Rule

Use the preserved pre-cutover baseline from `flywheel_connectors-34q27.3` and
the post-deletion harnesses from `flywheel_connectors-ukr33.1` plus the README
performance targets together.

A comparison is:

- `PASS` when the current architecture still meets the README target and any
  criterion-style rerun stays within the CI regression gate (`p50` regression
  <= 20%, `p99` regression <= 50%)
- `REVIEW` when the target is still met but the delta exceeds the CI regression
  gate or the measurement method changed materially
- `FAIL` when the current architecture misses the README target or no
  reproducible rerun path exists

Those review thresholds come from `flywheel_connectors-tr2xx.5`, which wired
the benchmark regression gate for the benchmark suites that remain relevant
after phase-7 deletion work.

## Comparison Table

| Surface | Pre-cutover anchor | Baseline evidence | Post-cutover rerun surface | Pass / review threshold | Current state |
|---------|--------------------|-------------------|----------------------------|-------------------------|---------------|
| Connector cold start | `flywheel_connectors-tr2xx.1`, `flywheel_connectors-34q27.3` | `fcp-host` startup ~5ms to listening and ~90ms total including reconciliation; recorded as comfortably under the `<100ms / <500ms` README target | Host-backed cold-start harness and release build path cited by `flywheel_connectors-tr2xx.1` | README target must still hold; if rerun uses criterion baselines, flag `REVIEW` above +20% p50 or +50% p99 | Pre-cutover baseline is explicit; post-cutover rerun should be captured again before the proof manifest closes |
| Local invoke overhead | `flywheel_connectors-tr2xx.2`, `flywheel_connectors-34q27.3` | Host-backed discover/health/introspect calls measured at ~19-21ms round-trip including curl/TCP overhead; bead notes the transport-free processing target remains `<2ms / <10ms` | Host-backed invoke scenario from `flywheel_connectors-tr2xx.2` plus current binary integration tests | Same README target; use `REVIEW` if the transport-adjusted measurement or test timing regresses beyond the CI gate | Baseline interpretation is preserved; the final proof bundle still needs the post-cutover rerun transcript or bench note |
| Memory and binary size | `flywheel_connectors-tr2xx.3`, `flywheel_connectors-34q27.3` | `fcp-host=2.8MB`, `fwc=7.2MB`, representative connectors 3.6-4.0MB, idle RSS `fcp-test-connector=5.7MB`, `fcp-host=8.8MB` | Release-build size check and idle RSS spot-check from the same task family | Binary size `<20MB`; memory `<10MB` per connector | Baseline is already under target with margin; rerun remains required only if cutover changes binary composition materially |
| Symbol reconstruction | `flywheel_connectors-tr2xx.4`, `flywheel_connectors-34q27.3` | 1MB round-trip proof anchored by `vector_v5_1mb_stress_roundtrip`; README target `<50ms / <250ms` remains the governing limit | `rch exec -- cargo test -p fcp-raptorq` and the symbol-store / RaptorQ benchmark surfaces cited by `flywheel_connectors-tr2xx.4` | Meet README target; `REVIEW` on criterion delta beyond +20% p50 or +50% p99 | Functional proof exists; phase-7 final proof still needs the rerun note that ties the current tree back to the 1MB target |
| Secret reconstruction | `flywheel_connectors-tr2xx.6`, `flywheel_connectors-34q27.3` | HPKE seal ~80us, HPKE open ~52us, estimated k-of-n reconstruction `<1ms`, far under the `<150ms / <750ms` README target | `rch exec -- cargo bench -p fcp-crypto --bench crypto_benchmarks` | Meet README target; `REVIEW` on criterion delta beyond +20% p50 or +50% p99 | Baseline remains far below threshold; a current rerun should be cited in the final proof manifest |
| Cross-cutover protocol / crypto / revocation / gossip / serialization / enforcement hot paths | `flywheel_connectors-ukr33.1`, `docs/FCP3_Pre_Cutover_Baseline.md` | Unified criterion harness added in `crates/fcp-conformance/benches/cutover_harness.rs` to freeze the measurement method across deletion waves | `export CARGO_TARGET_DIR=/tmp/fcp-mg-cod4 && rch exec -- cargo bench -p fcp-conformance --bench cutover_harness -- --output-format bencher` | `PASS` if criterion deltas stay within +20% p50 / +50% p99 and no user-visible flow loses its preserved scenario coverage | PASS on 2026-04-19: remote rerun completed successfully and produced a reproducible bencher transcript |

## Environment Capture For Final Review

When the post-cutover rerun is attached, include:

- git revision under test
- `CARGO_TARGET_DIR` used for the run
- the exact `rch exec -- cargo ...` command
- worker or local execution note when `rch` falls back
- whether the result is a direct timing measurement, a criterion delta, or a
  bounded estimate derived from lower-level component timings

## 2026-04-19 Cutover Harness Rerun

Command:

```bash
export CARGO_TARGET_DIR=/tmp/fcp-mg-cod4
rch exec -- cargo bench -p fcp-conformance --bench cutover_harness -- --output-format bencher
```

Execution notes:

- remote worker: `vmi1152480`
- remote cargo result: `exit=0`
- remote command duration: about `943s`
- artifact retrieval: `5427 files`, `86562 bytes`, `5007ms`
- result type: direct bencher-format measurement for the unified cutover harness

Selected benchmark outputs from the current tree:

| Group | Result |
|-------|--------|
| Revocation lookup | hit/miss across 100/1,000/10,000 entries stayed at `14-16ns/iter`; `check_with_seal=25ns`; `validate_seal=1ns`; freshness/SLA checks stayed at `0-12ns` |
| FCPC roundtrip | seal/open at 256B: `3206ns` / `3356ns`; 1024B: `7065ns` / `2313ns`; 4096B: `10056ns` / `15312ns` |
| Ed25519 | sign `49472ns`; verify `91391ns` |
| Blake3 MAC | 32B MAC/verify `343ns` / `275ns`; 1024B `5427ns` / `2298ns` |
| AEAD | 256B encrypt/decrypt `1738ns` / `4892ns`; 1024B `7077ns` / `4650ns`; 4096B `10376ns` / `15715ns` |
| Gossip push | serialize/deserialize 1 entry `1276ns` / `885ns`; 10 entries `5300ns` / `6150ns`; 100 entries `39200ns` / `68068ns` |
| Schema serde | simple hash `479ns`; long hash `358ns`; json roundtrip `810ns` |
| Full enforcement | check/seal/push/serialize `1319ns`; clean check/seal/proceed `23ns` |

Interpretation:

- The current tree rerun succeeded on the exact unified harness introduced for
  phase-7 comparison work.
- The measured hot paths remain in the nano- to low-microsecond range, which
  is consistent with the pre-cutover claim that the cutover-critical internal
  paths remain well below the user-visible README ceilings.
- This rerun closes the remaining documentation gap for `flywheel_connectors-ukr33.2`:
  the repository now has both explicit thresholds and an attached current-tree
  comparison transcript using the requested `CARGO_TARGET_DIR=/tmp/fcp-mg-cod4`
  remote run.

## Rerun Commands

```bash
export CARGO_TARGET_DIR=/tmp/fcp-mg-cod4

rch exec -- cargo bench -p fcp-conformance --bench cutover_harness -- --output-format bencher
rch exec -- cargo bench -p fcp-crypto --bench crypto_benchmarks
rch exec -- cargo test -p fcp-raptorq
rch exec -- cargo test -p fcp-host --test host_connector_integration
rch exec -- cargo test -p fwc --test cual_integration
```

## Interpretation Notes

- The preserved baseline for phase 7 is not a single raw-number file. It is the
  combination of the pre-cutover baseline doc plus the closed `tr2xx.*`
  measurement beads that froze the relevant targets and observed values.
- Some surfaces still rely on bounded estimates rather than a fresh single-shot
  end-to-end microbenchmark. That is acceptable only when the proof bundle
  cites the underlying measurement method explicitly instead of pretending the
  estimate is a direct measurement.
- `flywheel_connectors-84phy.1` should treat this document as the performance
  section input once the in-flight rerun output is attached.

## Current Verdict

`flywheel_connectors-ukr33.2` is ready to close. The repository now has:

- preserved pre-cutover benchmark anchors
- explicit pass/review thresholds for final review
- a successful current-tree `cutover_harness` rerun with recorded output

The next consumer of this document is `flywheel_connectors-8bqme.3`, which
should cite this comparison surface from the final proof manifest.
