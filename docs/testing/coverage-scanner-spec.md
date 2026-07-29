# Coverage Scanner Spec (Phase H.3)

> Filed under `flywheel_connectors-angoc.18.3`. Scanner artifact lives at
> `scripts/ci/coverage_scanner.sh`. Conformance gate is
> `crates/fcp-conformance/tests/coverage_scanner_conformance.rs`.

## Purpose

Enforce the Phase H coverage-discipline invariant: **every connector in
`connectors/` must ship at least one of `tests/local_non_mock.rs` or
`tests/live_verification.rs`**.

- `tests/local_non_mock.rs` exercises the connector against a real loopback
  fixture (TCP listener serving canned bytes, real testcontainer, etc.) —
  the production code path runs against bytes-on-the-wire, not a mock.
- `tests/live_verification.rs` is a gated live-tier test that exercises the
  real provider when operator prerequisites are present (env vars,
  approvals) and emits a structured `skipped` artifact otherwise.

Connectors without either file have zero non-mock evidence and are a
graduation candidate for `angoc.16` (Phase G — 49 incubating connectors).

## Scanner output

`scripts/ci/coverage_scanner.sh` walks `connectors/*`, sorts deterministically,
and emits one JSON object per line on stdout:

```json
{"connector":"airtable","has_local_non_mock":true,"has_live_verification":false,"verdict":"covered"}
{"connector":"asana","has_local_non_mock":false,"has_live_verification":false,"verdict":"gap"}
```

Exit code:

- `0` — every connector has at least one of the two files
- `1` — at least one connector has neither (gap detected)
- `2` — `connectors/` not found (scanner misconfigured)

A final `coverage_scanner: covered=N gap=M` summary is emitted to stderr so
stdout stays clean JSONL.

## Ratchet model

Hard "every connector must pass" enforcement is unachievable today (108 of 177
connectors currently lack both files). Instead the conformance test pins a
baseline in `EXPECTED_GAP_CONNECTORS` and fails CI on:

1. **Regression**: a connector NOT in the baseline regressed into the gap set
   (added without one of the two files).
2. **Stale baseline**: a connector IS in the baseline but actually has at least
   one of the two files (the baseline entry should be removed to ratchet the
   gate tighter).
3. **Sort drift**: the baseline must stay alphabetically sorted for stable
   diffs.

This mirrors the pattern already used by `test_coverage_workspace.rs` for the
broader `tests/` directory requirement.

## Adding a new connector

When `connectors/<name>/` is created:

1. Add `tests/local_non_mock.rs` (preferred — loopback fixture is deterministic
   and runs in every CI build) OR
2. Add `tests/live_verification.rs` (gated by `FCP_LIVE_*` env vars) OR
3. Add `<name>` to `EXPECTED_GAP_CONNECTORS` with an inline comment pointing
   to the graduation bead that will close the gap.

Option (3) is allowed only with an explicit graduation reference; it should
not be the default.

## Graduating a connector out of the baseline

When `tests/local_non_mock.rs` or `tests/live_verification.rs` lands for a
baseline connector:

1. Remove the entry from `EXPECTED_GAP_CONNECTORS`.
2. CI green confirms the ratchet tightened by one.

The Phase G epic (`angoc.16`) shrinks this list batch by batch:

- Batch 1 high-impact (7 connectors): `postgresql`, `stripe`, `github`,
  `gmail`, `telegram`, `slack`, `kubernetes`
- Batch 2 Google family (9 connectors)
- Batch 3 AI/ML (4 connectors)
- Batch 4 (~29 remaining)

## Conformance test surface

`crates/fcp-conformance/tests/coverage_scanner_conformance.rs` exposes:

| Test fn | Asserts |
|---|---|
| `test_scanner_enumerates_every_connector` | scanner reports the same set of connectors that exists on the filesystem |
| `test_scanner_classifies_correctly` | `has_local_non_mock` / `has_live_verification` / `verdict` columns agree with filesystem state |
| `test_scanner_exit_reflects_gap_presence` | exit code 0 iff every connector is covered; 1 iff any gap exists |
| `test_no_new_gap_connectors` | no connector outside `EXPECTED_GAP_CONNECTORS` is in gap state |
| `test_no_stale_gap_entries_in_baseline` | every entry in `EXPECTED_GAP_CONNECTORS` is actually missing both files (no stale entries) |
| `test_baseline_alphabetically_sorted` | baseline order is stable |

## Logging

The scanner is deliberately quiet. Per-row JSON goes to stdout for machine
consumption; one summary line goes to stderr for human grep. The conformance
test reports failures via standard Rust assertion messages naming the offending
connector(s).

## fwc doctor

When `angoc.6.1` lands `fwc doctor --probe coverage_files`, it should:

1. Shell out to `scripts/ci/coverage_scanner.sh`
2. Parse the JSONL output
3. Emit:

```json
{
  "n_connectors": 177,
  "n_covered": 69,
  "n_gap": 108,
  "failing_connectors": ["<gap_connector>", ...],
  "warning": "n_gap > 0"
}
```

Operator commands:

- `fwc test coverage scan` — run the scanner directly
- `fwc test coverage report --failing` — list only the gap connectors

## Future work

- **Differential test gate**: when both files exist for a connector, the
  Phase H.1 differential test harness (`angoc.18.1`) cross-validates that
  the loopback and live fixtures produce byte-equivalent semantic answers.
- **Mutation gate**: Phase H.2 (`angoc.18.2`) runs single-byte mutations
  against connector responses to catch silent-accept bugs.
- **Coverage budget per connector**: tie connector cold-start / invoke
  latency from the perf-evidence matrix (`angoc.1.4`) to the same baseline so
  Phase H and Phase B share a single per-connector covenant doc.
