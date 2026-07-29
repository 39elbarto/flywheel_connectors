# Mutation Testing Harness — Spec

Bead: `flywheel_connectors-angoc.18.2` (Phase H.2)

## Goal

Apply single-byte mutations to recorded connector responses and
assert the connector either:

1. **Rejects** with a structured error, OR
2. **Successfully parses** without panic and surfaces a structured
   field-level error.

What MUST NEVER happen:

- A `panic!`, `unwrap()` failure, or unbounded allocation.
- Silent acceptance of a malformed response (the connector returns
  `Ok(_)` with garbage data in the typed result).
- A secret leak in the error message (the bytes that triggered the
  error must not appear in the structured error).

This harness sits alongside the H.1 differential testing harness
(byte-equivalent comparison between loopback and live paths) and
the H.3 coverage-scanner ratchet (every connector ships at least
one of local_non_mock.rs or live_verification.rs). Together the
three legs constitute Phase H coverage discipline.

## Component layout

```
crates/fcp-testkit/src/mutation.rs           (MutationHarness)
crates/fcp-testkit/src/mutation_kinds.rs     (MutationKind enum + appliers)
connectors/<pilot>/tests/mutation.rs          (per-connector wiring; pilot: stripe)
docs/testing/mutation-harness-spec.md         (THIS FILE)
crates/fcp-conformance/tests/mutation_harness_conformance.rs
crates/fcp-testkit/tests/fixtures/mutation/   (mutation kind + result_class golden vectors)
```

Note: like the differential harness (`angoc.18.1`), this lives in
`fcp-testkit` rather than the bead's proposed new `fcp-testing`
crate.

## MutationHarness API

```rust
pub struct MutationHarness {
    seed: u64,
    max_mutations: usize,
}

impl MutationHarness {
    pub fn new() -> Self;  // seed=0, max_mutations=1000

    pub fn with_seed(mut self, seed: u64) -> Self;
    pub fn with_max_mutations(mut self, n: usize) -> Self;

    /// Apply mutations to the response bytes and feed each mutant
    /// through `parse_fn`. Classifies each result.
    pub fn run<T, E, F>(&self, response: &[u8], parse_fn: F) -> MutationReport
    where
        F: Fn(&[u8]) -> Result<T, E>,
        T: std::fmt::Debug,
        E: std::fmt::Debug;
}

#[derive(Debug)]
pub struct MutationReport {
    pub total_attempts: usize,
    pub by_kind: BTreeMap<MutationKind, KindReport>,
    pub never_panics: bool,
    pub overall_verdict: OverallVerdict,
}

#[derive(Debug)]
pub struct KindReport {
    pub attempts: usize,
    pub rejected: usize,
    pub graceful_partial_accept: usize,
    pub graceful_field_error: usize,
    pub silent_accept: usize,  // <- the bug we want to catch
}

#[derive(Debug)]
pub enum OverallVerdict {
    AllGraceful,           // every mutation either rejected or surfaced structured error
    SilentAcceptDetected { kind: MutationKind, examples: Vec<usize> },
    PanicDetected,          // any panic is a hard fail
}
```

The harness uses `catch_unwind` so panics in `parse_fn` are surfaced
as `PanicDetected` rather than tearing down the test process.

## MutationKind taxonomy

| Kind | Operation | Byte selection |
|---|---|---|
| `BitFlip` | XOR a single byte with a single bit (1 of 8) | uniform random |
| `ByteZero` | replace one byte with `0x00` | uniform random |
| `ByteMax` | replace one byte with `0xFF` | uniform random |
| `Truncate` | drop the last N bytes (1, 16, 64, half-length) | last 4 random offsets |
| `LengthPrefixCorrupt` | flip bits in a detected length-prefix byte | only fires when input has a recognizable length prefix |
| `NullByteInjection` | insert `0x00` between two adjacent valid bytes | uniform random |
| `HighBitFlip` | XOR a byte with `0x80` (sign-bit flip — catches signed/unsigned conversion bugs) | uniform random |

The mutation kind is determined by `seed + mutation_index`; running
the same harness twice with the same seed produces the same mutation
sequence — useful for fuzz reproduction without storing the mutants.

## Result classification

For each mutated input, `parse_fn` returns one of:

| Result | Class | Note |
|---|---|---|
| `Err(_)` with structured error type | `Rejected` | the GOOD path — connector caught the malformed input |
| `Ok(T)` where `T` carries a field-level error variant | `GracefulFieldError` | connector parsed the envelope but flagged a bad field — acceptable |
| `Ok(T)` with the mutated payload silently coerced or truncated | `SilentAccept` | the BUG path |
| `Ok(T)` from a mutation that only affected a truly-don't-care byte (trailing whitespace, padding) | `GracefulPartialAccept` | acceptable; the mutation didn't actually change semantics |
| panic via `catch_unwind` | `PanicDetected` | hard fail |

The classifier is connector-specific (`parse_fn` returns `Result<T,
E>` and the harness reads `T`'s `Debug` impl + an optional
`is_field_error()` trait method to distinguish `GracefulFieldError`
from `SilentAccept`). The default classifier treats every `Ok(T)`
as `SilentAccept` unless the connector overrides — opt-in
permissiveness, not opt-out.

## Pilot: connectors/stripe

`connectors/stripe/tests/mutation.rs` runs 200 mutations against a
recorded `stripe.charge.get` response and asserts:

- 0 panics
- 0 SilentAccept
- ≥ 50% Rejected (most single-byte mutations are clearly invalid)
- p99 mutation latency ≤ 30ms

Stripe is the pilot because:
1. Its response shape is well-documented and stable
2. The CHARGE response carries amount + currency + status — three
   independent fields where a silent coerce would be operationally
   dangerous
3. Stripe's webhook signature path (separate from response parsing)
   already has signature-tampering coverage, so this harness
   complements rather than duplicates

## Latency budget

The harness runs `max_mutations` × `parse_fn` invocations sequentially.
For a 100 KB response and `max_mutations = 1000`, total runtime must
be ≤ 30 seconds (p99 ≤ 30ms per mutation). The bench at
`crates/fcp-testkit/benches/mutation_harness.rs` (deferred to
`angoc.18.2.1`) pins this.

## Determinism

Same seed → same mutation sequence → same MutationReport. This is
load-bearing for CI: when a SilentAccept is detected, the test name
+ seed + report identifies the offending mutation deterministically.

For reproduction: `cargo test -p fcp-stripe --test mutation -- --seed 7`
re-runs the seed-7 mutation set.

## Conformance ratchet

`crates/fcp-conformance/tests/mutation_harness_conformance.rs`
enumerates every connector in `connectors/`. For each:

- If the connector is in the `MUTATION_HARNESS_REQUIRED` allowlist
  (initially just `stripe`; grows over time), the conformance test
  asserts `tests/mutation.rs` exists and is wired to the harness.
- If the connector is NOT in the allowlist, the conformance test
  skips silently (the ratchet only ratchets DOWN — connectors are
  added to the allowlist as they prove out the harness).

This avoids requiring 175+ connectors to ship the harness on day 1
while preserving the no-regression property: once a connector is in
the allowlist, removing the harness fails CI.

## Failure semantics

| Outcome | CI behavior |
|---|---|
| 0 panics + 0 SilentAccept | test passes |
| 0 panics + ≥1 SilentAccept | test fails with structured report; bead filed under the offending connector |
| ≥1 PanicDetected | test fails immediately (hard fail); P1 bead filed |
| Latency budget exceeded | test passes with a WARN line; tracked but not gating |

## Secret-leak check

After classifying each mutation, the harness verifies:

- The mutation byte position is NOT present in the structured error
  message (no `error.location.offset` leaks).
- Original response bytes from the mutation region are NOT present
  in the error message (no quoted-snippet leaks).

This is the same posture as the SecretTaintTracker
(`crates/fcp-testkit/src/secret_taint.rs` from `angoc.10.2`) — error
messages should describe SHAPE violations, not LEAK the bytes that
violated them.

## OTLP / observability

Spans under `fcp.testing.mutation`:

| Attribute | Value |
|---|---|
| `connector` | connector slug |
| `op` | operation id |
| `mutation_kind` | one of the 7 MutationKind values |
| `byte_index` | absolute byte offset within the response |
| `result_class` | one of {rejected, graceful_partial_accept, graceful_field_error, silent_accept, panic} |
| `seed` | RNG seed used to derive the mutation sequence |

Histogram of `result_class` per connector is emitted as a metric.

## Cross-references

- `crates/fcp-testkit/src/secret_taint.rs` (Phase P.2 / angoc.10.2) —
  the harness's secret-leak check borrows the same scanning approach
- `connectors/_adversarial/` (Phase P.4) — the existing adversarial
  connector is a complementary "synthetic-bad-response producer"
  that this harness consumes responses from
- `docs/testing/differential-harness-spec.md` (Phase H.1) — sibling
  testing harness focused on byte-equivalence rather than malformed-
  byte rejection

## Deferred implementation

Filed as `angoc.18.2.1`. The runtime work needs:

1. `crates/fcp-testkit/src/mutation.rs` + `mutation_kinds.rs`
2. `connectors/stripe/tests/mutation.rs` pilot wiring
3. `crates/fcp-conformance/tests/mutation_harness_conformance.rs`
   ratchet test
4. `crates/fcp-testkit/tests/fixtures/mutation/` golden vectors
   (this commit ships fixture-input definitions; the harness
   converts them into MutationReport snapshots once it lands)

Estimated effort: 6-8h once the writer has a clean working tree.
