# Differential Testing Harness — Spec

Bead: `flywheel_connectors-angoc.18.1` (Phase H.1)

## Goal

For every connector that ships BOTH `tests/local_non_mock.rs`
(loopback acceptance against a canned-bytes fixture server) AND
`tests/live_verification.rs` (gated live test against the real
provider), run the same operation against both paths and assert
that the loopback and live responses are byte-equivalent **after
scrubbing the non-semantic fields** (timestamps, UUIDs, server-side
session ids, etc.).

This is the third leg of Phase H coverage discipline (after the
H.3 coverage-scanner conformance gate and the H.2 mutation harness).
Differential testing catches a class of bugs the other two cannot:
**silent semantic drift between the loopback and live paths** — for
example, the loopback fixture returning a stable shape while the
live provider has changed its envelope.

## Component layout

```
crates/fcp-testkit/src/differential.rs    (DifferentialHarness)
crates/fcp-testkit/src/differential_scrub.rs  (ScrubRules)
connectors/<pilot>/tests/differential.rs   (per-connector wiring)
docs/testing/differential-harness-spec.md  (THIS FILE)
crates/fcp-conformance/tests/differential_harness_conformance.rs
crates/fcp-testkit/tests/fixtures/differential/  (canonical scrub
   inputs + expected outputs as golden vectors)
```

Note: the bead body proposes `crates/fcp-testing/src/differential.rs`,
but the workspace already has `fcp-testkit` for shared test helpers
and there is no `fcp-testing` crate. The harness lives in
`fcp-testkit` to avoid creating a new workspace member.

## DifferentialHarness API

```rust
pub struct DifferentialHarness {
    scrubs: Vec<Box<dyn ScrubRule>>,
}

impl DifferentialHarness {
    pub fn new() -> Self { /* loads default scrubs */ }

    /// Add a custom scrub rule (per-connector field redactions go here).
    pub fn with_scrub<R: ScrubRule + 'static>(mut self, rule: R) -> Self;

    /// Compare two response bytes after scrubbing.
    pub fn compare(&self, loopback: &[u8], live: &[u8]) -> DifferentialResult;
}

#[derive(Debug)]
pub enum DifferentialResult {
    /// Bytes are byte-equivalent after scrub.
    Equivalent,
    /// Scrubbed forms differ; carries the field-path diff and the
    /// number of scrub hits on each side.
    Divergent {
        diff_summary: String,
        loopback_scrub_hits: usize,
        live_scrub_hits: usize,
    },
    /// One side could not be parsed as JSON for diffing.
    ParseError {
        side: Side,
        error: String,
    },
}

pub enum Side { Loopback, Live }
```

The harness consumes already-deserialized response bytes — the
caller is responsible for invoking the loopback and live paths.
This keeps the harness agnostic to whether the response came from
wiremock, a TCP fixture server, or the real provider.

## Default scrub rules

The default rules live in `differential_scrub.rs` and target the
field shapes most connectors emit. Each rule is applied to JSON
strings; the harness round-trips JSON, applies rules, then
re-serializes for comparison.

| Rule | Pattern | Replacement |
|---|---|---|
| `uuid_v4` | `[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}` | `<UUID>` |
| `rfc3339_timestamp` | `\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z\|[+-]\d{2}:?\d{2})` | `<TS>` |
| `unix_seconds_2026` | `1[6-7]\d{8}` (epoch in 2023-2029 range) | `<UNIX>` |
| `unix_millis_2026` | `1[6-7]\d{11}` | `<UNIX_MS>` |
| `bearer_token_prefix` | `Bearer\s+[A-Za-z0-9._\-+/]{20,}` | `Bearer <TOKEN>` |
| `etag` | `"[0-9a-f]{8,}"` (HTTP ETag quoted body; intentionally does NOT consume the optional `W/` weak-prefix, so weak-vs-strong distinction is preserved in the scrubbed output) | `"<ETAG>"` |
| `connection_id` | provider-supplied request/connection ids like `req_*`, `cnx_*` | `<CONN_ID>` |

Custom rules per connector go via `.with_scrub(MyRule)`.

## Diff semantics

After scrubbing, the harness uses a structural JSON diff (not raw
byte diff) to surface field-path mismatches. A divergent example:

```
loopback: {"id": "<UUID>", "amount": 12.5, "currency": "USD"}
live:     {"id": "<UUID>", "amount": 12.5, "currency": "EUR"}

DifferentialResult::Divergent {
    diff_summary: "field `currency`: loopback=USD live=EUR",
    loopback_scrub_hits: 1,
    live_scrub_hits: 1,
}
```

When one side fails to parse as JSON, the harness short-circuits to
`ParseError` — typically a sign the loopback fixture is stale (live
provider returned an unexpected envelope) OR the live response was
binary (image bytes, PDF, etc., not covered by this harness).

## Per-connector wiring

The pilot lives at `connectors/github/tests/differential.rs`:

```rust
#[fcp_async_core::runtime::test]
async fn github_get_issue_loopback_vs_live() {
    let connector = build_connector_with_config_for_test();
    let request = GetIssueRequest::sample();

    // Loopback path
    let loopback_response = invoke_against_loopback(&connector, &request).await;

    // Live path (gated — skipped without env var)
    let live_response = match invoke_against_live(&connector, &request).await {
        Some(r) => r,
        None => {
            eprintln!("live verification disabled; differential test skipped");
            return;
        }
    };

    let harness = DifferentialHarness::new()
        .with_scrub(GithubIssueScrubs);

    match harness.compare(&loopback_response, &live_response) {
        DifferentialResult::Equivalent => {}
        other => panic!("loopback vs live diverged: {other:?}"),
    }
}
```

## Conformance test

`crates/fcp-conformance/tests/differential_harness_conformance.rs`
enumerates every connector in `connectors/`. For each, if BOTH
`tests/local_non_mock.rs` AND `tests/live_verification.rs` exist,
the conformance test asserts a `tests/differential.rs` is also
present. (When `tests/differential.rs` is absent and both prereqs
exist, the conformance test fails with `connector "<name>" has both
test paths but no differential.rs — file the per-connector wiring`.)

This is the same ratchet-baseline approach as the H.3 coverage
scanner: a growing set of connectors are required to have differential
tests, and the conformance test enforces no regression.

## OTLP / observability

The harness emits OTLP spans under `fcp.testing.differential`:

| Attribute | Value |
|---|---|
| `connector` | connector slug (e.g. "github") |
| `op` | operation id (e.g. "github.issue.get") |
| `n_fields_diff` | number of divergent field paths |
| `scrub_hits_loopback` | count of scrub applications on the loopback side |
| `scrub_hits_live` | count on the live side |
| `verdict` | one of `equivalent`, `divergent`, `parse_error` |

JSONL log per run:

```json
{
  "ts": "2026-05-13T...",
  "connector": "github",
  "op": "github.issue.get",
  "loopback_bytes": 1043,
  "live_bytes": 1067,
  "diff_summary": "field `headers.X-Request-Id`: present on live, absent on loopback (scrub miss)",
  "verdict": "divergent"
}
```

## Failure semantics

- **Test fails when divergent**: the test is the assertion. CI surfaces
  the diff in the failure message.
- **Test skips when live unavailable**: the gated live test produces
  no live bytes; the differential test should skip with a structured
  `eprintln!` message rather than failing. This mirrors the
  `live_verification.rs` skip pattern from `fcp-testkit::live_suite`.
- **Test fails when loopback parses but live doesn't**: this signals
  the live envelope shape changed and the loopback fixture is now
  unrepresentative. The connector graduation gauntlet (Phase G)
  should update the loopback fixture as part of the bump.

## Latency budget

The scrub + diff path for a 100 KB JSON response must run in p99
≤ 50ms. The benchmark at `crates/fcp-testkit/benches/differential_scrub.rs`
(deferred to `angoc.18.1.1`) pins this.

## Cross-references

- `scripts/ci/coverage_scanner.sh` (Phase H.3) — the coverage
  scanner uses this harness's existence as a positive signal when
  promoting a connector out of the gap baseline
- `connectors/*/tests/local_non_mock.rs` — loopback path inputs
- `connectors/*/tests/live_verification.rs` — live path inputs
- `crates/fcp-testkit/src/live_suite.rs` — existing live-suite
  scaffolding; the differential test follows the same env-gate pattern

## Deferred implementation

Filed as `angoc.18.1.1`. The Rust implementation needs:

1. `crates/fcp-testkit/src/differential.rs` + `differential_scrub.rs`
   with the API above
2. `connectors/github/tests/differential.rs` pilot
3. `crates/fcp-conformance/tests/differential_harness_conformance.rs`
   ratchet test
4. `crates/fcp-testkit/tests/fixtures/differential/` golden vectors

The fcp-testkit + fcp-conformance + connector test paths all currently
compile (fcp-core is the upstream-broken crate, and fcp-testkit
does not transitively depend on it). The runtime work is ~6-8h once
the writer has a clean working tree free of concurrent connector
test edits.
