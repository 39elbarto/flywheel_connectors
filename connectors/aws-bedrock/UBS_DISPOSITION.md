# AWS Bedrock UBS Disposition

Bead: `flywheel_connectors-4kw5f.2.9.2.13.1`
Date: 2026-05-10
Operator: GreenLake

## Current Scan

Command:

```bash
ubs connectors/aws-bedrock
```

Result from the 2026-05-10 scan:

- Critical: 0
- Warning: 590
- Info: 215
- Embedded `cargo fmt`, `cargo clippy`, `cargo check`, `cargo test --no-run`, `cargo audit`, and dependency-outdated checks were clean.
- `cargo-deny` and `cargo-udeps` were not installed, so UBS skipped those optional policy checks.

## Accepted Warning Buckets

### Test panic and assertion inventory

Most `unwrap`, `expect`, `assert`, `unwrap_err`, and `expect_err` findings are in `#[cfg(test)]` modules or integration tests. They deliberately turn fixture construction failures into hard test failures. They are accepted for this closeout because production code paths still compile cleanly under clippy and the tests are the counter-check.

Counter-test: `cargo test -p fcp-aws-bedrock --test integration` exercises the request signing, provider error, retry, timeout, and redaction fixtures.

### Event-stream checked indexing

UBS reports direct slices in `src/event_stream.rs` around frame length parsing. The decoder checks frame length and buffer availability before taking those ranges; malformed/truncated frames are covered by the event-stream unit tests. This bucket remains accepted unless a new failing malformed-frame case appears.

Counter-test: `cargo test -p fcp-aws-bedrock event_stream`.

### Request-header and credential-shape inventory

The connector constructs outbound AWS SigV4 and Mantle bearer request headers. UBS does not report critical request-derived header sinks in the current run. Credential-shaped test constants are fixture-only and redaction tests assert they are not emitted in request bodies or JSONL evidence.

Counter-test: `cargo test -p fcp-aws-bedrock --test integration fixture_e2e_jsonl_exercises_connector_boundary -- --nocapture`.

### Allocation and clone inventories

Clone, allocation-in-loop, and `as` cast findings are performance/style inventories. The hot-path conversions either build AWS JSON request bodies, normalize provider responses, or copy event-stream payloads for decoded output. No current finding changes connector correctness or redaction behavior.

Disposition: accepted for this closeout; future performance work can revisit with benchmarks.

## Not Accepted Without Follow-Up

Any future UBS critical finding, production panic reachable from provider input, leaked AWS credential material, or unchecked event-stream frame case must be fixed or filed as a separate security bead before this connector is marked fully closed.
