# Core Platform Evidence Index

> Bead: `flywheel_connectors-49z0b.7.4`
>
> Single reference for verifying FCP platform crates before and after
> downstream connector work. Covers rerun commands, artifact shapes,
> known flake notes, and regression triage.

## Platform Crate Map

| Crate | Role | Test Count | Primary Test Surface |
| --- | --- | --- | --- |
| `fcp-core` | Zone model, capabilities, provenance, lifecycle | ~2,000+ | Inline `#[cfg(test)]` + `crates/fcp-core/tests/lifecycle_tests.rs` |
| `fcp-protocol` | FCPC/FCPS framing, sessions | ~800+ | Inline |
| `fcp-crypto` | Ed25519, X25519, HPKE, COSE, Blake3 | ~600+ | Inline + RFC test vectors |
| `fcp-cbor` | Deterministic CBOR | ~400+ | Inline |
| `fcp-manifest` | Manifest parsing, validation | ~300+ | Inline |
| `fcp-sdk` | Connector authoring, runtime, retry | ~500+ | Inline + `crates/fcp-sdk/tests/` |
| `fcp-host` | Host/orchestrator, admin API | ~3,300+ | Inline + `crates/fcp-host/tests/` |
| `fcp-streaming` | Streaming health, SSE, WebSocket | ~420+ | Inline |
| `fcp-webhook` | Webhook delivery, retry, signatures | ~445+ | Inline + `crates/fcp-webhook/tests/no_mock_integration.rs` |
| `fcp-store` | Object store, repair, GC | ~700+ | Inline |
| `fcp-mesh` | Mesh routing, gossip, admission | ~160+ | Inline |
| `fcp-raptorq` | Fountain codes | ~720+ | Inline |
| `fcp-conformance` | Protocol conformance | ~200+ | `crates/fcp-conformance/tests/` |
| `fcp-testkit` | Shared fixtures, live-suite, evidence, swarm-latency harness primitives, operator decision cards | ~700+ | Inline + `crates/fcp-testkit/tests/` |
| `fcp-e2e` | End-to-end harness | ~100+ | `crates/fcp-e2e/tests/` |

## Rerun Commands

### Quick Verification (pre-commit)

```bash
# Format check
rch exec -- cargo fmt --check

# Type check (workspace)
rch exec -- cargo check --workspace --all-targets

# Clippy (pedantic + nursery)
rch exec -- cargo clippy --workspace --all-targets -- -D warnings
```

### Per-Crate Test Commands

```bash
# Core platform crates
rch exec -- cargo test -p fcp-core
rch exec -- cargo test -p fcp-protocol
rch exec -- cargo test -p fcp-crypto
rch exec -- cargo test -p fcp-cbor
rch exec -- cargo test -p fcp-manifest
rch exec -- cargo test -p fcp-sdk
rch exec -- cargo test -p fcp-host
rch exec -- cargo test -p fcp-streaming
rch exec -- cargo test -p fcp-webhook
rch exec -- cargo test -p fcp-store
rch exec -- cargo test -p fcp-mesh
rch exec -- cargo test -p fcp-raptorq
rch exec -- cargo test -p fcp-conformance
rch exec -- cargo test -p fcp-testkit
rch exec -- cargo test -p fcp-e2e

# Full workspace
rch exec -- cargo test --workspace
```

### Targeted Test Scenarios

```bash
# Health state machine lifecycle
rch exec -- cargo test -p fcp-testkit --test runtime_lifecycle_acceptance

# Live-suite infrastructure
rch exec -- cargo test -p fcp-testkit -- live_suite

# Evidence helpers
rch exec -- cargo test -p fcp-testkit -- evidence_helpers

# Swarm latency evidence model (1k/10k scenarios, p50/p95/p99/p999, JSONL records)
rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-swarm-latency-testkit cargo test -p fcp-testkit latency --lib

# Swarm operator decision cards (scheduler/placement/backpressure replay contract)
rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-swarm-decision-cards cargo test -p fcp-testkit decision_card --lib

# Streaming health model
rch exec -- cargo test -p fcp-streaming -- health

# Webhook no-mock pipeline
rch exec -- cargo test -p fcp-webhook --test no_mock_integration

# Host no-mock integration
rch exec -- cargo test -p fcp-host --test no_mock_integration

# Host connector integration
rch exec -- cargo test -p fcp-host --test host_connector_integration

# E2E host resilience
rch exec -- cargo test -p fcp-e2e --test host_resilience_e2e

# SDK tracing contract
rch exec -- cargo test -p fcp-sdk --test tracing_contract

# SDK streaming golden vectors
rch exec -- cargo test -p fcp-sdk --test streaming_golden_vector_tests

# Lifecycle state machine
rch exec -- cargo test -p fcp-core --test lifecycle_tests

# Testkit integration suites
rch exec -- cargo test -p fcp-testkit --test cancellation_race
rch exec -- cargo test -p fcp-testkit --test deadline_monotonicity
rch exec -- cargo test -p fcp-testkit --test differential_regression
rch exec -- cargo test -p fcp-testkit --test logging_contract
rch exec -- cargo test -p fcp-testkit --test parity_performance
```

### Benchmark Commands

```bash
# FWC benchmarks (search, schema, pipeline)
rch exec -- cargo bench -p fwc

# PCS benchmarks (epoch advance, removal rekey)
rch exec -- cargo bench -p fcp-core

# CUAL benchmarks
rch exec -- cargo bench -p fwc --bench cual_bench
```

## Evidence Artifact Shapes

### Test Evidence JSON

All acceptance tests produce evidence via `EvidenceCollector`:

```json
{
  "audit_events": 3,
  "receipts": 2,
  "decisions": 0,
  "log_lines": 5,
  "seeded_state": 1,
  "mutations": 0,
  "cleanup_verifications": 1,
  "total_artifacts": 12
}
```

### Live Environment Evidence

Live-suite runs produce `LiveEnvironment::evidence_summary()`:

```json
{
  "manifest": {
    "connector": "stripe",
    "tier": "sandbox_required",
    "provider": "Stripe",
    "secret_count": 1,
    "budget_usd": 1.0,
    "cleanup_strategy": {"kind": "auto_expire", "ttl_hours": 24}
  },
  "secrets_loaded": 1,
  "secrets_missing": [],
  "env_vars": {"complete": true, "loaded_count": 1},
  "budget": {
    "budget_max_usd": 1.0,
    "total_spent_usd": 0.15,
    "alert_level": "ok",
    "within_limits": true
  },
  "tenant_prefix": "fcp-test-stripe",
  "ready": true
}
```

### Prerequisite Report

Pre-flight check before live runs:

```json
{
  "connector": "aws",
  "tier": "sandbox_required",
  "ready": false,
  "gate_enabled": false,
  "gate_env_var": "FCP_LIVE_SANDBOX",
  "secrets_complete": false,
  "secrets_missing": ["access_key"],
  "budget_configured": true,
  "cleanup_configured": true,
  "problem_count": 2,
  "problems": ["Live tier not enabled", "Missing required secret: access_key"]
}
```

### Health Snapshot

Runtime health model output:

```json
{
  "status": {"state": "ready"},
  "uptime_ms": 3600000,
  "load": 0.45,
  "details": null,
  "rate_limit": null
}
```

### Adaptive Batch Scheduler

Host batch planning now supports an opt-in adaptive scheduler for massive
agent-swarm fanout. The default remains deterministic FIFO topological order;
adaptive mode reorders only within already-independent dependency tiers using
priority, estimated service time, and fairness buckets. Scheduler reports carry
the original tiers, scheduled tiers, per-operation actions, and FIFO-vs-scheduled
wait counterfactuals so test harnesses can replay the plan without trusting log
text.

The replay report also carries a compact queueing summary with p50/p95/p99/p999
FIFO waits, scheduled waits, p99/p999 wait improvement, promoted/delayed counts,
and the maximum per-operation wait increase. The 1k-operation deterministic
replay test intentionally uses a skewed long-then-short workload to prove p99
and p999 queueing gains while bounding long-operation delay.

Targeted verification:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-swarm-batch-scheduler cargo test -p fcp-host batch_scheduler --lib

rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-swarm-batch-scheduler-bench cargo bench -p fcp-host --bench batch_scheduler -- --sample-size 10 --warm-up-time 1 --measurement-time 2
```

## Known Flakes and Workarounds

### fcp-streaming health.rs timing tests

**Symptom:** `test_health_tracker_zombie_detection` occasionally fails on
loaded CI machines.

**Root cause:** Tests use wall-clock `Instant::now()` comparisons with tight
margins. Under high CPU load, timer granularity causes spurious failures.

**Workaround:** Margins were widened to 50ms heartbeat / 200ms zombie in
commit fixing flaky tests. If still seen, increase margins further or gate
behind `FCP_FLAKY_TIMING_TOLERANCE_MS`.

### fcp-host integration tests with concurrent builds

**Symptom:** `cargo test -p fcp-host` fails intermittently with lock
contention when other agents are building simultaneously.

**Workaround:** Use a dedicated target dir:
`CARGO_TARGET_DIR=/tmp/fcp-host-test cargo test -p fcp-host`

### rch worker connectivity

**Symptom:** `rch exec` commands fail with SSH connection errors or
open-circuit worker state.

**Workaround:** Falls back to local build. Use
`CARGO_TARGET_DIR=/tmp/fcp-local-<name>` to avoid lock contention.
Run `rch doctor` and `rch workers probe --all` to diagnose.

### Beads DB corruption

**Symptom:** `br show` or `br close` fails with "malformed disk image" or
"database is locked".

**Workaround:** `br doctor --repair` rebuilds from JSONL. Use
`br sync --flush-only` frequently to keep JSONL as source of truth.

## Regression Triage Workflow

### When a platform crate test fails

1. **Identify the failing crate and test**: `cargo test -p <crate> -- <test_name> --nocapture`
2. **Check if it's a known flake**: Search this document's "Known Flakes" section
3. **Check recent commits**: `git log --oneline -10 -- crates/<crate>/`
4. **Run the specific test in isolation**: `CARGO_TARGET_DIR=/tmp/fcp-triage cargo test -p <crate> -- <test_name>`
5. **If it reproduces**: Investigate root cause, fix, and add a regression test
6. **If it's flaky**: Add to "Known Flakes" section with reproduction conditions

### Before downstream connector work

Run the core platform verification suite:

```bash
rch exec -- cargo test -p fcp-core -p fcp-protocol -p fcp-crypto -p fcp-sdk -p fcp-host
rch exec -- cargo test -p fcp-testkit --test runtime_lifecycle_acceptance
```

If any failure: stop and fix the platform before touching connectors.

### After downstream connector work

Re-run the same suite to verify no regressions:

```bash
rch exec -- cargo test -p fcp-testkit -- live_suite evidence_helpers
rch exec -- cargo test -p fcp-testkit --test runtime_lifecycle_acceptance
```

## File Index

| File | What It Proves |
| --- | --- |
| `crates/fcp-testkit/tests/runtime_lifecycle_acceptance.rs` | Health tracker, supervisor config, polling cursor, streaming session, session-script DSL, evidence, cleanup, HealthState serialization (30 tests) |
| `crates/fcp-testkit/src/live_suite.rs` | Live-suite gating, secrets, cost budget, synthetic tenants, cleanup guards, environment manifests, prerequisite reports (88 tests) |
| `crates/fcp-testkit/src/evidence_helpers.rs` | Evidence collector, audit events, receipts, decisions, secret redaction, swarm-latency scenarios, environment fingerprints, raw samples, p50/p95/p99/p999 summaries, JSONL evidence records, scheduler/placement/backpressure decision cards (34 tests) |
| `crates/fcp-host/src/batch.rs` | Batch dependency validation, deterministic FIFO planning, opt-in adaptive priority/SRPT/fairness scheduling, FIFO counterfactual reports |
| `crates/fcp-host/tests/no_mock_integration.rs` | BudgetPolicyEngine, DoctorService, discovery→introspect→preflight pipeline (2,597 lines) |
| `crates/fcp-host/tests/host_connector_integration.rs` | Real subprocess connector integration (4,207 lines) |
| `crates/fcp-e2e/tests/host_resilience_e2e.rs` | Circuit breaker, bulkhead, adaptive load shedding (73 tests) |
| `crates/fcp-webhook/tests/no_mock_integration.rs` | Full webhook pipeline without mocks (438+ lines) |
| `crates/fcp-sdk/tests/tracing_contract.rs` | Retry/cancellation/runtime tracing (9 tests) |
| `crates/fcp-core/tests/lifecycle_tests.rs` | State machine transitions, persistence, rollback (350+ lines) |
| `docs/testing/live-suite-classification.md` | Connector tier classification (A-E) |
| `docs/testing/coverage-inventory.md` | Full test coverage inventory |
