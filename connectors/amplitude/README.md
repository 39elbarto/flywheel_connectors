# Amplitude Connector V3 Contract

> **Status**: PROVEN runtime contract documented with remote Amplitude verifier proof
> **Bead**: `flywheel_connectors-angoc.16.5`
> **Verification script**: `scripts/e2e/amplitude_connector_verification.sh`
> **Proof**: `/tmp/fcp-amplitude-proof2-20260606T1410Z/summary.json`, sha256 `0c6fc8e4446ffe8556e113a4f2d0d75e8b0bfb99437d740adfb546142e3bb726`, 11 passed steps, rch remotes `vmi1293453`, `vmi1152480`, `vmi1227854`
> **Connector**: `fcp.amplitude`

## Purpose

This document defines the V3 retrofit surface for the existing Amplitude connector. The connector is a read-only analytics adapter that exposes chart query, cohort listing, and event export without taking on the wider Amplitude administration or mutation surface.

## Current Runtime Snapshot

The current crate exposes these operations:

- `amplitude.charts.query`
- `amplitude.cohorts.list`
- `amplitude.events.export`
- `amplitude.health`

Important runtime truths:

- Authentication uses Amplitude Basic auth with both `api_key` and `secret_key`.
- The default base URL is `https://amplitude.com/api/2`.
- `https://analytics.amplitude.com` and `https://amplitude.com` are the intended production hosts.
- The connector is read-only. It does not ingest events, mutate cohorts, edit dashboards, or administer workspace settings.

## Scope Boundary

This retrofit keeps the connector intentionally narrow:

- query a chart by ID
- list cohorts
- export events for a bounded date range
- prove readiness and operator guidance through health, doctor, self-check, and introspection evidence

Explicit non-goals for this slice:

- event ingestion or cohort mutation
- dashboard, experiment, or user management
- admin or billing APIs
- any write-capable analytics workflow

## Auth And Zone Expectations

- Home zone is `z:work`.
- Required capabilities are network egress, DNS, TLS SNI, and connector state storage.
- Live verification requires concrete Basic-auth credentials; there is no secretless credential injection mode in this retrofit.

## Network And Runtime Invariants

- Production default hosts: `analytics.amplitude.com`, `amplitude.com`
- HTTPS required for non-local targets
- Localhost overrides are allowed only for deterministic tests
- Connector remains read-only even when upstream Amplitude plans expose richer mutation APIs

## Operation Inventory

| Operation | Capability | SafetyTier | RiskLevel | Idempotency | Purpose |
|-----------|------------|------------|-----------|-------------|---------|
| `amplitude.charts.query` | `amplitude.charts.read` | `Safe` | `Low` | `Strict` | Query one Amplitude chart by chart ID. |
| `amplitude.cohorts.list` | `amplitude.cohorts.read` | `Safe` | `Low` | `Strict` | List cohort metadata visible to the configured credentials. |
| `amplitude.events.export` | `amplitude.events.read` | `Safe` | `Low` | `Strict` | Export raw events for a caller-bounded date range. |
| `amplitude.health` | `amplitude.cohorts.read` | `Safe` | `Low` | `Strict` | Verify credentials and Amplitude API reachability. |

## Operator Guidance

- Use dedicated Amplitude service credentials scoped to the analytics project that should be visible to this connector.
- Keep event export windows narrow; the manifest caps the response at 50 MiB, but the upstream export can still include sensitive product analytics payloads.
- Run `amplitude.health` before chart, cohort, or event-export operations when validating a fresh deployment.
- Treat localhost and non-HTTPS base URLs as test-only overrides, not production provider targets.

Rerun commands:

- `env -u CARGO_TARGET_DIR RUN_ID=manual-amplitude bash scripts/e2e/amplitude_connector_verification.sh`
- `scripts/graduation/run_gauntlet.sh connectors/amplitude`

## Readiness And Verification

Verification is replayed through:

```bash
scripts/e2e/amplitude_connector_verification.sh
```

Promotion proof `purple-amplitude-proof2-20260606T1410Z` passed the tracked verifier with accepted remote Cargo proof for manifest validation, crate check, health/doctor/self-check/compliance evidence, full integration tests, crate-local tests, and clippy, plus source-state formatting.

Artifacts land under:

```text
artifacts/e2e/amplitude_connector/<timestamp>
```

The readiness contract should surface these operator truths:

- whether the configured base URL satisfies Amplitude host policy
- whether both Basic-auth secrets are present
- whether live `amplitude.health` and `amplitude.cohorts.list` probes succeed
- that the connector is intentionally limited to read-only analytics metadata and export flows

The gated sandbox live suite uses `FCP_LIVE_SANDBOX=1` plus `AMPLITUDE_SANDBOX_API_KEY`, `AMPLITUDE_SANDBOX_SECRET_KEY`, `AMPLITUDE_SANDBOX_PROJECT_ID`, and `FCP_SANDBOX_RUN_NAMESPACE`. `AMPLITUDE_SANDBOX_BASE_URL` defaults to `https://amplitude.com/api/2`.
The live suite performs the idempotent `amplitude.health` auth/reachability
probe plus read-only `amplitude.cohorts.list`, records a two-call ceiling, and
does not ingest events or mutate analytics project state.

Focused live-suite rerun:

```bash
rch exec -- cargo test -p fcp-amplitude --test live_verification -- --nocapture
```
