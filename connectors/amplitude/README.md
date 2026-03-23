# Amplitude Connector V3 Contract

> **Status**: retrofit contract
> **Bead**: `flywheel_connectors-j05nu.12.6`
> **Connector**: `fcp.amplitude`

## Purpose

This document defines the V3 retrofit surface for the existing Amplitude connector. The connector is a read-only analytics adapter that exposes chart query, cohort listing, and event export without taking on the wider Amplitude administration or mutation surface.

## Current Runtime Snapshot

The current crate exposes these operations:

- `amplitude.charts.query`
- `amplitude.cohorts.list`
- `amplitude.events.export`

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

## Readiness And Verification

Verification is replayed through:

```bash
scripts/e2e/amplitude_connector_verification.sh
```

Artifacts land under:

```text
artifacts/e2e/amplitude_connector/<timestamp>
```

The readiness contract should surface these operator truths:

- whether the configured base URL satisfies Amplitude host policy
- whether both Basic-auth secrets are present
- whether a live `amplitude.cohorts.list` probe succeeds
- that the connector is intentionally limited to read-only analytics metadata and export flows
