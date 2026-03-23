# PostHog Connector V3 Contract

> **Status**: retrofit contract
> **Bead**: `flywheel_connectors-j05nu.12.6`
> **Connector**: `fcp.posthog`

## Purpose

This document defines the V3 retrofit surface for the existing PostHog connector. The connector is a read-only analytics adapter that exposes HogQL event queries, saved insight listing, and feature flag listing without taking on the broader PostHog product surface.

## Current Runtime Snapshot

The current crate exposes these operations:

- `posthog.events.query`
- `posthog.insights.list`
- `posthog.feature_flags.list`

Important runtime truths:

- Authentication is either a direct PostHog API key or a secretless `credential_id` that depends on host-side injection.
- The default base URL is `https://app.posthog.com/api`.
- Regional SaaS hosts and compliant self-hosted PostHog deployments can be targeted with `base_url` overrides.
- The connector is read-only. It does not capture events, mutate insights, manage feature flags, or edit PostHog project state.

## Scope Boundary

This retrofit keeps the connector intentionally narrow:

- Query events with HogQL.
- List saved insights.
- List feature flags.
- Prove readiness and operator guidance through health, doctor, self-check, and introspection evidence.

Explicit non-goals for this slice:

- event capture or person/profile mutation
- feature flag creation, updates, or rollout changes
- cohort, dashboard, experiment, or survey mutation APIs
- streaming analytics export or webhook ingestion

## Auth And Zone Expectations

- Home zone is `z:work`.
- Required capabilities are network egress, DNS, TLS SNI, and connector state storage.
- `credential_id` mode is supported for host-managed secret injection, but live verification remains degraded until concrete secret material is injected.

## Network And Runtime Invariants

- Production default host: `app.posthog.com`
- Regional hosts: `us.posthog.com`, `eu.posthog.com`
- HTTPS required for non-local targets
- Localhost overrides are allowed only for deterministic tests
- Connector remains read-only even when the upstream PostHog deployment supports writes

## Readiness And Verification

Verification is replayed through:

```bash
scripts/e2e/posthog_connector_verification.sh
```

Artifacts land under:

```text
artifacts/e2e/posthog_connector/<timestamp>
```

The readiness contract should surface these operator truths:

- whether the configured base URL satisfies PostHog host policy
- whether concrete secret material is available or the connector is still waiting for credential injection
- whether a live `posthog.insights.list` probe succeeds
- that the connector is intentionally limited to read-only analytics metadata and query flows
