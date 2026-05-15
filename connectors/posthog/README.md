# PostHog Connector V3 Contract

> **Status**: retrofit contract
> **Bead**: `flywheel_connectors-j05nu.12.6`
> **Connector**: `fcp.posthog`

## Purpose

This document defines the V3 retrofit surface for the existing PostHog connector. The connector exposes read-only HogQL event queries, saved insight listing, and feature flag listing, plus a narrow sandbox-scoped event capture path used for live-proof ingestion checks.

## Current Runtime Snapshot

The current crate exposes these operations:

- `posthog.events.query`
- `posthog.events.capture`
- `posthog.insights.list`
- `posthog.feature_flags.list`

Important runtime truths:

- Read authentication is either a direct PostHog personal API key or a secretless `credential_id` that depends on host-side injection.
- Event capture requires a PostHog project API key and should only target dedicated sandbox projects.
- The default base URL is `https://app.posthog.com/api`.
- Regional SaaS hosts and compliant self-hosted PostHog deployments can be targeted with `base_url` and `capture_url` overrides.
- The connector does not mutate insights, manage feature flags, create aliases, identify persons/groups, or edit PostHog project state.

## Scope Boundary

This retrofit keeps the connector intentionally narrow:

- Query events with HogQL.
- Capture one namespaced sandbox event for verification.
- List saved insights.
- List feature flags.
- Prove readiness and operator guidance through health, doctor, self-check, and introspection evidence.

Explicit non-goals for this slice:

- production event capture or person/profile mutation
- feature flag creation, updates, or rollout changes
- cohort, dashboard, experiment, or survey mutation APIs
- streaming analytics export or webhook ingestion

## Auth And Zone Expectations

- Home zone is `z:work`.
- Required capabilities are network egress, DNS, TLS SNI, and connector state storage.
- `credential_id` mode is supported for host-managed personal-key injection, but live verification remains degraded until concrete secret material is injected.
- Project API keys are accepted only for event capture and must not be logged.

## Network And Runtime Invariants

- Production default host: `app.posthog.com`
- Regional hosts: `us.posthog.com`, `eu.posthog.com`
- Event capture uses PostHog ingestion hosts (`us.i.posthog.com`, `eu.i.posthog.com`) or the configured self-hosted origin's `/i/v0/e/` path
- HTTPS required for non-local targets
- Localhost overrides are allowed only for deterministic tests
- Capture operations must use namespaced sandbox distinct IDs and set `$process_person_profile=false` when the caller does not intend to create person profiles

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
- whether a live `posthog.events.capture` sandbox probe succeeds
- that the connector is intentionally limited to read/list analytics metadata and one sandbox-scoped event-capture flow

Live sandbox verification requires:

- `FCP_LIVE_SANDBOX=1`
- `POSTHOG_SANDBOX_HOST`
- `POSTHOG_SANDBOX_PERSONAL_API_KEY`
- `POSTHOG_SANDBOX_PROJECT_API_KEY`
- `POSTHOG_SANDBOX_PROJECT_ID`
- `FCP_SANDBOX_RUN_NAMESPACE`
