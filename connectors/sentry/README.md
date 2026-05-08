# Sentry Connector V3 Contract

> **Status**: runtime contract documented with capability-token, approval-token, and webhook-state drift
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Sentry API reference**: https://docs.sentry.io/api/
> **Sentry auth upstream**: https://docs.sentry.io/api/auth/
> **Sentry permissions upstream**: https://docs.sentry.io/api/permissions/

## Purpose

This document fixes the operator-facing contract for `fcp.sentry`. The connector exposes the Sentry Web API surfaces implemented in this crate: project discovery, issue search/read/update/delete, issue events, events and transactions, releases and release health, Discover queries, alert-rule CRUD and enable/disable, issue triage helpers, and performance summary helpers.

The connector is intentionally a bounded Sentry operations and diagnostics bridge. It is not a Sentry SDK ingest endpoint, DSN client, OAuth app install flow, webhook receiver, durable alert/event stream processor, organization/team administration client, source-map uploader, sourcemap release automation tool, or connector-local credential vault.

## Current Runtime Snapshot

The current crate exposes these operations:

- `sentry.list_projects`
- `sentry.list_issues`
- `sentry.get_issue`
- `sentry.update_issue`
- `sentry.delete_issue`
- `sentry.list_issue_events`
- `sentry.get_event`
- `sentry.get_transaction`
- `sentry.list_releases`
- `sentry.get_release`
- `sentry.list_release_deploys`
- `sentry.discover_query`
- `sentry.list_alert_rules`
- `sentry.create_alert_rule`
- `sentry.update_alert_rule`
- `sentry.delete_alert_rule`
- `sentry.get_alert_rule`
- `sentry.enable_alert_rule`
- `sentry.disable_alert_rule`
- `sentry.issue.search`
- `sentry.issue.get_summary`
- `sentry.issue.assign`
- `sentry.issue.set_status`
- `sentry.issue.set_priority`
- `sentry.performance.transactions`
- `sentry.performance.transaction.summary`
- `sentry.performance.trace.summary`
- `sentry.release.health`
- `sentry.release.create`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-sentry`.
- Runtime `BaseConnector` ID is `sentry`.
- Manifest and handshake connector ID are `fcp.sentry`.
- Connector version is `0.1.0`.
- Configuration requires exactly one auth source:
  - `auth_token`
  - `credential_id`
- `credential_id` must be a valid UUID.
- Default base URL is `https://sentry.io/api/0`.
- Optional `base_url` overrides the default and is trimmed of a trailing slash by the client.
- Optional `org_slug` and `project_slug` are used by diagnostics; normal invoke inputs still provide their own organization/project values.
- Direct-token mode sends bearer auth.
- `credential_id` mode sends `X-FCP-Credential-Id: <uuid>`.
- Runtime reqwest timeout is `30 seconds`.
- Runtime request context timeout is `30 seconds`.
- Runtime uses the shared retry loop with `max_retries = 3` for normal client construction.
- Runtime `invoke` uses `operation_id`, not `operation`.
- Runtime `invoke` checks connector readiness, operation identity, required input extraction, and client initialization before dispatch.
- Runtime does not verify `capability_token`.
- Runtime does not verify approval tokens.
- Runtime introspection sets `requires_approval = policy` only for `sentry.release.create`; other side-effecting operations currently report no approval requirement through runtime metadata.
- `simulate` checks only whether `operation_id` is known. It does not validate readiness, input shape, caller authority, capability, approval state, or rate limits.
- `handle_shutdown()` shuts down the client runtime, clears client/config state, and resets configured/handshaken flags.
- `handle_shutdown()` does not clear the stored `session_id` string.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Sentry documents its Web API as API version `v0` and supports bearer auth tokens, OAuth2, DSN auth for limited endpoints, and legacy API keys. Runtime supports only direct bearer tokens and host credential references.
- Sentry docs note region-specific domains such as `us.sentry.io` and `de.sentry.io`. Runtime can use a custom `base_url`, but doctor only checks HTTPS or loopback HTTP prefixes and does not enforce a Sentry-owned host.
- Manifest description mentions webhooks and streaming. Runtime introspection exposes no events, resource types, auth caps, or event caps, and `subscribe` is not implemented in this connector surface.
- Manifest says connector state stores webhook cursor timestamps, event idempotency keys, and auto-create-beads mapping state. Runtime keeps config, session, and request/error counters in memory only.
- Manifest marks alert-rule create/update/delete and release creation as approval-gated. Runtime invoke checks no approval tokens, and runtime metadata only marks `sentry.release.create` with `ApprovalMode::Policy`.
- Runtime has no bound capability-token verifier and no per-operation capability enforcement, despite capability IDs in operation metadata.
- Runtime self-check reports `ok` whenever config exists and does not call Sentry.
- Runtime doctor performs a live `list_projects` auth validation only when `org_slug` is configured. Without `org_slug`, auth validation is skipped as a noncritical degraded check.
- Runtime path segments and query values are percent-encoded, but required-field extraction does not enforce every manifest-schema enum, bound, or semantic constraint.
- Runtime `enable_alert_rule` and `disable_alert_rule` implement status changes with PUT bodies, while manifest text says there is no disable API. Treat runtime behavior as the current contract and the manifest text as stale explanatory drift.
- There is no tracked verification shell script for this connector.

A follow-up parity bead should install bound capability-token verification, enforce approval tokens for writes/deletes/alert and release mutations, align runtime approval metadata with manifest policy, add or remove the advertised webhook/state contract, tighten endpoint policy for Sentry SaaS and self-hosted deployments, and decide whether OAuth/device-flow provisioning belongs in this connector.

## First-Slice Scope

The current Sentry README slice documents the existing runtime surface:

- direct bearer-token configuration and host credential-reference configuration
- optional base URL, organization, and project diagnostic hints
- issue, event, release, Discover, performance, alert-rule, and triage-helper operations
- live doctor behavior, local self-check behavior, retry, timeout, provider error, readiness, simulate, introspect, invoke, and shutdown behavior
- runtime/manifest drift around capability enforcement, approval policy, webhook/event caps, state persistence, endpoint policy, and OAuth provisioning
- deterministic WireMock tests and direct proof commands

## Auth And Zone Boundary

- Authentication mechanisms: Sentry bearer token or host credential reference.
- Official Sentry API access uses bearer auth tokens for normal Web API calls.
- Runtime does not implement Sentry OAuth authorization, token exchange, token refresh, device authorization, DSN auth, legacy API-key auth, internal integration creation, or connector-local credential vaulting.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, `z:work`, and `z:infra`.
- Allowed target zones: `z:work` and `z:infra`.
- Forbidden zones: `z:public` and `z:community`.
- Capability families:
  - `sentry.read`
  - `sentry.write`
  - `sentry.alerts`
  - `sentry.admin`
- Sentry issues, events, stack traces, breadcrumbs, user context, release names, alerts, assignees, performance traces, and Discover rows can expose source paths, secrets, customer data, production request payloads, emails, URLs, and infrastructure topology. Do not log bearer tokens, full event payloads, request bodies, raw error bodies, or personally identifying fields in shared artifacts.

## Network And Runtime Invariants

- Default runtime base URL: `https://sentry.io/api/0`.
- Runtime request timeout: `30 seconds`.
- Runtime retry policy: `max_retries = 3`.
- Runtime auth:
  - `auth_token` uses bearer auth.
  - `credential_id` uses `X-FCP-Credential-Id`.
- Runtime sends JSON request bodies for POST/PUT operations and expects JSON responses.
- Runtime maps successful empty bodies to `{}`.
- Runtime maps 401 to unauthorized, 403 to forbidden, 404 to not found, 429 to rate limited using `Retry-After` with a 60 second default, retryable transport/server failures through the shared retry loop, and other non-success responses to provider API errors.
- Runtime path segments are percent-encoded with `NON_ALPHANUMERIC`.
- Runtime release version encoding covers `%`, `+`, space, and `@`.
- Runtime endpoint families:
  - `/organizations/{org}/projects/`
  - `/projects/{org}/{project}/issues/`
  - `/issues/{issue_id}/`
  - `/issues/{issue_id}/events/`
  - `/projects/{org}/{project}/events/{event_id}/`
  - `/organizations/{org}/releases/`
  - `/organizations/{org}/releases/{version}/deploys/`
  - `/organizations/{org}/releases/{version}/health/`
  - `/organizations/{org}/events/`
  - `/organizations/{org}/events-trace/{trace_id}/`
  - `/projects/{org}/{project}/rules/`
- Manifest live-operation policy requires TLS/SNI, denies localhost, private ranges, tailnet ranges, and IP literals, and allows `sentry.io`, `*.sentry.io`, and `$sentry_host` on port 443.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `300000 ms` wall-clock timeout, read-only `/usr` and `/lib`, writable `$CONNECTOR_STATE`, no exec, and no ptrace.
- The connector does not open inbound sockets.

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Required input |
|-----------|----------------|------------|------------|-----------|-------------|----------------|
| `sentry.list_projects` | `GET /organizations/{org}/projects/` | `sentry.read` | `Safe` | `Low` | `Strict` | `organization_slug`; optional `cursor`. |
| `sentry.list_issues` | `GET /projects/{org}/{project}/issues/` | `sentry.read` | `Safe` | `Low` | `Strict` | `organization_slug`, `project_slug`; optional `query`, `sort`, `cursor`. |
| `sentry.get_issue` | `GET /issues/{issue_id}/` | `sentry.read` | `Safe` | `Low` | `Strict` | `issue_id`. |
| `sentry.update_issue` | `PUT /issues/{issue_id}/` | `sentry.write` | `Risky` | `Medium` | `Strict` | `issue_id`; optional update fields. |
| `sentry.delete_issue` | `DELETE /issues/{issue_id}/` | `sentry.admin` | `Dangerous` | `High` | `Strict` | `issue_id`. |
| `sentry.list_issue_events` | `GET /issues/{issue_id}/events/` | `sentry.read` | `Safe` | `Low` | `Strict` | `issue_id`; optional `full`, `cursor`. |
| `sentry.get_event` | `GET /projects/{org}/{project}/events/{event_id}/` | `sentry.read` | `Safe` | `Low` | `Strict` | `organization_slug`, `project_slug`, `event_id`. |
| `sentry.get_transaction` | `GET /projects/{org}/{project}/events/{event_id}/` | `sentry.read` | `Safe` | `Low` | `Strict` | `organization_slug`, `project_slug`, `event_id`. |
| `sentry.list_releases` | `GET /organizations/{org}/releases/` | `sentry.read` | `Safe` | `Low` | `Strict` | `organization_slug`; optional `project_slug`, `query`, `cursor`. |
| `sentry.get_release` | `GET /organizations/{org}/releases/{version}/` | `sentry.read` | `Safe` | `Low` | `Strict` | `organization_slug`, `version`. |
| `sentry.list_release_deploys` | `GET /organizations/{org}/releases/{version}/deploys/` | `sentry.read` | `Safe` | `Low` | `Strict` | `organization_slug`, `version`. |
| `sentry.discover_query` | `GET /organizations/{org}/events/` | `sentry.read` | `Safe` | `Low` | `Strict` | `organization_slug`, `query`, `fields`; optional time/sort/page fields. |
| `sentry.list_alert_rules` | `GET /projects/{org}/{project}/rules/` | `sentry.read` | `Safe` | `Low` | `Strict` | `organization_slug`, `project_slug`. |
| `sentry.create_alert_rule` | `POST /projects/{org}/{project}/rules/` | `sentry.alerts` | `Risky` | `Medium` | `None` | `organization_slug`, `project_slug`, `name`, `conditions`, `actions`. |
| `sentry.update_alert_rule` | `PUT /projects/{org}/{project}/rules/{rule_id}/` | `sentry.alerts` | `Risky` | `Medium` | `Strict` | `organization_slug`, `project_slug`, `rule_id`. |
| `sentry.delete_alert_rule` | `DELETE /projects/{org}/{project}/rules/{rule_id}/` | `sentry.admin` | `Dangerous` | `High` | `Strict` | `organization_slug`, `project_slug`, `rule_id`. |
| `sentry.get_alert_rule` | `GET /projects/{org}/{project}/rules/{rule_id}/` | `sentry.alerts` | `Safe` | `Low` | `Strict` | `organization_slug`, `project_slug`, `rule_id`. |
| `sentry.enable_alert_rule` | `PUT /projects/{org}/{project}/rules/{rule_id}/` | `sentry.alerts` | `Risky` | `Medium` | `Strict` | `organization_slug`, `project_slug`, `rule_id`. |
| `sentry.disable_alert_rule` | `PUT /projects/{org}/{project}/rules/{rule_id}/` | `sentry.alerts` | `Risky` | `Medium` | `Strict` | `organization_slug`, `project_slug`, `rule_id`. |
| `sentry.issue.search` | `GET /projects/{org}/{project}/issues/` | `sentry.read` | `Safe` | `Low` | `Strict` | `organization_slug`, `project_slug`; optional structured filters. |
| `sentry.issue.get_summary` | `GET /issues/{issue_id}/` | `sentry.read` | `Safe` | `Low` | `Strict` | `issue_id`. |
| `sentry.issue.assign` | `PUT /issues/{issue_id}/` | `sentry.write` | `Risky` | `Medium` | `Strict` | `issue_id`; optional `assignee`. |
| `sentry.issue.set_status` | `PUT /issues/{issue_id}/` | `sentry.write` | `Risky` | `Medium` | `Strict` | `issue_id`, `status`; optional `substatus`. |
| `sentry.issue.set_priority` | `PUT /issues/{issue_id}/` | `sentry.write` | `Risky` | `Medium` | `Strict` | `issue_id`, `priority`. |
| `sentry.performance.transactions` | `GET /organizations/{org}/events/` | `sentry.read` | `Safe` | `Low` | `Strict` | `organization_slug`, `project_slug`; optional performance filters. |
| `sentry.performance.transaction.summary` | `GET /organizations/{org}/events/` | `sentry.read` | `Safe` | `Low` | `Strict` | `organization_slug`, `project_slug`, `transaction`. |
| `sentry.performance.trace.summary` | `GET /organizations/{org}/events-trace/{trace_id}/` | `sentry.read` | `Safe` | `Low` | `Strict` | `organization_slug`, `trace_id`. |
| `sentry.release.health` | `GET /organizations/{org}/releases/{version}/health/` | `sentry.read` | `Safe` | `Low` | `Strict` | `organization_slug`, `project_slug`, `version`. |
| `sentry.release.create` | `POST /organizations/{org}/releases/` | `sentry.write` | `Risky` | `Medium` | `None` | `organization_slug`, `version`; optional `projects`, `ref`, `url`. |

## Explicit Non-Goals

The current implementation does not include:

- SDK event ingest, envelope ingest, DSN auth, source-map upload, debug-file upload, or CLI release artifact automation
- Sentry OAuth authorization, token refresh, internal integration creation, personal-token creation, or device authorization
- organization, team, member, role, project-creation, billing, relay, replay, cron monitor, or uptime monitor administration
- webhooks, inbound listeners, provider event subscriptions, replay buffers, streaming, or durable cursor storage
- automatic Beads issue creation from Sentry alerts
- full Discover query planner, saved queries, dashboards, metrics API abstraction, or Snuba schema validation
- connector-local storage of tokens, issue payloads, stack traces, event contexts, release metadata, alert definitions, or query results
- direct FCP capability-token or approval-token verification at connector invoke time

These are excluded on purpose:

- Sentry payloads often contain production stack traces, request context, user context, and breadcrumbs.
- Issue deletion and alert changes mutate operational incident data.
- Release and Discover operations can expose internal repository names, deploy cadence, and system topology.
- Webhook and streaming semantics need persistence and replay behavior that this runtime does not yet have.

## Readiness And Verification Surface

`handle_doctor()`, `handle_health()`, `handle_self_check()`, `handle_simulate()`, and `handle_introspect()` are part of the public closeout contract. They surface:

- configuration, auth mode, client, and handshake state
- optional live auth/project validation when `org_slug` and `project_slug` are configured
- endpoint scheme checks
- in-memory request/error counters
- known operation metadata, schemas, capability IDs, risk levels, safety tiers, idempotency, and AI hints
- known versus unknown operation simulation
- provider error mapping for unauthorized, forbidden, not found, rate-limit, API, JSON, and transport failures

The deterministic integration evidence is anchored on connector-local tests covering:

- configure, credential-id mode, missing/both auth rejection, handshake, health, doctor, self-check, introspection, simulation, shutdown, and counters
- project listing, issue listing/search/summary/get/update/delete, issue events, event and transaction reads
- release list/get/deploys/health/create
- Discover and performance query helpers
- alert rule list/create/update/get/delete/enable/disable
- provider 401, 403, 404, 429, and 500 behavior
- missing operation and missing required input behavior

## Source Notes

- `connectors/sentry/src/connector.rs` defines configuration parsing, lifecycle handlers, diagnostics, introspection, simulation, invoke dispatch, operation IDs, operation metadata, and provisioning diagnostics.
- `connectors/sentry/src/client.rs` defines Sentry HTTP request construction, auth headers, retry/timeout behavior, endpoint paths, path/query encoding, and provider error mapping.
- `connectors/sentry/src/types.rs` defines provider response and error envelope shapes.
- `connectors/sentry/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/sentry/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, state claims, rate-limit pools, and AI hints.
- `connectors/sentry/tests/integration.rs` covers deterministic HTTP behavior and connector lifecycle behavior.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/sentry/README.md
ubs connectors/sentry/README.md
LC_ALL=C rg -n '[^ -~]' connectors/sentry/README.md
rg -n '\bmaster\b' connectors/sentry/README.md
```

For source or behavior changes, also run the connector proof lane through `rch`:

```bash
rch exec -- cargo test -p fcp-sentry
rch exec -- cargo check -p fcp-sentry --all-targets
rch exec -- cargo clippy -p fcp-sentry --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

## Operator Guidance

- Treat `sentry.update_issue`, `sentry.delete_issue`, `sentry.issue.assign`, `sentry.issue.set_status`, `sentry.issue.set_priority`, alert-rule mutations, and `sentry.release.create` as approval-gated until runtime approval enforcement lands.
- Configure `org_slug` for doctor when you need live token validation; self-check alone is only a local configured/not-configured status.
- Use `credential_id` only in environments where the host egress layer is known to inject bearer material.
- Do not treat this connector as a webhook/event stream until event caps and persistent cursor state exist.
