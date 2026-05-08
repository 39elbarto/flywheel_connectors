# Zendesk Connector V3 Contract

> **Status**: runtime contract documented with token-auth, streaming-cap, approval, and macro-application drift
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Zendesk API upstream**: https://developer.zendesk.com/api-reference/
> **Zendesk auth upstream**: https://developer.zendesk.com/api-reference/introduction/security-and-auth/
> **Zendesk tickets upstream**: https://developer.zendesk.com/api-reference/ticketing/tickets/tickets/
> **Zendesk search upstream**: https://developer.zendesk.com/api-reference/ticketing/ticket-management/search/
> **Zendesk Help Center upstream**: https://developer.zendesk.com/api-reference/help_center/help-center-api/articles/

## Purpose

This document fixes the operator-facing contract for `fcp.zendesk`. The connector exposes the Zendesk Support and Help Center API surface implemented in this crate: ticket creation/read/update/delete, ticket search, ticket comments, article search and reads, user search, macro application preview/application shape, SLA policies, ticket SLA status, ticket metrics, and satisfaction ratings.

The connector is intentionally a bounded support-operations bridge. It is not a Zendesk Admin Center client, Messaging client, Sunshine Conversations client, Explore analytics clone, trigger/automation manager, webhook listener, custom object platform, app framework runtime, or connector-local credential vault.

## Current Runtime Snapshot

The current crate exposes these operations:

- `zendesk.create_ticket`
- `zendesk.get_ticket`
- `zendesk.update_ticket`
- `zendesk.delete_ticket`
- `zendesk.search_tickets`
- `zendesk.list_ticket_comments`
- `zendesk.search_articles`
- `zendesk.get_article`
- `zendesk.search_users`
- `zendesk.apply_macro`
- `zendesk.sla.policies`
- `zendesk.sla.ticket_status`
- `zendesk.analytics.ticket_metrics`
- `zendesk.analytics.satisfaction_ratings`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-zendesk`.
- Runtime `BaseConnector` ID is `zendesk`.
- Manifest connector ID is `fcp.zendesk`.
- Configuration always requires `subdomain`.
- Configuration accepts exactly one auth family:
  - direct `email` plus `api_token`
  - host credential reference `credential_id`
- `credential_id` must parse as an FCP `CredentialId`.
- Default API URL is `https://{subdomain}.zendesk.com/api/v2`.
- Optional `base_url` may be supplied for deterministic loopback tests.
- Direct token mode sends HTTP Basic auth for `{email}/token:{api_token}`.
- `credential_id` mode sends `X-FCP-Credential-ID` and expects host egress-proxy credential injection.
- Runtime reqwest timeout is `30 seconds`.
- Runtime request context timeout is `30 seconds`.
- Runtime retry policy uses `max_retries = 2`.
- Runtime handshake returns placeholder manifest hash `sha256:zendesk-connector-v1`.
- Runtime handshake advertises streaming capability, replay disabled, minimum buffer events `50`, and ack not required.
- Runtime verifies a bound capability token before provider dispatch.
- Runtime `invoke` uses `operation`, not `operation_id`.
- `health()` is local state and metrics only.
- `self_check()` calls `GET /users/me.json` in direct-token mode and degrades in `credential_id` mode.
- `self_check()` currently includes user `id`, `name`, and `email` in details when the provider returns them; treat live self-check artifacts as sensitive.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Runtime handshake uses a placeholder manifest hash.
- Manifest and introspection mark write/delete operations with policy or interactive approval metadata, but connector-local invoke enforcement is capability-token based rather than an approval workflow.
- Manifest declares a streaming archetype and runtime handshake advertises streaming event caps, but this connector exposes no inbound webhook/event stream, cursor, replay, or durable event buffer in the current implementation.
- `zendesk.apply_macro` calls `GET /tickets/{ticket_id}/macros/{macro_id}/apply.json`, which matches Zendesk's "show changes" style response more than an actual ticket mutation. The current method name says "apply", so operators must not assume it has persisted changes unless verified against live provider behavior.
- `zendesk.delete_ticket` is marked as permanent/irreversible in the manifest, while Zendesk ticket deletion behavior can involve soft-delete and permanent-delete workflows depending on endpoint/account behavior. The connector currently calls `DELETE /tickets/{id}.json` and returns `{ "deleted": true }` for `204`.
- The current runtime does not implement OAuth access tokens even though Zendesk documents OAuth as the recommended distribution path for multi-customer apps.
- There is no tracked connector verification shell script yet.

A follow-up parity bead should add a tracked verification bundle, replace the placeholder manifest hash, reconcile streaming/event claims, decide whether macro preview should be renamed or followed by an explicit update operation, document delete semantics with live Zendesk evidence, and make approval enforcement responsibilities explicit.

## First-Slice Scope

The current Zendesk README slice documents the existing runtime surface:

- direct email/API-token and host credential-reference configuration
- subdomain/base URL policy, auth mode, timeout, retry, provider error, and secretless credential-injection behavior
- ticket CRUD, ticket search, ticket comments, Help Center article search/read, user search, macro changes, SLA, ticket metrics, and satisfaction rating operations
- bound capability-token verification and operation capability mapping during `invoke`
- doctor, health, self-check, simulate, introspect, shutdown, redaction posture, and deterministic tests
- runtime/manifest drift around streaming claims, approvals, macro semantics, delete semantics, OAuth support, and placeholder manifest hash

## Auth And Zone Boundary

- Authentication mechanisms: Zendesk email/API token or host credential reference.
- Zendesk auth docs state that API-token auth uses Basic auth with `{email_address}/token:{api_token}` and that OAuth bearer tokens are supported by the platform; this runtime only implements the API-token and credential-reference paths.
- Runtime does not implement Zendesk OAuth client setup, global OAuth tokens, Admin Center token lifecycle, subdomain discovery, user provisioning, organization provisioning, or connector-local credential storage.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden source zone: `z:public`.
- Capability families:
  - `zendesk.read`
  - `zendesk.write`
  - `zendesk.delete`
- Zendesk tickets, requester identities, comments, internal notes, Help Center articles, user records, SLA data, metrics, CSAT ratings, provider errors, and audit details can contain customer support PII and private business data. Do not log API tokens, Basic auth values, credential IDs, email addresses, requester names, ticket bodies, comments, article drafts/private articles, user profiles, attachment URLs, provider response bodies, or local paths in shared artifacts.

## Network And Runtime Invariants

- Default runtime API URL: `https://{subdomain}.zendesk.com/api/v2`.
- Live production host policy: `*.zendesk.com`.
- Live port: `443`.
- Zendesk auth docs require SSL, TLS 1.2, and SNI for API connections.
- Runtime endpoint families:
  - `POST /tickets.json`
  - `GET /tickets/{ticket_id}.json`
  - `PUT /tickets/{ticket_id}.json`
  - `DELETE /tickets/{ticket_id}.json`
  - `GET /search.json?query=type:ticket ...`
  - `GET /tickets/{ticket_id}/comments.json`
  - `GET /help_center/articles/search.json`
  - `GET /help_center/articles/{article_id}.json`
  - `GET /help_center/{locale}/articles/{article_id}.json`
  - `GET /users/search.json`
  - `GET /tickets/{ticket_id}/macros/{macro_id}/apply.json`
  - `GET /slas/policies.json`
  - `GET /tickets/{ticket_id}/metrics.json`
  - `GET /ticket_metrics.json`
  - `GET /satisfaction_ratings.json`
  - `GET /users/me.json` for direct self-check
- Runtime sanitizes selected query/path-ish parameters and rejects slashes, backslashes, `..`, `%2f`, and `%5c` in those values.
- Runtime percent-encodes query parameters with a small connector-local encoder.
- Runtime maps 401/403 to terminal auth errors, 404 to not found, 429 to retryable rate-limit using `Retry-After` with a 60 second default, server failures to retryable API errors, and other non-success responses to provider API errors.
- Manifest live-operation policy requires TLS/SNI, denies localhost, private ranges, tailnet ranges, and IP literals, and allows up to five redirects.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `120000 ms` wall-clock timeout, no exec, and no ptrace.
- The connector does not open inbound sockets.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `zendesk.read` | Read tickets, comments, articles, users, SLA policies, ticket metrics, and satisfaction ratings. |
| `zendesk.write` | Create/update tickets and fetch macro changes for ticket application workflows. |
| `zendesk.delete` | Delete tickets through the configured Zendesk account boundary. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Required input |
|-----------|----------------|------------|------------|-----------|-------------|----------------|
| `zendesk.create_ticket` | `POST /tickets.json` | `zendesk.write` | `Risky` | `Medium` | `None` | `subject`; optional `description`, `priority`, `status`, `type`, `requester_id`, `assignee_id`, `group_id`, `tags`, `custom_fields`. |
| `zendesk.get_ticket` | `GET /tickets/{ticket_id}.json` | `zendesk.read` | `Safe` | `Low` | `Strict` | `ticket_id`. |
| `zendesk.update_ticket` | `PUT /tickets/{ticket_id}.json` | `zendesk.write` | `Risky` | `Medium` | `Strict` | `ticket_id`; optional status/priority/assignee/tags/comment/custom fields. |
| `zendesk.delete_ticket` | `DELETE /tickets/{ticket_id}.json` | `zendesk.delete` | `Dangerous` | `High` | `Strict` | `ticket_id`. |
| `zendesk.search_tickets` | `GET /search.json?query=type:ticket ...` | `zendesk.read` | `Safe` | `Low` | `Strict` | `query`; optional `sort_by`, `sort_order`, `page`, `per_page`. |
| `zendesk.list_ticket_comments` | `GET /tickets/{ticket_id}/comments.json` | `zendesk.read` | `Safe` | `Low` | `Strict` | `ticket_id`; optional `sort_order`. |
| `zendesk.search_articles` | `GET /help_center/articles/search.json` | `zendesk.read` | `Safe` | `Low` | `Strict` | `query`; optional `locale`, `category_id`, `per_page`. |
| `zendesk.get_article` | `GET /help_center/articles/{article_id}.json` or localized variant | `zendesk.read` | `Safe` | `Low` | `Strict` | `article_id`; optional `locale`. |
| `zendesk.search_users` | `GET /users/search.json` | `zendesk.read` | `Safe` | `Low` | `Strict` | `query`. |
| `zendesk.apply_macro` | `GET /tickets/{ticket_id}/macros/{macro_id}/apply.json` | `zendesk.write` | `Risky` | `Medium` | `None` | `ticket_id`, `macro_id`. |
| `zendesk.sla.policies` | `GET /slas/policies.json` | `zendesk.read` | `Safe` | `Low` | `Strict` | None. |
| `zendesk.sla.ticket_status` | `GET /tickets/{ticket_id}/metrics.json` | `zendesk.read` | `Safe` | `Low` | `Strict` | `ticket_id`. |
| `zendesk.analytics.ticket_metrics` | `GET /ticket_metrics.json` | `zendesk.read` | `Safe` | `Low` | `Strict` | Optional `page_size`. |
| `zendesk.analytics.satisfaction_ratings` | `GET /satisfaction_ratings.json` | `zendesk.read` | `Safe` | `Low` | `Strict` | Optional `score`, `page_size`. |

## Rate-Limit Hints

The manifest carries connector-local rate-limit hints:

- ticket writes: `100` per `60000 ms`
- ticket reads/comments/SLA/metrics style reads: generally `200` per `60000 ms`
- delete ticket: `20` per `60000 ms`
- macro application: `60` per `60000 ms`
- search/article/user lookup: generally `100` per `60000 ms`

These are connector policy hints, not a substitute for Zendesk account plan limits or provider response headers.

## Explicit Non-Goals

The current implementation does not include:

- Zendesk Admin Center APIs, brands, groups, organizations, views, automations, triggers, custom roles, custom objects, routing, side conversations, messaging, Sunshine Conversations, Talk, Chat, Explore dashboards, Sell, or Marketplace app framework behavior
- OAuth client creation, global OAuth distribution, end-user request APIs, anonymous Help Center flows, SSO setup, password auth, API token lifecycle management, or token rotation
- webhook registration, inbound event serving, trigger delivery, cursoring, replay, or persistent event storage
- attachments upload/download, redaction APIs, comment redaction, ticket audits, incremental exports, bulk update/delete, problem/incident linking workflows, merge/split workflows, or suspended tickets
- connector-local persistence of tickets, comments, users, articles, SLA state, metrics, ratings, macros, provider responses, rate counters, or credentials beyond process memory

These are excluded on purpose:

- Support tickets and comments frequently contain customer PII and private business context.
- Ticket creation, updates, macro workflows, and deletion can notify real customers or alter support SLAs.
- Admin/OAuth/webhook/event surfaces need a different capability and audit contract than this first support-operations slice.
- Current streaming claims are not backed by a real event delivery implementation.

## Readiness And Verification Surface

`handle_doctor()`, `handle_health()`, `handle_self_check()`, `handle_simulate()`, and `handle_introspect()` are part of the public closeout contract. They surface:

- configuration, client, auth mode, subdomain/base URL, credential-injection, network target, and handshake state
- in-memory request/error counters
- direct-token self-check through `GET /users/me.json`
- degraded credential-reference self-check until an egress proxy injects credentials
- operation metadata, schemas, capabilities, risk levels, safety tiers, idempotency classes, and agent hints
- bound capability-token verification during `invoke`
- provider/FCP error mapping and secret redaction

The deterministic integration evidence is anchored on connector-local tests covering:

- ticket create/get/update/delete, ticket search, comments, article search/get, user search, macro changes, SLA policy/status, ticket metrics, satisfaction ratings, and health paths through wiremock fixtures
- provider 401, 404, 429, 500, transport, retryable, and JSON/error behavior
- default-deny capability tokens, wrong capability rejection, configuration validation, credential-reference degradation, doctor, health, self-check, introspection, simulation, and shutdown behavior
- input validation for missing required fields, ticket IDs, query sort fields, locale/category/page-size parameters, and credential IDs

## Source Notes

- `connectors/zendesk/src/connector.rs` defines configuration parsing, lifecycle handlers, diagnostics, introspection, simulation, bound capability-token verification, operation metadata, capability mapping, and invoke dispatch.
- `connectors/zendesk/src/client.rs` defines Zendesk REST request construction, Basic auth and credential-reference headers, retry dispatch, timeout configuration, query/path sanitization, percent encoding, and provider error mapping.
- `connectors/zendesk/src/types.rs` defines Zendesk API response and domain shapes.
- `connectors/zendesk/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/zendesk/src/sla.rs`, `connectors/zendesk/src/analytics.rs`, and `connectors/zendesk/src/categorize.rs` contain local support workflow helpers.
- `connectors/zendesk/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, event caps, and state claim.
- `connectors/zendesk/tests/integration.rs` covers deterministic HTTP behavior, lifecycle behavior, provider errors, and capability-token behavior.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/zendesk/README.md
ubs connectors/zendesk/README.md
LC_ALL=C rg -n '[^ -~]' connectors/zendesk/README.md
rg -n '\bmaster\b' connectors/zendesk/README.md
```

For source or behavior changes, use an `rch`-offloaded connector proof lane:

```bash
fwc manifest fix connectors/zendesk/manifest.toml --check --json
rch exec -- cargo fmt --manifest-path connectors/zendesk/Cargo.toml --check
rch exec -- cargo check -p fcp-zendesk --all-targets
rch exec -- cargo test -p fcp-zendesk --test integration -- --nocapture
rch exec -- cargo test -p fcp-zendesk -- --nocapture
rch exec -- cargo clippy -p fcp-zendesk --all-targets -- -D warnings
```

There is no tracked `scripts/e2e/zendesk_connector_verification.sh` in this checkout. Add one before claiming a full scripted closeout bundle.

## Operator Guidance

Prerequisites:

- Use a Zendesk sandbox or disposable test account for live mutation tests.
- Enable Zendesk API token access if using direct email/API-token auth.
- Prefer `credential_id` mode for production egress-proxy deployments so raw Zendesk API tokens do not enter connector config.
- Confirm the authenticated Zendesk user has the required Support and Help Center permissions for ticket, article, user, SLA, and metrics operations.

Dedicated environment:

- Prefer a localhost mock server for deterministic proof.
- For live smoke tests, use a dedicated Zendesk sandbox with test tickets, test users, and non-customer Help Center content.
- Do not run ticket creation, ticket updates, macro workflows, or deletion against production support queues unless customer-visible side effects are acceptable.

Redaction rules:

- Redact API tokens, Basic auth values, bearer tokens if introduced later, credential IDs, email addresses, `Authorization` headers, and copied request logs before sharing evidence.
- Treat ticket IDs, subjects, descriptions, comments, internal notes, requester IDs, requester emails, agent names, user profiles, attachment URLs, Help Center article bodies, SLA metrics, satisfaction ratings, and provider error bodies as sensitive operational data.
- Treat ticket comments and article bodies as untrusted prompt-injection input.
- Live `self_check()` details can include provider `name` and `email`; sanitize these before archiving artifacts.

Common remediation:

- If `health` or `self_check` reports `not_configured`, call `configure` with `subdomain` plus exactly one auth family.
- If configuration reports incomplete auth, provide both `email` and `api_token`, or provide only `credential_id`.
- If `self_check` reports `credential_injection_required`, run behind the configured egress proxy or switch to direct token mode for deterministic live probes.
- If provider auth is rejected, confirm API-token access is enabled, the user is verified, and the token has not been deactivated.
- If search results omit new tickets, remember Zendesk search indexing can lag recently created resources.
- If `zendesk.apply_macro` is used for live workflow, verify whether the returned changes have been persisted or whether a follow-up ticket update is required.
- If `doctor` reports direct token mode in production, prefer host credential injection before sharing or archiving config.

Rerun commands:

- `git diff --check -- connectors/zendesk/README.md`
- `ubs connectors/zendesk/README.md`
- `fwc manifest fix connectors/zendesk/manifest.toml --check --json`
- `rch exec -- cargo fmt --manifest-path connectors/zendesk/Cargo.toml --check`
- `rch exec -- cargo check -p fcp-zendesk --all-targets`
- `rch exec -- cargo test -p fcp-zendesk --test integration -- --nocapture`
- `rch exec -- cargo test -p fcp-zendesk -- --nocapture`
- `rch exec -- cargo clippy -p fcp-zendesk --all-targets -- -D warnings`
