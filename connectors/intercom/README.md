# Intercom Connector V3 Contract

> **Status**: runtime contract documented with contact-delete capability and regional-host drift
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Intercom REST API upstream**: https://developers.intercom.com/docs/references/rest-api/api.intercom.io
> **Contacts upstream**: https://developers.intercom.com/docs/references/rest-api/api.intercom.io/contacts/listcontacts
> **Create contact upstream**: https://developers.intercom.com/docs/references/rest-api/api.intercom.io/contacts/createcontact
> **Delete contact upstream**: https://developers.intercom.com/docs/references/rest-api/api.intercom.io/contacts/deletecontact
> **Conversations upstream**: https://developers.intercom.com/docs/references/rest-api/api.intercom.io/conversations/listconversations
> **Conversation reply upstream**: https://developers.intercom.com/docs/references/rest-api/api.intercom.io/conversations/replyconversation
> **Tags upstream**: https://developers.intercom.com/docs/references/rest-api/api.intercom.io/tags/listtags

## Purpose

This document fixes the operator-facing contract for `fcp.intercom`. The connector exposes the Intercom customer-messaging surfaces implemented in this crate: contacts list/create/delete, conversations list/reply, and tags list.

The connector is intentionally a bounded customer-support bridge. It is not a full Intercom platform SDK, Help Center client, AI Content client, webhook receiver, Messenger automation builder, data export client, admin client, article manager, company manager, ticketing client, or durable CRM sync.

## Current Runtime Snapshot

The current crate exposes these operations:

- `intercom.contacts.list`
- `intercom.contacts.create`
- `intercom.contacts.delete`
- `intercom.conversations.list`
- `intercom.conversations.reply`
- `intercom.tags.list`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-intercom`.
- Runtime `BaseConnector` ID is `intercom`.
- Manifest connector ID is `fcp.intercom`.
- Runtime connector version returned by handshake is `0.1.0`.
- Configuration requires exactly one auth source:
  - `access_token`
  - `credential_id`
- `access_token` mode sends `Authorization: Bearer <token>`.
- `credential_id` must be a valid UUID and sends `X-FCP-Credential-Id: <uuid>`.
- Default base URL is `https://api.intercom.io`.
- Runtime accepts exact Intercom regional hosts `api.intercom.io`, `api.eu.intercom.io`, and `api.au.intercom.io` over HTTPS.
- Runtime accepts localhost, `127.0.0.1`, and `::1` for tests.
- Runtime rejects base URLs with userinfo, query strings, or fragments.
- Runtime reqwest timeout is `30 seconds`.
- Runtime request-context timeout is `30 seconds`.
- Runtime stores a retry config with `max_retries = 3`, but normal GET/POST/DELETE helpers currently send one reqwest request and do not run a retry loop.
- Provider error bodies are truncated to 2048 bytes before API errors are surfaced.
- HTTP 401 maps to unauthorized, 403 maps to forbidden, 404 maps to not-found, and 429 maps to rate-limited with `Retry-After` support.
- `contact_id` and `conversation_id` path segments are allow-listed to ASCII alphanumeric, `-`, and `_`, with a 256-byte maximum.
- `health` reports local configured state, session-ID-backed handshaken state, request count, and error count.
- `doctor` checks local configuration, client initialization, and session-ID-backed handshake state.
- `self_check` reports local provisioning readiness and returns `credential_injection_required` for credential-id mode. It does not call Intercom.
- `handle_shutdown` shuts down the client runtime, clears config/client state, and resets configured and handshaken flags.
- `invoke` only checks connector ready state and operation ID. It does not require or verify an FCP capability token in this checkout.
- `simulate` only checks whether an operation ID is known. It does not check configured state, handshake state, approval policy, or capability tokens.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Runtime `BaseConnector` ID is `intercom`, while the manifest and handshake use `fcp.intercom`.
- Runtime handshake and introspection use a dedicated `intercom.contacts.delete` capability for destructive delete, but the manifest operation, optional capabilities, and rate-limit operation pool still place `intercom.contacts.delete` under `intercom.contacts.write`.
- Runtime host policy accepts official EU and AU regional API hosts, while each manifest operation currently allows only `api.intercom.io`.
- Runtime `health` treats a handshake without `session_id` as not handshaken because it checks `session_id.is_some()`, while `BaseConnector` readiness is set during handshake regardless of `session_id`.
- Runtime `doctor` does not include auth-mode, endpoint-policy, or credential-injection diagnostics; `self_check` carries those details.
- Runtime direct HTTP requests do not currently use the stored retry configuration.
- Runtime `contacts.list` implements only `per_page` and `starting_after`; it does not implement the Intercom contacts search endpoint or manifest `query` schema.
- Runtime `conversations.reply` always sends an admin-shaped body with `"type": "admin"` and defaults `admin_id` to `"0"` when omitted. Current Intercom docs support multiple reply variants with explicit admin or contact fields.
- Runtime `invoke` does not verify bound capability tokens for reads, writes, replies, or deletes.
- Runtime `simulate` can allow a known operation before configuration or handshake because it only checks the static operation inventory.
- Runtime operation metadata sets `requires_approval = None` in introspection, while the manifest marks create/reply as policy-gated and delete as interactive.

A follow-up parity bead should align connector ID spelling, reconcile the destructive delete capability across runtime, manifest, and rate-limit pools, add regional hosts to manifest network constraints or remove runtime regional allowance, make health and BaseConnector handshake semantics agree, route HTTP through the retry policy, implement contacts search or remove the schema hint, tighten conversation reply variant handling, and add bound capability-token verification.

## First-Slice Scope

The current Intercom README slice documents the existing runtime surface:

- bearer-token and credential-id configuration
- contacts list/create/delete operations
- conversations list/reply operations
- tags list operation
- regional base URL policy, path-segment validation, provider error mapping, and rate-limit handling
- local provisioning recipe, doctor, health, self-check, simulate, introspect, invoke, and shutdown surfaces
- runtime/manifest drift around destructive-delete capability, regional hosts, retry, approval metadata, and capability-token verification
- mock-only WireMock integration tests

## Auth And Zone Boundary

- Authentication mechanisms: Intercom bearer token or host credential reference.
- Official Intercom docs describe bearer-token auth on REST API requests.
- Runtime does not implement OAuth authorization, token exchange, token refresh, workspace app installation, token rotation, webhook setup, or connector-local credential vaulting.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Runtime handshake advertises:
  - `intercom.contacts.read`
  - `intercom.contacts.write`
  - `intercom.contacts.delete`
  - `intercom.conversations.read`
  - `intercom.conversations.write`
  - `intercom.tags.read`
- Manifest optional capabilities currently omit `intercom.contacts.delete`, even though runtime advertises and introspects it.
- The connector does not persist contacts, conversations, replies, tags, tokens, credential IDs beyond configuration metadata, provider payloads, provider error bodies, pagination cursors, or support transcripts.
- Intercom data can include customer names, email addresses, support conversation bodies, tags, internal notes, and operational customer context. Treat all live reads and writes as work-zone data.

## Network And Runtime Invariants

- Default runtime host: `api.intercom.io`.
- Other runtime-accepted production hosts: `api.eu.intercom.io` and `api.au.intercom.io`.
- Runtime production base URLs must use HTTPS.
- Runtime local test base URLs may use HTTP.
- Runtime request construction appends endpoint paths to `base_url`.
- Runtime reqwest timeout: `30 seconds`.
- Runtime request-context timeout: `30 seconds`.
- Runtime GET/POST/DELETE helpers send one HTTP request each.
- Runtime rejects base URL userinfo, query strings, and fragments before constructing the client.
- Manifest live-operation network policy requires TLS/SNI, denies localhost, private ranges, tailnet ranges, and IP literals, and allows only `api.intercom.io` on port 443.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `300000 ms` wall-clock timeout, no exec, no ptrace, read-only `/usr` and `/lib`, and writable `$CONNECTOR_STATE`.
- The connector does not open inbound sockets and does not implement webhooks.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `intercom.contacts.read` | List contacts. |
| `intercom.contacts.write` | Create contacts in the current manifest; runtime uses this for create only. |
| `intercom.contacts.delete` | Runtime-only dedicated destructive delete capability in this checkout. |
| `intercom.conversations.read` | List conversations. |
| `intercom.conversations.write` | Reply to conversations. |
| `intercom.tags.read` | List tags. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `intercom.contacts.list` | `GET /contacts` | `intercom.contacts.read` | `Safe` | `Low` | `Strict` | Reads paginated contacts with optional cursor. |
| `intercom.contacts.create` | `POST /contacts` | `intercom.contacts.write` | `Risky` | `Medium` | `None` | Creates a lead or user contact. |
| `intercom.contacts.delete` | `DELETE /contacts/{contact_id}` | `intercom.contacts.delete` in runtime, `intercom.contacts.write` in manifest | `Dangerous` | `High` | `Strict` | Deletes one Intercom contact and returns `{ "deleted": true }` on success. |
| `intercom.conversations.list` | `GET /conversations` | `intercom.conversations.read` | `Safe` | `Low` | `Strict` | Reads paginated conversation metadata. |
| `intercom.conversations.reply` | `POST /conversations/{conversation_id}/reply` | `intercom.conversations.write` | `Risky` | `Medium` | `None` | Sends an admin-shaped reply or note body to a conversation. |
| `intercom.tags.list` | `GET /tags` | `intercom.tags.read` | `Safe` | `Low` | `Strict` | Reads workspace tags. |

## Explicit Non-Goals

The current implementation does not include:

- OAuth authorization, OAuth token refresh, app installation, token rotation, or secret storage
- Help Center articles, AI Content, external pages, content import sources, admins, teams, companies, tickets, notes, segments, subscription types, data attributes, events, data export, or Switch APIs
- contact search, contact update, contact merge, conversation search, conversation create, conversation close/open/snooze, assignment, tag attach/detach, or webhook subscriptions
- inbound webhook listening, signature verification, replay, durable event cursors, or event acknowledgement
- persistent customer sync, support transcript storage, warehouse loading, or deduplication
- direct FCP capability-token verification at connector invoke time

These are excluded on purpose:

- Support conversations and contact records contain customer personal data and internal support context.
- Contact deletion is destructive and needs a dedicated capability plus approval parity before broad automation.
- Webhook receiving requires an inbound listener and signature verification boundary that this connector does not expose.

## Readiness And Verification Surface

`handle_doctor()`, `handle_health()`, `handle_self_check()`, `handle_simulate()`, and `handle_introspect()` are part of the public closeout contract. They surface:

- configuration and local client state
- request and error counters
- auth mode as bearer token or credential ID through self-check provisioning details
- base URL policy status through self-check provisioning details
- credential-injection requirement for credential-id mode
- known operation metadata, schemas, capability IDs, risk levels, safety tiers, idempotency, and AI hints
- provider error mapping for auth, forbidden, not-found, rate-limit, server-error, invalid-input, and JSON errors

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle health, configure, handshake, reconfigure, shutdown, doctor, self-check, introspection, and simulate
- WireMock contacts list/create/delete, conversations list/reply, and tags list behavior
- provider 401, 403, 404, 429, and 500-class error handling
- missing required fields for contact creation, contact deletion, and conversation replies
- request/error counters
- auth validation, credential-id validation, base URL policy, path-segment allow-list, destructive-delete capability separation, and operation inventory assertions

## Source Notes

- `connectors/intercom/src/connector.rs` defines configuration parsing, lifecycle handlers, diagnostics, provisioning recipe, introspection, simulation, invoke dispatch, operation metadata, base URL policy, and readiness reporting.
- `connectors/intercom/src/client.rs` defines Intercom HTTP request construction, auth headers, regional base URL use, path-segment sanitization, response parsing, and provider error handling.
- `connectors/intercom/src/types.rs` defines contact, conversation, reply, tag, pagination, and provider-error shapes.
- `connectors/intercom/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/intercom/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, rate-limit pools, and AI hints.
- `connectors/intercom/tests/integration.rs` covers deterministic HTTP behavior and lifecycle behavior.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/intercom_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- runtime operation inventory and policy metadata
- deterministic WireMock coverage for Intercom REST paths
- auth, endpoint policy, provider error, lifecycle, simulation, introspection, self-check, and doctor coverage
- destructive-delete capability and path-segment hardening regressions
- formatting, check, test, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use WireMock fixtures for routine verification.
- Use a disposable Intercom workspace for live mutation proof.
- Prefer credential-id mode only when the host or egress proxy is ready to inject Intercom auth.

**Dedicated environment**:

- Keep live contacts synthetic and clearly marked as test data.
- Avoid deleting real customer contacts.
- Use conversation replies only in disposable conversations or internal test workspaces.
- Provide explicit `admin_id` for conversation replies instead of relying on the runtime default.

**Redaction rules**:

- Redact bearer tokens, credential IDs where needed, contact emails, contact names, phone numbers, conversation bodies, internal notes, tags when sensitive, provider payloads, provider error bodies, workspace IDs, and request URLs containing custom test hosts.
- Verification output should use operation IDs, endpoint shapes, HTTP status classes, retry decisions, and synthetic Intercom IDs.

**Common remediation**:

- If configuration fails, provide exactly one of `access_token` or `credential_id`.
- If configuration rejects a custom host, use `https://api.intercom.io`, `https://api.eu.intercom.io`, `https://api.au.intercom.io`, or a local test host.
- If self-check reports `credential_injection_required`, use direct token mode or wire host-side injection.
- If contact delete rejects `contact_id`, use the Intercom-assigned ASCII ID and avoid emails, external IDs with punctuation, slashes, dots, or query characters.
- If `contacts.list` does not honor a `query` object, use the implemented pagination fields only; contact search is not in this runtime slice.
- If conversation reply fails, provide `conversation_id`, `body`, `message_type`, and a valid `admin_id` for live Intercom calls.
- If `simulate` allows an operation but policy should deny it, remember that current simulation only checks operation ID.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-intercom-readme cargo check -p fcp-intercom --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-intercom-readme cargo test -p fcp-intercom --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-intercom-readme cargo clippy -p fcp-intercom --all-targets --no-deps -- -D warnings`
- `ubs connectors/intercom/README.md`
