# Feishu/Lark Connector V3 Contract

> **Status**: implemented first-slice contract with readiness bundle
> **Beads**:
> - `flywheel_connectors-j05nu.8.7.1`
> - `flywheel_connectors-j05nu.8.7.2`
> - `flywheel_connectors-j05nu.8.7.3`
> **Verification script**: `scripts/e2e/feishu_connector_verification.sh`
> **Primary upstream**: `https://open.feishu.cn/document/`

## Purpose

This document fixes the accepted first V3 slice for `fcp.feishu` so the connector stays bounded to one tenant-installed Feishu/Lark app instead of drifting into a generic collaboration-platform SDK.

The connector is a request-response Feishu/Lark Open Platform surface for outbound bot messaging, chat lookup, user-directory reads, known-token docs and sheets reads, known-calendar event listing, host-forwarded webhook ingestion, and health verification. It is not an embedded webhook listener, websocket event consumer, drive crawler, or user-impersonation bridge.

## Current Runtime Snapshot

The current crate exposes these operations:

- `feishu.messages.send`
- `feishu.messages.reply`
- `feishu.messages.get`
- `feishu.chats.list`
- `feishu.chats.get`
- `feishu.users.get`
- `feishu.docs.get`
- `feishu.sheets.get`
- `feishu.calendar.events`
- `feishu.webhook.ingest_request`
- `feishu.health`

Important runtime truths from `connector.rs`, `client.rs`, and `manifest.toml`:

- Configuration is `base_url`, `app_id`, `app_secret`, retry policy, bounded `request_timeout_ms`, and optional `webhook_state` settings for connector-owned dedupe persistence.
- One connector instance is bound to one installed tenant app and one tenant access token flow.
- Production roots are `https://open.feishu.cn` and `https://open.larksuite.com`; localhost and `127.0.0.1` overrides are allowed only for deterministic test harnesses.
- `health` and `self_check()` are grounded in the tenant-access-token internal auth endpoint and now emit operator guidance, verification-script references, provisioning details, and structured self-check evidence.
- Docs, sheets, and calendar reads are known-resource operations. This connector does not search Drive, enumerate arbitrary docs, or mutate calendar state.
- Webhook ingestion is host-forwarded request processing only. It validates signature/token, applies sender/chat/comment policy, and uses connector-owned dedupe state before event emission. Embedded listener lifecycle, websocket events, cross-tenant brokering, and user-delegated OAuth remain explicit non-goals in the current slice.

## First-Slice Scope

The accepted first Feishu/Lark slice is intentionally narrow:

- Send one bot-authored message to a visible user or chat.
- Reply to one existing message.
- Read one known message by ID.
- List chats the installed app can already see and fetch one chat by ID.
- Read one known tenant user record.
- Read one known docx document by token.
- Read one known spreadsheet by token.
- List events from one known calendar.
- Ingest one host-forwarded Feishu/Lark webhook request with policy gating and dedupe state.
- Expose safe readiness, doctor, and self-check surfaces backed by the auth endpoint.

This slice is intentionally closer to "tenant app request-response automation" than to "full workplace platform coverage."

## Service Inventory

| Surface | Status in first slice | Notes |
|---------|-----------------------|-------|
| Outbound messaging | In scope | Send and reply are implemented. |
| Message lookup | In scope | One message can be fetched by ID. |
| Chat discovery | In scope | Chat listing and point lookup are implemented. |
| User directory lookup | In scope | User lookup is limited to one tenant user ID at a time. |
| Docs and Sheets reads | Partial | Known-token reads are implemented; Drive search/export/write remain out of scope. |
| Calendar reads | Partial | Event listing for one known calendar is implemented; mutations and subscriptions are out of scope. |
| Webhook ingestion | In scope | Host-forwarded request validation with signature/token checks, policy gating, and optional persistent dedupe state. |
| Websocket events | Out of scope | No long-lived event stream is exposed. |

## Auth And Scope Boundary

- One connector instance maps to one installed tenant app.
- Authentication is `app_id` + `app_secret`, exchanged against `POST /open-apis/auth/v3/tenant_access_token/internal`.
- The connector does not impersonate arbitrary users or cross tenant boundaries.
- User-delegated OAuth is out of scope for this first slice.
- Stable first-slice identifiers include `message_id`, `chat_id`, `user_id`, `document_id`, `spreadsheet_token`, and `calendar_id`.
- `receive_id_type` supports `open_id`, `user_id`, `union_id`, `email`, and `chat_id` for send paths.
- `user_id_type` supports `open_id`, `user_id`, and `union_id` for directory reads.

## Network And Runtime Invariants

- Production REST hosts: `open.feishu.cn`, `open.larksuite.com`
- Port: `443`
- TLS + SNI required
- `deny_localhost = true`
- `deny_private_ranges = true`
- `deny_tailnet_ranges = true`
- `deny_ip_literals = true`
- Localhost overrides are allowed only for deterministic tests
- The connector remains request-response only; webhook ingestion is a host-forwarded operation and does not open a listener socket

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `feishu.messages.write` | Outbound message send and reply |
| `feishu.messages.read` | Message lookup |
| `feishu.chats.read` | Chat listing and point lookup |
| `feishu.users.read` | User lookup and health probe |
| `feishu.docs.read` | Known-token docs and sheets reads |
| `feishu.calendar.read` | Calendar event listing |

## Accepted Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Notes |
|-----------|----------------|------------|------------|-----------|-------------|-------|
| `feishu.messages.send` | `POST /open-apis/im/v1/messages` | `feishu.messages.write` | `Risky` | `Medium` | `None` | Sends one bot-authored message through the installed tenant app. |
| `feishu.messages.reply` | `POST /open-apis/im/v1/messages/{message_id}/reply` | `feishu.messages.write` | `Risky` | `Medium` | `None` | Replies to one existing visible message. |
| `feishu.messages.get` | `GET /open-apis/im/v1/messages/{message_id}` | `feishu.messages.read` | `Safe` | `Low` | `Strict` | Reads one known message by ID. |
| `feishu.chats.list` | `GET /open-apis/im/v1/chats` | `feishu.chats.read` | `Safe` | `Low` | `Strict` | Lists visible chats with pagination. |
| `feishu.chats.get` | `GET /open-apis/im/v1/chats/{chat_id}` | `feishu.chats.read` | `Safe` | `Low` | `Strict` | Reads one visible chat by ID. |
| `feishu.users.get` | `GET /open-apis/contact/v3/users/{user_id}` | `feishu.users.read` | `Safe` | `Low` | `Strict` | Reads one user record using the supplied `user_id_type`. |
| `feishu.docs.get` | `GET /open-apis/docx/v1/documents/{document_id}/raw_content` | `feishu.docs.read` | `Safe` | `Low` | `Strict` | Reads one known docx document token. |
| `feishu.sheets.get` | `GET /open-apis/sheets/v3/spreadsheets/{spreadsheet_token}` | `feishu.docs.read` | `Safe` | `Low` | `Strict` | Reads one known spreadsheet token. |
| `feishu.calendar.events` | `GET /open-apis/calendar/v4/calendars/{calendar_id}/events` | `feishu.calendar.read` | `Safe` | `Low` | `Strict` | Lists events for one known calendar with pagination. |
| `feishu.webhook.ingest_request` | host-forwarded request | `feishu.webhook.ingest` | `Risky` | `Medium` | `BestEffort` | Validates, dedupes, policy-gates, and normalizes one webhook request. |
| `feishu.health` | `POST /open-apis/auth/v3/tenant_access_token/internal` | `feishu.users.read` | `Safe` | `Low` | `Strict` | Safe tenant-app reachability and credential probe used by readiness surfaces. |

## Explicit Non-Goals

The accepted first Feishu/Lark slice does not include:

- embedded webhook listener lifecycle or direct public HTTP serving
- websocket event streams
- cross-tenant brokering or arbitrary user impersonation
- Drive search, export, folder traversal, or write operations
- calendar mutation, subscription, or scheduling workflows
- user-delegated OAuth, admin writes, or tenant provisioning

These are excluded on purpose because they materially widen the trust boundary beyond the current tenant-app request-response surface.

## Readiness And Verification

The readiness closeout bead for this connector surface is `flywheel_connectors-j05nu.8.7.3`. Verification artifacts should be reproducible without reopening planning notes.

- Replayable verification bundle: `scripts/e2e/feishu_connector_verification.sh`
- Artifact root: `artifacts/e2e/feishu_connector/<timestamp>`
- Manifest verification command: `rch exec -- cargo run -q -p fwc -- manifest fix connectors/feishu/manifest.toml --check --json`
- Focused cargo checks:
  - `rch exec -- cargo check -p fcp-feishu --all-targets`
  - `rch exec -- cargo fmt --manifest-path connectors/feishu/Cargo.toml --check`
  - `rch exec -- cargo test -p fcp-feishu --test integration -- --nocapture`
  - `rch exec -- cargo test -p fcp-feishu -- --nocapture`
  - `rch exec -- cargo clippy -p fcp-feishu --all-targets -- -D warnings`

## Verification Bundle

The readiness closeout is anchored on `scripts/e2e/feishu_connector_verification.sh`.
It writes replayable artifacts under `artifacts/e2e/feishu_connector/<timestamp>` and captures manifest validation, focused `rch`-offloaded cargo checks, targeted readiness evidence, mutation and pagination evidence, the full integration suite, the full crate test suite, and `clippy`.

## Operator Guidance

Prerequisites:

- Use a disposable Feishu/Lark tenant app or a localhost mock server.
- Grant the tenant app the scopes needed for the operations you plan to verify.
- Keep one connector instance bound to one app credential pair and one production host boundary.

Dedicated environment:

- Never aim the verification bundle at a production chat where `feishu.messages.send` or `feishu.messages.reply` would cause operational harm.

Redaction rules:

- Redact `app_secret`, tenant access tokens, Authorization headers, and copied auth payloads.
- Treat `app_id`, message IDs, chat IDs, user IDs, document IDs, spreadsheet tokens, calendar IDs, email addresses, and raw content bodies as sensitive tenant metadata.
- Sanitize live response payloads before exporting artifacts.

Common remediation:

- `not_configured`: configure app credentials, timeout, retry policy, and a valid `base_url`, then rerun `self_check`.
- `network_constraints_invalid`: use `https://open.feishu.cn` or `https://open.larksuite.com` for live runs, or an explicit localhost override for deterministic tests.
- `feishu_auth_rejected`: rotate the tenant app secret, verify the credential pair against the tenant auth endpoint, and rerun the verification bundle.
- `self_check_retryable`: respect the upstream retry window or increase timeout and retry settings before rerunning.

Rerun commands:

- `scripts/e2e/feishu_connector_verification.sh`
- `rch exec -- cargo run -q -p fwc -- manifest fix connectors/feishu/manifest.toml --check --json`
- `rch exec -- cargo check -p fcp-feishu --all-targets`
- `rch exec -- cargo fmt --manifest-path connectors/feishu/Cargo.toml --check`
- `rch exec -- cargo test -p fcp-feishu --test integration -- --nocapture`
- `rch exec -- cargo test -p fcp-feishu -- --nocapture`
- `rch exec -- cargo clippy -p fcp-feishu --all-targets -- -D warnings`
