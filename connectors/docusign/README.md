# Docusign Connector V3 Contract

> **Status**: runtime contract documented; enforcement gaps documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Primary upstream**: https://developers.docusign.com/docs/esign-rest-api/
> **Envelope upstream**: https://developers.docusign.com/docs/esign-rest-api/reference/envelopes/envelopes/
> **Templates upstream**: https://developers.docusign.com/docs/esign-rest-api/reference/templates/templates/
> **Connect upstream**: https://developers.docusign.com/platform/webhooks/connect/

## Purpose

This document fixes the operator-facing contract for `fcp.docusign`. The connector exposes a focused Docusign eSignature REST API surface for envelope listing, envelope creation, sending, voiding, recipients, tabs, templates, document listing/download, template-based envelope creation, and a placeholder Connect-events polling surface.

The connector is intentionally a bounded agreement-workflow bridge. It is not a full Docusign administration client, OAuth lifecycle manager, embedded signing client, bulk-send client, organization management client, billing client, Connect webhook receiver, or legal-record archive.

## Current Runtime Snapshot

The current crate exposes these operations:

- `docusign.list_envelopes`
- `docusign.get_envelope`
- `docusign.create_envelope`
- `docusign.send_envelope`
- `docusign.void_envelope`
- `docusign.add_recipients`
- `docusign.list_templates`
- `docusign.get_template`
- `docusign.download_documents`
- `docusign.stream_connect_events`
- `docusign.update_recipients`
- `docusign.add_tabs`
- `docusign.resend_envelope`
- `docusign.list_documents`
- `docusign.create_from_template`

Important runtime truths the contract preserves:

- Configuration requires exactly one auth mode: `access_token` or `credential_id`.
- `access_token` mode sends `Authorization: Bearer ...`.
- `credential_id` mode sends `X-FCP-Credential-Id`.
- `credential_id` must be a valid UUID.
- Supplying both auth modes, no auth mode, non-string `credential_id`, or invalid UUID fails configuration.
- `base_url` is required; there is no production default because Docusign demo and production account roots are separate.
- Production base URLs must use HTTPS, must not include query strings or fragments, and must point at `/restapi/<version>/accounts` on a Docusign host.
- Accepted non-local hosts end in `.docusign.net` or `.docusign.com`, or are root `docusign.net` / `docusign.com`.
- `localhost`, `127.0.0.1`, and `::1` are accepted for deterministic loopback tests with HTTP or HTTPS.
- Runtime path segments reject empty values, `/`, `\`, `..`, `%2f`, and `%5c`.
- Access tokens are redacted in debug output and log labels.
- HTTP client timeout is `30 seconds`.
- A retry config with two maximum retries is constructed, but the current request helpers call reqwest directly rather than using the shared retry loop.
- Provider 401, 403, 404, 429 with `Retry-After`, malformed JSON, and generic API failures are mapped into typed connector/FCP errors.
- `stream_connect_events` currently returns a deterministic empty `events` array and `streaming: true`; it does not consume a live Connect webhook stream.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- Runtime `invoke` does not parse or verify capability tokens; it only requires configured and handshaken connector state before dispatching known operation IDs.
- Runtime `simulate` only checks whether the operation ID exists in the operation inventory.
- Runtime `OperationInfo` sets `requires_approval = None` for every operation, while the manifest marks envelope creation, recipient updates, tab writes, resend, send, void, and template-send paths as policy or interactive approval.
- Runtime `stream_connect_events` returns a local empty result; the manifest describes a streaming Connect webhook event operation with a large response budget.
- Runtime output for `stream_connect_events` is `{events: [], streaming: true}` while the manifest output schema still describes a singular `event` object.
- The client has a retry config field but currently does not route requests through `RetryLoop`.

A follow-up parity bead should wire capability-token enforcement, approval metadata, retry-loop use, and real Connect handling before treating this connector as policy-complete.

## First-Slice Scope

The current Docusign README slice documents the existing runtime surface:

- bearer-token and host credential-reference configuration
- explicit base URL policy for demo, production, and loopback environments
- envelope listing through `GET /{account_id}/envelopes`
- envelope retrieval through `GET /{account_id}/envelopes/{envelope_id}`
- envelope creation through `POST /{account_id}/envelopes`
- sending, resending, and voiding through `PUT /{account_id}/envelopes/{envelope_id}`
- recipient add/update through `/recipients`
- recipient tab add through `/recipients/{recipient_id}/tabs`
- template listing/retrieval through `/templates`
- document listing and download through `/documents`
- template-based envelope creation through `POST /{account_id}/envelopes`
- deterministic placeholder Connect-event polling
- provider error mapping, redaction posture, and current retry gap
- lifecycle, introspection, simulation, doctor, self-check, and shutdown surfaces

## Auth And Scope Boundary

- Authentication mechanisms: Docusign OAuth bearer token or host credential reference.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Runtime capability surface:
  - `docusign.read` gates envelope reads, templates, document listing/download, and placeholder Connect events.
  - `docusign.write` gates envelope creation, recipient edits, tabs, resend, and template-based creation.
  - `docusign.send` gates send and void operations.
- The manifest requires `media.download` because `docusign.download_documents` returns base64-encoded document bytes.
- The connector does not persist envelopes, documents, templates, recipients, tabs, access tokens, credential IDs, provider payloads, downloaded PDFs, or provider error bodies beyond process memory.
- Envelope send, void, create-as-sent, resend, recipient edits, and tab edits are human-impacting agreement workflow operations and should be policy gated by the host.

## Network And Runtime Invariants

- Demo account-root example: `https://demo.docusign.net/restapi/v2.1/accounts`.
- Production account-root examples vary by account region, such as `https://na1.docusign.net/restapi/v2.1/accounts`.
- Production port: `443`.
- Manifest host allowlist is `*.docusign.net`, `*.docusign.com`, and `demo.docusign.net`.
- TLS and SNI are required by the manifest for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live operations.
- Runtime loopback base URLs are test-only.
- Runtime request timeout: `30 seconds`.
- Manifest network constraints use larger budgets for document download and the placeholder Connect stream than normal JSON operations.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `120_000 ms` wall-clock timeout, no exec, and no ptrace.
- Manifest event capabilities declare streaming support, but current runtime only exposes handler-style `handle_*` methods and the local placeholder event operation.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `docusign.read` | Read envelopes, templates, document metadata/content, and placeholder Connect events. |
| `docusign.write` | Create and modify envelopes, recipients, tabs, template envelopes, and resend notices. |
| `docusign.send` | Send draft envelopes and void sent envelopes. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `docusign.list_envelopes` | `GET /{account_id}/envelopes` | `docusign.read` | `Safe` | `Low` | `Strict` | Read-only envelope search by status, date, text, and pagination. |
| `docusign.get_envelope` | `GET /{account_id}/envelopes/{envelope_id}` | `docusign.read` | `Safe` | `Low` | `Strict` | Read-only envelope metadata and optional included details. |
| `docusign.create_envelope` | `POST /{account_id}/envelopes` | `docusign.write` | `Risky` | `High` | `None` | Creates a draft or sent envelope depending on payload status. |
| `docusign.send_envelope` | `PUT /{account_id}/envelopes/{envelope_id}` | `docusign.send` | `Dangerous` | `High` | `BestEffort` | Sends real signing notifications to recipients. |
| `docusign.void_envelope` | `PUT /{account_id}/envelopes/{envelope_id}` | `docusign.send` | `Dangerous` | `High` | `Strict` | Cancels a sent envelope that is not completed. |
| `docusign.add_recipients` | `POST /{account_id}/envelopes/{envelope_id}/recipients` | `docusign.write` | `Risky` | `Medium` | `Strict` | Adds or modifies draft-envelope recipients. |
| `docusign.list_templates` | `GET /{account_id}/templates` | `docusign.read` | `Safe` | `Low` | `Strict` | Read-only template discovery. |
| `docusign.get_template` | `GET /{account_id}/templates/{template_id}` | `docusign.read` | `Safe` | `Low` | `Strict` | Read-only template detail lookup. |
| `docusign.download_documents` | `GET /{account_id}/envelopes/{envelope_id}/documents/{document_id}` | `docusign.read` | `Safe` | `Low` | `Strict` | Downloads signed or envelope documents as base64 output. |
| `docusign.stream_connect_events` | local placeholder result | `docusign.read` | `Safe` | `Low` | `Strict` | Returns an empty deterministic event array until real Connect polling exists. |
| `docusign.update_recipients` | `PUT /{account_id}/envelopes/{envelope_id}/recipients` | `docusign.write` | `Risky` | `Medium` | `BestEffort` | Updates existing recipients. |
| `docusign.add_tabs` | `POST /{account_id}/envelopes/{envelope_id}/recipients/{recipient_id}/tabs` | `docusign.write` | `Risky` | `Medium` | `None` | Adds recipient tabs and form fields. |
| `docusign.resend_envelope` | `PUT /{account_id}/envelopes/{envelope_id}?resend_envelope=true` | `docusign.write` | `Risky` | `Medium` | `Strict` | Resends signing notifications. |
| `docusign.list_documents` | `GET /{account_id}/envelopes/{envelope_id}/documents` | `docusign.read` | `Safe` | `Low` | `Strict` | Lists envelope document IDs before download. |
| `docusign.create_from_template` | `POST /{account_id}/envelopes` | `docusign.write` | `Risky` | `Medium` | `None` | Creates a draft or sent envelope from template roles. |

## Explicit Non-Goals

The current implementation does not include:

- OAuth authorization-code execution, JWT grant flow, token refresh, consent, or account base URI discovery
- embedded signing recipient views, embedded sending views, captive signing, or PowerForms
- real Docusign Connect webhook receiver, HMAC validation, Connect configuration management, or replay storage
- bulk-send, batch send, scheduled send, delayed routing, reminders/expirations, comments, attachments, brands, folders, custom fields, users, groups, organizations, billing, admin, Rooms, CLM, or Notary APIs
- envelope correction flows beyond direct recipient/tab helpers
- durable document cache, durable envelope tracking, or legal-record retention
- host-side policy enforcement inside runtime invoke

These are excluded on purpose:

- Agreement sending and voiding are high-impact actions that need explicit host approval and audit.
- Downloaded agreement documents can contain regulated personal or business data.
- Real Connect support requires webhook ingress, signature verification, replay/idempotency storage, and a separate operational contract.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration and handshake state
- request and error counters
- auth mode, token/credential-reference status, base URL, and network policy status
- degraded self-check for unconfigured state and credential-injection mode
- failure for invalid base URL policy or missing client state
- 15 operation descriptors with capability, risk, safety tier, idempotency, schemas, and AI hints
- simulation denial for unsupported operation IDs
- shutdown state reset

The deterministic integration evidence is anchored on connector-local tests covering:

- configuration, handshake, health, doctor, self-check, introspection, simulation, counters, and shutdown
- bearer auth header propagation
- all 15 operation IDs
- envelope list/get/create/send/void
- recipients add/update, tabs, templates, document list/download, resend, template envelope creation, and placeholder Connect events
- missing-field validation for core IDs and payload objects
- path-segment rejection for traversal-like values
- provider 401, 403, 404, 429 with `Retry-After`, 500, and malformed JSON behavior
- base URL policy for Docusign account roots and loopback tests

## Source Notes

- `connectors/docusign/src/connector.rs` defines configuration parsing, lifecycle handlers, provisioning readiness, operation metadata, simulation, and invoke dispatch.
- `connectors/docusign/src/client.rs` defines Docusign auth headers, account-root URL construction, path-segment guards, document download, timeout, error mapping, and redacted debug behavior.
- `connectors/docusign/src/envelopes.rs`, `recipients.rs`, `signing.rs`, and `tracking.rs` hold supporting typed surfaces.
- `connectors/docusign/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/docusign/src/types.rs` defines provider error response parsing.
- `connectors/docusign/manifest.toml` defines operation schemas, network constraints, sandbox boundary, zone policy, event caps, rate limits, and AI hints.
- `connectors/docusign/tests/integration.rs` covers deterministic HTTP behavior and manifest/runtime contract checks.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/docusign_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- runtime operation inventory and metadata
- deterministic WireMock coverage for all 15 operations
- auth, base URL policy, provider error, lifecycle, simulation, and introspection tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a Docusign developer/demo account for live mutation checks.
- Use a non-production account root unless production sending has explicit approval.
- Configure an explicit account-root base URL.
- Use WireMock loopback fixtures for routine proof.

**Dedicated environment**:

- Keep live envelopes, recipients, tabs, templates, and documents synthetic.
- Do not send, resend, void, or create-as-sent against real recipients without explicit approval.
- Do not download production agreements through routine verification.
- Treat placeholder Connect output as a local readiness shape, not a live webhook stream.

**Redaction rules**:

- Redact access tokens, credential IDs where needed, account IDs when sensitive, envelope IDs, template IDs, recipient names, recipient emails, document names, document bytes, envelope definitions, tab values, provider payloads, provider error bodies, and endpoint URLs when they reveal account topology.
- Verification output should use operation IDs, endpoint shapes, auth mode, host class, result counts, status/error classes, and payload-shape summaries.

**Common remediation**:

- If configuration fails, provide exactly one of `access_token` or `credential_id`.
- If base URL validation fails, pass an account-root URL such as `https://demo.docusign.net/restapi/v2.1/accounts`.
- If a path field fails validation, pass a single ID segment rather than a URL or path.
- If send or void is denied by host policy, verify approval for `docusign.send`.
- If provider returns 401 or 403, verify token scopes, account access, and environment mismatch between demo and production.
- If Connect events are expected, file or use a real webhook/polling follow-up instead of relying on `stream_connect_events`.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-docusign-readme cargo check -p fcp-docusign --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-docusign-readme cargo test -p fcp-docusign --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-docusign-readme cargo clippy -p fcp-docusign --all-targets --no-deps -- -D warnings`
