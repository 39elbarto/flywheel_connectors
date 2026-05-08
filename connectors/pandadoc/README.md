# PandaDoc Connector V3 Contract

> **Status**: runtime contract documented with auth-header and capability-token drift
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **PandaDoc API reference**: https://developers.pandadoc.com/reference
> **List documents upstream**: https://developers.pandadoc.com/reference/list-documents
> **Create document upstream**: https://developers.pandadoc.com/reference/create-document
> **Send document upstream**: https://developers.pandadoc.com/reference/send-document

## Purpose

This document fixes the operator-facing contract for `fcp.pandadoc`. The connector exposes the PandaDoc surfaces implemented in this crate: document listing, document lookup, document creation from a template, document sending, document deletion, and template listing.

The connector is intentionally a bounded document-automation bridge. It is not a full PandaDoc workspace administration client, OAuth installer, webhook listener, embedded editor client, pricing-table authoring tool, template creation client, document-upload client, or durable signing workflow daemon.

## Current Runtime Snapshot

The current crate exposes these operations:

- `pandadoc.documents.list`
- `pandadoc.documents.get`
- `pandadoc.documents.create`
- `pandadoc.documents.send`
- `pandadoc.documents.delete`
- `pandadoc.templates.list`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-pandadoc`.
- Runtime `BaseConnector` ID is `pandadoc`.
- Manifest and handshake connector ID are `fcp.pandadoc`.
- Connector version is `0.1.0`.
- Configuration requires exactly one auth source:
  - `api_key`
  - `credential_id`
- `credential_id` must be a valid UUID.
- Direct `api_key` mode trims whitespace and sends `Authorization: Bearer <token>`.
- `credential_id` mode sends `X-FCP-Credential-Id` and expects host or egress-proxy credential injection.
- Default base URL is `https://api.pandadoc.com/public/v1`.
- Runtime base URL policy accepts HTTPS `api.pandadoc.com` and loopback HTTP/HTTPS for tests.
- Runtime configure does not enforce the base URL policy; `self_check` reports invalid policy as failed.
- Runtime reqwest timeout is `30 seconds`.
- Runtime request context timeout is `30 seconds`.
- Runtime retry config sets `max_retries = 2` through the shared connector runtime.
- `health` reports `healthy` only after configuration and handshake.
- `doctor` checks local configuration, client initialization, and handshake state.
- `self_check` performs `GET /documents?count=1` in direct-key mode.
- `self_check` degrades in `credential_id` mode because egress-proxy injection cannot be proven locally.
- Runtime `invoke` uses `operation_id`, not `operation`.
- Runtime `invoke` checks only connector readiness and operation ID before dispatch.
- Runtime does not install a `CapabilityVerifier` and does not verify `capability_token`.
- Runtime does not verify approval tokens for create, send, or delete operations.
- `simulate` only checks whether `operation_id` is present in the local operation inventory.
- `handle_configure()` resets local session state and marks the connector unhandshaken.
- `handle_shutdown()` shuts down the client runtime, clears client/config state, and resets configured/handshaken flags.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Current PandaDoc examples and MCP setup docs show API-key auth as `Authorization: API-Key <token>`, while runtime direct `api_key` mode sends a bearer token.
- PandaDoc's create-document API supports many fields for template, URL, upload, pricing, tables, tokens, metadata, tags, owner, and content placeholders. Runtime locally requires only `name`, `template_uuid`, and an array `recipients`, then forwards the caller's full JSON body.
- PandaDoc's list-documents API documents integer status filters. Runtime accepts `status` as a string and forwards it unchanged.
- PandaDoc send semantics require a document in `document.draft`; newly created documents can remain in `document.uploaded` for several seconds. Runtime does not poll for draft state before sending.
- Runtime output schemas in introspection are simplified wrappers such as `documents`, `document`, `templates`, or `status`, while the HTTP client returns the raw provider JSON.
- Manifest marks delete as `requires_approval = "interactive"` and create/send as policy-gated, but runtime checks no approval token.
- Manifest network constraints deny localhost and private ranges for live operations, while runtime policy allows loopback hosts for deterministic tests and configure does not enforce the policy.
- Manifest state says API key and pagination cursors are stored. Runtime keeps configuration in memory and does not persist cursor state.
- Runtime `simulate` can return allowed without checking configured state, handshake state, approval policy, or caller authority.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should reconcile PandaDoc API-key header semantics, enforce or explicitly model approval tokens for document creation/send/delete, add bound capability-token verification, align runtime and manifest schemas, enforce endpoint policy at configure time, and decide whether template creation, document upload, webhooks, and OAuth are in or out of scope.

## First-Slice Scope

The current PandaDoc README slice documents the existing runtime surface:

- direct API-key and host credential-reference configuration
- default PandaDoc public v1 endpoint behavior
- document list/get/create/send/delete and template-list operations
- retry, timeout, provider error, readiness, doctor, health, self-check, simulate, introspect, invoke, and shutdown behavior
- runtime/manifest drift around auth headers, endpoint policy, output schemas, approval metadata, and capability-token verification
- deterministic WireMock tests and direct proof commands

## Auth And Zone Boundary

- Authentication mechanisms: PandaDoc API key or host credential reference.
- Official PandaDoc docs describe API-key or OAuth-token access for document workflows; this runtime implements direct key or credential reference only.
- Runtime does not implement OAuth, token exchange, token refresh, account selection, workspace administration, API-key rotation, webhook setup, or connector-local credential vaulting.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Handshake advertises:
  - `pandadoc.documents.read`
  - `pandadoc.documents.write`
  - `pandadoc.templates.read`
- The connector does not persist API keys, credential IDs beyond configuration metadata, document payloads, template lists, provider responses, provider error bodies, or signing workflow state outside process memory.
- PandaDoc document data can include customer names, emails, deal values, contracts, and signature status. Treat live reads and writes as work-zone or private-zone data based on the configured workspace.

## Network And Runtime Invariants

- Default runtime base URL: `https://api.pandadoc.com/public/v1`.
- Runtime document endpoints:
  - `GET /documents`
  - `GET /documents/{document_id}`
  - `POST /documents`
  - `POST /documents/{document_id}/send`
  - `DELETE /documents/{document_id}`
  - `GET /templates`
- Runtime request timeout: `30 seconds`.
- Runtime retry policy: `max_retries = 2`.
- Runtime direct API-key mode uses bearer auth.
- Runtime credential-id mode sends `X-FCP-Credential-Id`.
- Runtime path segment sanitization rejects empty IDs, slashes, backslashes, `..`, and encoded slash/backslash forms for document IDs.
- Provider HTTP 401, 403, 404, 429, and other API errors map to typed connector/FCP errors.
- `Retry-After` on 429 is converted to milliseconds; missing values default to 60000 ms.
- Manifest live-operation policy requires TLS/SNI, denies localhost, private ranges, tailnet ranges, and IP literals, and allows only `api.pandadoc.com` on port 443.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `300000 ms` wall-clock timeout, read-only `/usr` and `/lib`, writable `$CONNECTOR_STATE`, no exec, and no ptrace.
- The connector does not open inbound sockets.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `pandadoc.documents.read` | List documents and read one document. |
| `pandadoc.documents.write` | Create, send, or delete a document. |
| `pandadoc.templates.read` | List templates for document creation. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Required input |
|-----------|----------------|------------|------------|-----------|-------------|----------------|
| `pandadoc.documents.list` | `GET /documents` | `pandadoc.documents.read` | `Safe` | `Low` | `Strict` | Optional `status`, `count`. |
| `pandadoc.documents.get` | `GET /documents/{document_id}` | `pandadoc.documents.read` | `Safe` | `Low` | `Strict` | `document_id`. |
| `pandadoc.documents.create` | `POST /documents` | `pandadoc.documents.write` | `Risky` | `Medium` | `None` | `name`, `template_uuid`, array `recipients`; additional fields are forwarded. |
| `pandadoc.documents.send` | `POST /documents/{document_id}/send` | `pandadoc.documents.write` | `Risky` | `High` | `Strict` | `document_id`; optional `message`. |
| `pandadoc.documents.delete` | `DELETE /documents/{document_id}` | `pandadoc.documents.write` | `Dangerous` | `High` | `Strict` | `document_id`. |
| `pandadoc.templates.list` | `GET /templates` | `pandadoc.templates.read` | `Safe` | `Low` | `Strict` | None. |

## Explicit Non-Goals

The current implementation does not include:

- OAuth installation, account linking, token refresh, token revocation, or workspace/member administration
- document upload from local file, document creation from public URL as a first-class operation, template creation, template upload, or embedded editor sessions
- webhook subscription management, inbound webhook listener, document-status event replay, or durable signing workflow tracking
- folder management, contacts, members, content library items, pricing catalog management, quotes, forms, payments, or analytics
- automatic polling from `document.uploaded` to `document.draft` before sending
- direct FCP capability-token or approval-token verification at connector invoke time

These are excluded on purpose:

- Document send and delete operations can notify recipients or remove business-critical contracts.
- PandaDoc creation payloads can contain sensitive business terms, customer data, and signer identities.
- Webhook ingestion requires an ingress boundary that preserves raw request metadata and should be host-mediated.

## Readiness And Verification Surface

`handle_doctor()`, `handle_health()`, `handle_self_check()`, `handle_simulate()`, and `handle_introspect()` are part of the public closeout contract. They surface:

- configuration, client, handshake, request, and error-counter state
- auth mode as direct API key or credential ID
- credential-injection requirement for credential-id mode
- live list-documents probe for direct-key mode
- known operation metadata, schemas, capability IDs, risk levels, safety tiers, idempotency, and AI hints
- provider error mapping for unauthorized, forbidden, not-found, rate-limit, retryable server errors, JSON errors, and transport errors

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle health, configure, handshake, reconfigure, shutdown, doctor, self-check, and introspection
- all six operation dispatch paths through WireMock fixtures
- missing required input rejection for get/create/send/delete operations
- known and unknown simulation behavior
- provider 401, 403, 404, 429, and 500 behavior
- auth redaction, credential-id parsing, default/custom base URL behavior, provisioning readiness, and base URL policy

## Source Notes

- `connectors/pandadoc/src/connector.rs` defines configuration parsing, lifecycle handlers, diagnostics, base URL policy, introspection, simulation, invoke dispatch, operation IDs, and provisioning readiness.
- `connectors/pandadoc/src/client.rs` defines PandaDoc HTTP request construction, auth headers, retry/timeout behavior, document/template paths, path segment sanitization, and provider error mapping.
- `connectors/pandadoc/src/types.rs` defines API error envelope shapes.
- `connectors/pandadoc/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/pandadoc/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, rate-limit pools, and AI hints.
- `connectors/pandadoc/tests/integration.rs` covers deterministic HTTP behavior and connector-level behavior.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/pandadoc/README.md
ubs connectors/pandadoc/README.md
LC_ALL=C rg -n '[^ -~]' connectors/pandadoc/README.md
rg -n '\bmaster\b' connectors/pandadoc/README.md
```

For source or behavior changes, also run the connector proof lane through `rch`:

```bash
rch exec -- cargo test -p fcp-pandadoc
rch exec -- cargo check -p fcp-pandadoc --all-targets
rch exec -- cargo clippy -p fcp-pandadoc --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

## Operator Guidance

- Use WireMock fixtures for routine verification.
- Use a disposable PandaDoc sandbox/workspace for live mutation proof.
- Treat document creation and send as business-side-effect operations even though runtime approval checks are absent.
- Do not rely on capability-token or approval-token enforcement until runtime verification is implemented.
- If `send` fails after `create`, check whether the document is still in `document.uploaded` and wait for `document.draft`.
- If live auth fails with direct `api_key`, re-check the PandaDoc header contract before assuming the key is wrong.
- Prefer explicit document IDs, template UUIDs, and synthetic recipients in live tests.
- Redact API keys, credential IDs where needed, recipient emails, document names, template names, customer names, deal values, provider payloads, and provider error bodies in shared logs.
