# Evernote Connector V3 Contract

> **Status**: runtime contract documented with major upstream/runtime drift
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Evernote developer docs**: https://dev.evernote.com/documentation/
> **Evernote developer-token docs**: https://dev.evernote.com/doc/articles/dev_tokens.php
> **Evernote NoteStore reference**: https://dev.evernote.com/doc/reference/NoteStore.html
> **Evernote note-creation guide**: https://dev.evernote.com/doc/articles/creating_notes.php

## Purpose

This document fixes the operator-facing contract for `fcp.evernote`. The connector exposes the Evernote surface currently implemented in this crate: notebook listing, note listing within a notebook, single-note retrieval, note creation, and note deletion.

The connector is intentionally a bounded Evernote bridge. It is not a full Evernote Cloud API SDK, NoteStore Thrift client, OAuth onboarding implementation, ENML validator, attachment/resource manager, sync engine, tag manager, search client, webhook receiver, or local Evernote desktop integration.

## Current Runtime Snapshot

The current crate exposes these operations:

- `evernote.notebooks.list`
- `evernote.notes.list`
- `evernote.notes.get`
- `evernote.notes.create`
- `evernote.notes.delete`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-evernote`.
- Runtime `BaseConnector` ID is `evernote`.
- Configuration accepts exactly one of:
  - `access_token`
  - `credential_id`
- `access_token` is trimmed and must be non-empty.
- `credential_id` must be a valid UUID and is treated as secretless egress-proxy metadata.
- Default base URL is `https://api.evernote.com/v1`.
- Direct-token mode sends `Authorization: Bearer <token>`.
- Credential-id mode sends `X-FCP-Credential-Id: <uuid>`.
- Direct-token base URLs must target `https://api.evernote.com`, `https://sandbox.evernote.com`, or loopback test hosts.
- Credential-id mode accepts any HTTPS host, plus loopback test hosts, so a host-managed egress proxy can own final provider routing.
- `base_url` must not include userinfo, query strings, or fragments.
- Runtime loopback hosts are `localhost`, `127.0.0.1`, and `::1`.
- HTTP client timeout is `30 seconds`.
- The client stores a retry configuration with `max_retries = 2`, but the current GET, POST, and DELETE helpers call `reqwest` directly and do not run the shared retry loop.
- Provider response bodies are truncated to 2048 bytes before error parsing.
- Provider 401, 403, 404, 429, and other failures map to FCP errors.
- `health` is local readiness only and considers the connector healthy only when configured and a `session_id` was supplied during handshake.
- `doctor` checks local configuration, client initialization, and handshake state.
- `self_check` is local provisioning validation only. It does not call Evernote in direct-token mode.
- Credential-id mode makes `self_check` degraded with `credential_injection_required`.
- `simulate` only checks whether the operation ID is known.
- `introspect` exposes five typed operations and no streaming support.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- The connector uses a legacy `handle_*` method surface rather than the full typed `FcpConnector` trait implementation used by newer connectors.
- Runtime `BaseConnector` ID is `evernote`, while the manifest connector ID and handshake payload use `fcp.evernote`.
- Runtime `invoke` checks generic configured/handshaken readiness, but it does not verify a bound capability token for the requested operation.
- Runtime `simulate` does not validate readiness, input schema, approval state, resource constraints, or capability tokens.
- Manifest network constraints allow `*.evernote.com` and deny localhost, while runtime direct-token policy only allows exact `api.evernote.com`, exact `sandbox.evernote.com`, and loopback test hosts.
- Runtime credential-id mode permits arbitrary HTTPS proxy origins, which is broader than the manifest network policy.
- Manifest marks `evernote.notes.create` as policy-approved and `evernote.notes.delete` as interactive. Runtime `OperationInfo` currently sets `requires_approval` to `None` for all operations.
- Manifest output schemas use snake-case fields such as `note_id`, while runtime forwards provider JSON and tests assert Evernote-style fields such as `noteId`.
- The Evernote official Cloud API documentation centers on UserStore and NoteStore services. The runtime instead calls REST-shaped paths such as `/notebooks`, `/notebooks/{notebook_id}/notes`, and `/notes/{note_id}`.
- Official Evernote note creation expects a NoteStore `createNote` call with ENML content. Runtime `evernote.notes.create` only requires `notebook_id` and `title`, forwards caller JSON to `POST /notes`, and does not validate ENML.
- Official Evernote search/listing guidance uses `NoteStore.findNotesMetadata` with a `NoteFilter`. Runtime note listing calls `GET /notebooks/{notebook_id}/notes`.
- Official Evernote docs say developer tokens are currently unavailable except for proven necessity and recommend OAuth for Cloud API auth. Runtime supports direct token and credential-id only; it does not implement OAuth.
- `EvernoteClient::shutdown()` exists, but `handle_shutdown` currently drops local client/config state without calling it.

A follow-up parity bead should decide whether this connector should become a true Evernote Cloud API/NoteStore client or keep a provider-proxy REST contract, then align manifest operation IDs, schemas, approval metadata, base URL policy, capability-token enforcement, OAuth/provisioning, ENML validation, retry dispatch, and shutdown semantics.

## First-Slice Scope

The current Evernote README slice documents the existing runtime surface:

- access-token and credential-id configuration
- Evernote direct-token base URL policy and credential-proxy routing
- notebook list
- notes list by notebook
- note get
- note create
- note delete
- lifecycle, doctor, health, self-check, introspection, simulation, and shutdown surfaces
- deterministic WireMock tests for provider request paths and provider error mapping

## Auth And Scope Boundary

- Authentication mechanisms: Evernote bearer token or host credential reference.
- Runtime does not implement OAuth, browser authorization, token refresh, developer-token acquisition, NoteStore URL discovery, or connector-local credential vaulting.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Runtime handshake capabilities:
  - `evernote.notebooks.read`
  - `evernote.notes.read`
  - `evernote.notes.write`
- Runtime operation capabilities:
  - `evernote.notebooks.read` gates notebook listing.
  - `evernote.notes.read` gates note listing and note retrieval.
  - `evernote.notes.write` gates note creation and deletion.
- The connector does not persist notebooks, notes, note contents, tags, access tokens, credential IDs beyond configuration metadata, provider payloads, or provider error bodies.
- Evernote notes can contain private personal or work data. Treat all live reads and writes as private or work-zone data.

## Network And Runtime Invariants

- Direct-token production hosts: `api.evernote.com` and `sandbox.evernote.com`.
- Direct-token production scheme: `https`.
- Default API prefix: `/v1`.
- Credential-id mode may target a custom HTTPS egress proxy.
- Runtime loopback base URLs are test-only.
- Runtime request timeout: `30 seconds`.
- Runtime request construction appends endpoint paths to `base_url`.
- Runtime does not validate note IDs or notebook IDs as URL path segments before interpolating them into provider paths.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live operations.
- Manifest sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `300_000 ms` wall-clock timeout, no exec, and no ptrace.
- The connector does not open inbound sockets and does not implement subscriptions.

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `evernote.notebooks.list` | `GET /notebooks` | `evernote.notebooks.read` | `Safe` | `Low` | `Strict` | Reads notebook inventory visible to the authenticated account. |
| `evernote.notes.list` | `GET /notebooks/{notebook_id}/notes` | `evernote.notes.read` | `Safe` | `Low` | `Strict` | Reads notes for one caller-supplied notebook ID. |
| `evernote.notes.get` | `GET /notes/{note_id}` | `evernote.notes.read` | `Safe` | `Low` | `Strict` | Reads one note payload by caller-supplied note ID. |
| `evernote.notes.create` | `POST /notes` | `evernote.notes.write` | `Risky` | `Medium` | `None` | Creates provider-visible note state from caller-supplied JSON. |
| `evernote.notes.delete` | `DELETE /notes/{note_id}` | `evernote.notes.write` | `Dangerous` | `High` | `Strict` | Deletes or trashes provider note state by note ID. |

## Explicit Non-Goals

The current implementation does not include:

- OAuth authorization, token refresh, app-key provisioning, or NoteStore URL discovery
- UserStore calls, NoteStore Thrift calls, SDK-generated Evernote clients, or EDAM sync
- ENML validation, ENML-to-text conversion, note search grammar, saved searches, note versions, reminders, or tags
- notebook create/update/delete, tag list/create/delete, resource attachment upload/download, recognition data, linked notebooks, business notebooks, or sharing
- webhook receiving, webhook notification verification, local desktop automation, or Local API behavior
- connector-local durable storage of notes, notebooks, sync state, cursors, or credentials

These are excluded on purpose:

- Evernote notes and notebooks can contain high-sensitivity personal and work data.
- The official Cloud API differs materially from this crate's current REST-shaped runtime.
- Broader Evernote coverage should wait for a clear decision about official NoteStore alignment and OAuth/provisioning behavior.

## Readiness And Verification Surface

`handle_doctor()`, `handle_health()`, `handle_self_check()`, `handle_simulate()`, and `handle_introspect()` are part of the public closeout contract. They surface:

- configuration and handshake state
- request and error counters
- auth mode as bearer token or credential ID
- credential-injection requirement for credential-id mode
- base URL policy status
- known operation metadata, schemas, capability IDs, risk levels, safety tiers, idempotency, and AI hints
- simulation allow/deny based only on known operation ID
- self-check degradation for unconfigured, missing client, invalid endpoint policy, or credential-injection mode

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle health, doctor, self-check, introspection, simulate, and shutdown behavior
- bearer-token auth header propagation
- notebook list, note list, note get, note create, and note delete WireMock requests
- missing required input fields
- provider 401, 403, 404, 429, and 500-class error mapping
- unknown operation and simulation behavior
- request/error counters
- configuration validation, credential-id validation, direct-token base URL policy, credential-id custom HTTPS base URL allowance, and provisioning recipe shape

## Source Notes

- `connectors/evernote/src/connector.rs` defines configuration parsing, base URL policy, lifecycle handlers, diagnostics, simulation, operation metadata, provisioning recipe, and invoke dispatch.
- `connectors/evernote/src/client.rs` defines Evernote HTTP request construction, auth headers, timeout setup, API paths, response parsing, and provider error parsing.
- `connectors/evernote/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/evernote/src/types.rs` defines Evernote-shaped notebook, note, note-list, create-note, and error response shapes.
- `connectors/evernote/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, rate limits, and AI hints.
- `connectors/evernote/tests/integration.rs` covers deterministic HTTP behavior and handler lifecycle behavior.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/evernote_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- runtime operation contract tests
- deterministic WireMock coverage for the five runtime operations
- auth, endpoint policy, input validation, provider error, lifecycle, introspection, simulation, and shutdown tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use WireMock fixtures for routine verification.
- Use live Evernote credentials only in a disposable account.
- Prefer credential-id mode only when the host or egress proxy is ready to inject Evernote auth.

**Dedicated environment**:

- Keep live note creation and deletion confined to disposable notebooks.
- Never run delete checks against personal or production notebooks.
- Use synthetic notebook IDs, note IDs, titles, and note bodies in logs and transcripts.

**Redaction rules**:

- Redact access tokens, credential IDs where needed, notebook IDs, note IDs, titles when sensitive, note content, provider payloads, provider error bodies, and local paths.
- Verification output should use operation IDs, endpoint shapes, host classes, status/error classes, and synthetic Evernote resource identifiers.

**Common remediation**:

- If configuration fails, provide exactly one of `access_token` or `credential_id`.
- If direct-token base URL policy rejects a host, use `https://api.evernote.com/v1`, `https://sandbox.evernote.com/v1`, or a loopback fixture endpoint.
- If credential-id mode self-check reports `credential_injection_required`, use direct token mode or wire the egress proxy injection path.
- If invocation fails with readiness errors, configure and handshake with a non-empty `session_id` before invoking.
- If note creation fails against live Evernote, check whether the provider expects official NoteStore/ENML semantics instead of the current REST-shaped runtime contract.
- If repeated 500 or 429 errors appear, remember that the current direct HTTP helpers do not run the configured retry loop.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-evernote-readme cargo check -p fcp-evernote --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-evernote-readme cargo test -p fcp-evernote --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-evernote-readme cargo clippy -p fcp-evernote --all-targets --no-deps -- -D warnings`
- `ubs connectors/evernote/README.md`
