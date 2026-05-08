# Logseq Connector V3 Contract

> **Status**: runtime contract documented with local-API and manifest drift
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Logseq local HTTP server upstream**: https://docs.logseq.com/#/page/local%20http%20server
> **Logseq plugin API upstream**: https://logseq.github.io/plugins/
> **Logseq repository upstream**: https://github.com/logseq/logseq

## Purpose

This document fixes the operator-facing contract for `fcp.logseq`. The connector exposes the Logseq surfaces implemented in this crate: page listing, page lookup by name, block listing for a page, and block creation on a page through a local Logseq HTTP API adapter.

The connector is intentionally a bounded personal-knowledge-management bridge. It is not a full Logseq plugin runtime, graph query engine, sync client, graph import/export tool, block tree editor, filesystem watcher, or durable automation daemon.

## Current Runtime Snapshot

The current crate exposes these operations:

- `logseq.pages.list`
- `logseq.pages.get`
- `logseq.blocks.list`
- `logseq.blocks.create`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-logseq`.
- Runtime `BaseConnector` ID is `logseq`.
- Manifest connector ID is `fcp.logseq`.
- Runtime handshake returns connector ID `fcp.logseq` and version `0.1.0`.
- Manifest format is `wasi`.
- Configuration requires exactly one auth source:
  - `access_token`
  - `credential_id`
- `credential_id` must be a valid UUID.
- Direct `access_token` mode sends `Authorization: Bearer <token>`.
- `credential_id` mode sends `X-FCP-Credential-Id: <uuid>`.
- Default base URL is `http://localhost:12315/api`.
- The client trims trailing slashes from `base_url`.
- Runtime reqwest timeout is `15 seconds`.
- Runtime request-context timeout is configured to `15 seconds`, but normal request helpers do not use a retry loop.
- Runtime stores `HttpRetryConfig { max_retries = 3 }`, but it is not currently applied to POST requests.
- Runtime request helpers send `Accept: application/json`.
- `health` reports configured state plus `session_id.is_some()` as the handshake indicator.
- `doctor` checks local configuration, client initialization, and `session_id.is_some()`.
- `self_check` performs local provisioning readiness only and does not call Logseq.
- `self_check` reports `credential_injection_required` for credential-id mode and skips any live probe.
- `handle_shutdown()` shuts down the client runtime, clears client/config, and resets base configured/handshaken flags.
- `handle_shutdown()` does not clear the stored `session_id`.
- `invoke` expects `operation_id` and optional `input`.
- `invoke` checks `BaseConnector::check_ready()` and operation ID, but does not require or verify an FCP capability token in this checkout.
- `simulate` only checks whether an `operation_id` is known.

## Runtime API Adapter

The runtime uses these local HTTP calls:

| Operation | Runtime request | Required input | Output handling |
|-----------|-----------------|----------------|-----------------|
| `logseq.pages.list` | `POST {base_url}/pages` with `{}` | none | If provider returns an array, runtime wraps it as `{ "pages": [...] }`; otherwise it returns an empty pages array. |
| `logseq.pages.get` | `POST {base_url}/page` with `{ "name": name }` | `name` | Runtime returns provider JSON as-is, but maps `null` and `{}` to not-found. |
| `logseq.blocks.list` | `POST {base_url}/page-blocks` with `{ "page": page }` | `page` | If provider returns an array, runtime wraps it as `{ "blocks": [...] }`; otherwise it returns an empty blocks array. |
| `logseq.blocks.create` | `POST {base_url}/insert-block` with `{ "page": page, "content": content }` | `page`, `content` | Runtime returns provider JSON as-is. |

Input field validation only checks that required fields exist and are JSON strings. Empty page names or content strings are not rejected by the local `require_str` helper.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Official Logseq local HTTP API documentation describes a local API server and plugin API methods, while this runtime currently uses REST-shaped subpaths (`/pages`, `/page`, `/page-blocks`, `/insert-block`) under `base_url`.
- Manifest network constraints allow `localhost.localdomain` on port `12315`; runtime self-check accepts only `localhost`, `127.0.0.1`, `::1`, and `[::1]`.
- Manifest network constraints set `deny_ip_literals = true`, while runtime self-check accepts `127.0.0.1` and IPv6 loopback.
- Runtime base URL policy is evaluated by `self_check`, not during configure. Configure accepts any URL string that reqwest can store.
- Runtime tests use WireMock loopback URLs, so self-check accepts any local loopback port.
- Runtime `health` and `doctor` treat missing `session_id` as not handshaken even though `handle_handshake()` sets the base connector handshaken flag.
- A handshake without a `session_id` marks the base connector handshaken but still reports degraded health and a failed doctor handshake check.
- Runtime shutdown clears base handshaken state but leaves `session_id` populated.
- Runtime `invoke` does not require bound capability tokens for reads or writes.
- Runtime `simulate` does not check configured state, handshake state, input shape, network policy, approval policy, or capability tokens.
- Runtime introspection output schemas differ from the manifest for `logseq.pages.get` and `logseq.blocks.create`.
- Runtime request helpers do not use the stored retry configuration.
- Runtime self-check does not verify that Logseq is running or that the token is accepted.

A follow-up parity bead should reconcile the runtime adapter with the official Logseq local HTTP API shape, align manifest and runtime host policy, enforce endpoint policy during configure, clear `session_id` during shutdown, make lifecycle checks use the same handshake source, wire capability-token verification into invoke, align simulation with invoke policy, and decide whether request retries should be applied.

## First-Slice Scope

The current Logseq README slice documents the existing runtime surface:

- access-token and credential-id configuration
- local HTTP page/block adapter paths
- lifecycle, local readiness, doctor, health, self-check, simulate, introspect, invoke, and shutdown behavior
- runtime/manifest drift around API shape, endpoint policy, lifecycle state, schema metadata, retry, and capability-token verification
- mock-only WireMock integration tests

## Auth And Zone Boundary

- Authentication mechanisms: Logseq local API authorization token or host credential reference.
- Runtime provisioning recipe asks the operator to paste the Logseq API authorization token from Logseq Settings > Features > Developer and stores it as `access_token` under `connector:fcp.logseq`.
- Home zone: `z:private`.
- Allowed source zones: `z:owner` and `z:private`.
- Allowed target zone: `z:private`.
- Forbidden zones: `z:public`, `z:community`, and `z:work`.
- Runtime handshake advertises:
  - `logseq.pages.read`
  - `logseq.blocks.read`
  - `logseq.blocks.write`
- The connector does not persist pages, blocks, graph data, access tokens, credential IDs beyond configuration metadata, provider payloads, provider error bodies, or sync state.
- Logseq data can include private notes, journal entries, tasks, research, links, and personal graph metadata. Treat live reads and writes as private-zone data.

## Network And Runtime Invariants

- Default runtime base URL: `http://localhost:12315/api`.
- Runtime direct requests append fixed subpaths to `base_url`.
- Runtime self-check accepts only local hosts:
  - `localhost`
  - `127.0.0.1`
  - `::1`
  - `[::1]`
- Runtime self-check accepts any scheme for those local hosts, including `http` and `https`.
- Runtime self-check accepts any port for those local hosts.
- Runtime self-check rejects remote hosts, missing hosts, and invalid URLs.
- Manifest operation network policy permits local access on port `12315`, denies tailnet ranges, sets `require_sni = false`, and sets `max_redirects = 0`.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `300000 ms` wall-clock timeout, no exec, no ptrace, read-only `/usr` and `/lib`, and writable `$CONNECTOR_STATE`.
- The connector does not open inbound sockets.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `logseq.pages.read` | List pages and read a page by name. |
| `logseq.blocks.read` | List blocks on a page. |
| `logseq.blocks.write` | Create a block on a page. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `logseq.pages.list` | `POST /pages` | `logseq.pages.read` | `Safe` | `Low` | `Strict` | Lists all pages returned by the local API adapter. |
| `logseq.pages.get` | `POST /page` | `logseq.pages.read` | `Safe` | `Low` | `Strict` | Reads one page by name and maps empty objects or null to not-found. |
| `logseq.blocks.list` | `POST /page-blocks` | `logseq.blocks.read` | `Safe` | `Low` | `Strict` | Lists blocks on one page and preserves nested child JSON when returned. |
| `logseq.blocks.create` | `POST /insert-block` | `logseq.blocks.write` | `Risky` | `Medium` | `None` | Creates one block on a page and returns provider JSON. |

## Explicit Non-Goals

The current implementation does not include:

- Logseq graph selection, desktop app launch, plugin installation, token creation, or local server enablement
- Datalog queries, graph search, page creation, page update/delete, block update/delete/move, block tree traversal helpers, embeds, assets, whiteboards, queries, properties normalization, or journal-date conversion
- durable sync, background polling, filesystem access to Logseq graphs, Git-backed graph handling, or cloud sync integration
- inbound webhooks, event streams, watches, or Logseq plugin event callbacks
- direct FCP capability-token verification at connector invoke time

These are excluded on purpose:

- Logseq notes are private-zone data and write operations need narrow approval semantics.
- Desktop-local API availability depends on operator Logseq settings and local host state.
- The current runtime adapter is deliberately small until the official API shape is reconciled.

## Readiness And Verification Surface

`handle_doctor()`, `handle_health()`, `handle_self_check()`, `handle_simulate()`, and `handle_introspect()` are part of the public closeout contract. They surface:

- configuration and local client state
- request and error counters
- auth mode as bearer token or credential ID through self-check provisioning details
- endpoint policy status through self-check provisioning details
- credential-injection requirement for credential-id mode
- known operation metadata, schemas, capability IDs, risk levels, safety tiers, idempotency, and AI hints
- provider error mapping for auth failures, forbidden access, not-found, rate-limit, server errors, invalid input, and JSON errors

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle health, configure, handshake, shutdown, doctor, self-check, introspection, and simulate
- bearer auth headers and loopback request paths
- WireMock page listing, page get, block listing, and block creation behavior
- missing required input fields
- provider 401, 403, 404, 429, 500, and 503 error behavior
- request/error counters
- auth redaction, credential-id handling, base URL policy, provisioning recipe shape, and operation inventory assertions

## Source Notes

- `connectors/logseq/src/connector.rs` defines configuration parsing, lifecycle handlers, diagnostics, provisioning recipe, introspection, simulation, invoke dispatch, operation metadata, base URL policy, and readiness reporting.
- `connectors/logseq/src/client.rs` defines Logseq HTTP request construction, auth headers, response parsing, local adapter paths, timeout settings, and provider error handling.
- `connectors/logseq/src/types.rs` defines page, block, list, create-response, insert-request, and provider-error shapes.
- `connectors/logseq/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/logseq/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, and rate-limit pools.
- `connectors/logseq/tests/integration.rs` covers deterministic HTTP behavior and connector-level behavior.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/logseq_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- runtime operation inventory and policy metadata
- deterministic WireMock coverage for local Logseq adapter paths
- auth, provider error, lifecycle, simulation, introspection, self-check, and doctor coverage
- formatting, check, test, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Enable the Logseq local HTTP server in the desktop app.
- Use the local API authorization token from Settings > Features > Developer.
- Keep routine verification on WireMock fixtures.
- Use a disposable Logseq graph for live write proof.

**Dedicated environment**:

- Use synthetic page names and block content.
- Prefer `http://localhost:12315/api` for live local checks.
- Use loopback custom ports only for tests.
- Treat `logseq.blocks.create` as a private graph mutation requiring policy approval.

**Redaction rules**:

- Redact access tokens, credential IDs where needed, page names when sensitive, block content, graph names, provider error bodies, and request URLs containing custom test hosts.
- Verification output should use operation IDs, endpoint classes, HTTP status classes, retry decisions, synthetic page names, and synthetic block UUIDs.

**Common remediation**:

- If configuration fails, provide exactly one of `access_token` or `credential_id`.
- If credential-id mode self-check reports `credential_injection_required`, use direct token mode or wire host-side injection.
- If self-check reports `network_constraints_invalid`, use a loopback base URL such as `http://localhost:12315/api`.
- If live requests fail with 401, refresh the Logseq authorization token in the desktop app.
- If page lookup returns not-found, check the exact Logseq page name; journal page names are display-format strings, not necessarily ISO dates.
- If block creation succeeds but the block renders unexpectedly, verify the graph format and Logseq Markdown expected by the graph.
- If `simulate` allows a request but policy should deny it, remember that current simulation only checks operation ID.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-logseq-readme cargo check -p fcp-logseq --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-logseq-readme cargo test -p fcp-logseq --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-logseq-readme cargo clippy -p fcp-logseq --all-targets --no-deps -- -D warnings`
- `ubs connectors/logseq/README.md`
