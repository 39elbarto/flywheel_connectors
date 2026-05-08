# Segment Connector V3 Contract

> **Status**: runtime contract documented; Segment Public API / tracking drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Segment Public API upstream**: https://docs.segmentapis.com/
> **Segment Public API authentication upstream**: https://docs.segmentapis.com/tag/Authentication/
> **Segment sources upstream**: https://docs.segmentapis.com/tag/Sources/
> **Segment destinations upstream**: https://docs.segmentapis.com/tag/Destinations/
> **Segment tracking example upstream**: https://segment.com/recipes/increase-loyalty-and-revenue-by-personalizing-in-store-pickup-experience/

## Purpose

This document fixes the operator-facing contract for `fcp.segment`. The connector exposes the Segment workspace/control-plane and event-send surface implemented in this crate: source listing, destination listing for a source, and track-event submission.

The connector is intentionally a small Segment bridge. It is not a full Segment Public API client, tracking-plan manager, warehouse manager, Reverse ETL manager, catalog client, transformations client, source/destination create/update/delete client, identity graph client, batching engine, HTTP Tracking API-compatible library, or Segment SDK wrapper.

## Current Runtime Snapshot

The current crate exposes these operations:

- `segment.sources.list`
- `segment.destinations.list`
- `segment.track`

Important runtime truths the contract preserves:

- Package, library, and binary name are `fcp-segment`.
- Manifest ID is `fcp.segment`.
- `BaseConnector` runtime ID is `segment`.
- Manifest version is `0.1.0`.
- Manifest format is `wasi`.
- Manifest interface hash is all zeroes in this checkout.
- Configuration requires exactly one auth source:
  - `api_token`
  - `credential_id`
- Direct token mode sends `Authorization: Bearer <token>`.
- `credential_id` mode sends `X-FCP-Credential-Id` and expects host egress policy to inject real secret material.
- `credential_id` must be a valid UUID.
- Default runtime API URL is `https://api.segmentapis.com/v2`.
- Direct token mode permits `https://api.segmentapis.com`, `https://api.segment.io`, `https://cdn.segment.com`, and loopback test hosts.
- `credential_id` mode permits any HTTPS endpoint or loopback test endpoint after URL shape validation.
- Configure rejects userinfo, query strings, fragments, and non-local HTTP endpoints.
- Configure resets `session_id` and the base handshaken flag.
- Runtime request timeout is 30 seconds.
- Runtime request-context timeout is 30 seconds.
- The client uses the shared retry loop with `max_retries = 2`.
- `health()` reports configured and session-ID state. It does not call Segment.
- `doctor()` checks local configuration, client initialization, and whether a session ID was provided. It does not call Segment.
- `self_check()` checks local readiness only. Direct-token mode does not perform a live Segment probe.
- `credential_id` self-check reports degraded `credential_injection_required` and skips any live probe.
- Runtime `invoke` uses the JSON field `operation_id`, not `operation`.
- Runtime `invoke` does not require or verify a capability token.
- Runtime `simulate` only checks whether the `operation_id` is known.
- Runtime `simulate` does not check configuration, handshake, input shape, approval policy, or capability tokens.
- Runtime `shutdown()` calls client shutdown, clears config and client state, and clears the base configured/handshaken flags.
- Runtime `shutdown()` does not clear the stored `session_id`.

## Runtime API Adapter

The runtime uses these request shapes:

| Operation | Runtime request | Required input | Output handling |
|-----------|-----------------|----------------|-----------------|
| `segment.sources.list` | `GET /sources` | none | Reads `sources`, defaulting to an empty list. |
| `segment.destinations.list` | `GET /sources/{source_id}/destinations` | `source_id` | Reads `destinations`, defaulting to an empty list. |
| `segment.track` | `POST /track` with `{ "userId": user_id, "event": event, "properties": ... }` | `user_id`, `event` | Reads `success`, defaulting to `false`. |

Identifier and payload handling:

- `source_id` is trimmed before path use.
- Empty source IDs are rejected.
- Slashes, backslashes, `..`, `%2f`, and `%5c` are rejected in `source_id`.
- Accepted `source_id` values are inserted into paths without percent encoding.
- `segment.track` accepts optional `properties` and forwards it unchanged.
- `segment.track` does not support `anonymousId`, `context`, `integrations`, `timestamp`, `messageId`, batching, identify, page, screen, group, or alias calls.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Segment Public API documentation describes workspace/control-plane resources such as Sources and Destinations and uses Bearer API tokens over HTTPS. Runtime source and destination reads follow that control-plane auth shape.
- Segment event tracking examples use source write keys and the tracking endpoint shape such as `https://api.segment.io/v1/track`. Runtime posts `segment.track` to `{base_url}/track`, which defaults to `https://api.segmentapis.com/v2/track`, and uses a Bearer API token.
- Manifest network constraints allow `api.segmentapis.com`, `*.segment.io`, and `*.segment.com`. Runtime direct-token URL policy allows only exact `api.segmentapis.com`, `api.segment.io`, `cdn.segment.com`, and loopback hosts.
- Runtime `credential_id` URL policy is broader than the manifest because it allows any HTTPS host after URL shape validation.
- Manifest state says the connector stores API token and workspace slug. Runtime keeps config in memory and does not persist token, credential ID, workspace slug, provider payloads, counters, or cursors.
- Manifest operation approval marks `segment.track` as policy. Runtime does not enforce approval tokens.
- Runtime introspection reports no `requires_approval` metadata for any operation.
- Manifest rate-limit pools exist for sources-read, destinations-read, and track-write operations. Runtime introspection reports no rate-limit metadata and the client does not enforce those manifest pools.
- Manifest response caps vary by operation. Runtime does not enforce those response byte caps before parsing JSON.
- Handshake returns all three Segment capabilities unconditionally after configure. It does not filter requested capabilities.
- Handshake does not parse a full `HandshakeRequest`, does not install a `CapabilityVerifier`, and does not return a manifest hash.
- Health treats a configured connector without a `session_id` as degraded even though base configured state is true.
- Direct-token `self_check()` reports local readiness without a live Segment API probe.
- Runtime `simulate` is only a known-operation check.
- Provider 401, 403, 404, and 429 are mapped as `FcpError::External` with status codes, not specialized unauthorized/resource/rate-limit FCP variants.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should split Public API control-plane operations from tracking ingestion, decide whether `segment.track` should use the HTTP Tracking API and source write keys, reconcile URL policy with the manifest wildcard allowlist, add capability-token verification, expose approval and rate-limit metadata, add a live read-only self-check, and reconcile the manifest state model with in-memory runtime behavior.

## First-Slice Scope

The current Segment README slice documents the existing runtime surface:

- API-token and credential-id configuration
- base URL validation by auth mode
- source listing, destination listing, and event tracking operations
- lifecycle, doctor, health, self-check, simulate, introspect, invoke, and shutdown behavior
- provider error mapping, retry behavior, timeout behavior, and source-ID validation
- runtime/manifest/provider-doc drift around tracking endpoint semantics, URL policy, state persistence, approvals, rate limits, response caps, and capability-token verification
- deterministic WireMock integration tests

## Auth And Zone Boundary

- Authentication mechanisms: direct Segment API token or host credential reference.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Runtime capability families:
  - `segment.sources.read`
  - `segment.destinations.read`
  - `segment.track.write`
- Manifest required capabilities are `network.dns`, `network.egress`, `network.tls.sni`, and `storage.state`.
- Manifest forbids `system.exec`, `network.listen`, `media.upload`, and `media.download`.
- The connector does not intentionally persist API tokens, credential IDs, source lists, destination lists, event bodies, request counters, or error counters outside process memory.
- Segment payloads can contain workspace source metadata, destination metadata, user IDs, event names, and event properties. Treat live output and event input as work-zone sensitive data unless the host supplies a stricter zone policy.

## Network And Runtime Invariants

- Default runtime API URL: `https://api.segmentapis.com/v2`.
- Direct token requests use `Authorization: Bearer <token>`.
- `credential_id` requests use `X-FCP-Credential-Id: <uuid>`.
- Direct token mode allows exact Segment hosts accepted by runtime URL policy.
- `credential_id` mode allows any HTTPS host or loopback test host after URL shape validation.
- Runtime client timeout is 30 seconds.
- Runtime request-context timeout is 30 seconds.
- Runtime retry loop uses `max_retries = 2`.
- Manifest operation network policy allows `api.segmentapis.com`, `*.segment.io`, and `*.segment.com` on port `443`, requires TLS/SNI, denies localhost, private ranges, tailnet ranges, and IP literals, caps redirects at three, and caps response sizes by operation.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `300000 ms` wall-clock timeout, no exec, no ptrace, read-only `/usr` and `/lib`, and writable `$CONNECTOR_STATE`.
- The connector does not open inbound sockets.
- Provider 401 and 403 are terminal authentication or authorization failures.
- Provider 404 is a terminal not-found failure.
- Provider 429 is retryable and honors `Retry-After` seconds, defaulting to 60 seconds when absent.
- Provider 5xx responses are classified as retryable API errors.
- HTTP timeout/connect failures are retryable through the shared retry loop.
- JSON parse errors are internal failures.

## Capability Families

| Capability | Purpose |
|------------|---------|
| `segment.sources.read` | List Segment workspace sources. |
| `segment.destinations.read` | List destinations attached to a source. |
| `segment.track.write` | Submit one track event body. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `segment.sources.list` | `GET /sources` | `segment.sources.read` | `Safe` | `Low` | `Strict` | Reads workspace source metadata. |
| `segment.destinations.list` | `GET /sources/{source_id}/destinations` | `segment.destinations.read` | `Safe` | `Low` | `Strict` | Reads destinations connected to a source. |
| `segment.track` | `POST /track` | `segment.track.write` | `Risky` | `Medium` | `None` | Sends one analytics event. |

## Resource URIs

Runtime invoke currently does not verify capability tokens, so no resource binding is enforced locally. The effective authorization boundary is host-side admission plus operation dispatch.

Follow-up work should add resource URI shapes such as:

| Operation family | Candidate resource URI shape |
|------------------|------------------------------|
| Sources | `segment://source/{source_id}` |
| Destinations | `segment://source/{source_id}/destinations` |
| Track event | `segment://source/{source_id}/track` |

## Explicit Non-Goals

The current implementation does not include:

- Segment source creation, update, delete, labels, or sync controls
- Segment destination creation, update, delete, subscriptions, delivery metrics, or settings updates
- Warehouse, Reverse ETL, tracking-plan, transformation, Unify, or IAM operations
- HTTP Tracking API parity beyond a minimal `track` body
- Source write-key discovery or management
- Event batching
- Identify, page, screen, group, alias, or batch calls
- Durable event queueing or replay
- Schema validation against Protocols tracking plans
- Real Segment integration tests

## Test And Verification Contract

The tracked tests use deterministic WireMock servers. They cover:

- configure, reconfigure, handshake, health, doctor, self-check, introspect, simulate, and shutdown paths
- API-token configuration
- credential-ID configuration validation
- sources list, destinations list, and track operations
- missing required input fields
- default empty output behavior when provider keys are absent
- track success false handling
- Authorization header behavior for direct-token requests
- provider 401, 403, 404, 429, 500, and empty-body error responses
- unknown operation handling
- known and unknown simulate behavior
- source-ID path-segment rejection for traversal-like values

Before committing README-only changes for this connector, run:

```bash
git diff --check -- connectors/segment/README.md
LC_ALL=C rg -n '[^ -~]' connectors/segment/README.md
rg -n '\bmaster\b' connectors/segment/README.md
ubs connectors/segment/README.md
```

No Cargo/rch lane is required for README-only edits. Any runtime or test change must use the workspace verification lanes described in the root `AGENTS.md`.
