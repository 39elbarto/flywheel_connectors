# Google Places Connector V3 Contract

> **Status**: runtime contract documented; manifest/runtime drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Places API upstream**: https://developers.google.com/maps/documentation/places/web-service
> **Text Search upstream**: https://developers.google.com/maps/documentation/places/web-service/text-search
> **Autocomplete upstream**: https://developers.google.com/maps/documentation/places/web-service/place-autocomplete
> **Field masks upstream**: https://developers.google.com/maps/documentation/places/web-service/choose-fields

## Purpose

This document fixes the operator-facing contract for `fcp.google-places`. The connector exposes the Google Places API (New) surface implemented in this crate: text search, autocomplete, place details, and local health metadata for one configured Places API key.

The connector is intentionally a read-only place discovery bridge. It is not a Maps JavaScript client, geocoding client, route planner, photo downloader, place mutation client, billing analyzer, quota manager, or Google Cloud project provisioning tool.

## Current Runtime Snapshot

The current crate exposes these runtime operation IDs:

- `google_places.search_text`
- `google_places.autocomplete`
- `google_places.get_place`
- `google_places.health`

Important runtime truths the contract preserves:

- Configuration requires a nonblank `api_key`.
- The API key is sent as the `X-Goog-Api-Key` request header.
- `base_url` defaults to `https://places.googleapis.com`.
- Runtime `base_url` validation only checks that the URL uses `http` or `https`; it does not enforce the manifest's production host allowlist.
- `request_timeout_ms` defaults to `15_000` and must be greater than zero.
- Each operation has a default response field mask and accepts an optional per-call `field_mask` override.
- Text search sends `textQuery`, optional `maxResultCount`, and optional `openNow` to `POST /v1/places:searchText`.
- Autocomplete sends `input` and optional `sessionToken` to `POST /v1/places:autocomplete`.
- Place details sends `GET /v1/{place}` with optional `languageCode`; the runtime trims leading slashes from `place`.
- The client preserves extra provider fields in response structs.
- `health`, `doctor`, and `self_check` are local readiness surfaces. They do not perform a live Google Places API probe.
- Handshake installs a `CapabilityVerifier`.
- `invoke` and `simulate` verify a bound capability token for `google_places.read` before allowing the operation.
- The runtime is non-streaming. `subscribe` and `unsubscribe` return `StreamingNotSupported`.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- Manifest connector ID is `fcp.google-places`, while runtime requests use connector ID `fcp.google-places` and runtime operation IDs use the `google_places.*` prefix.
- Manifest operation keys are unprefixed (`search_text`, `autocomplete`, `get_place`, `health`), while runtime introspection exposes prefixed operation IDs.
- Manifest network constraints allow only `places.googleapis.com:443` with TLS, but runtime `base_url` accepts any `http` or `https` host.
- Manifest sandbox wall-clock timeout is `30_000 ms`; runtime request timeout defaults to `15_000 ms`.
- The runtime has no `credential_id` or shared Google auth mode; it requires direct API-key material in connector configuration.
- `self_check` reports configured field-mask and timeout state but does not prove live API-key validity.
- `get_place` trims leading slashes but does not otherwise validate resource path shape beyond nonblank input.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should align manifest operation IDs, runtime base URL enforcement, secretless Google auth support, live self-check semantics, and place resource-name validation before describing this connector as policy-complete.

## First-Slice Scope

The current Google Places README slice documents the existing runtime surface:

- direct Places API-key configuration
- Places API (New) text search, autocomplete, and place details
- operation-specific field-mask defaults and overrides
- local health, doctor, self-check, introspection, simulation, invoke, and shutdown behavior
- bound capability-token verification during invoke and simulate
- provider error mapping for 429/5xx retryable classes, timeouts, JSON errors, and configuration errors
- deterministic WireMock integration coverage and direct proof commands

## Auth And Scope Boundary

- Authentication mechanism: direct Google Places API key only.
- Home zone: `z:private`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zones: `z:private` and `z:work`.
- Runtime capability surface:
  - `google_places.read` gates all Places operations.
- The connector does not persist API keys, place queries, place IDs, addresses, provider payloads, or provider error bodies beyond process memory.
- Place queries, addresses, map URLs, phone numbers, business names, and language preferences can reveal user intent and location. Treat all live request and response data as private or work-zone data.

## Network And Runtime Invariants

- Production host in manifest: `places.googleapis.com`.
- Production API prefix: `/v1`.
- Production port: `443`.
- TLS is required by the manifest for live traffic.
- Manifest network policy denies private ranges and redirects for the declared operations.
- Runtime loopback or alternate `base_url` values are accepted by code and are intended for deterministic tests.
- Runtime request timeout: `15_000 ms` by default.
- There is no explicit retry loop in the current client; each operation performs one `reqwest` request.
- Sandbox profile is `strict`, with `64 MB` memory, `25%` CPU, `30_000 ms` wall-clock timeout, no exec, and no ptrace.
- The connector does not open inbound sockets and does not implement replay or streaming.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `google_places.read` | Search places, get autocomplete suggestions, fetch place details, and read local connector health metadata. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `google_places.search_text` | `POST /v1/places:searchText` | `google_places.read` | `Safe` | `Low` | `Strict` | Read-only ranked search for a free-form query. |
| `google_places.autocomplete` | `POST /v1/places:autocomplete` | `google_places.read` | `Safe` | `Low` | `Strict` | Read-only prediction list for an in-progress place query. |
| `google_places.get_place` | `GET /v1/{place}?languageCode=...` | `google_places.read` | `Safe` | `Low` | `Strict` | Read-only lookup for one Places API resource name. |
| `google_places.health` | local connector state | `google_places.read` | `Safe` | `Low` | `Strict` | Reports configured base URL, manifest hash, and field masks without provider I/O. |

## Explicit Non-Goals

The current implementation does not include:

- Google Cloud project setup, API enablement, API-key creation, API-key restriction management, or billing configuration
- OAuth, service accounts, shared Google discovery auth, credential references, or egress-proxy key injection
- Nearby Search, Place Photos, Address Validation, Geocoding, Routes, Maps JavaScript widgets, or Places SDK flows
- write or moderation operations against Google Maps data
- place-session accounting beyond accepting an autocomplete `session_token`
- durable query caches, analytics, quota ledgers, pagination stores, or map UI state

These are excluded on purpose:

- Places data often combines location intent, addresses, and business identifiers.
- Provider billing depends heavily on field masks and SKUs, so the connector should not silently broaden response fields.
- API-key provisioning and restriction policy belongs in a Google Cloud provisioning surface, not in this request-response connector.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configured state, API-key presence, base URL, request timeout, manifest hash, and configured field masks
- operation metadata with capability, risk, safety tier, idempotency, schemas, and AI hints
- bound capability-token verification during `invoke`
- simulation denial for unknown operation, unconfigured connector, missing handshake, and capability-token mismatch
- local-only self-check behavior

The deterministic integration evidence is anchored on connector-local tests covering:

- introspection metadata for all four runtime operations
- text search, autocomplete, and place-details request paths
- `X-Goog-Api-Key` and `X-Goog-FieldMask` headers
- default field masks and per-operation response parsing
- `languageCode` on place details
- bound capability-token setup in invoke tests
- blank field-mask and blank query validation
- retryability and FCP error mapping for configuration, API, HTTP, timeout, and JSON errors

## Source Notes

- `connectors/google-places/src/connector.rs` defines lifecycle handlers, operation metadata, capability-token verification, simulation, local readiness, and invoke dispatch.
- `connectors/google-places/src/client.rs` defines Places API paths, API-key and field-mask headers, request construction, response decoding, timeout, and provider error handling.
- `connectors/google-places/src/types.rs` defines configuration, input validation, field-mask defaults, and typed response shapes.
- `connectors/google-places/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/google-places/manifest.toml` defines the manifest operation catalog, network constraints, sandbox boundary, and zone policy.
- `connectors/google-places/tests/integration.rs` covers deterministic HTTP behavior and runtime invoke coverage.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/google_places_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- runtime operation inventory and metadata
- deterministic WireMock coverage for Places API (New) paths
- API-key header and field-mask behavior
- capability-token enforcement in invoke and simulate
- local readiness, validation, provider error, and retryability behavior
- formatting, check, test, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a Google Cloud project with Places API (New) enabled and a restricted test API key for live checks.
- Prefer field masks that request only the fields needed for the task.
- Use loopback WireMock fixtures for routine proof.

**Dedicated environment**:

- Keep live verification separate from production billing keys.
- Avoid broad wildcard field masks in live runs; Google documents wildcard masks as development-only because they can increase cost and latency.
- Use non-sensitive test queries and stable place resource names in archived evidence.

**Redaction rules**:

- Redact API keys, `X-Goog-Api-Key` headers, full request URLs, copied provider payloads, provider error bodies, and any billing project identifiers.
- Treat free-form queries, place IDs, place resource names, addresses, phone numbers, map URLs, business names, and language preferences as sensitive operational data.

**Common remediation**:

- If `configure` fails, provide a nonblank `api_key`, positive `request_timeout_ms`, and nonblank field masks.
- If `invoke` fails with `NotHandshaken`, complete handshake with the host public key before invoking.
- If `invoke` or `simulate` reports a missing capability, mint a bound token for `google_places.read` and the exact runtime operation ID.
- If Google rejects a request for missing fields, set the correct `field_mask` for the operation.
- If live calls unexpectedly target a non-Google host, inspect `base_url`; runtime currently trusts any `http` or `https` host while the manifest is stricter.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-google-places-readme cargo check -p fcp-google-places --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-google-places-readme cargo test -p fcp-google-places --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-google-places-readme cargo clippy -p fcp-google-places --all-targets --no-deps -- -D warnings`
- `ubs connectors/google-places/README.md`
