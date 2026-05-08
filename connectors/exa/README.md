# Exa Connector V3 Contract

> **Status**: manifest/runtime contract documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Primary upstream**: https://exa.ai/docs/reference/search

## Purpose

This document fixes the operator-facing contract for `fcp.exa`. The connector exposes Exa's read-only web search endpoint and optional search-result content extraction controls.

The connector is intentionally a search-only first slice. It does not crawl, fetch arbitrary page contents outside Exa's search response, manage datasets, answer questions, or provide durable retrieval storage.

## Current Runtime Snapshot

The current crate exposes this operation:

- `exa.search`

Important runtime truths the contract preserves:

- Configuration requires exactly one of `api_key` or `credential_id`.
- API-key mode sends `x-api-key: ...` plus `x-exa-integration: fcp`.
- Credential-id mode is accepted at configuration time but cannot perform live requests in this connector slice.
- Default base URL is `https://api.exa.ai`.
- Non-loopback base URLs must use HTTPS and a host under `exa.ai`.
- Loopback HTTP/HTTPS base URLs are accepted only for deterministic tests.
- A base URL ending in `/search` is normalized so requests still call exactly one `/search` path.
- Default `request_timeout_ms` is `60_000`.
- `query` is required, trimmed, and must not be empty.
- `numResults` is numeric and is clamped to 1 through 100.
- `type` must be one of `auto`, `neural`, `fast`, `deep`, `deep-reasoning`, or `instant`.
- `contents` may include only `text`, `highlights`, and `summary`.
- `contents.text` accepts boolean or object form with positive `maxCharacters`.
- `contents.highlights` accepts boolean or object form with positive `maxCharacters`, `numSentences`, `highlightsPerUrl`, and string `query`.
- `contents.summary` accepts boolean or object form with string `query`.
- `useAutoprompt`, `category`, `includeDomains`, and `excludeDomains` are passed through when present.
- Upstream 429 and server errors are surfaced as retryable external errors.
- `Retry-After` is parsed when present.

## First-Slice Scope

The first Exa README slice documents the existing runtime surface:

- search through `POST /search`
- direct `x-api-key` auth
- host credential reference configuration with explicit live-request limitation
- base URL normalization and production host allow-listing
- search query, result-count, type, and content-control validation
- pass-through domain/category/autoprompt options
- provider error and timeout mapping
- lifecycle, introspection, simulation, doctor, self-check, and shutdown surfaces

## Auth And Scope Boundary

- Authentication mechanisms: Exa API key or host credential reference.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Capability surface:
  - `exa.search` gates the search operation.
- The connector does not persist queries, result URLs, extracted snippets, answer payloads, API keys, or credential IDs.
- Credential-id mode is configuration metadata only in this slice; host-side credential injection is not implemented by the connector runtime.

## Network And Runtime Invariants

- Production host: `api.exa.ai`.
- Production path: `/search`.
- Production port: `443`.
- TLS and SNI are required for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live operations.
- Runtime loopback overrides are test-only.
- Runtime default `request_timeout_ms`: `60_000`.
- Manifest network constraints set total timeout `60_000 ms`.
- Maximum response bytes are `10_485_760`.
- Sandbox profile is `strict`, with `96 MB` memory, `25%` CPU, `30_000 ms` wall-clock timeout, no exec, and no ptrace.
- Handshake declares no FCP streaming support.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `exa.search` | Execute read-only Exa web search and optional result content extraction. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `exa.search` | `POST /search` | `exa.search` | `Safe` | `Low` | `Strict` | Read-only search over caller-supplied query text and optional result-content extraction controls. |

## Explicit Non-Goals

The current implementation does not include:

- Exa contents endpoint as a standalone operation
- Exa answer, research, websets, monitors, or team-management endpoints
- connector-managed crawling or recursive page retrieval
- search result persistence, vector storage, ranking feedback, or deduplication
- provider account or key management
- public-zone invocation
- FCP subscription-based streaming
- connector-local credential vaulting

These are excluded on purpose:

- The useful first slice is a narrow, read-only search bridge that keeps query handling explicit.
- Exa's broader contents and research surfaces need their own capability contracts before being exposed.
- Search responses can include page text and highlights, so verification should avoid logging sensitive query text or raw result snippets from real users.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, handshake state, auth mode, base URL, request counters, and error counters
- credential-injection warnings when `credential_id` is configured
- the explicit search-only surface boundary
- supported operation metadata derived from the embedded manifest
- simulation denial for unsupported operations and credential-id live requests

The deterministic integration evidence is anchored on WireMock and connector-local tests covering:

- `x-api-key` and `x-exa-integration` header behavior
- `/search` request body construction
- base URL suffix normalization to avoid double `/search` paths
- `numResults` clamping to 100
- `type` validation including `deep-reasoning`
- `contents` option validation for text, highlights, and summary
- expected upstream error handling
- structured E2E connector-suite logging
- manifest-backed introspection metadata

## Source Notes

- `connectors/exa/src/connector.rs` defines configuration parsing, auth handling, base URL normalization, search request validation, provider error mapping, lifecycle handlers, diagnostics, and manifest-backed introspection.
- `connectors/exa/manifest.toml` defines the search-only operation catalog, network constraints, sandbox boundary, zone policy, and operation AI hints.
- `connectors/exa/tests/connector_suite_happy_path.rs` covers deterministic search happy path, suffix-normalized base URL behavior, `numResults` clamping, content options, and error-path behavior.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/exa_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- manifest/runtime contract tests
- deterministic WireMock search coverage
- auth, base URL, query, result-count, type, contents, error, lifecycle, and introspection tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use an Exa API key for live provider verification.
- Do not expect `credential_id` mode to perform live requests until a host egress injection layer is wired for this connector.
- Prefer synthetic queries for deterministic verification.
- Use WireMock loopback fixtures for routine proof.

**Dedicated environment**:

- Use a test Exa account for live runs.
- Keep live queries short and non-sensitive.
- Keep standalone contents retrieval, answer generation, research, and websets out of this connector until separate beads define those contracts.

**Redaction rules**:

- Redact API keys, credential IDs where needed, private query text, result snippets, highlighted text, summaries, result URLs when sensitive, provider payloads, and provider error bodies.
- Verification output should use operation names, result counts, search type, content option shape, status/error classes, retry decisions, and path/host classes.

**Common remediation**:

- If `health` reports `unconfigured`, configure with exactly one of `api_key` or `credential_id`.
- If `health` reports `degraded` under `credential_id`, switch to API-key mode or add host egress credential injection before live requests.
- If base URL validation fails, use `https://api.exa.ai` or a loopback test origin.
- If search validation fails, check for an empty query, invalid `type`, non-object `contents`, unknown `contents` fields, or non-positive content limits.
- If the upstream returns 429, respect `Retry-After` where present and let caller-owned retry scheduling decide when to reissue.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-exa-e2e cargo check -p fcp-exa --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-exa-e2e cargo test -p fcp-exa --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-exa-e2e cargo clippy -p fcp-exa --all-targets --no-deps -- -D warnings`
