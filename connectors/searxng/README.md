# SearXNG Connector V3 Contract

> **Status**: manifest/runtime contract documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/searxng_manifest_operations_verification.sh`
> **Primary upstream**: https://docs.searxng.org/

## Purpose

This document fixes the operator-facing contract for `fcp.searxng`. The connector is a self-hosted, read-only SearXNG meta-search adapter with an operator-configured host policy, optional auth header support, and no commercial search fallback. Returned search content is treated as untrusted external content, and query/result evidence is redaction-sensitive.

## Current Runtime Snapshot

The current crate exposes these operations:

- `searxng.search.query`
- `searxng.search.images`
- `searxng.search.news`
- `searxng.health`

Important runtime truths the contract preserves:

- Configuration requires `base_url` because SearXNG is self-hosted/operator-hosted.
- Loopback, private-range, and tailnet targets require explicit opt-in through `allow_loopback`, `allow_private_ranges`, or `allow_tailnet_ranges`.
- Public HTTP is rejected unless the hostname is explicitly listed in `allow_operator_http_hosts`; public HTTPS is the default safe class.
- Optional authentication is either `bearer_token` or a custom `auth_header_name` plus `auth_header_value`.
- The runtime never falls back to a commercial search provider.
- Query text is hashed in connector outputs and logs.
- Result URLs, snippets, image metadata, answers, and suggestions are external untrusted content.
- The runtime is non-streaming and has no listener surface.

## First-Slice Scope

The first SearXNG slice is intentionally narrow:

- run text/meta-search against an operator-configured instance
- run image search with default `categories=images` when categories are omitted
- run news search with default `categories=news` when categories are omitted
- probe `/stats` for instance health
- support language, safe-search, time-range, page, result-count, category, and engine filters
- expose manifest-derived introspection for the operation catalog

## Auth And Scope Boundary

- Authentication mechanism: optional bearer token or custom static header.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zones: `z:public` and `z:work`.
- Forbidden zone: `z:community`.
- Capability surface:
  - `searxng.search.read` gates search and health operations.
- The connector does not store provider credentials and does not ingest webhooks or subscribe to provider events.

## Network And Runtime Invariants

- Production host policy: operator-configured `base_url`.
- Allowed ports in manifest: `80`, `443`, `8080`, and `8888`.
- TLS/SNI are optional at the manifest level because self-hosted instances can be HTTP loopback/private/tailnet services with explicit operator opt-in.
- Manifest network policy uses `host_allow = ["operator-configured"]`.
- Runtime policy rejects userinfo, query strings, fragments, unsupported schemes, and unapproved host classes.
- Default request timeout: `20_000 ms`.
- Maximum response bytes: `2_097_152`.
- Runtime advertises no replay, subscription, or streaming event support.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `searxng.search.read` | Run read-only text, image, news, and health operations against the configured instance. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `searxng.search.query` | `GET /search?format=json` | `searxng.search.read` | `Safe` | `Low` | `Strict` | Read-only meta-search returning normalized untrusted result records. |
| `searxng.search.images` | `GET /search?format=json&categories=images` | `searxng.search.read` | `Safe` | `Low` | `Strict` | Read-only image search returning normalized untrusted image records. |
| `searxng.search.news` | `GET /search?format=json&categories=news` | `searxng.search.read` | `Safe` | `Low` | `Strict` | Read-only news search returning normalized untrusted article records. |
| `searxng.health` | `GET /stats` | `searxng.search.read` | `Safe` | `Low` | `Strict` | Instance health probe against the configured SearXNG service. |

## Explicit Non-Goals

The first implementation slice does not include:

- hosting or provisioning a SearXNG instance
- commercial search fallback
- credential vaulting or dynamic credential injection
- webhook ingest or provider-side push events
- streaming result delivery
- logging raw queries, snippets, auth values, or full result URLs

These are excluded on purpose:

- SearXNG deployment posture belongs to the operator, not the connector runtime.
- The useful connector boundary is read-only search against a declared instance.
- Host-class opt-ins need to stay explicit because many real SearXNG instances live on loopback, private, or tailnet addresses.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, client, and handshake state
- auth mode
- base URL host class
- operator host-policy guidance
- no-commercial-fallback invariant
- privacy logging invariant
- `/stats` probe result
- operation catalog from the embedded manifest

The deterministic integration evidence is anchored on no-live-provider HTTP loopback runs covering:

- configured loopback host policy
- text, image, news, and health operation behavior
- manifest/runtime/schema unit contract tests
- manifest conformance for operator-configured host constraints
- cross-connector manifest operation audit evidence for `fcp.searxng`

## Source Notes

- `connectors/searxng/src/connector.rs` defines host-policy validation, optional auth headers, request construction, result normalization, lifecycle methods, and manifest-derived introspection.
- `connectors/searxng/manifest.toml` defines the four-operation catalog, operator-configured network boundary, sandbox boundary, and no-listener/no-exec capability posture.
- `connectors/searxng/tests/integration.rs` covers deterministic loopback behavior for the connector runtime.
- `connectors/searxng/tests/conformance.rs` verifies manifest shape and operator-configured host scoping.

## Verification Bundle

The closeout bundle is anchored on `scripts/e2e/searxng_manifest_operations_verification.sh`. It writes a redaction-safe JSONL log to the path supplied as its first argument, or to `/tmp/fcp-searxng-manifest-ops-<timestamp>.jsonl` by default.

The bundle captures:

- manifest/runtime/schema unit contract tests
- deterministic no-live-provider HTTP integration coverage
- cross-connector manifest operation audit evidence for `fcp.searxng`
- a JSONL record asserting 4 manifest operations and 4 runtime introspection operations

## Operator Guidance

**Prerequisites**:

- Provide an explicit `base_url` for the target SearXNG instance.
- Set `allow_loopback`, `allow_private_ranges`, `allow_tailnet_ranges`, or `allow_operator_http_hosts` only when that host class is intentional.
- Provide either `bearer_token` or `auth_header_name` plus `auth_header_value` if the instance requires authentication.

**Dedicated environment**:

- Prefer a disposable self-hosted SearXNG instance or loopback fixture for replayable evidence.
- Do not route sensitive searches through a public instance unless that exposure is acceptable.

**Redaction rules**:

- Redact bearer tokens, custom auth header names/values, raw query text, full result URLs, snippets, image URLs, answers, suggestions, provider payloads, and provider error bodies.
- Treat returned search records as untrusted external content.

**Common remediation**:

- If configuration rejects `base_url`, remove userinfo, query strings, and fragments, then use an allowed HTTP(S) scheme.
- If a loopback host is rejected, set `allow_loopback=true` only for a trusted test or local instance.
- If a private or tailnet host is rejected, use `allow_private_ranges=true` or `allow_tailnet_ranges=true` only for an intended internal instance.
- If public HTTP is rejected, switch to HTTPS or explicitly list the hostname in `allow_operator_http_hosts`.
- If `self_check` reports `not_configured`, configure the connector before probing `/stats`.
- If `self_check` reports `upstream_probe_failed`, verify the instance is reachable, the auth header is correct, and `/stats` is enabled.

**Rerun commands**:

- `CARGO_TARGET_DIR=/tmp/fcp-searxng-manifest-ops-target scripts/e2e/searxng_manifest_operations_verification.sh`
- `rch exec -- cargo test --locked -p fcp-searxng manifest --lib -- --nocapture`
- `rch exec -- cargo test --locked -p fcp-searxng --test integration -- --nocapture`
- `rch exec -- cargo run --locked -p fcp-conformance --bin fcp-manifest-ops-audit -- --repo-root . --allow-findings --log-jsonl /tmp/fcp-searxng-manifest-ops.jsonl`
