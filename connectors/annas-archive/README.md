# Anna's Archive Connector V3 Contract

> **Status**: manifest/runtime contract documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Primary upstream**: https://annas-archive.org

## Purpose

This document fixes the operator-facing contract for `fcp.annas-archive`. The connector exposes a read-only metadata/search surface for Anna's Archive book and document records.

The connector is intentionally a metadata and lookup bridge. It does not download books, fetch files, bypass provider access controls, manage mirrors, run bulk crawls, or persist archive data in connector state.

## Current Runtime Snapshot

The current crate exposes these operations:

- `annas.search`
- `annas.metadata`
- `annas.lookup.isbn`
- `annas.lookup.md5`

Important runtime truths the contract preserves:

- No authentication is required by the connector.
- Default base URL is `https://annas-archive.org`.
- Optional `base_url` overrides are accepted at configuration time and trimmed of trailing slashes.
- Manifest live-network policy allows `annas-archive.org` and `annas-archive.se` on port `443`.
- Runtime custom base URLs are primarily for deterministic loopback or mirror testing; live deployments should honor the manifest host policy.
- HTTP client timeout is `30 seconds`.
- `annas.search` calls `GET /search` with query parameters `q`, `lang`, `ext`, and `sort`.
- `annas.metadata` calls `GET /md5/{md5}`.
- `annas.lookup.isbn` calls `GET /isbn/{isbn}`.
- `annas.lookup.md5` calls `GET /md5/{md5}`.
- Search input requires `query`; `lang`, `ext`, and `sort` are optional strings.
- Metadata and MD5 lookup require `md5`.
- ISBN lookup requires `isbn`.
- Upstream 404, 429, 503, and other provider failures are mapped into FCP external/rate-limit/service errors.

## First-Slice Scope

The current Anna's Archive README slice documents the existing runtime surface:

- no-auth configuration
- default host and custom base URL behavior
- search by keyword, title, author, or topic
- metadata lookup by MD5
- ISBN lookup
- MD5 lookup
- provider error mapping and redaction posture
- lifecycle, introspection, simulation, doctor, self-check, and shutdown surfaces

## Auth And Scope Boundary

- Authentication mechanism: none.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Capability surface:
  - `annas.search` gates keyword search.
  - `annas.read` gates metadata, ISBN lookup, and MD5 lookup.
- The connector does not persist queries, ISBNs, MD5 values, titles, authors, returned metadata, provider payloads, or provider error bodies.
- The manifest forbids `media.download`; this connector is not a content retrieval or file download surface.

## Network And Runtime Invariants

- Default production host: `annas-archive.org`.
- Alternate manifest-allowed production host: `annas-archive.se`.
- Production port: `443`.
- TLS and SNI are required for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live operations.
- Runtime custom base URL overrides are test or operator-controlled mirror inputs, not a separate manifest live-host expansion.
- Runtime request timeout: `30 seconds`.
- Manifest network constraints set total timeout `30_000 ms`.
- Maximum response bytes are `10_485_760` for search and ISBN lookup, and `1_048_576` for metadata and MD5 lookup.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `300_000 ms` wall-clock timeout, no exec, and no ptrace.
- Handshake declares no FCP streaming support.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `annas.search` | Search archive metadata by query and optional filters. |
| `annas.read` | Read metadata records by MD5 or lookup records by ISBN/MD5. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `annas.search` | `GET /search?q=...` | `annas.search` | `Safe` | `Low` | `Strict` | Read-only metadata search over caller-supplied query and optional filters. |
| `annas.metadata` | `GET /md5/{md5}` | `annas.read` | `Safe` | `Low` | `Strict` | Read-only detail lookup for a known MD5 identifier. |
| `annas.lookup.isbn` | `GET /isbn/{isbn}` | `annas.read` | `Safe` | `Low` | `Strict` | Read-only lookup for records associated with an ISBN. |
| `annas.lookup.md5` | `GET /md5/{md5}` | `annas.read` | `Safe` | `Low` | `Strict` | Read-only lookup for a specific MD5 identifier. |

## Explicit Non-Goals

The current implementation does not include:

- file downloads or media retrieval
- fast-download links, account-only API surfaces, membership workflows, or mirror management
- bulk metadata export, torrent handling, crawling, or scraping loops
- metadata correction, upload, or provider-side write operations
- DOI-specific, Open Library, LibGen, or external catalog aggregation beyond returned provider data
- webhook ingest or provider-side push events
- FCP subscription-based streaming
- connector-local credential vaulting

These are excluded on purpose:

- The useful first slice is a narrow read-only metadata and lookup bridge.
- Returned metadata can describe copyrighted works, so logs and verification must avoid dumping full provider payloads.
- Download behavior would require a separate high-risk capability contract and is not present in this connector.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration and handshake state
- request and error counters
- no-auth posture
- connector ID and version
- four operation descriptors with capability, risk, safety tier, idempotency, schemas, and AI hints
- simulation denial for unsupported operation IDs

The deterministic integration evidence is anchored on connector-local tests covering:

- default and custom base URL configuration
- no-auth doctor behavior
- handshake capability advertisement
- search, metadata, ISBN lookup, and MD5 lookup loopback requests
- missing required input handling
- provider 404, 429, 503, malformed JSON, and retryability behavior
- manifest operation inventory, rate-limit pools, safety tiers, and network constraints
- lifecycle, health, doctor, self-check, simulation, and shutdown behavior

## Source Notes

- `connectors/annas-archive/src/connector.rs` defines no-auth configuration, lifecycle handlers, diagnostics, introspection, simulation, and invoke dispatch.
- `connectors/annas-archive/src/client.rs` defines request paths, base URL trimming, timeout, provider error mapping, and redacted URL logging.
- `connectors/annas-archive/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/annas-archive/manifest.toml` defines operation schemas, network constraints, sandbox boundary, zone policy, rate limits, and AI hints.
- `connectors/annas-archive/tests/integration.rs` covers deterministic HTTP behavior and manifest/runtime contract checks.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/annas_archive_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- manifest/runtime operation agreement
- deterministic HTTP coverage for all four operations
- no-auth lifecycle behavior
- input validation, provider error, lifecycle, and introspection tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- No API key is required for the current connector.
- Use deterministic loopback fixtures for routine proof.
- Use live provider checks sparingly and avoid sensitive search terms.

**Dedicated environment**:

- Keep live queries synthetic and non-sensitive.
- Treat returned titles, authors, metadata, and identifiers as untrusted external content.
- Keep file retrieval and bulk metadata workflows out of this connector until separate beads define those contracts.

**Redaction rules**:

- Redact private query text, sensitive ISBNs or MD5 identifiers, titles when sensitive, authors when sensitive, provider payloads, provider error bodies, and returned metadata dumps.
- Verification output should use operation IDs, endpoint shapes, host classes, result counts, status/error classes, retry decisions, and payload-shape summaries.

**Common remediation**:

- If `health` reports `unconfigured`, call `configure` before `handshake`.
- If search validation fails, provide a non-empty string `query`; use `lang`, `ext`, and `sort` only as optional strings.
- If metadata or MD5 lookup fails validation, provide an `md5` string.
- If ISBN lookup fails validation, provide an `isbn` string.
- If live networking fails, verify the configured base URL, provider availability, TLS behavior, and manifest host policy.
- If the upstream returns 429, respect retry-after behavior where present and let caller-owned retry scheduling decide when to reissue.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-annas-archive-readme cargo check -p fcp-annas-archive --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-annas-archive-readme cargo test -p fcp-annas-archive --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-annas-archive-readme cargo clippy -p fcp-annas-archive --all-targets --no-deps -- -D warnings`
