# Supabase Connector V3 Contract

> **Status**: runtime contract documented with manifest capability, simulation, and approval-token drift
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/supabase_connector_verification.sh`
> **Supabase Data API upstream**: https://supabase.com/docs/guides/api
> **Supabase API keys upstream**: https://supabase.com/docs/guides/getting-started/api-keys
> **Supabase Storage upstream**: https://supabase.com/docs/guides/storage
> **Supabase Storage uploads upstream**: https://supabase.com/docs/guides/storage/uploads/standard-uploads
> **Supabase Storage access control upstream**: https://supabase.com/docs/guides/storage/security/access-control

## Purpose

This document fixes the operator-facing contract for `fcp.supabase`. The connector exposes the Supabase project API surface implemented in this crate: PostgREST table reads and mutations, PostgREST RPC, OpenAPI-based schema discovery, health probing, and Supabase Storage object upload/download/delete.

The connector is intentionally a bounded Supabase Data API and Storage bridge. It is not a Supabase Management API client, project creator, database migration runner, auth admin client, Realtime subscriber, Edge Functions client, GraphQL client, dashboard automation layer, or connector-local credential vault.

## Current Runtime Snapshot

The current crate exposes these operations:

- `supabase.query`
- `supabase.insert`
- `supabase.update`
- `supabase.upsert`
- `supabase.delete`
- `supabase.rpc`
- `supabase.schema.tables`
- `supabase.storage.upload`
- `supabase.storage.download`
- `supabase.storage.delete`
- `supabase.health`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-supabase`.
- Runtime `BaseConnector` ID is `fcp.supabase`.
- Manifest connector ID is `fcp.supabase`.
- Connector version is `0.1.0`.
- Configuration fields are:
  - `project_url`, defaulting to placeholder `https://project-ref.supabase.co`
  - optional `api_key`
  - `schema`, defaulting to `public`
  - `request_timeout_ms`, defaulting to `30000`
- If `api_key` is present and non-empty, runtime sends both `apikey: <key>` and `Authorization: Bearer <key>`.
- If `api_key` is absent or empty, runtime enters secretless mode and expects host or egress-proxy credential injection.
- Production `project_url` must be a root HTTPS URL whose host ends in `.supabase.co`.
- Loopback project URLs are accepted for deterministic tests.
- Runtime REST URL is `{project_url}/rest/v1`.
- Runtime Storage URL is `{project_url}/storage/v1`.
- Runtime reqwest timeout and request context timeout follow `request_timeout_ms`.
- Runtime retry policy uses `max_retries = 2`.
- Runtime handshake installs a `CapabilityVerifier` and returns a SHA-256 hash of `manifest.toml`.
- Runtime `invoke` verifies a bound capability token for the operation capability, but currently uses an empty resource URI list.
- Runtime `simulate` always returns allowed and does not validate operation identity, readiness, input shape, capability, or approval state.
- `doctor()` and `self_check()` include operator guidance, provisioning readiness, manifest hash, and verification script paths.
- `health()` is local provisioning state plus guidance; provider reachability is checked by `self_check()` and the `supabase.health` operation.
- `shutdown()` shuts down client/runtime state and clears configuration, client, verifier, and configured/handshaken flags.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Manifest `[capabilities].optional` is empty even though every operation uses `supabase.read`, `supabase.write`, or `supabase.storage`.
- Runtime verifies capability tokens but binds them to no resource URIs, so table, bucket, path, schema, and function names are not part of connector-local capability checks.
- Runtime `simulate` is permissive for every request.
- Manifest and runtime introspection mark `supabase.delete` and `supabase.storage.delete` as interactive approval operations, but invoke checks no approval token.
- Runtime uses the Supabase project root host only. It does not use direct Storage hostnames such as `https://<project-ref>.storage.supabase.co` for large uploads.
- Runtime upload sends a raw object body to `/storage/v1/object/{bucket}/{path}` with `x-upsert`; Supabase's high-level standard-upload docs describe SDK/multipart flows and recommend resumable uploads for larger files.
- Runtime key classification supports `sb_publishable_`, `sb_secret_`, JWT `anon`, JWT `service_role`, and opaque keys, but live permissions still depend on project RLS and Storage policies.
- The verification script creates timestamped artifacts under `artifacts/e2e/supabase_connector/<timestamp>`, which are evidence outputs and not connector runtime state.

A follow-up parity bead should list the Supabase capability IDs in the manifest, add resource URI binding for tables/functions/buckets/paths, make simulation meaningful, clarify approval enforcement responsibilities, decide whether direct Storage host support belongs in runtime, and expand live/staging proof guidance around RLS and Storage policies.

## First-Slice Scope

The current Supabase README slice documents the existing runtime surface:

- direct API-key and secretless host-injection configuration
- project URL policy, key classification, default schema, timeout, retry, provider error, and redaction behavior
- PostgREST query/insert/update/upsert/delete/RPC/schema/health operations
- Storage upload/download/delete operations
- capability-token verification, approval metadata, doctor, health, self-check, simulate, introspect, shutdown, and verification artifacts
- runtime/manifest drift around optional capabilities, resource binding, simulation, approval checks, and direct Storage host support

## Auth And Zone Boundary

- Authentication mechanisms: Supabase API key or host/egress-proxy credential injection.
- Runtime does not implement Supabase Dashboard login, OAuth, Management API access tokens, Auth admin APIs, API-key creation, API-key rotation, JWT minting, service-role vaulting, or connector-local credential storage.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Capability families:
  - `supabase.read`
  - `supabase.write`
  - `supabase.storage`
- Supabase rows, RPC arguments, OpenAPI schemas, bucket names, object paths, downloaded object bodies, project refs, JWT claims, and provider errors can expose private application data. Do not log raw API keys, bearer headers, private row payloads, object contents, bucket paths, or full provider error bodies in shared artifacts.

## Network And Runtime Invariants

- Default runtime project URL: `https://project-ref.supabase.co`.
- Live production host suffix: `.supabase.co`.
- Runtime endpoint families:
  - `GET /rest/v1/{table}`
  - `POST /rest/v1/{table}`
  - `PATCH /rest/v1/{table}`
  - `DELETE /rest/v1/{table}`
  - `POST /rest/v1/rpc/{function}`
  - `GET /rest/v1/`
  - `POST /storage/v1/object/{bucket}/{path}`
  - `GET /storage/v1/object/authenticated/{bucket}/{path}`
  - `GET /storage/v1/object/public/{bucket}/{path}`
  - `DELETE /storage/v1/object/{bucket}/{path}`
- Runtime table, schema, bucket, function, filter-column, filter-operator, order-column, and conflict-column identifiers accept ASCII alphanumeric plus `_`, `-`, and `.`.
- Runtime storage paths trim leading/trailing slashes and reject empty paths or empty path segments.
- Runtime storage object path segments are percent-encoded.
- Runtime query operations use PostgREST query parameters for `select`, filters, `order`, `limit`, and `offset`.
- Runtime single-object reads use `Accept: application/vnd.pgrst.object+json`.
- Runtime schema selection uses `Accept-Profile` and `Content-Profile` headers.
- Runtime mutation return behavior uses PostgREST `Prefer: return=minimal` or `Prefer: return=representation`.
- Runtime maps 401 to auth errors, 403 to permission-denied, 404 to not found, 409 to conflict, 429 to retryable rate-limit using `Retry-After` with a 30 second default, 408 to timeout, retryable transport/server failures through the shared retry loop, and other non-success responses to provider API errors.
- Manifest live-operation policy requires TLS/SNI, denies localhost, private ranges, tailnet ranges, and IP literals, and allows `*.supabase.co` on port 443.
- Sandbox profile is `strict`, with `128 MB` memory, `25%` CPU, `30000 ms` wall-clock timeout, no exec, and no ptrace.
- The connector does not open inbound sockets.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `supabase.read` | Read table/view rows, inspect exposed schema, and check PostgREST health. |
| `supabase.write` | Insert, update, upsert, delete rows, and invoke PostgREST RPC functions. |
| `supabase.storage` | Upload, download, and delete Supabase Storage objects. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Required input |
|-----------|----------------|------------|------------|-----------|-------------|----------------|
| `supabase.query` | `GET /rest/v1/{table}` | `supabase.read` | `Safe` | `Low` | `Strict` | `table`; optional `schema`, `select`, `filters`, `order`, `limit`, `offset`, `single`. |
| `supabase.insert` | `POST /rest/v1/{table}` | `supabase.write` | `Risky` | `Medium` | `Strict` | `table`, non-empty `rows`; optional `schema`, `returning`. |
| `supabase.update` | `PATCH /rest/v1/{table}` | `supabase.write` | `Risky` | `Medium` | `Strict` | `table`, JSON-object `values`, non-empty `filters`; optional `schema`, `returning`. |
| `supabase.upsert` | `POST /rest/v1/{table}` | `supabase.write` | `Risky` | `Medium` | `Strict` | `table`, non-empty `rows`; optional `schema`, `on_conflict`, `ignore_duplicates`, `returning`. |
| `supabase.delete` | `DELETE /rest/v1/{table}` | `supabase.write` | `Dangerous` | `High` | `Strict` | `table`, non-empty `filters`; optional `schema`, `returning`. |
| `supabase.rpc` | `POST /rest/v1/rpc/{function}` | `supabase.write` | `Risky` | `Medium` | `BestEffort` | `function`; optional `schema`, `args`. |
| `supabase.schema.tables` | `GET /rest/v1/` | `supabase.read` | `Safe` | `Low` | `Strict` | Optional `schema`. |
| `supabase.storage.upload` | `POST /storage/v1/object/{bucket}/{path}` | `supabase.storage` | `Risky` | `Medium` | `BestEffort` | `bucket`, `path`, `content_base64`; optional `content_type`, `upsert`. |
| `supabase.storage.download` | `GET /storage/v1/object/{scope}/{bucket}/{path}` | `supabase.storage` | `Safe` | `Low` | `None` | `bucket`, `path`; optional `public`, `download_filename`. |
| `supabase.storage.delete` | `DELETE /storage/v1/object/{bucket}/{path}` | `supabase.storage` | `Dangerous` | `High` | `Strict` | `bucket`, `path`. |
| `supabase.health` | `GET /rest/v1/` | `supabase.read` | `Safe` | `Low` | `Strict` | None. |

## Explicit Non-Goals

The current implementation does not include:

- Supabase Management API, project creation, organization management, billing, database branching, API-key lookup, API-key rotation, or dashboard automation
- Supabase Auth user/admin flows, OAuth provider setup, JWT minting, invite links, password reset, service-role vaulting, or session refresh
- Realtime channels, database change subscriptions, Broadcast, Presence, or WebSocket flows
- Edge Functions invoke/deploy/secret-management flows
- GraphQL, SQL editor, migrations, pg_dump/restore, logical replication, row-level-security authoring, grant management, or policy generation
- Storage bucket creation/update/delete, signed URLs, resumable TUS uploads, S3-compatible access, image transformations, object moves/copies, object search, or CDN controls
- connector-local persistence of rows, RPC output, OpenAPI schemas, downloaded objects, bucket metadata, project metadata, credentials, counters, or provider responses beyond process memory

These are excluded on purpose:

- Row mutations and Storage deletes can permanently alter production application state.
- PostgREST and Storage authorization are policy-dependent; a reachable REST root does not prove table, RPC, or bucket permissions.
- Secretless mode belongs to host egress policy, not connector-local credential storage.
- Direct project management and Auth admin APIs need a different privilege and audit contract than table/object operations.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, client, runtime, handshake, project URL, key classification, credential-injection, and project-ref alignment state
- operator guidance, remediation hints, redaction rules, verification script path, and artifact root hint
- live self-check through `GET /rest/v1/` when an API key is configured and project URL policy passes
- degraded self-check for secretless mode and publishable/anon-style keys
- operation metadata, schemas, capability IDs, risk levels, safety tiers, idempotency classes, approval metadata, and agent hints
- bound capability-token verification during `invoke`
- typed provider/FCP error mapping

The deterministic integration evidence is anchored on connector-local tests covering:

- doctor, health, self-check, key classification, project URL policy, project-ref mismatch, secretless degradation, and publishable-key degradation
- query filters, ordering, limit, content-range count parsing, insert, RPC, OpenAPI schema discovery, Storage upload, Storage delete, and introspection evidence
- FCP invoke/handshake dispatch, capability tokens, unknown operation rejection, and missing input rejection
- provider auth, permission, not found, conflict, rate-limit, timeout, API, JSON, transport, path normalization, identifier validation, and redaction behavior

## Source Notes

- `connectors/supabase/src/connector.rs` defines configuration parsing, provisioning readiness, key classification, project URL policy, lifecycle handlers, diagnostics, introspection, simulation, capability-token verification, and invoke dispatch.
- `connectors/supabase/src/client.rs` defines Supabase REST and Storage request construction, auth headers, schema/profile headers, retry dispatch, timeout configuration, path/query encoding, binary response handling, and provider error mapping.
- `connectors/supabase/src/types.rs` defines table query, mutation, RPC, schema, Storage, response, and provider error shapes.
- `connectors/supabase/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/supabase/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, and state claim.
- `connectors/supabase/tests/integration.rs` covers deterministic HTTP behavior, lifecycle behavior, diagnostics, operation dispatch, evidence output, and contract assertions.
- `scripts/e2e/supabase_connector_verification.sh` runs the manifest, cargo, evidence-test, integration, and clippy proof bundle and records artifacts.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/supabase/README.md
ubs connectors/supabase/README.md
LC_ALL=C rg -n '[^ -~]' connectors/supabase/README.md
rg -n '\bmaster\b' connectors/supabase/README.md
```

For source or behavior changes, use the tracked connector proof lane:

```bash
scripts/e2e/supabase_connector_verification.sh
```

The verification script runs:

```bash
fwc manifest fix connectors/supabase/manifest.toml --check --json
rch exec -- cargo check -p fcp-supabase --all-targets
rch exec -- cargo fmt -p fcp-supabase -- --check
rch exec -- cargo test -p fcp-supabase --test integration self_check_ready_with_secret_key_and_evidence -- --nocapture
rch exec -- cargo test -p fcp-supabase --test integration storage_delete_preserves_artifact_evidence -- --nocapture
rch exec -- cargo test -p fcp-supabase --test integration introspection_emits_v3_compliance_evidence -- --nocapture
rch exec -- cargo test -p fcp-supabase --test integration -- --nocapture
rch exec -- cargo clippy -p fcp-supabase --all-targets -- -D warnings
```

For README-only changes, the local Markdown/ASCII/branch-name/UBS checks above are sufficient.

## Operator Guidance

- Use a dedicated Supabase staging project for mutation proof.
- Seed disposable tables, RPC functions, and Storage buckets before invoking writes or deletes.
- Prefer secretless mode when host policy owns credential injection; expect `self_check()` to degrade until injected credentials are available.
- Treat publishable and anon-style keys as policy-limited even when the REST root is reachable.
- Treat `supabase.delete` and `supabase.storage.delete` as approval-gated until runtime approval enforcement is clarified.
- Verify table RLS, function grants, bucket policies, and object-path policy separately; PostgREST health does not prove them.
- Redact raw API keys, bearer headers, project refs when sensitive, row payloads, object bodies, bucket names, and provider errors in shared artifacts.
