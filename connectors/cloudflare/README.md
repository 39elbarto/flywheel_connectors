# Cloudflare Connector V3 Contract

> **Status**: runtime contract documented with known manifest/capability metadata drift
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/cloudflare_connector_verification.sh`
> **Primary upstream**: https://developers.cloudflare.com/api/
> **API token upstream**: https://developers.cloudflare.com/fundamentals/api/get-started/create-token/
> **DNS upstream**: https://developers.cloudflare.com/api/resources/dns/subresources/records/
> **Workers upstream**: https://developers.cloudflare.com/api/resources/workers/subresources/scripts/
> **Pages upstream**: https://developers.cloudflare.com/api/resources/pages/subresources/projects/
> **KV upstream**: https://developers.cloudflare.com/api/resources/kv/subresources/namespaces/

## Purpose

This document fixes the operator-facing contract for `fcp.cloudflare`. The connector exposes the Cloudflare surface implemented in this crate: zones, credential health, DNS records, Workers scripts, Pages projects/deployments, and Workers KV values.

The connector is intentionally a bounded Cloudflare API v4 operations bridge. It is not a full Cloudflare SDK, Wrangler replacement, account administration tool, tunnel manager, Pages project creator, DNS zone provisioner, Workers asset bundler, webhook receiver, GraphQL analytics client, or Terraform-like reconciler.

## Current Runtime Snapshot

The current runtime exposes these operations:

- `cloudflare.zones.list`
- `cloudflare.health`
- `cloudflare.dns.list_records`
- `cloudflare.dns.create_record`
- `cloudflare.dns.update_record`
- `cloudflare.dns.delete_record`
- `cloudflare.workers.list`
- `cloudflare.workers.get`
- `cloudflare.workers.deploy`
- `cloudflare.workers.delete`
- `cloudflare.pages.list_projects`
- `cloudflare.pages.create_deployment`
- `cloudflare.kv.get`
- `cloudflare.kv.put`
- `cloudflare.kv.delete`

Important runtime truths the contract preserves:

- Configuration requires `account_id`, `mode`, and auth fields for the selected mode.
- Supported auth modes are:
  - `api_token` with `api_token`
  - `api_key` with `api_key` and `email`
- API-token mode sends `Authorization: Bearer <api_token>`.
- API-key mode sends `X-Auth-Key` and `X-Auth-Email`; this is treated as a legacy global-key mode in diagnostics.
- Empty token/key material is accepted as secretless mode so the host or egress proxy can inject auth headers.
- Empty secret material makes `health` and `self_check` degraded with `credential_injection_required`.
- `account_id`, `base_url`, token/key material, and email are trimmed on configure.
- Default base URL is `https://api.cloudflare.com/client/v4`.
- Production base URL policy requires HTTPS, host `api.cloudflare.com`, and path prefix `/client/v4`.
- Loopback or `.localhost` origins are accepted for deterministic tests.
- `request_timeout_ms` defaults to `30_000` and must be greater than zero.
- The client uses the shared retry loop for provider dispatch.
- Retryable classes include connect/timeout transport failures, HTTP 429, selected 5xx/Cloudflare edge errors, and retryable Cloudflare envelope errors.
- 401 and 403 map to unauthorized; 404 maps to not found.
- Error bodies are sanitized and truncated before surfacing.
- Handshake installs a bound `CapabilityVerifier`.
- `invoke` verifies bound capability tokens against the requested operation and computed Cloudflare resource URI list.
- `simulate` currently returns allowed for any request ID without validating readiness, operation ID, input schema, approval state, or capability token.
- `health` is local readiness plus provisioning detail and does not call Cloudflare.
- `self_check` calls `/user/tokens/verify` when credential material is configured.
- `introspect` exposes no streaming support.

## Known Contract Gaps

The runtime, manifest, and policy metadata are not fully aligned in this checkout:

- `manifest.toml` has `capabilities.optional = []`, while manifest operation entries and runtime introspection use operation-specific capabilities such as `cloudflare.dns.read`, `cloudflare.dns.write`, `cloudflare.workers.write`, and `cloudflare.kv.write`.
- `simulate` is less strict than `invoke`; it does not exercise the bound capability verifier.
- `cloudflare.workers.deploy` accepts raw JavaScript source only. It does not support module metadata, assets, bindings, compatibility dates, secrets, routes, or Wrangler-style upload bundles.
- `cloudflare.pages.create_deployment` sends only `{ "branch": <branch> }` to the deployment endpoint.
- `cloudflare.kv.put` writes a string value only. It does not support metadata, expiration, multipart form fields, or bulk writes.
- `cloudflare.kv.get` returns the raw value as a string and does not decode JSON.
- DNS update is a full `PUT` style replacement using the runtime fields, not a partial patch operation.

Operators should treat this README as the current truthfulness snapshot. A follow-up should align manifest optional capabilities, tighten simulation, and expand operation-specific provider payload support before this connector is described as complete Cloudflare coverage.

## First-Slice Scope

The current Cloudflare README slice documents the existing runtime surface:

- API-token and legacy global API-key configuration
- secretless credential-injection mode
- Cloudflare API v4 base URL policy
- token health verification through `/user/tokens/verify`
- zone listing
- DNS list/create/update/delete
- Workers list/get/deploy/delete
- Pages project listing and branch deployment trigger
- Workers KV get/put/delete
- lifecycle, doctor, health, self-check, introspection, simulation, and shutdown surfaces
- deterministic WireMock tests and the tracked verification bundle

## Auth And Scope Boundary

- Authentication mechanisms: scoped Cloudflare API token, legacy global API key plus email, or secretless host injection.
- Scoped API tokens are preferred for live verification.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Capability surface:
  - `cloudflare.zones.read` gates zone listing and credential health.
  - `cloudflare.dns.read` gates DNS record listing.
  - `cloudflare.dns.write` gates DNS record create, update, and delete.
  - `cloudflare.workers.read` gates Workers listing and script metadata lookup.
  - `cloudflare.workers.write` gates Workers deploy and delete.
  - `cloudflare.pages.read` gates Pages project listing.
  - `cloudflare.pages.write` gates Pages deployment creation.
  - `cloudflare.kv.read` gates Workers KV value reads.
  - `cloudflare.kv.write` gates Workers KV value writes and deletes.
- The connector does not persist Cloudflare responses, account IDs, zone IDs, DNS record IDs, Workers scripts, Pages deployments, KV keys/values, API tokens, API keys, provider payloads, or provider error bodies.

## Network And Runtime Invariants

- Production host: `api.cloudflare.com`.
- Production API prefix: `/client/v4`.
- Production port: `443`.
- TLS and SNI are required for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live operations.
- Runtime loopback and `.localhost` overrides are test-only.
- Runtime request timeout defaults to `30_000 ms`.
- Manifest network constraints set `5_000 ms` connect timeout and `30_000 ms` total timeout.
- Maximum response bytes vary by operation:
  - `16_777_216` for DNS record listing and Workers deploy.
  - `8_388_608` for zone, Workers, and Pages listing.
  - `4_194_304` for DNS create/update, Workers get, Pages deploy, and KV get.
  - `2_097_152` for deletion and KV write responses.
  - `1_048_576` for credential health.
- Sandbox profile is `strict`, with `128 MB` memory, `25%` CPU, `30_000 ms` wall-clock timeout, no exec, and no ptrace.
- The connector does not open listeners and does not implement subscriptions.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `cloudflare.zones.read` | List zones and verify credential health. |
| `cloudflare.dns.read` | List DNS records in a zone. |
| `cloudflare.dns.write` | Create, update, and delete DNS records. |
| `cloudflare.workers.read` | List Workers scripts and read script metadata. |
| `cloudflare.workers.write` | Deploy or delete Workers scripts. |
| `cloudflare.pages.read` | List Pages projects. |
| `cloudflare.pages.write` | Trigger Pages deployments. |
| `cloudflare.kv.read` | Read Workers KV values. |
| `cloudflare.kv.write` | Write and delete Workers KV values. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `cloudflare.zones.list` | `GET /zones` | `cloudflare.zones.read` | `Safe` | `Low` | `Strict` | Reads zones visible to the configured identity. |
| `cloudflare.health` | `GET /user/tokens/verify` | `cloudflare.zones.read` | `Safe` | `Low` | `Strict` | Verifies credential status and returns token health. |
| `cloudflare.dns.list_records` | `GET /zones/{zone_id}/dns_records` | `cloudflare.dns.read` | `Safe` | `Low` | `Strict` | Reads DNS records before mutation. |
| `cloudflare.dns.create_record` | `POST /zones/{zone_id}/dns_records` | `cloudflare.dns.write` | `Risky` | `Medium` | `None` | Creates a DNS record that can affect live traffic. |
| `cloudflare.dns.update_record` | `PUT /zones/{zone_id}/dns_records/{record_id}` | `cloudflare.dns.write` | `Risky` | `Medium` | `Strict` | Replaces existing DNS record content. |
| `cloudflare.dns.delete_record` | `DELETE /zones/{zone_id}/dns_records/{record_id}` | `cloudflare.dns.write` | `Dangerous` | `High` | `Strict` | Deletes DNS records and requires interactive approval metadata. |
| `cloudflare.workers.list` | `GET /accounts/{account_id}/workers/scripts` | `cloudflare.workers.read` | `Safe` | `Low` | `Strict` | Reads Workers script inventory. |
| `cloudflare.workers.get` | `GET /accounts/{account_id}/workers/scripts/{script_name}` | `cloudflare.workers.read` | `Safe` | `Low` | `Strict` | Reads metadata for one Workers script. |
| `cloudflare.workers.deploy` | `PUT /accounts/{account_id}/workers/scripts/{script_name}` | `cloudflare.workers.write` | `Risky` | `Medium` | `Strict` | Creates or updates executable Worker source. |
| `cloudflare.workers.delete` | `DELETE /accounts/{account_id}/workers/scripts/{script_name}` | `cloudflare.workers.write` | `Dangerous` | `High` | `Strict` | Deletes a Worker and may affect live traffic. |
| `cloudflare.pages.list_projects` | `GET /accounts/{account_id}/pages/projects` | `cloudflare.pages.read` | `Safe` | `Low` | `Strict` | Reads Pages project inventory. |
| `cloudflare.pages.create_deployment` | `POST /accounts/{account_id}/pages/projects/{project_name}/deployments` | `cloudflare.pages.write` | `Risky` | `Medium` | `None` | Triggers a deployment from a branch. |
| `cloudflare.kv.get` | `GET /accounts/{account_id}/storage/kv/namespaces/{namespace_id}/values/{key}` | `cloudflare.kv.read` | `Safe` | `Low` | `Strict` | Reads one KV value as raw text. |
| `cloudflare.kv.put` | `PUT /accounts/{account_id}/storage/kv/namespaces/{namespace_id}/values/{key}` | `cloudflare.kv.write` | `Risky` | `Medium` | `Strict` | Creates or replaces one KV value. |
| `cloudflare.kv.delete` | `DELETE /accounts/{account_id}/storage/kv/namespaces/{namespace_id}/values/{key}` | `cloudflare.kv.write` | `Dangerous` | `High` | `Strict` | Deletes one KV entry and requires interactive approval metadata. |

## Explicit Non-Goals

The current implementation does not include:

- account creation, zone creation, zone deletion, registrar operations, or account-member administration
- Cloudflare GraphQL analytics, logs, rulesets, cache, firewall, access, tunnels, R2, D1, Queues, Durable Objects, Vectorize, Images, Stream, or AI APIs
- DNS import/export, batch DNS record changes, partial DNS patching, or zone settings
- Workers routes, bindings, secrets, assets, compatibility dates, module upload metadata, tailing, schedules, deployments, or versions
- Wrangler integration or local Worker bundling
- Pages project create/update/delete, domain management, build-cache purge, logs, rollback, retry, or deployment deletion
- KV namespace create/rename/delete, key listing, metadata reads/writes, expiration, bulk operations, or JSON decoding
- webhook/event subscriptions or streaming
- connector-local credential vaulting

These are excluded on purpose:

- Runtime invocation is capability-token bound and should expose only narrow provider actions.
- DNS, Workers, Pages, and KV mutations can affect production traffic and must remain explicit operations.
- Broader Cloudflare coverage needs separate provider fixtures, permission models, and verification resources.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, handshake state, runtime readiness, and provisioning status
- auth mode, legacy-global-key status, secret-material status, account ID status, and base URL policy
- credential-injection requirement for secretless auth material
- operator guidance, manifest hash, verification script, artifact root, and rerun commands
- operation metadata, schemas, capability IDs, risk levels, safety tiers, idempotency, and approval modes
- self-check proof through `/user/tokens/verify` when credential material is configured
- simulation allow behavior, currently without operation/capability validation

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle health, doctor guidance, and self-check evidence output
- API-token and legacy API-key headers
- invalid network policy rejection
- bound capability-token verification for reads and destructive DNS mutation
- token health success, retryable provider failure, and degraded status
- risky mutation evidence for DNS deletion
- simulation behavior

## Source Notes

- `connectors/cloudflare/src/connector.rs` defines configuration parsing, base URL policy, operator guidance, lifecycle handlers, capability-token verification, resource URI derivation, simulation, introspection metadata, and invoke dispatch.
- `connectors/cloudflare/src/client.rs` defines API v4 request paths, auth headers, path-segment rejection, KV key encoding, timeout, retry dispatch, response-envelope parsing, and provider error mapping.
- `connectors/cloudflare/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/cloudflare/src/types.rs` defines Cloudflare auth modes, response envelopes, zones, DNS records, Workers, Pages, KV, and token verification types.
- `connectors/cloudflare/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, and AI hints.
- `connectors/cloudflare/tests/integration.rs` covers deterministic HTTP behavior and runtime capability enforcement.
- `scripts/e2e/cloudflare_connector_verification.sh` wraps the manifest, check, format, self-check, mutation-evidence, integration, and clippy proof lanes.

## Verification Bundle

The tracked verification bundle is `scripts/e2e/cloudflare_connector_verification.sh`.

The verification surface captures:

- manifest validation through `fwc`
- runtime operation contract tests
- deterministic WireMock Cloudflare API coverage
- auth, base URL, input validation, capability-token, provider error, lifecycle, introspection, and self-check tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a disposable Cloudflare account or staging account for live verification.
- Use a non-production zone, Pages project, Workers script name, and KV namespace for mutation tests.
- Prefer a scoped API token with only the permissions needed for the operations under test.
- Avoid legacy global API-key mode unless a specific compatibility test requires it.

**Dedicated environment**:

- Keep DNS mutations confined to a disposable zone.
- Keep Workers deploy/delete confined to a disposable script name with no production routes.
- Keep Pages deployments confined to a disposable project and branch.
- Keep KV writes/deletes confined to a disposable namespace.

**Redaction rules**:

- Redact API tokens, API keys, paired email/key material, account IDs when private, zone IDs, DNS record IDs, Workers script names when sensitive, Pages project names/URLs when private, KV namespace IDs, KV keys and values, provider payloads, provider error bodies, and local paths.
- Verification output should use operation IDs, endpoint shapes, host classes, status/error classes, retry decisions, resource URI shapes, and synthetic Cloudflare resource identifiers.

**Common remediation**:

- If configuration fails, check `mode`, `account_id`, `base_url`, `request_timeout_ms`, and auth fields.
- If API-key mode fails configuration, provide `email` whenever `api_key` material is present.
- If `doctor` or `self_check` reports `credential_injection_required`, inject auth headers through the host/egress proxy or use direct credentials for verification.
- If `self_check` returns inactive or unauthorized, create a scoped API token and verify it with `/user/tokens/verify`.
- If Workers, Pages, or KV calls fail while zone reads succeed, confirm the configured `account_id` owns those account-scoped resources.
- If DNS mutation fails, run `cloudflare.zones.list` and `cloudflare.dns.list_records` first to confirm `zone_id` and `record_id`.
- If KV keys contain slash-like logical names, rely on the connector's percent encoding and avoid traversal sequences.

**Rerun commands**:

- `scripts/e2e/cloudflare_connector_verification.sh`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-cloudflare-readme cargo check -p fcp-cloudflare --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-cloudflare-readme cargo test -p fcp-cloudflare --test integration -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-cloudflare-readme cargo clippy -p fcp-cloudflare --all-targets --no-deps -- -D warnings`
- `ubs connectors/cloudflare/README.md`
