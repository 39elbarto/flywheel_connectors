# Airtable Connector V3 Contract

> **Status**: manifest/runtime contract documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Primary upstream**: https://airtable.com/developers/web/api/introduction

## Purpose

This document fixes the operator-facing contract for `fcp.airtable`. The connector exposes Airtable base discovery, schema discovery, record CRUD, batch record operations, bounded linked-record expansion, webhook management, webhook payload replay normalization, and attachment download.

The connector is intentionally a work-zone Airtable bridge. It is not a local database, public ingest surface, long-running webhook listener, file store, or unbounded graph traversal engine. Webhook payloads and record contents are external service data and must be treated as untrusted.

## Current Runtime Snapshot

The current crate exposes these operations:

- `airtable.list_bases`
- `airtable.get_base_schema`
- `airtable.list_tables`
- `airtable.get_table`
- `airtable.list_fields`
- `airtable.list_views`
- `airtable.get_view`
- `airtable.list_view_records`
- `airtable.list_records`
- `airtable.get_record`
- `airtable.create_record`
- `airtable.create_records`
- `airtable.update_records`
- `airtable.upsert_records`
- `airtable.update_record`
- `airtable.replace_record`
- `airtable.delete_record`
- `airtable.delete_records`
- `airtable.create_webhook`
- `airtable.list_webhooks`
- `airtable.refresh_webhook`
- `airtable.set_webhook_notifications`
- `airtable.delete_webhook`
- `airtable.list_webhook_payloads`
- `airtable.download_attachment`

Important runtime truths the contract preserves:

- Configuration requires exactly one of `token` or `credential_id`.
- Direct token mode sends bearer auth.
- Credential-id mode sends `X-FCP-Credential-ID`.
- Credential IDs must be valid UUIDs.
- Default base URL is `https://api.airtable.com/v0`.
- Direct token mode allows only `https://api.airtable.com` or loopback HTTP/HTTPS test origins.
- Credential-id mode accepts any absolute base URL without userinfo, query string, or fragment so a host proxy can own routing policy.
- Base URLs are trimmed of trailing slashes after validation.
- Reconfiguration clears the schema cache and resets handshake state.
- Invocations use `operation`, `input`, and `capability_token`, and require bound capability-token verification.
- Handshake grants requested capabilities and advertises event caps: streaming true, replay true, min buffer events 50, requires ack false.
- The schema cache TTL is 300 seconds per base.
- Table, view, and field selectors accept stable IDs or exact names; ambiguous exact names are rejected.
- `filter_by_formula` must be a non-empty string and must not contain control characters.
- Pagination offsets must be non-empty strings and no more than 512 bytes.
- `max_records` and `page_size` are bounded to 1 through 100.
- Batch create, update, upsert, and delete inputs are bounded to 1 through 10 records.
- Linked-record expansion defaults to depth 1 and limit 25, with runtime maxima of depth 3 and 50 linked records.
- Attachment downloads require allowed Airtable attachment hosts, HTTPS, port 443, no IP literals, at most 5 redirects, and at most 100 MB.
- Attachment download returns base64 data plus content type and optional filename.
- 429 and retryable transport failures are routed through the shared retry loop.
- Unauthorized/forbidden responses terminate as auth failures, and non-success API responses map to FCP-facing error classes.

## First-Slice Scope

The first Airtable README slice documents the existing runtime surface:

- base discovery through `/meta/bases`
- schema discovery through `/meta/bases/{base_id}/tables`
- table, field, and view lookup from cached schema responses
- record list/get/create/update/replace/delete operations against `/v0/{base_id}/{table_id}`
- batch create, update, upsert, and delete operations
- bounded linked-record expansion with cycle and truncation markers
- webhook list/create/refresh/notification/delete/payload-history operations
- webhook payload normalization into FCP event envelopes
- attachment download from Airtable-managed attachment hosts
- direct bearer-token auth and host credential reference auth
- capability-token verification on invoke and simulate
- lifecycle, introspection, simulation, doctor, self-check, and shutdown surfaces

## Auth And Scope Boundary

- Authentication mechanisms: Airtable personal access/OAuth token or host credential reference.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden source zone: `z:public`.
- Capability surface:
  - `airtable.read` gates base, schema, view, record-read, webhook-payload, and attachment-read operations.
  - `airtable.write` gates record create/update/replace/upsert operations.
  - `airtable.delete` gates record delete operations.
  - `airtable.webhooks.manage` gates webhook registration, refresh, notification, deletion, listing, and payload replay.
- The connector does not persist bases, schemas, records, attachments, webhook MAC secrets, webhook payloads, tokens, or credential IDs beyond process memory.
- Schema responses are cached in memory for 300 seconds per base and are cleared on reconfiguration.
- Credential-id mode forwards a host credential reference header; host-side credential materialization remains outside this connector.

## Network And Runtime Invariants

- Production host: `api.airtable.com`.
- Production path root: `/v0`.
- Production port: `443`.
- TLS and SNI are required for live direct-token traffic.
- Manifest provider network policy denies localhost, private ranges, tailnet ranges, and IP literals.
- Runtime loopback provider API overrides are test-only for direct-token mode.
- Runtime default Airtable API timeout: `30_000 ms`.
- Runtime default retry config uses two retries through the shared retry loop; 429 `Retry-After` is honored when present.
- Manifest read/detail operations set total timeout `30_000 ms`; list and batch operations can set `60_000 ms`.
- Attachment download connect timeout is `30_000 ms`, total timeout is `120_000 ms`, redirect limit is 5, and max bytes are `104_857_600`.
- Attachment hosts are limited to `dl.airtable.com`, `*.dl.airtable.com`, and `v5.airtableusercontent.com`, except loopback test origins when the provider base URL is loopback.
- Maximum response bytes are `1_048_576`, `2_097_152`, `5_242_880`, `10_485_760`, or `104_857_600` depending on operation.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `120_000 ms` wall-clock timeout, no exec, and no ptrace.
- The connector does not open a listener; webhook support is provider management plus polling/replay of Airtable payload history.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `airtable.read` | Read base metadata, schemas, table/view/field metadata, records, webhook payload history, and attachments. |
| `airtable.write` | Create, patch, replace, and upsert records. |
| `airtable.delete` | Delete one or more records. |
| `airtable.webhooks.manage` | Create, list, refresh, toggle, delete, and replay Airtable webhooks. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `airtable.list_bases` | `GET /meta/bases` | `airtable.read` | `Safe` | `Low` | `Strict` | Lists accessible bases. |
| `airtable.get_base_schema` | `GET /meta/bases/{base_id}/tables` | `airtable.read` | `Safe` | `Low` | `Strict` | Reads schema, field, table, view, and computed-field metadata. |
| `airtable.list_tables` | schema cache | `airtable.read` | `Safe` | `Low` | `Strict` | Lists table summaries from schema. |
| `airtable.get_table` | schema cache | `airtable.read` | `Safe` | `Low` | `Strict` | Resolves one table by ID or exact name. |
| `airtable.list_fields` | schema cache | `airtable.read` | `Safe` | `Low` | `Strict` | Resolves field metadata and linked-table summaries. |
| `airtable.list_views` | schema cache | `airtable.read` | `Safe` | `Low` | `Strict` | Lists saved views for a table. |
| `airtable.get_view` | schema cache | `airtable.read` | `Safe` | `Low` | `Strict` | Resolves one view by ID or exact name. |
| `airtable.list_view_records` | `GET /{base_id}/{table_id}` with view | `airtable.read` | `Safe` | `Low` | `Strict` | Lists records through a resolved saved view and explicit field projection. |
| `airtable.list_records` | `GET /{base_id}/{table_id}` | `airtable.read` | `Safe` | `Low` | `Strict` | Lists records with validated filters, sorting, pagination, and optional bounded links. |
| `airtable.get_record` | `GET /{base_id}/{table_id}/{record_id}` | `airtable.read` | `Safe` | `Low` | `Strict` | Reads one record with optional bounded linked-record expansion. |
| `airtable.create_record` | `POST /{base_id}/{table_id}` | `airtable.write` | `Risky` | `Medium` | `None` | Creates one record. |
| `airtable.create_records` | `POST /{base_id}/{table_id}` | `airtable.write` | `Risky` | `Medium` | `None` | Creates up to 10 records. |
| `airtable.update_records` | `PATCH /{base_id}/{table_id}` | `airtable.write` | `Risky` | `Medium` | `Strict` | Patches up to 10 existing records. |
| `airtable.upsert_records` | `PATCH /{base_id}/{table_id}` with `performUpsert` | `airtable.write` | `Risky` | `Medium` | `Strict` | Creates or updates up to 10 records using resolved merge fields. |
| `airtable.update_record` | `PATCH /{base_id}/{table_id}/{record_id}` | `airtable.write` | `Risky` | `Medium` | `Strict` | Patches one record. |
| `airtable.replace_record` | `PUT /{base_id}/{table_id}/{record_id}` | `airtable.write` | `Dangerous` | `High` | `Strict` | Replaces all fields on one record. |
| `airtable.delete_record` | `DELETE /{base_id}/{table_id}/{record_id}` | `airtable.delete` | `Dangerous` | `High` | `Strict` | Deletes one record. |
| `airtable.delete_records` | `DELETE /{base_id}/{table_id}?records[]=...` | `airtable.delete` | `Dangerous` | `High` | `Strict` | Deletes up to 10 records. |
| `airtable.create_webhook` | `POST /bases/{base_id}/webhooks` | `airtable.webhooks.manage` | `Dangerous` | `High` | `None` | Registers a webhook and returns a one-time MAC secret. |
| `airtable.list_webhooks` | `GET /bases/{base_id}/webhooks` | `airtable.webhooks.manage` | `Safe` | `Low` | `Strict` | Lists webhook registrations. |
| `airtable.refresh_webhook` | `POST /bases/{base_id}/webhooks/{webhook_id}/refresh` | `airtable.webhooks.manage` | `Safe` | `Low` | `Strict` | Refreshes webhook expiration. |
| `airtable.set_webhook_notifications` | `POST /bases/{base_id}/webhooks/{webhook_id}/enableNotifications` | `airtable.webhooks.manage` | `Risky` | `Medium` | `Strict` | Enables or disables provider notification pings. |
| `airtable.delete_webhook` | `DELETE /bases/{base_id}/webhooks/{webhook_id}` | `airtable.webhooks.manage` | `Dangerous` | `High` | `Strict` | Removes a webhook registration. |
| `airtable.list_webhook_payloads` | `GET /bases/{base_id}/webhooks/{webhook_id}/payloads` | `airtable.webhooks.manage` | `Safe` | `Low` | `Strict` | Reads provider payload history and normalizes FCP events. |
| `airtable.download_attachment` | Airtable attachment URL | `airtable.read` | `Safe` | `Low` | `Strict` | Downloads one bounded attachment from allowed Airtable attachment hosts. |

## Explicit Non-Goals

The current implementation does not include:

- inbound webhook HTTP listener or public callback endpoint
- durable webhook cursor storage
- persistent schema, record, or attachment cache
- Airtable OAuth authorization flow, token refresh, or app installation management
- base creation, table creation, schema mutation, field mutation, view mutation, comments, automations, interfaces, sync API, or enterprise admin APIs
- file upload to Airtable
- unbounded linked-record expansion or whole-base graph mirroring
- public-zone invocation
- connector-local credential vaulting

These are excluded on purpose:

- The useful first slice is a bounded work-zone data bridge, not a database replica.
- Linked-record expansion is intentionally bounded to avoid cyclic or explosive graph traversal.
- Webhook support manages provider registrations and normalizes payload history, while host-owned ingress remains outside the connector.
- Attachment download is limited to Airtable-managed attachment hosts and size-bounded binary transfer.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, auth mode, base URL, local request/error metrics, and client readiness
- base URL policy and credential-injection mode
- live self-check through `list_bases` for direct-token mode
- degraded self-check for credential-id mode because proxy injection is required
- manifest/runtime operation metadata, schemas, capability IDs, risk levels, safety tiers, and idempotency
- simulate denial for missing configuration, missing handshake, unknown operation, and missing capability grants

The deterministic integration evidence is anchored on WireMock and connector-local tests covering:

- error mapping and token redaction
- client paths for base listing, schema retrieval, record list/get/create/update/replace/delete, batch create/update/upsert/delete, and webhook operations
- direct bearer auth and credential-id config behavior
- base URL validation for token mode and credential-id mode
- attachment URL host filtering, redirect handling, oversize rejection, and invoke-level rejection
- connector-level capability-token verification
- linked-record expansion, cycle handling, truncation markers, and missing-target markers
- schema cache reuse within TTL
- table/view/field exact-name and ambiguity handling
- formula-field metadata, read-only/computed metadata, and Airtable formula error mapping
- webhook payload normalization into ordered FCP event envelopes

## Source Notes

- `connectors/airtable/src/connector.rs` defines configuration parsing, base URL policy, handshake, capability verification, lifecycle handlers, operation dispatch, schema cache, selector resolution, linked-record expansion, webhook event normalization, diagnostics, simulation, and manifest-backed introspection.
- `connectors/airtable/src/client.rs` defines Airtable REST calls, bearer/credential headers, retry loop use, attachment download policy, request construction, response parsing, and provider error mapping.
- `connectors/airtable/src/types.rs` defines Airtable request/response DTOs for records, schemas, webhooks, attachments, and errors.
- `connectors/airtable/manifest.toml` defines the operation catalog, event capabilities, network constraints, sandbox boundary, zone policy, rate-limit pools, and operation AI hints.
- `connectors/airtable/tests/integration.rs` covers deterministic client and connector behavior across record, schema, webhook, attachment, lifecycle, and authorization surfaces.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/airtable_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- manifest/runtime contract tests
- deterministic WireMock Airtable API coverage
- auth, base URL, schema, record, batch, webhook, attachment, linked-record, capability-token, error, lifecycle, simulation, and introspection tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use an Airtable personal access token or OAuth access token for direct live verification.
- Use `credential_id` only when an egress proxy can inject Airtable auth at request time.
- Use WireMock loopback fixtures for routine proof.
- Use a test Airtable base with synthetic records and attachments for live runs.

**Dedicated environment**:

- Use stable base, table, field, view, record, and webhook IDs for automated tests.
- Prefer schema discovery before record operations so table, field, and view names resolve deterministically.
- Keep production base data, attachment contents, webhook MAC secrets, and payload history out of routine logs.
- Keep inbound callback hosting, OAuth installation, schema mutation, and base mirroring out of this connector until separate beads define those contracts.

**Redaction rules**:

- Redact tokens, credential IDs where needed, base IDs when sensitive, table names when sensitive, field names when sensitive, record IDs when sensitive, record field values, formulas when sensitive, attachment URLs, attachment bytes, webhook IDs when sensitive, webhook MAC secrets, provider payloads, and provider error bodies.
- Verification output should use operation names, endpoint paths, auth mode, host classes, record counts, schema counts, webhook counts, attachment byte classes, status/error classes, retry decisions, and capability-token result classes.

**Common remediation**:

- If `health` reports `not_configured`, configure with exactly one of `token` or `credential_id`.
- If configuration fails in token mode, use `https://api.airtable.com/v0` or a loopback test origin with no userinfo, query string, or fragment.
- If configuration fails in credential-id mode, ensure the URL is absolute and does not include userinfo, query string, or fragment.
- If `self_check` is degraded in credential-id mode, verify the egress credential injection layer before treating it as a connector bug.
- If invoke fails before network dispatch, check `operation`, `capability_token`, handshake state, and the required capability for that operation.
- If table, field, or view resolution is ambiguous, use stable Airtable IDs instead of exact names.
- If linked-record expansion fails, include projected linked fields and keep depth and record limits bounded.
- If webhook creation succeeds, persist the returned MAC secret outside connector logs immediately.
- If attachment download fails, use the full Airtable attachment URL, avoid thumbnails unless intended, and verify host, HTTPS, port, redirect, and size limits.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-airtable-e2e cargo check -p fcp-airtable --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-airtable-e2e cargo test -p fcp-airtable --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-airtable-e2e cargo clippy -p fcp-airtable --all-targets --no-deps -- -D warnings`
