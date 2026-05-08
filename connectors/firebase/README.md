# Firebase Connector V3 Contract

> **Status**: runtime contract documented; enforcement gaps documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/firebase_connector_verification.sh`
> **Firestore upstream**: https://firebase.google.com/docs/firestore/reference/rest/
> **Realtime Database upstream**: https://firebase.google.com/docs/reference/rest/database

## Purpose

This document fixes the operator-facing contract for `fcp.firebase`. The connector exposes the Firebase surface implemented in this crate: Firestore document reads and writes, Firestore structured queries and batch writes, Realtime Database JSON reads and writes, and a Firestore-backed health probe.

The connector is intentionally a bounded Firebase data-access bridge. It is not a Firebase Admin SDK, Auth user-management client, Cloud Messaging client, Storage client, Hosting client, Functions client, App Check client, Remote Config client, project-provisioning tool, Realtime Database streaming client, or Firestore listener.

## Current Runtime Snapshot

The current crate exposes these operations:

- `firebase.firestore.get`
- `firebase.firestore.list`
- `firebase.firestore.create`
- `firebase.firestore.update`
- `firebase.firestore.delete`
- `firebase.firestore.query`
- `firebase.firestore.batch_write`
- `firebase.rtdb.get`
- `firebase.rtdb.set`
- `firebase.rtdb.delete`
- `firebase.health`

Important runtime truths the contract preserves:

- Configuration requires `project_id` plus exactly one Google auth source accepted by `fcp-google-discovery`.
- Supported auth modes include direct bearer-token material and host credential references such as `credential_id`.
- `credential_id` mode is secretless; configuration succeeds with `pending_credentials` and self-check reports `credential_injection_required`.
- Default `database_id` is `(default)`.
- Default Firestore base URL is `https://firestore.googleapis.com/v1`.
- Default Realtime Database URL is `https://{project_id}.firebaseio.com`.
- Default required scopes are `https://www.googleapis.com/auth/datastore` and `https://www.googleapis.com/auth/firebase.database`; `https://www.googleapis.com/auth/cloud-platform` satisfies both readiness checks.
- Production Firestore traffic must use HTTPS and host `firestore.googleapis.com`.
- Production Realtime Database traffic must use HTTPS and a host under `firebaseio.com` or `firebasedatabase.app`.
- `localhost`, `127.0.0.1`, `::1`, and `.localhost` hosts are accepted for deterministic verification stubs.
- `request_timeout_ms` defaults to `30_000` and must be greater than zero.
- The client uses the shared retry loop with two maximum retries.
- Firestore document and collection paths are relative paths. The parser rejects empty, `.`, and `..` segments and validates document-vs-collection segment counts.
- Realtime Database paths are rendered as `.json` REST resources.
- Auth labels, bearer tokens, and credential material are redacted in diagnostics.
- Provider 401, 403, 404, 429, retryable transport/5xx classes, malformed JSON, and provider error payloads map into typed connector and FCP errors.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- Runtime `handle_invoke` dispatches by `operation_id` after configured and handshaken readiness, but it does not parse or verify FCP capability tokens.
- Runtime `handle_simulate` only checks whether the operation ID exists in the operation inventory.
- Runtime operation metadata includes policy or interactive approval for Firestore create, update, delete, batch write, Realtime Database set, and Realtime Database delete.
- The manifest operation metadata matches the broad operation list but AI hints are still empty in `manifest.toml`.
- The manifest network constraints deny localhost for live traffic, while runtime host policy deliberately accepts loopback for deterministic verification.
- The health operation checks Firestore database metadata. It does not prove every Firestore collection, Realtime Database rule, index, or security-rule path is accessible.

A follow-up parity bead should add capability-token verification to runtime invoke, tighten simulation, and refresh manifest AI hints before describing this connector as policy-complete.

## First-Slice Scope

The current Firebase README slice documents the existing runtime surface:

- Google bearer-token and secretless credential-reference configuration
- Firestore and Realtime Database endpoint policy
- Firestore document get, list, create, update, delete, structured query, and batch write
- Realtime Database get, set, and delete with supported query parameters
- Firestore database metadata health check
- provider error mapping, retry behavior, path validation, and redaction posture
- lifecycle, doctor, health, self-check, introspection, simulation, and shutdown surfaces
- deterministic WireMock tests and the tracked verification bundle

## Auth And Scope Boundary

- Authentication mechanisms: Google bearer token or host credential reference through the shared Google discovery auth layer.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Runtime capability surface:
  - `firebase.read` gates Firestore reads, Firestore queries, Realtime Database reads, and health.
  - `firebase.write` gates Firestore document mutation, Firestore batch writes, Realtime Database writes, and Realtime Database deletes.
- The connector does not persist Firebase documents, Realtime Database values, access tokens, credential IDs, provider payloads, or provider error bodies beyond process memory.
- Firestore deletes, Realtime Database deletes, and broad Realtime Database writes are destructive data operations and should be host policy gated.

## Network And Runtime Invariants

- Firestore production host: `firestore.googleapis.com`.
- Firestore production API prefix: `/v1`.
- Realtime Database production hosts: `<project>.firebaseio.com` or `<database>.firebasedatabase.app`.
- Production port: `443`.
- TLS and SNI are required by the manifest for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live operations.
- Runtime loopback base URLs are test-only.
- Runtime request timeout defaults to `30_000 ms`.
- Manifest total timeouts are `120_000 ms` for mutating Firestore and Realtime Database operations.
- Manifest response budgets are `16_777_216` bytes for most Firestore document operations, `33_554_432` bytes for batch writes, and `67_108_864` bytes for Realtime Database reads.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `120_000 ms` wall-clock timeout, no exec, and no ptrace.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `firebase.read` | Read Firestore documents, run Firestore queries, read Realtime Database JSON, and check database metadata. |
| `firebase.write` | Create, update, delete, and batch-write Firestore documents, and set or delete Realtime Database JSON. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `firebase.firestore.get` | `GET /v1/projects/{project}/databases/{database}/documents/{document_path}` | `firebase.read` | `Safe` | `Low` | `Strict` | Reads one Firestore document by relative document path. |
| `firebase.firestore.list` | `GET /v1/projects/{project}/databases/{database}/documents/{collection_path}` | `firebase.read` | `Safe` | `Low` | `None` | Lists documents in a relative collection path with paging and masks. |
| `firebase.firestore.create` | `POST /v1/projects/{project}/databases/{database}/documents/{collection_path}` | `firebase.write` | `Risky` | `Medium` | `Strict` | Creates a Firestore document under a collection. |
| `firebase.firestore.update` | `PATCH /v1/projects/{project}/databases/{database}/documents/{document_path}` | `firebase.write` | `Risky` | `Medium` | `Strict` | Patches a Firestore document with an update mask and optional preconditions. |
| `firebase.firestore.delete` | `DELETE /v1/projects/{project}/databases/{database}/documents/{document_path}` | `firebase.write` | `Dangerous` | `High` | `Strict` | Permanently deletes one Firestore document. |
| `firebase.firestore.query` | `POST /v1/projects/{project}/databases/{database}/documents:runQuery` | `firebase.read` | `Safe` | `Low` | `None` | Runs a raw Firestore `structuredQuery` payload. |
| `firebase.firestore.batch_write` | `POST /v1/projects/{project}/databases/{database}/documents:batchWrite` | `firebase.write` | `Risky` | `Medium` | `Strict` | Sends raw Firestore write operations and returns per-write status. |
| `firebase.rtdb.get` | `GET /{path}.json` | `firebase.read` | `Safe` | `Low` | `None` | Reads Realtime Database JSON with optional REST query parameters. |
| `firebase.rtdb.set` | `PUT /{path}.json` | `firebase.write` | `Risky` | `Medium` | `BestEffort` | Replaces the JSON value at one Realtime Database path. |
| `firebase.rtdb.delete` | `DELETE /{path}.json` | `firebase.write` | `Dangerous` | `High` | `Strict` | Deletes the JSON value at one Realtime Database path. |
| `firebase.health` | `GET /v1/projects/{project}/databases/{database}` | `firebase.read` | `Safe` | `Low` | `Strict` | Reads Firestore database metadata as a reachability probe. |

## Explicit Non-Goals

The current implementation does not include:

- Firebase Auth, user management, custom-token minting, or Security Rules management
- Cloud Firestore listen streams, transactions, commits, batch get, collection ID listing, aggregation queries, backups, exports, imports, indexes, or TTL configuration
- Firestore query builder helpers beyond raw `structured_query` JSON
- Realtime Database streaming, conditional ETag updates, priorities, rules, indexes, or auth-variable helpers
- Firebase Cloud Messaging, Cloud Storage for Firebase, Hosting, Functions, App Check, Remote Config, Analytics, Crashlytics, Performance, or project management APIs
- OAuth consent, service-account key provisioning, IAM role provisioning, or Firebase project creation
- connector-local credential vaulting, durable document cache, event subscriptions, or local offline sync

These are excluded on purpose:

- The first slice keeps mutable document/database operations narrow and explicit.
- Firestore and Realtime Database can contain sensitive personal, work, and agent state data.
- Streaming/listener support requires a separate flow-control and replay contract.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, client initialization, handshake state, request counters, and error counters
- auth mode, secretless credential-injection state, project ID, database ID, and endpoint policy
- Firestore and Realtime Database scope coverage guidance
- operator guidance, verification script, artifact root hint, and rerun commands
- operation metadata, schemas, capability IDs, risk levels, safety tiers, idempotency, and approval modes
- degraded self-check for secretless credential references
- failure for invalid endpoint policy, unauthorized provider responses, retryable provider failures, and missing configuration
- simulation denial for unsupported operation IDs
- shutdown state reset

The deterministic integration evidence is anchored on connector-local tests covering:

- access-token and credential-reference configuration
- default Realtime Database URL construction
- official host policy and loopback verification overrides
- typed operation inventory and approval metadata
- health, doctor, self-check, introspection, simulation, and shutdown surfaces
- Firestore get/list/create/query/batch-write endpoint shapes
- Realtime Database set and get endpoint/query behavior
- provider auth header propagation, retryable failures, and self-check evidence

## Source Notes

- `connectors/firebase/src/connector.rs` defines configuration parsing, lifecycle handlers, provisioning readiness, operator guidance, operation metadata, simulation, and invoke dispatch.
- `connectors/firebase/src/client.rs` defines Firestore and Realtime Database request paths, auth header application, retry dispatch, timeout, path validation, and provider error handling.
- `connectors/firebase/src/types.rs` defines request, response, and Firestore wire-conversion types.
- `connectors/firebase/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/firebase/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, and AI hint placeholders.
- `connectors/firebase/tests/integration.rs` covers deterministic readiness and HTTP behavior.
- `scripts/e2e/firebase_connector_verification.sh` wraps the tracked verification evidence.

## Verification Bundle

The tracked closeout surface is the Firebase verification script plus direct crate proof commands.

The verification surface captures:

- runtime operation inventory and metadata
- deterministic WireMock coverage for Firestore and Realtime Database paths
- auth, endpoint policy, provider error, lifecycle, simulation, and introspection tests
- formatting, check, test, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a disposable Firebase project plus non-production Firestore and Realtime Database data for live verification.
- Use least-privilege Google credentials for the target project and database.
- Prefer `credential_id` when host-side credential injection should own Google secret material.
- Use WireMock loopback fixtures for routine proof.

**Dedicated environment**:

- Keep live collection names, document IDs, Realtime Database paths, and JSON payloads synthetic.
- Do not run deletes or broad Realtime Database writes against production paths through routine verification.
- Verify Firestore rules, Realtime Database rules, and IAM permissions separately; the connector can only report provider responses.

**Redaction rules**:

- Redact access tokens, credential IDs where needed, project IDs when sensitive, database IDs, document paths, collection paths, Realtime Database paths, document fields, Realtime Database values, query payloads, provider payloads, provider error bodies, and endpoint URLs when they reveal account topology.
- Verification output should use operation IDs, endpoint shapes, auth mode, host class, result counts, status/error classes, and payload-shape summaries.

**Common remediation**:

- If configuration fails, provide `project_id` and exactly one Google auth source.
- If self-check is degraded with `credential_injection_required`, inject host credentials before running live probes.
- If Firestore endpoint policy fails, use `https://firestore.googleapis.com/v1` or a loopback verification URL.
- If Realtime Database endpoint policy fails, use a Firebase-owned HTTPS database domain or a loopback verification URL.
- If path validation fails, pass relative paths without empty, `.`, or `..` segments.
- If Firestore query returns no documents, verify the raw `structured_query`, index requirements, and security rules.
- If Realtime Database queries fail, verify `order_by` indexing and rule access for the target path.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-firebase-readme cargo check -p fcp-firebase --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-firebase-readme cargo test -p fcp-firebase --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-firebase-readme cargo clippy -p fcp-firebase --all-targets --no-deps -- -D warnings`
