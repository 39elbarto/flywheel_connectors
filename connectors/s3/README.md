# S3 Connector V3 Contract

> **Status**: runtime contract documented; AWS/API drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Amazon S3 API reference**: https://docs.aws.amazon.com/AmazonS3/latest/API/Type_API_Reference.html
> **PutObject API**: https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html
> **GetObject API**: https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html
> **Presigned URL guide**: https://docs.aws.amazon.com/AmazonS3/latest/userguide/ShareObjectPreSignedURL.html

## Purpose

This document fixes the operator-facing contract for `fcp.s3`. The connector currently exposes the S3-shaped object-storage surface implemented in this crate: bucket list/create/delete, object put/get/head/list/copy/delete, and presigned URL generation.

The connector is intentionally a bounded object-storage bridge. It is not a complete AWS SDK, IAM/STSesion client, multipart upload manager, event-notification listener, inventory client, lifecycle-policy tool, bucket-policy admin client, S3 Select client, Glacier restore client, or general S3 API proxy.

## Current Runtime Snapshot

The current crate exposes these operations:

- `s3.put_object`
- `s3.get_object`
- `s3.delete_object`
- `s3.create_bucket`
- `s3.delete_bucket`
- `s3.head_object`
- `s3.list_objects`
- `s3.list_buckets`
- `s3.copy_object`
- `s3.generate_presigned_url`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-s3`.
- Runtime `BaseConnector` ID is `s3`.
- Manifest connector ID is `fcp.s3`.
- Manifest interface hash is `blake3-256:fcp.interface.v2:64aa293ebcaba6acf7045b72e715585f9b45ae9731dc2d07ec94de1b85f63eeb`.
- Configuration requires exactly one auth source:
  - direct `access_key_id` plus `secret_access_key`
  - `credential_id`
- Direct-key mode also accepts `region`, defaulting to `us-east-1`.
- `credential_id` must be a valid UUID.
- Default base URL is `https://s3.amazonaws.com`.
- `base_url` is optional and is not validated by `configure`.
- `base_url` is not trimmed by the S3 client; callers should avoid trailing slashes.
- Direct-key normal HTTP operations send `Authorization: Bearer {access_key_id}` and `x-amz-content-sha256: UNSIGNED-PAYLOAD`.
- Direct-key normal HTTP operations do not use AWS SigV4 request signing.
- `secret_access_key` is used for `s3.generate_presigned_url`, not for normal runtime requests.
- `credential_id` mode sends `X-FCP-Credential-ID` and expects host egress policy to inject real secret material.
- Client builder timeout is 300 seconds; shared request context timeout is 30 seconds.
- The client uses the shared retry loop for S3 HTTP helpers with `max_retries = 2`.
- Runtime `invoke` uses `operation`, not `operation_id`.
- Runtime `invoke` requires a serialized `capability_token`.
- Runtime installs a `CapabilityVerifier` during handshake and verifies bound capability tokens for invoke and simulate.
- `handle_configure()` replaces the old client, clears verifier/session state, sets configured, and clears the handshaken flag.
- `handle_handshake()` requires prior configuration, stores a host-key verifier, creates a fresh session ID, and returns a placeholder manifest hash.
- `health()` reports configured/not_configured and request counters; it does not report handshake state.
- `doctor()` reports configuration, client, base URL, auth mode, network target, and credential-injection mode; it does not do a live probe.
- `self_check()` calls `list_buckets()` in direct-key mode and returns degraded for `credential_id` mode.
- `handle_shutdown()` shuts down the client and clears config, verifier, session, configured, and handshaken state.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Current Amazon S3 docs describe REST object APIs and SigV4-authenticated requests. This runtime uses simplified bearer-style auth for normal operations and expects JSON fixtures, so it is S3-shaped and S3-compatible-test friendly rather than a production AWS S3 client for normal operations.
- Real S3 `GET Object` returns object bytes and metadata headers. Runtime `get_object()` expects a JSON body with `body` and `content_type`.
- Real S3 `HEAD Object` returns metadata in headers and no response body. Runtime `head_object()` issues HEAD and then tries to parse a JSON body; connector tests explicitly avoid a full HEAD fixture because HTTP bodies are stripped for HEAD.
- Real S3 error bodies are commonly XML. Runtime error parsing is JSON-first and only has fallback string handling.
- Manifest network constraints allow Amazon S3 hosts on port 443 and deny localhost/private ranges. Runtime accepts any `base_url` string that later reaches reqwest, including local HTTP fixtures.
- Manifest marks `s3.put_object` and `s3.copy_object` as policy-approved risky writes. Runtime introspection also says risky operations require policy approval, but invoke only requires `approval_token` for `s3.delete_object`, `s3.create_bucket`, `s3.delete_bucket`, and `s3.generate_presigned_url`.
- Runtime approval-token checks validate local time, execution scope, connector ID, operation pattern, and input constraints. They do not validate token signatures in this connector.
- Runtime `s3.generate_presigned_url` creates a SigV4 presigned URL only in direct-key mode. In `credential_id` mode it returns an unsigned object URL because the connector does not hold the secret key.
- Handshake grants the host-requested capabilities and returns `manifest_hash = "sha256:s3-connector-v1"`, not the manifest interface hash.
- Manifest says connector state uses singleton-writer storage. Runtime keeps configuration in process memory and does not persist connector state itself.
- Manifest rate-limit pools are documented intent only; runtime does not enforce connector-local rate limits.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should decide whether this connector targets real AWS S3 or a JSON S3-compatible facade, add SigV4 signing for normal AWS requests if real AWS is in scope, align HEAD/GET/error parsing with AWS response shapes, enforce endpoint policy at configure time, add approval signature validation or route through a shared verifier, align policy approval for risky writes, make credential-ID presigning explicit or unsupported, and add a tracked verification bundle.

## First-Slice Scope

The current S3 README slice documents the existing runtime surface:

- direct access-key and host credential-reference configuration
- S3-shaped HTTP paths, simplified JSON response handling, timeout, retry, and error mapping
- bucket and object CRUD operations, object copy, object listing, metadata lookup, and presigned URL behavior
- bound capability-token verification for invoke and simulate
- local approval-token checks for dangerous operations
- lifecycle, health, doctor, self-check, simulation, introspection, and shutdown behavior
- deterministic WireMock tests and direct proof commands

## Auth And Scope Boundary

- Authentication mechanisms: direct access key plus secret key, or host credential reference.
- Home zone: `z:private`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zones: `z:private` and `z:work`.
- Forbidden zone: `z:public`.
- Runtime capability surface:
  - `s3.read`
  - `s3.write`
  - `s3.delete`
- Handshake stores a bound-token verifier for the host public key, zone, and connector instance ID.
- Invoke rejects missing, malformed, unbound, wrong-operation, or wrong-capability tokens before dispatch.
- Dangerous runtime operations also require an execution-scope approval token:
  - `s3.delete_object`
  - `s3.create_bucket`
  - `s3.delete_bucket`
  - `s3.generate_presigned_url`
- The connector does not persist access keys, secret keys, credential secret material, object bodies, bucket listings, object metadata, provider error bodies, or API responses outside process memory.
- Bucket names, object keys, object bodies, and presigned URLs can expose private or work data. Treat live output according to the configured bucket zone and account policy.

## Network And Runtime Invariants

- Default endpoint: `https://s3.amazonaws.com`.
- Runtime object URL shape: `{base_url}/{bucket}/{key}` with bucket and key percent-encoded.
- Runtime bucket URL shape: `{base_url}/{bucket}`.
- Runtime list-buckets URL shape: `{base_url}/`.
- Runtime list-objects request: `GET {base_url}/{bucket}?list-type=2[&prefix=...][&max-keys=...]`.
- Runtime copy-object request sends `x-amz-copy-source`.
- Runtime request timeout through request context: `30 seconds`.
- Runtime retry policy: `max_retries = 2` using the shared retry loop.
- Runtime direct-key normal requests send bearer auth with only the access-key ID.
- Runtime direct-key presigning uses SigV4 with `service = "s3"` and the configured region.
- Runtime credential-ID presigning returns an unsigned URL because the secret key is not available.
- Runtime expects JSON success responses for all HTTP helper paths.
- Provider HTTP 401/403, 404, 429, and other API errors map to typed connector/FCP errors.
- `Retry-After` on 429 is honored when present and otherwise defaults to 30000 ms.
- Manifest connect timeout is `10000 ms`, operation total timeout ranges from `30000 ms` to `300000 ms`, and maximum response bytes vary by operation.
- Sandbox profile is `strict`, with `512 MB` memory, `50%` CPU, no exec, and no inbound listener capability.
- The connector does not open inbound sockets, subscribe to bucket events, or manage AWS credentials outside the configured process state.

## Operation Inventory

| Operation | Runtime request shape | Capability | SafetyTier | RiskLevel | Idempotency | Required input |
|-----------|-----------------------|------------|------------|-----------|-------------|----------------|
| `s3.put_object` | `PUT /{bucket}/{key}` | `s3.write` | `Risky` | `Medium` | `Strict` | `bucket`, `key`, `body` |
| `s3.get_object` | `GET /{bucket}/{key}` | `s3.read` | `Safe` | `Low` | `Strict` | `bucket`, `key` |
| `s3.delete_object` | `DELETE /{bucket}/{key}` | `s3.delete` | `Dangerous` | `High` | `Strict` | `bucket`, `key`, approval token |
| `s3.create_bucket` | `PUT /{bucket}` | `s3.write` | `Dangerous` | `High` | `Strict` | `bucket`, approval token |
| `s3.delete_bucket` | `DELETE /{bucket}` | `s3.delete` | `Dangerous` | `High` | `Strict` | `bucket`, approval token |
| `s3.head_object` | `HEAD /{bucket}/{key}` | `s3.read` | `Safe` | `Low` | `Strict` | `bucket`, `key` |
| `s3.list_objects` | `GET /{bucket}?list-type=2` | `s3.read` | `Safe` | `Low` | `Strict` | `bucket`; optional `prefix`, `max_keys` |
| `s3.list_buckets` | `GET /` | `s3.read` | `Safe` | `Low` | `Strict` | none |
| `s3.copy_object` | `PUT /{dest_bucket}/{dest_key}` | `s3.write` | `Risky` | `Medium` | `Strict` | `source_bucket`, `source_key`, `dest_bucket`, `dest_key` |
| `s3.generate_presigned_url` | local signing only | `s3.read` | `Dangerous` | `High` | `None` | `bucket`, `key`; optional `expires_in`; approval token |

## Explicit Non-Goals

The current implementation does not include:

- AWS SigV4 signing for normal S3 HTTP operations
- AWS STS, IAM role assumption, session tokens, MFA, profile discovery, or credential refresh
- multipart upload, resumable upload, checksum selection, server-side encryption options, object tags, ACLs, object lock, legal holds, or retention policies
- bucket policy, CORS, website hosting, lifecycle, replication, inventory, notification, versioning, requester-pays, or access-point management
- pagination continuation tokens, delimiter/common-prefix handling, S3 Select, Glacier restore, batch operations, or object-lambda routing
- inbound event notifications, SQS/SNS/EventBridge integration, durable cursors, or replay
- durable local object cache, large-object streaming, binary-body handling, or content-type negotiation

These are excluded on purpose:

- S3 write/delete and presigned URL operations can leak or destroy durable storage state.
- A general AWS SDK facade would bypass the connector's typed capability model.
- Real AWS S3 parity requires auth, body, header, error, and pagination contracts beyond the current JSON fixture facade.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- local configuration, client, auth mode, base URL, and request/error counter state
- direct-key live list-buckets self-check behavior
- degraded self-check for credential-ID mode
- typed introspection with operations, schemas, capability IDs, risk levels, safety tiers, idempotency, and approval metadata
- simulation allow/deny with the same bound capability and dangerous-operation approval checks used by invoke
- provider/FCP error mapping for auth failures, missing resources, rate limits, retryable provider errors, JSON errors, and transport errors

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle, configuration, health, handshake, introspection, simulation, shutdown, and missing-input behavior
- client-level put/get/delete/list/copy/list-buckets and presigning behavior through deterministic HTTP fixtures
- connector-level invoke dispatch with bound capability tokens
- wrong-capability rejection, unknown-operation rejection, and missing required input rejection
- approval-token requirement for dangerous operations
- direct-key presigning and credential-ID unsigned URL behavior
- provider 401/403, 404, 429, and retryable server-error classes
- auth redaction and JSON error-shape handling

## Source Notes

- `connectors/s3/src/connector.rs` defines configuration parsing, lifecycle handlers, capability verification, approval-token checks, operation catalog, simulation, introspection, and invoke dispatch.
- `connectors/s3/src/client.rs` defines URL construction, auth headers, timeout, retry behavior, simplified S3 HTTP helpers, presigning, and provider error mapping.
- `connectors/s3/src/types.rs` defines runtime response and API error shapes.
- `connectors/s3/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/s3/manifest.toml` defines the manifest operation catalog, network constraints, sandbox boundary, zone policy, and rate-limit intent.
- `connectors/s3/tests/integration.rs` contains the runtime contract proof surface.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/s3/README.md
ubs connectors/s3/README.md
LC_ALL=C rg -n '[^ -~]' connectors/s3/README.md
rg -n '\bmaster\b' connectors/s3/README.md
```

For source or behavior changes, also run the connector proof lane through `rch`:

```bash
rch exec -- cargo test -p fcp-s3
rch exec -- cargo check -p fcp-s3 --all-targets
rch exec -- cargo clippy -p fcp-s3 --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

## Operator Guidance

- Treat this connector as a JSON S3-compatible facade unless and until normal operations gain AWS SigV4 signing and AWS response-shape parsing.
- Keep direct-key mode pointed at deterministic test endpoints or S3-compatible services that accept the simplified bearer-style auth and JSON response shape.
- Do not rely on `self_check()` as proof of full AWS S3 compatibility; it only calls runtime `list_buckets()`.
- Prefer host-managed credential references for secret injection, but do not use credential-ID mode to generate shareable presigned URLs.
- Treat `s3.delete_object`, `s3.create_bucket`, `s3.delete_bucket`, and `s3.generate_presigned_url` as high-review operations even though the current approval token is locally validated rather than signature-verified here.
- Do not use this connector for large binary objects, streaming downloads, multipart uploads, or bucket-admin workflows without a follow-up runtime contract.
