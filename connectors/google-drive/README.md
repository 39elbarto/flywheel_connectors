# Google Drive Connector V3 Contract

> **Status**: runtime contract documented; manifest/runtime drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Drive files upstream**: https://developers.google.com/drive/api/reference/rest/v3/files
> **Drive files list upstream**: https://developers.google.com/drive/api/reference/rest/v3/files/list
> **Drive files get upstream**: https://developers.google.com/drive/api/reference/rest/v3/files/get
> **Drive files create upstream**: https://developers.google.com/drive/api/reference/rest/v3/files/create
> **Drive files update upstream**: https://developers.google.com/drive/api/reference/rest/v3/files/update
> **Drive permissions create upstream**: https://developers.google.com/drive/api/reference/rest/v3/permissions/create
> **Drive uploads upstream**: https://developers.google.com/drive/api/guides/manage-uploads

## Purpose

This document fixes the operator-facing contract for `fcp.google_drive`. The connector exposes the Google Drive API surface implemented in this crate: file listing, metadata lookup, content download, folder creation, file upload, trashing, and user permission creation.

The connector is intentionally a bounded Drive bridge. It is not a full Google Workspace admin client, Docs/Sheets/Slides export client, sync engine, permission auditor, shared-drive administrator, resumable uploader, or long-running Drive warehouse.

## Current Runtime Snapshot

The current crate exposes these operations:

- `drive.list_files`
- `drive.get_file`
- `drive.download_file`
- `drive.create_folder`
- `drive.upload_file`
- `drive.trash_file`
- `drive.share_file`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-google-drive`.
- Runtime `BaseConnector` ID is `google-drive`.
- Configuration accepts Google auth at the top level through `GoogleAuthSelection`: direct bearer token, `credential_id`, or `oauth_refresh`.
- Direct bearer-token mode sends the Google Authorization header through `GoogleRestExecutor`.
- `credential_id` mode is secretless and reports `configured_pending_token_materialization`.
- Default base URL is `https://www.googleapis.com/drive/v3`.
- Public base URLs must use HTTPS, must target exact host `www.googleapis.com`, and must not contain userinfo, query strings, or fragments.
- `localhost`, `127.0.0.1`, and `::1` are accepted with HTTP or HTTPS for deterministic loopback tests.
- Runtime request timeout is 30 seconds.
- The client uses the shared retry loop with `max_retries = 2`, `initial_delay_ms = 500`, `max_delay_ms = 30000`, and jitter enabled.
- File IDs are inserted into URL path segments only after local path-segment validation and URL encoding.
- Path-segment validation rejects empty strings, slashes, backslashes, `..`, query strings, fragments, encoded slash/backslash/query/fragment markers, and literal percent characters.
- `drive.list_files` URL-encodes `query` and `page_token`, and forwards `max_results` as `pageSize` without clamping it in the client.
- `drive.download_file` requests `alt=media` and returns `content_base64`; if the executor returns JSON instead of binary, the current runtime returns the JSON value as a string.
- `drive.upload_file` calls `files?uploadType=multipart` but sends a JSON wrapper containing `metadata` and `media_body_base64` through `GoogleRestExecutor`. It does not implement Google resumable upload.
- `drive.share_file` creates a user permission and accepts roles `reader`, `commenter`, `writer`, and `organizer`.
- Runtime handshake installs a `CapabilityVerifier`.
- `invoke` requires `capability_token`, validates input, computes resource URIs, and verifies a bound capability token before provider execution.
- `simulate` validates operation inventory, input shape, configured/handshaken state, and bound capability token before returning an allowed result.
- `doctor()` and `self_check()` probe Drive API reachability through the `about` endpoint when credentials are materialized.
- `health()` reports local configured/client state only.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- Manifest connector ID is `fcp.google_drive`, while runtime `BaseConnector` ID is `google-drive`.
- Runtime handshake returns placeholder manifest hash `sha256:google-drive-connector-v1`.
- Manifest `interface_hash` is all zeroes.
- Manifest optional capabilities include `media.download` and `media.upload`, but runtime introspection and capability verification use only `drive.read` and `drive.write`.
- Runtime `drive.download_file` can return a JSON string in `content_base64` if the executor gives the client a JSON response body.
- Runtime `drive.upload_file` advertises multipart upload but sends a JSON wrapper rather than constructing a true multipart request body or resumable upload session.
- Runtime introspection says `max_results` has a maximum of 1000, but runtime input validation and client dispatch do not clamp the value.
- Runtime `handle_shutdown` calls client shutdown but does not clear client, verifier, session, configured flags, or handshaken flags.
- `self_check()` reports `DEFAULT_BASE_URL` in details even when a loopback or custom base URL was configured.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should align connector ID spelling, replace placeholder manifest/interface proofs, reconcile media capabilities, fix upload/download response semantics, clamp or reject out-of-range pagination input, reset lifecycle state consistently on shutdown, and report the active base URL in self-check.

## First-Slice Scope

The current Google Drive README slice documents the existing runtime surface:

- Google bearer-token, credential-reference, and OAuth refresh auth selection
- Drive API base URL policy and loopback test allowance
- file list/get/download, folder create, file upload, file trash, and user share operations
- bound capability-token verification during both `invoke` and `simulate`
- provider error mapping, retry behavior, redaction posture, doctor behavior, and health behavior
- lifecycle, doctor, health, self-check, introspection, simulation, invoke, and shutdown surfaces
- deterministic WireMock tests and direct proof commands

## Auth And Scope Boundary

- Authentication mechanisms: Google bearer token, host credential reference, or OAuth refresh material through the shared Google auth layer.
- Home zone: `z:private`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zones: `z:private` and `z:work`.
- Forbidden zone: `z:public`.
- Runtime capability surface:
  - `drive.read` gates file listing, metadata lookup, and file download.
  - `drive.write` gates folder creation, file upload, trashing, and sharing.
- Manifest capability surface also lists `media.download` and `media.upload`, but current runtime checks only `drive.read` and `drive.write`.
- The connector does not persist file metadata, file content, permission records, access tokens, credential IDs, provider payloads, or provider error bodies beyond process memory.
- Drive data can contain private filenames, folder topology, document contents, owners, thumbnails, links, and sharing relationships. Treat all live reads and writes as private or work-zone data.

## Network And Runtime Invariants

- Production host: `www.googleapis.com`.
- Production API prefix: `/drive/v3`.
- Production port: `443`.
- TLS and SNI are required by the manifest for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live operations.
- Runtime loopback base URLs are test-only.
- Runtime request timeout: `30 seconds`.
- Manifest network constraints use `10_000 ms` or `15_000 ms` connect timeout depending on operation.
- Manifest total timeout ranges from `30_000 ms` to `600_000 ms`, with the longest window reserved for upload.
- Manifest maximum response bytes range from `1_048_576` to `52_428_800` depending on operation size.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `600_000 ms` wall-clock timeout, no exec, and no ptrace.
- The connector does not open inbound sockets.
- The connector does not implement streaming events or replay.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `drive.read` | Read Drive file lists, metadata, and file bytes visible to the authenticated principal. |
| `drive.write` | Create folders, upload files, move files to trash, and create user permissions. |
| `media.download` | Manifest-only optional capability in this checkout; runtime checks `drive.read`. |
| `media.upload` | Manifest-only optional capability in this checkout; runtime checks `drive.write`. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `drive.list_files` | `GET /drive/v3/files?fields=...` | `drive.read` | `Safe` | `Low` | `Strict` | Lists Drive files and folders visible to the authenticated principal. |
| `drive.get_file` | `GET /drive/v3/files/{file_id}?fields=...` | `drive.read` | `Safe` | `Low` | `Strict` | Reads metadata for one Drive file or folder. |
| `drive.download_file` | `GET /drive/v3/files/{file_id}?alt=media` | `drive.read` | `Safe` | `Low` | `Strict` | Downloads file content and returns it as `content_base64` when the executor returns binary. |
| `drive.create_folder` | `POST /drive/v3/files?fields=id,name,mimeType,parents` | `drive.write` | `Risky` | `Medium` | `None` | Creates a new folder, optionally under a parent folder. |
| `drive.upload_file` | `POST /drive/v3/files?uploadType=multipart&fields=id,name,mimeType,size` | `drive.write` | `Dangerous` | `High` | `None` | Creates a new file from base64 input using the current JSON-wrapper upload path. |
| `drive.trash_file` | `PATCH /drive/v3/files/{file_id}?fields=id,name,trashed` | `drive.write` | `Dangerous` | `High` | `Strict` | Moves a file or folder to trash. |
| `drive.share_file` | `POST /drive/v3/files/{file_id}/permissions` | `drive.write` | `Dangerous` | `Critical` | `None` | Grants another user access to a file or folder. |

## Resource URIs

Runtime capability-token verification binds operations to these resource URI shapes:

| Operation | Resource URI |
|-----------|--------------|
| `drive.list_files` | `drive://files` |
| `drive.get_file` | `drive://files/{file_id}` |
| `drive.download_file` | `drive://files/{file_id}` |
| `drive.trash_file` | `drive://files/{file_id}` |
| `drive.share_file` | `drive://files/{file_id}` |
| `drive.create_folder` | `drive://folders/{parent_id_or_root}/children` |
| `drive.upload_file` | `drive://folders/{parent_id_or_root}/children` |

## Explicit Non-Goals

The current implementation does not include:

- Google Docs, Sheets, or Slides export before download
- resumable uploads, multipart body construction outside the current executor wrapper, upload progress, or checksum verification
- permission listing, permission deletion, link-sharing policy management, domain sharing, ownership transfer, shared-drive administration, or ACL audit
- file copy, move, rename, patch, labels, revisions, comments, shortcuts, change feeds, watch channels, or hard delete
- folder search/create idempotency, sync-token storage, durable file indexes, Drive warehouse export, or connector-local credential vaulting
- OAuth consent setup, Drive API enablement, service-account/domain-wide delegation provisioning, or Google Workspace tenant onboarding

These are excluded on purpose:

- Drive contents and permission records are high-sensitivity user data.
- Upload, export, and shared-drive behavior need separate idempotency and proof contracts.
- Permission changes are sensitive enough to keep narrowly documented and explicitly confirmed before live use.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration and local client state
- Drive API reachability and storage quota through the `about` endpoint in `doctor()`
- provider-backed self-check through the same health path when credentials are materialized
- operation metadata with capability, risk, safety tier, idempotency, schemas, and AI hints
- bound capability-token verification during `invoke`
- simulation denial for unknown operation, unconfigured connector, missing handshake, invalid input, and bound capability-token mismatch
- local-only `health()` behavior
- typed provider/FCP error mapping

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle, configuration, base URL policy, loopback allowance, introspection, simulation, doctor, self-check, and shutdown behavior
- file list/get/download, folder create, file upload, file trash, and file share through deterministic HTTP fixtures
- invoke rejection for unknown operation, missing token, missing input, wrong capability, and pre-provider capability verification
- provider 401, 403, 404, 429, retryable transport/server classes, malformed JSON, quota errors, and FCP error mapping
- path-segment validation for traversal and double-encoded separators

## Source Notes

- `connectors/google-drive/src/connector.rs` defines configuration parsing, base URL policy, lifecycle handlers, introspection, simulation, capability-token verification, resource URI binding, and invoke dispatch.
- `connectors/google-drive/src/client.rs` defines Drive paths, Google auth application, retry dispatch, timeout, request metrics, path-segment validation, download response conversion, upload body construction, and provider error mapping.
- `connectors/google-drive/src/types.rs` defines file, permission, about, quota, doctor, and request/response shapes.
- `connectors/google-drive/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/google-drive/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, event caps, and rate-limit pools.
- `connectors/google-drive/tests/connector_suite_happy_path.rs` covers deterministic runtime behavior and connector-suite expectations.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/google_drive_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- runtime operation inventory and policy metadata
- deterministic WireMock coverage for Drive API paths
- auth, endpoint policy, provider error, lifecycle, simulation, and introspection tests
- formatting, check, test, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a Google account or Workspace test tenant with Drive API access enabled for live verification.
- Prefer credential-reference mode when host policy should own Google secret material.
- Use loopback WireMock fixtures for routine proof.

**Dedicated environment**:

- Keep test files and folders separate from personal and production Drives.
- Use disposable files for upload, trash, and share proof.
- Avoid organizer role in live proof unless the shared-drive authority model is explicitly under test.

**Redaction rules**:

- Redact access tokens, credential IDs where needed, file IDs when sensitive, folder IDs, filenames, owner names, owner emails, permission IDs, target emails, file content, provider payloads, provider error bodies, and endpoint URLs when they reveal tenant topology.
- Verification output should use operation IDs, endpoint shapes, auth mode, host class, result counts, status/error classes, retry decisions, and payload-shape summaries.

**Common remediation**:

- If configuration fails, provide exactly one Google auth source at the top level.
- If live checks fail with a credential reference, materialize host credentials before invoking provider operations.
- If `drive.download_file` fails on Google-native documents, export through the appropriate Google API first; this connector does not implement export.
- If `drive.upload_file` fails against real Drive, inspect the current upload body contract before assuming resumable or true multipart upload is implemented.
- If list pagination behaves unexpectedly, validate `max_results`, `query`, and `page_token` against Drive API syntax and provider limits.
- If provider returns 403, treat it as an auth/permission failure rather than a retryable transport error.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-google-drive-readme cargo check -p fcp-google-drive --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-google-drive-readme cargo test -p fcp-google-drive --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-google-drive-readme cargo clippy -p fcp-google-drive --all-targets --no-deps -- -D warnings`
- `ubs connectors/google-drive/README.md`
