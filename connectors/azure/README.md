# Azure Connector V3 Contract

> **Status**: runtime contract documented; simulation gap documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/azure_connector_verification.sh`
> **ARM upstream**: https://learn.microsoft.com/en-us/rest/api/resources/subscriptions/list
> **Blob upstream**: https://learn.microsoft.com/en-us/rest/api/storageservices/blob-service-rest-api
> **Key Vault upstream**: https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/

## Purpose

This document fixes the operator-facing contract for `fcp.azure`. The connector exposes the Azure surface implemented in this crate: Azure Resource Manager subscription/resource-group/resource listing, Blob Storage container/blob read/write operations, and Key Vault secret metadata/value operations.

The connector is intentionally a work-zone Azure operations bridge. It is not a general Azure SDK, OAuth installer, tenant admin client, ARM mutation engine, storage account manager, Key Vault lifecycle manager, durable inventory warehouse, or event listener.

## Current Runtime Snapshot

The current runtime exposes these operations:

- `azure.management.list_subscriptions`
- `azure.management.list_resource_groups`
- `azure.management.list_resources`
- `azure.storage.blob_list_containers`
- `azure.storage.blob_list_blobs`
- `azure.storage.blob_get`
- `azure.storage.blob_put`
- `azure.keyvault.list_secrets`
- `azure.keyvault.get_secret`
- `azure.keyvault.set_secret`

Important runtime truths the contract preserves:

- Configuration requires auth mode `bearer_token` or `credential_id`.
- Bearer-token mode sends `Authorization: Bearer ...`.
- Credential-id mode sends `X-FCP-Credential-ID`.
- Bearer tokens are redacted in debug output.
- Credential-id mode is treated as secretless and reports degraded health/self-check until host or egress credential injection is available.
- `management_url` defaults to `https://management.azure.com`.
- Production `management_url` must use HTTPS, host `management.azure.com`, and resolve to port 443.
- Loopback HTTP/HTTPS management URLs are accepted for deterministic tests.
- Optional per-operation `blob_base_url` values must target `https://<account>.blob.core.windows.net` or loopback verification stubs.
- Optional per-operation `vault_base_url` values must target `https://<vault>.vault.azure.net` or loopback verification stubs.
- Controlled base URLs must not include userinfo, paths, query strings, or fragments.
- Runtime request timeout defaults to `30_000 ms`.
- The client uses user agent `fcp-azure/0.1.0`.
- Azure API versions default to:
  - subscriptions: `2022-12-01`
  - resource groups: `2021-04-01`
  - resources: `2021-04-01`
  - Key Vault: `2025-07-01`
  - Blob Storage: `2026-02-06`
- API versions can be overridden through config or `FCP_AZURE_*_API_VERSION` environment variables.
- ARM responses are parsed as JSON.
- Blob container/blob list responses are parsed as XML.
- Blob get returns `content_base64`, `content_type`, and `content_length`.
- Blob put decodes caller-supplied `content_base64`, sends `x-ms-blob-type: BlockBlob`, and can overwrite an existing blob.
- Key Vault list returns secret metadata only; get and set return secret bundles that may include secret values.
- `self_check` proves readiness by calling ARM `list_subscriptions`.
- Handshake grants requested capabilities and installs a bound `CapabilityVerifier`.
- `invoke` verifies bound capability tokens against the requested operation.
- `simulate` currently returns allowed without capability-token or operation validation.
- `introspect` exposes no streaming support.

## Simulation Gap In This Checkout

Runtime dispatch and manifest metadata are broadly aligned, but one readiness surface is intentionally visible here:

- `invoke` enforces bound capability-token verification.
- `simulate` currently returns `SimulateResponse::allowed` for every request without checking operation ID, readiness, or capability token.

This README documents that runtime truth. A follow-up simulation parity bead should make Azure simulation match invoke-time capability and operation validation before treating simulation as an authorization preview.

## First-Slice Scope

The first Azure README slice documents the existing runtime surface:

- subscription listing through `GET /subscriptions?api-version=...`
- resource group listing through `GET /subscriptions/{subscriptionId}/resourcegroups?api-version=...`
- resource listing through `GET /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/resources?api-version=...`
- blob container listing through `GET https://{account}.blob.core.windows.net/?comp=list`
- blob listing through `GET /{container}?restype=container&comp=list`
- blob download through `GET /{container}/{blob}`
- block blob upload/overwrite through `PUT /{container}/{blob}`
- Key Vault secret listing through `GET {vaultBaseUrl}/secrets?api-version=...`
- Key Vault secret get through `GET {vaultBaseUrl}/secrets/{secret-name}?api-version=...`
- Key Vault secret set through `PUT {vaultBaseUrl}/secrets/{secret-name}?api-version=...`
- bearer-token and host credential reference auth
- management, blob, and vault endpoint policy
- lifecycle, doctor, self-check, introspection, simulation, and shutdown surfaces

## Auth And Scope Boundary

- Authentication mechanisms: Azure bearer token or host credential reference.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Capability surface:
  - `azure.management.read` gates subscription, resource group, and resource listing.
  - `azure.storage.read` gates blob container listing, blob listing, and blob download.
  - `azure.storage.write` gates blob upload/overwrite.
  - `azure.keyvault.read` gates Key Vault secret listing and secret value retrieval.
  - `azure.keyvault.write` gates Key Vault secret set/update.
- The connector does not persist tokens, credential IDs, tenant IDs, subscription IDs, resource IDs, blob payloads, secret values, or provider responses beyond process memory.
- Credential-id mode forwards a host credential reference header; host-side credential materialization remains outside this connector.
- The manifest required capability list covers network primitives; operation entries and runtime introspection carry the operation-specific `azure.*` capability IDs.

## Network And Runtime Invariants

- ARM production host: `management.azure.com`.
- Blob production host pattern: `*.blob.core.windows.net`.
- Key Vault production host pattern: `*.vault.azure.net`.
- Production port: `443`.
- TLS and SNI are required for live provider traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live operations.
- Runtime loopback overrides are test-only.
- Runtime request timeout: `30_000 ms`.
- Manifest operation total timeout: `30_000 ms`.
- Maximum response bytes are `67_108_864` for blob get, `8_388_608` for list/read metadata paths, and `4_194_304` for write/secret value paths.
- Sandbox profile is `strict`, with `128 MB` memory, `25%` CPU, `30_000 ms` wall-clock timeout, no exec, and no ptrace.
- The connector does not open listeners and does not implement FCP subscriptions.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `azure.management.read` | List subscriptions, resource groups, and resources. |
| `azure.storage.read` | List containers, list blobs, and download blob content. |
| `azure.storage.write` | Upload or overwrite blob content. |
| `azure.keyvault.read` | List secret metadata and retrieve secret values. |
| `azure.keyvault.write` | Create or update Key Vault secrets. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `azure.management.list_subscriptions` | `GET /subscriptions` | `azure.management.read` | `Safe` | `Low` | `Strict` | Reads subscriptions visible to the credentials. |
| `azure.management.list_resource_groups` | `GET /subscriptions/{subscriptionId}/resourcegroups` | `azure.management.read` | `Safe` | `Low` | `Strict` | Reads resource groups under one subscription. |
| `azure.management.list_resources` | `GET /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/resources` | `azure.management.read` | `Safe` | `Low` | `Strict` | Reads resource inventory in one resource group. |
| `azure.storage.blob_list_containers` | `GET /?comp=list` | `azure.storage.read` | `Safe` | `Low` | `Strict` | Reads blob containers in one storage account. |
| `azure.storage.blob_list_blobs` | `GET /{container}?restype=container&comp=list` | `azure.storage.read` | `Safe` | `Low` | `Strict` | Reads blob names and metadata in one container. |
| `azure.storage.blob_get` | `GET /{container}/{blob}` | `azure.storage.read` | `Safe` | `Low` | `Strict` | Downloads one blob and returns base64 content. |
| `azure.storage.blob_put` | `PUT /{container}/{blob}` | `azure.storage.write` | `Risky` | `Medium` | `Strict` | Uploads or overwrites one block blob. |
| `azure.keyvault.list_secrets` | `GET /secrets` | `azure.keyvault.read` | `Safe` | `Low` | `Strict` | Reads secret metadata without values. |
| `azure.keyvault.get_secret` | `GET /secrets/{secret-name}` | `azure.keyvault.read` | `Risky` | `Medium` | `Strict` | Retrieves a secret value and metadata. |
| `azure.keyvault.set_secret` | `PUT /secrets/{secret-name}` | `azure.keyvault.write` | `Dangerous` | `High` | `Strict` | Creates a new secret version and mutates sensitive vault state. |

## Explicit Non-Goals

The current implementation does not include:

- OAuth authorization, token refresh, managed identity acquisition, or service principal provisioning
- ARM create/update/delete operations, deployments, role assignments, policy, locks, tags, or tenant management
- storage account creation, container creation/deletion, blob deletion, leases, snapshots, copy operations, append/page blobs, multipart/block-list uploads, or SAS issuance
- Key Vault vault creation, secret deletion/purge/recovery, certificates, keys, backup/restore, rotation policy, or RBAC management
- durable inventory storage, local cache, blob sync, or secret replication
- public-zone invocation or inbound callback listeners
- connector-local credential vaulting

These are excluded on purpose:

- The useful first slice is bounded ARM read, Blob read/write, and Key Vault secret read/write coverage.
- Blob upload and Key Vault secret set mutate live data and require dedicated staging resources for proof.
- Broader Azure mutation workflows need separate state, RBAC, idempotency, and rollback contracts.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, handshake state, request counters, and error counters
- auth mode as bearer token or credential ID
- management URL, effective API versions, supported blob/vault overrides, and credential-injection status
- manifest hash, verification script, artifact root, rerun commands, and operator guidance
- operation metadata, schemas, capability IDs, risk levels, safety tiers, idempotency, and approval modes
- degraded self-check for credential-id mode because egress proxy injection is required
- permissive simulation status until the simulation parity gap is closed

The deterministic integration evidence is anchored on WireMock and connector-local tests covering:

- lifecycle health, doctor, self-check, introspection, and shutdown
- bearer auth header behavior
- local management URL readiness through `list_subscriptions`
- Blob put dispatch with `x-ms-version` and `x-ms-blob-type: BlockBlob`
- Key Vault set secret dispatch and redacted evidence handling
- risky and dangerous operation metadata
- bound capability-token verification on invoke
- retryable management failure reporting
- API version defaults and provisioning detail

## Source Notes

- `connectors/azure/src/connector.rs` defines configuration parsing, endpoint policy, lifecycle handlers, capability mapping, doctor/self-check details, operation dispatch, simulation behavior, and introspection metadata.
- `connectors/azure/src/client.rs` defines API version defaults, ARM JSON calls, Blob XML and byte calls, Key Vault JSON calls, auth headers, retry dispatch, and provider error mapping.
- `connectors/azure/src/types.rs` defines auth modes and normalized ARM, Blob, Key Vault, and error response types.
- `connectors/azure/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, and operation AI hints.
- `connectors/azure/tests/integration.rs` covers deterministic WireMock operation behavior, lifecycle diagnostics, capability verification, risky/dangerous metadata, and readiness evidence.

## Verification Bundle

The tracked verification bundle is `scripts/e2e/azure_connector_verification.sh`.

The verification surface captures:

- runtime operation contract tests
- deterministic WireMock ARM, Blob Storage, and Key Vault coverage
- auth, endpoint override, API version, lifecycle, doctor, self-check, risky mutation, dangerous operation, and introspection tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a scoped bearer token for direct live verification.
- Use `credential_id` only when a host or egress proxy can inject a concrete Azure bearer token.
- Use a disposable Azure subscription, resource group, storage account, blob container, and Key Vault for live mutation tests.
- Use loopback fixtures for routine proof.

**Dedicated environment**:

- Use staging-only subscriptions, storage accounts, containers, blobs, vaults, and secrets.
- Never run blob overwrite or Key Vault secret set against production resources during verification.
- Keep secret values and blob payloads synthetic.
- Treat tenant IDs, subscription IDs, resource IDs, storage account names, vault names, container names, blob names, and secret names as sensitive.

**Redaction rules**:

- Redact bearer tokens, credential IDs where needed, `Authorization` headers, `X-FCP-Credential-ID` values when sensitive, tenant IDs, subscription IDs, resource IDs, storage account names, vault names, blob payloads, secret values, provider payloads, and provider error bodies.
- Verification output should use operation names, endpoint classes, status/error classes, result counts, API version labels, and redacted resource markers.

**Common remediation**:

- If configuration fails, check auth mode, non-empty bearer token, `management_url`, and API version values.
- If `doctor` reports `credential_injection_required`, provide a bearer token for direct proof or configure the host/egress injector for the credential ID.
- If `self_check` fails against ARM, verify the bearer token audience/scope, expiry, and subscription visibility.
- If blob or vault override validation fails, use the exact production host patterns or a loopback verification URL without paths, userinfo, query strings, or fragments.
- If blob put validation fails, make sure `content_base64` is valid base64 and that the operation is targeting a staging container.
- If Key Vault set succeeds but logs contain secret material, treat the artifact as contaminated and rerun with redaction.
- If `simulate` allows an operation that `invoke` would reject, treat invoke as authoritative until the simulation parity gap is fixed.

**Rerun commands**:

- `scripts/e2e/azure_connector_verification.sh`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-azure-e2e cargo check -p fcp-azure --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-azure-e2e cargo test -p fcp-azure --test integration -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-azure-e2e cargo clippy -p fcp-azure --all-targets --no-deps -- -D warnings`
- `ubs connectors/azure/README.md`
