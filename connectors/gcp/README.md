# GCP Connector V3 Contract

> **Status**: runtime contract documented; manifest/policy drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/gcp_connector_verification.sh`
> **Compute upstream**: https://cloud.google.com/compute/docs/reference/rest/v1/instances
> **Storage upstream**: https://cloud.google.com/storage/docs/json_api/v1/
> **Cloud Run upstream**: https://cloud.google.com/run/docs/reference/rest/v2/projects.locations.services
> **Resource Manager upstream**: https://cloud.google.com/resource-manager/reference/rest/v1/projects/get
> **Service account upstream**: https://developers.google.com/identity/protocols/oauth2/service-account

## Purpose

This document fixes the operator-facing contract for `fcp.gcp`. The connector exposes the Google Cloud surface implemented in this crate: Compute Engine instances, Cloud Storage objects, Cloud Run services, project metadata, and a project-backed health check.

The connector is intentionally a bounded Google Cloud operations bridge. It is not a full Google Cloud SDK, Terraform replacement, IAM administration tool, billing client, log/metrics client, Pub/Sub client, BigQuery client, Kubernetes client, Secret Manager client, project factory, or organization-policy manager.

## Current Runtime Snapshot

The current crate exposes these operations:

- `gcp.compute.list_instances`
- `gcp.compute.get_instance`
- `gcp.compute.start_instance`
- `gcp.compute.stop_instance`
- `gcp.compute.delete_instance`
- `gcp.storage.list_objects`
- `gcp.storage.get_object`
- `gcp.storage.upload_object`
- `gcp.storage.delete_object`
- `gcp.run.list_services`
- `gcp.run.deploy_service`
- `gcp.run.delete_service`
- `gcp.projects.get`
- `gcp.health`

Important runtime truths the contract preserves:

- Configuration requires `project_id` and a GCP auth mode.
- Supported auth modes are `access_token` and `service_account`.
- `access_token` mode sends a static bearer token unless the token is empty.
- `service_account` mode validates private-key PEM at configure time, builds a JWT assertion, exchanges it for an OAuth access token, and caches the resulting token.
- Empty access tokens and empty service-account private keys are secretless credential-injection mode.
- Secretless mode leaves Authorization absent and makes health/self-check degraded with `credential_injection_required`.
- Default OAuth scope for service-account token exchange is `https://www.googleapis.com/auth/cloud-platform`.
- Default production hosts are `compute.googleapis.com`, `storage.googleapis.com`, `run.googleapis.com`, and `cloudresourcemanager.googleapis.com`.
- Base URL overrides are accepted for the four services, but production overrides must use HTTPS, the expected service host, no path, no query string, and no fragment.
- `localhost`, `127.0.0.1`, `::1`, and `.localhost` hosts are accepted for deterministic tests with HTTP or HTTPS.
- `request_timeout_ms` defaults to `30_000` and must be greater than zero.
- Requests run through the shared retry loop with connector runtime deadlines.
- 429, retryable transport errors, and 5xx/API retryable classes are retried; 401, 403, 404, non-retryable API errors, and JSON parse failures are terminal.
- Compute zone and instance names, bucket names, Cloud Run locations, service names, and most URL path segments are sanitized to reject traversal and path-injection characters.
- Cloud Storage object names allow `/` for hierarchical object names but reject backslash and traversal-like sequences.
- Debug output redacts token and private-key material.
- Handshake installs a `CapabilityVerifier`, and `invoke` verifies bound capability tokens against the requested operation.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- Runtime `simulate` returns allowed for any requested operation ID; it does not validate readiness, operation inventory, input schema, capability token, or approval policy.
- Runtime approval metadata is missing for several mutating operations that the manifest marks as policy-sensitive. Runtime only marks `gcp.compute.delete_instance`, `gcp.storage.delete_object`, and `gcp.run.delete_service` as `Interactive`.
- Runtime `gcp.storage.upload_object` overwrites by simple media upload and has no approval metadata despite being a write operation.
- Runtime `gcp.run.deploy_service` creates a minimal Cloud Run v2 service with only `template.containers[0].image`; it does not support update, patch, traffic, env vars, volumes, secrets, service accounts, ingress, or long-running operation polling.
- Runtime `gcp.run.delete_service` expects the service input under `service_name`, while operation metadata and manifest input schema name the field `service`.
- Runtime object upload places the object name in a query string without percent-encoding slash-bearing names; object reads/deletes place object names directly in the path.
- Cloud Resource Manager runtime uses the v1 `projects/{project_id}` endpoint, while current Google Cloud project-management docs also emphasize v3 resource-name forms.

A follow-up parity bead should tighten simulation, align approval metadata and Cloud Run delete input names, encode object names consistently, and decide whether to move project metadata to Resource Manager v3.

## First-Slice Scope

The current GCP README slice documents the existing runtime surface:

- access-token, service-account, and secretless auth configuration
- production and loopback endpoint policy for Compute, Storage, Cloud Run, and Resource Manager
- Compute Engine list/get/start/stop/delete instance operations
- Cloud Storage list/get/upload/delete object operations
- Cloud Run list/deploy/delete service operations
- Resource Manager project lookup and health check
- bound capability-token verification for invoke
- provider error mapping, retry behavior, path validation, and redaction posture
- lifecycle, doctor, health, self-check, introspection, simulation, and shutdown surfaces
- deterministic WireMock tests and the tracked verification bundle

## Auth And Scope Boundary

- Authentication mechanisms: Google Cloud bearer access token, service-account JWT exchange, or secretless host injection.
- Home zone: `z:work`.
- Allowed source zones: `z:work` and `z:private`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Runtime capability surface:
  - `gcp.compute.read` gates Compute instance listing and lookup.
  - `gcp.compute.write` gates Compute instance start, stop, and delete.
  - `gcp.storage.read` gates Cloud Storage object listing and metadata reads.
  - `gcp.storage.write` gates Cloud Storage object upload and delete.
  - `gcp.run.read` gates Cloud Run service listing.
  - `gcp.run.write` gates Cloud Run service deploy and delete.
  - `gcp.iam.read` gates project metadata and health checks.
- The connector does not persist GCP resources, access tokens, service-account private keys, provider payloads, or provider error bodies beyond process memory.
- Compute delete, Storage delete, and Cloud Run delete are destructive and require interactive approval metadata at runtime.
- Compute start/stop, Storage upload, and Cloud Run deploy mutate live infrastructure and should be host policy gated even where runtime approval metadata is currently missing.

## Network And Runtime Invariants

- Compute production host: `compute.googleapis.com`.
- Cloud Storage production host: `storage.googleapis.com`.
- Cloud Run production host: `run.googleapis.com`.
- Cloud Resource Manager production host: `cloudresourcemanager.googleapis.com`.
- Production port: `443`.
- TLS and SNI are required by the manifest for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live operations.
- Runtime loopback and `.localhost` overrides are test-only.
- Runtime request timeout defaults to `30_000 ms`.
- Manifest network constraints set `10_000 ms` connect timeout and `30_000 ms` total timeout.
- Manifest response budgets are `10_485_760` bytes for list operations and `1_048_576` bytes for single-resource and mutation operations.
- Sandbox profile is `strict`, with `512 MB` memory, `50%` CPU, `300_000 ms` wall-clock timeout, no exec, and no ptrace.
- The connector does not implement subscriptions or streaming.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `gcp.compute.read` | List and inspect Compute Engine instances. |
| `gcp.compute.write` | Start, stop, or delete Compute Engine instances. |
| `gcp.storage.read` | List Cloud Storage objects and read object metadata. |
| `gcp.storage.write` | Upload or delete Cloud Storage objects. |
| `gcp.run.read` | List Cloud Run services. |
| `gcp.run.write` | Deploy or delete Cloud Run services. |
| `gcp.iam.read` | Read project metadata and credential health through Resource Manager. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `gcp.compute.list_instances` | `GET /compute/v1/projects/{project}/zones/{zone}/instances` | `gcp.compute.read` | `Safe` | `Low` | `None` | Reads VM inventory for one zone. |
| `gcp.compute.get_instance` | `GET /compute/v1/projects/{project}/zones/{zone}/instances/{instance}` | `gcp.compute.read` | `Safe` | `Low` | `None` | Reads one VM's metadata. |
| `gcp.compute.start_instance` | `POST /compute/v1/projects/{project}/zones/{zone}/instances/{instance}/start` | `gcp.compute.write` | `Risky` | `Medium` | `Strict` | Starts a stopped VM and changes compute state. |
| `gcp.compute.stop_instance` | `POST /compute/v1/projects/{project}/zones/{zone}/instances/{instance}/stop` | `gcp.compute.write` | `Risky` | `Medium` | `Strict` | Stops a running VM and can interrupt workloads. |
| `gcp.compute.delete_instance` | `DELETE /compute/v1/projects/{project}/zones/{zone}/instances/{instance}` | `gcp.compute.write` | `Dangerous` | `Critical` | `Strict` | Permanently deletes a VM instance. |
| `gcp.storage.list_objects` | `GET /storage/v1/b/{bucket}/o` | `gcp.storage.read` | `Safe` | `Low` | `None` | Reads object inventory for one bucket. |
| `gcp.storage.get_object` | `GET /storage/v1/b/{bucket}/o/{object}` | `gcp.storage.read` | `Safe` | `Low` | `None` | Reads object metadata, not media content. |
| `gcp.storage.upload_object` | `POST /upload/storage/v1/b/{bucket}/o?uploadType=media&name={object}` | `gcp.storage.write` | `Risky` | `Medium` | `Strict` | Uploads or overwrites object content with a simple media upload. |
| `gcp.storage.delete_object` | `DELETE /storage/v1/b/{bucket}/o/{object}` | `gcp.storage.write` | `Dangerous` | `High` | `Strict` | Deletes a Cloud Storage object. |
| `gcp.run.list_services` | `GET /v2/projects/{project}/locations/{location}/services` | `gcp.run.read` | `Safe` | `Low` | `None` | Lists Cloud Run services in one location. |
| `gcp.run.deploy_service` | `POST /v2/projects/{project}/locations/{location}/services?serviceId={service_id}` | `gcp.run.write` | `Risky` | `High` | `Strict` | Creates a minimal service from one container image. |
| `gcp.run.delete_service` | `DELETE /v2/projects/{project}/locations/{location}/services/{service_name}` | `gcp.run.write` | `Dangerous` | `Critical` | `Strict` | Deletes a Cloud Run service. |
| `gcp.projects.get` | `GET /v1/projects/{project_id}` | `gcp.iam.read` | `Safe` | `Low` | `None` | Reads Resource Manager project metadata. |
| `gcp.health` | `GET /v1/projects/{project_id}` | `gcp.iam.read` | `Safe` | `Low` | `Strict` | Treats an active project lookup as API health. |

## Explicit Non-Goals

The current implementation does not include:

- Compute instance create, update, reset, suspend, resume, resize, metadata, disks, networking, snapshots, images, templates, managed instance groups, or operations polling
- Cloud Storage bucket create/update/delete, IAM, ACLs, retention, version-specific operations, object media download, resumable upload, multipart upload, compose, copy, rewrite, metadata patching, or signed URLs
- Cloud Run get, patch, traffic splitting, revisions, jobs, workers, IAM, operation polling, env vars, secrets, volumes, VPC, ingress, labels, annotations, or service-account configuration
- IAM policy management, Service Usage enablement, billing, organization/folder APIs, project creation/deletion, quota management, audit log retrieval, or Cloud Asset Inventory
- Application Default Credentials discovery, OAuth consent, Workload Identity Federation, metadata-server tokens, or gcloud integration
- connector-local credential vaulting, durable resource cache, event subscriptions, or infrastructure reconciliation

These are excluded on purpose:

- The first slice keeps live-infrastructure mutations explicit and narrow.
- Google Cloud resources can carry production workloads, secrets, and cost impact.
- Broader GCP coverage needs service-specific operation polling, idempotency, IAM, and provider fixtures.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, runtime initialization, handshake state, request counters, and error counters
- auth mode, service-account mode, secretless credential-injection state, project ID status, and endpoint policy
- allowed production hosts, per-service endpoint readiness, operator guidance, manifest hash, verification script, and artifact root hint
- operation metadata, schemas, capability IDs, risk levels, safety tiers, idempotency, and approval modes
- degraded self-check for unconfigured and secretless states
- project-backed live self-check through Resource Manager when credentials are materialized
- bound capability-token verification during `invoke`
- current simulation behavior, which is permissive
- shutdown state reset

The deterministic integration evidence is anchored on connector-local tests covering:

- access-token, service-account, and secretless configuration
- service-account PEM validation and mocked JWT token exchange
- endpoint policy rejection for cross-wired service hosts, pathful URLs, and invalid schemes
- health, doctor, self-check, introspection, simulation, and shutdown surfaces
- bound capability-token verification for a destructive Storage operation
- Cloud Storage delete endpoint behavior
- connector-suite happy path for `gcp.projects.get`
- operation metadata, dangerous-operation approval metadata, and manifest hash exposure

## Source Notes

- `connectors/gcp/src/connector.rs` defines configuration parsing, endpoint policy, lifecycle handlers, capability-token verification, operation metadata, simulation, and invoke dispatch.
- `connectors/gcp/src/client.rs` defines Compute, Storage, Cloud Run, and Resource Manager request paths, auth header application, retry dispatch, token exchange, timeout, path validation, and provider error handling.
- `connectors/gcp/src/jwt.rs` defines service-account JWT assertion and OAuth token-exchange behavior.
- `connectors/gcp/src/types.rs` defines auth modes and provider response types.
- `connectors/gcp/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/gcp/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, and AI hints.
- `connectors/gcp/tests/integration.rs` covers deterministic HTTP behavior and runtime capability enforcement.
- `connectors/gcp/tests/connector_suite_happy_path.rs` covers a host-style connector suite happy path.
- `scripts/e2e/gcp_connector_verification.sh` wraps the tracked verification evidence.

## Verification Bundle

The tracked closeout surface is the GCP verification script plus direct crate proof commands.

The verification surface captures:

- runtime operation inventory and metadata
- deterministic WireMock coverage for project and Storage paths
- service-account token exchange and invalid credential evidence
- auth, endpoint policy, provider error, lifecycle, simulation, and introspection tests
- formatting, check, test, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a disposable Google Cloud project for live mutation checks.
- Use service-account or access-token material with the smallest useful IAM permissions.
- Prefer secretless credential injection when host policy should own credential material.
- Use WireMock loopback fixtures for routine proof.

**Dedicated environment**:

- Keep live VM names, bucket names, object names, Cloud Run service IDs, and container images synthetic.
- Do not delete production VMs, Storage objects, or Cloud Run services through routine verification.
- Do not use broad project-owner credentials when service-specific roles are enough.
- Verify that Cloud Run deploy creates new service resources only in a disposable region.

**Redaction rules**:

- Redact access tokens, service-account private keys, credential IDs where needed, project IDs when sensitive, VM names, bucket names, object names, Cloud Run service names, image names when private, provider payloads, provider error bodies, and endpoint URLs when they reveal account topology.
- Verification output should use operation IDs, endpoint shapes, auth mode, host class, result counts, status/error classes, retry decisions, and payload-shape summaries.

**Common remediation**:

- If configuration fails, provide `project_id`, a valid auth mode, and no cross-wired base URL overrides.
- If self-check is degraded with `credential_injection_required`, inject host credentials before running live probes.
- If service-account configuration fails, verify `client_email`, PKCS8 PEM formatting, and clock skew around JWT exchange.
- If endpoint policy fails, use the exact Google service host for the relevant override or a loopback verification URL.
- If path validation fails, pass single path segments for zones, instance names, buckets, locations, and service names.
- If Cloud Storage object operations fail for hierarchical names, check URL encoding and use a follow-up parity fix before live use.
- If Cloud Run deploy returns a long-running operation, verify completion through provider tooling because this connector does not poll operations.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-gcp-readme cargo check -p fcp-gcp --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-gcp-readme cargo test -p fcp-gcp --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-gcp-readme cargo clippy -p fcp-gcp --all-targets --no-deps -- -D warnings`
