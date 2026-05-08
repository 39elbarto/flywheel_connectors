# Terraform Connector V3 Contract

> **Status**: runtime contract documented; HCP Terraform API and safety drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **HCP Terraform API upstream**: https://developer.hashicorp.com/terraform/cloud-docs/api-docs
> **HCP Terraform runs API upstream**: https://developer.hashicorp.com/terraform/cloud-docs/api-docs/run
> **HCP Terraform plans API upstream**: https://developer.hashicorp.com/terraform/cloud-docs/api-docs/plans
> **HCP Terraform workspaces API upstream**: https://developer.hashicorp.com/terraform/cloud-docs/api-docs/workspaces
> **HCP Terraform API tokens upstream**: https://developer.hashicorp.com/terraform/cloud-docs/users-teams-organizations/api-tokens

## Purpose

This document fixes the operator-facing contract for `fcp.terraform`. The connector exposes the HCP Terraform/Terraform Enterprise API surface implemented in this crate: workspace lookup, run creation for plan and drift workflows, plan inspection, run apply, current-state reads, output reads, and private-registry/module-adjacent inventory.

The connector is intentionally a bounded HCP Terraform API bridge. It is not the Terraform CLI, a provider runner, a configuration upload pipeline, a VCS integration manager, a policy-set manager, a variable-set editor, a workspace lifecycle admin client, or a general Terraform Enterprise SDK wrapper.

## Current Runtime Snapshot

The current crate exposes these runtime operation IDs:

- `terraform.init`
- `terraform.validate`
- `terraform.plan`
- `terraform.show_plan`
- `terraform.apply`
- `terraform.destroy`
- `terraform.state_list`
- `terraform.state_show`
- `terraform.output`
- `terraform.import`
- `terraform.detect_drift`
- `terraform.list_modules`

Important runtime truths the contract preserves:

- Package, library, and binary name are `fcp-terraform`.
- Manifest ID is `fcp.terraform`.
- `BaseConnector` runtime ID is `terraform`.
- Handshake response connector ID is `fcp.terraform`.
- Manifest version is `0.1.0`.
- Manifest format is `native`.
- Manifest schema version is `2.1`.
- Configuration requires exactly one auth source:
  - `api_token`
  - `credential_id`
- Direct-token requests send `Authorization: Bearer <token>`.
- `credential_id` must be a valid UUID.
- `credential_id` requests send `X-FCP-Credential-Id: <uuid>` and require host egress credential injection to become real Terraform API calls.
- Default base URL is `https://app.terraform.io/api/v2`.
- Runtime base URL policy accepts `app.terraform.io`, other `*.terraform.io` hosts, and loopback hosts for tests.
- Runtime base URL policy requires `https` except for loopback test hosts.
- `organization` may be configured as a default and overridden per invocation.
- Runtime request timeout is 60 seconds at the reqwest client layer.
- Runtime request-context timeout is 60 seconds.
- The client stores a retry config, but the current low-level GET/POST helpers send direct requests and do not run a retry loop.
- `health()` reports configured/session-ID state, request counters, error counters, and local provisioning readiness. It does not call HCP Terraform.
- `doctor()` checks local configuration, client initialization, base URL policy, auth mode, credential-injection readiness, organization presence, and handshake session ID. It does not call HCP Terraform.
- `self_check()` reports local provisioning readiness only. It does not perform a live Terraform API probe.
- Runtime `invoke` uses the JSON field `operation_id`, not `operation`.
- Runtime `invoke` does not require or verify a capability token.
- Runtime `invoke` does not verify approval tokens.
- Runtime `simulate` only checks whether the `operation_id` is known.
- Runtime `simulate` does not check configuration, handshake, input shape, authorization, approval policy, provider permissions, or capability tokens.
- Runtime `shutdown()` shuts down the client runtime, clears config and client state, and clears base configured/handshaken flags.
- Runtime `shutdown()` does not clear the stored `session_id`.

## Runtime API Adapter

The runtime uses these request shapes under `{base_url}`:

| Operation | Runtime request | Required input | Output handling |
|-----------|-----------------|----------------|-----------------|
| `terraform.init` | `GET /organizations/{org}/workspaces/{workspace_name}` | `working_dir` | Uses the final path segment of `working_dir` as workspace name; returns initialized flag, workspace ID, and provider/version summary. |
| `terraform.validate` | `GET /organizations/{org}/workspaces/{workspace_name}` | `working_dir` | Treats presence of workspace data as valid and returns an empty diagnostics list. |
| `terraform.plan` | workspace lookup, then `POST /runs` | `working_dir` | Creates a run against the current workspace configuration; returns `plan_hash = blake3:{run_id}` and `plan_file = run_id`. |
| `terraform.show_plan` | `GET /runs/{plan_file}`, optionally `GET /plans/{plan_id}` or plan JSON redirect path | `plan_file` | Uses run relationship plan ID when present; otherwise returns run attributes as plan detail. |
| `terraform.apply` | `POST /runs/{run_id}/actions/apply` | `working_dir`, `plan_hash` | Strips `blake3:` from `plan_hash` and applies that run ID. |
| `terraform.destroy` | `POST /runs/{run_id}/actions/apply` | `working_dir`, `plan_hash` | Applies the referenced run ID with a destroy comment. |
| `terraform.state_list` | workspace lookup, `GET /workspaces/{id}/current-state-version`, then `GET /state-versions/{id}/resources` | `working_dir` | Returns resource addresses, optionally prefix-filtered by `filter`. |
| `terraform.state_show` | same state-resource path as `state_list` | `working_dir`, `address` | Finds one resource by exact `attributes.address` and returns its attributes. |
| `terraform.output` | workspace lookup, current state version, then `GET /state-versions/{id}/outputs` | `working_dir` | Returns outputs by name and replaces sensitive values with `<sensitive>`. |
| `terraform.import` | workspace lookup, then `POST /runs` with `plan-only: true` | `working_dir`, `address`, `id` | Creates a placeholder plan-only run and returns imported receipt fields. |
| `terraform.detect_drift` | workspace lookup, then `POST /runs` with `refresh-only: true`, `plan-only: true` | `working_dir` | Reports `drifted` from immediate run `has-changes`, with an empty drift summary. |
| `terraform.list_modules` | workspace lookup, then `GET /workspaces/{id}/configuration-versions` | `working_dir` | Maps configuration-version `source` and ID fields into module entries. |

Input and request handling:

- Most operations resolve the workspace from the last slash-delimited segment of `working_dir`.
- `effective_org()` uses per-invocation `organization` first and configured `organization` second.
- `terraform.plan` forwards optional `destroy`, `refresh_only`, and string-array `targets` as run attributes.
- `terraform.plan` sets `plan-only` to the value of `refresh_only`, so normal plan calls create non-plan-only runs in the current runtime.
- `terraform.show_plan` uses runtime field `plan_file`; the manifest uses `plan_id`.
- `terraform.apply` and `terraform.destroy` use runtime field `plan_hash`; the manifest uses `run_id` or `workspace_id`.
- `terraform.state_show` uses runtime field `address`; the manifest uses `resource_address`.
- `terraform.import` uses runtime fields `address` and `id`; the manifest uses `resource_address` and `resource_id`.
- `terraform.list_modules` uses runtime field `working_dir`; the manifest says `organization`.
- Empty Terraform API success bodies become `{}` at the client layer.
- Terraform JSON API error bodies are truncated to 2048 bytes before local error mapping.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- HCP Terraform documents the stable API under the `/v2` prefix and JSON API request/response documents. Runtime default base URL correctly includes `/api/v2`.
- HCP Terraform documents API authentication as `Authorization: Bearer <token>`. Runtime direct-token mode matches that transport.
- HCP Terraform documents that organization tokens cannot perform plans and applies. Runtime accepts any bearer token string and does not preflight token type or permissions.
- HCP Terraform's API-driven run workflow involves configuration versions and uploaded configuration content. Runtime creates runs against the workspace's current configuration version and does not upload configuration files.
- HCP Terraform runs can proceed through plan and apply behavior depending on workspace configuration and run state. Runtime `terraform.plan` is marked safe in metadata, but its default request body sets `plan-only` to `false`, so a follow-up must make the read-only contract mechanically true.
- HCP Terraform plan API states that a plan ID is discovered through a run object's `relationships.plan`. Runtime returns a fabricated `plan_hash` of `blake3:{run_id}` and uses the run ID as `plan_file`.
- Runtime `blake3:{run_id}` is not a cryptographic hash of plan JSON or Terraform plan content.
- Manifest schemas are materially out of sync with runtime inputs for most operations, especially `working_dir`, `plan_file`, `plan_hash`, `address`, and `id`.
- Manifest marks `terraform.apply` and `terraform.destroy` as interactive-approval dangerous operations. Runtime dispatch does not enforce approval tokens.
- Runtime introspection reports no `requires_approval` metadata for any operation.
- Runtime `invoke` does not require capability tokens and does not install a `CapabilityVerifier` during handshake.
- Runtime `simulate` is only a known-operation check.
- The crate contains richer `plan`, `apply`, `import`, and `safety` modules with plan parsing, approval-token, destroy-denial, and policy-enforcement concepts. The main `TerraformConnector::handle_invoke` path does not call those modules.
- `terraform.destroy` is not forbidden by runtime policy; it applies a caller-supplied run ID with a destroy comment.
- `terraform.import` does not perform Terraform import semantics directly. It creates a plan-only run with an import message.
- `terraform.list_modules` reads configuration versions, not the full HCP Terraform private registry modules API.
- `credential_id` mode is accepted and sends `X-FCP-Credential-Id`, but self-check is degraded until host egress injection exists.
- Runtime base URL policy allows any host ending in `.terraform.io`, including custom Terraform Enterprise style hosts in tests and deployments, but manifest network constraints document `app.terraform.io` and `*.terraform.io` without the runtime's local-test exception.
- Manifest rate-limit pools exist for plan, apply, state, and state-write operations. Runtime introspection reports no rate-limit metadata and the client does not enforce those pools.
- Manifest state model says plan artifact hashes and drift checkpoints are stored. The live connector does not persist those artifacts through the main dispatch path.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should reconcile manifest schemas with runtime inputs, route live dispatch through the existing safety/approval modules, add capability-token verification, make plan IDs and plan hashes reflect provider reality, implement the full configuration-version upload workflow or document existing-current-config semantics, add live read-only self-checks, enforce rate-limit metadata, and decide whether `terraform.import` should become a real import workflow or remain explicitly planned-only.

## First-Slice Scope

The current Terraform README slice documents the existing runtime surface:

- API-token and credential-ID configuration
- base URL, organization, provisioning readiness, doctor, health, and self-check behavior
- HCP Terraform run, plan, workspace, current state version, state resources, outputs, and configuration-version request paths
- init, validate, plan, show-plan, apply, destroy, state, output, import, drift, and module-listing operations
- runtime/manifest/provider-doc drift around input schemas, configuration upload workflow, plan hashes, safety/approval modules, capability tokens, rate limits, and state persistence
- deterministic WireMock integration tests

## Auth And Zone Boundary

- Authentication mechanisms: direct HCP Terraform API token or host credential reference.
- Home zone: `z:infra`.
- Allowed source zones: `z:owner` and `z:infra`.
- Allowed target zone: `z:infra`.
- Forbidden zones: `z:public`, `z:community`, and `z:work`.
- Runtime capability families:
  - `terraform.plan`
  - `terraform.apply`
  - `terraform.state`
  - `terraform.state_write`
- Manifest required capabilities are `network.dns`, `network.egress`, `network.tls.sni`, and `storage.state`.
- Manifest forbids `system.exec`, `network.listen`, `media.download`, and `media.upload`.
- The live connector does not intentionally persist API tokens, credential IDs beyond configuration metadata, Terraform state payloads, plan details, request counters, or error counters outside process memory.
- Terraform payloads can contain workspace names, state resource addresses, cloud resource identifiers, output values, plan/run IDs, and infrastructure topology. Treat live output as infra-zone sensitive data unless the host supplies a stricter zone policy.

## Network And Runtime Invariants

- Default runtime base URL: `https://app.terraform.io/api/v2`.
- Direct token requests use `Authorization: Bearer <token>`.
- `credential_id` requests use `X-FCP-Credential-Id: <uuid>`.
- Runtime base URL policy accepts `https://app.terraform.io`, other `https://*.terraform.io` hosts, and loopback hosts for tests.
- Runtime base URL policy rejects non-local `http` and unknown hosts.
- Runtime client timeout is 60 seconds.
- Runtime request-context timeout is 60 seconds.
- Manifest operation network policy allows `app.terraform.io` and `*.terraform.io` on port `443` and requires TLS/SNI.
- Sandbox profile is `strict`, with `512 MB` memory, `75%` CPU, `1800000 ms` wall-clock timeout, no exec, no ptrace, read-only `/usr` and `/lib`, and writable `$CONNECTOR_STATE`.
- The connector does not open inbound sockets.
- Provider 401 maps to unauthorized.
- Provider 403 maps to forbidden.
- Provider 404 maps to not found.
- Provider 409 maps to conflict.
- Provider 429 maps to rate limited and honors `Retry-After` seconds, defaulting to 30 seconds when absent.
- Other non-success provider responses become Terraform API errors.
- JSON parse errors become Terraform parse errors and then FCP internal/external errors through connector mapping.

## Capability Families

| Capability | Purpose |
|------------|---------|
| `terraform.plan` | Read or queue plan-like HCP Terraform workflows. |
| `terraform.apply` | Apply already-created HCP Terraform runs. |
| `terraform.state` | Read current state resources and outputs. |
| `terraform.state_write` | Queue import-adjacent state-write workflows. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `terraform.init` | `GET /organizations/{org}/workspaces/{name}` | `terraform.plan` | `Safe` | `Low` | `Strict` | Checks existing workspace metadata. |
| `terraform.validate` | `GET /organizations/{org}/workspaces/{name}` | `terraform.plan` | `Safe` | `Low` | `Strict` | Treats workspace presence as validation success. |
| `terraform.plan` | `POST /runs` | `terraform.plan` | `Safe` | `Low` | `Strict` | Queues a run against current workspace configuration; current body is not plan-only by default. |
| `terraform.show_plan` | `GET /runs/{id}` and optional plan endpoints | `terraform.plan` | `Safe` | `Low` | `Strict` | Reads run or plan detail. |
| `terraform.apply` | `POST /runs/{id}/actions/apply` | `terraform.apply` | `Dangerous` | `High` | `BestEffort` | Applies real infrastructure changes for a referenced run. |
| `terraform.destroy` | `POST /runs/{id}/actions/apply` | `terraform.apply` | `Dangerous` | `High` | `BestEffort` | Applies a referenced run intended to destroy resources. |
| `terraform.state_list` | current state version resources | `terraform.state` | `Safe` | `Low` | `Strict` | Reads current state resource addresses. |
| `terraform.state_show` | current state version resources | `terraform.state` | `Safe` | `Low` | `Strict` | Reads one current state resource. |
| `terraform.output` | current state version outputs | `terraform.state` | `Safe` | `Low` | `Strict` | Reads output values and redacts sensitive values. |
| `terraform.import` | `POST /runs` with `plan-only` | `terraform.state_write` | `Risky` | `Medium` | `Strict` | Queues an import-adjacent plan-only run receipt. |
| `terraform.detect_drift` | `POST /runs` with `refresh-only` and `plan-only` | `terraform.plan` | `Safe` | `Low` | `Strict` | Queues refresh-only drift detection against current config. |
| `terraform.list_modules` | `GET /workspaces/{id}/configuration-versions` | `terraform.plan` | `Safe` | `Low` | `Strict` | Reads configuration-version source metadata as module-like inventory. |

## Resource URIs

Runtime invoke currently does not verify capability tokens, so no resource binding is enforced locally. The effective authorization boundary is host-side admission plus operation dispatch.

Follow-up work should add resource URI shapes such as:

| Operation family | Candidate resource URI shape |
|------------------|------------------------------|
| Organization | `terraform:organization:{organization}` |
| Workspace | `terraform:organization:{organization}:workspace:{workspace}` |
| Run | `terraform:run:{run_id}` |
| Plan | `terraform:plan:{plan_id}` |
| State version | `terraform:state-version:{state_version_id}` |
| Resource address | `terraform:workspace:{workspace}:resource:{address}` |
| Output | `terraform:workspace:{workspace}:output:{name}` |

## Explicit Non-Goals

The current implementation does not include:

- Local Terraform CLI execution
- Provider plugin installation
- Configuration upload or archive creation
- VCS repository integration
- Workspace creation, deletion, lock, unlock, or variable management
- Sentinel, OPA, policy-set, cost-estimation, or run-task management
- Full private registry module APIs
- Run polling to terminal status
- Plan log streaming
- Real plan content hashing
- State download through hosted blob URLs
- Direct state mutation
- Capability-token verification
- Approval-token enforcement in the live `invoke` path

## Verification

README-only changes do not require Cargo or `rch` compilation. For this connector contract, use:

```bash
git diff --check -- connectors/terraform/README.md
LC_ALL=C rg -n '[^ -~]' connectors/terraform/README.md
rg -n '\bmaster\b' connectors/terraform/README.md
ubs connectors/terraform/README.md
```
