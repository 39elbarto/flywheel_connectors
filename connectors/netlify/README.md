# Netlify Connector V3 Contract

> **Status**: runtime contract documented; manifest/introspection/API drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Netlify API guide upstream**: https://docs.netlify.com/api-and-cli-guides/api-guides/get-started-with-api/
> **Netlify OpenAPI upstream**: https://open-api.netlify.com/
> **Netlify environment variables upstream**: https://docs.netlify.com/environment-variables/get-started/
> **Netlify deploys upstream**: https://docs.netlify.com/site-deploys/overview/

## Purpose

This document fixes the operator-facing contract for `fcp.netlify`. The connector exposes the Netlify REST API surface currently implemented in this crate: site listing and details, site creation and deletion, deploy listing and details, deploy creation and rollback, DNS zone listing, environment variable listing, environment variable set/delete, and a live API-token health probe.

The connector is intentionally a bounded Netlify operations bridge. It is not a Netlify CLI replacement, OAuth app, site deploy file uploader, repository connection manager, form-submission client, domain-purchase flow, functions runtime, analytics exporter, build-log streamer, or durable deploy monitor.

## Current Runtime Snapshot

The current crate exposes these runtime operation IDs:

- `netlify.sites.list`
- `netlify.sites.get`
- `netlify.sites.create`
- `netlify.sites.delete`
- `netlify.deploys.list`
- `netlify.deploys.get`
- `netlify.deploys.create`
- `netlify.deploys.rollback`
- `netlify.dns.list_zones`
- `netlify.env.list`
- `netlify.env.set`
- `netlify.env.delete`
- `netlify.health`

Important runtime truths the contract preserves:

- Package, library, and binary name are `fcp-netlify`.
- Manifest ID is `fcp.netlify`.
- `BaseConnector` runtime ID is `fcp.netlify`.
- Manifest version is `0.1.0`.
- Manifest format is `wasi`.
- Configuration accepts:
  - `access_token`
  - `base_url`
  - `retry`
  - `request_timeout_ms`
  - `account_slug`
- `access_token` is the only implemented auth material. Empty or whitespace-only `access_token` is treated as secretless and sends no provider auth header.
- There is no `credential_id` config key in the current Netlify connector.
- Direct token mode sends `Authorization: Bearer <access_token>`.
- Default runtime base URL is `https://api.netlify.com`.
- Runtime client paths add `/api/v1/...` under the configured base URL.
- Default HTTP client timeout is 30 seconds.
- Runtime request-context timeout defaults to 30000 ms and is configurable with `request_timeout_ms`.
- Runtime HTTP calls use the configured `HttpRetryConfig` through `RetryLoop`.
- `health()` reports local readiness, uptime, manifest hash, base URL, and provisioning readiness. It does not call Netlify.
- `doctor()` checks local configuration, client initialization, runtime initialization, network constraints, and whether secret material is present. It does not call Netlify.
- `self_check()` calls `GET /api/v1/user` when local network policy and token material allow live validation.
- `self_check()` reports degraded when not configured or when token material is omitted.
- `self_check()` reports failed if the base URL violates local network policy or if client/runtime state is missing.
- Runtime `handshake()` parses a full `HandshakeRequest`, installs a `CapabilityVerifier`, hashes the checked-in manifest, and reports non-streaming event caps.
- Runtime `handshake()` grants every requested capability unfiltered.
- Runtime `invoke()` uses the FCP `InvokeRequest` shape: `operation`, `input`, and `capability_token`.
- Runtime `invoke()` requires configured and handshaken base state and verifies a bound capability token for the operation capability.
- Runtime capability verification currently passes an empty resource URI list for all Netlify operations.
- Runtime `simulate()` always returns allowed and does not validate operation, input, configuration, handshake, network policy, or capability token.
- Runtime `shutdown()` shuts down the connector runtime, clears runtime/client/config/verifier state, and clears configured/handshaken flags.
- Runtime `subscribe()` is unsupported.

## Runtime API Adapter

The runtime uses these request shapes under `{base_url}/api/v1`:

| Operation | Capability | Required input | Runtime request |
|-----------|------------|----------------|-----------------|
| `netlify.sites.list` | `netlify.sites.read` | none | `GET /sites` |
| `netlify.sites.get` | `netlify.sites.read` | `site_id` | `GET /sites/{site_id}` |
| `netlify.sites.create` | `netlify.sites.write` | `name` | `POST /sites` with optional `custom_domain` |
| `netlify.sites.delete` | `netlify.sites.write` | `site_id` | `DELETE /sites/{site_id}` |
| `netlify.deploys.list` | `netlify.deploys.read` | `site_id` | `GET /sites/{site_id}/deploys` |
| `netlify.deploys.get` | `netlify.deploys.read` | `site_id`, `deploy_id` | `GET /sites/{site_id}/deploys/{deploy_id}` |
| `netlify.deploys.create` | `netlify.deploys.write` | `site_id` | `POST /sites/{site_id}/deploys` with optional `branch` and `title` |
| `netlify.deploys.rollback` | `netlify.deploys.write` | `site_id`, `deploy_id` | `POST /sites/{site_id}/deploys/{deploy_id}/restore` |
| `netlify.dns.list_zones` | `netlify.dns.read` | none | `GET /dns_zones` |
| `netlify.env.list` | `netlify.env.read` | `site_id`, `account_slug` | `GET /accounts/{account_slug}/env?site_id={site_id}` |
| `netlify.env.set` | `netlify.env.write` | `site_id`, `account_slug`, `key`, `value` | `POST /accounts/{account_slug}/env?site_id={site_id}` with one env-var object |
| `netlify.env.delete` | `netlify.env.write` | `site_id`, `account_slug`, `key` | `DELETE /accounts/{account_slug}/env/{key}?site_id={site_id}` |
| `netlify.health` | `netlify.sites.read` | none | `GET /user` |

Path and query handling:

- Path segments are rejected when empty, whitespace-only, containing `/`, containing `\`, or containing encoded slash/backslash markers such as `%2f` or `%5C`.
- Environment `site_id` is encoded as a query parameter and rejects control characters.
- List responses must deserialize to provider arrays.
- Object responses must deserialize to provider objects.
- HTTP 429 maps to an FCP rate-limit error and honors `Retry-After` when present.
- HTTP 401 and 403 map to terminal unauthorized errors.
- HTTP 5xx responses are retryable through the retry loop.
- Other non-success provider responses are terminal API errors.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Netlify documents API paths under `https://api.netlify.com/api/v1`. Runtime defaults the base to `https://api.netlify.com` and appends `/api/v1` in each client helper.
- The manifest operation table keys are snake-case names such as `sites_list` and `deploys_create`; runtime operation IDs are dotted names such as `netlify.sites.list` and `netlify.deploys.create`.
- Manifest required capabilities use `network.dns` and `network.outbound`; current root guidance generally uses `network.egress` and `network.tls.sni` for provider connectors.
- Configuration accepts `account_slug`, but runtime env operations still require `account_slug` in each invoke input.
- Configuration validation only rejects an empty `base_url`. The stricter base URL policy is surfaced through provisioning readiness, health, doctor, and self-check; `invoke()` itself does not re-check that policy before building requests.
- Local base URL policy accepts `api.netlify.com` over HTTPS and localhost-style test hosts. Manifest network constraints deny localhost and private ranges because production operation is expected to target Netlify.
- Empty `access_token` is treated as secretless, but there is no host credential-injection path implemented. Provider calls then run without an Authorization header.
- Runtime `simulate()` is an allow-all stub.
- Runtime capability verification does not bind site IDs, deploy IDs, account slugs, env keys, or DNS zones as resource URIs.
- Runtime `handshake()` grants every requested capability unfiltered.
- `netlify.sites.delete` and `netlify.env.delete` declare interactive approval metadata. `netlify.deploys.rollback`, `netlify.deploys.create`, and `netlify.env.set` can affect live sites but currently have no approval requirement.
- `netlify.deploys.create` posts deploy metadata only. It does not upload a ZIP archive or file digest set.
- `netlify.env.set` writes exactly one variable object per invocation and leaves scopes unset.
- `health()` is a live provider operation while `self_check()` is also a live provider probe. The local lifecycle `health()` method is not live.
- No dedicated tracked verification shell script exists for this connector.

A follow-up parity bead should enforce base URL policy before invoke, add a real credential-ID or egress-injection path if secretless mode is desired, make `simulate()` validate operation/input/capability state, bind capability tokens to Netlify resource URIs, reconcile manifest capability names with root connector conventions, add approval metadata for live-site deploy and env mutations, and either implement or explicitly reject deploy file upload flows.

## First-Slice Scope

The current Netlify README slice documents the existing runtime surface:

- Access-token configuration and current secretless behavior
- Sites, deploys, DNS zones, env vars, and API-token health operations
- Local health, doctor, live self-check, introspection, simulate, invoke, and shutdown behavior
- Capability-token verification and current empty resource-URI binding
- Provider error mapping, path/query sanitization, retry behavior, and timeout behavior
- Runtime/manifest/provider-doc drift around operation IDs, network capabilities, approval metadata, base URL policy, secretless auth, env scopes, deploy uploads, and simulation
- Existing integration-test orientation through manifest schema checks, operation introspection checks, and WireMock-backed provider flows

## Auth And Zone Boundary

- Authentication mechanism: direct Netlify personal access token.
- Home zone: `z:work`.
- Allowed source zones: `z:work` and `z:private`.
- Allowed target zone: `z:work`.
- Runtime capability families:
  - `netlify.sites.read`
  - `netlify.sites.write`
  - `netlify.deploys.read`
  - `netlify.deploys.write`
  - `netlify.dns.read`
  - `netlify.env.read`
  - `netlify.env.write`
- Manifest required capabilities are `network.dns` and `network.outbound`.
- Manifest forbids `system.exec` and `system.privileged`.
- The connector does not intentionally persist Netlify tokens, site payloads, deploy payloads, DNS zones, env values, request counters, or error counters outside process memory.
- Netlify payloads can contain site names, custom domains, deploy metadata, DNS zones, environment variable keys and values, account slugs, user IDs, and user email addresses. Treat live output as work-zone sensitive unless the host supplies a stricter zone policy.

## Explicit Non-Goals

- No OAuth app flow.
- No Netlify CLI shellout.
- No ZIP or file deploy upload.
- No deploy log streaming.
- No form-submission API.
- No domain purchase or verification automation.
- No functions runtime management.
- No durable deploy monitor.
- No environment variable secret escrow.
- No cross-zone site administration.

## Verification

README-only changes do not require Cargo or `rch` verification. Before committing this file, run:

```bash
git diff --check -- connectors/netlify/README.md
LC_ALL=C rg -n '[^ -~]' connectors/netlify/README.md
rg -n '\bmaster\b' connectors/netlify/README.md
ubs connectors/netlify/README.md
```

For code changes in this connector, use the workspace-required proof lane from the root `AGENTS.md`:

```bash
rch exec -- cargo check --workspace --all-targets
rch exec -- cargo clippy --workspace --all-targets -- -D warnings
rch exec -- cargo fmt --check
```
