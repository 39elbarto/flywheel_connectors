# Mailchimp Connector V3 Contract

> **Status**: runtime contract documented; manifest/runtime drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Mailchimp Marketing API upstream**: https://mailchimp.com/developer/marketing/docs/fundamentals/
> **Campaigns upstream**: https://mailchimp.com/developer/marketing/api/campaigns/list-campaigns/

## Purpose

This document fixes the operator-facing contract for `fcp.mailchimp`. The connector exposes the Mailchimp Marketing API surface implemented in this crate: audiences, audience members, and campaigns.

The connector is intentionally a bounded marketing-operations bridge. It is not a full Mailchimp administration client, template manager, reports client, transactional email client, journey automation client, webhook listener, ecommerce store client, OAuth installer, or campaign authoring workflow.

## Current Runtime Snapshot

The current crate exposes these operations:

- `mailchimp.lists.list`
- `mailchimp.members.list`
- `mailchimp.members.delete`
- `mailchimp.campaigns.list`
- `mailchimp.campaigns.send`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-mailchimp`.
- Runtime `BaseConnector` ID is `mailchimp`.
- Manifest and reported connector ID are `fcp.mailchimp`.
- Manifest interface hash is `blake3-256:fcp.interface.v2:d01b5c19607f90aee1f48af0b0324f799b1cae4be8c94d244febb1f71a5cd338`.
- Configuration requires exactly one auth source: direct `api_key` or `credential_id`.
- Direct API-key mode sends HTTP Basic auth as `anyuser:{api_key}`.
- `credential_id` mode sends `X-FCP-Credential-Id` and expects host egress policy to inject real secret material.
- With no `base_url`, direct API-key mode derives `https://{dc}.api.mailchimp.com/3.0` from the final dash-delimited API-key suffix.
- If the API key has no dash, the whole key becomes the derived data-center string; the runtime does not validate Mailchimp key shape.
- With no `base_url`, `credential_id` mode defaults to `https://us1.api.mailchimp.com/3.0`.
- Custom `base_url` values reject userinfo, query strings, fragments, and parse failures at configure time.
- Custom `base_url` host policy is checked by `self_check`, not by `configure`.
- Runtime host policy accepts `*.api.mailchimp.com` over HTTPS plus loopback hosts for tests.
- Runtime request timeout is 30 seconds.
- The client uses the shared retry loop with `max_retries = 3`.
- Runtime `invoke` uses `operation_id`, not `operation`.
- Runtime does not install a `CapabilityVerifier` and does not verify `capability_token`.
- Runtime does not verify approval tokens even for member deletion or campaign sending.
- `simulate` only checks whether `operation_id` is present in the local operation inventory.
- `health()` and `doctor()` consider a handshake complete only when a `session_id` was provided, while `invoke` readiness follows the base handshaken flag.
- `handle_configure()` invalidates the prior Mailchimp handshake.
- `handle_shutdown()` shuts down the client runtime, clears config/client/base flags, and returns an empty object.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- Manifest marks `mailchimp.campaigns.send` as `safety_tier = "risky"`, `requires_approval = "policy"`, and `idempotency = "strict"`; runtime introspection marks it `Dangerous`, `requires_approval = None`, and `idempotency = None`.
- Manifest marks `mailchimp.members.delete` as interactive approval, but runtime introspection reports no approval requirement and runtime checks no approval token.
- Runtime does not verify capability tokens or bind operations to resource URIs.
- Manifest optional capability `mailchimp.members.write` is returned by handshake, but no current runtime operation uses it.
- Manifest state hint says API key and data-center prefix are stored; runtime keeps configuration in memory and does not persist connector state.
- Configure rejects URL userinfo, query, and fragment, but does not hard-stop unknown HTTPS hosts. Unknown hosts surface through `self_check` readiness.
- API-key data-center derivation accepts any non-empty suffix after the final dash and accepts a no-dash key as a data-center string.
- Runtime introspection has no event catalog, resource types, auth capabilities, or event capabilities.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should align approval and idempotency metadata, implement capability-token and approval-token verification, remove unused `mailchimp.members.write` from handshake or add a real write operation, tighten API-key data-center validation, make provider host policy a configure-time hard stop where appropriate, and add a tracked verification bundle.

## First-Slice Scope

The current Mailchimp README slice documents the existing runtime surface:

- direct API-key and host credential-reference configuration
- data-center-derived base URL behavior
- provider host policy, timeout, retry, and provider error mapping
- audience, member, and campaign operations
- simplified handshake and local readiness behavior
- deterministic WireMock tests and direct proof commands

## Auth And Scope Boundary

- Authentication mechanisms: Mailchimp API key or host credential reference.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Runtime capability surface:
  - `mailchimp.lists.read` gates audience listing.
  - `mailchimp.members.read` gates audience member listing.
  - `mailchimp.members.delete` gates member deletion metadata, but runtime does not enforce capability tokens.
  - `mailchimp.campaigns.read` gates campaign listing.
  - `mailchimp.campaigns.write` gates campaign sending metadata, but runtime does not enforce capability tokens.
- Manifest optional capability `mailchimp.members.write` is not mapped to an operation in this runtime slice.
- The connector does not persist API keys, credential secret material, audience data, member data, campaign data, or provider error bodies outside process memory.
- Mailchimp payloads can include subscriber identities, email addresses, campaign state, audience names, and marketing topology. Treat live output as work-zone operational data.

## Network And Runtime Invariants

- Default Mailchimp API host shape: `{dc}.api.mailchimp.com`.
- Default API path prefix: `/3.0`.
- Production port: `443`.
- TLS and SNI are required by the manifest for provider operations.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live provider operations.
- Runtime readiness policy accepts `*.api.mailchimp.com` HTTPS endpoints and loopback hosts.
- Runtime readiness policy rejects non-loopback HTTP and unknown hosts.
- Configure-time URL hygiene rejects userinfo, query strings, fragments, and unparseable URLs.
- Runtime request timeout: `30 seconds`.
- Runtime retry policy: three attempts using the shared retry loop.
- Provider 401, 403, 404, 429, and other API errors map to typed connector/FCP errors.
- `Retry-After` on 429 is converted to milliseconds; missing values default to 60000 ms.
- Manifest connect timeout is `10000 ms`, total timeout is `30000 ms`, and maximum response bytes are `1048576` or `10485760` by operation.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, no exec, and no inbound listener capability.
- The connector does not open inbound sockets or subscribe to Mailchimp webhooks.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `mailchimp.lists.read` | List Mailchimp audiences. |
| `mailchimp.members.read` | List members in one audience. |
| `mailchimp.members.delete` | Delete one audience member by subscriber hash. |
| `mailchimp.campaigns.read` | List campaigns. |
| `mailchimp.campaigns.write` | Send an existing campaign. |
| `mailchimp.members.write` | Returned by handshake but unused by the current operation inventory. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `mailchimp.lists.list` | `GET /lists` | `mailchimp.lists.read` | `Safe` | `Low` | `Strict` | Lists audiences and returns `lists`, defaulting missing lists to an empty array. |
| `mailchimp.members.list` | `GET /lists/{list_id}/members` | `mailchimp.members.read` | `Safe` | `Low` | `Strict` | Lists members for one audience and returns `members`, defaulting missing members to an empty array. |
| `mailchimp.members.delete` | `DELETE /lists/{list_id}/members/{subscriber_hash}` | `mailchimp.members.delete` | `Dangerous` | `High` | `Strict` | Deletes one member by MD5 hash of lowercase email address. |
| `mailchimp.campaigns.list` | `GET /campaigns` | `mailchimp.campaigns.read` | `Safe` | `Low` | `Strict` | Lists campaigns and returns `campaigns`, defaulting missing campaigns to an empty array. |
| `mailchimp.campaigns.send` | `POST /campaigns/{campaign_id}/actions/send` | `mailchimp.campaigns.write` | `Dangerous` | `High` | `None` | Sends an existing campaign to its configured recipients. |

## Resource URIs

Runtime capability-token verification is absent for Mailchimp in this checkout, so there are no effective resource URI bindings. The practical authorization binding is configuration plus base readiness plus operation name.

Follow-up work should add resource URI shapes such as:

| Operation family | Candidate resource URI shape |
|------------------|------------------------------|
| Audiences | `mailchimp://{dc}/lists/{list_id}` |
| Members | `mailchimp://{dc}/lists/{list_id}/members/{subscriber_hash}` |
| Campaigns | `mailchimp://{dc}/campaigns/{campaign_id}` |

## Explicit Non-Goals

The current implementation does not include:

- audience create/update/delete, batch member upsert, tags, segments, interests, merge fields, or member search
- campaign create/update/content/schedule/cancel, template management, reports, or send checklist reads
- transactional email, Customer Journeys, automations, ecommerce stores, landing pages, surveys, files, or account administration
- OAuth installation flow, API-key rotation, webhooks, webhook signature verification, or durable event replay
- durable storage of campaign, audience, or member data

These are excluded on purpose:

- Campaign sending and member deletion are high-risk marketing operations and need explicit approval/runtime verification before broader mutation is safe.
- Webhook signature verification belongs at the host ingress boundary before connector invocation.
- Audience and campaign authoring need narrower schemas than the current pass-through JSON shapes.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- local configuration, client, handshake, request, and error counter state
- provider URL readiness and credential-injection warning state
- degraded self-check for unconfigured and `credential_id` modes
- direct API-key self-check based on local readiness only, not a live Mailchimp API probe
- operation metadata with capability, risk, safety tier, idempotency, schemas, and hints
- simulation allow/deny for known versus unknown operation IDs
- typed provider/FCP error mapping

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle, configuration, reconfigure handshake invalidation, introspection, simulation, doctor, self-check, shutdown, and counters
- audience listing, member listing/deletion, campaign listing/sending through deterministic HTTP fixtures
- invoke rejection for unknown operation and missing required inputs
- provider 401, 403, 404, 429, and 500 classes
- auth redaction, data-center URL derivation, custom URL hygiene, provisioning readiness, and base URL policy

## Source Notes

- `connectors/mailchimp/src/connector.rs` defines configuration parsing, URL hygiene, URL readiness policy, lifecycle handlers, introspection, simulation, and invoke dispatch.
- `connectors/mailchimp/src/client.rs` defines Mailchimp Marketing API paths, auth headers, retry dispatch, timeout, data-center URL derivation, and provider error mapping.
- `connectors/mailchimp/src/types.rs` defines campaign, audience, and API error shapes.
- `connectors/mailchimp/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/mailchimp/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, and rate-limit intent.
- `connectors/mailchimp/tests/integration.rs` contains the runtime contract proof surface.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/mailchimp/README.md
ubs connectors/mailchimp/README.md
LC_ALL=C rg -n '[^ -~]' connectors/mailchimp/README.md
rg -n '\bmaster\b' connectors/mailchimp/README.md
```

For source or behavior changes, also run the connector proof lane through `rch`:

```bash
rch exec -- cargo test -p fcp-mailchimp
rch exec -- cargo check -p fcp-mailchimp --all-targets
rch exec -- cargo clippy -p fcp-mailchimp --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

## Operator Guidance

- Prefer `credential_id` for production so host policy owns secret injection.
- Use direct `api_key` only in local deterministic tests or explicitly scoped environments.
- Verify the Mailchimp data-center suffix before relying on automatic URL derivation.
- Treat `mailchimp.members.delete` and `mailchimp.campaigns.send` as high-review operations even though runtime approval checks are absent.
- Do not rely on capability-token or approval-token enforcement until runtime verification is implemented.
- Do not interpret this connector as a campaign authoring or webhook ingestion surface.
