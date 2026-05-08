# SendGrid Connector V3 Contract

> **Status**: runtime contract documented; manifest/runtime drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **SendGrid v3 API reference**: https://www.twilio.com/docs/sendgrid/api-reference
> **Mail Send API**: https://www.twilio.com/docs/sendgrid/api-reference/mail-send/mail-send
> **Contacts API**: https://www.twilio.com/docs/sendgrid/api-reference/contacts/search-contacts
> **Lists API**: https://www.twilio.com/docs/sendgrid/api-reference/lists/create-list
> **Stats API**: https://www.twilio.com/docs/sendgrid/api-reference/stats/retrieve-global-email-statistics

## Purpose

This document fixes the operator-facing contract for `fcp.sendgrid`. The connector currently targets the Twilio SendGrid v3 REST API surface implemented in this crate: transactional mail send, marketing contact reads/searches, marketing list reads/creates/deletes, dynamic template reads, and global email statistics.

The connector is intentionally a bounded SendGrid v3 bridge. It is not a complete SendGrid administration client, SMTP client, inbound parse webhook receiver, Event Webhook consumer, suppression manager, sender-authentication setup tool, subuser manager, dedicated IP manager, campaign builder, or general SendGrid API proxy.

## Current Runtime Snapshot

The current crate exposes these operations:

- `sendgrid.mail.send`
- `sendgrid.contacts.list`
- `sendgrid.contacts.search`
- `sendgrid.contacts.get`
- `sendgrid.lists.list`
- `sendgrid.lists.create`
- `sendgrid.lists.delete`
- `sendgrid.templates.list`
- `sendgrid.templates.get`
- `sendgrid.stats.get`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-sendgrid`.
- Runtime `BaseConnector` ID is `sendgrid`.
- Manifest and reported connector ID are `fcp.sendgrid`.
- Manifest interface hash is `blake3-256:fcp.interface.v2:a70876e5fbdeb908a5567993f3085faf382c2282c9bd167ff54a3d026af3a650`.
- Configuration requires exactly one auth source: direct `api_key` or `credential_id`.
- Direct API-key mode sends `Authorization: Bearer {api_key}`.
- `credential_id` mode sends `X-FCP-Credential-Id` and expects host egress policy to inject real secret material.
- `credential_id` must be a valid UUID.
- Default base URL is `https://api.sendgrid.com/v3`.
- Direct API-key mode only accepts `api.sendgrid.com` for non-local custom `base_url` values.
- Credential-ID mode accepts custom HTTP/HTTPS hosts after URL hygiene checks.
- Non-local HTTP is rejected; local HTTP is allowed for `localhost`, `127.0.0.1`, and `::1` tests.
- Custom `base_url` must not include userinfo, query string, or fragment.
- The client trims trailing slashes from `base_url`.
- Runtime request timeout is 30 seconds.
- The client uses the shared retry loop with `max_retries = 2`.
- Runtime `invoke` uses `operation_id`, not `operation`.
- Runtime does not install a `CapabilityVerifier` and does not verify `capability_token`.
- Runtime does not verify approval tokens for mail send, list create, or list delete operations.
- `simulate` only checks whether `operation_id` is present in the local operation inventory.
- `handle_configure()` does not clear a prior session ID and does not reset the base handshaken flag.
- `handle_handshake()` requires configuration, accepts an optional `session_id`, and returns capability IDs.
- `health()` and `doctor()` consider a handshake complete only when `session_id` is present.
- `handle_shutdown()` shuts down the client runtime and clears config/client/base flags, but leaves `session_id` in memory.
- `self_check()` is a local readiness check only; it does not issue a live SendGrid probe.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- Manifest exposes only five operations: `sendgrid.lists.delete`, `sendgrid.contacts.list`, `sendgrid.mail.send`, `sendgrid.stats.get`, and `sendgrid.templates.list`.
- Runtime also exposes `sendgrid.contacts.search`, `sendgrid.contacts.get`, `sendgrid.lists.list`, `sendgrid.lists.create`, and `sendgrid.templates.get`.
- Manifest optional capabilities include `sendgrid.contacts.write`, but runtime has no contact write operation.
- Manifest omits `sendgrid.lists.read`, `sendgrid.lists.write`, and `sendgrid.templates.get` operation entries even though runtime uses those capabilities/operations.
- Manifest marks `sendgrid.mail.send` as policy-approved and `sendgrid.lists.delete` as interactive approval; runtime operation metadata sets `requires_approval = None` for every operation and invoke checks no approval token.
- Manifest marks `sendgrid.lists.delete` as `idempotency = "strict"`, while runtime metadata marks it `None`.
- Runtime `sendgrid.mail.send` only checks that either `personalizations` or top-level `to` exists. It does not locally require manifest-listed `from`, `subject`, or `content`.
- Runtime `contacts.list` wraps the provider `result` array as `contacts`, while manifest output schema advertises `result`.
- Runtime `lists.list` wraps the provider `result` array as `lists`.
- Manifest says API key and sender identity are stored under singleton-writer state. Runtime keeps config in process memory and does not persist connector state itself.
- Runtime `self_check()` validates local URL policy and credential mode, but does not call SendGrid.
- Manifest rate-limit pools are documented intent only; runtime does not enforce connector-local rate limits.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should align manifest/runtime operation catalogs, add capability-token and approval-token verification, decide whether `to` is a supported mail-send convenience field or should be rejected, align output schemas, reset session and handshake state on reconfigure and shutdown, add live readiness where desired, and add a tracked verification bundle.

## First-Slice Scope

The current SendGrid README slice documents the existing runtime surface:

- direct API-key and host credential-reference configuration
- URL policy for default SendGrid and local test endpoints
- mail send, marketing contacts, marketing lists, dynamic templates, and stats operations
- local self-check, simplified handshake, typed introspection, and simulation behavior
- deterministic WireMock tests and direct proof commands

## Auth And Scope Boundary

- Authentication mechanisms: SendGrid API key or host credential reference.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Runtime capability surface:
  - `sendgrid.mail.write` gates mail send metadata, but runtime does not enforce capability or approval tokens.
  - `sendgrid.contacts.read` gates contact list/search/get metadata, but runtime does not enforce capability tokens.
  - `sendgrid.lists.read` gates list listing metadata, but runtime does not enforce capability tokens.
  - `sendgrid.lists.write` gates list create metadata, but runtime does not enforce capability or approval tokens.
  - `sendgrid.lists.delete` gates list deletion metadata, but runtime does not enforce capability or approval tokens.
  - `sendgrid.templates.read` gates template list/get metadata, but runtime does not enforce capability tokens.
  - `sendgrid.stats.read` gates stats metadata, but runtime does not enforce capability tokens.
- The connector does not persist API keys, credential secret material, email payloads, contact records, list metadata, template bodies, stats, provider error bodies, or API responses outside process memory.
- SendGrid payloads can include email addresses, names, message content, template data, unsubscribe metadata, tracking fields, and campaign/contact data. Treat live output as work-zone or private-zone data based on the configured account and sender policy.

## Network And Runtime Invariants

- Default endpoint: `https://api.sendgrid.com/v3`.
- Runtime sends `Accept: application/json`.
- Runtime sends bearer auth in direct API-key mode.
- Runtime sends `X-FCP-Credential-Id` in credential-reference mode.
- Runtime user agent is `fcp-sendgrid/0.1.0 (FCP connector)`.
- Runtime request timeout: `30 seconds`.
- Runtime retry policy: `max_retries = 2` using the shared retry loop.
- Provider HTTP 401, 403, 404, 429, and other API errors map to typed connector/FCP errors.
- `Retry-After` on 429 is converted to milliseconds; missing values default to 60000 ms.
- Provider error bodies are truncated to 2048 bytes before extracting a SendGrid error message.
- Manifest connect timeout is `10000 ms`, operation total timeout is `30000 ms`, and maximum response bytes are `1048576` or `10485760` by operation.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, no exec, and no inbound listener capability.
- The connector does not open inbound sockets, receive Event Webhooks, handle inbound parse emails, or send through SMTP.

## Runtime Endpoints

| Operation | HTTP request | Runtime output wrapper |
|-----------|--------------|------------------------|
| `sendgrid.mail.send` | `POST /mail/send` | provider body or `{}` for empty 202 response |
| `sendgrid.contacts.list` | `GET /marketing/contacts` | `{ "contacts": result }` |
| `sendgrid.contacts.search` | `POST /marketing/contacts/search` | `{ "contacts": result }` |
| `sendgrid.contacts.get` | `GET /marketing/contacts/{contact_id}` | provider body |
| `sendgrid.lists.list` | `GET /marketing/lists` | `{ "lists": result }` |
| `sendgrid.lists.create` | `POST /marketing/lists` | provider body |
| `sendgrid.lists.delete` | `DELETE /marketing/lists/{list_id}` | provider body or `{}` |
| `sendgrid.templates.list` | `GET /templates?generations=dynamic` | `{ "templates": templates }` |
| `sendgrid.templates.get` | `GET /templates/{template_id}` | provider body |
| `sendgrid.stats.get` | `GET /stats?start_date=...&end_date=...` | `{ "stats": provider_body }` |

## Operation Inventory

| Operation | Capability | SafetyTier | RiskLevel | Idempotency | Required input |
|-----------|------------|------------|-----------|-------------|----------------|
| `sendgrid.mail.send` | `sendgrid.mail.write` | `Risky` | `High` | `None` | runtime requires `personalizations` or `to`; SendGrid expects valid mail-send payload |
| `sendgrid.contacts.list` | `sendgrid.contacts.read` | `Safe` | `Low` | `Strict` | none |
| `sendgrid.contacts.search` | `sendgrid.contacts.read` | `Safe` | `Low` | `Strict` | `query` SGQL string |
| `sendgrid.contacts.get` | `sendgrid.contacts.read` | `Safe` | `Low` | `Strict` | `contact_id` |
| `sendgrid.lists.list` | `sendgrid.lists.read` | `Safe` | `Low` | `Strict` | none |
| `sendgrid.lists.create` | `sendgrid.lists.write` | `Risky` | `Medium` | `None` | `name` |
| `sendgrid.lists.delete` | `sendgrid.lists.delete` | `Dangerous` | `High` | `None` | `list_id` |
| `sendgrid.templates.list` | `sendgrid.templates.read` | `Safe` | `Low` | `Strict` | none; runtime always requests dynamic templates |
| `sendgrid.templates.get` | `sendgrid.templates.read` | `Safe` | `Low` | `Strict` | `template_id` |
| `sendgrid.stats.get` | `sendgrid.stats.read` | `Safe` | `Low` | `Strict` | `start_date`; optional `end_date` |

## Explicit Non-Goals

The current implementation does not include:

- contact import/update/delete, custom fields, contact exports, segment management, single sends, automations, campaigns, suppressions, unsubscribe groups, sender authentication, API-key management, subusers, IP pools, or webhook configuration
- template create/update/delete, version management, template rendering, dynamic data validation, or template test sends
- SMTP transport, inbound parse webhooks, Event Webhook verification, bounce/spam handling, or delivery event storage
- sender identity verification, domain authentication, DKIM/SPF setup, link branding, or compliance checks
- pagination helpers, cursor persistence, backfill, retry queueing, idempotency keys, or email deduplication
- API-key provisioning automation beyond the local provisioning recipe prompts

These are excluded on purpose:

- Email send is an irreversible external side effect and needs explicit approval/runtime verification before broad automation is safe.
- Contact and list operations can affect marketing audiences and compliance surfaces.
- SendGrid has many v3 APIs; this connector should grow only through typed, manifest-aligned, capability-gated slices.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- local configuration, client, session ID, request, and error counter state
- local URL readiness and credential-injection warning state
- degraded self-check for unconfigured and `credential_id` modes
- typed introspection with operations, no events, no resource types, no auth caps, and no event caps
- simulation allow/deny for known versus unknown operation IDs only
- typed provider/FCP error mapping

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle, configuration, health, doctor, self-check, introspection, simulation, shutdown, and counters
- all ten SendGrid runtime operations through deterministic HTTP fixtures
- invoke rejection for unknown operation and missing required inputs
- provider 401, 403, 404, 429, and 500 classes
- auth redaction, credential-ID mode metadata, default/custom URL behavior, provisioning readiness, and base URL policy
- capability-catalog uniqueness and list-delete/list-create capability separation

## Source Notes

- `connectors/sendgrid/src/connector.rs` defines configuration parsing, URL policy, provisioning recipe, lifecycle handlers, typed introspection, simulation, and invoke dispatch.
- `connectors/sendgrid/src/client.rs` defines SendGrid v3 endpoint paths, auth headers, timeout, retry config, URL trimming, and provider error mapping.
- `connectors/sendgrid/src/types.rs` defines SendGrid error response shapes.
- `connectors/sendgrid/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/sendgrid/manifest.toml` defines the manifest operation subset, network constraints, sandbox boundary, zone policy, and rate-limit intent.
- `connectors/sendgrid/tests/integration.rs` contains the runtime contract proof surface.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/sendgrid/README.md
ubs connectors/sendgrid/README.md
LC_ALL=C rg -n '[^ -~]' connectors/sendgrid/README.md
rg -n '\bmaster\b' connectors/sendgrid/README.md
```

For source or behavior changes, also run the connector proof lane through `rch`:

```bash
rch exec -- cargo test -p fcp-sendgrid
rch exec -- cargo check -p fcp-sendgrid --all-targets
rch exec -- cargo clippy -p fcp-sendgrid --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

## Operator Guidance

- Use a least-privilege SendGrid API key scoped to the runtime operations you actually need.
- Keep direct API-key mode pointed at `https://api.sendgrid.com/v3`; custom non-local direct-key endpoints are rejected.
- Use credential-ID mode for host-managed secret injection or proxy endpoints.
- Treat `sendgrid.mail.send`, `sendgrid.lists.create`, and `sendgrid.lists.delete` as high-review operations until approval-token verification is implemented.
- Validate sender identity, template IDs, unsubscribe/compliance settings, and recipient lists outside this connector before sending mail.
- Do not rely on `self_check()` as a live SendGrid account probe; it only validates local configuration and URL policy.
