# Mastodon Connector V3 Contract

> **Status**: runtime contract documented; manifest/introspection/API drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Mastodon API upstream**: https://docs.joinmastodon.org/api/
> **Mastodon timelines upstream**: https://docs.joinmastodon.org/methods/timelines/
> **Mastodon statuses upstream**: https://docs.joinmastodon.org/methods/statuses/
> **Mastodon accounts upstream**: https://docs.joinmastodon.org/methods/accounts/
> **Mastodon notifications upstream**: https://docs.joinmastodon.org/methods/notifications/
> **Mastodon search upstream**: https://docs.joinmastodon.org/methods/search/

## Purpose

This document fixes the operator-facing contract for `fcp.mastodon`. The connector exposes the Mastodon API surface currently implemented in this crate: home and public timeline reads, status reads and writes, favourites, boosts, account lookup, credential verification, notification listing, search, and a live instance health probe.

The connector is intentionally a bounded Mastodon request-response bridge. It is not a full Mastodon client, OAuth application-registration flow, media uploader, streaming API client, list manager, conversation client, marker manager, scheduled-status manager, moderation/admin surface, follow graph manager, push-notification relay, or durable social inbox.

## Current Runtime Snapshot

The current crate exposes these runtime operation IDs:

- `mastodon.timeline.home`
- `mastodon.timeline.public`
- `mastodon.statuses.get`
- `mastodon.statuses.post`
- `mastodon.statuses.delete`
- `mastodon.statuses.favourite`
- `mastodon.statuses.boost`
- `mastodon.accounts.get`
- `mastodon.accounts.verify`
- `mastodon.notifications.list`
- `mastodon.search`
- `mastodon.health`

Important runtime truths the contract preserves:

- Package, library, and binary name are `fcp-mastodon`.
- Manifest ID is `fcp.mastodon`.
- `BaseConnector` runtime ID is `fcp.mastodon`.
- Manifest version is `0.1.0`.
- Manifest format table uses the older `[format]` shape and does not declare `native` or `wasi`.
- Configuration requires:
  - `instance_url`
  - `access_token`
- Configuration accepts:
  - `retry`
  - `request_timeout_ms`
- Direct token mode sends `Authorization: Bearer <access_token>` for normal runtime GET, POST, and DELETE calls when `access_token` is non-empty.
- Empty `access_token` is accepted by configuration and results in provider calls without an Authorization header.
- There is no `credential_id` config key or host credential-injection path in the current Mastodon connector.
- Runtime base URL is `{instance_url}/api/v1` after trimming a trailing slash from `instance_url`.
- The search operation switches to `/api/v2/search`.
- The live instance health probe calls `/api/v2/instance` first and falls back to `/api/v1/instance` on non-success.
- The HTTP client timeout is fixed at 30 seconds.
- Runtime request-context timeout defaults to 30000 ms and is configurable with `request_timeout_ms`.
- Runtime HTTP calls use the configured `HttpRetryConfig` through `RetryLoop`.
- `health()` reports local configured state and uptime. It does not call Mastodon.
- `doctor()` checks local configuration, client initialization, runtime initialization, and reports the configured instance URL scheme. It does not call Mastodon.
- `self_check()` calls the live instance health probe.
- Runtime `handshake()` parses a full `HandshakeRequest`, installs a `CapabilityVerifier`, hashes the checked-in manifest, and reports non-streaming event caps.
- Runtime `handshake()` grants every requested capability unfiltered.
- Runtime `invoke()` uses the FCP `InvokeRequest` shape: `operation`, `input`, and `capability_token`.
- Runtime `invoke()` requires configured and handshaken base state and verifies a bound capability token for the operation capability.
- Runtime capability verification currently passes an empty resource URI list for all Mastodon operations.
- Runtime `simulate()` always returns allowed and does not validate operation, input, configuration, handshake, provider state, or capability token.
- Runtime `shutdown()` shuts down the connector runtime but does not clear client/config/verifier state or configured/handshaken flags.
- Runtime `subscribe()` and `unsubscribe()` are unsupported.

## Runtime API Adapter

The runtime uses these request shapes:

| Operation | Capability | Required input | Runtime request |
|-----------|------------|----------------|-----------------|
| `mastodon.timeline.home` | `mastodon.read` | none | `GET /api/v1/timelines/home` with optional `limit` |
| `mastodon.timeline.public` | `mastodon.read` | none | `GET /api/v1/timelines/public` with optional `local` and `limit` |
| `mastodon.statuses.get` | `mastodon.read` | `id` | `GET /api/v1/statuses/{id}` |
| `mastodon.statuses.post` | `mastodon.write` | `status` | `POST /api/v1/statuses` with optional `visibility`, `in_reply_to_id`, `sensitive`, and `spoiler_text` |
| `mastodon.statuses.delete` | `mastodon.write` | `id` | `DELETE /api/v1/statuses/{id}` |
| `mastodon.statuses.favourite` | `mastodon.write` | `id` | `POST /api/v1/statuses/{id}/favourite` |
| `mastodon.statuses.boost` | `mastodon.write` | `id` | `POST /api/v1/statuses/{id}/reblog` |
| `mastodon.accounts.get` | `mastodon.read` | `id` | `GET /api/v1/accounts/{id}` |
| `mastodon.accounts.verify` | `mastodon.read` | none | `GET /api/v1/accounts/verify_credentials` |
| `mastodon.notifications.list` | `mastodon.read` | none | `GET /api/v1/notifications` with optional `limit` |
| `mastodon.search` | `mastodon.read` | `q` | `GET /api/v2/search` with optional `type` and `limit` |
| `mastodon.health` | `mastodon.read` | none | `GET /api/v2/instance`, falling back to `GET /api/v1/instance` |

Path, query, and error handling:

- Status and account IDs used as path segments are rejected when empty, whitespace-only, containing `/`, containing `\`, containing `..`, containing a null byte, or containing encoded slash/backslash markers such as `%2f` or `%5C`.
- Timeline and notification `limit` is documented in the schema as 1 through 40, but runtime does not clamp or reject values before forwarding.
- Status post input is documented with a 500-character maximum, but runtime does not enforce that local limit before forwarding.
- `visibility` is documented as `public`, `unlisted`, `private`, or `direct`, but runtime forwards any string it receives.
- Search `type` is documented as `accounts`, `hashtags`, or `statuses`, but runtime forwards any string it receives.
- HTTP 429 maps to a rate-limit error and honors `Retry-After` when present, defaulting to 60 seconds otherwise.
- HTTP 401 and 403 map to terminal unauthorized errors.
- HTTP 5xx responses are retryable through the retry loop.
- Other non-success provider responses are terminal API errors.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Mastodon documents broader query parameters for timelines, statuses, notifications, and search than this connector forwards.
- Mastodon documents media attachments, polls, scheduling, quote status fields, language, and idempotency keys for status creation. Runtime forwards only text, visibility, reply ID, sensitivity, and spoiler text, and does not send `Idempotency-Key`.
- Mastodon documents undo-favourite and undo-boost operations. Runtime only implements favourite and boost.
- Mastodon documents status edit, context, bookmark, mute, pin, quote, and source operations. Runtime does not implement them.
- Mastodon documents notification dismiss, clear, unread count, and notification-request operations. Runtime only lists notifications.
- Mastodon documents public access rules that vary by instance configuration. Runtime permits an empty access token and lets the provider accept or reject each call.
- The manifest operation table keys are snake-case names such as `timeline_home`; runtime operation IDs are dotted names such as `mastodon.timeline.home`.
- Manifest required capabilities use `network.dns` and `network.outbound`; current root guidance generally uses `network.egress` and `network.tls.sni` for provider connectors.
- The manifest uses `z:social`, but root guidance describes the standard zone hierarchy without a `z:social` entry.
- Runtime `doctor()` labels any non-HTTPS instance URL as `http` but still passes the local instance URL diagnostic.
- Runtime `health()` is local while runtime `self_check()` and `mastodon.health` are live provider probes.
- Runtime `simulate()` is an allow-all stub.
- Runtime capability verification does not bind account IDs, status IDs, timelines, notification streams, search terms, or instance URL as resource URIs.
- Runtime `handshake()` grants every requested capability unfiltered.
- Runtime `shutdown()` does not clear configured state, handshaken state, config, client, or verifier.
- `mastodon.statuses.delete` declares interactive approval metadata. `mastodon.statuses.post` and `mastodon.statuses.boost` can publish or amplify content but currently require no interactive approval.
- No dedicated tracked verification shell script exists for this connector.

A follow-up parity bead should enforce configuration URL policy, decide whether empty-token mode is intentional, add credential-ID support or remove the concept from operator docs, validate invoke input against the advertised schemas, bind capability tokens to Mastodon resource URIs, add simulation checks, reconcile manifest capabilities and zones with root conventions, clear runtime state on shutdown, and decide whether media, streaming, idempotency keys, status editing, undo actions, and notification mutations belong in this connector.

## First-Slice Scope

The current Mastodon README slice documents the existing runtime surface:

- Direct access-token configuration and current empty-token behavior
- Timelines, statuses, favourites, boosts, accounts, credential verification, notifications, search, and instance health operations
- Local health, doctor, live self-check, introspection, simulate, invoke, subscribe, unsubscribe, and shutdown behavior
- Capability-token verification and current empty resource-URI binding
- Provider error mapping, path sanitization, retry behavior, and timeout behavior
- Runtime/manifest/provider-doc drift around broad Mastodon API coverage, empty-token mode, local validation, approval metadata, shutdown, simulation, capabilities, and zone names
- Existing test orientation through manifest checks, operation introspection checks, path-sanitization tests, token-redaction tests, and WireMock-backed client flows

## Auth And Zone Boundary

- Authentication mechanism: direct Mastodon OAuth access token.
- Home zone: `z:social`.
- Allowed source zones: `z:social` and `z:private`.
- Allowed target zone: `z:social`.
- Runtime capability families:
  - `mastodon.read`
  - `mastodon.write`
- Manifest required capabilities are `network.dns` and `network.outbound`.
- Manifest forbids `system.exec` and `system.privileged`.
- The connector does not intentionally persist Mastodon tokens, timelines, statuses, accounts, notifications, search results, request counters, or error counters outside process memory.
- Mastodon payloads can contain profile data, post HTML, private or direct statuses visible to the acting account, notification data, search terms, hashtags, server metadata, and social graph context. Treat live input and output as private or social-zone sensitive unless the host supplies a stricter zone policy.

## Explicit Non-Goals

- No OAuth app registration or authorization-code flow.
- No media upload.
- No streaming API support.
- No status edit or scheduled-status management.
- No poll management.
- No quote-post management.
- No undo favourite or undo boost.
- No follow, mute, block, or report operations.
- No notification clearing or dismissing.
- No moderation/admin API.
- No durable social inbox.
- No cross-zone social publishing.

## Verification

README-only changes do not require Cargo or `rch` verification. Before committing this file, run:

```bash
git diff --check -- connectors/mastodon/README.md
LC_ALL=C rg -n '[^ -~]' connectors/mastodon/README.md
rg -n '\bmaster\b' connectors/mastodon/README.md
ubs connectors/mastodon/README.md
```

For code changes in this connector, use the workspace-required proof lane from the root `AGENTS.md`:

```bash
rch exec -- cargo check --workspace --all-targets
rch exec -- cargo clippy --workspace --all-targets -- -D warnings
rch exec -- cargo fmt --check
```
