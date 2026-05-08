# Reddit Connector V3 Contract

> **Status**: runtime contract documented with approval-token, schema-validation, and durable-state drift
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Reddit API reference**: https://www.reddit.com/dev/api/
> **Reddit developer API capability**: https://developers.reddit.com/docs/capabilities/server/reddit-api

## Purpose

This document fixes the operator-facing contract for `fcp.reddit`. The connector exposes the Reddit surfaces implemented in this crate: search, subreddit listing, post-thread reads, post/comment writes, private messages, moderation remove/approve/queue, subreddit/user lookup, saved-item operations, inbox reads and mark-read, polling-style subreddit streams, and bounded media downloads from allowlisted Reddit media hosts.

The connector is intentionally a bounded Reddit community bridge. It is not a full Reddit app platform runtime, OAuth token-exchange service, webhook receiver, durable stream processor, subreddit-management console, advertising client, moderation automation policy engine, or connector-local credential vault.

## Current Runtime Snapshot

The current crate exposes these operations:

- `reddit.search_posts`
- `reddit.list_subreddit_new`
- `reddit.get_post_thread`
- `reddit.create_post`
- `reddit.create_comment`
- `reddit.send_message`
- `reddit.mod_remove`
- `reddit.download_media`
- `reddit.stream_subreddit_new`
- `reddit.subreddit.get`
- `reddit.subreddit.search`
- `reddit.user.posts`
- `reddit.user.comments`
- `reddit.edit_content`
- `reddit.delete_content`
- `reddit.saved.list`
- `reddit.saved.save`
- `reddit.saved.unsave`
- `reddit.mod.queue`
- `reddit.mod.approve`
- `reddit.inbox.list`
- `reddit.inbox.mark_read`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-reddit`.
- Runtime `BaseConnector` ID is `reddit`.
- Manifest and handshake connector ID are `fcp.reddit`.
- Connector version is `0.1.0`.
- Configuration requires exactly one auth source:
  - `bearer_token`
  - `credential_id`
- `credential_id` must be a valid UUID.
- Default base URL is `https://oauth.reddit.com`.
- Direct-token mode sends `Authorization: Bearer <token>`.
- `credential_id` mode sends `X-FCP-Credential-Id: <uuid>`.
- Runtime reqwest timeout is `30 seconds` for Reddit API calls.
- Runtime media-download timeout is `90 seconds`.
- Runtime request context timeout is `30 seconds`.
- Runtime contains an `HttpRetryConfig` with `max_retries = 2`, but current request methods send requests directly and do not use a retry loop.
- Runtime `invoke` uses `operation_id`, not `operation`.
- Runtime `invoke` checks only connector readiness, operation identity, local required-field extraction, and client initialization before dispatch.
- Runtime does not verify `capability_token`.
- Runtime does not verify approval tokens for posting, messaging, moderation, deletion, save/unsave, or inbox mark-read operations.
- `simulate` checks only whether `operation_id` is a known operation. It does not validate readiness, input shape, caller authority, capability, approval state, or rate limits.
- `handle_shutdown()` shuts down the client runtime, clears client/config state, and resets configured/handshaken flags.
- `handle_shutdown()` does not clear the stored `session_id` string.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Reddit public API documentation exposes many more endpoints than this connector implements. The current runtime is limited to the operation inventory below.
- Runtime provisioning describes OAuth2 Authorization Code plus PKCE against `https://www.reddit.com/api/v1/authorize` and `https://www.reddit.com/api/v1/access_token`, but the connector itself does not perform browser authorization, token exchange, refresh-token rotation, consent UX, or account enrollment.
- Runtime OAuth provisioning scopes are `read`, `identity`, `history`, `mysubreddits`, `submit`, and `privatemessages`. Moderator operations require appropriate Reddit account permissions and may require additional upstream scopes or app configuration outside this connector.
- Manifest says state stores subreddit polling checkpoints, pagination cursors, and idempotency keys. Runtime keeps request counters and configuration in memory and does not persist polling checkpoints, cursors, or idempotency keys.
- Manifest marks write and moderation operations as policy-gated or interactive. Runtime introspection exposes every operation with `requires_approval = None`, and invoke checks no approval token.
- Manifest input schemas declare patterns, enums, bounds, and idempotency fields. Runtime extraction mostly checks required fields and primitive types, but does not centrally enforce every manifest/input-schema constraint before building request paths or form bodies.
- Manifest network policy allows only `www.reddit.com` and `oauth.reddit.com` for API operations. Runtime base URL policy allows Reddit hosts plus loopback HTTP(S) for deterministic tests, and configure constructs a client before any live provider probe.
- Manifest and operation metadata advertise `reddit.stream`, but `reddit.stream_subreddit_new` is implemented as a poll/list operation over `/r/{subreddit}/new`, not as a durable provider event stream.
- Runtime introspection returns no events, no resource types, no auth caps, and no event caps.
- `credential_id` mode can configure and build a client, but self-check reports `credential_injection_required` and skips live provider probing. Actual calls rely on an egress proxy or host layer to materialize the bearer credential.
- `self_check` performs local configuration, endpoint-policy, and client checks only. It does not call Reddit.
- `doctor` performs local configuration, client, and handshake checks only. It does not call Reddit.
- Runtime accepts arbitrary strings for several path-segment inputs after required-field extraction. Callers must not rely on manifest patterns being enforced locally until that drift is closed.
- There is no tracked verification shell script for this connector.

A follow-up parity bead should install bound capability-token verification, enforce approval-token semantics for side-effecting operations, align runtime input validation with manifest schemas, persist or remove advertised polling/idempotency state, decide whether `credential_id` is a fully supported provider path, and replace polling stream language with a durable event contract only when replay/checkpointing exists.

## First-Slice Scope

The current Reddit README slice documents the existing runtime surface:

- direct bearer-token configuration and host credential-reference configuration
- OAuth provisioning recipe metadata and its current token-exchange gap
- search, read, posting, commenting, messaging, moderation, subreddit/user, saved-item, inbox, polling, and media-download operations
- media host allowlist, size caps, redirect handling, retry, timeout, provider error, readiness, doctor, health, self-check, simulate, introspect, invoke, and shutdown behavior
- runtime/manifest drift around approvals, capability-token verification, schema enforcement, state persistence, credential IDs, endpoint policy, stream semantics, and idempotency keys
- deterministic WireMock and loopback-media tests plus direct proof commands

## Auth And Zone Boundary

- Authentication mechanisms: Reddit bearer token or host credential reference.
- Direct bearer-token mode expects a usable Reddit API bearer token at configure time.
- `credential_id` mode delegates bearer materialization to a host or egress proxy.
- Runtime does not implement Reddit app creation, browser authorization, OAuth callback handling, token refresh, token revocation, two-factor flows, account switching, or connector-local credential vaulting.
- Home zone: `z:community`.
- Allowed source zones: `z:owner`, `z:private`, `z:work`, and `z:community`.
- Allowed target zones: `z:community` and `z:work`.
- Forbidden zone: `z:public`.
- Capability families:
  - `reddit.read`
  - `reddit.search`
  - `reddit.post`
  - `reddit.comment`
  - `reddit.message`
  - `reddit.moderate`
  - `reddit.stream`
  - `reddit.media.read`
- Reddit posts, comments, messages, moderator queues, saved items, user histories, and community membership can contain public, private, work, and community-sensitive data. Do not log bearer tokens, message bodies, private-message recipients, moderation queues, saved-item lists, raw provider errors, or full content payloads in shared artifacts.

## Network And Runtime Invariants

- Default runtime API base URL: `https://oauth.reddit.com`.
- Runtime API endpoints:
  - `GET /search` or `GET /r/{subreddit}/search`
  - `GET /r/{subreddit}/new`
  - `GET /comments/{post_id}`
  - `POST /api/submit`
  - `POST /api/comment`
  - `POST /api/compose`
  - `POST /api/remove`
  - `GET /r/{subreddit}/about`
  - `GET /subreddits/search`
  - `GET /user/{username}/submitted`
  - `GET /user/{username}/comments`
  - `POST /api/editusertext`
  - `POST /api/del`
  - `GET /user/{username}/saved`
  - `POST /api/save`
  - `POST /api/unsave`
  - `GET /r/{subreddit}/about/modqueue`
  - `POST /api/approve`
  - `GET /message/{category}`
  - `POST /api/read_message`
- Runtime sends read requests with query parameters and write requests as form-encoded bodies.
- Runtime maps successful empty bodies to `{}`.
- Runtime maps 401 to unauthorized, 403 to forbidden, 404 to not found, 429 to rate limited using `Retry-After` with a 60 second default, and other non-success responses to provider API errors.
- Runtime media download allowlist:
  - `i.redd.it`
  - `v.redd.it`
  - `preview.redd.it`
  - `external-preview.redd.it`
- Runtime media downloads reject userinfo, missing hosts, nonallowlisted hosts, nonlocal IP literals, non-HTTPS Reddit media URLs, Reddit media ports other than 443, oversized `Content-Length`, oversized streamed bodies, and redirects that leave the allowlist.
- Runtime media downloads allow loopback HTTP(S) only when the configured API base URL is also a local test host.
- Default media cap is `10485760` bytes.
- Accepted media cap range is `1024` through `26214400` bytes.
- Runtime computes a SHA-256 digest for downloaded media and returns content type, byte count, and digest.
- Manifest live-operation policy requires TLS/SNI, denies localhost, private ranges, tailnet ranges, and IP literals, and allows only Reddit API hosts on port 443.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `300000 ms` wall-clock timeout, read-only `/usr` and `/lib`, writable `$CONNECTOR_STATE`, no exec, and no ptrace.
- The connector does not open inbound sockets.

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Required input |
|-----------|----------------|------------|------------|-----------|-------------|----------------|
| `reddit.search_posts` | `GET /search` or `/r/{subreddit}/search` | `reddit.search` | `Safe` | `Low` | `Strict` | `query`; optional `subreddit`, `sort`, `time_range`, `limit`, `after`. |
| `reddit.list_subreddit_new` | `GET /r/{subreddit}/new` | `reddit.read` | `Safe` | `Low` | `Strict` | `subreddit`; optional `limit`, `after`. |
| `reddit.get_post_thread` | `GET /comments/{post_id}` | `reddit.read` | `Safe` | `Low` | `Strict` | `post_fullname`; optional `sort`, `comment_limit`. |
| `reddit.create_post` | `POST /api/submit` | `reddit.post` | `Dangerous` | `High` | `BestEffort` | `subreddit`, `kind`, `title`; optional `text`, `url`, `nsfw`, `spoiler`, `idempotency_key`. |
| `reddit.create_comment` | `POST /api/comment` | `reddit.comment` | `Risky` | `Medium` | `BestEffort` | `parent_fullname`, `text`; optional `idempotency_key`. |
| `reddit.send_message` | `POST /api/compose` | `reddit.message` | `Dangerous` | `High` | `BestEffort` | `recipient`, `subject`, `message`; optional `idempotency_key`. |
| `reddit.mod_remove` | `POST /api/remove` | `reddit.moderate` | `Dangerous` | `High` | `Strict` | `thing_fullname`; optional `spam`, `mod_note`. |
| `reddit.download_media` | external media URL | `reddit.media.read` | `Safe` | `Low` | `Strict` | `url`; optional `max_bytes`. |
| `reddit.stream_subreddit_new` | polling wrapper over `/r/{subreddit}/new` | `reddit.stream` | `Risky` | `Medium` | `None` | `subreddit`; optional `limit`, `after`. |
| `reddit.subreddit.get` | `GET /r/{subreddit}/about` | `reddit.read` | `Safe` | `Low` | `Strict` | `subreddit`. |
| `reddit.subreddit.search` | `GET /subreddits/search` | `reddit.search` | `Safe` | `Low` | `Strict` | `query`; optional `limit`, `after`. |
| `reddit.user.posts` | `GET /user/{username}/submitted` | `reddit.read` | `Safe` | `Low` | `Strict` | `username`; optional `limit`, `after`. |
| `reddit.user.comments` | `GET /user/{username}/comments` | `reddit.read` | `Safe` | `Low` | `Strict` | `username`; optional `limit`, `after`. |
| `reddit.edit_content` | `POST /api/editusertext` | `reddit.post` | `Risky` | `Medium` | `BestEffort` | `thing_fullname`, `text`; optional `idempotency_key`. |
| `reddit.delete_content` | `POST /api/del` | `reddit.post` | `Dangerous` | `High` | `Strict` | `thing_fullname`. |
| `reddit.saved.list` | `GET /user/{username}/saved` | `reddit.read` | `Safe` | `Low` | `Strict` | `username`; optional `limit`, `after`. |
| `reddit.saved.save` | `POST /api/save` | `reddit.post` | `Safe` | `Low` | `Strict` | `thing_fullname`. |
| `reddit.saved.unsave` | `POST /api/unsave` | `reddit.post` | `Safe` | `Low` | `Strict` | `thing_fullname`. |
| `reddit.mod.queue` | `GET /r/{subreddit}/about/modqueue` | `reddit.moderate` | `Safe` | `Low` | `Strict` | `subreddit`; optional `limit`, `after`. |
| `reddit.mod.approve` | `POST /api/approve` | `reddit.moderate` | `Risky` | `Medium` | `Strict` | `thing_fullname`. |
| `reddit.inbox.list` | `GET /message/{category}` | `reddit.message` | `Safe` | `Low` | `Strict` | Optional `category`, `limit`, `after`. |
| `reddit.inbox.mark_read` | `POST /api/read_message` | `reddit.message` | `Safe` | `Low` | `Strict` | `fullnames`. |

## Explicit Non-Goals

The current implementation does not include:

- Reddit app registration, OAuth authorization UI, token exchange, token refresh, token revocation, or account enrollment
- durable polling checkpoints, replay cursors, event buffers, or provider push events
- subreddit settings, flair templates, wiki editing, modmail, ban/mute flows, moderation notes beyond the remove call, automod, reports, or rule-management APIs
- live comment-stream or websocket/SSE ingestion
- arbitrary Reddit API endpoint passthrough
- advertising, awards, chat, live threads, polls, collections, contributor programs, trophies, or account-management APIs
- media upload, video transcoding, image submission upload, or crosspost creation
- connector-local storage of bearer tokens, private messages, saved items, moderation queues, post/comment bodies, media blobs, idempotency keys, cursors, or request history
- direct FCP capability-token or approval-token verification at connector invoke time

These are excluded on purpose:

- Reddit write operations can publish, delete, moderate, or message real users.
- Private messages and saved items can expose private user data.
- Moderation operations need explicit human policy and audit handling before production use.
- Durable stream semantics need persisted checkpoints and replay rules that are not present in this runtime.

## Readiness And Verification Surface

`handle_doctor()`, `handle_health()`, `handle_self_check()`, `handle_simulate()`, and `handle_introspect()` are part of the public closeout contract. They surface:

- configuration, auth mode, client, and handshake state
- credential-injection status for host credential references
- in-memory request/error counters
- known operation metadata, schemas, capability IDs, risk levels, safety tiers, idempotency, and AI hints
- local simulation of known versus unknown operations
- provider error mapping for unauthorized, forbidden, not found, rate-limit, API, JSON, media-size, media-URL, and transport failures

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle health, configure, handshake, shutdown, doctor, self-check, introspection, and counters
- search, subreddit listing, post-thread reads, post/comment creation, private messages, moderation remove/approve/queue, subreddit/user reads, saved-item operations, and inbox operations
- missing required input rejection
- provider 401, 404, 429, unknown-operation, and simulation behavior
- loopback media download success with SHA-256 output
- media content-length rejection and redirect-to-disallowed-host rejection

## Source Notes

- `connectors/reddit/src/connector.rs` defines configuration parsing, lifecycle handlers, diagnostics, introspection, simulation, invoke dispatch, operation IDs, operation metadata, provisioning readiness, and base URL policy.
- `connectors/reddit/src/client.rs` defines Reddit HTTP request construction, auth headers, endpoint paths, form encoding, media-download policy, timeout configuration, and provider error mapping.
- `connectors/reddit/src/types.rs` defines Reddit request/response helper shapes.
- `connectors/reddit/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/reddit/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, rate-limit pools, state claims, and AI hints.
- `connectors/reddit/tests/integration.rs` covers deterministic HTTP behavior, lifecycle behavior, operation dispatch, media security behavior, and diagnostics.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/reddit/README.md
ubs connectors/reddit/README.md
LC_ALL=C rg -n '[^ -~]' connectors/reddit/README.md
rg -n '\bmaster\b' connectors/reddit/README.md
```

For source or behavior changes, also run the connector proof lane through `rch`:

```bash
rch exec -- cargo test -p fcp-reddit
rch exec -- cargo check -p fcp-reddit --all-targets
rch exec -- cargo clippy -p fcp-reddit --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

## Operator Guidance

- Treat `reddit.create_post`, `reddit.create_comment`, `reddit.send_message`, `reddit.mod_remove`, `reddit.edit_content`, `reddit.delete_content`, `reddit.mod.approve`, and `reddit.inbox.mark_read` as side-effecting operations requiring host approval until runtime approval enforcement lands.
- Treat `reddit.stream_subreddit_new` as polling, not a durable stream.
- Prefer `credential_id` only in environments where the host egress layer is known to inject bearer material.
- Keep Reddit API calls scoped to the connector's configured zone and explicit capabilities; do not use this connector as an arbitrary Reddit API passthrough.
