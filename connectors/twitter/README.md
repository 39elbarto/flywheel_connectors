# Twitter Connector V3 Contract

> **Status**: runtime contract documented; manifest/introspection/API drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **X API overview upstream**: https://docs.x.com/x-api/overview
> **X API v2 overview upstream**: https://docs.x.com/x-api/getting-started/about-x-api
> **X OAuth 1.0a upstream**: https://docs.x.com/fundamentals/authentication/oauth-1-0a/overview
> **X app-only bearer token upstream**: https://docs.x.com/fundamentals/authentication/oauth-2-0/application-only
> **X filtered stream upstream**: https://docs.x.com/x-api/posts/filtered-stream/introduction

## Purpose

This document fixes the operator-facing contract for `fcp.twitter`. The connector exposes the X API surface currently implemented in this crate: user lookup, post lookup and search, timelines and mentions, trends, post creation and deletion, repost and like mutations, direct-message send/read helpers, filtered-stream rule management, and a filtered-stream subscription loop.

The connector is intentionally a bounded X API bridge. It is not a browser automation client, media uploader, OAuth authorization-code server, account provisioning flow, analytics warehouse, social listening pipeline, compliance archive, moderation queue, or durable streaming relay.

## Current Runtime Snapshot

The current crate exposes these runtime operation IDs:

- `twitter.user.me`
- `twitter.user.get`
- `twitter.user.by_username`
- `twitter.tweet.get`
- `twitter.tweet.get_many`
- `twitter.tweet.search`
- `twitter.user.timeline`
- `twitter.user.mentions`
- `twitter.trends.place`
- `twitter.tweet.retweet`
- `twitter.tweet.unretweet`
- `twitter.tweet.like`
- `twitter.tweet.unlike`
- `twitter.tweet.create`
- `twitter.tweet.reply`
- `twitter.tweet.delete`
- `twitter.stream.rules.list`
- `twitter.stream.rules.add`
- `twitter.dm.send`
- `twitter.dm.events`
- `twitter.stream.rules.delete`

Important runtime truths the contract preserves:

- Package, library, and binary name are `fcp-twitter`.
- Manifest ID is `fcp.twitter`.
- `BaseConnector` runtime ID is `twitter:social:v1`.
- Manifest version is `0.1.0`.
- Manifest format is `wasi`.
- Configuration requires exactly one auth mode:
  - `credential_id`
  - direct OAuth credentials
- Direct OAuth mode requires `consumer_key`, `consumer_secret`, `access_token`, and `access_token_secret`; `bearer_token` is optional.
- `credential_id` mode must not be combined with direct OAuth fields.
- `credential_id` must be a valid UUID.
- Default API base URL is `https://api.twitter.com`.
- Runtime configure accepts custom `api_url`.
- Legacy config defaults include upload URL `https://upload.twitter.com` and stream URL `https://api.twitter.com`, but runtime REST and stream-rule operations use the configured `api_url` client base.
- Runtime request timeout is 30 seconds.
- Runtime retry defaults are three attempts, 1000 ms initial delay, and 60000 ms maximum delay.
- `handle_configure()` creates the API client, clears authenticated user, verifier, and session state, and marks the base configured but not handshaken.
- `handshake()` performs a live `GET /2/users/me` probe, stores the authenticated user, installs a `CapabilityVerifier`, grants every requested capability unfiltered, and returns hard-coded `manifest_hash = "sha256:twitter-connector-v1"`.
- Runtime event caps report streaming support, no replay, no ack requirement, and zero minimum buffer in handshake.
- Runtime introspection reports event caps with streaming support, no replay, no ack requirement, and minimum buffer of 100.
- `health()` reports local readiness, request counters, active stream flag, and subscriber count. It does not call X.
- `doctor()` checks local configuration, client initialization, API URL scheme, auth mode, static network constraints, and credential-injection readiness. It does not call X.
- `self_check()` calls the live `GET /2/users/me` health check and reports degraded on provider failure.
- Runtime `invoke` uses the JSON fields `operation`, `args`, and `capability_token`.
- Runtime `simulate` uses the FCP `SimulateRequest` shape and reads operation input from `input`.
- Runtime `invoke` and `simulate` require a bound capability token for the operation capability.
- Runtime resource URI binding only covers `user_id` and `tweet_id` arguments, producing `twitter:user:{user_id}` and `twitter:tweet:{tweet_id}`.
- Runtime `subscribe()` only accepts `event_type = "stream"`.
- Runtime `shutdown()` stops the stream task, sends the shutdown signal, shuts down the client, clears config/client/auth/verifier/session state, and clears configured/handshaken flags.

## Runtime API Adapter

The runtime uses these request shapes under `{api_url}`:

| Operation | Capability | Required args | Runtime behavior |
|-----------|------------|---------------|------------------|
| `twitter.user.me` | `twitter.read.account` | none | Gets the authenticated user's profile. |
| `twitter.user.get` | `twitter.read.public` | `user_id` | Gets a user by numeric ID. |
| `twitter.user.by_username` | `twitter.read.public` | `username` | Gets a user by username; runtime strips an `@` prefix. |
| `twitter.tweet.get` | `twitter.read.public` | `tweet_id` | Gets one post by ID. |
| `twitter.tweet.get_many` | `twitter.read.public` | `tweet_ids` | Gets multiple posts by ID; input must be a non-empty array of strings. |
| `twitter.tweet.search` | `twitter.read.public` | `query` | Searches recent posts; optional `max_results`, `sort_order`, `next_token`, and `since_id`. |
| `twitter.user.timeline` | `twitter.read.account` | `user_id` | Gets a user's post timeline; optional `max_results` and `pagination_token`. |
| `twitter.user.mentions` | `twitter.read.account` | none | Gets mentions; uses the authenticated user if `user_id` is omitted. |
| `twitter.trends.place` | `twitter.read.public` | `woeid` | Gets trends for a Where On Earth ID. |
| `twitter.tweet.retweet` | `twitter.write.tweets` | `tweet_id` | Reposts a post. |
| `twitter.tweet.unretweet` | `twitter.write.tweets` | `tweet_id` | Removes a repost. |
| `twitter.tweet.like` | `twitter.write.tweets` | `tweet_id` | Likes a post. |
| `twitter.tweet.unlike` | `twitter.write.tweets` | `tweet_id` | Removes a like. |
| `twitter.tweet.create` | `twitter.write.tweets` | `text` | Creates a new post. |
| `twitter.tweet.reply` | `twitter.write.tweets` | `text`, `reply_to` | Creates a reply to an existing post. |
| `twitter.tweet.delete` | `twitter.write.tweets` | `tweet_id` | Deletes a post owned by the authenticated user. |
| `twitter.stream.rules.list` | `twitter.stream.read` | none | Lists active filtered-stream rules. |
| `twitter.stream.rules.add` | `twitter.stream.read` | `rules` | Adds filtered-stream rules; input must be a non-empty array. |
| `twitter.stream.rules.delete` | `twitter.stream.read` | `rule_ids` | Deletes filtered-stream rules by ID; input must be a non-empty string array. |
| `twitter.dm.send` | `twitter.write.dms` | `text` | Sends a direct message to an existing `conversation_id` or a new `participant_id`. |
| `twitter.dm.events` | `twitter.read.dms` | `conversation_id` | Reads direct-message events in a conversation. |

Path and query handling:

- Numeric IDs are validated as non-empty ASCII-digit strings before URL-path interpolation in the client.
- Query-string values are percent-encoded by the local query encoder before request construction.
- Direct OAuth mode signs requests with OAuth 1.0a when a user-context request is needed.
- Bearer-token support exists for app-only reads when the configured auth data includes `bearer_token`.
- `credential_id` mode sends no OAuth signer or bearer token from the connector; host egress policy must inject credentials.
- Client error mapping preserves rate-limit headers where available.

Streaming behavior:

- `subscribe()` starts a single filtered-stream supervisor if one is not already active.
- The stream connector uses the legacy `TwitterConfig` built during configure.
- Stream events are broadcast as JSON values of type `tweet`, `connected`, `disconnected`, `heartbeat`, or `error`.
- No replay buffer is implemented in the connector runtime.
- Subscriber count is incremented on subscribe; there is no per-subscriber durable acknowledgement state.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- X currently documents X API v2 as the recommended API. Runtime operation names still use `tweet` terminology throughout.
- X documents app-only bearer tokens for public read-only access and OAuth 1.0a for user-context calls. Runtime supports both direct OAuth credentials and an optional bearer token, but configuration does not declare provider scopes.
- Manifest optional capabilities use `twitter.stream`, `twitter.write`, `twitter.delete`, and `twitter.read`. Runtime introspection uses more granular capabilities: `twitter.stream.read`, `twitter.write.tweets`, `twitter.read.public`, and `twitter.read.account`.
- Manifest declares `twitter.stream.rules.delete` input as `ids`; runtime requires `rule_ids`.
- Manifest declares `twitter.tweet.delete` capability `twitter.delete`; runtime requires `twitter.write.tweets`.
- Runtime introspection includes `twitter.stream.rules.delete`, but some existing introspection tests only assert a smaller subset.
- Handshake grants every requested capability unfiltered. It does not intersect requested capabilities with the actual runtime catalog.
- Handshake returns a hard-coded manifest hash instead of hashing the checked-in manifest.
- Runtime introspection does not include provider approval metadata even for post creation, replies, deletes, reposts, likes, and direct messages.
- Runtime `simulate` validates known operation, required input shape, configured state, handshake state, capability token, and current resource URI binding, but it does not model provider rate limits, access tiers, account suspension, write permissions, app review state, DM access, or filtered-stream plan limits.
- Runtime resource URI binding only covers `user_id` and `tweet_id`; it does not bind `username`, `reply_to`, `conversation_id`, `participant_id`, `rule_ids`, or `woeid`.
- Runtime `health()` and `doctor()` are local diagnostics only.
- Runtime `self_check()` is live and can fail or degrade due to provider auth, quota, network, or egress policy even when local configuration is syntactically valid.
- `credential_id` mode creates a client without OAuth signing or bearer headers. Without an egress proxy, X itself will not authenticate requests.
- Stream subscription has no replay or durable offset contract.
- No dedicated tracked verification shell script exists for this connector.

A follow-up parity bead should reconcile manifest capabilities and input schemas with runtime introspection, filter handshake grants, hash the manifest, add approval metadata for social write operations, bind capability tokens to more resource arguments, surface required provider scopes/access levels, and document or implement a durable streaming acknowledgement contract.

## First-Slice Scope

The current Twitter README slice documents the existing runtime surface:

- Direct OAuth and credential-ID configuration
- User, post, search, timeline, mention, trend, engagement, direct-message, filtered-stream rule, and stream subscription operations
- Local health and doctor behavior plus live self-check behavior
- Capability-token verification and current resource URI binding
- Runtime/manifest/provider-doc drift around terminology, capability names, input schema names, approval metadata, provider access tiers, and streaming replay
- Existing integration-test orientation through WireMock-backed provider flows

## Auth And Zone Boundary

- Authentication mechanisms: direct OAuth 1.0a credentials with optional bearer token, or host credential reference.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zone: `z:public`.
- Runtime capability families:
  - `twitter.read.public`
  - `twitter.read.account`
  - `twitter.write.tweets`
  - `twitter.stream.read`
  - `twitter.write.dms`
  - `twitter.read.dms`
- Manifest required capabilities are `network.dns`, `network.egress`, `network.tls.sni`, `storage.state`, `crypto.hmac`, and `streaming.events`.
- Manifest forbids `system.exec` and `network.listen`.
- The connector does not intentionally persist OAuth credentials, bearer tokens, credential IDs beyond configuration metadata, X payloads, stream events, request counters, or error counters outside process memory.
- X payloads can contain public posts, account metadata, private account context, direct-message content, conversation IDs, and stream-matched posts. Treat live output as private or work-zone sensitive unless the host supplies a stricter zone policy.

## Explicit Non-Goals

- No OAuth browser callback server.
- No credential refresh daemon.
- No media upload or chunked media processing surface.
- No browser or web UI automation.
- No durable compliance archive.
- No moderation workflow.
- No replayable stream storage.
- No downstream data-use enforcement.
- No automatic developer-account or app provisioning.
- No cross-zone social fanout.

## Verification

README-only changes do not require Cargo or `rch` verification. Before committing this file, run:

```bash
git diff --check -- connectors/twitter/README.md
LC_ALL=C rg -n '[^ -~]' connectors/twitter/README.md
rg -n '\bmaster\b' connectors/twitter/README.md
ubs connectors/twitter/README.md
```

For code changes in this connector, use the workspace-required proof lane from the root `AGENTS.md`:

```bash
rch exec -- cargo check --workspace --all-targets
rch exec -- cargo clippy --workspace --all-targets -- -D warnings
rch exec -- cargo fmt --check
```
