# Mattermost Connector V3 Contract

> **Status**: runtime contract documented; manifest/introspection/API drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Mattermost API reference upstream**: https://api.mattermost.com/
> **Mattermost REST API upstream**: https://developers.mattermost.com/contribute/more-info/server/rest-api/

## Purpose

This document fixes the operator-facing contract for `fcp.mattermost`. The connector exposes the Mattermost API surface currently implemented in this crate: user, team, channel, post, thread, search, reaction, file, direct-message, group-message, slash-command authorization, and websocket monitor events.

The connector is intentionally a bounded Mattermost collaboration bridge. It is not a full workspace-admin API, System Console client, SCIM/LDAP manager, plugin manager, incoming-webhook server, outgoing-webhook server, slash-command route server, OAuth app, channel-provisioning framework, compliance export tool, durable message archive, or cross-workspace federation layer.

## Current Runtime Snapshot

The current crate exposes these runtime operation IDs:

- `mattermost.get_me`
- `mattermost.get_user`
- `mattermost.get_my_teams`
- `mattermost.get_team`
- `mattermost.get_channels_for_team`
- `mattermost.get_channel`
- `mattermost.get_thread`
- `mattermost.create_direct_channel`
- `mattermost.create_post`
- `mattermost.get_post`
- `mattermost.get_posts_for_channel`
- `mattermost.search_posts`
- `mattermost.authorize_slash_command`
- `mattermost.create_reaction`
- `mattermost.delete_reaction`
- `mattermost.get_file_info`
- `mattermost.get_file_link`
- `mattermost.download_file`
- `mattermost.get_file_infos_for_post`
- `mattermost.upload_file`
- `mattermost.delete_post`
- `mattermost.update_post`
- `mattermost.pin_post`
- `mattermost.unpin_post`
- `mattermost.get_reactions_for_post`
- `mattermost.create_group_channel`

Important runtime truths the contract preserves:

- Package, library, and binary name are `fcp-mattermost`.
- Manifest ID is `fcp.mattermost`.
- `BaseConnector` runtime ID is `fcp.mattermost`.
- Manifest version is `0.1.0`.
- Manifest format is `native`.
- Manifest schema version is `2.1`.
- Configuration requires `base_url`.
- Configuration requires exactly one auth mode:
  - `token`
  - `credential_id`
- `token` may be a personal access token or bot access token.
- Direct token mode sends `Authorization: Bearer <token>`.
- Credential-ID mode sends `x-fcp-credential-id: <credential_id>` on REST requests and websocket connections.
- `base_url` is trimmed but not restricted to HTTPS at configure time.
- Default request timeout is 30000 ms.
- `request_timeout_ms` must be greater than zero.
- Configuration also accepts optional `monitor_policy` and `chat_coordination` objects.
- Runtime `handle_configure()` stops websocket mode, parses config, resets subscribed topics, stores monitor/chat coordination policy, initializes the HTTP client/runtime, and marks the base configured.
- Runtime `handle_handshake()` parses a full `HandshakeRequest`, installs a `CapabilityVerifier`, hashes the checked-in manifest, and reports streaming event caps with a minimum buffer of 256 events and no replay.
- Runtime `handshake()` grants every requested capability unfiltered.
- Runtime `handle_health()` reports local configured state plus websocket status, subscribed topics, monitor-policy summary, and monitor-policy audit counters. It does not call Mattermost.
- Runtime `handle_doctor()` calls `GET /api/v4/users/me` when configured and reports websocket connection state.
- Runtime `handle_self_check()` calls `GET /api/v4/users/me`.
- Runtime `handle_invoke()` uses the FCP `InvokeRequest` shape: `operation`, `input`, and `capability_token`.
- Runtime `invoke()` requires configured and handshaken base state and verifies a bound capability token for the operation capability.
- Runtime capability verification currently passes an empty resource URI list for all Mattermost operations.
- Runtime `handle_simulate()` always returns allowed and does not validate operation, input, configuration, handshake, provider state, monitor policy, chat coordination, or capability token.
- Runtime `handle_subscribe()` starts supervised websocket mode and returns confirmed topics, non-replay buffering, connection status, and redacted monitor policy.
- Runtime `handle_shutdown()` stops websocket mode, clears subscribed topics, and calls `shutdown()`.
- Runtime `shutdown()` shuts down the connector runtime and clears the client, but does not clear config, verifier, runtime, configured flag, or handshaken flag.

## Runtime API Adapter

The runtime uses these REST request shapes under `{base_url}/api/v4`:

| Operation | Capability | Required input | Runtime request |
|-----------|------------|----------------|-----------------|
| `mattermost.get_me` | `mattermost.read` | none | `GET /users/me` |
| `mattermost.get_user` | `mattermost.read` | `user_id` | `GET /users/{user_id}` |
| `mattermost.get_my_teams` | `mattermost.read` | none | `GET /users/me/teams` |
| `mattermost.get_team` | `mattermost.read` | `team_id` | `GET /teams/{team_id}` |
| `mattermost.get_channels_for_team` | `mattermost.read` | `team_id` | `GET /users/{user_id}/teams/{team_id}/channels?include_deleted=...`; `user_id` defaults to current user |
| `mattermost.get_channel` | `mattermost.read` | `channel_id` | `GET /channels/{channel_id}` |
| `mattermost.get_thread` | `mattermost.read` | `post_id` | `GET /posts/{post_id}/thread` with optional thread pagination and collapse controls |
| `mattermost.get_post` | `mattermost.read` | `post_id` | `GET /posts/{post_id}` |
| `mattermost.get_posts_for_channel` | `mattermost.read` | `channel_id` | `GET /channels/{channel_id}/posts?page=...&per_page=...` |
| `mattermost.search_posts` | `mattermost.read` | `team_id`, `terms` | `POST /teams/{team_id}/posts/search` |
| `mattermost.authorize_slash_command` | `mattermost.read` | `channel_id`, `user_id`, `command` | Local monitor-policy decision only; no provider HTTP call |
| `mattermost.get_file_info` | `mattermost.read` | `file_id` | `GET /files/{file_id}/info` plus deterministic access paths |
| `mattermost.get_file_link` | `mattermost.read` | `file_id` | `GET /files/{file_id}/link` plus deterministic access paths |
| `mattermost.download_file` | `mattermost.read` | `file_id` | `GET /files/{file_id}` and return base64 content |
| `mattermost.get_file_infos_for_post` | `mattermost.read` | `post_id` | `GET /posts/{post_id}/files/info` plus deterministic access paths |
| `mattermost.get_reactions_for_post` | `mattermost.read` | `post_id` | `GET /posts/{post_id}/reactions` |
| `mattermost.create_direct_channel` | `mattermost.write` | `user_ids` | `POST /channels/direct` with exactly two distinct user IDs |
| `mattermost.create_group_channel` | `mattermost.write` | `user_ids` | `POST /channels/group` with at least three distinct user IDs |
| `mattermost.create_post` | `mattermost.write` | `channel_id`, `message` | `POST /posts`; optionally includes `root_id`, `file_ids`, and `props` |
| `mattermost.update_post` | `mattermost.write` | `id` | `PUT /posts/{id}/patch` |
| `mattermost.pin_post` | `mattermost.write` | `post_id` | `POST /posts/{post_id}/pin` |
| `mattermost.unpin_post` | `mattermost.write` | `post_id` | `POST /posts/{post_id}/unpin` |
| `mattermost.create_reaction` | `mattermost.write` | `user_id`, `post_id`, `emoji_name` | `POST /reactions` |
| `mattermost.delete_reaction` | `mattermost.write` | `user_id`, `post_id`, `emoji_name` | `DELETE /users/{user_id}/posts/{post_id}/reactions/{emoji_name}` |
| `mattermost.upload_file` | `mattermost.write` | `channel_id`, `filename`, `content_base64` | `POST /files` multipart upload |
| `mattermost.delete_post` | `mattermost.write` | `post_id` | `DELETE /posts/{post_id}` |

Websocket behavior:

- `handle_subscribe()` accepts an FCP `SubscribeRequest` and topic list from params.
- If no topics are requested, the connector defaults to:
  - `mattermost.posted`
  - `mattermost.post_edited`
  - `mattermost.post_deleted`
  - `mattermost.reaction_added`
  - `mattermost.reaction_removed`
  - `mattermost.thread_updated`
  - `mattermost.channel_created`
  - `mattermost.channel_updated`
  - `mattermost.channel_deleted`
  - `mattermost.typing`
- Websocket URL is `{base_url}/api/v4/websocket`, with `https://` mapped to `wss://` and `http://` mapped to `ws://`.
- Reconnect backoff starts at 1000 ms and caps at 30000 ms.
- Event buffer capacity is 256.
- Replay is not supported.
- Event acknowledgements are not required.
- The websocket connection sends an auth challenge for direct-token mode and includes auth headers through the websocket config for both supported auth modes.
- Monitor policy can deny websocket events before they become FCP events.

Path, payload, and policy handling:

- Path segments are percent-encoded with a narrow unreserved set instead of rejected.
- `create_direct_channel` requires exactly two distinct non-empty user IDs.
- `create_group_channel` requires at least three distinct user IDs.
- `create_post` requires a non-empty `channel_id`; `message` is required by serde but is not locally checked for non-empty content.
- `create_post` runs chat coordination before sending to Mattermost and returns coordination audit records in the response object.
- `upload_file` requires non-empty `channel_id`, `filename`, and `content_base64`, decodes standard base64, and sends one multipart file.
- `authorize_slash_command` validates stable ASCII identifiers, redacts text/token/response URL/trigger ID in the receipt, and applies the configured monitor policy without opening an HTTP listener.
- Monitor policy defaults to requiring bot mentions in normal channels, allowing direct messages, and rejecting messages outside configured allowed channels or users when those sets are present.
- Monitor policy set fields are capped at 256 items and stable IDs are capped at 128 characters.
- Chat coordination defaults to the in-memory backend. Supported config backends are `agent_mail`, `mesh_gossip`, and `in_memory`.
- Chat coordination supports `enabled`, `ttl_seconds`, `fail_open`, `allowlist_channels`, `backend`, and `dm_mode` (`skip` or `treat_as_thread`).
- REST errors map through the crate error type into FCP errors. Server-side permissions, rate limits, and object visibility are left to Mattermost.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Mattermost documents a broad API v4 surface. Runtime exposes a bounded subset around users, teams, channels, posts, files, reactions, search, slash authorization, and websocket events.
- Runtime does not implement System Console, SCIM, LDAP, plugin, compliance, import/export, admin, OAuth, webhook registration, or workspace provisioning APIs.
- Runtime `authorize_slash_command` is a local authorization helper only. It does not register slash commands, serve HTTP routes, validate Mattermost shared-secret tokens, or call response URLs.
- Runtime websocket subscription is monitor-only. It does not persist an event cursor, replay missed events, or acknowledge events.
- Runtime event topics are normalized FCP topic names such as `mattermost.posted`, not raw provider event names.
- Manifest network constraints use placeholder hosts `*.example.com`, while runtime accepts any trimmed `base_url` and builds requests from it.
- Manifest required capabilities use `network.dns`, `network.egress`, and `network.tls.sni`, while the runtime configure path does not enforce a URL or network policy.
- Runtime accepts `credential_id` and forwards a credential-ID header, but this connector does not itself prove that an egress proxy resolves the credential into a provider token.
- Runtime `health()` is local while `doctor()` and `self_check()` are live `GET /api/v4/users/me` probes.
- Runtime `simulate()` is an allow-all stub.
- Runtime capability verification does not bind user IDs, team IDs, channel IDs, post IDs, file IDs, emoji names, or websocket topics as resource URIs.
- Runtime `handshake()` grants every requested capability unfiltered.
- Runtime `delete_post` declares interactive approval metadata. Other write operations that create, edit, pin, unpin, react, upload, or open channels currently require no interactive approval.
- Runtime `shutdown()` clears the client and websocket state but does not clear config, verifier, runtime, configured flag, or handshaken flag.
- No dedicated tracked verification shell script exists for this connector.

A follow-up parity bead should enforce base URL/network policy before provider calls, prove or remove credential-ID egress injection, add real slash-command token validation if route use is intended, make `simulate()` validate operation/input/capability state, bind capability tokens to Mattermost resource URIs and topics, reconcile approval metadata for all user-visible write operations, add replay/cursor semantics only if a durable event store is introduced, and clear all runtime state on shutdown.

## First-Slice Scope

The current Mattermost README slice documents the existing runtime surface:

- Token and credential-ID configuration
- User, team, channel, post, thread, search, reaction, file, direct-channel, group-channel, slash-authorization, and websocket monitor operations
- Local health, live doctor, live self-check, introspection, simulate, invoke, subscribe, and shutdown behavior
- Monitor policy, chat coordination, websocket supervision, event topics, and buffer behavior
- Capability-token verification and current empty resource-URI binding
- Runtime/manifest/provider-doc drift around broad API v4 coverage, network constraints, credential injection, slash routes, simulation, approvals, replay, and shutdown
- Existing test orientation through manifest schema checks, operation catalog checks, policy tests, chat coordination tests, WireMock-backed REST flows, and websocket subscription tests

## Auth And Zone Boundary

- Authentication mechanisms: direct personal/bot access token or host credential reference.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zone: `z:public`.
- Runtime capability families:
  - `mattermost.read`
  - `mattermost.write`
- Manifest required capabilities are `network.dns`, `network.egress`, and `network.tls.sni`.
- Manifest forbids `system.exec`, `network.listen`, and `system.privileged`.
- The connector does not intentionally persist tokens, credential IDs beyond configuration metadata, users, teams, channels, posts, files, reactions, search results, websocket events, or monitor-policy audit counters outside process memory.
- Mattermost payloads can contain names, email addresses, channel membership, private-channel data visible to the acting account, direct messages, file bodies, post content, mentions, slash-command text, and search terms. Treat live input and output as work-zone sensitive unless the host supplies a stricter zone policy.

## Explicit Non-Goals

- No Mattermost server administration.
- No System Console API.
- No SCIM or LDAP management.
- No plugin management.
- No OAuth app flow.
- No incoming-webhook or outgoing-webhook server.
- No slash-command HTTP listener or command registration.
- No compliance export.
- No channel or team provisioning beyond direct/group-message channel creation.
- No durable message archive.
- No websocket replay.
- No cross-zone workspace publishing.

## Verification

README-only changes do not require Cargo or `rch` verification. Before committing this file, run:

```bash
git diff --check -- connectors/mattermost/README.md
LC_ALL=C rg -n '[^ -~]' connectors/mattermost/README.md
rg -n '\bmaster\b' connectors/mattermost/README.md
ubs connectors/mattermost/README.md
```

For code changes in this connector, use the workspace-required proof lane from the root `AGENTS.md`:

```bash
rch exec -- cargo check --workspace --all-targets
rch exec -- cargo clippy --workspace --all-targets -- -D warnings
rch exec -- cargo fmt --check
```
