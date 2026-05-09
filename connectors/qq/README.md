# QQ Connector V3 Contract

> **Status**: accepted first-slice contract
> **Bead**: `flywheel_connectors-j05nu.1.14.1`
> **Unblocks**:
> - `flywheel_connectors-j05nu.1.14.2`
> - `flywheel_connectors-j05nu.1.14.6`
> **Follow-on beads**:
> - `flywheel_connectors-j05nu.1.14.3`
> - `flywheel_connectors-j05nu.1.14.4`
> - `flywheel_connectors-j05nu.1.14.5`
> - `flywheel_connectors-j05nu.1.14.7`
> - `flywheel_connectors-j05nu.1.14.8`
> **Primary upstreams**:
> - https://bot.q.qq.com/wiki/
> - https://bot.q.qq.com/wiki/develop/api-v2/
> - https://bot.q.qq.com/wiki/develop/api-v2/server-inter/message/send-receive/send.html
> - https://bot.q.qq.com/wiki/develop/api-v2/dev-prepare/error-trace/openapi.html

## Purpose

This document fixes the accepted first V3 slice for `fcp.qq` so the follow-on runtime work converges on the connector that actually exists today instead of a much broader idea of "QQ bot integration" that would mix outbound sends, websocket ingress, passive-reply policy, channel private messages, media flows, and platform administration into one undefined surface.

The current connector is a request-response QQ bot surface for plain-text outbound sends to channel, group, and C2C targets, plus gateway discovery, credential health verification, raw event normalization, and stateful gateway event projection for a host-owned WebSocket loop. It is not yet the component that opens and owns the WebSocket connection itself, nor is it a full passive-reply policy engine, channel-DM connector, media uploader, or general Tencent bot SDK.

## Current Runtime Snapshot

The current crate exposes these operations:

- `qq.messages.send_channel`
- `qq.messages.send_group`
- `qq.messages.send_c2c`
- `qq.gateway.get`
- `qq.health`
- `qq.events.normalize`
- `qq.gateway.project_event`

Important implementation truths from `connector.rs`, `main.rs`, and `manifest.toml`:

- Configuration is `base_url`, `token_base_url`, `app_id`, `client_secret`, and bounded `request_timeout_ms`.
- One connector instance is bound to one QQ bot app identity through one `app_id` / `client_secret` pair.
- Access tokens are fetched with `POST /app/getAppAccessToken` against the token host and cached in memory only with a refresh safety margin.
- Live REST calls use `Authorization: QQBot <token>` against the API host.
- Channel sends call `POST /channels/{channel_id}/messages`.
- Group sends call `POST /v2/groups/{group_openid}/messages`.
- C2C sends call `POST /v2/users/{openid}/messages`.
- The current send bodies only expose plain `content`; they do not surface the broader QQ message-type matrix even though the upstream API supports markdown, ark, embed, keyboard, and media payloads.
- Direct and group sends currently hard-code `msg_type = 0` and `msg_seq = 1`, and only optionally thread through `msg_id`.
- `qq.gateway.get` is a plain `GET /gateway` discovery call. The connector does not actually open the websocket session yet.
- `qq.events.normalize` decodes a raw gateway message dispatch into channel/group/C2C routing, quote context, sender metadata, and attachment presence.
- `qq.gateway.project_event` is the stateful gateway-runtime core: it tracks restored session ID, sequence cursor, heartbeat acknowledgements, duplicate event IDs, queue bounds, group/C2C access policy, and group mention gating before returning `qq.message.authorized` or `qq.event.dropped` projection records. This lets a host-supervised WebSocket worker keep the socket ownership while reusing connector-side security and redaction decisions.
- `qq.health` verifies both token issuance and gateway discovery; `self_check()` is narrower and only validates token issuance.
- `simulate()` validates configuration, handshake, capability, path, and event payload shape; `subscribe()` / `unsubscribe()` still return `StreamingNotSupported`.
- The current crate has inline unit tests for channel-send payload shape, gateway auth-header behavior, and gateway projection state, plus crate-local connector-suite and gateway-projection e2e tests.

## Accepted First Slice

The accepted first QQ slice is intentionally narrow:

- send one plain-text message to one known channel target
- send one plain-text message to one known group target
- send one plain-text message to one known C2C target
- discover the official QQ gateway websocket URL for a higher-level runtime
- expose a safe credential and reachability probe

This slice is intentionally closer to "outbound bot message dispatch plus connectivity primitives" than to "full QQ bot platform integration."

## Service Inventory

| Surface | Status in first slice | Notes |
|---------|-----------------------|-------|
| Channel, group, and C2C text sends | In scope | Implemented as plain-text request-response sends to known identifiers. |
| Gateway discovery | In scope | Implemented as `GET /gateway` so higher layers can later establish websocket ingress. |
| Credential and reachability probe | In scope | `qq.health` issues a token and checks gateway discovery. |
| Websocket connection ownership | Out of scope | No connect/identify/read loop is spawned by this connector slice yet. |
| Gateway event projection | In scope | `qq.gateway.project_event` tracks sequence, session, heartbeat ack, duplicate IDs, bounded queue state, access policy, and group mention gating for host-fed gateway frames. |
| Passive reply policy and event-linked sends | Out of scope | The QQ docs distinguish active vs passive messaging, but the connector does not model `event_id`-driven semantics or policy enforcement. |
| Channel private messages | Out of scope | The upstream `POST /dms/{guild_id}/messages` surface is not implemented. |
| Rich payloads and media | Out of scope | No markdown, ark, embed, keyboard, media upload, voice, or file-send support is exposed in the first slice. |
| Guild, channel, user, or group management | Out of scope | The connector does not list channels, inspect guilds, manage groups, or read user profiles. |

## Auth And Scope Boundary

- One connector instance maps to one QQ bot app identity.
- Authentication is app-level `app_id` + `client_secret`, exchanged for an access token.
- The older QQ bot token model is deprecated in the official docs; the connector uses access-token issuance rather than the deprecated token path.
- Access tokens are cached in memory only and are never persisted to disk by this connector.
- Stable first-slice target identifiers are:
  - `channel_id` for text subchannel sends
  - `group_openid` for group-chat sends
  - `openid` for C2C sends
  - optional `msg_id` values for reply-context linkage when the caller already has one
- The connector does not model user OAuth, delegated user tokens, cross-app brokering, or multi-tenant account switching.
- The connector does not acquire identifiers for the caller; upstream event flows or external provisioning must supply `channel_id`, `group_openid`, or `openid`.
- The connector does not currently encode the platform's active-message, passive-reply, recall, or wake-up policy into capability or input validation. That higher-level policy handling belongs in later beads.

## Gateway Projection Configuration

`gateway` is optional and defaults to disabled for compatibility with the first REST-only slice. When enabled, the connector can project host-fed QQ Bot gateway frames through FCP-owned state and policy:

```json
{
  "gateway": {
    "enabled": true,
    "restore_session_id": "previous-session-id",
    "restore_sequence": 42,
    "heartbeat_interval_ms": 45000,
    "reconnect_backoff_ms": 1000,
    "max_reconnect_attempts": 5,
    "dedupe_window_size": 1024,
    "max_queue_depth": 128,
    "policy": {
      "dm_policy": "open",
      "dm_allow_from": [],
      "group_policy": "allowlist",
      "group_allow_from": ["GROUP_OPENID"],
      "group_require_mention": true,
      "bot_user_id": "BOT_OPENID"
    }
  }
}
```

The projection operation does not log `client_secret`, access tokens, or raw transport credentials. It returns the normalized message payload already present in the incoming gateway frame, a policy decision, and a runtime snapshot with counters and bounded state sizes.

## Network And Runtime Invariants

- Production API host: `api.sgroup.qq.com`
- Production token host: `bots.qq.com`
- Port: `443`
- TLS + SNI required for live traffic
- Send, gateway-discovery, and health operations declare per-operation egress only to `api.sgroup.qq.com` and `bots.qq.com`
- Gateway event normalization and gateway event projection are connector-local and declare a no-egress sentinel
- `localhost` and `127.0.0.1` remain accepted only in connector configuration for deterministic tests or local harnesses, not in production manifest egress constraints
- The runtime remains request-response at the transport boundary
- No inbound listener, webhook server, websocket read loop, or durable connector-local state is part of this slice
- Gateway projection state is in-memory only and intentionally bounded by `gateway.dedupe_window_size` and `gateway.max_queue_depth`
- The connector exposes gateway discovery without consuming the gateway itself; later websocket work must not be assumed already solved just because `qq.gateway.get` exists
- The official send docs explicitly distinguish active vs passive sends and per-scene frequency limits. The current connector does not yet enforce those provider policy rules locally.
- The official docs also note that channel sends require the bot to remain connected to the websocket gateway. The current connector does not manage that online-state requirement yet, so channel send success may depend on external runtime wiring added later.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `qq.messages.write` | Outbound plain-text channel, group, and C2C sends |
| `qq.gateway.read` | Gateway URL discovery for a higher-level ingress runtime |
| `qq.health.read` | Credential and reachability verification |

## Accepted Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Notes |
|-----------|----------------|------------|------------|-----------|-------------|-------|
| `qq.messages.send_channel` | `POST /channels/{channel_id}/messages` | `qq.messages.write` | `Risky` | `Medium` | `None` | Sends plain-text content to one text subchannel. The current connector does not expose richer QQ message types. |
| `qq.messages.send_group` | `POST /v2/groups/{group_openid}/messages` | `qq.messages.write` | `Risky` | `Medium` | `None` | Sends plain-text content to one QQ group target. `msg_id` may be supplied, but full passive-reply semantics are not modeled. |
| `qq.messages.send_c2c` | `POST /v2/users/{openid}/messages` | `qq.messages.write` | `Risky` | `Medium` | `None` | Sends plain-text content to one C2C target. The first slice does not expose wake-up or richer reply fields. |
| `qq.gateway.get` | `GET /gateway` | `qq.gateway.read` | `Safe` | `Low` | `Strict` | Returns the official gateway URL for later websocket ingestion work. |
| `qq.events.normalize` | local decode | `qq.events.read` | `Safe` | `Low` | `Strict` | Normalizes raw QQ Bot gateway message events without mutating runtime state. |
| `qq.gateway.project_event` | local projection | `qq.events.read` | `Safe` | `Low` | `Strict` | Stateful host-fed gateway projection with sequence/replay/policy decisions and redaction-safe runtime snapshot. |
| `qq.health` | `POST /app/getAppAccessToken` then `GET /gateway` | `qq.health.read` | `Safe` | `Low` | `Strict` | Safe auth and reachability probe backed by access-token issuance and gateway discovery. |

## Explicit Non-Goals

The accepted first QQ slice does not include:

- websocket connect, identify, read-loop ownership, or automatic reconnect worker spawning
- channel private-message sends via `/dms/{guild_id}/messages`
- passive-reply policy orchestration using `event_id`, custom `msg_seq`, or reply-window enforcement
- markdown, ark, embed, keyboard, media, voice, or file payload support
- media upload and attachment download flows
- channel, guild, group, or user discovery and management APIs
- moderation, permission-application, or admin review workflows
- local enforcement of QQ per-scene send quotas or proactive-message policy
- multi-app brokering, delegated user auth, or cross-tenant routing

These are excluded on purpose:

- The current runtime is a small REST wrapper plus token bootstrap, not a full QQ bot session runtime.
- The official platform semantics for active vs passive messages and channel-online requirements are subtle enough that they should be introduced explicitly in later beads instead of being hidden inside the first contract.
- Gateway discovery is useful on its own, but websocket ingress, event normalization, and message-policy handling deserve their own beads and their own capability boundaries.

## Implementation Notes For `flywheel_connectors-j05nu.1.14.2`

- Preserve the one-app, one-bot boundary. Do not widen the connector into a multi-app router.
- Keep `base_url` and `token_base_url` explicit; token issuance and API dispatch are separate surfaces in the current runtime.
- Keep access-token caching in memory only, and make expiry / refresh behavior explicit in the typed client layer.
- Keep identifier families explicit: `channel_id`, `group_openid`, and `openid` are not interchangeable.
- Do not silently broaden the current send surface into markdown, media, or websocket-driven reply semantics as part of the client refactor.
- If channel sends require an active websocket session for trustworthy operation, surface that clearly in readiness and runtime guidance rather than leaving it as an undocumented upstream gotcha.
- Error mapping should preserve provider HTTP status and QQ business-code detail where available instead of collapsing everything into generic external failures.

## Source Notes

This contract is grounded in the current connector implementation and the official QQ bot documentation:

- `connectors/qq/src/connector.rs` defines the current operation inventory, input schema, access-token flow, and gateway / health behavior.
- `connectors/qq/src/main.rs` confirms the connector is currently a request-response JSON-RPC loop with no streaming implementation.
- `connectors/qq/manifest.toml` defines the current capability families, zone posture, and sandbox profile.
- QQ bot start guide and access-ticket docs describe the AppID / AppSecret model and the deprecation of the older token path.
- QQ's send-message docs define the C2C, group, channel, and channel-DM endpoint families plus the platform's active / passive send rules and rate-limit constraints.
- QQ's OpenAPI error docs describe the layered HTTP + business-code failure model that follow-on error mapping should preserve.
