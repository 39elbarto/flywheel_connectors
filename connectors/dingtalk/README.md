# DingTalk Connector V3 Contract

> **Status**: accepted runtime contract with host-forwarded Stream Mode supervision
> **Bead**: `flywheel_connectors-j05nu.1.13.1`
> **Unblocks**:
> - `flywheel_connectors-j05nu.1.13.2`
> - `flywheel_connectors-j05nu.1.13.6`
> **Follow-on beads**:
> - `flywheel_connectors-j05nu.1.13.3`
> - `flywheel_connectors-j05nu.1.13.4`
> - `flywheel_connectors-j05nu.1.13.5`
> - `flywheel_connectors-j05nu.1.13.7`
> - `flywheel_connectors-j05nu.1.13.8`
> **Primary upstreams**:
> - https://open.dingtalk.com/document/tutorial/create-a-robot
> - https://open.dingtalk.com/

## Purpose

This document fixes the accepted V3 runtime contract for `fcp.dingtalk` so follow-on runtime and capability beads can converge on a stable boundary instead of treating "DingTalk enterprise messaging" as an open-ended bucket that mixes outbound robot sends, token bootstrap, Stream Mode transport ownership, admin provisioning, and collaboration sync.

The current connector is a DingTalk robot surface for outbound text, link, and file sends, media upload, credential health verification, callback normalization, and host-forwarded Stream Mode frame supervision. It does not open or own the DingTalk public Stream Mode WebSocket; a host bridge forwards signed SDK frames into `dingtalk.stream.ingest_message`, and accepted frames can cache a validated `session_webhook` for `dingtalk.stream.reply`.

## Current Runtime Snapshot

The current crate exposes these operations:

- `dingtalk.messages.send_text`
- `dingtalk.messages.send_link`
- `dingtalk.messages.send_file`
- `dingtalk.media.upload`
- `dingtalk.events.normalize`
- `dingtalk.stream.ingest_message`
- `dingtalk.stream.reply`
- `dingtalk.health`

Important implementation truths from `connector.rs`, `main.rs`, and `manifest.toml`:

- Configuration is `base_url`, `media_base_url`, `client_id`, `client_secret`, bounded `request_timeout_ms`, and explicit Stream Mode policy fields: `stream_mode_enabled`, DM/group gates, mention-required behavior, allowed users, free-response chats, mention patterns, replay cache size, session-webhook cache size, session-webhook expiry safety margin, and reply timeout.
- One connector instance is bound to one DingTalk app credential pair and therefore one robot identity as modeled by the current runtime.
- Authentication is app-level token bootstrap against `POST /v1.0/oauth2/accessToken`; the access token is cached in memory only.
- Group sends go through `/v1.0/robot/groupMessages/send` using `openConversationId`.
- Direct sends go through `/v1.0/robot/oToMessages/batchSend` using one supplied user ID at a time.
- Media upload uses the separate `oapi.dingtalk.com` host and the legacy `/media/upload` flow with `access_token` and `type` in query parameters.
- `health` and `self_check()` are both grounded in token issuance, not in a separate provider health endpoint.
- `main.rs` accepts `subscribe` and `unsubscribe` RPC methods because of the shared connector interface, but the connector advertises `streaming = false`: it supervises host-forwarded Stream Mode frames rather than owning a long-lived DingTalk WebSocket transport.
- When `stream_mode_enabled = true`, handshake and introspection advertise replay support using the configured replay cache size. When it is false, stream ingest/reply fail closed and EventCaps do not claim replay.
- Crate-local tests cover connector-suite request/response behavior plus a no-mock loopback Stream Mode harness that writes JSONL evidence for policy, duplicate, reply, rate-limit, timeout, and shutdown paths.

## Accepted First Slice

The accepted first DingTalk slice is intentionally narrow:

- send one text or markdown-style robot message to one direct user target or one group conversation target
- send one link-style robot message to one direct user target or one group conversation target
- send one file message using a previously acquired `media_id`
- upload one media object to obtain a `media_id`
- normalize one DingTalk robot callback event
- policy-gate and normalize one host-forwarded Stream Mode message frame
- reply through a cached or explicitly forwarded DingTalk `session_webhook`
- expose a safe token-issuance health probe

This slice is intentionally closer to "outbound robot automation" than to "full DingTalk collaboration integration."

## Service Inventory

| Surface | Status in first slice | Notes |
|---------|-----------------------|-------|
| Outbound robot messaging | In scope | Text, link, and file sends are implemented. |
| Media upload | In scope | Upload is implemented so later send flows can reference a `media_id`. |
| Credential and reachability probe | In scope | `health` and `self_check()` verify token issuance. |
| Stream frame supervision | In scope | Host-forwarded frames are policy-gated, deduplicated, normalized, and optionally emitted as `dingtalk.message` EventEnvelope JSON. |
| Stream WebSocket transport ownership | Out of scope | The connector does not own the public DingTalk WebSocket client, reconnect loop, or SDK listener. The host bridge owns transport and forwards frames. |
| Chat discovery and conversation listing | Out of scope | The caller must already know the target user ID or `openConversationId`. |
| Message history and readback | Out of scope | The connector does not fetch prior messages or conversation state. |
| User directory and org reads | Out of scope | No user profile, org, or directory APIs are exposed in this first slice. |
| Bot provisioning and tenant admin | Out of scope | The connector does not install apps, create robots, or manage tenant policy. |

## Auth And Scope Boundary

- One connector instance maps to one DingTalk app credential pair.
- Authentication is `client_id` + `client_secret`, exchanged against `POST /v1.0/oauth2/accessToken`.
- The connector caches the access token in memory only; no token material is persisted to disk.
- The runtime acts as the configured app or robot only. It does not impersonate arbitrary users and does not model delegated user OAuth.
- Stable first-slice target identifiers are:
  - direct user IDs, passed either as bare strings or as `user:<userid>`
  - group conversation IDs, passed as `chat:<openConversationId>`
  - `media_id` values returned by upload flows
- The current runtime treats `client_id` as the `robotCode` for send operations.
- The connector does not create or install the robot into chats. Provisioning the app, granting it the required DingTalk permissions, and making it visible in the intended group or direct-message contexts happen out of band.
- The connector does not model cross-tenant brokering, user-granted OAuth, token rotation workflows, or secretless credential injection in this first slice.

## Network And Runtime Invariants

- Production auth and message host: `api.dingtalk.com`
- Production media upload host: `oapi.dingtalk.com`
- Production session-webhook reply hosts: `api.dingtalk.com` and `oapi.dingtalk.com`
- Port: `443`
- TLS + SNI required for live traffic
- Send and health operations declare per-operation egress only to `api.dingtalk.com`
- Media upload and Stream Mode reply operations declare per-operation egress only to `api.dingtalk.com` and `oapi.dingtalk.com`
- Callback normalization and Stream Mode ingest are connector-local and declare a no-egress sentinel
- `localhost` and `127.0.0.1` remain accepted only in connector configuration for deterministic test harnesses, not in production manifest egress constraints
- The runtime does not open inbound listeners and does not own DingTalk's WebSocket Stream Mode transport
- Host-forwarded stream frames use bounded in-memory replay/session-webhook state owned by the connector instance
- Session webhook URLs are validated against DingTalk reply hosts, reject userinfo, and use HTTPS outside explicit localhost test seams

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `dingtalk.messages.write` | Outbound text, link, and file sends |
| `dingtalk.messages.read` | Callback normalization and Stream Mode frame supervision |
| `dingtalk.media.write` | Media upload for later file-send flows |
| `dingtalk.health.read` | Token issuance probe and readiness check |

## Accepted Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Notes |
|-----------|----------------|------------|------------|-----------|-------------|-------|
| `dingtalk.messages.send_text` | `POST /v1.0/robot/groupMessages/send` or `POST /v1.0/robot/oToMessages/batchSend` | `dingtalk.messages.write` | `Risky` | `Medium` | `None` | Sends one markdown-style message to one group target or one direct user target. |
| `dingtalk.messages.send_link` | `POST /v1.0/robot/groupMessages/send` or `POST /v1.0/robot/oToMessages/batchSend` | `dingtalk.messages.write` | `Risky` | `Medium` | `None` | Sends one link-style card to one known target. |
| `dingtalk.messages.send_file` | `POST /v1.0/robot/groupMessages/send` or `POST /v1.0/robot/oToMessages/batchSend` | `dingtalk.messages.write` | `Risky` | `Medium` | `None` | Sends a file-backed message using a previously returned `media_id`. |
| `dingtalk.media.upload` | `POST /media/upload?access_token=...&type=...` | `dingtalk.media.write` | `Risky` | `Medium` | `BestEffort` | Uploads bytes and returns provider media metadata; exact-once semantics are not guaranteed. |
| `dingtalk.events.normalize` | Local normalization | `dingtalk.messages.read` | `Safe` | `Low` | `Strict` | Converts a DingTalk robot callback/stream frame into normalized message metadata. |
| `dingtalk.stream.ingest_message` | Host-forwarded Stream Mode frame | `dingtalk.messages.read` | `Safe` | `Low` | `Strict` | Applies enablement, sender, DM/group, mention, duplicate, media-bound, and session-webhook policy before emitting EventEnvelope JSON. |
| `dingtalk.stream.reply` | `POST <sessionWebhook>` | `dingtalk.messages.write` | `Risky` | `Medium` | `None` | Sends a markdown reply through a validated cached or explicitly supplied Stream Mode session webhook. |
| `dingtalk.health` | `POST /v1.0/oauth2/accessToken` | `dingtalk.health.read` | `Safe` | `Low` | `Strict` | Safe credential and reachability probe backed by token issuance. |

## Explicit Non-Goals

The accepted first DingTalk slice does not include:

- connector-owned Stream Mode WebSocket sessions
- webhook receipt or signature verification
- chat listing, conversation membership, or message history retrieval
- user directory reads, org graph reads, or contact synchronization
- bot installation, tenant provisioning, or app-admin workflows
- arbitrary multi-user fanout beyond the current direct-user batch-send shape
- media download, attachment readback, or rich content rendering beyond the current file-send path
- delegated user OAuth, token rotation orchestration, or cross-tenant brokering

These are excluded on purpose:

- They materially widen the trust boundary beyond the robot send, media upload, callback normalization, and host-forwarded stream-frame surface already implemented.
- Public WebSocket transport ownership, reconnect backoff, and SDK listener lifecycle remain a separate risk class from host-forwarded frame supervision.
- Admin and provisioning flows are a different risk class from message send and health probe operations.

## Implementation Notes For `flywheel_connectors-j05nu.1.13.2`

- Preserve the one-app, one-robot boundary. Do not widen the runtime into multi-tenant brokering.
- Keep token cache state in memory only and make refresh behavior explicit; token issuance is the central readiness dependency for this connector.
- Factor the current inline HTTP logic into a typed client and explicit error-mapping layer without changing the accepted operation inventory.
- Preserve the split between `base_url` and `media_base_url`; upload and message-send flows currently hit different hosts and should stay explicit.
- Tighten configuration validation around host canonicalization, path or query drift, and timeout bounds rather than allowing silent URL mutation.
- Do not add connector-owned WebSocket streams, chat discovery, or admin APIs as part of the typed-config or client follow-on.

## Source Notes

This contract is grounded in the current connector implementation and DingTalk's public developer entry points:

- `connectors/dingtalk/src/connector.rs` defines the operation inventory, target parsing, auth bootstrap, safety semantics, and health behavior.
- `connectors/dingtalk/src/main.rs` defines the JSON-RPC method surface; `subscribe` and `unsubscribe` remain unsupported because Stream Mode is currently host-forwarded through explicit invoke operations.
- `connectors/dingtalk/manifest.toml` defines the current declared capabilities and basic sandbox posture, even though it still needs a later schema and network-constraint refresh.
- DingTalk robot tutorial: https://open.dingtalk.com/document/tutorial/create-a-robot
- DingTalk open platform entry point: https://open.dingtalk.com/
