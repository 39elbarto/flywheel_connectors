# WeCom Connector V3 Contract

> **Status**: accepted first-slice contract
> **Bead**: `flywheel_connectors-j05nu.1.12.1`
> **Unblocks**:
> - `flywheel_connectors-j05nu.1.12.2`
> - `flywheel_connectors-j05nu.1.12.6`
> **Follow-on beads**:
> - `flywheel_connectors-j05nu.1.12.3`
> - `flywheel_connectors-j05nu.1.12.4`
> - `flywheel_connectors-j05nu.1.12.5`
> - `flywheel_connectors-j05nu.1.12.7`
> - `flywheel_connectors-j05nu.1.12.8`
> **Primary upstreams**:
> - https://developer.work.weixin.qq.com/

## Purpose

This document fixes the accepted first V3 slice for `fcp.wecom` so the follow-on runtime and capability work converges on the connector that actually exists today instead of a broader idea of "WeCom enterprise collaboration integration" that would mix outbound app sends, media lifecycle, tenant directory reads, inbound callbacks, websocket delivery, admin provisioning, and org sync into one undefined surface.

The current connector is a request-response WeCom application surface for outbound text and markdown sends, temporary media upload, user lookup, department listing, and credential health verification. It is not yet an inbound event connector, callback-verification service, websocket session runtime, tenant admin SDK, or full WeCom messaging platform abstraction.

## Current Runtime Snapshot

The current crate exposes these operations:

- `wecom.messages.send_text`
- `wecom.messages.send_markdown`
- `wecom.media.upload`
- `wecom.users.get`
- `wecom.departments.list`
- `wecom.health`

Important implementation truths from `connector.rs`, `main.rs`, and `manifest.toml`:

- Configuration is `base_url`, `corp_id`, `agent_id`, `agent_secret`, and bounded `request_timeout_ms`.
- One connector instance is bound to one WeCom tenant application through one `corp_id` / `agent_id` / `agent_secret` tuple.
- Authentication is application-level token bootstrap against `GET /cgi-bin/gettoken`; the access token is cached in memory only with a refresh safety margin.
- Text and markdown sends both call `POST /cgi-bin/message/send`.
- Message sends require at least one WeCom targeting field: `touser`, `toparty`, or `totag`.
- The current send surface only exposes text and markdown payloads. It does not expose WeCom image, news, template-card, task-card, or recall semantics.
- Media upload uses `POST /cgi-bin/media/upload` and returns provider media metadata such as `media_id`.
- `wecom.users.get` calls `GET /cgi-bin/user/get` and requires one `userid`.
- `wecom.departments.list` calls `GET /cgi-bin/department/list` with an optional `id`.
- `wecom.health` and `self_check()` are both grounded in token issuance, not in a separate provider health endpoint.
- `main.rs` accepts `subscribe` and `unsubscribe` RPC methods because of the shared connector interface, but the connector advertises `streaming = false` and both methods return `StreamingNotSupported`.
- The current crate has inline unit tests for configuration validation, message-send payload shape, and media upload behavior, but no crate-local `tests/` directory yet.
- Runtime configuration validation currently allows only `qyapi.weixin.qq.com` plus `localhost` / `127.0.0.1` for deterministic tests. This first slice is deliberately narrower than a generic operator-supplied host model.

## Accepted First Slice

The accepted first WeCom slice is intentionally narrow:

- send one text message to WeCom users, parties, or tags
- send one markdown message to WeCom users, parties, or tags
- upload one temporary media object and return its provider metadata
- fetch one user profile by known `userid`
- list departments, optionally from a supplied department root
- expose a safe credential and reachability probe

This slice is intentionally closer to "tenant-bound enterprise app automation" than to "full WeCom collaboration platform integration."

## Service Inventory

| Surface | Status in first slice | Notes |
|---------|-----------------------|-------|
| Outbound text and markdown sends | In scope | Implemented through the WeCom app send API with explicit target fields. |
| Temporary media upload | In scope | Implemented so later media-aware flows can reference returned provider metadata. |
| User lookup | In scope | Implemented as direct lookup by known `userid`. |
| Department listing | In scope | Implemented as bounded org-structure discovery. |
| Credential and reachability probe | In scope | `wecom.health` and `self_check()` validate token issuance. |
| Inbound callbacks and event delivery | Out of scope | No callback verification, webhook listener, or websocket event pipeline exists yet. |
| Conversation or message history readback | Out of scope | The connector does not fetch prior messages, receipts, or chat state. |
| Rich message families beyond text or markdown | Out of scope | No image, news, template-card, task-card, or recall flows are exposed yet. |
| Tenant admin and provisioning flows | Out of scope | The connector does not create apps, manage secrets, or administer WeCom tenant policy. |
| Broad directory or org sync | Out of scope | The current runtime only exposes one user lookup and one department-list surface. |

## Auth And Scope Boundary

- One connector instance maps to one WeCom tenant application.
- Authentication is application-level `corp_id` + `agent_id` + `agent_secret`, exchanged for an access token.
- The connector caches access tokens in memory only and does not persist token material to disk.
- The runtime acts as the configured enterprise application only. It does not impersonate arbitrary users and does not model delegated user OAuth.
- The operator must provision the WeCom application out of band, keep the app secret available to the connector, and grant the app whatever outbound-send and directory-read privileges are required for the intended tenant workflow.
- Stable first-slice target identifiers are:
  - `touser` for one or more known user IDs
  - `toparty` for one or more known department IDs
  - `totag` for one or more known tag IDs
  - `userid` for direct user-profile lookups
- The current runtime does not discover recipients for the caller. The caller must already know the intended user, department, or tag identifiers.
- The connector does not model cross-tenant brokering, user-granted OAuth, secretless credential injection, callback verification secrets, or message-origin validation in this first slice.

## Network And Runtime Invariants

- Production API host: `qyapi.weixin.qq.com`
- Port: `443`
- TLS + SNI required for live traffic
- `localhost` and `127.0.0.1` are accepted only for deterministic tests
- The runtime is request-response only
- No inbound listener, webhook server, websocket loop, replay buffer, or durable connector-local state is part of the accepted slice
- Health proves credential issuance and basic API reachability, not inbound-event readiness
- Runtime config validation intentionally pins the first slice to the official WeCom API host rather than allowing arbitrary operator-selected endpoints in production
- The host allowlist assumption is part of the security boundary for this first slice: production traffic is constrained to the official WeCom API host, while local harnesses are the only accepted exception

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `wecom.messages.write` | Outbound text and markdown sends |
| `wecom.media.write` | Temporary media upload |
| `wecom.users.read` | User profile lookup by known `userid` |
| `wecom.departments.read` | Department listing |
| `wecom.health.read` | Credential and reachability verification |

## Accepted Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Notes |
|-----------|----------------|------------|------------|-----------|-------------|-------|
| `wecom.messages.send_text` | `POST /cgi-bin/message/send` | `wecom.messages.write` | `Risky` | `Medium` | `None` | Sends one text message to at least one supplied WeCom target family. |
| `wecom.messages.send_markdown` | `POST /cgi-bin/message/send` | `wecom.messages.write` | `Risky` | `Medium` | `None` | Sends one markdown message to at least one supplied target family. |
| `wecom.media.upload` | `POST /cgi-bin/media/upload` | `wecom.media.write` | `Risky` | `Medium` | `BestEffort` | Uploads one temporary media object and returns provider metadata such as `media_id`. |
| `wecom.users.get` | `GET /cgi-bin/user/get` | `wecom.users.read` | `Safe` | `Low` | `Strict` | Fetches one user profile for a known `userid`. |
| `wecom.departments.list` | `GET /cgi-bin/department/list` | `wecom.departments.read` | `Safe` | `Low` | `Strict` | Lists departments with an optional starting `id`. |
| `wecom.health` | `GET /cgi-bin/gettoken` | `wecom.health.read` | `Safe` | `Low` | `Strict` | Safe auth and reachability probe backed by token issuance. |

## Explicit Non-Goals

The accepted first WeCom slice does not include:

- inbound callback verification, webhook receipt, or websocket event streams
- message history readback, thread reconstruction, or receipt tracking
- image, news, template-card, task-card, or other richer message families
- media send flows that consume `media_id` in later outbound message types
- app provisioning, secret rotation, tenant admin, or org-policy management
- broad people or directory synchronization beyond direct user lookup and department listing
- user OAuth, delegated-user auth, or multi-tenant brokering
- runtime enforcement of enterprise policy beyond capability verification and the documented scope boundary

These are excluded on purpose:

- The current runtime is a small tenant-app wrapper with explicit outbound/admin primitives, not a full collaboration or event-ingestion runtime.
- The parent feature's inbound and richer messaging ambitions belong to later beads and should not be implied by the current operation inventory.
- App-provisioning and callback-management flows are a different trust and risk class from bounded outbound messaging and read-only tenant lookup surfaces.

## Implementation Notes For `flywheel_connectors-j05nu.1.12.2`

- Preserve the one-tenant, one-app boundary. Do not widen the runtime into a multi-tenant broker.
- Keep token cache state in memory only and make refresh behavior explicit; token issuance is the central readiness dependency for this connector.
- Keep the first-slice host boundary explicit around `qyapi.weixin.qq.com` for production and deterministic localhost harnesses for tests.
- Preserve the current target model where at least one of `touser`, `toparty`, or `totag` is required for sends.
- Do not silently expand the current runtime into inbound callbacks, richer message families, or user-impersonation flows as part of the typed-config or client refactor.
- Error mapping should preserve provider error detail such as `errcode` / `errmsg` rather than collapsing failures into opaque internal errors.

## Source Notes

This contract is grounded in the current connector implementation:

- `connectors/wecom/src/connector.rs` defines the operation inventory, token bootstrap, input validation, capability boundary, and current truth about send, upload, and lookup behavior.
- `connectors/wecom/src/main.rs` confirms the connector is currently a request-response JSON-RPC loop with no streaming implementation.
- `connectors/wecom/manifest.toml` defines the current capability families, zone posture, sandbox profile, and production host assumptions.
- The WeCom developer portal documents the broader enterprise messaging platform, including the richer outbound and inbound surfaces that remain explicit non-goals for this first slice.
