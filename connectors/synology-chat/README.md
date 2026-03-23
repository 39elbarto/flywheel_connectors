# Synology Chat Connector V3 Contract

> **Status**: accepted first-slice contract
> **Bead**: `flywheel_connectors-j05nu.1.16.1`
> **Unblocks**:
> - `flywheel_connectors-j05nu.1.16.2`
> - `flywheel_connectors-j05nu.1.16.6`
> **Follow-on beads**:
> - `flywheel_connectors-j05nu.1.16.3`
> - `flywheel_connectors-j05nu.1.16.4`
> - `flywheel_connectors-j05nu.1.16.5`
> - `flywheel_connectors-j05nu.1.16.7`
> **Primary upstreams**:
> - https://www.synology.com/en-id/dsm/7.2/software_spec/chat
> - https://www.synology.com

## Purpose

This document fixes the accepted first V3 slice for `fcp.synology-chat` so follow-on work converges on the connector that actually exists today instead of a broader idea of a full Synology Chat integration with inbound webhook hosting, event normalization, richer reply semantics, and self-hosted deployment guidance already solved.

The current connector is an outbound incoming-webhook client for Synology Chat. It can send plain text, forward a raw webhook payload, and report configuration and health details. It is not yet an outgoing-webhook receiver, slash-command handler, bot platform runtime, or inbound message bridge.

## Current Runtime Snapshot

The current crate exposes these operations:

- `synology_chat.send_message`
- `synology_chat.send_payload`
- `synology_chat.health`

Important implementation truths from `connector.rs`, `client.rs`, `types.rs`, and `manifest.toml`:

- Configuration is `incoming_url`, optional `outgoing_token`, bounded `request_timeout_ms`, and `allow_insecure_ssl`.
- `incoming_url` must be a valid `http://` or `https://` URL and is normalized by trimming surrounding whitespace.
- One connector instance is bound to one incoming webhook delivery target.
- `send_message` requires `text` and optionally accepts `user_id`, `user_ids`, and `bot_name`.
- `user_id` is normalized into a single-entry `user_ids` array; `user_ids` must be an array of non-empty strings.
- `bot_name` is currently translated to the outbound payload field `username`.
- `send_payload` requires a JSON object and forwards it directly to the webhook endpoint for advanced card or attachment shapes.
- Delivery is an outbound `POST` with JSON to the configured incoming webhook URL.
- Non-success HTTP status codes are surfaced as API errors with the provider body preserved.
- Successful empty responses are normalized to `{ "status": "ok" }`; successful non-JSON bodies are wrapped as `{ "status": "ok", "body": "<raw>" }`.
- `health` reports configured target details, manifest hash, `allow_insecure_ssl`, and whether `outgoing_token` is present, but it does not perform a live delivery probe.
- `self_check()` is also configuration-centric: it reports normalized URL and settings but does not call the webhook endpoint.
- A `doctor()` helper exists internally and reports configuration state plus the normalized incoming URL, but it is not yet exposed as an FCP operation.
- The connector stores a `ConnectorRuntime`, but this first slice does not use it for any streaming or inbound server lifecycle.
- `simulate()` always returns allowed, and `subscribe()` / `unsubscribe()` return `StreamingNotSupported`.

## Accepted First Slice

The accepted first Synology Chat slice is intentionally narrow:

- send one plain-text message through one configured incoming webhook
- send one raw JSON webhook payload through the same incoming webhook
- expose safe configuration and readiness metadata for operators

This slice is intentionally closer to "outbound incoming-webhook sender" than to "full Synology Chat connector."

## Service Inventory

| Surface | Status in first slice | Notes |
|---------|-----------------------|-------|
| Plain-text outbound delivery | In scope | Implemented as `send_message` against a configured incoming webhook URL. |
| Raw webhook payload passthrough | In scope | Implemented as `send_payload` for cards or attachment-shaped JSON. |
| Configuration and health reporting | In scope | Implemented without a live webhook round-trip. |
| Incoming webhook hosting | Out of scope | No HTTP listener or outgoing-webhook receive path exists. |
| Inbound event normalization | Out of scope | No room, thread, or sender identity mapping exists. |
| Slash commands, bots, or interactive replies | Out of scope | No command or callback runtime exists. |
| Dedicated file upload flow | Out of scope | Raw payload passthrough exists, but there is no explicit upload or file lifecycle surface. |
| Persistent sync or subscription model | Out of scope | No background runtime or event stream exists. |

## Auth And Scope Boundary

- One connector instance maps to one Synology Chat incoming webhook URL.
- In practice, the incoming webhook URL is the primary credential and capability boundary for outbound delivery.
- `outgoing_token` exists in config and is surfaced in health and self-check output, but it is not used to authenticate any receive path in the current runtime.
- The first slice does not implement incoming webhook validation, outgoing-webhook token verification, slash-command signing, or multi-webhook routing.
- The connector is scoped to `z:work` and `z:project:*` targets rather than community or public zones.
- Host-level placement is intentionally operator-configured because deployments may be public, private, or tailnet-addressed.

## Network And Runtime Invariants

- Transport is outbound HTTP or HTTPS only.
- The reqwest client uses the configured request timeout and may optionally disable certificate verification with `allow_insecure_ssl`.
- The connector does not listen on a socket or expose any inbound service surface.
- `health` and `self_check()` do not currently prove remote webhook reachability; they only prove that configuration was parsed and stored.
- There is no replay buffer, retry queue, dedupe key, webhook signature verifier, or persistent local state in the accepted slice.
- The current implementation is strictly request-response outbound delivery.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `synology_chat.write` | Send messages or raw webhook payloads through the configured incoming webhook |
| `synology_chat.read` | Inspect configuration and health metadata |

## Accepted Operation Inventory

| Operation | Protocol shape | Capability | SafetyTier | RiskLevel | Idempotency | Notes |
|-----------|----------------|------------|------------|-----------|-------------|-------|
| `synology_chat.send_message` | HTTP `POST` JSON webhook body with `text`, optional `user_ids`, optional `username` | `synology_chat.write` | `Risky` | `Medium` | `None` | Outbound plain-text message delivery only. The connector does not model inbound reply semantics. |
| `synology_chat.send_payload` | HTTP `POST` arbitrary JSON object | `synology_chat.write` | `Risky` | `Medium` | `None` | Passes a raw webhook payload through directly for richer provider-specific payloads. |
| `synology_chat.health` | local configuration report | `synology_chat.read` | `Safe` | `Low` | `Strict` | Returns configured URL and settings, but does not perform a live webhook probe. |

## Explicit Non-Goals

The accepted first Synology Chat slice does not include:

- hosting an outgoing webhook receiver
- verifying `outgoing_token` on inbound requests
- inbound message or thread normalization
- slash commands, bot callbacks, or interactive response flows
- durable retries, dedupe, or delivery receipts
- multi-webhook routing or tenant multiplexing
- explicit file upload, attachment hosting, or media lifecycle management
- background streaming or subscription support

These are excluded on purpose:

- The current runtime is an outbound webhook client, not a full bidirectional Synology Chat integration.
- The presence of `outgoing_token` and `ConnectorRuntime` could mislead follow-on work into assuming an inbound surface already exists when it does not.
- Self-hosted deployment guidance and inbound webhook behavior deserve explicit follow-on design instead of being silently implied by the first contract.

## Implementation Notes For `flywheel_connectors-j05nu.1.16.2`

- Preserve the one-webhook, one-instance boundary. Do not silently widen the client into a multi-target router.
- Keep the distinction between outbound incoming-webhook delivery and any future inbound outgoing-webhook receive path explicit in types and capabilities.
- Keep `allow_insecure_ssl` visible and deliberate because it weakens the transport boundary for self-hosted operators.
- Preserve provider response detail in error mapping; HTTP status plus provider body is important for operator diagnosis.
- Do not silently convert `outgoing_token` into an active security guarantee until there is an actual receive surface that uses it.
- Keep `send_message` and `send_payload` distinct: one is a constrained ergonomic helper, the other is a raw provider passthrough.
- If live health probes are added later, make that a deliberate expansion of the contract instead of changing `health` semantics invisibly.

## Source Notes

This contract is grounded in the current connector implementation and the published Synology Chat product surface:

- `connectors/synology-chat/src/connector.rs` defines the current operation inventory, capability mapping, health behavior, and unused-but-present doctor/runtime surfaces.
- `connectors/synology-chat/src/client.rs` defines the outbound webhook HTTP behavior and response normalization.
- `connectors/synology-chat/src/types.rs` defines the current config surface and validation rules.
- `connectors/synology-chat/manifest.toml` defines the work-zone posture, outbound-only capabilities, and intentionally operator-configured network placement.
- Synology's published Chat specs confirm that incoming and outgoing webhooks exist at the product level, but the current connector only implements the incoming-webhook outbound half.
