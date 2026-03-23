# Nostr Connector V3 Contract

> **Status**: accepted first-slice contract
> **Bead**: `flywheel_connectors-j05nu.1.15.1`
> **Unblocks**:
> - `flywheel_connectors-j05nu.1.15.2`
> - `flywheel_connectors-j05nu.1.15.6`
> **Follow-on beads**:
> - `flywheel_connectors-j05nu.1.15.3`
> - `flywheel_connectors-j05nu.1.15.4`
> - `flywheel_connectors-j05nu.1.15.5`
> - `flywheel_connectors-j05nu.1.15.7`
> - `flywheel_connectors-j05nu.1.15.8`
> **Primary upstreams**:
> - https://github.com/nostr-protocol/nips
> - https://nips.be/

## Purpose

This document fixes the accepted first V3 slice for `fcp.nostr` so the follow-on runtime work converges on the connector that actually exists today instead of the much broader parent feature idea of a "Nostr Relay DM Connector" that would mix encrypted DMs, relay-session management, profile metadata, scoring, dedupe, and relay policy control into one undefined surface.

The current connector is a request-response relay client for public-note publishing, bounded public-event queries, relay inspection, and health verification. It is not yet an encrypted DM connector, long-lived subscription runtime, relay-health scoring engine, profile publisher, or relay-policy manager.

## Current Runtime Snapshot

The current crate exposes these operations:

- `nostr.notes.publish`
- `nostr.events.query`
- `nostr.relays.list`
- `nostr.health`

Important implementation truths from `connector.rs`, `main.rs`, and `manifest.toml`:

- Configuration is `relay_urls`, `secret_key_hex`, bounded `request_timeout_ms`, and `default_query_limit`.
- One connector instance is bound to one raw secp256k1 secret key and therefore one derived x-only public key.
- The connector expects `secret_key_hex` as raw hex. It does not accept bech32 `nsec` input.
- Signing happens locally in-process; the connector derives `public_key_hex` and keeps the configured secret key in memory only.
- `nostr.notes.publish` signs one kind-`1` note locally and sends `["EVENT", <event>]` to every configured relay.
- `nostr.notes.publish` accepts optional `tags`, but the first-slice runtime now rejects non-note kinds so the capability boundary stays aligned with `nostr.notes.write`.
- `nostr.events.query` opens one websocket per configured relay, sends one bounded `["REQ", <sub_id>, <filter>]` query, collects `EVENT` frames until `EOSE`, then closes the session.
- Query results are returned per relay. The connector does not deduplicate the same event across relays.
- `nostr.relays.list` returns the configured relay list and the derived public key. It does not perform discovery or mutation.
- `nostr.health` opens and closes each configured relay and reports reachability alongside the derived public key.
- `main.rs` accepts `subscribe` and `unsubscribe` because of the shared connector interface, but the connector advertises `streaming = false` and returns `StreamingNotSupported` for both methods.
- The current crate has inline unit tests only. There is no crate-local `tests/` directory yet.
- The parent feature talks about encrypted DMs and profile metadata, but the current runtime does not implement those surfaces. This contract deliberately captures the narrower surface that exists now.

## Accepted First Slice

The accepted first Nostr slice is intentionally narrow:

- publish one signed public note to the configured relay set
- query bounded public events from the configured relay set
- inspect the configured relay allowlist and derived public key
- expose a safe relay reachability and signing-identity probe

This slice is intentionally closer to "public-note publish plus public-query primitives" than to "full Nostr DM and profile integration."

## Service Inventory

| Surface | Status in first slice | Notes |
|---------|-----------------------|-------|
| Public-note publishing | In scope | Implemented by locally signing and fanout-publishing one kind-1 note to all configured relays. |
| Public-event queries | In scope | Implemented as bounded `REQ` / `EOSE` queries with per-relay results. |
| Relay inspection | In scope | Exposes the configured relay allowlist and derived public key. |
| Relay reachability probe | In scope | `nostr.health` opens and closes each configured relay. |
| Encrypted DMs | Out of scope | No NIP-04 or NIP-17 construction, encryption, publication, sync, or decryption exists yet. |
| Long-lived subscriptions | Out of scope | No persistent websocket session, replay cursor, reconnect loop, or event stream surface exists yet. |
| Relay dedupe and health scoring | Out of scope | Results are per relay and the runtime does not score or rank relay quality. |
| Profile metadata and relay policy changes | Out of scope | No NIP-01 profile metadata publication, relay-list publication, or relay mutation controls are exposed. |

## Auth And Scope Boundary

- One connector instance maps to one raw secp256k1 secret key and one static relay allowlist.
- Authentication is local key custody, not OAuth, delegated user auth, or remote token exchange.
- The connector signs locally with `secret_key_hex` and derives `public_key_hex` from that key.
- The configured secret key is expected as raw hex, not `nsec`.
- The connector keeps the secret key in memory only. It does not persist derived or raw key material to disk.
- The current runtime acts only as the configured keypair. It does not impersonate arbitrary users or multiplex multiple identities.
- `relay_urls` are the effective network boundary in the first slice. The runtime currently accepts any operator-supplied `ws://` or `wss://` relay URL and does not maintain a separate built-in host allowlist.
- The connector does not negotiate authenticated relay sessions, manage relay credentials, or model operator-approved relay policy changes.

## Network And Runtime Invariants

- Relay URLs must use `ws://` or `wss://`
- `wss://` should be considered the live-production path; `ws://` is primarily useful for deterministic local harnesses
- The runtime is request-response only
- No inbound listener, long-lived subscription loop, replay buffer, dedupe store, or durable connector-local state is part of the accepted slice
- Querying is bounded by `default_query_limit` unless the caller supplies an explicit `limit`
- Publish fanout currently targets every configured relay; there is no per-request relay override or policy filter
- Health proves websocket reachability and local key derivation, not encrypted DM support or relay-policy correctness

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `nostr.notes.write` | Publish one signed public note to configured relays |
| `nostr.events.read` | Query bounded public events from configured relays |
| `nostr.relays.read` | Inspect the configured relay set and derived public key |
| `nostr.health.read` | Relay reachability and signing-identity verification |

## Accepted Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Notes |
|-----------|----------------|------------|------------|-----------|-------------|-------|
| `nostr.notes.publish` | websocket `["EVENT", <event>]` per relay | `nostr.notes.write` | `Risky` | `Medium` | `None` | Publishes one locally signed kind-1 public note to every configured relay. The first slice does not construct encrypted DMs or publish other event kinds. |
| `nostr.events.query` | websocket `["REQ", <sub_id>, <filter>]` until `EOSE` | `nostr.events.read` | `Safe` | `Low` | `Strict` | Executes one bounded public-event query across configured relays with per-relay results and no dedupe. |
| `nostr.relays.list` | local inspection only | `nostr.relays.read` | `Safe` | `Low` | `Strict` | Returns configured relay URLs and the derived public key. |
| `nostr.health` | websocket connect / close per relay | `nostr.health.read` | `Safe` | `Low` | `Strict` | Safe readiness probe backed by relay reachability and local signing identity derivation. |

## Explicit Non-Goals

The accepted first Nostr slice does not include:

- NIP-04 or NIP-17 encrypted DM construction, publish, sync, or decrypt flows
- publication of non-note event kinds such as profile metadata or contact-list writes
- long-lived websocket subscriptions, replay cursors, reconnect loops, or event streaming
- relay-health scoring, ranked routing, or cross-relay dedupe
- profile metadata publication or relay-list publication
- per-request relay override, relay discovery, or relay policy mutation
- bech32 `nsec` parsing, key derivation UX, or alternative key-storage backends
- inbound moderation, relay admin, or authenticated relay management

These are excluded on purpose:

- The current runtime is a small note-publish and public-query client, not a full Nostr session manager.
- The parent feature's encrypted-DM ambition belongs to later beads and should not be implied by the current operation inventory.
- Key-custody and relay-allowlist boundaries need to be made explicit before any DM or session-runtime work is layered on top.

## Implementation Notes For `flywheel_connectors-j05nu.1.15.2`

- Preserve the one-key, one-relay-set boundary. Do not widen the connector into a multi-identity router.
- Keep the local secp256k1 signing path explicit; future secure-key storage can be introduced later, but the typed client layer should truthfully model raw-hex secret-key input today.
- Keep `relay_urls` as explicit operator-supplied configuration. The follow-on state model should treat relay choice as a first-class allowlist, not an incidental string vector.
- Do not silently turn the current bounded query flow into long-lived subscriptions, replay, or DM sync while doing the typed-client refactor.
- Error mapping should preserve per-relay failures rather than collapsing every relay problem into one opaque connector-level error.

## Source Notes

This contract is grounded in the current connector implementation:

- `connectors/nostr/src/connector.rs` defines the operation inventory, relay interaction model, signing boundary, and current truth about publish/query behavior.
- `connectors/nostr/src/main.rs` confirms the connector is currently a request-response JSON-RPC loop with no streaming implementation.
- `connectors/nostr/manifest.toml` defines the current capability families, zone posture, and sandbox profile.
- The Nostr NIPs repository documents the broader protocol family, including the encrypted-DM and profile surfaces that remain explicit non-goals for this first slice.
