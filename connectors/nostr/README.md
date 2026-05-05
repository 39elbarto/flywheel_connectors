# Nostr Connector V3 Contract

> **Status**: accepted request-response contract with outbound DM send and inbound DM stream
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

This document fixes the accepted V3 contract for `fcp.nostr` so follow-on runtime work converges on the connector that actually exists today instead of a broader undefined session manager mixing relay mutation, authenticated relay sessions, and multi-identity routing into one surface.

The current connector is a relay client for public-note publishing, NIP-01 profile publish/state/import management, outbound NIP-04 encrypted DM publishing, inbound NIP-04 DM streaming for the configured identity, bounded public-event queries, relay inspection, relay health scoring, and health verification. It is not a NIP-17 private-DM runtime, relay-policy manager, or general multi-relay session router.

## Current Runtime Snapshot

The current crate exposes these operations:

- `nostr.notes.publish`
- `nostr.dm.send`
- `nostr.profile.publish`
- `nostr.profile.state`
- `nostr.profile.import`
- `nostr.events.query`
- `nostr.relays.list`
- `nostr.health`
- `nostr.relays.health`
- event stream topic `nostr.dm.inbound`

Important implementation truths from `connector.rs`, `main.rs`, and `manifest.toml`:

- Configuration is `relay_urls`, `secret_key_hex`, bounded `request_timeout_ms`, `default_query_limit`, local-harness relay opt-in, relay circuit-breaker thresholds, and nested `inbound_dm` policy/replay/rate-limit settings.
- One connector instance is bound to one secp256k1 secret key and therefore one derived x-only public key.
- The connector accepts `secret_key_hex` as raw 64-character hex or NIP-19 `nsec`; secrets are redacted in Debug and error paths.
- Signing happens locally in-process; the connector derives `public_key_hex` and keeps the configured secret key in memory only.
- `nostr.notes.publish` signs one kind-`1` note locally and sends `["EVENT", <event>]` to every configured relay.
- `nostr.notes.publish` accepts optional `tags`, but the runtime rejects non-note kinds so the capability boundary stays aligned with `nostr.notes.write`.
- `nostr.dm.send` normalizes `recipient`, `recipient_pubkey`, or `target` from raw hex, NIP-19 `npub`, or `nostr:npub`, encrypts `plaintext`/`content` with NIP-04 AES-256-CBC, signs a kind-`4` event with a recipient `p` tag, and sends `["EVENT", <event>]` to every configured relay.
- DM operation output returns event id, kind, sender/recipient public metadata, tags, and per-relay delivery diagnostics; it intentionally omits plaintext and encrypted content.
- Self-send DMs are rejected unless `allow_self_send` is explicitly true.
- `nostr.profile.publish` validates a NIP-01 profile object, requires profile URLs to be `https://` and not loopback/private/link-local/`.local`/`.internal`, signs one kind-`0` event with the connector key, fans out to configured relays, and recommends/persists state only after at least one relay accepts.
- `nostr.profile.state` reads connector-owned profile publish state from handshake `zone_dir` when present. It stores public event/profile metadata only.
- `nostr.profile.import` performs bounded kind-`0` relay queries for a public key, verifies event signatures, chooses the newest valid profile, drops unsafe imported URL fields, and can merge imported values into caller-supplied local profile fields without overwriting local values.
- `nostr.events.query` opens one websocket per configured relay, sends one bounded `["REQ", <sub_id>, <filter>]` query, collects `EVENT` frames until `EOSE`, then closes the session.
- Query filters accept author keys as raw hex, NIP-19 `npub`, or `nostr:npub`, then send canonical hex to relays.
- Query results are returned per relay. The connector does not deduplicate the same event across relays.
- `nostr.relays.list` returns the configured relay list and the derived public key. It does not perform discovery or mutation.
- `nostr.health` opens and closes each configured relay and reports reachability alongside the derived public key.
- `nostr.relays.health` scores configured relays with latency, NIP-04/NIP-44 probe results, and circuit-breaker state.
- `subscribe` accepts only the explicit `nostr.dm.inbound` topic, issues relay filters for kind-`4` events tagged to the connector public key, applies the configured inbound DM policy, decrypts accepted NIP-04 DMs, and emits one event envelope per accepted DM.
- `unsubscribe`, `shutdown`, and reconfigure abort subscription tasks and record structured cancellation diagnostics.
- Event caps advertise `streaming = true`, `replay = false`, no ack requirement, and no host replay buffer. Restart/reconnect duplicate suppression is connector-owned state, not an FCP replay-buffer promise.
- Inbound state is memory-only unless handshake supplies `zone_dir`. With `zone_dir`, the connector persists only cursor timestamps, recent event IDs, public sender buckets, rate counters, and generation counters in `nostr_inbound_dm_state.json`; plaintext, private keys, shared secrets, and ciphertext bodies are never persisted.
- The current crate has inline unit tests and a crate-local no-mock loopback relay integration harness under `tests/`.
- The parent feature talks about NIP-17 private DMs, relay mutation, and broader session ownership. This contract deliberately captures the narrower surface that exists now while including the additive NIP-01 profile surface.

## Accepted Connector Slice

The accepted Nostr connector slice is intentionally narrow:

- publish one signed public note to the configured relay set
- publish one NIP-04 encrypted outbound DM to the configured relay set
- publish/import/read NIP-01 profile metadata through distinct profile operations and capabilities
- query bounded public events from the configured relay set
- inspect the configured relay allowlist and derived public key
- expose a safe relay reachability and signing-identity probe
- score configured relay health and resilience state without mutating relay policy
- subscribe to inbound NIP-04 DMs for the configured public key with bounded replay and rate-limit state

This slice is intentionally closer to "public-note publish plus NIP-01 profile management plus outbound DM send plus inbound NIP-04 stream plus public-query primitives" than to "NIP-17 and relay-policy integration."

## Service Inventory

| Surface | Status in current slice | Notes |
|---------|-----------------------|-------|
| Public-note publishing | In scope | Implemented by locally signing and fanout-publishing one kind-1 note to all configured relays. |
| Outbound encrypted DMs | In scope | Implemented by NIP-04 encrypting plaintext, signing one kind-4 event with a recipient `p` tag, and fanout-publishing it to all configured relays. |
| Profile metadata | In scope | Implemented as separate NIP-01 kind-0 publish, local state, and bounded import operations with URL safety and monotonic publish timestamps. |
| Public-event queries | In scope | Implemented as bounded `REQ` / `EOSE` queries with per-relay results. |
| Relay inspection | In scope | Exposes the configured relay allowlist and derived public key. |
| Relay reachability probe | In scope | `nostr.health` opens and closes each configured relay. |
| Relay health scoring | In scope | `nostr.relays.health` reports latency, NIP kind-support probes, and resilience state for the configured allowlist. |
| Inbound encrypted DM stream | In scope | NIP-04 kind-4 relay subscriptions for the configured public key, with decrypt, policy, recent-ID replay suppression, cursor state, rate-limit diagnostics, and redacted durable state when `zone_dir` is present. |
| Long-lived subscriptions | Partially in scope | The connector exposes `subscribe`/`unsubscribe` for inbound DMs. It does not yet own an unbounded reconnect loop or host replay buffer. |
| Cross-relay dedupe and relay mutation | Partial / out of scope | Inbound DM recent IDs suppress duplicate accepted events across relay tasks. Public query results remain per relay, and the runtime does not discover, add, remove, or mutate relays. |
| Relay-list publication and relay policy changes | Out of scope | No relay-list publication or relay mutation controls are exposed. |

## Auth And Scope Boundary

- One connector instance maps to one secp256k1 secret key and one static relay allowlist.
- Authentication is local key custody, not OAuth, delegated user auth, or remote token exchange.
- The connector signs locally with `secret_key_hex` and derives `public_key_hex` from that key.
- The configured secret key may be raw 64-character hex or NIP-19 `nsec`; both normalize to the same in-memory secret scalar.
- Peer public keys in query filters and outbound DMs may be raw hex, NIP-19 `npub`, or `nostr:npub`; relay filters/events use canonical x-only hex.
- The connector keeps the secret key in memory only. It does not persist derived or raw key material to disk.
- The current runtime acts only as the configured keypair. It does not impersonate arbitrary users or multiplex multiple identities.
- `relay_urls` are the effective network boundary in the request-response slice. Production relay URLs must be public `wss://`; local/private `ws://` and `wss://` relays require explicit local-harness opt-in.
- The connector does not negotiate authenticated relay sessions, manage relay credentials, or model operator-approved relay policy changes.

## Network And Runtime Invariants

- Relay URLs must use `ws://` or `wss://`
- `wss://` should be considered the live-production path; `ws://` is primarily useful for deterministic local harnesses
- The runtime has request-response operations plus one explicit inbound DM stream topic
- Inbound DM subscriptions use outbound WebSocket relay connections only; there is no inbound listener
- Durable inbound DM replay/rate state is connector-owned only when the host provides `zone_dir`; otherwise state is memory-only and diagnostics say so
- Host replay remains unsupported: event caps report `replay = false` and `min_buffer_events = 0`
- Querying is bounded by `default_query_limit` unless the caller supplies an explicit `limit`
- Publish fanout currently targets every configured relay; there is no per-request relay override or policy filter
- DM publish fanout currently targets every configured relay; there is no per-request relay override or policy filter
- Health proves websocket reachability and local key derivation, while `nostr.relays.health` probes relay kind support and resilience state

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `nostr.notes.write` | Publish one signed public note to configured relays |
| `nostr.dm.write` | Encrypt and publish one NIP-04 direct message to configured relays |
| `nostr.profile.write` | Publish one signed NIP-01 profile metadata event to configured relays |
| `nostr.profile.read` | Read connector-owned profile state and import verified public profile metadata from configured relays |
| `nostr.events.read` | Query bounded public events and subscribe to inbound NIP-04 DM events for the configured identity |
| `nostr.relays.read` | Inspect the configured relay set and derived public key |
| `nostr.health.read` | Relay reachability and signing-identity verification |

## Accepted Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Notes |
|-----------|----------------|------------|------------|-----------|-------------|-------|
| `nostr.notes.publish` | websocket `["EVENT", <event>]` per relay | `nostr.notes.write` | `Risky` | `Medium` | `None` | Publishes one locally signed kind-1 public note to every configured relay. It stays separate from encrypted DM sends and rejects other event kinds. |
| `nostr.dm.send` | websocket `["EVENT", <kind-4 event>]` per relay | `nostr.dm.write` | `Risky` | `High` | `None` | Encrypts plaintext with NIP-04, signs one kind-4 event with a recipient `p` tag, returns public event metadata and per-relay diagnostics, and omits plaintext/ciphertext from operation output. |
| `nostr.profile.publish` | websocket `["EVENT", <kind-0 event>]` per relay | `nostr.profile.write` | `Risky` | `Medium` | `None` | Validates profile fields and URL safety, signs one kind-0 event, fans out to configured relays, and persists publish state only after relay acceptance. |
| `nostr.profile.state` | local inspection only | `nostr.profile.read` | `Safe` | `Low` | `Strict` | Returns last profile event id, timestamp, per-relay publish results, and profile fields from connector-owned state. |
| `nostr.profile.import` | websocket `["REQ", <sub_id>, <kind-0 filter>]` until `EOSE` | `nostr.profile.read` | `Safe` | `Low` | `Strict` | Imports the newest verified kind-0 profile from configured relays, drops unsafe URL fields, and returns display-sanitized/merge-ready profile data. |
| `nostr.events.query` | websocket `["REQ", <sub_id>, <filter>]` until `EOSE` | `nostr.events.read` | `Safe` | `Low` | `Strict` | Executes one bounded public-event query across configured relays with per-relay results and no dedupe. |
| `nostr.relays.list` | local inspection only | `nostr.relays.read` | `Safe` | `Low` | `Strict` | Returns configured relay URLs and the derived public key. |
| `nostr.health` | websocket connect / close per relay | `nostr.health.read` | `Safe` | `Low` | `Strict` | Safe readiness probe backed by relay reachability and local signing identity derivation. |
| `nostr.relays.health` | websocket connect + bounded kind probes per relay | `nostr.health.read` | `Safe` | `Low` | `Strict` | Relay scoring backed by latency, NIP-04/NIP-44 probe support, and resilience state. |

## Explicit Non-Goals

The accepted Nostr slice still does not include:

- NIP-17 private DM construction, sync, or decrypt flows
- publication of non-note event kinds beyond the explicit NIP-01 kind-0 profile surface, such as contact-list writes
- host replay buffers or ack-based replay semantics for inbound DM streams
- unbounded reconnect loops or relay session ownership beyond explicit subscribe calls
- ranked routing, relay mutation, or public-query cross-relay dedupe
- relay-list publication
- per-request relay override, relay discovery, or relay policy mutation
- alternative key-storage backends or multi-identity key custody
- inbound moderation, relay admin, or authenticated relay management

These are excluded on purpose:

- The current runtime is a small note-publish, NIP-01 profile, outbound-DM-send, inbound NIP-04 stream, and public-query client, not a full Nostr session manager.
- The parent feature's NIP-17 and relay/session ambitions belong to later beads and should not be implied by the current operation inventory.
- Key-custody and relay-allowlist boundaries need to be made explicit before any DM or session-runtime work is layered on top.

## Inbound State Contract

- Ownership: connector-owned, scoped to the configured keypair and the handshake `zone_dir`.
- Policy and bounds: `inbound_dm` defaults to open policy, a 4096-entry recent-ID window, a 60-second rate window, 256 global events per window, and 64 events per sender per window. Operators may set `policy_mode = "disabled"`, `"open"`, `"allowlist"`, or `"pairing_equivalent"` plus `allowed_senders`, `stale_after_secs`, `future_skew_secs`, `max_content_bytes`, `seen_event_capacity`, `rate_window_secs`, `global_rate_limit`, and `per_sender_rate_limit`.
- Sender normalization: `allowed_senders` accepts raw 64-character public-key hex, NIP-19 `npub`, or `nostr:npub`; values are normalized to canonical x-only hex before policy checks.
- Durable path: `<zone_dir>/nostr_inbound_dm_state.json`; if `zone_dir` is absent, the connector stays memory-only and diagnostics report `memory_only_no_zone_dir`.
- Cursor semantics: the connector stores the latest accepted inbound DM `created_at` timestamp and uses the maximum of host `since` and connector cursor for the next relay filter. Event caps still advertise `replay = false` because this is relay-filter resume plus local duplicate suppression, not a host replay buffer.
- Recent IDs: the connector keeps a bounded oldest-evicting recent-ID window so inclusive relay replays and restart replays can be suppressed without unbounded memory growth.
- Rate limits: global and per-sender counters are kept with the same state snapshot and surfaced through diagnostics with bucket before/after values, scope, retryability, and `retry_after_ms`.
- Privacy: durable state and diagnostics contain event IDs, public sender keys, cursor timestamps, counters, and relay URLs only. They do not contain plaintext, private keys, shared secrets, or ciphertext bodies.
- Reset behavior: reconfigure and shutdown clear in-memory subscription tasks; durable state remains as replay/rate evidence for the same configured identity unless the operator changes `zone_dir` or the configured public key changes. Public-key mismatch resets loaded state rather than applying another identity's cursor.

## Implementation Notes

- Preserve the one-key, one-relay-set boundary. Do not widen the connector into a multi-identity router.
- Keep the local secp256k1 signing path explicit; future secure-key storage can be introduced later, but the typed client layer should truthfully model raw-hex and NIP-19 `nsec` secret-key input today.
- Keep `relay_urls` as explicit operator-supplied configuration. The follow-on state model should treat relay choice as a first-class allowlist, not an incidental string vector.
- Keep bounded public queries separate from inbound DM streams. Public query results are per relay; inbound DM stream state is private to the configured identity.
- Keep inbound DM policy, replay, and rate-limit settings in connector configuration rather than per-subscription request parameters so callers cannot silently widen acceptance policy at subscribe time.
- Preserve the no-mock loopback e2e proof for `nostr.dm.inbound`; it must continue to cover allowlist acceptance, invalid signatures, wrong targets, policy blocks, per-sender and global rate limits, reconnect/restart replay suppression, reply routing through `nostr.dm.send`, unsubscribe, shutdown, structured JSONL diagnostics, and redaction. Preserve the profile e2e proof for kind-0 publish/import URL safety, partial/all relay failure, monotonic timestamp state, structured JSONL diagnostics, and redaction.
- Error mapping should preserve per-relay failures rather than collapsing every relay problem into one opaque connector-level error.

## Source Notes

This contract is grounded in the current connector implementation:

- `connectors/nostr/src/connector.rs` defines the operation inventory, relay interaction model, signing boundary, and current truth about publish/query behavior.
- `connectors/nostr/src/main.rs` hosts the shared JSON-RPC connector loop; streaming behavior is implemented by `NostrConnector::subscribe` and `NostrConnector::unsubscribe`.
- `connectors/nostr/manifest.toml` defines the current capability families, zone posture, and sandbox profile.
- The Nostr NIPs repository documents the broader protocol family, including the NIP-17 private-DM and relay/session surfaces that remain explicit non-goals for this connector slice.
