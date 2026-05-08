# Redis Connector V3 Contract

> **Status**: runtime contract documented; manifest/runtime drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Upstash Redis REST API**: https://upstash.com/docs/redis/features/restapi

## Purpose

This document fixes the operator-facing contract for `fcp.redis`. The connector currently targets an Upstash-compatible Redis REST API surface implemented in this crate: string keys, TTL operations, counters, hashes, lists, and sets.

The connector is intentionally a bounded Redis REST bridge. It is not a Redis protocol client, pub/sub stream consumer, monitor client, pipeline or transaction client, Redis admin client, scan/keyspace browser, module client, ACL manager, backup/restore tool, or general Redis command proxy.

## Current Runtime Snapshot

The current crate exposes these operations:

- `redis.get`
- `redis.set`
- `redis.del`
- `redis.exists`
- `redis.expire`
- `redis.ttl`
- `redis.incr`
- `redis.hget`
- `redis.hset`
- `redis.hgetall`
- `redis.lpush`
- `redis.lrange`
- `redis.sadd`
- `redis.smembers`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-redis`.
- Runtime `BaseConnector` ID is `redis`.
- Manifest and reported connector ID are `fcp.redis`.
- Manifest interface hash is `blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000`.
- Configuration requires exactly one auth source: direct `api_token` or `credential_id`.
- Direct token mode sends `Authorization: Bearer {api_token}`.
- `credential_id` mode sends `X-FCP-Credential-Id` and expects host egress policy to inject real secret material.
- `credential_id` must be a valid UUID.
- `base_url` is optional and defaults to `https://redis.example.com`.
- `base_url` is not validated by `configure`.
- If a non-string `base_url` is provided, runtime silently uses the default URL.
- If an empty string `base_url` is provided, the client can be constructed with an empty endpoint.
- The client trims trailing slashes from `base_url`.
- Runtime request timeout is 30 seconds.
- The client uses the shared retry loop with `max_retries = 2`.
- Every Redis command is sent as one HTTP `POST` to `base_url` with a JSON array command body.
- Runtime `invoke` uses `operation_id`, not `operation`.
- Runtime does not install a `CapabilityVerifier` and does not verify `capability_token`.
- Runtime does not verify approval tokens for write, delete, counter, hash, list, or set operations.
- `simulate` only checks whether `operation_id` is present in the local operation inventory.
- `handle_configure()` does not clear a prior session ID and does not reset the base handshaken flag.
- `handle_handshake()` requires configuration, accepts an optional `session_id`, and returns operation IDs in the `capabilities` array.
- `health()` and `doctor()` consider a handshake complete only when `session_id` is present.
- `handle_shutdown()` shuts down the client runtime and clears config/client/base flags, but leaves `session_id` in memory.
- `self_check()` is a local configured/unconfigured check only; it does not validate `base_url` and does not issue a live Redis command.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- Manifest and runtime operation IDs are aligned, but the interface hash is still the all-zero placeholder.
- Manifest marks write operations as policy-approved and `redis.del` as interactive approval; runtime operation metadata sets `requires_approval = None` for every operation and invoke checks no approval token.
- Manifest network constraints allow only `*.upstash.io` over HTTPS. Runtime accepts any `base_url` string that `reqwest` later accepts, including non-Upstash hosts.
- Manifest says the REST endpoint URL and API token are stored under singleton-writer state. Runtime keeps configuration in process memory and does not persist connector state itself.
- Runtime `self_check()` does not report credential injection readiness or URL readiness.
- Runtime `introspect()` returns only `connector_id`, `version`, and operations, not the full `Introspection` shape with events, resource types, auth caps, or event caps.
- Handshake returns operation IDs such as `redis.get` and `redis.set` in `capabilities`, while manifest capability IDs are `redis.read` and `redis.write`.
- Manifest rate-limit pools are documented intent only; runtime does not enforce connector-local rate limits.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should add capability-token and approval-token verification, replace the placeholder interface hash, align handshake capability grants with capability IDs, validate URL policy at configure or self-check time, reset session and handshake state on reconfigure and shutdown, expose credential readiness, and add a tracked verification bundle.

## First-Slice Scope

The current Redis README slice documents the existing runtime surface:

- direct REST token and host credential-reference configuration
- Upstash-compatible JSON-array command transport
- timeout, retry, response, and provider error mapping
- strings, counters, TTL, hashes, lists, and sets
- simplified handshake, self-check, introspection, and simulation behavior
- deterministic WireMock tests and direct proof commands

## Auth And Scope Boundary

- Authentication mechanisms: REST API token or host credential reference.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Runtime capability surface:
  - `redis.read` gates read metadata, but runtime does not enforce capability tokens.
  - `redis.write` gates write metadata, but runtime does not enforce capability or approval tokens.
- Manifest capability surface:
  - `redis.read`
  - `redis.write`
- The connector does not persist tokens, credential secret material, keys, values, command arrays, provider error bodies, or command results outside process memory.
- Redis values can contain arbitrary application data. Treat live output as work-zone or private-zone data based on the configured database and key namespace.

## Network And Runtime Invariants

- Default endpoint: `https://redis.example.com`; this is a placeholder, not a usable Upstash endpoint.
- Runtime endpoint shape: `POST {base_url}`.
- Runtime command body shape: JSON array such as `["SET", "key", "value", "EX", "60"]`.
- Runtime sends `Content-Type: application/json` and `Accept: application/json`.
- Runtime sends bearer auth in direct token mode.
- Runtime sends `X-FCP-Credential-Id` in credential-reference mode.
- Runtime user agent is `fcp-redis/0.1.0 (FCP connector)`.
- Runtime request timeout: `30 seconds`.
- Runtime retry policy: `max_retries = 2` using the shared retry loop.
- Runtime expects an Upstash-style JSON response with `result` or `error`.
- Upstash-style command errors in a 2xx response are mapped to non-retryable Redis command errors.
- Provider HTTP 401, 403, 429, and other API errors map to typed connector/FCP errors.
- `Retry-After` on 429 is converted to milliseconds; missing values default to 60000 ms.
- Manifest connect timeout is `10000 ms`, operation total timeout is `30000 ms`, and maximum response bytes are `1048576` or `10485760` by operation.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, no exec, and no inbound listener capability.
- The connector does not open inbound sockets, hold Redis TCP connections, subscribe to channels, execute pipelines, or run transactions.

## Operation Inventory

| Operation | Redis command | Capability | SafetyTier | RiskLevel | Idempotency | Required input |
|-----------|---------------|------------|------------|-----------|-------------|----------------|
| `redis.get` | `GET key` | `redis.read` | `Safe` | `Low` | `Strict` | `key` |
| `redis.set` | `SET key value [EX seconds] [NX] [XX]` | `redis.write` | `Risky` | `Medium` | `BestEffort` | `key`, `value`; optional `ttl_seconds`, `nx`, `xx` |
| `redis.del` | `DEL key...` | `redis.write` | `Risky` | `High` | `None` | `keys` string array |
| `redis.exists` | `EXISTS key...` | `redis.read` | `Safe` | `Low` | `Strict` | `keys` string array |
| `redis.expire` | `EXPIRE key seconds` | `redis.write` | `Risky` | `Medium` | `BestEffort` | `key`, `seconds` |
| `redis.ttl` | `TTL key` | `redis.read` | `Safe` | `Low` | `Strict` | `key` |
| `redis.incr` | `INCR key` | `redis.write` | `Risky` | `Medium` | `None` | `key` |
| `redis.hget` | `HGET key field` | `redis.read` | `Safe` | `Low` | `Strict` | `key`, `field` |
| `redis.hset` | `HSET key field value...` | `redis.write` | `Risky` | `Medium` | `BestEffort` | `key`, `fields` object |
| `redis.hgetall` | `HGETALL key` | `redis.read` | `Safe` | `Low` | `Strict` | `key` |
| `redis.lpush` | `LPUSH key element...` | `redis.write` | `Risky` | `Medium` | `None` | `key`, `elements` string array |
| `redis.lrange` | `LRANGE key start stop` | `redis.read` | `Safe` | `Low` | `Strict` | `key`; optional `start`, `stop` |
| `redis.sadd` | `SADD key member...` | `redis.write` | `Risky` | `Medium` | `BestEffort` | `key`, `members` string array |
| `redis.smembers` | `SMEMBERS key` | `redis.read` | `Safe` | `Low` | `Strict` | `key` |

## Explicit Non-Goals

The current implementation does not include:

- Redis TCP/RESP protocol support, connection pooling, TLS Redis negotiation, database selection, or Redis cluster routing
- arbitrary Redis commands, scripting, streams, sorted sets, bitmaps, geospatial commands, HyperLogLog, scan/keyspace browsing, pub/sub, monitor, pipelines, or transactions
- key pattern deletion, namespace policy, value-size policy, command allowlist by prefix, or output redaction
- API-token provisioning automation beyond manual config, credential validation beyond UUID shape, or live self-check probes
- durable caching, cache invalidation policy, migration, backup, restore, metrics, or key inventory

These are excluded on purpose:

- Redis write/delete operations can mutate or destroy arbitrary application data and need approval/runtime verification before broader mutation is safe.
- Arbitrary command proxying would bypass the connector's capability model and should not be added without a typed policy layer.
- Upstash REST supports pipelines, transactions, and SSE-based monitor/pub-sub, but those surfaces need separate flow-control and replay contracts.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- local configuration, client, session ID, request, and error counter state
- configured/unconfigured self-check status only
- operation metadata with capability, risk, safety tier, idempotency, schemas, and hints
- simulation allow/deny for known versus unknown operation IDs only
- typed provider/FCP error mapping

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle, configuration, health, doctor, self-check, introspection, simulation, shutdown, and counters
- all fourteen Redis command operations through deterministic HTTP fixtures
- invoke rejection for unknown operation and missing required inputs
- provider 401, 403, 429, and other API error classes
- Upstash `result` and `error` response decoding
- auth redaction, credential-ID mode metadata, default/custom URL behavior, and request formation

## Source Notes

- `connectors/redis/src/connector.rs` defines configuration parsing, lifecycle handlers, operation catalog, introspection, simulation, and invoke dispatch.
- `connectors/redis/src/client.rs` defines Upstash-compatible command body shape, auth headers, timeout, retry config, URL trimming, and provider error mapping.
- `connectors/redis/src/types.rs` defines Upstash response and API error shapes.
- `connectors/redis/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/redis/manifest.toml` defines the manifest operation catalog, network constraints, sandbox boundary, zone policy, and rate-limit intent.
- `connectors/redis/tests/integration.rs` contains the runtime contract proof surface.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/redis/README.md
ubs connectors/redis/README.md
LC_ALL=C rg -n '[^ -~]' connectors/redis/README.md
rg -n '\bmaster\b' connectors/redis/README.md
```

For source or behavior changes, also run the connector proof lane through `rch`:

```bash
rch exec -- cargo test -p fcp-redis
rch exec -- cargo check -p fcp-redis --all-targets
rch exec -- cargo clippy -p fcp-redis --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

## Operator Guidance

- Configure a real Upstash REST endpoint; the default `redis.example.com` URL is only a placeholder.
- Prefer host-managed credential references where possible; direct token mode keeps the token in process memory.
- Use read-only Upstash tokens for read-only deployments, but remember runtime does not enforce `redis.read` versus `redis.write` tokens itself.
- Treat `redis.del`, `redis.set`, `redis.expire`, `redis.incr`, `redis.hset`, `redis.lpush`, and `redis.sadd` as high-review operations until approval-token verification is implemented.
- Do not rely on `self_check()` for URL or credential validation; it only reports whether local configuration exists.
- Avoid using large `HGETALL` or `SMEMBERS` targets without an application-level size budget.
