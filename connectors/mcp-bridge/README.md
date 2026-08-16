# MCP Bridge Connector Phase-0 Security Contract

> **Status**: bounded Phase-0 security packet implemented; no live MCP calls in verification
> **Bead**: `flywheel_connectors-nqm81.2`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **MCP upstream specification**: https://modelcontextprotocol.io/specification/2025-06-18/
> **MCP transport implemented here**: Streamable HTTP-style JSON-RPC over an exact allowlisted endpoint (`/mcp`, or n8n's `/mcp-server/http`)

## Purpose

This document fixes the operator-facing contract for `fcp.mcp-bridge`. The connector exposes the Model Context Protocol server surface implemented in this crate: tools, resources, prompts, sampling request fallback, and local bridge metrics.

The connector is intentionally a bounded MCP bridge. It is not a full MCP host runtime, incremental SSE stream consumer, stdio process launcher, OAuth installer, prompt execution engine, direct LLM router, MCP server registry, or general egress proxy.

## Current Runtime Snapshot

The current crate exposes these operations:

- `mcp.tools.list`
- `mcp.tools.call`
- `mcp.resources.list`
- `mcp.resources.read`
- `mcp.prompts.list`
- `mcp.sampling.handle`
- `mcp.server.metrics`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-mcp-bridge`.
- Runtime `BaseConnector` ID is `mcp-bridge`.
- Manifest and reported connector ID are `fcp.mcp-bridge`.
- Manifest status is `ready`; tool calls are conditionally enabled only after fresh discovery and exact security gates.
- Manifest interface hash is `blake3-256:fcp.interface.v2:0d9f9c20f0f3556a12ff0946155ce71c94352774e367eba94b9b03f02fbd72b6`.
- Configuration requires `server_id` and a non-empty exact MCP endpoint.
- `server_id` is a generic lowercase canonical slug: 1–64 ASCII letters, digits, `-`, or `_`; first and last characters are alphanumeric. The FWC layer owns any eec/hetzner/legacy registry mapping.
- `mcp_url` must use exactly `/mcp` or the official n8n `/mcp-server/http` path; only one trailing slash is normalized. Production URLs require HTTPS/443. Loopback HTTP is reserved for local fixtures.
- Direct non-loopback egress fails closed until host-mediated exact-origin enforcement is available.
- Configuration accepts one of an optional trimmed `api_key` or a UUID `credential_id`, never both.
- Optional `capability_policy` is owner-reviewed configuration for `eec`, `hetzner`, or `legacy` and contains bounded `n8n_version`, exact `auth_mode` (`oauth` or `access_token`), bounded `api_scope_digest`, and up to 256 unique exact `approved_tools` entries (`name`, `class`, input/output schema digests). A direct `api_key` requires `auth_mode = access_token`; with `credential_id`, the mode remains trusted host-provisioning metadata because the connector cannot inspect the referenced secret type.
- Without `capability_policy`, generic catalog reads still work but `mcp.tools.call` is denied locally before provider I/O.
- Direct API-key mode sends `Authorization: Bearer {api_key}`.
- `credential_id` is only a host-mediated reference; this crate never resolves it or sends it as a provider header.
- `description_scan` may be supplied at top level or under `security.description_scan`.
- `description_scan` accepts `warn`, `block`, or `off`; the default is `warn`.
- `sampling` is optional and disabled by default.
- Sampling defaults are `max_rpm = 10`, `timeout_secs = 30`, `max_tokens_cap = 4096`, and `max_tool_rounds = 5`.
- Sampling may also set `llm_connector`, `model_override`, and `allowed_models`.
- The client sends JSON-RPC requests to the canonical `{mcp_url}` endpoint.
- The current path sends `MCP-Protocol-Version: 2026-07-28`; only an empty or unrecognized HTTP 400 enters the bounded legacy initialize fallback for negotiated 2025 protocol versions.
- The client sends `Accept: application/json, text/event-stream` and parses bounded JSON or buffered SSE event sequences with an exact request ID and body, line, and event limits. Incremental/long-lived streaming, subscriptions, and unsolicited server streams remain out of scope.
- Runtime request timeout is 30 seconds; the operation manifest may retain a larger outer deadline.
- There is no automatic retry: every provider request is one attempt, including 401, 404, 429, and unknown-effect failures. Authentication expiry is fail-closed with no connector-side refresh; retry counters remain zero.
- Runtime `invoke` requires `operation`, a host-key-verified bound `capability_token`, the negotiated zone, exact instance binding, expiry, capability, and resource URI.
- `mcp.tools.call` and enabled `mcp.sampling.handle` require exactly one valid execution approval. The approval includes exact normalized input constraints and a SHA-256 digest of the canonical payload.
- `mcp.tools.call` performs exactly two provider calls per invocation: one fresh `tools/list` with the verified call context, then one `tools/call` only for an exact `Approved` snapshot entry. Unknown, blocked, or schema-drifted tools fail locally. There is no automatic retry or replay.
- The attached `capability_snapshot` contains only server/protocol/auth metadata, schema digests, classes, statuses, and a snapshot digest; raw schemas, descriptions, arguments, results, and provider payloads are not retained.
- Sampling remains local-only and returns safe metadata counts, never prompt content.
- Provisioning requests only the trusted `server_id`, exact supported endpoint (`/mcp` or `/mcp-server/http`), and host-managed `credential_id` reference. It has no raw-secret prompt or storage step.
- Reconfigure and shutdown clear the client, verifier, zone, session, and handshaken state.
- `self_check()` issues one local-fixture `tools/list` probe against the configured endpoint and discards the catalog response. Credential and production direct-egress modes fail before network traffic.

## Enforced Security Boundaries

This packet makes the following boundaries mechanical:

- Manifest and runtime introspection share the same seven-operation catalog.
- Capability verification is keyed by the host public key from handshake and binds the negotiated zone and requested instance.
- Resource URI bindings are deterministic and include the generic `server_id` slug.
- Approval matching is exact: connector, operation, zone, validity, signature presence, normalized constraints, and optional `input_hash` must all match. A changed payload fails before provider or local effect.
- Raw tool arguments, sampling messages, provider response bodies, and scanner descriptions are not emitted in logs or approval serialization; only redaction-safe metadata and digest values are exposed.
- Reconfiguration and shutdown reset session authorization state.
- The HTTP client disables redirects and performs no automatic retry.
- Description scanning remains an independent hostile-input guardrail; it is not an authorization substitute.

Out of scope for this packet are incremental or long-lived Streamable HTTP/SSE streams, subscriptions, unsolicited server streams, stdio/process transport, OAuth installation or refresh, and host-side credential resolution.

## First-Slice Scope

The current MCP Bridge slice documents the bounded runtime surface:

- canonical `server_id` and exact `/mcp` or `/mcp-server/http` endpoint configuration
- loopback fixture egress or fail-closed host-mediated production/credential modes
- JSON-RPC over an exact `/mcp` or `/mcp-server/http` endpoint
- tool, resource, prompt, sampling, and metrics operations
- host-key capability verification and exact approval gates
- prompt-injection description scanning for server-provided catalogs
- handshake/session reset, self-check probe, introspection, and simulation behavior
- deterministic WireMock tests and direct proof commands

## Auth And Scope Boundary

- Authentication mechanisms: optional bearer API key for loopback fixtures, or a host-mediated `credential_id` reference.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Runtime capability surface is enforced by a host-key verifier, negotiated zone, exact bound instance, operation, expiry, capability, and resource URI:
  - `mcp.tools.read` gates tool catalog metadata.
- `mcp.tools.write` gates the fresh-discovery and exact-approval tool-call route.
  - `mcp.resources.read` gates resource listing and reads.
  - `mcp.prompts.read` gates prompt catalog metadata.
  - `mcp.sampling.handle` gates the local sampling fallback.
  - `mcp.server.metrics` gates local counter metadata.
- `mcp.tools.call` and `mcp.sampling.handle` require exactly one execution approval with canonical input constraints and a SHA-256 payload digest.
- The connector does not persist API keys, MCP catalog data, resource contents, prompt definitions, tool results, sampling request content, or provider error bodies outside process memory.
- MCP catalog descriptions and resource/tool outputs are untrusted model-facing input. Treat live output as work-zone operational data unless a stricter zone boundary is implemented.

## Provisioning

The `mcp-bridge.host_credential` recipe collects only the trusted lowercase `server_id`, an exact supported endpoint (`/mcp` or `/mcp-server/http`), and an optional host-managed `credential_id` UUID reference. It does not prompt for, store, or return a raw API key; an unauthenticated mode is reserved for loopback fixtures.

An owner-reviewed policy is supplied in connector configuration when tool calls
are required:

```json
{
  "server_id": "eec",
  "mcp_url": "https://operator-configured.example/mcp",
  "capability_policy": {
    "n8n_version": "1.0.0",
    "auth_mode": "access_token",
    "api_scope_digest": "scope-digest",
    "approved_tools": [
      {
        "name": "read_file",
        "class": "read",
        "input_schema_digest": "sha256:...",
        "output_schema_digest": "sha256:..."
      }
    ]
  }
}
```

Every `mcp.tools.call` re-discovers the remote catalog and compares only
bounded schema digests and the exact reviewed class. Names, descriptions,
annotations, and remote payloads never classify or approve a tool. The
connector keeps no durable raw catalog or tool result state.

## Network And Runtime Invariants

- Runtime endpoint shape: exact `{mcp_url}` path `/mcp` or `/mcp-server/http`; one trailing slash is normalized.
- Production endpoint policy: HTTPS, port 443, no userinfo/query/fragment, no private/tailnet hostnames, and no IP literals.
- Loopback HTTP is accepted only for local deterministic fixtures.
- Manifest `network_constraints` are declarative operator policy (operator-configured host, HTTPS/443, TLS/SNI, and deny rules); they are not a substitute for host-mediated DNS/private-range/max-response enforcement.
- Non-loopback and `credential_id` egress fail before DNS/HTTP until host mediation exists.
- Redirects are disabled and automatic retry is disabled.
- Runtime request timeout: `30 seconds` (the operation manifest may retain a larger outer deadline).
- Runtime retry policy: single attempt; retry metrics are retained for compatibility and always remain zero.
- Runtime JSON-RPC IDs are process-local integers starting at `1`.
- Provider HTTP 401, 403, 404, 429, and other API errors map to typed connector/FCP errors.
- `Retry-After` on 429 is converted to milliseconds; missing values default to 60000 ms.
- MCP JSON-RPC errors are returned as redacted typed MCP errors; provider bodies are discarded.
- Manifest connect timeout is `5000 ms`, operation total timeout is `15000 ms`, `30000 ms`, or `120000 ms`, and maximum response bytes range from `1048576` to `52428800` by operation.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, no exec, and no inbound listener capability.
- The connector does not launch MCP stdio servers, listen for inbound MCP clients, or maintain durable MCP sessions.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `mcp.tools.read` | List tools exposed by the configured MCP server. |
| `mcp.tools.write` | Call one tool on the configured MCP server. |
| `mcp.resources.read` | List or read MCP resources. |
| `mcp.prompts.read` | List MCP prompt templates. |
| `mcp.sampling.handle` | Convert an MCP sampling request into a local FCP event fallback. |
| `mcp.server.metrics` | Return local bridge counters. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `mcp.tools.list` | JSON-RPC `tools/list` | `mcp.tools.read` | `Safe` | `Low` | `Strict` | Lists tools, scans descriptions when enabled, and filters names that collide with bridge-owned operations. |
| `mcp.tools.call` | fresh `tools/list` then one `tools/call` | `mcp.tools.write` | `Risky` | `High` | `None` | Requires capability-token, exact execution approval, explicit policy, and a fresh exact Approved snapshot. |
| `mcp.resources.list` | JSON-RPC `resources/list` | `mcp.resources.read` | `Safe` | `Low` | `Strict` | Lists resources and annotates descriptions with scanner findings when enabled. |
| `mcp.resources.read` | JSON-RPC `resources/read` | `mcp.resources.read` | `Safe` | `Low` | `Strict` | Reads one resource by `uri`. |
| `mcp.prompts.list` | JSON-RPC `prompts/list` | `mcp.prompts.read` | `Safe` | `Low` | `Strict` | Lists prompt templates and annotates descriptions with scanner findings when enabled. |
| `mcp.sampling.handle` | local fallback | `mcp.sampling.handle` | `Risky` | `High` | `None` | Converts `sampling/createMessage` input into an `mcp_sampling_request_received` event for host or agent orchestration. |
| `mcp.server.metrics` | local metrics | `mcp.server.metrics` | `Safe` | `Low` | `Strict` | Returns request, error, scan, finding, sampling, and zero automatic-retry counters. |

## Prompt-Injection Scanner

The bridge treats MCP server-provided descriptions as hostile model-facing input.

Scanner modes:

| Mode | Behavior |
|------|----------|
| `warn` | Default. Scan descriptions, log redacted findings, and attach `injection_findings` arrays to catalog entries. |
| `block` | Scan descriptions and fail catalog operations when findings are present. |
| `off` | Do not scan descriptions. |

The scanner currently looks for prompt override language, role tags, concealment instructions, network-command hints, code execution references, dangerous import references, FCP capability-token references, external API host references, egress bypass hints, and Tailscale/tailnet references. Some patterns are warning severity and some are blocking severity.

`mcp.tools.list` also filters remote tool names that collide with bridge-owned operation names such as `mcp.tools.call`, `mcp.resources.read`, or `server.metrics`.

This scanner is a guardrail, not a trust boundary. Capability and approval enforcement remain independent from description scanning.

## Sampling Fallback

`mcp.sampling.handle` is local-only in this runtime slice:

- it is disabled unless `sampling.enabled = true`
- it normalizes input to a `sampling/createMessage` request
- it requires request `params`
- it requires integer `params.maxTokens`
- it rejects requests over `sampling.max_tokens_cap`
- it increments `sampling_requests`
- it returns an event payload with `dispatch = "agent_event"`
- it sets `host_orchestrated = false`
- it sets `requires_human_approval = true`
- it includes redaction flags that say prompt, response, and metadata logging are disabled

It does not directly call another connector or LLM. The host or agent layer must consume the event fallback and decide how to orchestrate the request.

## Resource URIs

Capability-token verification binds every operation to a deterministic resource URI:

| Operation family | Candidate resource URI shape |
|------------------|------------------------------|
| MCP server | `fwc-mcp-bridge://{server_id}` |
| Tools | `fwc-mcp-bridge://{server_id}/tools/{percent-encoded-tool-name}` |
| Resources | `fwc-mcp-bridge://{server_id}/resources/{percent-encoded-uri}` |
| Prompts | server resource URI (prompt catalog is instance-scoped) |

## Explicit Non-Goals

The current implementation does not include:

- MCP stdio transport, process spawning, server lifecycle management, or server discovery
- incremental or long-lived SSE streaming, subscriptions, and unsolicited server streams
- tool schema validation beyond requiring `name` and object `arguments`
- prompt execution, prompt rendering, resource subscriptions, notifications, roots, elicitation, or completion
- direct sampling dispatch to an LLM or connector
- OAuth installation or token refresh, secretless credential injection, or API-key rotation
- durable storage of MCP catalogs, resources, prompts, tool results, or sampling requests

These are excluded on purpose:

- Tool calls are remote side-effect boundaries and need explicit approval/runtime verification before broader mutation is safe.
- Sampling is model-invocation orchestration and must stay host-mediated until the approval and logging policy is explicit.
- Server-provided descriptions are untrusted and cannot substitute for capability-token enforcement.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, `introspect()`, and `mcp.server.metrics` are part of the public closeout contract. They surface:

- local configuration, client, session ID, request, error, scan, finding, sampling, and zero-retry counter state
- URL readiness plus a configured-endpoint `tools/list` self-check probe
- degraded or unhealthy states for unconfigured, missing client, and missing session ID cases
- operation metadata with capability, risk, safety tier, idempotency, schemas, and hints
- simulation allow/deny for canonical `operation` values, with `mcp.tools.call` reporting conditional policy-gated semantics
- typed provider/FCP error mapping

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle, configuration, health, doctor, self-check, introspection, simulation, shutdown, and counters
- tool listing, tool calling, resource listing/reading, prompt listing, sampling fallback, and metrics
- description scanner warn/block/off behavior and built-in tool-name collision filtering
- invoke rejection for unknown operation and missing required inputs
- provider 401, 403, 404, 429, 500, single-attempt behavior, redaction, and bad JSON-RPC response classes
- auth redaction, URL trimming, base URL policy, sampling config parsing, and request normalization

## Source Notes

- `connectors/mcp-bridge/src/connector.rs` defines configuration parsing, lifecycle handlers, URL readiness policy, prompt-injection catalog annotation, introspection, simulation, sampling fallback, metrics, and invoke dispatch.
- `connectors/mcp-bridge/src/client.rs` defines JSON-RPC over HTTP, auth header shape, single-attempt timeout behavior, endpoint/egress policy, MCP protocol header, and redacted provider/MCP error mapping.
- `connectors/mcp-bridge/src/security.rs` defines description scan modes, scanner patterns, built-in operation collision detection, and redacted finding payloads.
- `connectors/mcp-bridge/src/types.rs` defines MCP JSON-RPC request/response and catalog shapes.
- `connectors/mcp-bridge/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/mcp-bridge/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, rate-limit intent, and default scanner mode.
- `connectors/mcp-bridge/tests/integration.rs` contains the runtime contract proof surface.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/mcp-bridge/README.md
ubs connectors/mcp-bridge/README.md
LC_ALL=C rg -n '[^ -~]' connectors/mcp-bridge/README.md
rg -n '\bmaster\b' connectors/mcp-bridge/README.md
```

For source or behavior changes, also run the connector proof lane through `rch`:

```bash
rch exec -- cargo test -p fcp-mcp-bridge
rch exec -- cargo check -p fcp-mcp-bridge --all-targets
rch exec -- cargo clippy -p fcp-mcp-bridge --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

## Operator Guidance

- Use a canonical exact `/mcp` or `/mcp-server/http` endpoint. Production direct egress is intentionally fail-closed until host mediation is present.
- Treat all MCP catalog descriptions and remote tool output as untrusted model-facing input.
- Keep `description_scan = "warn"` or `"block"` unless deterministic fixture tests require disabling it.
- Treat `mcp.tools.call` and `mcp.sampling.handle` as high-review operations; tool calls are arbitrary official MCP side-effect boundaries and require fresh discovery, exact snapshot approval, capability-token, and execution approval. No remote tool is assumed safe from its name or description.
- Runtime capability and approval verification is enforced before provider or local effects; keep host signatures and exact input bindings authoritative.
- Do not interpret this connector as a stdio MCP server launcher or direct LLM sampling engine.
