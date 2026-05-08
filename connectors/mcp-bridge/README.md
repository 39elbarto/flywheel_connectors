# MCP Bridge Connector V3 Contract

> **Status**: runtime contract documented; manifest/runtime drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **MCP upstream specification**: https://modelcontextprotocol.io/specification/2025-06-18/
> **MCP transport implemented here**: Streamable HTTP-style JSON-RPC over `POST /mcp`

## Purpose

This document fixes the operator-facing contract for `fcp.mcp-bridge`. The connector exposes the Model Context Protocol server surface implemented in this crate: tools, resources, prompts, sampling request fallback, and local bridge metrics.

The connector is intentionally a bounded MCP bridge. It is not a full MCP host runtime, SSE stream consumer, stdio process launcher, OAuth installer, prompt execution engine, direct LLM router, MCP server registry, or general egress proxy.

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
- Manifest status is `ready`.
- Manifest interface hash is `blake3-256:fcp.interface.v2:7641c4d323456be37407868ce9f161c119505f9c64cf6538d538ae7b45b86ba2`.
- Configuration requires a non-empty `mcp_url`.
- Configuration accepts an optional trimmed `api_key`.
- Direct API-key mode sends `Authorization: Bearer {api_key}`.
- There is no `credential_id` mode in this runtime slice.
- `description_scan` may be supplied at top level or under `security.description_scan`.
- `description_scan` accepts `warn`, `block`, or `off`; the default is `warn`.
- `sampling` is optional and disabled by default.
- Sampling defaults are `max_rpm = 10`, `timeout_secs = 30`, `max_tokens_cap = 4096`, and `max_tool_rounds = 5`.
- Sampling may also set `llm_connector`, `model_override`, and `allowed_models`.
- The client sends JSON-RPC requests to `{mcp_url}/mcp`.
- The client sends `MCP-Protocol-Version: 2025-06-18`.
- The client sends `Accept: application/json, text/event-stream`, but the runtime reads the response body as a JSON-RPC JSON document. It does not consume a streaming SSE event sequence.
- Runtime request timeout is 120 seconds.
- The client uses the shared retry loop with `max_retries = 2`.
- Runtime retries one unauthorized response when an API key is configured and one MCP session-expired error.
- Runtime tracks auth retry and session-expired retry counters for `mcp.server.metrics`.
- Runtime `invoke` uses `operation_id`, not `operation`.
- Runtime does not install a `CapabilityVerifier` and does not verify `capability_token`.
- Runtime does not verify approval tokens for `mcp.tools.call` or `mcp.sampling.handle`.
- `simulate` only checks whether `operation_id` is present in the local operation inventory.
- `handle_configure()` does not clear a prior session ID and does not reset the base handshaken flag.
- `handle_shutdown()` shuts down the client runtime and clears config/client/base flags, but leaves `session_id` in memory.
- `health()` and `doctor()` consider a handshake complete only when a `session_id` was provided.
- `self_check()` is a local readiness check only; it does not issue a live MCP probe.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- Manifest marks the connector `ready`, while the runtime remains a first-slice bridge with no capability-token enforcement, no approval-token enforcement, no live self-check probe, and no SSE response handling.
- Manifest network constraints allow `localhost.localdomain` on selected ports. Runtime URL readiness accepts any parseable HTTP or HTTPS URL with a non-empty host.
- Manifest state hint says endpoint and transport config are stored. Runtime keeps configuration in memory and does not persist connector state.
- Runtime exposes API-key bearer auth only; there is no host `credential_id` or secretless injection mode.
- Runtime `introspect()` returns only `connector_id`, `version`, and `operations`, not the full `Introspection` shape with events, resource types, auth caps, or event caps.
- Runtime metadata marks `mcp.tools.call` and `mcp.sampling.handle` as policy-approval operations, but runtime checks no approval token.
- Runtime `simulate()` can return allowed before the connector is configured or handshaken because it only checks the operation inventory.
- `handle_configure()` can leave the connector handshaken after reconfiguration because it does not reset handshake state.
- `handle_shutdown()` can leave `session_id` present, so health/doctor semantics can be misleading after shutdown.
- The client advertises `text/event-stream` but currently parses one JSON-RPC response body.
- Description scanning annotates catalogs and can block in `block` mode, but it is heuristic and does not make remote MCP descriptions trusted.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should implement capability-token and approval-token verification, align manifest/runtime network policy, add a real live MCP self-check probe, support actual Streamable HTTP/SSE response handling where needed, reset handshake/session state consistently on reconfigure and shutdown, add secretless credential support if desired, and add a tracked verification bundle.

## First-Slice Scope

The current MCP Bridge README slice documents the existing runtime surface:

- direct MCP endpoint configuration with optional bearer API key
- permissive HTTP/HTTPS URL readiness
- JSON-RPC over `POST /mcp`
- tool, resource, prompt, sampling, and metrics operations
- prompt-injection description scanning for server-provided catalogs
- simplified handshake, self-check, introspection, and simulation behavior
- deterministic WireMock tests and direct proof commands

## Auth And Scope Boundary

- Authentication mechanism: optional bearer API key.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Runtime capability surface:
  - `mcp.tools.read` gates tool catalog metadata, but runtime does not enforce capability tokens.
  - `mcp.tools.write` gates tool call metadata, but runtime does not enforce capability or approval tokens.
  - `mcp.resources.read` gates resource listing and reads, but runtime does not enforce capability tokens.
  - `mcp.prompts.read` gates prompt catalog metadata, but runtime does not enforce capability tokens.
  - `mcp.sampling.handle` gates local sampling fallback metadata, but runtime does not enforce approval tokens.
  - `mcp.server.metrics` gates local counter metadata, but runtime does not enforce capability tokens.
- The connector does not persist API keys, MCP catalog data, resource contents, prompt definitions, tool results, sampling request content, or provider error bodies outside process memory.
- MCP catalog descriptions and resource/tool outputs are untrusted model-facing input. Treat live output as work-zone operational data unless a stricter zone boundary is implemented.

## Network And Runtime Invariants

- Runtime endpoint shape: `{mcp_url}/mcp`.
- Runtime allows HTTP and HTTPS URLs with any non-empty host.
- Runtime does not reject non-local HTTP, private hosts, IP literals, userinfo, query strings, or fragments during configure.
- Manifest network policy is narrower than runtime and lists `localhost.localdomain` ports `3000`, `8080`, and `8443`.
- Runtime request timeout: `120 seconds`.
- Runtime retry policy: `max_retries = 2` using the shared retry loop.
- Runtime JSON-RPC IDs are process-local integers starting at `1`.
- Provider HTTP 401, 403, 404, 429, and other API errors map to typed connector/FCP errors.
- `Retry-After` on 429 is converted to milliseconds; missing values default to 60000 ms.
- MCP JSON-RPC errors are returned as typed MCP errors; session-expired errors are retried once.
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
| `mcp.tools.call` | JSON-RPC `tools/call` | `mcp.tools.write` | `Risky` | `High` | `None` | Calls one remote MCP tool by `name` with object `arguments`; runtime checks no approval token. |
| `mcp.resources.list` | JSON-RPC `resources/list` | `mcp.resources.read` | `Safe` | `Low` | `Strict` | Lists resources and annotates descriptions with scanner findings when enabled. |
| `mcp.resources.read` | JSON-RPC `resources/read` | `mcp.resources.read` | `Safe` | `Low` | `Strict` | Reads one resource by `uri`. |
| `mcp.prompts.list` | JSON-RPC `prompts/list` | `mcp.prompts.read` | `Safe` | `Low` | `Strict` | Lists prompt templates and annotates descriptions with scanner findings when enabled. |
| `mcp.sampling.handle` | local fallback | `mcp.sampling.handle` | `Risky` | `High` | `None` | Converts `sampling/createMessage` input into an `mcp_sampling_request_received` event for host or agent orchestration. |
| `mcp.server.metrics` | local metrics | `mcp.server.metrics` | `Safe` | `Low` | `Strict` | Returns request, error, scan, finding, sampling, auth-retry, and session-expired retry counters. |

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

This scanner is a guardrail, not a trust boundary. Follow-up work should keep capability and approval enforcement independent from description scanning.

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

Runtime capability-token verification is absent for MCP Bridge in this checkout, so there are no effective resource URI bindings. The practical authorization binding is configuration plus base readiness plus operation name.

Follow-up work should add resource URI shapes such as:

| Operation family | Candidate resource URI shape |
|------------------|------------------------------|
| MCP server | `mcp://{server-id}` |
| Tools | `mcp://{server-id}/tools/{tool_name}` |
| Resources | `mcp://{server-id}/resources/{encoded_uri}` |
| Prompts | `mcp://{server-id}/prompts/{prompt_name}` |

## Explicit Non-Goals

The current implementation does not include:

- MCP stdio transport, process spawning, server lifecycle management, or server discovery
- actual streaming SSE event parsing despite the advertised `Accept` header
- tool schema validation beyond requiring `name` and object `arguments`
- prompt execution, prompt rendering, resource subscriptions, notifications, roots, elicitation, or completion
- direct sampling dispatch to an LLM or connector
- OAuth installation, token refresh, secretless credential injection, or API-key rotation
- durable storage of MCP catalogs, resources, prompts, tool results, or sampling requests

These are excluded on purpose:

- Tool calls are remote side-effect boundaries and need explicit approval/runtime verification before broader mutation is safe.
- Sampling is model-invocation orchestration and must stay host-mediated until the approval and logging policy is explicit.
- Server-provided descriptions are untrusted and cannot substitute for capability-token enforcement.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, `introspect()`, and `mcp.server.metrics` are part of the public closeout contract. They surface:

- local configuration, client, session ID, request, error, scan, finding, sampling, and retry counter state
- local URL readiness only, not a live MCP server probe
- degraded or unhealthy states for unconfigured, missing client, and missing session ID cases
- operation metadata with capability, risk, safety tier, idempotency, schemas, and hints
- simulation allow/deny for known versus unknown operation IDs only
- typed provider/FCP error mapping

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle, configuration, health, doctor, self-check, introspection, simulation, shutdown, and counters
- tool listing, tool calling, resource listing/reading, prompt listing, sampling fallback, and metrics
- description scanner warn/block/off behavior and built-in tool-name collision filtering
- invoke rejection for unknown operation and missing required inputs
- provider 401, 403, 404, 429, 500, auth retry, session-expired retry, retry exhaustion, and bad JSON-RPC response classes
- auth redaction, URL trimming, base URL policy, sampling config parsing, and request normalization

## Source Notes

- `connectors/mcp-bridge/src/connector.rs` defines configuration parsing, lifecycle handlers, URL readiness policy, prompt-injection catalog annotation, introspection, simulation, sampling fallback, metrics, and invoke dispatch.
- `connectors/mcp-bridge/src/client.rs` defines JSON-RPC over HTTP, auth header shape, retry dispatch, timeout, MCP protocol header, and provider/MCP error mapping.
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

- Use a tightly scoped MCP server URL. The runtime URL policy is permissive.
- Treat all MCP catalog descriptions and remote tool output as untrusted model-facing input.
- Keep `description_scan = "warn"` or `"block"` unless deterministic fixture tests require disabling it.
- Treat `mcp.tools.call` and `mcp.sampling.handle` as high-review operations even though runtime approval checks are absent.
- Do not rely on capability-token or approval-token enforcement until runtime verification is implemented.
- Do not interpret this connector as a stdio MCP server launcher or direct LLM sampling engine.
