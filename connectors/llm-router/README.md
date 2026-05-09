# LLM Router Connector V3 Contract

> **Status**: runtime contract documented with routing-only dispatch semantics
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **OpenAI chat upstream**: https://developers.openai.com/api/reference/resources/chat
> **Cloudflare AI Gateway upstream**: https://developers.cloudflare.com/ai-gateway/configuration/authentication/
> **Vercel AI Gateway upstream**: https://vercel.com/docs/ai-gateway
> **LiteLLM upstream**: https://docs.litellm.ai/

## Purpose

This document fixes the operator-facing contract for `fcp.llm-router`. The connector exposes the runtime routing surface implemented in this crate: provider/model selection, cost estimation, provider inventory, in-memory usage counters, and session budget reporting.

The connector is intentionally a routing meta-connector. It does not call the selected LLM provider and does not return generated text. `llm-router.route` returns a dispatch decision that the caller must use to invoke the chosen provider connector separately.

## Current Runtime Snapshot

The current crate exposes these operations:

- `llm-router.route`
- `llm-router.estimate_cost`
- `llm-router.list_providers`
- `llm-router.get_usage`
- `llm-router.get_budget`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-llm-router`.
- Runtime `BaseConnector` ID is `llm-router`.
- Manifest connector ID is `fcp.llm-router`.
- Manifest version is `0.1.0`.
- Manifest format is `native`.
- Configuration requires a non-empty `providers` array.
- Each provider requires exactly one auth source:
  - `api_key`
  - `credential_id`
- Direct `api_key` mode validates that the value can be used in an HTTP bearer authorization header.
- Direct `api_key` mode is redacted in logs, doctor output, self-check output, and configure output.
- `credential_id` mode is a non-empty string reference and assumes host or egress-proxy credential injection.
- Provider models are supplied by configuration. There is no live model discovery during configure, route, or cost estimation.
- Default routing strategy is `cost`.
- Invalid request-level `strategy` values fall back to the configured default strategy.
- `preferred_provider` and `preferred_model` are honored only by the `fallback` strategy in the current selector.
- Token estimates use a simple character-count heuristic, roughly `ceil(chars / 4)`.
- `max_tokens` defaults to `4096` and is used as the estimated output-token count.
- Hard budget enforcement denies a route only when already-spent session cost is greater than or equal to the configured budget before the new route.
- `budget_limit_usd` is a per-request ceiling applied to candidate estimated cost.
- `provider_status` starts every configured provider as healthy with `100 ms` latency and is not updated by routing.
- `handle_health()` reports only local configured state.
- `handle_doctor()` checks local configuration, static provider status, network policy, credential-injection mode, and budget settings.
- `handle_self_check()` reports provider readiness, credential-injection requirements, network-policy failures, unavailable providers, and providers with no models.
- `handle_handshake()` creates a new session ID, marks the base connector handshaken, and creates a `CapabilityVerifier` from the host public key, zone, and requested instance ID.
- Runtime handshake returns placeholder manifest hash `blake3-256:fcp.interface.v2:pending`.
- `invoke` expects `operation`, `input`, and `capability_token`.
- Proper FCP capability tokens are verified against the operation capability when a verifier exists.
- Legacy string `capability_token` values are accepted as a presence check.
- `handle_simulate()` only reports whether the connector is configured.
- `handle_shutdown()` reports total tracked cost and does not clear config, verifier, session, provider usage, or base lifecycle flags.

## Provider Catalog

The runtime has three baseline allowed provider hosts:

- `api.anthropic.com`
- `api.openai.com`
- `generativelanguage.googleapis.com`

It also has built-in OpenAI-compatible gateway/provider descriptors:

| Provider name | Base URL source | Auth fields | Notes |
|---------------|-----------------|-------------|-------|
| `cloudflare-ai-gateway` | Built from `account_id` and `gateway_id` | `api_key`, optional `cloudflare_gateway_api_key` | Uses `https://gateway.ai.cloudflare.com/v1/{account_id}/{gateway_id}/openai`; optional gateway key becomes `cf-aig-authorization`. |
| `microsoft-foundry` | Operator-provided Azure resource URL | `credential_id` | Uses `https://<resource>.openai.azure.com/openai/v1` or `https://<resource>.services.ai.azure.com/openai/v1`; routes to the `fcp.microsoft-foundry` connector and never reads Foundry API keys or bearer tokens. |
| `vercel-ai-gateway` | Fixed descriptor | `api_key` or `credential_id` | Uses `https://ai-gateway.vercel.sh/v1`; normalizes bare Claude aliases to provider-prefixed model IDs. |
| `litellm` | Operator-configured | `api_key` or `credential_id` | Requires an HTTPS public DNS URL on port 443, path empty or `/v1`, and no userinfo, query, fragment, IP literal, single-label, `.local`, localhost, or private host. |
| `deepseek` | Fixed descriptor | `api_key` or `credential_id` | Uses `https://api.deepseek.com` and appends `/v1`. |
| `groq` | Fixed descriptor | `api_key` or `credential_id` | Uses `https://api.groq.com/openai/v1`. |
| `xai` | Fixed descriptor | `api_key` or `credential_id` | Uses `https://api.x.ai/v1`; normalizes selected OpenClaw-style Grok aliases. |
| `openrouter` | Fixed descriptor | `api_key` or `credential_id` | Uses `https://openrouter.ai/api/v1`; allows provider-prefixed model IDs. |
| `moonshot` | Fixed descriptor | `api_key` or `credential_id` | Uses `https://api.moonshot.ai/v1`. |
| `kimi` | Fixed descriptor | `api_key` or `credential_id` | Uses `https://api.moonshot.ai/v1`. |
| `kimi-coding` | Fixed descriptor | `api_key` or `credential_id` | Uses `https://api.moonshot.ai/v1`. |
| `qwen` | Fixed descriptor | `api_key` or `credential_id` | Uses `https://dashscope-intl.aliyuncs.com/compatible-mode/v1`. |
| `together` | Fixed descriptor | `api_key` or `credential_id` | Uses `https://api.together.xyz/v1`. |

Fixed descriptors reject `base_url` overrides unless the provided URL normalizes to the descriptor URL. Gateway hosts are reserved for their descriptor names, so a custom provider cannot claim `gateway.ai.cloudflare.com`, `ai-gateway.vercel.sh`, Microsoft Foundry resource hosts, or the other fixed descriptor hosts.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- `llm-router.route` does not invoke upstream providers. It returns `dispatch_required = true`, a `dispatch_instruction`, provider, model, usage estimate, cost estimate, routing metadata, and provenance for the routing decision.
- Runtime provenance marks the routing decision with `AI_GENERATED` taint even though no provider-generated content is returned.
- Runtime has an HTTP client for OpenAI-compatible chat completions and model listing, but the connector operation path currently does not use it for inference dispatch.
- Baseline allowed hosts include Anthropic and Google AI, but the connector's transport helper is OpenAI-compatible. This is harmless while route is selection-only, but it matters if dispatch is later added.
- `credential_id` values are not required to be UUIDs in this crate.
- Model entries that fail `ModelInfo` deserialization are skipped during configure instead of producing a per-model validation error.
- Configure accepts providers with zero models. Self-check reports `providers_no_models`, and route fails if no candidate can satisfy the request.
- `estimate_cost` uses capability `llm-router.route`, while its manifest rate-limit pool is `llm-router.estimate`.
- Real FCP tokens are accepted without verification if a verifier has not been installed yet.
- Legacy string capability tokens are accepted by presence only.
- Runtime `simulate` does not check operation ID, input shape, budget, provider availability, handshake state, or capability tokens.
- Runtime `health` and `doctor` do not perform a live provider probe.
- Runtime provider latency and health are initialized statically and do not change through normal route calls.
- Runtime shutdown does not reset lifecycle state or clear in-memory usage and budget counters.
- `microsoft-foundry` routing is descriptor-only. The router selects deployment/API family and returns a `dispatch` object for `fcp.microsoft-foundry`; it does not perform Foundry auth, HTTP calls, streaming, embeddings, or Responses API execution itself.

A follow-up parity bead should decide whether the router remains selection-only or gains provider dispatch, wire capability-token verification to reject unverifiable real tokens, align simulation with invoke policy, validate models strictly, clarify `credential_id` shape, make health probes explicit, and make shutdown reset state if the connector lifecycle expects it.

## First-Slice Scope

The current LLM Router README slice documents the existing runtime surface:

- provider configuration, built-in gateway descriptors, and endpoint-policy rules
- direct-key and credential-id auth modes
- route, cost-estimate, provider-list, usage, and budget operations
- cost, latency, capability, and fallback routing strategies
- in-memory usage and budget accounting
- lifecycle, doctor, health, self-check, simulate, introspect, invoke, and shutdown behavior
- runtime/manifest drift around dispatch semantics, token verification, simulation, health probes, provider status, and shutdown
- deterministic connector and helper tests

## Auth And Zone Boundary

- Authentication mechanisms: direct provider API key or host credential reference.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zone: `z:public`.
- Required manifest capabilities are `network.dns`, `network.egress`, and `network.tls.sni`.
- Optional manifest capabilities are `llm-router.route` and `llm-router.admin`.
- The connector does not persist provider responses, model lists discovered from providers, API keys, credential IDs beyond configuration metadata, usage counters beyond process memory, or budget counters beyond process memory.
- LLM prompts can include private source code, work planning, personal data, and customer data. Treat live routing input as work-zone data unless a stricter zone is configured by the host.

## Network And Runtime Invariants

- Provider URLs must be HTTPS on port 443.
- Runtime rejects userinfo, query strings, fragments, non-HTTPS schemes, wrong ports, unknown hosts, localhost, private ranges, tailnet ranges, and IP literals for built-in live providers.
- Operator-configured `litellm` URLs must be HTTPS public DNS names on port 443 with path empty or `/v1`.
- Microsoft Foundry URLs must be HTTPS Azure resource DNS names ending in `.openai.azure.com` or `.services.ai.azure.com` with path `/openai/v1`.
- Cloudflare AI Gateway URLs are constructed from path-safe `account_id` and `gateway_id`; caller-provided `base_url` is rejected.
- Fixed gateway descriptors reject mismatched `base_url` overrides.
- Manifest live-operation network policy requires TLS/SNI, denies localhost, private ranges, tailnet ranges, and IP literals, and allows only the configured provider host set on port 443.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `120000 ms` wall-clock timeout, no exec, no ptrace, read-only `/usr` and `/lib`, and writable `$CONNECTOR_STATE`.
- The connector does not open inbound sockets.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `llm-router.route` | Select a provider/model and estimate request cost. Also gates `llm-router.estimate_cost` in runtime metadata. |
| `llm-router.admin` | Read provider inventory, usage counters, and budget counters. |
| `llm-router.estimate` | Manifest rate-limit pool for cost estimation; not a runtime introspection capability in this checkout. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `llm-router.route` | Local selection only, no provider egress | `llm-router.route` | `Safe` | `Medium` | `None` | Chooses one configured provider/model and returns a dispatch instruction. |
| `llm-router.estimate_cost` | Local model-cost estimate | `llm-router.route` | `Safe` | `Low` | `Strict` | Estimates all configured provider/model costs and returns the cheapest available recommendation. |
| `llm-router.list_providers` | Local provider inventory | `llm-router.admin` | `Safe` | `Low` | `Strict` | Lists configured providers, status, capability union, p50 latency, and optional model metadata. |
| `llm-router.get_usage` | Local in-memory counters | `llm-router.admin` | `Safe` | `Low` | `Strict` | Returns session input/output token estimates, cost, request count, error count, and optional provider breakdown. |
| `llm-router.get_budget` | Local in-memory budget state | `llm-router.admin` | `Safe` | `Low` | `Strict` | Returns configured budget, spent amount, remaining amount, enforcement mode, period, and empty alerts. |

## Explicit Non-Goals

The current implementation does not include:

- provider inference dispatch, streaming responses, tool-call execution, embeddings, image generation, or chat-completion normalization
- live model listing during configure or self-check
- durable usage/budget persistence, monthly billing reconciliation, provider dashboard reconciliation, or quota sync
- OAuth setup for provider accounts, API key provisioning, credential vaulting, or token refresh
- automatic failover after provider execution failures, because provider execution is not performed here
- inbound webhooks, event streams, or background health monitoring

These are excluded on purpose:

- FCP security invariant 3 requires cross-connector composition through the Gateway, not direct connector-to-connector calls.
- Provider execution needs provider-specific policy, redaction, retry, streaming, and provenance contracts.
- Cost estimates are heuristics and should not be treated as billing truth.

## Readiness And Verification Surface

`handle_doctor()`, `handle_health()`, `handle_self_check()`, `handle_simulate()`, and `handle_introspect()` are part of the public closeout contract. They surface:

- local configuration state
- provider readiness by auth, network policy, and model count
- credential-injection requirement for credential-id mode
- budget configuration and in-memory spend
- static provider health and latency state
- known operation metadata, schemas, capability IDs, risk levels, safety tiers, idempotency, and AI hints
- FCP and legacy capability-token behavior during invoke

The deterministic integration evidence is anchored on connector-local tests covering:

- provider configuration for baseline hosts and built-in gateway descriptors
- Cloudflare, Vercel, LiteLLM, and long-tail OpenAI-compatible provider catalog behavior
- route output schema, dispatch-only contract, strategy selection, capability filters, provenance, budget behavior, and usage counters
- provider host policy, reserved gateway host rejection, unsafe base URL rejection, auth redaction, and header-injection rejection
- lifecycle, doctor, self-check, introspection, simulation, and shutdown behavior
- malformed inputs, unknown operations, missing capability tokens, and provider/model selection edge cases

## Source Notes

- `connectors/llm-router/src/connector.rs` defines configuration parsing, lifecycle handlers, diagnostics, capability-token checks, introspection, simulation, operation dispatch, routing output, usage, budget, provider policy, and gateway descriptor handling.
- `connectors/llm-router/src/routing.rs` defines token estimation, candidate construction, strategy selection, capability filtering, preferred-provider behavior, and cost calculation.
- `connectors/llm-router/src/types.rs` defines routing strategy, provider status, model capabilities, provider auth, gateway endpoint descriptors, built-in provider catalog, host policy, budget types, and usage structures.
- `connectors/llm-router/src/client.rs` defines the OpenAI-compatible HTTP helper, auth headers, extra headers, retry behavior, chat-completion dispatch helper, model-list helper, and health-probe helper.
- `connectors/llm-router/src/error.rs` defines router error classes and FCP error conversion.
- `connectors/llm-router/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, rate-limit pools, and AI hints.
- `connectors/llm-router/tests/integration.rs` covers connector-level behavior and gateway-provider catalog behavior.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/llm_router_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- runtime operation inventory and policy metadata
- deterministic provider catalog and routing behavior
- auth, provider error, lifecycle, simulation, introspection, self-check, and doctor coverage
- formatting, check, test, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use synthetic provider configs for routine verification.
- Use disposable provider keys for any future live transport proof.
- Keep model IDs and per-token costs explicit in configuration.

**Dedicated environment**:

- Prefer configured gateway providers when routing across heterogeneous model vendors.
- Use `litellm` only with a public HTTPS gateway URL that passes the runtime policy.
- Use `cloudflare-ai-gateway` with `account_id` and `gateway_id`; omit `base_url`.
- Use `vercel-ai-gateway` with provider-prefixed model IDs unless relying on the built-in Claude aliases.
- Use `microsoft-foundry` with `credential_id`, explicit deployment IDs, optional `deployment_aliases`, and `api_family` values `responses`, `chat`, `streaming`, or `embeddings`. Use `fallback_policy = "none"` when a request must stay inside the Azure enterprise boundary.
- Treat route output as a plan, not as provider output.

**Redaction rules**:

- Redact provider API keys, gateway API keys, credential IDs where needed, prompts, tool schemas, model/provider names when sensitive, budget numbers when sensitive, and provider error bodies.
- Verification output should use operation IDs, provider classes, endpoint classes, strategy names, HTTP status classes, retry decisions, and synthetic model IDs.

**Common remediation**:

- If configuration fails, provide a non-empty `providers` array.
- If provider auth fails, provide exactly one of `api_key` or `credential_id`.
- If Cloudflare AI Gateway configuration fails, remove `base_url` and provide path-safe `account_id` and `gateway_id`.
- If a fixed provider rejects `base_url`, omit the override or use the descriptor's exact URL.
- If Microsoft Foundry configuration fails, ensure `base_url` ends `/openai/v1`, uses an Azure Foundry/OpenAI resource host, and uses `credential_id` rather than a raw API key.
- If `litellm` rejects a URL, use HTTPS public DNS on port 443 with no userinfo, query, fragment, IP literal, private host, `.local` host, or custom path other than `/v1`.
- If route fails for capability requirements, call `llm-router.list_providers` with `include_models = true` and verify each model's capabilities.
- If route appears to succeed but no generated content is returned, dispatch the selected provider/model through the appropriate provider connector.
- If `simulate` allows a request but policy should deny it, remember that current simulation only checks whether the connector is configured.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-llm-router-readme cargo check -p fcp-llm-router --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-llm-router-readme cargo test -p fcp-llm-router --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-llm-router-readme cargo clippy -p fcp-llm-router --all-targets --no-deps -- -D warnings`
- `ubs connectors/llm-router/README.md`
