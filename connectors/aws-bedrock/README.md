# AWS Bedrock Connector V1 Contract

> **Status**: Bedrock Runtime, Bedrock Mantle Anthropic Messages, and control-plane slices documented with SigV4, bearer-token, event-stream/SSE, and verification-bundle boundaries
> **Bead**: `flywheel_connectors-4kw5f.2.9.2.13.1`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/aws_bedrock_connector_verification.sh`
> **Converse upstream**: https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_Converse.html
> **ConverseStream upstream**: https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_ConverseStream.html
> **InvokeModel upstream**: https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_InvokeModel.html
> **InvokeModelWithResponseStream upstream**: https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_InvokeModelWithResponseStream.html
> **ListFoundationModels upstream**: https://docs.aws.amazon.com/bedrock/latest/APIReference/API_ListFoundationModels.html

## Purpose

This document fixes the operator-facing contract for `fcp.aws-bedrock`. The connector exposes the AWS Bedrock Runtime and model-discovery surface currently implemented in this crate: Converse, ConverseStream, InvokeModel, InvokeModelWithResponseStream, foundation model listing, Bedrock Mantle Anthropic Messages routing, Mantle model listing, and local health/provisioning metadata for one configured AWS region and credential set.

The connector is intentionally a Bedrock Runtime adapter. It is not an AWS account bootstrapper, IAM policy authoring tool, model-access enrollment flow, Bedrock Agents client, Knowledge Bases client, Guardrails manager, Prompt Management editor, Marketplace endpoint provisioner, async invoke job tracker, billing analyzer, quota manager, or generic AWS SDK wrapper.

## Current Runtime Snapshot

The current crate exposes these runtime operation IDs:

- `aws_bedrock.converse`
- `aws_bedrock.converse_stream`
- `aws_bedrock.invoke_model`
- `aws_bedrock.invoke_model_stream`
- `aws_bedrock.models.list`
- `aws_bedrock.health`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-aws-bedrock`.
- Runtime and manifest connector ID are `fcp.aws-bedrock`.
- Configuration requires `region` plus either `access_key_id` and `secret_access_key` for SigV4 calls or `mantle_bearer_token` for Bedrock Mantle calls.
- `session_token` is optional and changes the reported auth mode from `static_keys` to `static_keys_with_session_token`.
- `request_timeout_ms` defaults to `240000` and must be greater than zero.
- `retry` uses the shared `HttpRetryConfig` and `RetryLoop` path.
- `runtime_base_url` and `control_base_url` are optional endpoint overrides for deterministic verification.
- `mantle_base_url` is an optional endpoint override for deterministic Mantle `/v1/models` and `/anthropic/v1/messages` verification.
- Endpoint overrides are trimmed, stripped of trailing slashes, must not include credentials, query strings, or fragments, and must use HTTPS unless they target localhost for verification.
- Default Runtime endpoint shape is `https://bedrock-runtime.{region}.amazonaws.com`.
- Default control-plane endpoint shape is `https://bedrock.{region}.amazonaws.com`.
- All Bedrock requests are SigV4-signed with service name `bedrock`.
- Bedrock Mantle requests use bearer auth and never treat `AWS_BEARER_TOKEN_BEDROCK` as an Anthropic API key. The connector accepts the resulting bearer token as `mantle_bearer_token`; IAM credential-chain token minting remains a provisioning concern.
- `converse` and `converse_stream` use the unified Bedrock message shape.
- `invoke_model` and `invoke_model_stream` accept either raw `body` JSON or a connector-built body for selected model families.
- `invoke_model` and `invoke_model_stream` also accept `model_family = "mantle_anthropic_messages"` to call Mantle's `/anthropic/v1/messages` route, including default `fine-grained-tool-streaming-2025-05-14` beta header injection, optional reasoning budget expansion, and SSE normalization into the existing stream response envelope.
- Built model-family bodies currently cover `anthropic_claude`, `meta_llama`, `amazon_titan`, `cohere_command`, and `mistral`.
- AWS event-stream responses are decoded into event metadata, payload byte counts, and JSON or UTF-8 payloads.
- `self_check()` abstains from the default AWS control-plane endpoint and requires `control_base_url` for deterministic reachability proof.
- `health()` is degraded when default Bedrock endpoints are configured because the connector refuses to probe production AWS during local readiness.
- Runtime computes `manifest_hash` from `manifest.toml`.
- Runtime `invoke` verifies a bound capability token before provider dispatch.
- Runtime `simulate` uses the same capability verifier and reports missing capabilities when appropriate.
- FCP subscription APIs are not supported even though streaming Bedrock request-response operations are implemented.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- The manifest limits declared production hosts to `us-east-1` and `us-west-2`, while runtime accepts any syntactically valid lowercase AWS region.
- Runtime endpoint overrides allow HTTPS hosts outside the manifest allowlist and HTTP loopback hosts for deterministic verification.
- The manifest advertises streaming as an archetype and handshake reports `streaming: true`, but `subscribe()` and `unsubscribe()` still return `StreamingNotSupported`.
- Bedrock streaming is currently exposed as request-response event-stream decoding, not as an FCP subscription or replay stream.
- `handshake()` grants every requested capability instead of filtering to `aws_bedrock.chat` and `aws_bedrock.models.read`.
- Runtime rejects model IDs containing `/`, `\`, `..`, or encoded slash/backslash forms, even though some AWS model ARN and prompt-resource shapes include slash path components.
- `self_check()` deliberately refuses to hit default AWS endpoints with operator credentials.
- The checked-in verification bundle exists for AWS Bedrock, but live verification is skipped unless `AWS_BEDROCK_E2E=1`.

A follow-up parity bead should align manifest host policy with runtime region behavior, filter handshake grants, reconcile FCP streaming metadata with unsupported subscription APIs, and add a shared SigV4 path canonicalizer that can safely support slash-bearing model resources.

## First-Slice Scope

The current AWS Bedrock README slice documents the existing runtime surface:

- static AWS credential configuration and optional session-token mode
- Runtime and control-plane endpoint override rules
- Converse, ConverseStream, InvokeModel, InvokeModelWithResponseStream, foundation model listing, and local health metadata
- SigV4 signing, retry, event-stream decoding, and Bedrock error mapping
- bound capability-token enforcement for invoke and simulate
- doctor, health, self-check, introspect, simulate, shutdown, and non-subscription posture
- tracked verification bundle behavior and optional live smoke gate
- drift around region host policy, model ID path rejection, handshake grants, and streaming metadata

## Auth And Scope Boundary

- Authentication mechanisms: static AWS access key ID and secret access key, with optional session token, for native Bedrock; explicit `mantle_bearer_token` for Bedrock Mantle.
- Runtime does not implement AWS SSO, profile loading, EC2/ECS metadata credentials, STS AssumeRole, credential process execution, web identity, Secrets Manager loading, or connector-local credential persistence.
- Home zone: `z:work`.
- Allowed source zones: `z:work` and `z:private`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Capability families:
  - `aws_bedrock.chat` gates model inference operations.
  - `aws_bedrock.models.read` gates foundation model listing and local health metadata.
- Required network capabilities: `network.dns`, `network.egress`, and `network.tls.sni`.
- Forbidden capabilities: `system.exec`, `network.listen`, and `system.privileged`.
- Prompts, completions, tool payloads, guardrail traces, request metadata, model IDs, AWS account identifiers, AWS keys, session tokens, SigV4 signatures, and provider error bodies are work-sensitive or private-sensitive data. Redact them before sharing evidence.

## Network And Runtime Invariants

- Runtime API paths:
  - `POST /model/{model_id}/converse`
  - `POST /model/{model_id}/converse-stream`
  - `POST /model/{model_id}/invoke`
  - `POST /model/{model_id}/invoke-with-response-stream`
  - `GET /foundation-models`
- Bedrock Mantle API paths:
  - `GET /v1/models`
  - `POST /anthropic/v1/messages`
- `models.list` supports `byCustomizationType`, `byInferenceType`, `byOutputModality`, and `byProvider` query filters.
- `models.list` accepts `source = "mantle"` to query Mantle's OpenAI-format model catalog and normalize it into the connector's model summary envelope.
- `model_id` must be nonblank and must not contain slashes, backslashes, `..`, `%2f`, or `%5c`.
- Converse request fields are converted to AWS camel-case JSON fields such as `inferenceConfig`, `additionalModelRequestFields`, `additionalModelResponseFieldPaths`, `guardrailConfig`, `performanceConfig`, `promptVariables`, `requestMetadata`, and `toolConfig`.
- InvokeModel defaults `accept` and `content_type` to `application/json`.
- InvokeModel applies optional trace, guardrail, performance, and service-tier headers.
- Event-stream decoding validates prelude CRC and message CRC and returns chunk counts plus total payload bytes.
- Mantle Anthropic streaming decodes SSE `event:`/`data:` blocks into the same chunk-count and payload metadata envelope without logging streamed text.
- `401` and `403` map to unauthorized, `404` maps to resource-not-found, and `429` maps to rate limiting with a default retry-after.
- Retryable API classes include timeouts, throttling, model-not-ready, service-unavailable, 408, 424, 429, and 5xx-style statuses.
- AWS API response bodies are not persisted by the connector.
- Sandbox profile is strict, with no exec, no inbound listen, and no privileged system access.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `aws_bedrock.chat` | Run Converse, ConverseStream, InvokeModel, and InvokeModelWithResponseStream. |
| `aws_bedrock.models.read` | List foundation models and read local connector health/provisioning metadata. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Required input |
|-----------|----------------|------------|------------|-----------|-------------|----------------|
| `aws_bedrock.converse` | `POST /model/{model_id}/converse` | `aws_bedrock.chat` | `Risky` | `Medium` | `BestEffort` | `model_id`, `messages`. |
| `aws_bedrock.converse_stream` | `POST /model/{model_id}/converse-stream` | `aws_bedrock.chat` | `Risky` | `Medium` | `BestEffort` | `model_id`, `messages`. |
| `aws_bedrock.invoke_model` | `POST /model/{model_id}/invoke` | `aws_bedrock.chat` | `Risky` | `Medium` | `BestEffort` | `model_id` plus `body` or `model_family`. |
| `aws_bedrock.invoke_model_stream` | `POST /model/{model_id}/invoke-with-response-stream` | `aws_bedrock.chat` | `Risky` | `Medium` | `BestEffort` | `model_id` plus `body` or `model_family`. |
| `aws_bedrock.models.list` | `GET /foundation-models` | `aws_bedrock.models.read` | `Safe` | `Low` | `Strict` | None; optional list filters. |
| `aws_bedrock.health` | local readiness plus provisioning metadata | `aws_bedrock.models.read` | `Safe` | `Low` | `Strict` | None. |

## Explicit Non-Goals

The current implementation does not include:

- AWS account creation, IAM role creation, IAM policy attachment, model access enrollment, or quota/billing setup
- AWS SSO, shared credential files, STS AssumeRole, web identity, EC2/ECS metadata credentials, or Secrets Manager integration
- Bedrock Agents, Knowledge Bases, Guardrails management, Prompt Management mutation, Marketplace endpoint creation, custom model jobs, provisioned throughput management, async invoke jobs, or response-file download
- OpenAI-compatible Bedrock endpoints, Chat Completions, Responses API, or model-router policy management
- FCP subscription streams, replay buffers, acknowledgements, durable transcript storage, prompt caching, or output moderation persistence

These are excluded on purpose:

- Bedrock prompts and completions can contain sensitive work data and should not be persisted by the connector.
- Live provider calls spend quota and may have billing impact.
- Credential provisioning belongs in an AWS setup surface, not in a request-response connector.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, `introspect()`, and the tracked verification script are part of the public closeout contract. They surface:

- configured state, client/runtime initialization, handshake state, manifest hash, region, auth mode, endpoint overrides, request timeout, and artifact root hint
- SigV4 readiness and event-stream decoder readiness
- explicit degraded state when self-check would otherwise hit default AWS control-plane endpoints
- operation catalog, schemas, capabilities, risk levels, safety tiers, idempotency classes, and AI hints
- bound capability-token acceptance and denial in both `invoke` and `simulate`
- non-replay streaming metadata plus unsupported FCP subscribe/unsubscribe behavior

The tracked verification bundle runs:

- manifest check through `fwc manifest fix connectors/aws-bedrock/manifest.toml --check --json` or an `rch` cargo-run fallback
- `rch exec -- cargo check -p fcp-aws-bedrock --all-targets`
- `rch exec -- cargo fmt -p fcp-aws-bedrock -- --check`
- `rch exec -- cargo test -p fcp-aws-bedrock --test integration -- --nocapture`
- `rch exec -- cargo clippy -p fcp-aws-bedrock --all-targets -- -D warnings`
- optional `rch exec -- cargo test -p fcp-aws-bedrock --test live_verification -- --nocapture` when `AWS_BEDROCK_E2E=1`

The deterministic integration evidence is anchored on WireMock and fixture JSONL coverage for SigV4 headers, Converse, InvokeModel, stream frame decoding, model listing, provider error mapping, and connector-boundary behavior.

The verification script has two explicit modes:

- `--mode replay` is the default. It runs the deterministic WireMock-backed proof lane, writes schema-versioned JSON artifacts under the selected `OUT_ROOT`, and emits a structured live-skip record instead of touching AWS.
- `--mode live` also runs `tests/live_verification.rs` with `AWS_BEDROCK_E2E=1`. It requires a sealed Bedrock test account and the `AWS_BEDROCK_*` variables documented in [aws_bedrock_e2e_test_account.md](../../docs/runbooks/aws_bedrock_e2e_test_account.md).

UBS disposition for this connector lives in [UBS_DISPOSITION.md](UBS_DISPOSITION.md). The current scanner run reports zero critical findings; remaining warnings are test panic inventories, checked parser/index invariants, and performance/style inventories that do not block replay proof.

## Source Notes

- `connectors/aws-bedrock/src/types.rs` defines credentials, request bodies, model-family body builders, foundation model summaries, and stream response shapes.
- `connectors/aws-bedrock/src/client.rs` defines endpoint construction, SigV4 signing, Bedrock paths, retry loops, JSON response handling, event-stream response handling, and model ID validation.
- `connectors/aws-bedrock/src/event_stream.rs` defines AWS event-stream frame decoding and CRC validation.
- `connectors/aws-bedrock/src/connector.rs` defines lifecycle handlers, capability-token enforcement, operation metadata, diagnostics, self-check behavior, and verification guidance.
- `connectors/aws-bedrock/src/error.rs` defines provider/FCP error mapping and retry classification.
- `connectors/aws-bedrock/manifest.toml` defines the operation catalog, capability families, zone policy, network constraints, and sandbox boundary.
- `connectors/aws-bedrock/tests/integration.rs` covers deterministic HTTP behavior, SigV4 request behavior, stream decoding, and capability-token paths.
- `connectors/aws-bedrock/tests/live_verification.rs` covers optional live smoke behavior when explicitly enabled.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/aws-bedrock/README.md
ubs connectors/aws-bedrock/README.md
LC_ALL=C rg -n '[^ -~]' connectors/aws-bedrock/README.md
```

For source or behavior changes, use the tracked verification bundle:

```bash
scripts/e2e/aws_bedrock_connector_verification.sh --mode replay
```

Direct proof commands from the bundle are:

```bash
fwc manifest fix connectors/aws-bedrock/manifest.toml --check --json
rch exec -- cargo check -p fcp-aws-bedrock --all-targets
rch exec -- cargo fmt -p fcp-aws-bedrock -- --check
rch exec -- cargo test -p fcp-aws-bedrock --test integration -- --nocapture
rch exec -- cargo clippy -p fcp-aws-bedrock --all-targets -- -D warnings
```

Set `AWS_BEDROCK_E2E=1` only for a disposable verification account with cheapest-model smoke settings before running the live smoke suite.
The preferred live invocation is:

```bash
AWS_BEDROCK_ACCESS_KEY_ID=... \
AWS_BEDROCK_SECRET_ACCESS_KEY=... \
AWS_BEDROCK_REGION=us-east-1 \
AWS_BEDROCK_MODEL_ID=anthropic.claude-3-haiku-20240307-v1:0 \
scripts/e2e/aws_bedrock_connector_verification.sh --mode live
```

## Operator Guidance

Prerequisites:

- Provision credentials scoped to `bedrock:InvokeModel`, `bedrock:InvokeModelWithResponseStream`, and `bedrock:ListFoundationModels` for the intended region.
- Use `runtime_base_url` and `control_base_url` overrides for routine deterministic proof.
- Use a disposable AWS account or tightly scoped role for live smoke.

Dedicated environment:

- Prefer WireMock or a signing-proxy verifier for closeout evidence.
- Keep live prompts synthetic and non-sensitive.
- Keep model selection stable and low-cost.

Redaction rules:

- Redact access keys, secret keys, session tokens, SigV4 signatures, prompt text, completion text, guardrail traces, request metadata, AWS account IDs, provider error bodies, and raw request/response logs.
- Verification artifacts should contain only model IDs, body sizes, token counts, stream chunk counts, HTTP status, and signature prefix hashes.

Common remediation:

- If `configure` fails, verify region syntax, nonblank credentials, positive timeout, and endpoint override shape.
- If `health` is degraded on default endpoints, use `self_check` only with a deterministic `control_base_url`.
- If `invoke_model` reports missing input, provide either `body` or `model_family`.
- If model IDs with ARNs or prompt resources fail validation, confirm whether they include slash path components; this runtime intentionally rejects those today.
- If `simulate` reports missing capabilities, mint a bound token for `aws_bedrock.chat` or `aws_bedrock.models.read` according to the operation.

Rerun commands:

- `git diff --check -- connectors/aws-bedrock/README.md`
- `ubs connectors/aws-bedrock/README.md`
- `scripts/e2e/aws_bedrock_connector_verification.sh`
