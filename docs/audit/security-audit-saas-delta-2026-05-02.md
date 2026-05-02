# SaaS Delta Security Audit - 2026-05-02

Agent: VioletPine

Scope:
- `crates/fcp-streaming`
- `crates/fcp-webhook`
- `crates/fcp-graphql`
- `crates/fcp-oauth`

Focus:
- Auth bypass through empty or null tokens
- Signature verification ordering
- Replay and idempotency defense
- OAuth state-injection regressions
- GraphQL depth, complexity, and request-size DoS
- Webhook idempotency and duplicate-delivery handling

## Findings Filed

### `flywheel_connectors-gxwsv`

`[security-audit][delta] Webhook HMAC verifiers accept empty signing secrets`

Evidence:
- `crates/fcp-webhook/src/signature.rs` constructs `HmacSha256Verifier` and `HmacSha1Verifier` by copying the provided secret bytes without rejecting zero-length input.
- Existing tests assert empty-secret HMAC verification succeeds.
- `crates/fcp-webhook/src/provider.rs` forwards GitHub, Stripe, Slack, and Linear secrets into `HmacSha256Verifier::new` without validation.

Impact:
An empty or missing env/config secret becomes a deterministic empty-key HMAC that an attacker can compute.

Required fix:
Reject empty or whitespace-only HMAC secrets at verifier/provider construction time and update tests to assert fail-closed behavior.

### `flywheel_connectors-v0wme`

`[security-audit][delta] OAuth callback accepts empty authorization code after state validation`

Evidence:
- `AuthorizationCallback::validate` verifies state, then returns `self.code` with only an `Option` presence check.
- `code=&state=<valid>` deserializes as `Some("")`.
- `AuthorizationSession::validate_callback` consumes the one-time session on successful callback validation.
- `exchange_code_internal` inserts the supplied code into token-request parameters without rejecting empty strings.

Impact:
A state-bearing empty-code callback can consume a valid authorization session and drive token exchange with an invalid authorization code.

Required fix:
Reject empty or whitespace-only authorization codes in callback validation and direct exchange APIs, and test that invalid empty-code callbacks do not consume sessions.

### `flywheel_connectors-nb1p2`

`[security-audit][delta] GraphQL bearer-token helper accepts empty tokens`

Evidence:
- `GraphqlClientBuilder::with_bearer_token` always formats `Authorization: Bearer <token>`.
- The current unit test asserts that an empty token produces `Authorization: Bearer `.

Impact:
Connector config paths can silently treat empty auth material as configured auth, masking configuration failure and sending ambiguous bearer headers to upstream services.

Required fix:
Reject empty or whitespace-only bearer tokens during configuration/build and update tests to require rejection.

### `flywheel_connectors-ziovc`

`[security-audit][delta] GraphQL requests lack query depth and size guardrails`

Evidence:
- `GraphqlQuery::new` accepts arbitrary query strings, including empty and very long strings.
- `execute_request` and `execute_batch_request` serialize query text directly into outbound requests.
- GraphQL subscription setup forwards `O::QUERY` into the WebSocket subscribe payload without local query limits.
- No query-byte, depth, alias, or complexity limit is present in `GraphqlClientConfig`.

Impact:
Agent- or user-influenced GraphQL operations can create oversized or deeply nested queries that amplify cost against upstream GraphQL APIs or internal gateways.

Required fix:
Add explicit query byte/depth/complexity limits for normal, batch, and subscription operations, and fail closed before sending pathological queries.

## Reviewed Controls Without New Findings

Webhook signature verification ordering:
- Provider implementations cap body size before expensive HMAC/JSON work.
- GitHub, Stripe, Slack, and Linear paths verify signatures before JSON parsing.
- Stripe and Slack enforce timestamp freshness before accepting signed events.

Webhook replay/idempotency:
- `WebhookHandler::claim_event` provides atomic duplicate-delivery rejection.
- The older split `check_replay` / `record_event` APIs are documented as deprecated and racy; runtime callers in the audited crate use `claim_event` where atomic replay rejection is required.

OAuth state handling:
- Duplicate OAuth callback parameters are rejected.
- Provider error callbacks must carry a matching state before provider-controlled error fields are surfaced.
- Empty expected state and empty callback state are rejected.
- PKCE token parameters are ordered so generated verifier material overrides extra token params.

Streaming:
- `fcp-streaming` redacts configured headers in debug output.
- SSE has bounded parser data retention and configured buffer clamps.
- WebSocket handshake code rejects unsolicited pong replay before treating a connection as live.
- No auth-specific helper was found in `fcp-streaming`; generic header builders still need callers to validate auth material before insertion.
