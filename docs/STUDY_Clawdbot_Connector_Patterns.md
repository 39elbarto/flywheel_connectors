# Study: Clawdbot Connector Patterns — Synthesis & Recommendations

**Bead**: `flywheel_connectors-bvs`
**Status**: In Progress (blocked by `flywheel_connectors-v6w` closure)
**Date**: 2026-01-27

## Executive Summary

This synthesis merges findings from the Discord and Telegram connector studies into actionable guidance for FCP2 connector design. The shared core is: **supervised connectivity + strict input validation + deterministic retries + structured events + default‑deny security**. The differentiators are transport (WebSocket vs polling), ordering (gateway sequence vs per-chat sequentialization), and state durability (session resumption vs update offsets). This document provides a single-source pattern library, a template skeleton, style guidance, a review checklist, and a migration plan to port existing connectors into FCP2.

Sources:
- `docs/STUDY_Discord_Connector_Implementation.md`
- `docs/STUDY_Telegram_Connector_Implementation.md`

---

## 1. Common Patterns Identified (Cross-Platform)

### 1.1 Supervised Connectivity + Backoff
- **Discord**: WebSocket supervisor loop with exponential backoff + session resumption.
- **Telegram**: Polling loop with backoff + recoverable error classifier + update offset.

**FCP2 take**: Provide a reusable `SupervisedConnection` utility in SDK or shared kit to encapsulate backoff, retry budgets, and shutdown hooks.

### 1.2 Input Validation Before Side Effects
- Validate parameters before API calls (Discord: content/embeds limits; Telegram: target normalization, parse mode constraints).

**FCP2 take**: Standardize a `ValidateInput` trait for operations and enforce input+output schema checks at SDK boundary.

### 1.3 Explicit Ordering Semantics
- **Discord**: gateway sequence + heartbeat; order preserved by protocol.
- **Telegram**: per-chat sequentialization key to avoid reordering.

**FCP2 take**: Expose ordering hints in `EventEnvelope` metadata (e.g., `stream_key`, `sequence`), and support SDK-level sequential processing by key.

### 1.4 Retry Taxonomy and Recoverability
- **Discord**: error classification with retryable/non-retryable + Retry-After.
- **Telegram**: centralized recoverable error classifier for polling/webhook/send.

**FCP2 take**: Provide a shared `RetryPolicy` + `RetrySemantics` mapping to FCP error taxonomy (FCP‑7xxx for external errors).

### 1.5 Rate Limiting at the Edge
- **Discord**: REST rate limit buckets.
- **Telegram**: grammY throttler.

**FCP2 take**: SDK should expose RateLimitDeclarations + enforcement hooks (per op + per connector pool).

### 1.6 Strict Formatting + Fallback
- Telegram HTML parsing fallback to plain text.

**FCP2 take**: Provide a platform-specific formatter with “safe fallback” on parse failures.

---

## 2. Platform-Specific Adaptations

### Discord-Specific
- WebSocket heartbeats + zombie detection
- Session resumption (session_id/sequence)
- Typed events (avoid `serde_json::Value` in gateway events)

### Telegram-Specific
- Update offset persistence + dedupe
- Forum topic threading (`message_thread_id`)
- Group migration (old chat ID -> new -100... ID)
- getUpdates 409 conflict handling
- Node 22 networking workaround (`autoSelectFamily`)

**FCP2 take**: Treat these as optional “capability modules” in SDK: `StreamingSupervisor` (Discord), `PollingSupervisor` (Telegram).

---

## 3. Reusable Components Catalog

### Core Infrastructure
- **RetryConfig + RetryPolicy** (shared across connectors)
- **Supervisor loop + backoff**
- **Heartbeat manager** (for streaming)
- **Error classifier** (retryable vs terminal)
- **Rate limit enforcement**

### Message Processing
- **Command parser** + normalization
- **Formatter + safe fallback**
- **Attachment/media handling** (split captions, follow-up text)
- **Inline action adapters** (buttons/menus)

### State Management
- **Session tracking** (streaming resume)
- **Update offset + dedupe cache** (polling)
- **Group/thread routing** (per-peer session keys)
- **State durability** (mesh-backed, not local disk)

---

## 4. Anti-Patterns to Avoid

1. **Unbounded raw JSON events** → prefer typed structs + `Unknown(Value)` fallback.
2. **Inline state mutation inside event handlers** → return state updates, apply centrally.
3. **Magic numbers** for limits → define `limits.rs` constants per platform.
4. **No shutdown path** for streaming loops → add explicit shutdown signals.
5. **Local disk secrets/state** → replace with mesh-backed ConnectorState + secret injection.
6. **Implicit allow** when allowlist empty → default deny unless explicitly granted.

---

## 5. FCP2 Connector Design Recommendations

### 5.1 Architecture (Recommended Module Layout)
```
connectors/<platform>/src/
├── lib.rs           # re-exports + archetype declaration
├── main.rs          # stdin/stdout loop or host integration
├── connector.rs     # FcpConnector impl
├── config.rs        # config + defaults
├── error.rs         # platform errors + retryability
├── types.rs         # platform API types
├── limits.rs        # platform limits + TODOs
├── api.rs           # REST client (if applicable)
├── stream.rs        # streaming supervisor (if applicable)
└── polling.rs       # polling cursor + scheduler (if applicable)
```

### 5.2 Implementation Guidelines
- **Schema-first**: Validate input/output schemas at SDK boundary.
- **Default deny**: No ambient authority; capabilities must be explicit.
- **Secrets never on disk**: use host injection or mesh secret objects.
- **Structured logs**: JSON logs with `connector_id`, `zone_id`, `operation_id`, `correlation_id`.
- **Strict timeouts**: enforce connect/read/total timeouts.
- **Fail closed**: on auth and policy errors, deny by default.

### 5.3 Documentation Standards
- Document every operation with schema, risk tier, and example.
- Provide minimal onboarding steps; reduce manual steps where possible.
- Include troubleshooting section with common error codes.

---

## 6. FCP Connector Template (Skeleton)

### 6.1 Directory Skeleton
```
connectors/fcp.myservice/
├── Cargo.toml
├── manifest.toml
└── src/
    ├── main.rs
    ├── lib.rs
    ├── connector.rs
    ├── config.rs
    ├── error.rs
    ├── limits.rs
    ├── types.rs
    ├── api.rs       # request-response only
    ├── stream.rs    # streaming or bidirectional
    └── polling.rs   # polling only
```

### 6.2 Minimal Connector Skeleton (Rust)
```rust
// connector.rs
use fcp_sdk::prelude::*;

pub struct MyServiceConnector {
    base: BaseConnector,
    config: MyServiceConfig,
}

#[async_trait]
impl FcpConnector for MyServiceConnector {
    fn id(&self) -> &ConnectorId { &self.base.id }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        self.config = MyServiceConfig::from_json(config)?;
        self.base.set_configured(true);
        Ok(())
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        validate_input(&req)?; // schema + limits
        // ... execute ...
        Ok(InvokeResponse::success(serde_json::json!({})))
    }
}
```

### 6.3 Default-Deny Manifest Pattern
- NetworkConstraints must be explicit per operation.
- No IP literals, redirects disabled by default, timeouts + max response sizes set.

---

## 7. Style Guide (Connector Engineering)

- **Errors**: use FCP codes + retry semantics (`RetryImmediately`, `BackoffWithJitter`, `RetryAfter`).
- **Validation**: reject invalid inputs before touching external APIs.
- **Observability**: structured logs only; never log tokens or PII.
- **Testing**: mocks only in CI; deterministic timing; no external network calls.
- **Safety**: `#![forbid(unsafe_code)]` at crate root.

---

## 8. Connector Review Checklist

- [ ] Manifest passes validation (single-zone binding, default-deny network constraints)
- [ ] Input + output schemas enforced
- [ ] Operations mapped to capability families
- [ ] Errors return stable FCP codes + retry semantics
- [ ] Secrets never written to disk
- [ ] Structured logs with correlation + trace context
- [ ] Rate limit declarations present (if applicable)
- [ ] Streaming: heartbeat + supervised reconnect
- [ ] Polling: update offset persistence + dedupe
- [ ] Tests: mock-only, deterministic, no network

---

## 9. Migration Guide (Clawdbot → FCP2)

1. **Inventory operations**: list API calls, rate limits, and side effects.
2. **Define manifest**: capabilities + network constraints per operation.
3. **Map state**: replace local caches with mesh-backed ConnectorState.
4. **Implement SDK boundary**: schema validation + error taxonomy.
5. **Integrate supervisor**: streaming/polling with backoff.
6. **Add tests**: mock-based unit + integration harness.
7. **Enable observability**: structured logs + receipts.

---

## 10. Gaps / Next Work

- Formalize shared `fcp-connector-kit` utilities (retry, supervisor, heartbeat).
- Encode ordering semantics in EventEnvelope metadata.
- Add SDK helpers for polling update offsets backed by mesh state.
- Standardize formatter adapters with safe fallback across connectors.

---

## Acceptance Criteria Alignment

- Deterministic CI: mocks only, no real network.
- Structured JSON logs with stable `test_name` identifiers.
- Clear template + checklist usable by `fcp new` scaffold.
