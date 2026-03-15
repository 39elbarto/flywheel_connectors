# FCP3 Tokio Compatibility Bridge Decision

> Bead: `bs5ih.6` — Evaluate whether the Tokio compat bridge can be removed
>
> Author: BeigeCave | Date: 2026-03-15
>
> Decision: **RETAIN the bridge as managed infrastructure** (Option 3)

---

## Context

The `fcp-async-core` crate wraps the Asupersync runtime and maintains a Tokio
compatibility bridge (`get_or_create_tokio_compat_handle` +
`TokioContextFuture`). This bridge exists because two widely-used crates —
`wiremock` and `reqwest` — internally call `tokio::runtime::Handle::current()`.

## Current State (2026-03-15)

| Metric | Count |
|--------|-------|
| wiremock usages (Cargo.toml) | ~90 (all connectors + core test infrastructure) |
| reqwest usages (Cargo.toml) | ~90 (all connectors + fwc + core crates) |
| tokio-tungstenite usages | 3 (slack, discord, fcp-graphql tests) |
| asupersync-tokio-compat usages | 2 (fcp-async-core, fcp-graphql tests) |

## Options Evaluated

### Option 1: Replace wiremock with native mock server

**Effort:** Very high
- wiremock is used in ~90 test files across the workspace
- Every connector integration test depends on `MockServer` and `Mock::given()`
- Replacing would require either writing a custom async mock HTTP server on
  asupersync, or finding a community crate (none exist for asupersync)
- Estimated: 2-4 weeks of test infrastructure work

**Benefit:** Could remove tokio from the test path
**Risk:** Custom mock server is itself a maintenance burden; may have subtle
behavioral differences from wiremock

**Verdict:** Not worth the effort. wiremock is mature, well-tested, and the
bridge handles it transparently.

### Option 2: Replace reqwest with asupersync-native HTTP client

**Effort:** Very high
- reqwest is used in ~90 connector crates for production HTTP calls
- asupersync has `asupersync::http::h1::HttpClient` but it's lower-level
  (no cookie jar, no redirect following, no multipart, no JSON body helpers)
- Some connectors use reqwest-specific features (streaming body, multipart)
- Estimated: 3-6 weeks to replace reqwest + handle all feature gaps

**Benefit:** Could remove tokio from production paths
**Risk:** reqwest handles TLS, connection pooling, and HTTP/2 correctly;
replacing it would require re-implementing or finding equivalents for all
of that

**Verdict:** Not worth the effort. reqwest works correctly through the bridge
and handles many edge cases we'd have to reimplement.

### Option 3: Retain bridge as managed infrastructure (CHOSEN)

**Effort:** Zero
- The bridge already works and is well-contained
- It adds ~5ms startup overhead (one-time background thread creation)
- Zero runtime overhead after initialization (thread-local cached handle)

**Benefit:**
- No disruption to existing test or production code
- wiremock and reqwest continue to work transparently
- The bridge is quarantined in fcp-async-core internals (not exposed in API)

**Risk:**
- Tokio remains a transitive dependency (~200KB compile overhead)
- If asupersync fundamentally changes its threading model, the bridge may break
  (mitigated: bridge has been stable through all asupersync API changes so far)

**Verdict:** Best cost/benefit ratio. The bridge is invisible to users,
adds negligible overhead, and avoids massive test infrastructure churn.

## Decision

**Retain the Tokio compat bridge as permanent managed infrastructure.**

Rationale:
1. The bridge works correctly and has been stable through all migrations
2. Replacing wiremock (~90 files) or reqwest (~90 files) would be 2-6 weeks
   of work with high regression risk
3. The bridge is internal to fcp-async-core and invisible to connector authors
4. The ~200KB compile overhead from tokio is negligible in a workspace this size

## Review Date

Revisit this decision if:
- asupersync provides a production-ready HTTP client with reqwest-parity features
- A native async mock HTTP server becomes available for asupersync
- Tokio becomes incompatible with the asupersync threading model
- The bridge causes a real production incident (none to date)

Next scheduled review: 2026-06-15 (3 months)
