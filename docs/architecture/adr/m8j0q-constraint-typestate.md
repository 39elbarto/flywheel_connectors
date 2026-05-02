# ADR — `ConstraintsEnforced` typestate for capability-constraint enforcement

**Status:** Accepted (2026-05-02)
**Epic:** `flywheel_connectors-m8j0q`
**Bead:** `m8j0q.6`
**Depends on:** `m8j0q.1` (`CapabilityConstraintEnforcer` trait), `jkcka.2`
(prior typestate split that established `BoundVerified` / `UnboundVerified`)

## Context

After bead `jkcka.2` (`docs/architecture/adr/jkcka-typestate-split.md`) the
capability-token typestate ladder is:

```
Unverified ── verify_unbound ──▶ UnboundVerified ── promote_with_instance ──▶ BoundVerified
            └─ verify_bound ─────────────────────────────────────────────────▶ BoundVerified
```

A `CapabilityToken<BoundVerified>` proves that all five cryptographic
verification checks ran (signature, timing, zone, operation, instance
binding). Holding it in a function signature is a compile-time guarantee
that an unverified or partially-verified token cannot reach the operation
executor.

It does **not** prove that the constraints encoded inside the token's
`CWT` claims (`object_id` allowlist, host allowlist, time window, scope
ceiling, principal binding) were actually checked against the inbound
request. That check is what `m8j0q.1`'s `CapabilityConstraintEnforcer`
does at runtime — but the type system has no way to record that the check
ran, so the host pipeline currently has to enforce the call ordering by
convention rather than by typing.

This is exactly the kind of "by-convention" gap that bit jkcka before:
the gateway path and the connector path both produced
`CryptographicallyVerified` tokens, and a refactor that wired the wrong
constructor into the wrong call site would have compiled silently.

## Goal

Add a third typestate, `ConstraintsEnforced`, distinct from
`BoundVerified`. The host's `dispatch_to_connector` (the entry point
that crosses the boundary into the subprocess sandbox) requires
`CapabilityToken<ConstraintsEnforced>` in its signature. A
`CapabilityToken<BoundVerified>` does **not** satisfy that signature:
the only legal way to obtain `ConstraintsEnforced` is to call
`promote_with_constraints` with an evaluator that has returned allow from
`CapabilityConstraintEnforcer::evaluate(constraints, request)`. The concrete
`fcp_policy::DefaultConstraintEnforcer` implements the `fcp-core` bridge trait
used by the promotion API.

A future refactor that silently widens the dispatch surface to accept
`BoundVerified` tokens — bypassing constraint enforcement — fails at
compile time, in CI, before it can ship.

## Options considered

### Option A — Separate marker type (ACCEPTED)

```rust
// In crates/fcp-core/src/capability.rs (next to BoundVerified / UnboundVerified)
pub struct ConstraintsEnforced;

mod verified_sealed {
    impl Sealed for super::ConstraintsEnforced {}
}
impl AnyVerified for ConstraintsEnforced {}
```

Promotion shape:

```rust
impl CapabilityToken<BoundVerified> {
    pub fn promote_with_constraints<E, Request>(
        self,
        enforcer: &E,
        constraints: &CapabilityConstraints,
        request: &Request,
    ) -> Result<CapabilityToken<ConstraintsEnforced>, E::Denial>
    where
        E: CapabilityConstraintEvaluator<Request>;
}
```

**Pros**
- Mirrors jkcka.2's shape exactly — BoundVerified → ConstraintsEnforced
  is the same pattern as UnboundVerified → BoundVerified
- Function signatures are explicit and grep-friendly:
  `fn dispatch_to_connector(token: CapabilityToken<ConstraintsEnforced>, ...)`
- Easy to evolve: `ConstraintsEnforced + ApprovalChecked + RateLimited`
  marker stack is a natural extension
- `trybuild` compile-fail tests are trivial — drop a fixture that hands a
  `BoundVerified` to the dispatch entry

**Cons**
- One more sealed-trait impl line, one more marker struct, one more
  promotion call site per dispatch path

### Option B — Type-level boolean flag pair on `BoundVerified`

```rust
pub struct BoundVerified<const CONSTRAINTS_OK: bool = false> { /* ... */ }
```

**Cons that ruled it out**
- Inverts the readability story: `CapabilityToken<BoundVerified<true>>`
  in a function signature is harder to grep and read than
  `CapabilityToken<ConstraintsEnforced>`
- Pollutes every helper with a const-generic parameter
- The default value is a footgun — `CapabilityToken<BoundVerified>`
  silently means `<BoundVerified<false>>`, which is the unsafe variant

### Option C — Tagged-state enum at the value level

```rust
pub enum CapabilityToken<S> { Bound(...), ConstraintsEnforced(...) }
```

Defeats typestate. Rejected.

### Option D — Carry the `ConstraintEvaluation` receipt as a field

Threading the `ConstraintEvaluation::Allow` value through every call site
adds noise without compile-time enforcement: any function that "just"
takes `BoundVerified` plus a receipt could ignore the receipt. Rejected.

## Decision

**Option A**: a new sealed marker `ConstraintsEnforced`, parallel to
`BoundVerified`, produced exclusively by
`CapabilityToken<BoundVerified>::promote_with_constraints(...)`.

`dispatch_to_connector` and every executor that crosses the
host→subprocess boundary requires `CapabilityToken<ConstraintsEnforced>`
in its signature.

## Required API shape (binding contract for m8j0q.6 implementation)

### Markers and seal

```rust
// crates/fcp-core/src/capability.rs

/// Marker: token has passed BoundVerified AND its `CapabilityConstraints`
/// claims were evaluated against the inbound request via a
/// `CapabilityConstraintEnforcer`, with outcome `ConstraintEvaluation::Allow`.
///
/// Hold this type at a function boundary to prove at compile time that
/// every check on the token — cryptographic AND semantic — completed
/// successfully before the request reached the boundary.
pub struct ConstraintsEnforced;

mod verified_sealed {
    impl Sealed for super::ConstraintsEnforced {}
}
impl AnyVerified for ConstraintsEnforced {}
```

### Promotion (single-shot consumption)

```rust
impl CapabilityToken<BoundVerified> {
    /// Run constraint enforcement and promote to `ConstraintsEnforced`.
    ///
    /// Consumes `self`: the `BoundVerified` token cannot be reused after
    /// promotion. This prevents accidentally dispatching via the un-enforced
    /// token alongside the enforced one.
    ///
    /// # Errors
    /// Returns the evaluator denial if any constraint check denies the request.
    pub fn promote_with_constraints<E, Request>(
        self,
        enforcer: &E,
        constraints: &CapabilityConstraints,
        request: &Request,
    ) -> Result<CapabilityToken<ConstraintsEnforced>, E::Denial>
    where
        E: fcp_core::CapabilityConstraintEvaluator<Request>;
}
```

The `consume self` shape is deliberate — the previous `BoundVerified`
witness is invalidated, so the only token that can reach the dispatch
boundary is the `ConstraintsEnforced` one. (Same pattern as
`Result::ok()` consuming the `Result`.)

### Dispatch boundary

```rust
// crates/fcp-host/src/enforcement.rs (post m8j0q.A.2 wiring)
pub async fn dispatch_to_connector(
    token: CapabilityToken<ConstraintsEnforced>,
    invoke_request: InvokeRequest,
    /* ... */
) -> Result<InvokeResponse, FcpError>;
```

Calling this with a `CapabilityToken<BoundVerified>` is a compile error.
Calling this with a `CapabilityToken<UnboundVerified>` is a compile error.
Calling this with a `CapabilityToken<Unverified>` is a compile error.

### Generic helpers

`AnyVerified` bound continues to cover state-agnostic helpers (claim
inspection, token id) — so `token_id<V: AnyVerified>(t: &CapabilityToken<V>)`
works for the new marker without ceremony.

## Migration plan

1. **m8j0q.6.a (this ADR)** — design accepted, contract published. ✅
2. **m8j0q.6.b** — add `ConstraintsEnforced` marker + sealed-trait impl
   in `crates/fcp-core/src/capability.rs`. (Blocked: requires fcp-core
   to compile cleanly; currently waiting on m8j0q.3 sibling work landing
   the missing `CapabilityConstraintDenied` match arms in
   `crates/fcp-core/src/error.rs`.)
3. **m8j0q.6.c** — implement `promote_with_constraints` on
   `CapabilityToken<BoundVerified>`. Returns `ConstraintDenialReason` on
   deny — call sites convert to `FcpError::CapabilityConstraintDenied`
   (the variant added by m8j0q.3).
4. **m8j0q.6.d** — change `fcp-host/src/enforcement.rs::dispatch_to_connector`
   signature to require `CapabilityToken<ConstraintsEnforced>`.
   (Coordinates with m8j0q.A.2: the wiring agent threads
   `DefaultConstraintEnforcer::evaluate` immediately after capability-token
   verify and before dispatch.)
5. **m8j0q.6.e** — add trybuild fixtures under
   `crates/fcp-core/tests/ui/`:
   - `bound_cannot_reach_dispatch.rs` (compile-fail) — proves
     `BoundVerified` is rejected by the dispatch signature
   - `constraints_enforced_dispatch_compiles.rs` (pass) — proves the
     promote-then-dispatch path is the only way through
   Hook them into `crates/fcp-core/tests/typestate_compile_fail.rs`
   alongside the existing jkcka.6 fixtures.

## Consequences

### Upside
- Constraint enforcement becomes mechanical, not "by call-site
  discipline"
- Future "I added a new dispatch entry point" refactors fail compile if
  the author forgot to wire enforcement
- Sets the precedent for stacking further boundary checks
  (`ApprovalChecked`, `RateLimited`) as additional markers if the next
  reality-check uncovers analogous gaps

### Downside / migration cost
- Workspace-wide signature change on the dispatch entry point. Every
  call site (currently a single one in `fcp-host/src/enforcement.rs`)
  must promote first. The work is bounded.
- One additional promotion call per request. Promotion is a
  sub-microsecond pure-function call (no I/O, no allocation beyond the
  denial-reason path), so the overhead does not threaten the
  `< 2ms p50 local invoke` performance target.

### Wire compat
Zero. Typestate is purely compile-time; runtime behavior is unchanged.

## Open questions resolved

1. **Why consume `self` on promotion?** Prevents a refactor where the
   author keeps the `BoundVerified` reference around "just in case" and
   accidentally dispatches via it. The compile error is the safety belt.
2. **Why does promotion return `ConstraintDenialReason` not
   `FcpError`?** Keeps `fcp-policy` decoupled from the FCP error
   taxonomy. Call sites convert to the host-facing error at the
   boundary; conformance vectors test the structured denial reason
   directly.
3. **Why not require `ConstraintsEnforced` on every executor, not just
   dispatch?** YAGNI. The dispatch boundary is the unforgeable choke
   point: nothing crosses into the subprocess sandbox without it. Adding
   the marker requirement to internal helpers would force every
   refactoring sweep to re-enforce constraints, with no security gain.

## Tests expected to follow

- **m8j0q.6.b runtime tests** (in `capability.rs`):
  - `promote_with_constraints_allow_returns_constraints_enforced` — happy
    path
  - `promote_with_constraints_deny_returns_structured_reason` — sad path
  - `promote_with_constraints_consumes_bound_token` — type-level
    assertion that the original token is moved
- **m8j0q.6.e compile-fail tests** (trybuild):
  - `bound_cannot_reach_dispatch.rs` — function takes
    `CapabilityToken<ConstraintsEnforced>`, fixture passes
    `CapabilityToken<BoundVerified>`, expect compile error
  - `unbound_cannot_reach_dispatch.rs` — function takes
    `CapabilityToken<ConstraintsEnforced>`, fixture passes
    `CapabilityToken<UnboundVerified>`, expect compile error
  - `constraints_enforced_dispatch_compiles.rs` (pass) — the full
    `verify_unbound → promote_with_instance → promote_with_constraints
    → dispatch_to_connector` chain compiles end-to-end
- **m8j0q.6.d host integration tests** (in
  `crates/fcp-host/tests/capability_constraint_enforcement.rs`):
  - covered by m8j0q.A.4's negative-test matrix (object-id allowlist,
    host allowlist, time-window, scope ceiling, principal binding)

## Reference implementation sketch

Once the fcp-core error-taxonomy WIP (m8j0q.3) lands, the typed
contract is:

```rust
use fcp_core::{BoundVerified, CapabilityToken, ConstraintsEnforced, InvokeRequest};
use fcp_policy::{DefaultConstraintEnforcer, RequestDescriptor};

fn enforce_and_dispatch(
    token: CapabilityToken<BoundVerified>,
    invoke: InvokeRequest,
    request: RequestDescriptor,
) -> Result<(), FcpError> {
    let enforcer = DefaultConstraintEnforcer::new();
    let constraints = token.claims().constraints.clone();
    let enforced = token
        .promote_with_constraints(&enforcer, &constraints, &request)
        .map_err(|deny| FcpError::CapabilityConstraintDenied {
            reason: deny.explanation,
            claim_type: format!("{:?}", deny.kind),
            detail: serde_json::to_string(&deny.kind).unwrap_or_default(),
        })?;
    dispatch_to_connector(enforced, invoke).await
}
```

Holding `enforced: CapabilityToken<ConstraintsEnforced>` is the
compile-time proof that `evaluate` returned `Allow` before
`dispatch_to_connector` was reached.
