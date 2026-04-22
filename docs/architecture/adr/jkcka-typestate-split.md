# ADR — VerifiedToken typestate split for instance-binding enforcement

**Status:** Accepted (2026-04-22)
**Epic:** `flywheel_connectors-jkcka`
**Bead:** `jkcka.2`
**Depends on:** `jkcka.1` (call-site audit)

## Context

`CapabilityVerifier::verify(...)` produces a
`CapabilityToken<CryptographicallyVerified>` whether or not the
instance-binding check ran. The two legitimate verifier modes (gateway
= `without_instance_binding` = 4/5 checks; connector runtime = `new` =
5/5 checks) produce the same typestate output. A function that takes
a `CapabilityToken<CryptographicallyVerified>` has no type-level way
to demand full enforcement.

jkcka.1's audit confirmed the architecture is sound: the gateway
legitimately skips instance binding, and connectors re-verify downstream
with the real instance id. The fix needed is purely type-level — make
the two verification outcomes distinct types so a function demanding
full enforcement cannot accept a partial-enforcement token.

## Options considered

### Option A — Separate marker types (ACCEPTED)

```rust
pub struct BoundVerified;   // full 5/5 checks, instance-binding enforced
pub struct UnboundVerified; // 4/5 checks, instance-binding deferred
```

Two phantom markers, following the same pattern as existing
`Unverified` / `CryptographicallyVerified`. `CapabilityToken<V>`
parameterizes over the state; the verifier's constructor mode
determines which variant its `.verify_*` method returns.

**Pros**
- Consistent with existing typestate conventions (Unverified,
  CryptographicallyVerified)
- Function signatures are explicit and grep-friendly:
  `fn execute_op(token: CapabilityToken<BoundVerified>, ...)`
- Easy to evolve: a third verification state (e.g., `PartiallyBound`)
  is a new marker, not a new encoding scheme
- Trivial compile-fail testing via `trybuild`

**Cons**
- Helpers that genuinely work on both states need a sealed trait
  (`AnyVerified`) for generic bounds. Low ceremony, once.

### Option B — Const-generic boolean marker

```rust
pub struct CapabilityToken<const BOUND: bool = false> { /* ... */ }
```

**Cons that ruled it out**
- Const-generic booleans on stable feature status: the repo is on
  nightly, so this works, but it's less common and less
  grep-friendly.
- Generic parameter value vs type value: `CapabilityToken<BoundVerified>`
  in function signatures reads more naturally than
  `CapabilityToken<true>`.

### Option C — Enum-valued sealed-trait marker

Functionally equivalent to Option A, adds a sealed-trait ceremony.
Rejected on grounds of YAGNI — the sealed trait goes in A only where
it's actually needed (generic helpers).

### Option D — Data-carrying phantom field

`CapabilityToken<Verified> { ..., bound: PhantomData<Bound> }`.
Adds a second type parameter in disguise. Rejected for clarity.

## Decision

**Option A**: two distinct marker types, `BoundVerified` and
`UnboundVerified`. `CapabilityToken<V>` unchanged in shape.

## Required API shape (binding contract for jkcka.3)

### Markers

```rust
// In crates/fcp-core/src/capability.rs

/// Verification-state marker: instance-binding check was PERFORMED.
/// Hold a `CapabilityToken<BoundVerified>` to prove full enforcement.
pub struct BoundVerified;

/// Verification-state marker: instance-binding check was SKIPPED.
/// Produced by gateway-vantage verifiers (`without_instance_binding`).
/// A downstream enforcement point must call
/// `promote_with_instance` before executing the operation.
pub struct UnboundVerified;
```

### Verifier split

```rust
impl CapabilityVerifier {
    /// Full bound verification. Only works when the verifier was
    /// constructed with `::new(_, _, instance_id)`.
    ///
    /// Runtime invariant (belt-and-braces): panics in debug if the
    /// verifier's `instance_id` is None. Release builds return
    /// a clear error rather than silently producing an unsafe token.
    pub fn verify_bound(
        self,
        token: CapabilityToken,
        required_capability: &CapabilityId,
        operation: &OperationId,
        resource_uris: &[String],
    ) -> FcpResult<CapabilityToken<BoundVerified>>;

    /// Unbound verification (4/5 checks). Only works when the
    /// verifier was constructed with `::without_instance_binding`.
    pub fn verify_unbound(
        self,
        token: CapabilityToken,
        required_capability: &CapabilityId,
        operation: &OperationId,
        resource_uris: &[String],
    ) -> FcpResult<CapabilityToken<UnboundVerified>>;
}
```

### Promotion (the gateway → connector handoff)

```rust
impl CapabilityToken<UnboundVerified> {
    /// Run the missing instance-binding check and promote to full
    /// verification.
    ///
    /// This is the explicit gateway→connector handoff. The connector
    /// runtime receives an `UnboundVerified` token, calls this
    /// method with its own real `InstanceId`, and passes the
    /// resulting `BoundVerified` to the operation executor.
    ///
    /// # Errors
    /// Returns `FcpError::ZoneViolation` (or similar) if the token's
    /// `instance_id` claim does not equal `expected`.
    pub fn promote_with_instance(
        self,
        expected: &InstanceId,
    ) -> FcpResult<CapabilityToken<BoundVerified>>;
}
```

### Legacy `verify()` / `CryptographicallyVerified`

Per AGENTS.md "we do not care about backwards compatibility":
**delete `verify(...)` and `CryptographicallyVerified`.** Every caller
must explicitly pick between `verify_bound` / `verify_unbound` after
jkcka.3-4.

### Generic helpers (sealed trait)

Helpers that are state-agnostic (e.g., `token_id(&self)`, `claims(&self)`)
use a sealed `AnyVerified` trait:

```rust
mod sealed { pub trait Sealed {} }
pub trait AnyVerified: sealed::Sealed {}
impl sealed::Sealed for BoundVerified {}
impl sealed::Sealed for UnboundVerified {}
impl AnyVerified for BoundVerified {}
impl AnyVerified for UnboundVerified {}

// Usage
fn token_id<V: AnyVerified>(t: &CapabilityToken<V>) -> &Cti { ... }
```

The seal prevents external crates from accidentally implementing
`AnyVerified` for some other marker and widening the type surface.

## Migration plan (for jkcka.3 and jkcka.4)

1. **jkcka.3** — implement markers, split verifier, add promote.
   Migrate in-crate tests (`capability.rs:2429-2527`,
   `tests/metamorphic.rs:95,164`) to use `verify_unbound`.
2. **jkcka.4** — sweep the workspace. Change every
   `CapabilityToken<CryptographicallyVerified>` signature to either
   `Bound`, `Unbound`, or `<V: AnyVerified>`. Workspace compile is
   the acceptance criterion.
3. **jkcka.5** — the fcp-host gateway site at
   `fcp-host.rs:1494-1497` becomes:
   ```rust
   let verifier = CapabilityVerifier::without_instance_binding(key, zone);
   let unbound: CapabilityToken<UnboundVerified> =
       verifier.verify_unbound(token, cap, op, &[])?;
   // transported to connector; connector calls promote_with_instance.
   ```
   A concrete connector is demonstrated promoting to bound.
6. **jkcka.6** — `trybuild` compile-fail tests lock in the
   type-level enforcement so future refactors can't silently widen
   the surface.
7. **jkcka.7** — docs.

## Consequences

### Upside
- Type system reflects architectural reality.
- Functions demanding full enforcement cannot accept gateway tokens.
- Future third-state (e.g., `PartiallyBound` where only some claims
  were checked) is a cheap addition.
- `promote_with_instance` makes the handoff visible at the call site.

### Downside / migration cost
- Workspace-wide signature changes on every `CapabilityToken<CryptographicallyVerified>`
  (jkcka.4 scope).
- Test rewrites for the five unbound-mode tests.

### Wire compat
Zero. Typestate is a purely compile-time concept; runtime behavior
is unchanged after this change.

## Open questions resolved

1. **Does the connector-side flow actually re-verify?** YES, confirmed
   by jkcka.1 audit (`CapabilityVerifier::new(..., instance_id)` call
   sites in 15+ connectors).
2. **Is promote_with_instance safe from replay?** It performs the
   instance-id equality check against the already-validated token
   claims; if the claims were verified (signature, timing, zone, op)
   by the gateway, and the instance check runs on the connector,
   the token has passed all five checks by the time BoundVerified
   exists.
3. **Can the gateway produce a BoundVerified token if its verifier
   was instance-bound?** API-wise yes: `verify_bound` would succeed
   when `instance_id.is_some()`. In practice the gateway never has
   a real instance id, so it ONLY calls `verify_unbound`.

## Tests expected to follow

- **jkcka.3 runtime tests** (in `capability.rs`):
  - `verify_bound_rejects_when_no_instance_id` — constructor mode
    mismatch returns an error
  - `verify_unbound_produces_unbound_marker_type` — type-level assertion
  - `promote_with_instance_correct_id_returns_bound` — happy path
  - `promote_with_instance_wrong_id_returns_error` — sad path
- **jkcka.6 compile-fail tests** (trybuild):
  - Function requiring `BoundVerified` refuses `UnboundVerified`
  - External construction of `BoundVerified` is not possible
