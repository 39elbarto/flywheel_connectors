# ADR 8n0rm-typed-claims — Typed Auth-Claim Schema Architecture

**Status:** Accepted (2026-04-22)
**Epic:** `flywheel_connectors-8n0rm`
**Input:** `docs/architecture/adr/8n0rm-claim-schema-inventory.md` (8n0rm.1)

## Context

The `fcp-crypto::cose::CapabilityTokenBuilder` builds auth-critical
token claims as raw CBOR labels and text, and
`fcp-core::CapabilityVerifier` separately interprets those claims by
label integer. The two crates can drift silently while still
compiling — evidenced by the GRANTS↔OPERATIONS legacy-fallback branch
at `capability.rs:1597-1621`. We want a single typed schema that both
crates consume so the compiler forces them to evolve together.

## Options considered

### Option A — `AuthClaims` in `fcp-core`

**Rejected.** Would require `fcp-crypto` to depend on `fcp-core` to
consume the struct, but `fcp-core` already depends on `fcp-crypto`
(`crates/fcp-core/Cargo.toml` has `fcp-crypto = { path = "../fcp-crypto"
}`). Reversing would create a dependency cycle Cargo refuses.

### Option B — new `fcp-auth-schema` crate (ACCEPTED)

A small, dependency-light crate (only `serde` + `ciborium` + `chrono`
+ `blake3`-adjacent types) that owns `AuthClaims` and the label
constants. Both `fcp-crypto` and `fcp-core` depend on it.

The bullets below describe the intended post-cutover shape for
8n0rm.4+; they are not all fully landed in the current tree yet.

- `fcp-crypto` is expected to become schema-agnostic: it should accept
  `&fcp_auth_schema::AuthClaims`, serialize it via the schema crate's
  canonical-CBOR serde impl, and sign the bytes. Today it still
  exposes field-wise `CapabilityTokenBuilder` setters and retains
  legacy raw-claim synthesis logic for FCP field labels and the
  GRANTS↔OPERATIONS bridge.
- `fcp-core::CapabilityVerifier` is expected to parse signed bytes into
  `AuthClaims` and operate on typed fields (`.capability_id`,
  `.zone_id`, `.grants`) instead of raw CBOR lookups. Today the live
  verifier still reads and validates the raw `CwtClaims` / CBOR map
  directly.
- Label integer constants (`fcp2_claims::CAPABILITY_ID` etc.) move to
  `fcp-auth-schema`. `fcp-crypto` re-exports them for backwards
  compatibility during the transition; after 8n0rm.4 migration
  completes, those re-exports are removed.

### Option C — `AuthClaims` inside `fcp-crypto`

A lower-ceremony alternative: move `AuthClaims` into
`fcp-crypto::cose::claims`, have `fcp-core` import it. Works because
the dep direction is right. Downside: keeps security semantics
co-located with crypto primitives in a single crate, which is the
exact layering mistake the epic intends to fix. Option B better
matches the epic's architectural narrative.

## Decision

**Option B.** New workspace member `fcp-auth-schema`.

### Crate scope

Path: `crates/fcp-auth-schema/`

Files:
- `Cargo.toml` — workspace member, `serde` + `ciborium` + `chrono`
  + minimal deps
- `src/lib.rs` — public surface
- `src/claims.rs` — `AuthClaims` struct + serde impl
- `src/labels.rs` — `cwt_claims` and `fcp2_claims` label integer
  constants (moved from `fcp-crypto::cose`)
- planned: `src/grants.rs` — `CapabilityGrant`,
  `CapabilityConstraints` once they move out of
  `fcp-core::capability`

As of the current checkout, `fcp-auth-schema` only contains
`src/lib.rs`, `src/claims.rs`, and `src/labels.rs`; typed grant and
constraint structs still live in `fcp-core`, while `AuthClaims`
currently carries those payloads as opaque `ciborium::Value`.

No `tokio`, no `fcp-async-core` — schema-only crate.

### Dependency graph after

```
fcp-auth-schema ── (serde, ciborium, chrono)
      │
      ├─ fcp-crypto  (primitives + COSE framing)
      │        │
      │        └─ fcp-core  (zone/cap semantics)
      │
      └─ fcp-core (directly imports AuthClaims, re-exports)
```

`fcp-crypto` continues to depend on `fcp-auth-schema` for
`AuthClaims` and `labels`. `fcp-core` continues to depend on both
`fcp-crypto` (primitives) and `fcp-auth-schema` (claim types).

### API shape (binding contract for 8n0rm.3 + 8n0rm.4)

```rust
// In fcp-auth-schema

pub struct AuthClaims {
    // schema_version field added in 8n0rm.5
    // CWT standard
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub audience: Option<String>,
    pub expiration: Option<DateTime<Utc>>,
    pub not_before: Option<DateTime<Utc>>,
    pub issued_at: Option<DateTime<Utc>>,
    pub token_id: Option<Vec<u8>>,

    // FCP2
    pub capability_id: Option<String>,
    pub zone_id: Option<String>,
    pub principal_id: Option<String>,
    pub issuing_node: Option<String>,
    pub holder_node: Option<String>,
    pub audience_binary: Option<Vec<u8>>,
    pub grant_object_ids: Vec<Vec<u8>>,
    pub checkpoint_id: Option<Vec<u8>>,
    pub checkpoint_seq: Option<u64>,
    pub instance_id: Option<String>,
    pub grants: Vec<CapabilityGrant>,
    pub constraints: Option<CapabilityConstraints>,
    pub delegation_depth: Option<u64>,
    pub parent_token: Option<Vec<u8>>,

    // NOTE: fcp2_claims::OPERATIONS intentionally NOT on this struct —
    // legacy shape removed in 8n0rm.6.
}

impl AuthClaims {
    /// Serialize to canonical CBOR. Deterministic: entries sorted by
    /// label integer before emission (lowest-first negative, then
    /// lowest-first positive). Only non-None / non-empty fields are
    /// emitted.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SchemaError>;

    /// Parse canonical CBOR back into typed form.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SchemaError>;

    /// An empty claim set. schema_version stamped to
    /// CURRENT_SCHEMA_VERSION (=1 after 8n0rm.5).
    pub fn empty() -> Self;
}
```

### Re-export strategy during transition

`fcp-crypto::cose::{cwt_claims, fcp2_claims}` keep their existing
paths as `pub use fcp_auth_schema::labels::*`. Callers don't break.
After 8n0rm.4 migrates all direct callers to the schema crate's
paths, the re-exports can be dropped (AGENTS.md "no backwards
compatibility — no users yet").

## Consequences

### Upside
- Single source of truth for claim schema
- Compiler forces builder and verifier to agree
- Clean layering: schema → primitives → semantics
- Natural home for schema_version (8n0rm.5)
- Natural test site for round-trip conformance (8n0rm.7)

### Downside / migration cost
- One new crate (Cargo.toml workspace member, CI check-list)
- Moving `CapabilityGrant` + `CapabilityConstraints` from `fcp-core`
  to `fcp-auth-schema` is a modest refactor (they are small types;
  main risk is that they've grown implementation methods that pull in
  fcp-core-only deps — must verify in 8n0rm.3)
- ~20 `CapabilityTokenBuilder` chain methods are expected to be
  deleted once 8n0rm.4 fully removes the legacy field-wise builder
  surface

### Wire compat
Zero. Bit-for-bit identical to current emitted CBOR for equal field
values. Validated by the conformance test in 8n0rm.7.

## Open questions (for downstream beads to resolve)

1. Does moving `CapabilityGrant` to `fcp-auth-schema` pull in any
   fcp-core-only traits? If yes, those move too; if the fanout is
   large, re-examine Option C.
2. Should `CapabilityConstraints` move too, or stay in fcp-core with
   a `From<CapabilityConstraints>` impl on the schema side? Tentative
   answer: move. Constraint shape is part of the auth-critical
   schema.
3. What happens to `fcp-crypto::cose::CwtClaims` (the raw
   `ciborium::Value::Map` wrapper)? Tentative: becomes a
   `schema_version=0` fallback parser used only by
   `AuthClaims::from_canonical_cbor` internally; not part of the
   public surface anymore.

## Handoff

8n0rm.3 implemented the initial `AuthClaims` crate surface. The
remaining steps are still staged work: 8n0rm.4 refactors
`fcp-crypto::cose` to consume it end-to-end, 8n0rm.5 adds
`schema_version`, 8n0rm.6 removes the GRANTS-fallback-to-OPERATIONS
branch, and 8n0rm.7 adds conformance golden vectors. Until those land,
the builder and verifier remain partially migrated.
