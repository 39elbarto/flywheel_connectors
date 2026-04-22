# ADR — Capability Token Claim Schema Versioning

**Status:** Accepted (2026-04-22)
**Epic:** `flywheel_connectors-8n0rm`
**Bead:** `8n0rm.5`
**Depends on:** `8n0rm.3` (AuthClaims exists)

## Context

`AuthClaims` lives in `fcp-auth-schema` and is consumed by both
`fcp-crypto` (builder) and `fcp-core` (verifier). Any change to its
wire layout is, by definition, a wire-format change. Without a
versioning discipline, schema changes can ship silently and leave
verifiers either (a) failing in unexpected ways on new tokens, or
(b) silently accepting old tokens that no longer meet our intended
semantics.

`AuthClaims` carries an explicit `schema_version: u16` field
(see `CURRENT_SCHEMA_VERSION` in
`crates/fcp-auth-schema/src/claims.rs`). This ADR fixes the rules
by which that field is interpreted.

## Current version

`CURRENT_SCHEMA_VERSION = 1`

The schema as of version 1 includes: 7 CWT-standard fields + 15 FCP2
fields + the version marker itself. See
`docs/architecture/adr/8n0rm-claim-schema-inventory.md` for the
field-by-field layout.

## When to bump `schema_version`

### Major bump required (N → N+1)

- **Removing a field.** Any typed field in `AuthClaims` going away.
- **Changing a field's type.** e.g., `principal_id: Option<String>`
  → `Option<Vec<u8>>`.
- **Changing a field's CBOR label integer.** Any constant in
  `fcp-auth-schema::labels::{cwt_claims, fcp2_claims}` changing its
  numeric value.
- **Changing the semantic meaning of an existing field.** e.g.,
  `zone_id` interpreted as a URI path instead of a plain string.
- **Removing or weakening a claim-level invariant.** e.g., if
  `zone_id` is currently "always present when
  `capability_id` is present", and that coupling is dropped.
- **Removing a reserved-but-unused field's label allocation.** Label
  integers are a consumed resource; freeing one for reuse is a
  breaking change for any verifier that knows about the old meaning.

### Bump NOT required

- **Adding a new optional field.** Old verifiers treat the field as
  absent (the `Default` value); no wire conflict.
- **Adding a new optional constraint variant.** Old verifiers reject
  the unknown variant via the default-deny rule (C3.4).
- **Internal refactors that preserve the wire format.** e.g., moving
  a field between modules within `fcp-auth-schema`, changing the
  serde-impl internal helper signatures.
- **Renaming a `labels::` constant without changing its integer.**
  Purely source-level change.

## Deployment rules for a bump

Version bumps require a staged rollout to avoid simultaneous upgrade
of all issuers and verifiers:

1. **Land the schema change** behind the new `schema_version = N+1`.
   `CURRENT_SCHEMA_VERSION` constant bumps.
2. **Teach verifiers to accept both old and new.** Update every call
   site that invokes `check_schema_version` to pass the multi-version
   window: `claims.check_schema_version(&[N, N+1])`.
3. **Wait one full release cycle** to let live peers migrate. During
   this window both old- and new-version tokens are valid.
4. **Issuers upgrade** to emit the new version first. Verifiers
   continue accepting both.
5. **Drop old-version acceptance.** Update verifier call sites back
   to `&[N+1]`. Remove the now-unused pre-bump fallback code.
6. **Optional — drop old-version-only construction paths.** If the
   builder had a compat branch for the old version, remove it.

At each step, update the `minimum_accepted_schema_version_*` tests
(added in future beads when multi-version acceptance is actually
needed) to reflect the current state.

## Verifier integration (current state)

`AuthClaims::check_schema_version(&[u16])` is the blessed API for
verifiers. Callers pass the accepted-version window; unsupported
versions yield `SchemaError::UnsupportedSchemaVersion`.

Today `fcp-core::CapabilityVerifier` does **not** call this method
because it still reads raw CBOR (the 8n0rm.4 refactor that lands
the consumption of `AuthClaims` is pending). Once that lands, every
verifier pipeline in `fcp-core`, `fcp-host`, and any connector that
verifies tokens directly MUST call `check_schema_version` early in
its pipeline before trusting any other field.

## Rationale

- The `u16` width accommodates 65,535 version bumps. Even under
  aggressive change (one per year), that's overkill — but the
  encoding cost of a 16-bit integer is trivial and leaves headroom.
- The multi-version window approach (`&[u16]`) is explicitly NOT
  "accept any version ≤ N" because sometimes a middle version has
  known bugs we want to reject. The set-based API is more
  expressive and just as easy to use for the common case.
- `check_schema_version` returns a `SchemaError` rather than
  panicking because verifier error paths are already `Result`-based.

## Tests guarding these invariants

In `crates/fcp-auth-schema/src/claims.rs`:

- `empty_stamps_current_schema_version` — issuance stamps the right version
- `check_schema_version_accepts_current` — happy path
- `check_schema_version_rejects_unsupported` — sad path with correct error variant
- `check_schema_version_accepts_multi_version_window` — deployment window works
- `schema_version_zero_is_not_valid_as_current` — `Default` (=0) cannot impersonate a valid version

Future beads that change `CURRENT_SCHEMA_VERSION` or the schema layout
MUST update or reaffirm each of these.

## Related

- Inventory: `docs/architecture/adr/8n0rm-claim-schema-inventory.md` (8n0rm.1)
- Architecture: `docs/architecture/adr/8n0rm-typed-claims.md` (8n0rm.2)
- Canonical impl: `crates/fcp-auth-schema/src/claims.rs`
