# 8n0rm.1 — Capability-Token Claim Schema Inventory

Exhaustive enumeration of CBOR labels and string conventions used across
`fcp-crypto::cose` (builder side) and `fcp-core::capability` (verifier
side). Input for the typed-claims design in 8n0rm.2.

## Label allocation

### CWT standard claims (positive integers)

Defined in `fcp_crypto::cose::cwt_claims`:

| Label | Int | Builder emits (method + CBOR shape) | Verifier reads (via getter) |
|---|---|---|---|
| `ISS` | 1 | `.issuer(&str)` → `Value::Text` (cose.rs:104) | `CwtClaims::get_zone_id` (derived — uses ISS as zone binding) via capability.rs:1519 |
| `SUB` | 2 | `.subject(&str)` → `Value::Text` (cose.rs:112) | not directly verified; available via `claims.get(SUB)` |
| `AUD` | 3 | `.audience(&str)` → `Value::Text` (cose.rs:120) | not directly verified |
| `EXP` | 4 | `.expiration(DateTime<Utc>)` → `Value::Integer` (cose.rs:128) | `CoseToken::validate_timing` (cose.rs; called capability.rs:1513) |
| `NBF` | 5 | `.not_before(DateTime<Utc>)` → `Value::Integer` (cose.rs:138) | `CoseToken::validate_timing` |
| `IAT` | 6 | `.issued_at(DateTime<Utc>)` → `Value::Integer` (cose.rs:148) | `CoseToken::validate_timing` |
| `CTI` | 7 | `.token_id(&[u8])` → `Value::Bytes` (cose.rs:158) | `CwtClaims::get_token_id` (cose.rs:373) |

### FCP2 claims (negative integers, range -65537 to -65551)

Defined in `fcp_crypto::cose::fcp2_claims`:

| Label | Int | Builder emits (method + CBOR shape) | Verifier reads | Semantic role |
|---|---|---|---|---|
| `CAPABILITY_ID` | -65537 | `.capability_id(&str)` → `Value::Text` (cose.rs:166) | `claims.get_capability_id()` (cose.rs:332; capability.rs:1603) | Which capability is being asserted |
| `ZONE_ID` | -65538 | `.zone_id(&str)` → `Value::Text` (cose.rs:176) | `claims.get_zone_id()` (cose.rs:341; capability.rs:1519) | Required zone scope |
| `OPERATIONS` | -65539 | `.operations(&[&str])` → `Value::Array<Text>` (cose.rs:188) | **LEGACY** — capability.rs:1601 (fallback branch) | Operation whitelist — deprecated by `GRANTS` |
| `PRINCIPAL_ID` | -65540 | `.principal_id(&str)` → `Value::Text` (cose.rs:196) | `claims.get_principal_id()` (cose.rs:350) | Identity on whose behalf the action runs |
| `DELEGATION_DEPTH` | -65541 | **NOT EMITTED** by builder; reserved label only | read by `fcp-host/admin_state.rs` (via claims.get(...)) | Delegation chain depth |
| `PARENT_TOKEN` | -65542 | **NOT EMITTED** by builder; reserved label only | read by `fcp-host/admin_state.rs` | Parent token id for delegation chain |
| `ISS_NODE` | -65543 | `.issuing_node(&str)` → `Value::Text` (cose.rs:206) | not read in capability.rs (auditing only) | Node that issued the token |
| `AUD_BINARY` | -65544 | `.audience_binary(&[u8])` → `Value::Bytes` (cose.rs:214) | used by `CwtClaims::get(...)` pattern (cose.rs:1547) | Binary audience / object_id |
| `GRANT_OBJECT_IDS` | -65545 | `.grant_objects(&[&[u8]])` → `Value::Array<Bytes>` (cose.rs:228) | read at cose.rs:1560 (test) | Object IDs this grant covers |
| `HOLDER_NODE` | -65546 | `.holder_node(&str)` → `Value::Text` (cose.rs:238) | `claims.get_holder_node()` (cose.rs:362) | Node holding / exercising token |
| `CHK_ID` | -65547 | `.checkpoint(id, seq)` → `Value::Bytes` (cose.rs:248) | read at cose.rs:1574 (test) | Checkpoint identifier |
| `CHK_SEQ` | -65548 | `.checkpoint(id, seq)` → `Value::Integer` (cose.rs:250) | read at cose.rs:1578 (test) | Checkpoint sequence number |
| `CONSTRAINTS` | -65549 | `.constraints_cbor(&[u8])` → `Value::Map<...>` (cose.rs:276) | capability.rs:1630 — `CapabilityConstraints` deserialize | Resource/scope constraints (default-deny semantics, C3.4) |
| `GRANTS` | -65550 | (no chain method — constructed manually via `.custom(GRANTS, ...)`) | capability.rs:1579 — canonical `Vec<CapabilityGrant>` | Operation grant list (canonical) |
| `INSTANCE_ID` | -65551 | `.target_instance(&str)` → `Value::Text` (cose.rs:258) | capability.rs:1555 (custom read, not via getter) | Connector instance binding target |

## Legacy / fallback paths

### GRANTS → OPERATIONS fallback (lines 1597-1621 in capability.rs)

**Smoking-gun evidence of schema drift.** Verifier first checks
`fcp2_claims::GRANTS`; if absent, falls back to reading
`fcp2_claims::OPERATIONS` + interpreting `CAPABILITY_ID` as the scope
anchor. Comment reads:

```
// Fallback to checking fcp2_claims::OPERATIONS if legacy/simplified?
// The builder uses fcp2_claims::OPERATIONS for string list.
```

The builder DOES emit `OPERATIONS` (`.operations(&[&str])` at cose.rs:188)
and DOES NOT have a chain method for `GRANTS`. So today tokens minted
by the chain API use OPERATIONS and the verifier falls through to the
legacy branch.

**Implication for 8n0rm.4/.6:** the refactored `AuthClaims.grants:
Vec<CapabilityGrant>` must emit the canonical `GRANTS` claim. The
`OPERATIONS` label can remain reserved but the fallback branch is
removed (8n0rm.6).

### INSTANCE_ID read is type-strict, not via getter

capability.rs:1555-1574 reads `fcp2_claims::INSTANCE_ID` directly
(not via a getter) and enforces that non-Text values reject even when
instance-binding is disabled. The typed schema must preserve this
"non-Text always rejects" property. See bead `br-5qp7o` context in
capability.rs:1380-1391.

## Asymmetries

### Builder emits but no verifier read
- `ISS_NODE` (auditing-only today; not read by `capability.rs` verify
  path)
- `CHK_ID` / `CHK_SEQ` (reserved; read only in tests today)

These are NOT a bug — they exist for downstream/audit consumers. The
typed schema should still expose them so audit-path consumers can read
`AuthClaims.issuing_node` instead of raw CBOR.

### Verifier-adjacent reads but no builder emit
- `DELEGATION_DEPTH` and `PARENT_TOKEN` are defined as constants but
  neither `CapabilityTokenBuilder` in fcp-crypto nor `AuthClaims` (yet)
  emits them. They ARE read by `fcp-host/admin_state.rs`. So tokens
  minted by the current builder have no delegation metadata; delegation
  must be emitted via the `.custom(...)` escape hatch today.

**Implication:** the typed `AuthClaims` struct MUST include both
`delegation_depth: Option<u64>` and `parent_token: Option<Vec<u8>>`
so delegation tokens can be built typed.

## Integer-label contract

Tests at cose.rs:1850-1877 assert:
- `cwt_claims::*` are positive integers (IANA-registered ranges)
- `fcp2_claims::*` are negative integers (private-use range in CWT)

These sign-invariants are wire-format contracts. The typed-claims
serde impl (8n0rm.3) must preserve them.

## Deterministic encoding

`ciborium::Value::Map` internally uses `Vec<(Value, Value)>` which
preserves insertion order. The current builder uses `CwtClaims::new()`
which inserts in call-order. Two calls that insert the same keys in
different orders produce different CBOR bytes.

**Implication for 8n0rm.3:** the typed-claims serde impl MUST sort
entries by label (lowest integer first) during serialize to guarantee
determinism regardless of struct-field declaration order. Tests at
cose.rs (existing determinism tests in the golden-vector suite)
currently compensate by always calling builder methods in the same
order.

## Count summary

- CWT labels: 7 (all used)
- FCP2 labels: 15 defined, 13 emitted by builder chain, 2 reserved
  (DELEGATION_DEPTH, PARENT_TOKEN)
- Legacy/fallback paths: 1 (GRANTS ↔ OPERATIONS)
- Non-getter raw reads: 3 (INSTANCE_ID hard type check, GRANT_OBJECT_IDS
  test, CHK_ID/SEQ test)

## Handoff to 8n0rm.2 (ADR)

Input-ready. Design options:
- **Option A** (AuthClaims in fcp-core): works — inventory confirms
  fcp-crypto is the lower layer; pulling claim *types* into fcp-core
  reverses the semantics/primitives layering correctly.
- **Option B** (separate fcp-auth-schema crate): also works, adds one
  crate of ceremony.

Fields the typed struct must support: every emitting and every reading
label above, including the two reserved delegation labels.

Wire-compat requirement: byte-for-byte identical to current builder
output for equal field values. Serde impl must sort by label integer.

Legacy removal scope: 8n0rm.6 deletes the GRANTS-fallback-to-OPERATIONS
branch once no production issuer emits `OPERATIONS`. Today the builder
chain DOES emit OPERATIONS — so 8n0rm.4's refactor must switch minting
to GRANTS (or keep both during transition) before 8n0rm.6 can proceed.
