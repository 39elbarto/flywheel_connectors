# jkcka.1 — Call-site audit: `CapabilityVerifier::without_instance_binding`

This document enumerates every caller of
`fcp_core::capability::CapabilityVerifier::without_instance_binding`
and confirms the two-phase enforcement model that this bead's parent
epic (jkcka) exists to make visible in types.

## Summary

- **Production Gateway use:** 1 site (`fcp-host` live request path).
  Legitimately skips instance binding because the gateway has no link
  to the connector's `InstanceId`; the connector itself re-verifies
  with its real instance id downstream.
- **Connector-side re-verification:** CONFIRMED. All connectors we
  checked construct `CapabilityVerifier::new(..., instance_id)`
  (full-enforcement constructor) in their runtime, which implies the
  gateway handoff IS followed by a bound re-verification.
- **Test uses:** 2 test files exercising unbound-mode semantics on
  purpose. Stays as-is after jkcka.3 migration, just using the new
  `verify_unbound` / `UnboundVerified` API.
- **Suspicious / misuse:** 0. The documented two-phase model is
  faithfully followed in the code.

## Site-by-site

### Definition
| File:line | Role |
|---|---|
| `crates/fcp-core/src/capability.rs:1421` | The `without_instance_binding` constructor. Not a call site — the thing we're auditing. |
| `crates/fcp-core/src/capability.rs:1380-1391` | Docstring on `CapabilityVerifier.instance_id` field explaining the two-phase model and the `br-5qp7o` incident that drove this design. |
| `crates/fcp-core/src/capability.rs:1549-1573` | The verifier branch that gates on `self.instance_id.is_some()`. When `None` (unbound mode), the text-type parser still fires (non-Text rejected) but the equality check is skipped. This is the code jkcka.3 will split. |

### Production / runtime callers

| File:line | Kind | Classification | Why OK |
|---|---|---|---|
| `crates/fcp-host/src/bin/fcp-host.rs:1494-1497` | Gateway | **GATEWAY (correct skip)** | Documented in-line: `Gateway can't enforce this; defer to the connector process (br-flywheel_connectors-5qp7o).` The gateway has no link from token → specific SubprocessConnector instance at preflight time. |

### Connector-side bound re-verification (found during audit)

Connectors DO NOT call `without_instance_binding`. They call
`CapabilityVerifier::new(..., instance_id)` which enforces the
instance match. Examples seen:

- `connectors/qq/src/connector.rs:353`
- `connectors/outlook/src/connector.rs:520`
- `connectors/google-admin-reports/src/connector.rs:355`
- `connectors/perplexity-search/src/connector.rs:477`
- `connectors/google-people/src/connector.rs:305`
- `connectors/feishu/src/connector.rs:1116`
- `connectors/stripe/src/connector.rs:470`
- `connectors/hackernews/src/connector.rs:772`
- `connectors/azure/src/connector.rs:1274`
- `connectors/s3/src/connector.rs:187`
- `connectors/twilio/src/connector.rs:234`
- `connectors/package-registry/src/connector.rs:656`
- `connectors/dockerhub/src/connector.rs:546`
- `connectors/shopify/src/connector.rs:1001`
- `connectors/twitter/src/connector.rs:293`

(Non-exhaustive — there are more similar hits across `connectors/`.)

All use the signature:
```rust
self.verifier = Some(CapabilityVerifier::new(
    host_public_key,
    zone_id,
    instance_id,   // the connector's real, self-chosen InstanceId
));
```

So the gateway-produces-unbound-token / connector-re-verifies-bound
handoff is real and working. **jkcka.3's typestate split models an
architecture that exists, not one that needs to be invented.**

### Test callers (unbound mode exercised on purpose)

| File:line | Purpose | Action needed in jkcka.3-4 |
|---|---|---|
| `crates/fcp-core/src/capability.rs:2432` `without_instance_binding_accepts_token_that_declares_instance_id` | Tests that unbound mode does accept a token carrying an `instance_id` claim (it just doesn't match it). | Rewrite to use `verify_unbound` and assert the return type is `CapabilityToken<UnboundVerified>`. |
| `crates/fcp-core/src/capability.rs:2468` `without_instance_binding_still_rejects_non_text_instance_id` | Tests that the type-strict check on `instance_id` claim fires even in unbound mode (non-Text CBOR rejected). | Same — rewrite onto `verify_unbound`. |
| `crates/fcp-core/src/capability.rs:2507` `without_instance_binding_ignores_tokens_without_instance_claim` | Tests that tokens with no `instance_id` claim pass in unbound mode. | Same. |
| `crates/fcp-core/tests/metamorphic.rs:95, 164` | Metamorphic tests that use unbound mode to focus on invariants of the other checks. | Rewrite onto `verify_unbound`. |

## Risk assessment for jkcka.3

- **Suspicious sites:** zero. The split can proceed.
- **Test churn:** 5 tests move from `verify(...)` to
  `verify_unbound(...)` and assert `CapabilityToken<UnboundVerified>`.
- **Production churn:** the gateway site in `fcp-host.rs` shifts to
  `verify_unbound(...)`, then its downstream consumers (in
  `jkcka.4`) either accept the unbound variant or call
  `promote_with_instance` somewhere before reaching an executor.
- **Connector churn:** connectors keep using `CapabilityVerifier::new`
  but their downstream code needs to accept
  `CapabilityToken<BoundVerified>` specifically after jkcka.3.

## Unanticipated findings

None. The two-phase enforcement model is faithfully implemented. The
ONLY reason the type system doesn't reflect it today is that
`CapabilityToken<CryptographicallyVerified>` is a single marker
spanning both cases. jkcka.2-3 fix that.

## Handoff to jkcka.2 (ADR)

- Input-ready.
- Expected API shape (per epic description):
  `verify_bound` / `verify_unbound` on `CapabilityVerifier`;
  `promote_with_instance(&InstanceId)` on
  `CapabilityToken<UnboundVerified>`.
- The phantom-marker style (Option A in the epic's design space) is
  consistent with the existing `Unverified` / `CryptographicallyVerified`
  pattern; expect the ADR to pick it unless a const-generic-bool
  alternative surfaces a surprise benefit.
