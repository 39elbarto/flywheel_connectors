# crkft.1 — Call-site audit: `fcp_protocol::session::negotiate_suite`

This document enumerates every call site of `negotiate_suite` and
classifies each by semantic dependence on the current
**initiator-picks** iteration order. It is a precondition for the
responder-picks flip in `crkft.2`.

## Inventory

### Definition
| File:line | Note |
|---|---|
| `crates/fcp-protocol/src/session.rs:810` | Public API — target of the flip. |
| `crates/fcp-conformance/src/interop/session.rs:225` | Private local helper shadowing the public name; takes `&[&str]` (scenario-level). See "Conformance helper" below. |

### Production callers
No production callers outside of tests. The function is exported but
every caller currently lives in test / conformance / fuzz code. The
session-handshake production path constructs Hello/Ack messages that
carry suite lists on the wire; the actual suite selection happens
later in the session setup, and the fuzz + conformance sites exist to
cover that step.

### Test callers — semantically independent of picks order
| File:line | Reason |
|---|---|
| `crates/fcp-protocol/src/session.rs:1107` | Single-overlap setup; either picks order yields the same result. |
| `crates/fcp-protocol/src/session.rs:1175` | Asserts `None` for no-overlap. Order-independent. |
| `crates/fcp-protocol/src/session.rs:2262` | Empty initiator ⇒ `None`. |
| `crates/fcp-protocol/src/session.rs:2267` | Empty responder ⇒ `None`. |
| `crates/fcp-protocol/src/session.rs:2272` | Both empty ⇒ `None`. |
| `crates/fcp-protocol/src/session.rs:3039` | Single overlap on `Suite1`. |
| `crates/fcp-protocol/src/session.rs:3045` | Duplicate entries; exercises contains-semantics. |
| `crates/fcp-protocol/tests/session_golden_vectors.rs:508` | No-overlap failure path. |
| `crates/fcp-protocol/tests/session_golden_vectors.rs:707-709` | Determinism (same-call-twice) check. |
| `crates/fcp-protocol/tests/session_golden_vectors.rs:731,750,767,784` | Golden-vector setup; each uses a fixed pair where either order yields the same pick. |
| `crates/fcp-protocol/tests/no_mock_integration.rs:547-557` | No-mutual / empty cases. |
| `fuzz/fuzz_targets/version_negotiation_handshake.rs:53-54` | Idempotency (call twice, same result). |
| `fuzz/fuzz_targets/version_negotiation_handshake.rs:88` | Idempotency under random input. |

### Test callers — DEPENDS on initiator-picks semantics
| File:line | What it asserts | Action for crkft.2 |
|---|---|---|
| `crates/fcp-protocol/src/session.rs:2277` `test_negotiate_suite_initiator_preference` | Initiator `[Suite2, Suite1]`, responder `[Suite1, Suite2]` ⇒ `Suite2`. Asserts initiator wins. | **Rewrite** to assert the symmetric responder-picks outcome: expect `Suite1` (responder's first choice). Rename to `test_negotiate_suite_responder_preference`. |
| `crates/fcp-protocol/tests/no_mock_integration.rs:539` `negotiate_suite_prefers_initiator_order` | Initiator `[Suite2, Suite1]`, responder `[Suite1, Suite2]` ⇒ `Suite2`. | **Rewrite** similarly; rename to `negotiate_suite_prefers_responder_order`. |

### Conformance helper (local shadow)
`crates/fcp-conformance/src/interop/session.rs:225` defines a
**separate, local** `negotiate_suite(&[&str], &[&str])` (note the
`&str` signature vs the public API's `&SessionCryptoSuite`). It is
a scenario-level helper that simulates the negotiation for
protocol-conformance scenarios.

| Callers | Dependence |
|---|---|
| `session.rs:199,208,216` (scenario runners) | Use `offered=[Suite1,Suite2]` with `supported=[Suite2]` — single overlap, order-independent. |
| `session.rs:516-574` (tests) | `negotiate_suite_first_offered_preferred` at 563 DOES assert initiator wins on `[Suite1,Suite2]` ∩ `[Suite2,Suite1]`. |
| `session.rs:717-727` (tests) | `negotiate_suite_preserves_offered_order` at 720 asserts offered ordering is preserved. |

**Decision**: the conformance helper's semantic is the **conformance
target**, not the public API. If we flip the public API in crkft.2,
the conformance helper should ALSO flip so "conformance implementation
matches reference implementation" stays true. Update its tests in the
same PR.

## Summary

- **Public callers**: 0 (the fn is exported but every live callsite is
  test / conformance / fuzz code).
- **Semantic-independent hits**: 15. No change needed.
- **Semantic-dependent hits that require rewrite in crkft.2**: 2 in the
  public-API test suite + 2 in the conformance-helper test suite
  (`session.rs:2277`, `no_mock_integration.rs:539`,
  `interop/session.rs:563`, `interop/session.rs:720`).

## Handoff to crkft.2

The flip is safe. Expected test churn:
- 2 public-API tests renamed + assertion flipped
- 2 conformance-helper tests renamed + flipped (local helper also flips)
- No production code changes outside `session.rs:810` and
  `interop/session.rs:225-229`.
- Fuzz targets are order-independent (idempotency assertions); no
  rewrite needed.

The function name `negotiate_suite` stays — the docstring is the
semantic-visible change, not the identifier.
