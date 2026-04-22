# Session Handshake — Suite Negotiation

FCP session handshakes negotiate a crypto suite via the
`negotiate_suite` function in `fcp_protocol::session`. This document
codifies the invariants that implementation must preserve.

## Suite Negotiation (responder picks)

`negotiate_suite` returns the **responder's** first-preferred suite
that the initiator also offers, subject to the [`MINIMUM_SUITE`] floor.
The initiator's ordering is not consulted.

### Why responder-picks

An attacker positioned as (or coercing) the initiator can order its
offered-suite list worst-first to force negotiation down to the weakest
mutually-supported suite. Responder-picks defends against this because
the responder's preferences are independent of attacker influence.

This matches TLS 1.3, Noise, and WireGuard.

### What responder-picks does NOT do

It does not protect against on-wire rewriting of the initiator's
suite list. That is handled separately by
`MeshSessionHello::transcript_bytes`, which includes the `suites` field
in the signed transcript. The two defenses are complementary and
address different threat models:

| Threat | Defense |
|---|---|
| Initiator deliberately orders offers worst-first | responder-picks |
| MITM rewrites offered suites in transit | signed transcript |

### Minimum suite floor

`MINIMUM_SUITE` is an explicit lower bound on what `negotiate_suite`
will ever return. Even if a responder's preference list still contains
a deprecated suite, negotiation will refuse to select below the floor.

The companion `suite_rank` function is the single site that encodes
"Suite X is stronger than Suite Y" — a STRENGTH ordering, distinct
from the PREFERENCE ordering expressed by list order.

### Adding a new suite

1. Add the variant to `SessionCryptoSuite`.
2. Assign a rank in `suite_rank`. Higher = stronger.
3. Update every peer (initiator + responder preference lists) before
   relying on the new suite in production.
4. After one full release cycle with the new suite universally
   supported, consider bumping `MINIMUM_SUITE` to deprecate an older
   one (see deprecation policy below).

### Deprecating a suite

1. Ensure the deprecated suite's replacement is universally deployed
   (all issuers + verifiers support the new suite).
2. Wait one full release cycle to let live peers migrate.
3. Bump `MINIMUM_SUITE` to the new floor.
4. Update the `minimum_suite_equals_current_weakest` test in
   `fcp-protocol/src/session.rs` to assert the new floor (or delete it
   if the floor now equals a non-trivial strength).
5. Schedule removal of the deprecated variant from `SessionCryptoSuite`
   for a future release after all peers have seen the floor bump.

### Suite list (current)

| Suite | KDF | MAC | Notes |
|---|---|---|---|
| `Suite1` | HKDF-SHA256 | HMAC-SHA256 (16B tag) | X25519 KEX. Current floor. |
| `Suite2` | HKDF-SHA256 | BLAKE3-keyed (16B tag) | X25519 KEX. |

Both are cryptographically sound today. `MINIMUM_SUITE = Suite1` reflects
the current weakest; bumping requires the deprecation process above.

## Regression tests guarding these invariants

Changing the behavior of `negotiate_suite` must update or reaffirm each
of the following tests in `crates/fcp-protocol/src/session.rs`:

- `negotiate_suite_responder_wins_on_multi_suite_overlap`
- `negotiate_suite_ignores_initiator_order_preference`
- `negotiate_suite_malicious_initiator_cannot_downgrade`
- `negotiate_suite_accepts_at_or_above_floor`
- `minimum_suite_equals_current_weakest`
- `suite_rank_is_monotonic`
- Plus the golden-vector tests in
  `tests/session_golden_vectors.rs::suite_negotiation` and the
  conformance mirror in `fcp-conformance/src/interop/session.rs`.

## Related documents

- `docs/architecture/adr/crkft-call-sites.md` — call-site audit for
  the responder-picks flip (crkft.1)
- Bead epics: `flywheel_connectors-crkft` (this epic)
