# ADR · X-Wing KEM vendor selection

**Bead:** `flywheel_connectors-kyopb.1.2.1`
**Date:** 2026-05-02
**Status:** Accepted
**Author:** CrimsonWolf
**Supersedes:** §10 Q1 of `docs/post-quantum/x_wing_kem_design.md`
**Implemented in:** `crates/fcp-crypto/src/xwing.rs`

## Decision

**Use the RustCrypto `x-wing = "0.1.0-rc.0"` crate** as the X-Wing KEM
provider for FCP V4 zone-key sealing. Drive it via the `XWingKem` trait
declared in `fcp-crypto::xwing`; production callers go through
`XWingProvider`, while `XWingStub` is retained as a marker for callers
that have not yet been cut over (see `kyopb.1.2.4`).

## Context

Sub-bead `kyopb.1.2.1` directs us to "pick the production X-Wing
implementation source" given two finalists named in the parent
design doc (§10 Q1):

- **RustCrypto `ml-kem`**, the FIPS 203 ML-KEM-768 building block, plus
  a hand-built X-Wing combiner on top.
- **`pqcrypto-mldsa` / `pqcrypto-mlkem`** PQClean bindings — mature C
  with FFI overhead and a sharp build-system footprint.

Since the design doc was written, the RustCrypto KEMs workspace has
shipped a third option that was not on the table at design time:
**`x-wing = "0.1.0-rc.0"`**, a dedicated pure-Rust crate that
*already* composes ML-KEM-768 with `x25519-dalek` per
draft-connolly-cfrg-xwing-kem **draft 06**, including the SHA3-256
combiner verbatim. This subsumes the "build the combiner ourselves"
work that Option 1 implied.

## Comparison

| Criterion                              | `x-wing` (chosen)                                   | `ml-kem` + custom combiner                                 | PQClean (`pqcrypto-mlkem`)              |
| -------------------------------------- | --------------------------------------------------- | ---------------------------------------------------------- | --------------------------------------- |
| Language / unsafe surface              | Pure Rust, `#![cfg_attr(not(test), no_std)]`        | Pure Rust                                                  | C bindings via FFI; `unsafe` boundary   |
| FIPS 203 ML-KEM-768                    | ✓ via `ml-kem` 0.3                                  | ✓ via `ml-kem` 0.3                                         | ✓ via PQClean                           |
| X-Wing combiner                        | ✓ draft 06, byte-for-byte                           | ✗ would be hand-rolled in this crate                       | ✗ would be hand-rolled in this crate    |
| Draft test vectors pass byte-for-byte  | ✓ (verified in `tests/xwing_vectors.rs`)            | n/a until combiner written                                 | n/a until combiner written              |
| `zeroize` on secret material           | ✓ feature-gated; enabled here                       | ✓ on ml-kem; would need manual on combiner                 | Manual at the FFI boundary              |
| Dependency surface                     | `ml-kem` + `x25519-dalek` + `sha3` (already in tree)| Same                                                       | Adds C build deps + lockfile churn      |
| Audit story                            | RustCrypto org review + draft 06 conformance        | We carry the combiner risk                                 | PQClean review, but FFI boundary review |
| API shape                              | RustCrypto `kem` trait family (Encapsulate/Decap)   | Manual                                                     | C-style by-pointer                      |
| Transitive `rand_core` requirement     | `0.10` (we already shim this for `ml-dsa`)          | `0.10`                                                     | Bring-your-own RNG                      |

## Rationale

1. **Combiner correctness is load-bearing for the hybrid claim.** Hand-
   rolling the X-Wing combiner gives us a single point where a
   transcription error against the IETF draft silently downgrades
   security. The `x-wing` crate's combiner is byte-for-byte the draft 06
   text, and our `tests/xwing_vectors.rs` harness pins three normative
   IETF draft vectors against it.
2. **Pure Rust + `zeroize`** matches every other primitive in
   `fcp-crypto`: ed25519-dalek, x25519-dalek, ml-dsa, ml-kem. Using a C
   binding for one PQ primitive while every other primitive is Rust
   would expand the audit surface for marginal speedup.
3. **No new transitive deps.** `x-wing` pulls `ml-kem`, `x25519-dalek`,
   `sha3` — all already in the workspace transitively. The only fresh
   crate is `x-wing` itself.
4. **`rand_core 0.10` plumbing was already done** under
   `crates/fcp-crypto/src/ml_dsa.rs` (`OsRngV10`); X-Wing reuses the
   same pattern.
5. **API harmony.** The crate exposes the `kem::Kem`/`Encapsulate`/
   `Decapsulate` traits, which match what RustCrypto consumers expect
   and let us layer ChaCha20-Poly1305 on top exactly as
   `docs/post-quantum/x_wing_kem_design.md` §4.2 describes.

## Side-channel posture

Recorded for the parent bead's "side-channel posture documented" criterion.

- **ML-KEM-768 (`ml-kem` 0.3, FIPS 203):** the `ml-kem` crate
  documents constant-time decapsulation including FIPS 203's implicit
  rejection path (junk shared secret on invalid ciphertext, verified by
  our `provider_open_rejects_tampered_ciphertext` test).
- **X25519 (`x25519-dalek` 2.x):** constant-time per the dalek
  documentation; we rely on the same constant-time scalar mult that
  ed25519-dalek's signing path already uses.
- **Combiner (`SHA3-256`):** the digest of (`ss_mlkem || ss_x25519 ||
  ct_x25519 || pk_x25519 || X-Wing label`) has no secret-dependent
  branches in the upstream `sha3` crate.
- **AEAD layer (`ChaCha20Poly1305`):** the `chacha20poly1305` crate
  documents constant-time encrypt/decrypt; auth-tag verification is
  constant-time.
- **Memory hygiene:** secret keys held as 32-byte seeds wrapped in a
  redacting `Debug`; `x-wing` zeroizes its expanded secret on drop
  when the `zeroize` feature is enabled (we enable it).
- **Out of scope at the library layer:** physical-attack mitigations
  (power, EM, fault). Captured in `docs/post-quantum/x_wing_kem_design.md`
  §7 "Out of scope (explicitly punted)" — punted to
  hardware-backed deployments rather than software defences.

## Wire-format reconciliation

Adopting `x-wing` 0.1.0-rc.0 forces one wire-format correction relative
to the parent design doc:

| Field         | Design doc (pre-decision) | x-wing 0.1.0-rc.0 / draft 06 (chosen) |
| ------------- | ------------------------- | ------------------------------------- |
| Public key    | 1216 B                    | 1216 B (unchanged)                    |
| Secret key    | **2464 B** (expanded)     | **32 B** (compressed seed)            |
| Ciphertext    | 1120 B                    | 1120 B (unchanged)                    |
| Shared secret | 32 B                      | 32 B (unchanged)                      |

Draft 06 stores the secret key as a 32-byte seed and re-expands it via
SHAKE256 inside `decapsulate`. The 2464-byte figure in the design doc
described the in-memory expanded form, not the wire/storage form. The
constants in `fcp-crypto::xwing` and the corresponding section of
`x_wing_kem_design.md` are updated to the 32-byte compressed form
under this ADR.

## Test-vector harness

`crates/fcp-crypto/tests/xwing_vectors.rs` runs three checks against the
vendored normative draft vectors at
`crates/fcp-crypto/tests/data/xwing_test_vectors.json` (fetched
2026-05-02 from the official spec repository):

1. `x_wing_kat_upstream_seed_driven` — re-derive each vector's `sk` /
   `pk` / `ct` / `ss` byte-for-byte using the `x-wing` crate's
   seed-driven keygen and encap APIs.
2. `x_wing_kat_fcp_provider_round_trips` — reconstruct each vector's
   keypair, then run FCP's `XWingProvider::seal` / `open` against it,
   proving the FCP wrapper does not drift from the draft wire form.
3. `x_wing_kat_harness_loads_three_canonical_vectors` — sanity-check
   the harness itself is reading the canonical 3-vector corpus.

`cargo test -p fcp-crypto x_wing_kat` runs all three.

## Consequences

- **Acceptance criteria met.**
  - "Decision recorded as ADR under docs/architecture/" — this file.
  - "Test-vector harness in fcp-crypto/tests/xwing_vectors.rs that
    loads the draft-connolly-cfrg-xwing-kem normative vectors and
    round-trips them byte-for-byte" — landed; passes 3 vectors.
  - "Side-channel posture documented per §7" — covered above.
  - "Replaces fcp-crypto::xwing::XWingStub with real impl behind the
    same XWingKem trait" — `XWingProvider` is the real impl;
    `XWingStub` is kept as a deliberate "not yet cut over" marker for
    `kyopb.1.2.4`.
- **Sub-bead `kyopb.1.2.2`** (wire format + AEAD profile finalisation)
  becomes mostly a confirmation pass on `XWING_AEAD_INFO`,
  `XWING_ENCAPSULATION_RANDOMNESS_SIZE`, and the all-zero nonce
  decision.
- **Sub-bead `kyopb.1.2.3`** (`ZoneKeyManifest` schema migration) can
  now reference the real `XWingSealedBox` shape instead of stub
  constants.
- **Followups not in scope here:**
  - Pulling Wycheproof's broader X-Wing/ML-KEM corpus once published
    (deferred per parent design doc §10 Q5).
  - Performance benchmarks under `kyopb.1.2.5`.

## References

- draft-connolly-cfrg-xwing-kem (IETF CFRG, draft 06+).
- NIST FIPS 203 *Module-Lattice-Based Key-Encapsulation Mechanism Standard*.
- `crates/fcp-crypto/src/xwing.rs` — production impl + 18 unit tests.
- `crates/fcp-crypto/tests/xwing_vectors.rs` — 3 IETF KATs.
- `docs/post-quantum/x_wing_kem_design.md` — parent design (this ADR
  amends §2.1 secret-key size and resolves §10 Q1).
