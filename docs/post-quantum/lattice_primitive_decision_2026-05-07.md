# Lattice Primitive Decision Gate - 2026-05-07

Bead: `flywheel_connectors-kyopb.1.3.1.1.7`

Repository revision inspected: `90705fcc4605f696ce5049209c33fe508f133c65`

Decision: **formal hold for production arithmetic**. No inspected Rust dependency or
public reference implementation is acceptable as a direct production route for
FCP V4 MP12 TrapGen, CHKP Delegate, and GPV SamplePre today. The correct next
step is to keep arithmetic blocked behind the basis-capable representation bead
(`flywheel_connectors-kyopb.1.3.1.1.8`) and require any future primitive route
to arrive as a vendored or internal implementation with an explicit cryptography
review packet, deterministic fixtures, allocation evidence, and redaction-safe
JSONL proof.

This does not remove V4 lattice functionality. It prevents the system from
shipping toy arithmetic, SHAKE-only trapdoor bundles, or an unaudited research
crate as production capability-token security.

## Requirements Applied

- Production primitives must cover MP12-compatible `TrapGen`, CHKP-compatible
  `Delegate`, GPV-compatible `SamplePre`, and `Verify` relation checks.
- Secret trapdoors must be basis-capable, redacted in `Debug`, zeroized on
  drop where observable, and isolated from general serialization.
- Public matrix material may remain seed-backed, but only as a public expansion
  contract with strict allocation ceilings.
- V4 reference shape must stay bounded: `n=512`, `q=4294967291`, `m=16384`,
  `sigma_x100=11300`, `depth=4`, and expanded public matrices must stay under
  the existing 64 MiB ceiling.
- Logs and evidence may include command lines, repository revisions, candidate
  ids, public hashes, dimensions, length buckets, timings, and result status.
  They must not include trapdoor coefficients, secret seeds, expanded secret
  matrices, raw zone labels, raw principal or operation text, local private
  paths, or PII.

## Candidate Matrix

| Candidate | Fit for FCP V4 primitives | Maintenance and license | Side-channel and secret handling | Decision |
| --- | --- | --- | --- | --- |
| `fcp-crypto-pq` current scaffold | API shape exists, but `trap_gen` and `delegate` create deterministic SHAKE fixture seed bundles; `sample_pre` and `verify` intentionally return `NotImplemented`. | In-tree, `unsafe_code` forbidden, small dependency set. | Version-2 metadata envelopes, redacted debug, relation summaries, storage buckets, and zeroization exist for current secret blobs, but the blobs are still not real trapdoor bases. | Keep as fixture/API scaffold only. |
| RustCrypto `module-lattice` 0.2.2 | Provides degree-256 polynomial, vector, NTT, packing, and truncate helpers for ML-KEM/ML-DSA; it does not expose MP12 `TrapGen`, CHKP `Delegate`, GPV `SamplePre`, or FCP relation checks. | Apache-2.0 OR MIT, crates.io semver release, RustCrypto maintained; README labels it hazmat and intended only for ML-KEM/ML-DSA. | `unsafe_code = "deny"` in the crate metadata; zeroize feature exists, but it is not a trapdoor lifecycle API. | Reject as direct primitive route. It may only be reconsidered as a narrow audited arithmetic substrate. |
| qFALL `qfall-tools` 0.1.0 at `b8eb4842fb80c36f7f3494930ea316472cb75793` | Exposes GPV/MP12-style preimage-samplable functions, trapdoor generation, short basis helpers, and trapdoor sampling examples. It is the closest inspected Rust API shape, but it does not implement FCP root/child CHKP delegation, capability-token binding, V4 representation boundaries, or FCP redaction/evidence policy. | Published on crates.io, MPL-2.0, MSRV 1.85, qFALL-maintained. It depends on `qfall-math` and `flint-sys`, requiring FLINT/C toolchain assumptions that conflict with FCP's one-binary connector posture. | Inspected crate source contains `unsafe` call sites through unchecked matrix/polynomial accessors, derives `Serialize` for `PSFPerturbation`, and has no FCP secret-type zeroization/redaction lifecycle. | Reject as direct production dependency. Keep as a high-value algorithmic study input for an internal/vendored reviewed route. |
| `lattirust/lattirust` at `6ce6b09bd30d4e057975a071c50095f018bc4699` | Arithmetic, SIS estimator, relations, and ZK-oriented protocols exist; search found no direct MP12/CHKP/GPV capability-token primitive surface. | No release package found by `cargo search lattirust`; workspace package licenses are unset in Cargo metadata; README says research/prototyping and not audited or fit for deployment. | Rust search found no `unsafe` matches, but there is no production trapdoor lifecycle, no semver release, and no FCP-specific secret policy. | Reject as direct production dependency. Could be a study input for a reviewed implementation. |
| `NethermindEth/latticefold` at `15cc045c18ea92a50c23528d1e7b62dd392b8c42` | Implements LatticeFold/LatticeFold+ proof/folding machinery and Ajtai commitments, not MP12/CHKP/GPV token delegation. | Apache-2.0 OR MIT; README explicitly calls it a proof-of-concept prototype and not production ready. | Some crates forbid unsafe, but the project is not a reviewed production primitive and carries Git dependencies. | Reject. It is the wrong primitive family and maturity level. |
| Standalone reference papers and hand-rolled arithmetic | The papers define the needed construction family, but FCP has no audited implementation yet. | Internal code would be maintainable only if vendored with design correspondence, review, and test vectors. | Side-channel resistance, constant-time policy, zeroization, deterministic RNG fixtures, and allocation bounds would all need first-class evidence. | Allowed only as a future reviewed implementation route, not as immediate production work. |

## Representation Requirements for `.8`

`flywheel_connectors-kyopb.1.3.1.1.8` remains the right next bead. Its
implementation must not bind the public API to any rejected candidate above.
Instead it should introduce a versioned representation boundary that can carry
or safely reference the eventual reviewed primitive:

- Root and child trapdoor representations need explicit type tags, parameter
  profile binding, representation version, relation-check metadata, and secret
  storage length buckets.
- Secret-bearing types must keep redacted `Debug`, constant-time equality where
  equality remains available, and zeroization/drop behavior.
- Serialization must separate public metadata from local secret material. Any
  export/import of secrets needs an explicit sealed-secret format, not implicit
  `serde` on coefficients.
- Public matrix seeds and expanded matrix shapes must be checked before
  allocation; V4 reference expansion remains bounded by the 64 MiB ceiling.
- Fixture-only SHAKE helpers must be namespaced away from production paths and
  documented as non-cryptographic compatibility scaffolding.
- Relation-check summaries may report booleans, norm/quality buckets, matrix
  dimensions, and public hashes; they must never log coefficients or seeds.

## Required Test and E2E Plan

Any future primitive route that unblocks `.3` and `.4` must add these proof
surfaces before closeout:

- Unit/property tests for deterministic `SMALL_TEST` TrapGen fixtures, public
  seed expansion stability, root and child relation checks, malformed version
  and length rejection, wrong parameter profile rejection, wrong parent,
  wrong zone, wrong period, depth boundary, outside-period validation, and
  redaction/zeroization behavior.
- Allocation tests for `V4_REFERENCE` that verify shape and ceilings without
  dumping expanded public matrices or any secret matrix material.
- Arithmetic tests proving `TrapGen -> Delegate -> SamplePre -> Verify`
  success for supported profiles and denial cases for forged equation,
  over-norm preimage, malformed preimage, unsupported profile, and encoding
  failure.
- E2E scripts that emit JSONL with command line, git revision, primitive route
  and revision, representation version, parameter profile, fixture id, hashed
  zone and period ids, matrix dimensions, relation results, norm/quality
  buckets, allocation summary, timings, result, and skip reason.
- Logging assertions that fail if JSONL contains trapdoor coefficients, secret
  seeds, expanded secret matrices, raw zone/principal/operation text, local
  private paths, or PII.

## Downstream Bead Impact

- Keep `flywheel_connectors-kyopb.1.3.1.1.3` blocked on `.8`; it must not start
  until the representation can honestly carry real root and child trapdoors.
- Keep `flywheel_connectors-kyopb.1.3.1.1.4` blocked by `.3`; SamplePre/Verify
  cannot be implemented before TrapGen/Delegate and representation relation
  checks are real.
- Do not remove the V4 promise. The correct state is a guarded implementation
  path, not a simplified cryptographic scope.

## Evidence

Machine-readable evidence is in
`docs/post-quantum/evidence/lattice_primitive_decision_2026-05-07.jsonl`.

Primary inspected local files:

- `crates/fcp-crypto-pq/src/lib.rs`
- `crates/fcp-crypto-pq/Cargo.toml`
- `docs/post-quantum/lattice_trapdoor_delegation.md`
- `docs/post-quantum/throughput_benchmark.md`
- `Cargo.lock`
- `.beads/issues.jsonl`

Primary public sources inspected:

- `https://github.com/lattirust/lattirust`
- `https://github.com/RustCrypto/KEMs`
- `https://docs.rs/module-lattice/0.2.2`
- `https://qfall.github.io/`
- `https://docs.rs/qfall-tools/0.1.0`
- `https://github.com/qfall/tools`
- `https://github.com/NethermindEth/latticefold`

Key commands used for Beads graph changes in this decision pass:

- `br --no-db --lock-timeout 120000 --actor Codex --json update flywheel_connectors-kyopb.1.3.1.1.7 --claim`
- `br --no-db --lock-timeout 120000 --actor Codex --json comments add flywheel_connectors-kyopb.1.3.1.1.7 <start-comment>`

The closeout comment for `.7` records the final `br` close/sync commands and
the `bv --robot-triage` impact after this artifact lands.
