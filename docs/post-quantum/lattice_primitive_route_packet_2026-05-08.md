# Lattice Primitive Route Packet - 2026-05-08

Bead: `flywheel_connectors-kyopb.1.3.1.1.9`

Repository revision inspected: `fd73e0463a0d56e3086baac7b1701f64f22bfae6`

Decision: **internal no-FFI Rust implementation route, with qFALL as a study
and fixture-comparison input only**. The later arithmetic bead
`flywheel_connectors-kyopb.1.3.1.1.3` must not wire `qfall-tools`,
`module-lattice`, or any rejected research/prototype crate into production
capability-token security. It should implement the MP12 root trapdoor and
CHKP/Bonsai child-delegation path directly in `fcp-crypto-pq`, preserving the
version-2 representation envelope from `.8` and keeping `SamplePre`/`Verify`
for `.4`.

The important correction is API-level: the current deterministic
`trap_gen(params)` shape is a fixture scaffold. Production TrapGen needs
explicit entropy. The implementation bead should introduce a typed entropy
surface, such as `TrapGenEntropy`, with an OS-random production constructor and
deterministic seed constructor for tests. The existing fixture SHAKE helpers
may remain only as compatibility fixtures and must be named as such.

## Sources and Route Inputs

Primary construction inputs:

- MP12: Micciancio and Peikert, "Trapdoors for Lattices: Simpler, Tighter,
  Faster, Smaller", IACR ePrint 2011/501. The route uses MP12-style
  strong-trapdoor generation with `A = [A_bar | H * G - A_bar * R]` and secret
  basis material derived from `R` plus gadget-basis data.
- CHKP/Bonsai: Cash, Hofheinz, Kiltz, and Peikert, "Bonsai Trees, or How to
  Delegate a Lattice Basis", IACR ePrint 2010/591. The route uses child
  public matrices as structured extensions of the parent matrix and derives a
  child trapdoor from the parent-controlled branch.
- GPV08: Gentry, Peikert, and Vaikuntanathan, "Trapdoors for Hard Lattices and
  New Cryptographic Constructions". This remains the downstream `.4` input for
  preimage sampling and norm-bound verification, not part of `.3` closeout.
- qFALL `qfall-tools` 0.1.0: use as an algorithmic comparison and fixture
  oracle only. Its docs expose GPV and MP12 PSF surfaces, `trap_gen`,
  `samp_p`, G-trapdoor helpers, and short-basis helpers, but the crate is a
  prototyping library, derives serialization on PSF structs, is not `Send` or
  `Sync` for the perturbation PSF, and depends on `qfall-math`/FLINT via C/FFI
  tooling. Those facts make it useful for study and unacceptable as a direct
  FCP dependency.

References:

- https://eprint.iacr.org/2011/501
- https://eprint.iacr.org/2010/591
- https://www.mit.edu/~vinodv/papers/trapcvp.pdf
- https://docs.rs/qfall-tools/latest/qfall_tools/
- https://docs.rs/qfall-tools/latest/qfall_tools/primitive/psf/struct.PSFPerturbation.html
- https://github.com/qfall/tools

## Algorithm-to-Code Correspondence

| Route piece | Paper concept | FCP implementation target | Required evidence |
| --- | --- | --- | --- |
| Parameter validation | MP12 gadget and modulus constraints | Extend `LatticeParams::validate` with gadget-base, width, modulus, depth, and entropy-route checks. Do not silently accept profiles whose `m` no longer matches the selected gadget decomposition. | Unit tests for malformed dimensions, modulus, depth, and oversize V4 allocation. |
| Public root matrix | MP12 `A = [A_bar | H * G - A_bar * R]` | Add a public seed plus deterministic streaming expansion for `A_bar`, gadget block `G`, and the combined `A_root`; keep serialized public material seed-backed. | Deterministic `SMALL_TEST` matrix fixture hash and V4 shape/allocation proof without dumping matrix entries. |
| Root trapdoor | MP12 strong trapdoor `R` plus gadget-basis data | Store a `BasisEnvelope` inside `MasterTrapdoor`, with route id, entropy id hash, parameter profile, length bucket, norm/quality bucket, and zeroized secret bytes. | `A_root/T_root` relation check returns `MetadataConsistent` or a stronger route-specific success enum without revealing coefficients. |
| Entropy | Required for real setup | Replace production use of deterministic SHAKE seed bundles with typed entropy. Production constructor uses OS randomness; fixture constructor uses explicit test seed and fixture id. | Unit tests prove production path cannot be called through fixture-only helper names by accident; evidence logs hash fixture ids only. |
| Child public matrix | CHKP/Bonsai controlled branch extension | Derive child seed from parent public hash, hashed zone id, period bounds, depth, and route id; represent `A_child` as parent-compatible public extension. | Domain-separation tests for zone, period start, period end, parent hash, and profile. |
| Child trapdoor | CHKP/Bonsai basis delegation | Derive `ZonePeriodTrapdoor` as a `BasisEnvelope` from parent basis material and child extension matrix. The route must reject fixture parent trapdoors for production child delegation. | Child relation check succeeds for supported test profile and fails for wrong parent, wrong zone, wrong period, malformed secret, and mismatched profile. |
| Relation summaries | Redaction-safe proof surface | Preserve `.8` metadata summaries, but split fixture-only results from real route relation results. Norm quality must be bucketed, never raw. | JSONL evidence includes relation result and norm bucket only. |
| SamplePre/Verify boundary | GPV downstream work | Leave `sample_pre` and positive `verify` success to `.4`. `.3` may add shared matrix/preimage utilities only when required for relation tests. | Tests continue to expect `.4` `NotImplemented` for positive mint/verify paths. |

## Dependency and License Boundary

The production route must stay inside the FCP workspace and avoid new FFI or C
toolchain requirements. `qfall-tools` is MPL-2.0 and depends on
`qfall-math`/FLINT; it also exposes prototype-style APIs where parameter
mismatch may panic. That is incompatible with FCP connector distribution,
fail-closed error policy, and secret lifecycle requirements.

Allowed use of qFALL in `.3`:

- Inspect public algorithms and tests as a reference.
- Generate independent comparison vectors outside the production crate, if
  the command is documented and emits only public hashes and relation booleans.
- Cite it in the route evidence.

Disallowed use of qFALL in `.3`:

- Adding `qfall-tools`, `qfall-math`, `flint-sys`, or `typetag` to
  `Cargo.toml` for production.
- Serializing qFALL trapdoor structs or mirroring its tuple-shaped secret key
  API in public FCP types.
- Treating qFALL panics as acceptable error handling.

## Side-Channel and Secret-Lifecycle Policy

- `unsafe_code` remains forbidden in `fcp-crypto-pq`.
- Trapdoor bytes stay non-`Serialize` and redacted in `Debug`.
- Secret storage uses `zeroize` or equivalent observable drop behavior for all
  owned secret buffers.
- Relation checks may branch on public metadata and public matrix dimensions.
  They must not branch on secret coefficients except in explicitly reviewed
  constant-time or constant-work sections.
- No evidence log may include trapdoor coefficients, secret seeds, expanded
  secret matrices, raw zone labels, raw operation/principal text, local private
  paths, or PII.
- Deterministic fixtures must be tagged with fixture ids and route ids so they
  cannot be mistaken for production entropy.

## Required Unit and Property Tests for `.3`

The TrapGen/Delegate implementation bead must add all of these before close:

- `SMALL_TEST` deterministic TrapGen fixture: public root seed/hash, route id,
  entropy fixture id, matrix dimensions, and relation result.
- V4 reference shape and allocation guard: prove matrix expansion remains under
  the 64 MiB public-matrix ceiling and trapdoor envelope stays under 1 MiB
  without logging expanded matrices.
- Root relation validation: supported test profile succeeds, malformed basis
  fails, wrong parameter profile fails, wrong route id fails.
- Entropy boundary: production constructor requires explicit entropy and
  fixture constructor is named and logged as fixture-only.
- Delegate domain separation: parent hash, zone hash, period start, period end,
  depth, and parameter profile each affect child public material.
- Child relation validation: success for matching parent/child trapdoor, failure
  for wrong parent, wrong zone, wrong period, wrong depth, malformed child
  secret, fixture parent secret in production route, and unsupported profile.
- Redaction and serialization: root and child basis envelopes do not implement
  accidental secret serialization, `Debug` redacts, equality stays
  constant-time where exposed, and metadata round-trips without secrets.
- Fail-closed behavior: unsupported primitive/profile returns an explicit error
  and leaves downstream `.4` blocked rather than returning success.

## Required E2E JSONL Proof for `.3`

The deterministic setup/delegation harness must emit one JSONL record per
profile and scenario. Required fields:

- `command_line`
- `git_revision`
- `primitive_route_id`
- `primitive_route_revision`
- `representation_version`
- `parameter_profile`
- `fixture_id`
- `zone_id_hash`
- `period_id_hash`
- `matrix_dimensions`
- `root_relation_result`
- `child_relation_result`
- `trapdoor_norm_quality_bucket`
- `allocation_summary`
- `timing_ms`
- `result`
- `skip_reason`

Required denial scenarios:

- malformed root basis
- malformed child basis
- wrong parent
- wrong zone
- wrong period
- wrong parameter profile
- unsupported profile
- fixture-only trapdoor used on production route

Required log assertions:

- reject `trapdoor_coefficients`
- reject `secret_seed`
- reject `expanded_secret_matrix`
- reject raw zone labels
- reject raw operation or principal text
- reject local private paths
- reject PII

## Unblock Rule

`flywheel_connectors-kyopb.1.3.1.1.3` may be reopened only when this route
packet is accepted and cited in its start comment. If later inspection shows
the internal MP12/CHKP route cannot be implemented without unsafe/FFI or
cryptographic assumptions outside the design envelope, `.3` must remain
blocked and a narrower research or external-review bead must be added instead
of reducing the V4 lattice promise.
