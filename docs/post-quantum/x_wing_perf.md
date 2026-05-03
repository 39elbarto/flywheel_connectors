# X-Wing KEM performance benchmark

**Bead:** `flywheel_connectors-kyopb.1.2.5` ([J.5.2.5]).
**Bench file:** `crates/fcp-crypto/benches/x_wing_kem.rs`.
**Companion design:** `docs/post-quantum/x_wing_kem_design.md`.

This note records the first Criterion baseline for the FCP V4 X-Wing
KEM path: pure KEM encap/decap, FCP sealed-box round trips, and the
V3 X25519/HPKE baseline used during the V3 to V4 migration window.

## Summary

| Operation                    | Median        | Baseline / Read |
| ---------------------------- | ------------: | --------------- |
| X-Wing keygen                |     44.167 us | 4.25x X25519 keygen |
| X-Wing KEM encap             |     68.456 us | 3.03x vanilla X25519 DH |
| X-Wing KEM decap             |     76.147 us | 3.37x vanilla X25519 DH |
| FCP X-Wing seal, 32 B        |     64.158 us | 1.36x HPKE-X25519 seal |
| FCP X-Wing open, 32 B        |    122.000 us | 3.71x HPKE-X25519 open |
| FCP X-Wing round trip, 32 B  |    211.120 us | seal + open + wrapper |
| FCP X-Wing seal, 1 KiB       |     71.992 us | 13.565 MiB/s |
| FCP X-Wing open, 1 KiB       |    121.120 us | 8.063 MiB/s |

The practical cost is concentrated in receiver-side decapsulation.
That is acceptable for zone-key issuance because V4 KEM operations are
control-plane events, not per-object encryption; per-object payloads
remain on ChaCha20-Poly1305 after the zone key is unwrapped.

## Methodology

### Implementations under test

- **X-Wing KEM:** RustCrypto `x-wing = 0.1.0-rc.0`, draft-06 wire
  shape in the current FCP wrapper. The benchmark uses the upstream
  KEM API for pure `encap` / `decap`.
- **FCP X-Wing sealed box:** `XWingProvider::seal` /
  `XWingProvider::open`, which run X-Wing then derive the AEAD key via
  HKDF-SHA256 with `FCP4-XWING-AEAD` and encrypt with
  ChaCha20-Poly1305.
- **Vanilla X25519 baseline:** `X25519SecretKey::generate` and
  `diffie_hellman`, without HPKE framing.
- **HPKE-X25519 baseline:** existing V3 `hpke_seal` / `hpke_open`
  over a 32-byte zone-key payload.

### Command

The requested verification command was run with an isolated target dir
because the shared workspace target was locked by other active panes:

```sh
TMPDIR=/Volumes/USB_NVME \
  CARGO_TARGET_DIR=/Volumes/USB_NVME/fcp-silverfox-xwing-kem \
  cargo bench -p fcp-crypto x_wing_kem
```

The bench group uses Criterion `0.8` with sample size 20, 1 second
warmup, and 3 seconds measurement per row. That keeps the run short
enough for review beads while still producing stable order-of-magnitude
regression data. Criterion HTML output is written under
`/Volumes/USB_NVME/fcp-silverfox-xwing-kem/criterion/`.

### Hardware + toolchain

| Item          | Value |
| ------------- | ----- |
| CPU           | Apple M4 Pro |
| OS            | macOS 26.2, Darwin 25.2.0 |
| Rust          | nightly 1.97.0 (`67bcaa9c4`, 2026-05-01) |
| Build profile | `[bench]` optimized |
| Captured      | 2026-05-02T11:04:46Z |

## Results

### Pure KEM / DH

| Operation             | Low       | Median    | High      | Ops/sec at median |
| --------------------- | --------: | --------: | --------: | ----------------: |
| X-Wing keygen         | 42.845 us | 44.167 us | 45.283 us | 22,641 |
| X-Wing encap          | 64.637 us | 68.456 us | 74.425 us | 14,608 |
| X-Wing decap          | 74.230 us | 76.147 us | 78.213 us | 13,132 |
| X25519 keygen         | 10.093 us | 10.389 us | 10.908 us | 96,255 |
| X25519 DH             | 22.143 us | 22.611 us | 23.265 us | 44,226 |

**Read:** X-Wing keygen is ~4.25x the X25519 keygen baseline. X-Wing
encap/decap are ~3.0x and ~3.4x vanilla X25519 DH respectively. The
ML-KEM side dominates, but the absolute cost remains sub-100 us per
KEM operation on this machine.

### FCP sealed-box path

| Operation                   | Low        | Median     | High       | Notes |
| --------------------------- | --------: | ---------: | ---------: | ----- |
| X-Wing seal, 32 B           |  62.115 us |  64.158 us |  66.420 us | KEM encap + HKDF + AEAD |
| X-Wing open, 32 B           | 119.990 us | 122.000 us | 125.290 us | KEM decap + HKDF + AEAD |
| X-Wing round trip, 32 B     | 201.790 us | 211.120 us | 220.160 us | seal + open in one loop |
| X-Wing seal, 1 KiB          |  68.269 us |  71.992 us |  75.375 us | 13.565 MiB/s |
| X-Wing open, 1 KiB          | 118.660 us | 121.120 us | 124.810 us | 8.063 MiB/s |
| HPKE-X25519 seal, 32 B      |  46.001 us |  47.003 us |  48.150 us | V3 baseline |
| HPKE-X25519 open, 32 B      |  32.813 us |  32.915 us |  33.064 us | V3 baseline |

**Read:** FCP X-Wing seal is close to V3 HPKE seal because both paths
pay an ephemeral X25519-like operation plus AEAD wrapping. FCP X-Wing
open is ~3.7x slower than HPKE-X25519 open because it pays ML-KEM-768
decapsulation in addition to the X25519 half.

## Hybrid-security regression coverage

`crates/fcp-crypto/tests/x_wing_kem.rs` reconstructs X-Wing draft
component secrets from the published KAT vectors:

- `ss_mlkem` from ML-KEM-768 decapsulation of the vector's ML-KEM
  ciphertext half.
- `ss_x25519` from X25519 over the vector's X25519 ciphertext half.
- the draft combiner `SHA3-256(ss_mlkem || ss_x25519 || ct_x || pk_x || label)`.

The tests assert:

- the reconstructed combiner matches the draft KAT shared secret;
- replacing `ss_mlkem` with all zeros still yields a usable AEAD key
  when the X25519 half is live;
- replacing `ss_x25519` with all zeros still yields a usable AEAD key
  when the ML-KEM half is live;
- replacing both components with zeros fails to authenticate a real
  sealed box;
- the X-Wing KAT shared secret is not equal to the vanilla X25519 DH
  output, so the hybrid path cannot silently collapse to the classical
  baseline.

That is the regression shape promised by the design doc §8 while
keeping component fault injection out of the production `XWingProvider`
API.

## Design question resolutions

### Q4: lattice-trapdoor delegation key separation

`kyopb.1.3` must not share the X-Wing key pair. X-Wing is a KEM for
wrapping V4 zone-key material to recipients; lattice-trapdoor
delegation needs a signing/delegation trapdoor with different lifetime,
rotation, audit, and compromise semantics. Reusing the KEM key would
couple confidentiality and delegation authority, make rollback harder,
and blur hardware-token policy. The migration plan should treat X-Wing
recipient keys and lattice delegation keys as separate attested key
families under the V4 owner attestation chain.

### Q5: X-Wing draft status and swap policy

As of 2026-05-02, the IETF Datatracker lists
`draft-connolly-cfrg-xwing-kem-10` as an active individual
Internet-Draft, Independent Submission stream, intended Informational,
last updated 2026-03-02, and expiring 2026-09-03:
<https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/>.

That status is acceptable for this codebase because FCP wraps X-Wing
behind `XWingKem`, pins draft wire sizes and KAT vectors in tests, and
does not expose the upstream crate's types in durable public artifacts.
The swap policy is:

- keep V4 manifests algorithm-tagged as `XWing`;
- keep draft-version and KAT provenance in docs/tests;
- if CFRG/IRTF standardizes a different hybrid KEM or changes X-Wing
  wire format, add a new algorithm tag and migration bead rather than
  mutating existing `XWing` semantics in place.

## Regression commands

```sh
TMPDIR=/Volumes/USB_NVME \
  CARGO_TARGET_DIR=/Volumes/USB_NVME/fcp-silverfox-xwing-kem \
  cargo test -p fcp-crypto x_wing_kem --all-targets
```

```sh
TMPDIR=/Volumes/USB_NVME \
  CARGO_TARGET_DIR=/Volumes/USB_NVME/fcp-silverfox-xwing-kem \
  cargo bench -p fcp-crypto x_wing_kem
```
