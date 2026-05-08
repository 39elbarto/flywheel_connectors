//! Throughput benchmark: lattice-trapdoor delegation vs Ed25519 + ML-DSA-65
//! (br-kyopb.1.3.4).
//!
//! ## What this measures
//!
//! Three signature/delegation families across the same per-op shapes
//! (keygen, sign-equivalent, verify-equivalent, end-to-end):
//!
//! - **Ed25519** — V3 baseline. Real production primitives via the
//!   [`fcp_crypto::ed25519`] wrapper (ed25519-dalek under the hood).
//! - **ML-DSA-65** — V4 owner-key candidate. Real FIPS 204 primitives
//!   via [`fcp_crypto::ml_dsa`] (`RustCrypto` `ml-dsa` crate).
//! - **Lattice-trapdoor** — V4 capability-delegation candidate. Calls
//!   into [`fcp_crypto_pq`]. This benchmark keeps the explicit fixture-only
//!   setup/delegation helpers as a bridge-cost floor even though the production
//!   V4 TrapGen/Delegate public-matrix route now exists. `sample_pre` / `verify`
//!   currently return
//!   `LatticePqError::NotImplemented`; the structural / hashing /
//!   parameter-check work IS real (public-matrix seed derivation,
//!   period-bounds checks, parameter agreement, etc.).
//!
//! ## What the lattice numbers mean — IMPORTANT
//!
//! Because this benchmark's `V4_REFERENCE` TrapGen/Delegate path is
//! deliberately fixture-only and `sample_pre` / `verify` are stubs, the
//! lattice-trapdoor group reflects **the cost of the bridge-floor primitives,
//! NOT the cost the real large-profile Micciancio-Peikert `TrapGen` /
//! Cash-Hofheinz-Kiltz-Peikert basis-shortening /
//! Gentry-Peikert-Vaikuntanathan `SamplePre` will incur once they land**.
//!
//! This bench's lattice numbers are therefore a **lower bound** on
//! actual production throughput — they represent only the bridge
//! work the verifier always pays (parameter checks, period bounds,
//! hash-input construction). Real `sample_pre` is dominated by
//! Gaussian-distribution sampling over the lattice (typically 1-10ms
//! at the `V4_REFERENCE` profile per the design doc §3.2, ~10⁵× slower
//! than Ed25519 sign); real `verify` is matrix-vector multiplication
//! plus norm check (~100µs-1ms, ~10²-10³× slower than Ed25519
//! verify).
//!
//! The companion document `docs/post-quantum/throughput_benchmark.md`
//! records both the measured stub numbers and the projected real-impl
//! numbers from the lattice literature, with the regression-tracking
//! plan for when the lattice arithmetic lands.
//!
//! ## Reproducibility
//!
//! ```sh
//! TMPDIR=/Volumes/USB_NVME \
//!   AGENT_NAME=AmberLark \
//!   CARGO_TARGET_DIR=/Volumes/USB_NVME/fcp-alpha-pq \
//!   cargo bench -p fcp-crypto-pq --bench lattice_vs_ed25519_vs_mldsa
//! ```

use std::hint::black_box;
use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};

use fcp_crypto::{Ed25519SigningKey, Ed25519VerifyingKey, MlDsa65SigningKey, MlDsa65VerifyingKey};
use fcp_crypto_pq::{
    DelegationPeriod, LatticeParams, LatticePreimage, MasterPublicKey, MasterTrapdoor,
    ZonePeriodPublicKey, ZonePeriodTrapdoor, delegate_fixture, operation_hash, sample_pre,
    trap_gen_fixture, verify,
};

const SAMPLE_MESSAGE: &[u8] = b"capability-token canonical body for throughput-bench/v0";
const SIGNING_CONTEXT: &[u8] = b"fcp/throughput-bench/v0";
const REQUEST_ZONE: [u8; 32] = [7u8; 32];
const REQUEST_PRINCIPAL: &[u8] = b"principal:bench-user";
const REQUEST_OP: &[u8] = b"op:bench.invoke";

const fn ref_period() -> DelegationPeriod {
    DelegationPeriod {
        start_secs: 1_000,
        end_secs: 1_000_000_000,
    }
}

fn lattice_setup() -> (
    LatticeParams,
    MasterPublicKey,
    MasterTrapdoor,
    ZonePeriodPublicKey,
    ZonePeriodTrapdoor,
) {
    let params = LatticeParams::V4_REFERENCE;
    let (mp, mt) = trap_gen_fixture(params).expect("fixture trap_gen never fails");
    let (zp, zt) = delegate_fixture(&mp, &mt, REQUEST_ZONE, ref_period(), params)
        .expect("fixture delegate never fails on agreeing params");
    (params, mp, mt, zp, zt)
}

// ── Group: keygen ─────────────────────────────────────────────────────────

fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("keygen");
    group.throughput(Throughput::Elements(1));

    group.bench_function("ed25519", |b| {
        b.iter(|| {
            let _ = black_box(Ed25519SigningKey::generate());
        });
    });

    group.bench_function("ml_dsa_65", |b| {
        b.iter(|| {
            let _ = black_box(MlDsa65SigningKey::generate().expect("ml-dsa keygen succeeds"));
        });
    });

    group.bench_function("lattice_trapdoor_master_setup", |b| {
        // The lattice analogue of "key generation" is `trap_gen`, which
        // returns the master public key + trapdoor. In the real impl
        // this is the most expensive lattice operation (lattice basis
        // sampling); in the scaffold it's a single SHAKE256 expansion so the
        // number is a lower bound.
        let params = LatticeParams::V4_REFERENCE;
        b.iter(|| {
            let _ = black_box(trap_gen_fixture(black_box(params)).expect("fixture never fails"));
        });
    });

    group.finish();
}

// ── Group: signing / token issuance ───────────────────────────────────────

fn bench_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign_or_issue");
    group.throughput(Throughput::Elements(1));

    let ed_sk = Ed25519SigningKey::generate();
    group.bench_function("ed25519_sign", |b| {
        b.iter(|| {
            let _ = black_box(ed_sk.sign(black_box(SAMPLE_MESSAGE)));
        });
    });

    let mldsa_sk = MlDsa65SigningKey::generate().expect("ml-dsa keygen");
    group.bench_function("ml_dsa_65_sign", |b| {
        b.iter(|| {
            let _ = black_box(
                mldsa_sk
                    .sign(black_box(SAMPLE_MESSAGE), black_box(SIGNING_CONTEXT))
                    .expect("ml-dsa sign succeeds"),
            );
        });
    });

    // The lattice analogue of "sign" is one delegate hop (issuance node
    // mints a per-(zone, period) sub-trapdoor). Real impl: CHKP basis-
    // shortening over a lattice basis. Scaffold: deterministic SHAKE256
    // chain. Numbers represent the structural bridge cost only.
    let (params, mp, mt, _, _) = lattice_setup();
    group.bench_function("lattice_delegate_one_hop", |b| {
        b.iter(|| {
            let _ = black_box(
                delegate_fixture(
                    black_box(&mp),
                    black_box(&mt),
                    black_box(REQUEST_ZONE),
                    black_box(ref_period()),
                    black_box(params),
                )
                .expect("fixture delegate never fails"),
            );
        });
    });

    // Operation-hash construction (h ← H(zone | period | op | principal))
    // — every sub-token mint pays this. Useful as a per-op fixed cost
    // floor for the lattice family.
    group.bench_function("lattice_operation_hash", |b| {
        let zone = REQUEST_ZONE;
        let period = ref_period();
        b.iter(|| {
            let _ = black_box(operation_hash(
                black_box(&zone),
                black_box(period),
                black_box(REQUEST_OP),
                black_box(REQUEST_PRINCIPAL),
            ));
        });
    });

    group.finish();
}

// ── Group: verify ─────────────────────────────────────────────────────────

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify");
    group.throughput(Throughput::Elements(1));

    let ed25519_signer = Ed25519SigningKey::generate();
    let ed25519_checker: Ed25519VerifyingKey = ed25519_signer.verifying_key();
    let ed25519_sig = ed25519_signer.sign(SAMPLE_MESSAGE);
    group.bench_function("ed25519_verify", |b| {
        b.iter(|| {
            ed25519_checker
                .verify(black_box(SAMPLE_MESSAGE), black_box(&ed25519_sig))
                .expect("ed25519 verify succeeds");
        });
    });

    let mldsa_signer = MlDsa65SigningKey::generate().expect("ml-dsa keygen");
    let mldsa_checker: &MlDsa65VerifyingKey = mldsa_signer.verifying_key();
    let mldsa_sig = mldsa_signer
        .sign(SAMPLE_MESSAGE, SIGNING_CONTEXT)
        .expect("ml-dsa sign succeeds");
    group.bench_function("ml_dsa_65_verify", |b| {
        b.iter(|| {
            mldsa_checker
                .verify(
                    black_box(SAMPLE_MESSAGE),
                    black_box(SIGNING_CONTEXT),
                    black_box(&mldsa_sig),
                )
                .expect("ml-dsa verify succeeds");
        });
    });

    // Lattice verify: the cryptographic body returns NotImplemented;
    // what we measure here is the structural-check cost (parameter
    // agreement, period bounds) plus the NotImplemented branch. This is
    // a hard floor for the production verify cost — real impl adds
    // matrix-vector multiplication + norm check on top of this.
    let (params, _, _, zp, _) = lattice_setup();
    let h = operation_hash(&REQUEST_ZONE, ref_period(), REQUEST_OP, REQUEST_PRINCIPAL);
    let preimage = LatticePreimage::fixture_zero(params).expect("reference preimage fixture");
    let now_secs = ref_period().start_secs + 100;
    group.bench_function("lattice_verify_structural_floor", |b| {
        b.iter(|| {
            // Returns Err(NotImplemented) — but only after running
            // every cheap structural check, so the timing reflects
            // the bridge floor cost the real verify must pay too.
            let _ = black_box(verify(
                black_box(&zp),
                black_box(h),
                black_box(&preimage),
                black_box(now_secs),
                black_box(params),
            ));
        });
    });

    group.finish();
}

// ── Group: end-to-end ─────────────────────────────────────────────────────

fn bench_end_to_end(c: &mut Criterion) {
    let mut group = c.benchmark_group("end_to_end");
    group.throughput(Throughput::Elements(1));
    // E2E groups are noisier; bump warmup to stabilize.
    group.warm_up_time(Duration::from_secs(2));

    group.bench_function("ed25519_sign_then_verify", |b| {
        let sk = Ed25519SigningKey::generate();
        let vk = sk.verifying_key();
        b.iter(|| {
            let sig = sk.sign(black_box(SAMPLE_MESSAGE));
            vk.verify(black_box(SAMPLE_MESSAGE), black_box(&sig))
                .expect("verify succeeds");
        });
    });

    group.bench_function("ml_dsa_65_sign_then_verify", |b| {
        let sk = MlDsa65SigningKey::generate().expect("ml-dsa keygen");
        let vk = sk.verifying_key();
        b.iter(|| {
            let sig = sk
                .sign(black_box(SAMPLE_MESSAGE), black_box(SIGNING_CONTEXT))
                .expect("sign succeeds");
            vk.verify(
                black_box(SAMPLE_MESSAGE),
                black_box(SIGNING_CONTEXT),
                black_box(&sig),
            )
            .expect("verify succeeds");
        });
    });

    // Lattice E2E: trap_gen → delegate → operation_hash → sample_pre →
    // verify. sample_pre returns NotImplemented immediately; verify
    // runs structural checks then NotImplemented. Measures the full
    // bridge-cost path the production verifier pays.
    group.bench_function("lattice_full_pipeline_floor", |b| {
        let params = LatticeParams::V4_REFERENCE;
        b.iter(|| {
            let (mp, mt) = trap_gen_fixture(black_box(params)).expect("trap_gen fixture");
            let (zp, zt) = delegate_fixture(
                black_box(&mp),
                black_box(&mt),
                black_box(REQUEST_ZONE),
                black_box(ref_period()),
                black_box(params),
            )
            .expect("delegate fixture");
            let h = operation_hash(
                black_box(&REQUEST_ZONE),
                black_box(ref_period()),
                black_box(REQUEST_OP),
                black_box(REQUEST_PRINCIPAL),
            );
            // sample_pre returns NotImplemented; we still pay its
            // entry cost (one parameter-equality check) which is what
            // the real impl will gate on too.
            let _ = black_box(sample_pre(
                black_box(&zp),
                black_box(&zt),
                black_box(h),
                black_box(params),
            ));
            // Verify with a placeholder preimage — exercises the same
            // bridge code real callers will use.
            let preimage =
                LatticePreimage::fixture_zero(params).expect("reference preimage fixture");
            let now_secs = ref_period().start_secs + 100;
            let _ = black_box(verify(
                black_box(&zp),
                black_box(h),
                black_box(&preimage),
                black_box(now_secs),
                black_box(params),
            ));
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_keygen,
    bench_sign,
    bench_verify,
    bench_end_to_end
);
criterion_main!(benches);
