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
//!   the reviewed `fcp-internal-mp12-chkp-no-ffi-v1` route in
//!   [`fcp_crypto_pq`] for `TrapGen`, `Delegate`, `SamplePre`, and
//!   `Verify`.
//!
//! ## What the lattice numbers mean — IMPORTANT
//!
//! The lattice numbers are real route measurements for this repository's
//! internal no-FFI arithmetic path. They include public-matrix material
//! construction, bounded basis-envelope derivation, preimage sampling,
//! matrix-vector verification, norm checks, and period/parameter checks.
//!
//! The companion document `docs/post-quantum/throughput_benchmark.md`
//! records the latest raw measurements plus the host policy/dispatcher
//! e2e timing artifact that exercises this same primitive route.
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
    DelegationPeriod, LatticeParams, MasterPublicKey, MasterTrapdoor, TrapGenEntropy,
    ZonePeriodPublicKey, ZonePeriodTrapdoor, delegate, operation_hash, sample_pre,
    trap_gen_with_entropy, verify,
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
    let entropy = TrapGenEntropy::from_fixture_seed(b"fcp-pq-bench/lattice-setup-v1", [0x17; 32]);
    let (mp, mt) = trap_gen_with_entropy(params, &entropy).expect("trap_gen succeeds");
    let (zp, zt) =
        delegate(&mp, &mt, REQUEST_ZONE, ref_period(), params).expect("delegate succeeds");
    (params, mp, mt, zp, zt)
}

// ── Group: keygen ─────────────────────────────────────────────────────────

fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("keygen");
    group.throughput(Throughput::Elements(1));
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(10));

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
        // returns the master public key + trapdoor. This measures the
        // reviewed route, not the legacy fixture seed-bundle helper.
        let params = LatticeParams::V4_REFERENCE;
        let entropy = TrapGenEntropy::from_fixture_seed(b"fcp-pq-bench/trap-gen-v1", [0x23; 32]);
        b.iter(|| {
            let _ = black_box(
                trap_gen_with_entropy(black_box(params), black_box(&entropy))
                    .expect("trap_gen succeeds"),
            );
        });
    });

    group.finish();
}

// ── Group: signing / token issuance ───────────────────────────────────────

fn bench_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign_or_issue");
    group.throughput(Throughput::Elements(1));
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(10));

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

    // The lattice analogue of "sign" at this layer is one delegate hop:
    // the issuance node mints a per-(zone, period) sub-trapdoor.
    let (params, mp, mt, _, _) = lattice_setup();
    group.bench_function("lattice_delegate_one_hop", |b| {
        b.iter(|| {
            let _ = black_box(
                delegate(
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

    let (params, _, _, zp, zt) = lattice_setup();
    let h = operation_hash(&REQUEST_ZONE, ref_period(), REQUEST_OP, REQUEST_PRINCIPAL);
    group.bench_function("lattice_sample_pre_real_route", |b| {
        b.iter(|| {
            let _ = black_box(
                sample_pre(
                    black_box(&zp),
                    black_box(&zt),
                    black_box(h),
                    black_box(params),
                )
                .expect("sample_pre succeeds"),
            );
        });
    });

    group.finish();
}

// ── Group: verify ─────────────────────────────────────────────────────────

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify");
    group.throughput(Throughput::Elements(1));
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(10));

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

    let (params, _, _, zp, zt) = lattice_setup();
    let h = operation_hash(&REQUEST_ZONE, ref_period(), REQUEST_OP, REQUEST_PRINCIPAL);
    let preimage = sample_pre(&zp, &zt, h, params).expect("sample_pre succeeds");
    let now_secs = ref_period().start_secs + 100;
    group.bench_function("lattice_verify_real_route", |b| {
        b.iter(|| {
            black_box(verify(
                black_box(&zp),
                black_box(h),
                black_box(&preimage),
                black_box(now_secs),
                black_box(params),
            ))
            .expect("verify succeeds");
        });
    });

    group.finish();
}

// ── Group: end-to-end ─────────────────────────────────────────────────────

fn bench_end_to_end(c: &mut Criterion) {
    let mut group = c.benchmark_group("end_to_end");
    group.throughput(Throughput::Elements(1));
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(10));

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

    // Lattice E2E: trap_gen → delegate → operation_hash → sample_pre → verify.
    group.bench_function("lattice_full_crypto_route", |b| {
        let params = LatticeParams::V4_REFERENCE;
        let entropy = TrapGenEntropy::from_fixture_seed(b"fcp-pq-bench/full-route-v1", [0x31; 32]);
        b.iter(|| {
            let (mp, mt) =
                trap_gen_with_entropy(black_box(params), black_box(&entropy)).expect("trap_gen");
            let (zp, zt) = delegate(
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
            let preimage = black_box(sample_pre(
                black_box(&zp),
                black_box(&zt),
                black_box(h),
                black_box(params),
            ))
            .expect("sample_pre");
            let now_secs = ref_period().start_secs + 100;
            black_box(verify(
                black_box(&zp),
                black_box(h),
                black_box(&preimage),
                black_box(now_secs),
                black_box(params),
            ))
            .expect("verify");
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
