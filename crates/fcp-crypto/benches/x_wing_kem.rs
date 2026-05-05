//! Criterion benchmarks for the FCP V4 X-Wing KEM path.

use core::convert::Infallible;
use std::{hint::black_box, time::Duration};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use fcp_crypto::{
    Fcp2Aad, Fcp4Aad, X25519SecretKey, XWING_SECRET_KEY_SIZE, XWingKem, XWingProvider, hpke_open,
    hpke_seal,
};
use rand_core_pq::{TryCryptoRng, TryRng};
use x_wing::{
    Decapsulate, DecapsulationKey as XWingDecapsulationKey, Encapsulate,
    EncapsulationKey as XWingEncapsulationKey,
};

struct BenchRng;

impl TryRng for BenchRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        getrandom::fill(dst).expect("OS RNG must be available for X-Wing benchmarks");
        Ok(())
    }
}

impl TryCryptoRng for BenchRng {}

fn real_x_wing_keys(
    provider: XWingProvider,
) -> (
    fcp_crypto::XWingPublicKey,
    fcp_crypto::XWingSecretKey,
    XWingEncapsulationKey,
    XWingDecapsulationKey,
) {
    let (pk, sk) = provider.generate().expect("X-Wing keygen must succeed");
    let upstream_encapsulation_key = XWingEncapsulationKey::try_from(pk.as_bytes())
        .expect("FCP X-Wing public key must parse as upstream key");
    let sk_seed: [u8; XWING_SECRET_KEY_SIZE] = sk
        .as_bytes()
        .try_into()
        .expect("FCP X-Wing secret key is a 32-byte seed");
    let upstream_decapsulation_key = XWingDecapsulationKey::from(sk_seed);
    (
        pk,
        sk,
        upstream_encapsulation_key,
        upstream_decapsulation_key,
    )
}

fn x_wing_kem_benchmarks(c: &mut Criterion) {
    let provider = XWingProvider::new();
    let (pk, sk, upstream_encapsulation_key, upstream_decapsulation_key) =
        real_x_wing_keys(provider);
    let mut rng = BenchRng;
    let (ct, _ss) = upstream_encapsulation_key.encapsulate_with_rng(&mut rng);
    let aad = Fcp4Aad::for_zone_key(b"z:work", b"node-7", 1_700_000_000)
        .encode()
        .expect("FCP4 AAD must encode");
    let small_payload = [0xA5u8; 32];
    let small_sealed = provider
        .seal(&pk, &small_payload, &aad)
        .expect("X-Wing seal must succeed");

    {
        let mut group = c.benchmark_group("x_wing_kem");
        group.sample_size(20);
        group.warm_up_time(Duration::from_secs(1));
        group.measurement_time(Duration::from_secs(3));

        group.bench_function("keygen", |b| {
            b.iter(|| {
                let _ = black_box(provider.generate().expect("X-Wing keygen must succeed"));
            });
        });

        group.bench_function("encap", |b| {
            b.iter(|| {
                let mut rng = BenchRng;
                let _ = black_box(upstream_encapsulation_key.encapsulate_with_rng(&mut rng));
            });
        });

        group.bench_function("decap", |b| {
            b.iter(|| {
                let _ = black_box(upstream_decapsulation_key.decapsulate(black_box(&ct)));
            });
        });

        group.bench_function("seal_32b", |b| {
            b.iter(|| {
                let _ = black_box(
                    provider
                        .seal(black_box(&pk), black_box(&small_payload), black_box(&aad))
                        .expect("X-Wing seal must succeed"),
                );
            });
        });

        group.bench_function("open_32b", |b| {
            b.iter(|| {
                let _ = black_box(
                    provider
                        .open(black_box(&sk), black_box(&small_sealed), black_box(&aad))
                        .expect("X-Wing open must succeed"),
                );
            });
        });

        group.bench_function("round_trip_32b", |b| {
            b.iter(|| {
                let sealed = provider
                    .seal(black_box(&pk), black_box(&small_payload), black_box(&aad))
                    .expect("X-Wing seal must succeed");
                let opened = provider
                    .open(black_box(&sk), black_box(&sealed), black_box(&aad))
                    .expect("X-Wing open must succeed");
                black_box(opened);
            });
        });

        group.finish();
    }

    let mut payload_group = c.benchmark_group("x_wing_kem_payload");
    payload_group.sample_size(20);
    payload_group.warm_up_time(Duration::from_secs(1));
    payload_group.measurement_time(Duration::from_secs(3));
    payload_group.throughput(Throughput::Bytes(1024));

    let large_payload = vec![0x5Au8; 1024];
    let large_sealed = provider
        .seal(&pk, &large_payload, &aad)
        .expect("X-Wing seal must succeed");

    payload_group.bench_function("seal_1kb", |b| {
        b.iter(|| {
            let _ = black_box(
                provider
                    .seal(black_box(&pk), black_box(&large_payload), black_box(&aad))
                    .expect("X-Wing seal must succeed"),
            );
        });
    });

    payload_group.bench_function("open_1kb", |b| {
        b.iter(|| {
            let _ = black_box(
                provider
                    .open(black_box(&sk), black_box(&large_sealed), black_box(&aad))
                    .expect("X-Wing open must succeed"),
            );
        });
    });

    payload_group.finish();
}

fn x_wing_baseline_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("x_wing_kem_baseline");
    group.sample_size(20);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));

    let alice_secret = X25519SecretKey::generate();
    let bob_secret = X25519SecretKey::generate();
    let bob_public = bob_secret.public_key();

    group.bench_function("vanilla_x25519_keygen", |b| {
        b.iter(|| {
            let _ = black_box(X25519SecretKey::generate());
        });
    });

    group.bench_function("vanilla_x25519_dh", |b| {
        b.iter(|| {
            let _ = black_box(
                alice_secret
                    .diffie_hellman(black_box(&bob_public))
                    .expect("X25519 DH must succeed"),
            );
        });
    });

    let recipient_secret = X25519SecretKey::generate();
    let recipient_public = recipient_secret.public_key();
    let aad = Fcp2Aad::for_zone_key(b"z:work", b"node-7", 1_700_000_000);
    let payload = [0xA5u8; 32];
    let sealed = hpke_seal(&recipient_public, &payload, &aad).expect("HPKE seal must succeed");

    group.bench_function("hpke_x25519_seal_32b", |b| {
        b.iter(|| {
            let _ = black_box(
                hpke_seal(
                    black_box(&recipient_public),
                    black_box(&payload),
                    black_box(&aad),
                )
                .expect("HPKE seal must succeed"),
            );
        });
    });

    group.bench_function("hpke_x25519_open_32b", |b| {
        b.iter(|| {
            let _ = black_box(
                hpke_open(
                    black_box(&recipient_secret),
                    black_box(&sealed),
                    black_box(&aad),
                )
                .expect("HPKE open must succeed"),
            );
        });
    });

    group.finish();
}

criterion_group!(benches, x_wing_kem_benchmarks, x_wing_baseline_benchmarks);
criterion_main!(benches);
