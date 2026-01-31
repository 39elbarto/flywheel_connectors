//! Benchmarks for fcp-crypto hot paths.
//!
//! These benchmarks verify performance of the critical cryptographic operations:
//! - Ed25519 signing and verification (capability tokens, attestations)
//! - X25519 key exchange (session establishment)
//! - BLAKE3 keyed MAC (session frame authentication)
//! - ChaCha20-Poly1305 AEAD (symmetric encryption)
//! - HPKE seal/open (zone key distribution)
//! - COSE token signing/verification (capability tokens)

use chrono::{Duration, Utc};
use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use fcp_crypto::{
    AeadKey, ChaCha20Nonce, Ed25519SigningKey, Fcp2Aad, MacKey, X25519SecretKey, blake3_mac,
    blake3_mac_verify, chacha20_decrypt, chacha20_encrypt, cose::CapabilityTokenBuilder, hpke_open,
    hpke_seal,
};

// ============================================================================
// Ed25519 Benchmarks
// ============================================================================

fn bench_ed25519_sign(c: &mut Criterion) {
    let signing_key = Ed25519SigningKey::generate();
    let message = b"This is a test message for signing benchmarks";

    c.bench_function("ed25519_sign", |b| {
        b.iter(|| {
            let _ = signing_key.sign(black_box(message));
        });
    });
}

fn bench_ed25519_verify(c: &mut Criterion) {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let message = b"This is a test message for signing benchmarks";
    let signature = signing_key.sign(message);

    c.bench_function("ed25519_verify", |b| {
        b.iter(|| {
            let _ = verifying_key.verify(black_box(message), black_box(&signature));
        });
    });
}

fn bench_ed25519_keygen(c: &mut Criterion) {
    c.bench_function("ed25519_keygen", |b| {
        b.iter(|| {
            let _ = Ed25519SigningKey::generate();
        });
    });
}

// ============================================================================
// X25519 Benchmarks
// ============================================================================

fn bench_x25519_keygen(c: &mut Criterion) {
    c.bench_function("x25519_keygen", |b| {
        b.iter(|| {
            let _ = X25519SecretKey::generate();
        });
    });
}

fn bench_x25519_dh(c: &mut Criterion) {
    let alice_secret = X25519SecretKey::generate();
    let bob_secret = X25519SecretKey::generate();
    let bob_public = bob_secret.public_key();

    c.bench_function("x25519_dh", |b| {
        b.iter(|| {
            let _ = alice_secret.diffie_hellman(black_box(&bob_public));
        });
    });
}

// ============================================================================
// BLAKE3 MAC Benchmarks
// ============================================================================

fn bench_blake3_mac_32b(c: &mut Criterion) {
    let key = MacKey::from_bytes([0xABu8; 32]);
    let data = [0u8; 32];

    c.bench_function("blake3_mac_32b", |b| {
        b.iter(|| {
            let _ = blake3_mac(black_box(&key), black_box(&data));
        });
    });
}

fn bench_blake3_mac_1kb(c: &mut Criterion) {
    let key = MacKey::from_bytes([0xABu8; 32]);
    let data = vec![0u8; 1024];

    let mut group = c.benchmark_group("blake3_mac");
    group.throughput(Throughput::Bytes(1024));
    group.bench_function("blake3_mac_1kb", |b| {
        b.iter(|| {
            let _ = blake3_mac(black_box(&key), black_box(&data));
        });
    });
    group.finish();
}

fn bench_blake3_mac_64kb(c: &mut Criterion) {
    let key = MacKey::from_bytes([0xABu8; 32]);
    let data = vec![0u8; 65_536];

    let mut group = c.benchmark_group("blake3_mac_large");
    group.throughput(Throughput::Bytes(65_536));
    group.bench_function("blake3_mac_64kb", |b| {
        b.iter(|| {
            let _ = blake3_mac(black_box(&key), black_box(&data));
        });
    });
    group.finish();
}

fn bench_blake3_mac_verify(c: &mut Criterion) {
    let key = MacKey::from_bytes([0xABu8; 32]);
    let data = vec![0u8; 1024];
    let mac = blake3_mac(&key, &data);

    c.bench_function("blake3_mac_verify_1kb", |b| {
        b.iter(|| {
            let _ = blake3_mac_verify(black_box(&key), black_box(&data), black_box(&mac));
        });
    });
}

// ============================================================================
// ChaCha20-Poly1305 AEAD Benchmarks
// ============================================================================

fn bench_chacha20_encrypt_1kb(c: &mut Criterion) {
    let key = AeadKey::from_bytes([0xABu8; 32]);
    let nonce = ChaCha20Nonce::from_bytes([0u8; 12]);
    let plaintext = vec![0u8; 1024];
    let aad = b"additional authenticated data";

    let mut group = c.benchmark_group("chacha20_aead");
    group.throughput(Throughput::Bytes(1024));
    group.bench_function("chacha20_encrypt_1kb", |b| {
        b.iter(|| {
            let _ = chacha20_encrypt(
                black_box(&key),
                black_box(&nonce),
                black_box(&plaintext),
                black_box(aad),
            );
        });
    });
    group.finish();
}

fn bench_chacha20_decrypt_1kb(c: &mut Criterion) {
    let key = AeadKey::from_bytes([0xABu8; 32]);
    let nonce = ChaCha20Nonce::from_bytes([0u8; 12]);
    let plaintext = vec![0u8; 1024];
    let aad = b"additional authenticated data";
    let ciphertext = chacha20_encrypt(&key, &nonce, &plaintext, aad).unwrap();

    let mut group = c.benchmark_group("chacha20_aead_decrypt");
    group.throughput(Throughput::Bytes(1024));
    group.bench_function("chacha20_decrypt_1kb", |b| {
        b.iter(|| {
            let _ = chacha20_decrypt(
                black_box(&key),
                black_box(&nonce),
                black_box(&ciphertext),
                black_box(aad),
            );
        });
    });
    group.finish();
}

fn bench_chacha20_encrypt_64kb(c: &mut Criterion) {
    let key = AeadKey::from_bytes([0xABu8; 32]);
    let nonce = ChaCha20Nonce::from_bytes([0u8; 12]);
    let plaintext = vec![0u8; 65_536];
    let aad = b"additional authenticated data";

    let mut group = c.benchmark_group("chacha20_aead_large");
    group.throughput(Throughput::Bytes(65_536));
    group.bench_function("chacha20_encrypt_64kb", |b| {
        b.iter(|| {
            let _ = chacha20_encrypt(
                black_box(&key),
                black_box(&nonce),
                black_box(&plaintext),
                black_box(aad),
            );
        });
    });
    group.finish();
}

// ============================================================================
// HPKE Benchmarks
// ============================================================================

fn bench_hpke_seal(c: &mut Criterion) {
    let recipient_secret = X25519SecretKey::generate();
    let recipient_public = recipient_secret.public_key();
    let plaintext = b"secret zone key material for distribution";
    let aad = Fcp2Aad::for_zone_key(b"z:work", b"node-123", 1_234_567_890);

    c.bench_function("hpke_seal", |b| {
        b.iter(|| {
            let _ = hpke_seal(
                black_box(&recipient_public),
                black_box(plaintext),
                black_box(&aad),
            );
        });
    });
}

fn bench_hpke_open(c: &mut Criterion) {
    let recipient_secret = X25519SecretKey::generate();
    let recipient_public = recipient_secret.public_key();
    let plaintext = b"secret zone key material for distribution";
    let aad = Fcp2Aad::for_zone_key(b"z:work", b"node-123", 1_234_567_890);
    let sealed = hpke_seal(&recipient_public, plaintext, &aad).unwrap();

    c.bench_function("hpke_open", |b| {
        b.iter(|| {
            let _ = hpke_open(
                black_box(&recipient_secret),
                black_box(&sealed),
                black_box(&aad),
            );
        });
    });
}

// ============================================================================
// COSE Token Benchmarks
// ============================================================================

fn bench_cose_token_sign(c: &mut Criterion) {
    let issuance_key = Ed25519SigningKey::generate();
    let now = Utc::now();
    let exp = now + Duration::hours(24);

    c.bench_function("cose_token_sign", |b| {
        b.iter(|| {
            let _ = CapabilityTokenBuilder::new()
                .capability_id("cap:discord.send")
                .zone_id("z:work")
                .principal("agent:claude")
                .operations(&["discord.send_message"])
                .issuer("node:primary")
                .validity(now, exp)
                .sign(black_box(&issuance_key));
        });
    });
}

fn bench_cose_token_verify(c: &mut Criterion) {
    let issuance_key = Ed25519SigningKey::generate();
    let verifying_key = issuance_key.verifying_key();
    let now = Utc::now();
    let exp = now + Duration::hours(24);

    let token = CapabilityTokenBuilder::new()
        .capability_id("cap:discord.send")
        .zone_id("z:work")
        .principal("agent:claude")
        .operations(&["discord.send_message"])
        .issuer("node:primary")
        .validity(now, exp)
        .sign(&issuance_key)
        .unwrap();

    c.bench_function("cose_token_verify", |b| {
        b.iter(|| {
            let _ = token.verify(black_box(&verifying_key));
        });
    });
}

// ============================================================================
// Criterion Groups
// ============================================================================

criterion_group!(
    ed25519_benches,
    bench_ed25519_sign,
    bench_ed25519_verify,
    bench_ed25519_keygen,
);

criterion_group!(x25519_benches, bench_x25519_keygen, bench_x25519_dh,);

criterion_group!(
    blake3_benches,
    bench_blake3_mac_32b,
    bench_blake3_mac_1kb,
    bench_blake3_mac_64kb,
    bench_blake3_mac_verify,
);

criterion_group!(
    aead_benches,
    bench_chacha20_encrypt_1kb,
    bench_chacha20_decrypt_1kb,
    bench_chacha20_encrypt_64kb,
);

criterion_group!(hpke_benches, bench_hpke_seal, bench_hpke_open,);

criterion_group!(cose_benches, bench_cose_token_sign, bench_cose_token_verify,);

criterion_main!(
    ed25519_benches,
    x25519_benches,
    blake3_benches,
    aead_benches,
    hpke_benches,
    cose_benches,
);
