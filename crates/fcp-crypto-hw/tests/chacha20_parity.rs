use fcp_crypto_hw::{
    Chacha20Poly1305Backend, Chacha20Poly1305Dispatch, Chacha20Poly1305Error, HwFeatureSet,
    aead::golden_vectors,
};

#[test]
fn test_each_backend_matches_rfc8439_kat() {
    let vector = golden_vectors::vectors()
        .into_iter()
        .find(|vector| vector.name == "rfc8439-aead")
        .expect("RFC 8439 vector must exist");
    let expected = vector
        .expected_ciphertext
        .as_ref()
        .expect("RFC 8439 vector must have fixed ciphertext");

    for backend in declared_backends() {
        let sealed = Chacha20Poly1305Dispatch::with_backend(backend)
            .seal(&vector.key, &vector.nonce, &vector.plaintext, &vector.aad)
            .expect("seal should succeed");
        assert_eq!(
            sealed.as_slice(),
            expected.as_slice(),
            "backend {} diverged from RFC 8439 KAT",
            backend.as_str()
        );
        let opened = Chacha20Poly1305Dispatch::with_backend(backend)
            .open(&vector.key, &vector.nonce, &sealed, &vector.aad)
            .expect("open should succeed");
        assert_eq!(opened, vector.plaintext);
    }
}

#[test]
fn test_cross_backend_parity_random() {
    for seed in 0_u64..1000 {
        let key = fixed_array::<32>(seed ^ 0x100);
        let nonce = fixed_array::<12>(seed ^ 0x200);
        let aad = deterministic_bytes(seed ^ 0x300, usize::try_from(seed % 31).unwrap());
        let plaintext = deterministic_bytes(seed ^ 0x400, usize::try_from(seed % 2048).unwrap());

        let scalar = Chacha20Poly1305Dispatch::with_backend(Chacha20Poly1305Backend::Scalar)
            .seal(&key, &nonce, &plaintext, &aad)
            .expect("scalar seal");
        for backend in declared_backends() {
            let dispatch = Chacha20Poly1305Dispatch::with_backend(backend);
            let sealed = dispatch
                .seal(&key, &nonce, &plaintext, &aad)
                .expect("backend seal");
            assert_eq!(
                sealed,
                scalar,
                "backend {} diverged for seed {seed}",
                backend.as_str()
            );
            let opened = dispatch
                .open(&key, &nonce, &sealed, &aad)
                .expect("backend open");
            assert_eq!(opened, plaintext);
        }
    }
}

#[test]
fn test_dispatcher_selects_strongest_available() {
    let mut features = HwFeatureSet::all_false();
    assert_eq!(
        Chacha20Poly1305Dispatch::from_features(features).backend(),
        Chacha20Poly1305Backend::Scalar
    );

    features.has_sse3 = true;
    assert_eq!(
        Chacha20Poly1305Dispatch::from_features(features).backend(),
        Chacha20Poly1305Backend::X86Sse3
    );

    features.has_avx2 = true;
    assert_eq!(
        Chacha20Poly1305Dispatch::from_features(features).backend(),
        Chacha20Poly1305Backend::X86Avx2
    );
}

#[test]
fn test_fallback_when_feature_disabled() {
    let features = HwFeatureSet::all_false();
    let dispatch = Chacha20Poly1305Dispatch::from_features(features);
    assert_eq!(dispatch.backend(), Chacha20Poly1305Backend::Scalar);
}

#[test]
fn test_open_rejects_tampered_tag() {
    let vector = golden_vectors::vectors()
        .into_iter()
        .next()
        .expect("at least one vector exists");
    for backend in declared_backends() {
        let dispatch = Chacha20Poly1305Dispatch::with_backend(backend);
        let mut sealed = dispatch
            .seal(&vector.key, &vector.nonce, &vector.plaintext, &vector.aad)
            .expect("seal should succeed");
        let last = sealed.last_mut().expect("ciphertext has tag byte");
        *last ^= 0x01;
        assert_eq!(
            dispatch.open(&vector.key, &vector.nonce, &sealed, &vector.aad),
            Err(Chacha20Poly1305Error::TagMismatch)
        );
    }
}

#[test]
fn test_env_override_forces_scalar() {
    let mut features = HwFeatureSet::all_false();
    features.has_avx2 = true;
    let dispatch = Chacha20Poly1305Dispatch::from_features_with_override(features, Some("scalar"))
        .expect("scalar override should parse");
    assert_eq!(dispatch.backend(), Chacha20Poly1305Backend::Scalar);
}

#[test]
fn test_all_golden_vectors_roundtrip_on_declared_backends() {
    let vectors = golden_vectors::vectors();
    assert_eq!(vectors.len(), 32);
    for vector in vectors {
        for backend in declared_backends() {
            let dispatch = Chacha20Poly1305Dispatch::with_backend(backend);
            let sealed = dispatch
                .seal(&vector.key, &vector.nonce, &vector.plaintext, &vector.aad)
                .expect("seal should succeed");
            if let Some(expected) = &vector.expected_ciphertext {
                assert_eq!(sealed.as_slice(), expected.as_slice());
            }
            let opened = dispatch
                .open(&vector.key, &vector.nonce, &sealed, &vector.aad)
                .expect("open should succeed");
            assert_eq!(opened, vector.plaintext);
        }
    }
}

fn declared_backends() -> Vec<Chacha20Poly1305Backend> {
    vec![
        Chacha20Poly1305Backend::Scalar,
        Chacha20Poly1305Backend::X86Sse3,
        Chacha20Poly1305Backend::X86Avx2,
    ]
}

fn fixed_array<const N: usize>(seed: u64) -> [u8; N] {
    let bytes = deterministic_bytes(seed, N);
    let mut out = [0_u8; N];
    out.copy_from_slice(&bytes);
    out
}

fn deterministic_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed ^ 0xa076_1d64_78bd_642f;
    let mut bytes = Vec::with_capacity(len);
    while bytes.len() < len {
        state ^= state << 9;
        state ^= state >> 11;
        state = state.wrapping_mul(0xe703_7ed1_a0b4_28db);
        bytes.extend_from_slice(&state.to_le_bytes());
    }
    bytes.truncate(len);
    bytes
}
