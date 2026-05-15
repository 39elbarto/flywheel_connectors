use criterion::{Criterion, criterion_group, criterion_main};
use fcp_crypto_hw::{Chacha20Poly1305Backend, Chacha20Poly1305Dispatch};

fn chacha20_dispatch(c: &mut Criterion) {
    let key = [0x42_u8; 32];
    let nonce = [0x24_u8; 12];
    let aad = b"fcp-crypto-hw-bench";
    let plaintext = vec![0x11_u8; 16 * 1024];

    for backend in [
        Chacha20Poly1305Backend::Scalar,
        Chacha20Poly1305Backend::X86Sse3,
        Chacha20Poly1305Backend::X86Avx2,
    ] {
        let dispatch = Chacha20Poly1305Dispatch::with_backend(backend);
        c.bench_function(
            &format!("chacha20_poly1305_seal_{}", backend.as_str()),
            |b| {
                b.iter(|| {
                    dispatch
                        .seal(&key, &nonce, &plaintext, aad)
                        .expect("bench seal should succeed")
                });
            },
        );
    }
}

criterion_group!(benches, chacha20_dispatch);
criterion_main!(benches);
