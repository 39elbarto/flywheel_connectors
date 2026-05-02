use criterion::{Criterion, criterion_group, criterion_main};
use fcp_bootstrap::hardware_token::{
    CertificateSelectionIndex, TokenCertificate, TokenKeyInfo, TokenKeyType,
};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair};
use time::{Duration as TimeDuration, OffsetDateTime};

const LOOKUP_SIZES: [usize; 4] = [10, 100, 1_000, 10_000];

fn build_workload(size: usize) -> (Vec<TokenCertificate>, Vec<TokenKeyInfo>) {
    assert!(size >= 2, "workload needs a leaf and CA certificate");

    let now = OffsetDateTime::now_utc();
    let mut issuer_params =
        CertificateParams::new(Vec::<String>::new()).expect("issuer params are valid");
    issuer_params.not_before = now - TimeDuration::days(60);
    issuer_params.not_after = now + TimeDuration::days(60);
    issuer_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    issuer_params
        .distinguished_name
        .push(DnType::CommonName, "Benchmark CA");

    let issuer_key = KeyPair::generate().expect("issuer key generation succeeds");
    let issuer = CertifiedIssuer::self_signed(issuer_params, issuer_key)
        .expect("self-signed benchmark CA is valid");

    let mut leaf_params =
        CertificateParams::new(Vec::<String>::new()).expect("leaf params are valid");
    leaf_params.not_before = now - TimeDuration::days(7);
    leaf_params.not_after = now + TimeDuration::days(7);
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "selected-leaf");
    let leaf_key = KeyPair::generate().expect("leaf key generation succeeds");
    let leaf = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("leaf certificate signs successfully");

    let selected = TokenCertificate {
        label: "selected-leaf".to_string(),
        id: vec![1],
        der_bytes: leaf.der().to_vec(),
        subject: "CN=selected-leaf".to_string(),
        issuer: "CN=Benchmark CA".to_string(),
        is_ca: false,
    };
    let ca = TokenCertificate {
        label: "Benchmark CA".to_string(),
        id: vec![9],
        der_bytes: issuer.der().to_vec(),
        subject: "CN=Benchmark CA".to_string(),
        issuer: "CN=Benchmark CA".to_string(),
        is_ca: true,
    };
    let mut certs = Vec::with_capacity(size);
    certs.push(selected.clone());
    certs.push(ca);

    for index in 2..size {
        let mut noise = selected.clone();
        noise.label = format!("noise-cert-{index:05}");
        noise.id = index.to_be_bytes().to_vec();
        certs.push(noise);
    }

    let keys = vec![TokenKeyInfo {
        label: "selected-key".to_string(),
        id: vec![1],
        key_type: TokenKeyType::Ed25519,
        can_sign: true,
        can_derive: false,
    }];

    (certs, keys)
}

fn certificate_selection_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("certificate_selection_lookup");
    for size in LOOKUP_SIZES {
        let (certs, keys) = build_workload(size);
        let index = CertificateSelectionIndex::new(&certs, &keys);
        group.bench_function(format!("size_{size}"), |b| {
            b.iter(|| {
                std::hint::black_box(
                    index
                        .select_for_provisioning()
                        .expect("indexed lookup succeeds"),
                );
            });
        });
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .warm_up_time(std::time::Duration::from_millis(100))
        .measurement_time(std::time::Duration::from_millis(500));
    targets = certificate_selection_lookup
}
criterion_main!(benches);
