use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use fcp_core::pem::{
    ED25519_PUBLIC_KEY_PEM_LABEL, FROST_PUBLIC_KEY_PACKAGE_PEM_LABEL, PEM_LINE_WRAP, PemBlock,
    X25519_PUBLIC_KEY_PEM_LABEL, parse_pem,
};
use fcp_crypto::{
    Ed25519SigningKey, Ed25519VerifyingKey, FrostDkgRound2Package, FrostPublicKeyPackage,
    X25519PublicKey, X25519SecretKey, dkg_part1, dkg_part2, dkg_part3,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn body_lines(pem: &str) -> Vec<&str> {
    pem.lines()
        .filter(|line| !line.starts_with("-----BEGIN ") && !line.starts_with("-----END "))
        .collect()
}

fn assert_pem_shape(pem: &str, label: &str, body: &[u8]) -> TestResult {
    let lines: Vec<&str> = pem.lines().collect();
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    assert_eq!(lines.first().copied(), Some(begin.as_str()));
    assert_eq!(lines.last().copied(), Some(end.as_str()));

    let body_lines = body_lines(pem);
    assert!(!body_lines.is_empty(), "PEM body must contain base64 data");
    assert!(
        body_lines[..body_lines.len() - 1]
            .iter()
            .all(|line| line.len() == PEM_LINE_WRAP),
        "all complete PEM body lines must be 64 characters"
    );
    assert!(
        body_lines
            .last()
            .is_some_and(|line| !line.is_empty() && line.len() <= PEM_LINE_WRAP),
        "final PEM body line must be nonempty and no wider than 64 characters"
    );
    assert_eq!(STANDARD.decode(body_lines.concat())?, body);

    Ok(())
}

fn assert_public_key_pem_roundtrip(label: &str, body: &[u8]) -> TestResult<PemBlock> {
    let pem = PemBlock::new(label, body)?.to_pem();

    assert_pem_shape(&pem, label, body)?;

    let parsed = parse_pem(&pem)?;
    assert_eq!(parsed.label(), label);
    assert_eq!(parsed.body(), body);
    assert_eq!(parsed.to_pem(), pem);

    Ok(parsed)
}

#[test]
fn ed25519_public_key_pem_roundtrips() -> TestResult {
    let public_key = Ed25519SigningKey::from_bytes(&[0x2a; 32])?.verifying_key();
    let parsed = assert_public_key_pem_roundtrip(
        ED25519_PUBLIC_KEY_PEM_LABEL,
        public_key.to_bytes().as_slice(),
    )?;
    let parsed_bytes = parsed.body().try_into()?;
    let reparsed_public_key = Ed25519VerifyingKey::from_bytes(&parsed_bytes)?;

    assert_eq!(reparsed_public_key, public_key);

    Ok(())
}

#[test]
fn x25519_public_key_pem_roundtrips() -> TestResult {
    let public_key = X25519SecretKey::from_bytes([0x17; 32]).public_key();
    let parsed =
        assert_public_key_pem_roundtrip(X25519_PUBLIC_KEY_PEM_LABEL, &public_key.to_bytes())?;
    let reparsed_public_key = X25519PublicKey::try_from_slice(parsed.body())?;

    assert_eq!(reparsed_public_key, public_key);

    Ok(())
}

#[test]
fn frost_public_key_package_pem_wraps_body_at_64_columns() -> TestResult {
    let public_key_package = frost_public_key_package()?;
    let mut body = Vec::new();
    ciborium::into_writer(&public_key_package, &mut body)?;
    let pem = PemBlock::new(FROST_PUBLIC_KEY_PACKAGE_PEM_LABEL, body.as_slice())?.to_pem();
    let lines = body_lines(&pem);

    assert_pem_shape(&pem, FROST_PUBLIC_KEY_PACKAGE_PEM_LABEL, body.as_slice())?;
    assert!(
        lines.len() > 1,
        "test vector must force multiple base64 body lines"
    );

    let parsed = parse_pem(&pem)?;
    let reparsed_public_key_package: FrostPublicKeyPackage = ciborium::from_reader(parsed.body())?;

    assert_eq!(reparsed_public_key_package, public_key_package);
    assert_eq!(parsed.to_pem(), pem);

    Ok(())
}

fn frost_public_key_package() -> TestResult<FrostPublicKeyPackage> {
    let min_signers = 2u16;
    let max_signers = 3u16;
    let mut round1_secrets = BTreeMap::new();
    let mut round1_public = BTreeMap::new();

    for participant in 1..=max_signers {
        let (secret, package) = dkg_part1(participant, max_signers, min_signers)?;
        round1_secrets.insert(participant, secret);
        round1_public.insert(participant, package);
    }

    let mut round2_secrets = BTreeMap::new();
    let mut inbound_round2: BTreeMap<u16, BTreeMap<u16, FrostDkgRound2Package>> = BTreeMap::new();

    for participant in 1..=max_signers {
        let received_round1 = round1_public
            .iter()
            .filter(|(sender, _)| **sender != participant)
            .map(|(sender, package)| (*sender, package.clone()))
            .collect();
        let (secret, outbound_round2) = dkg_part2(&round1_secrets[&participant], &received_round1)?;

        round2_secrets.insert(participant, secret);
        for (recipient, package) in outbound_round2 {
            inbound_round2
                .entry(recipient)
                .or_default()
                .insert(participant, package);
        }
    }

    let mut public_key_package = None;
    for participant in 1..=max_signers {
        let received_round1 = round1_public
            .iter()
            .filter(|(sender, _)| **sender != participant)
            .map(|(sender, package)| (*sender, package.clone()))
            .collect();
        let (_, package) = dkg_part3(
            &round2_secrets[&participant],
            &received_round1,
            &inbound_round2[&participant],
        )?;
        public_key_package = Some(package);
    }

    public_key_package.ok_or_else(|| "FROST DKG must produce a public key package".into())
}
