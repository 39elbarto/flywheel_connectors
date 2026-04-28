use fcp_core::ManifestSignature;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct ManifestSignatureCase {
    value: ManifestSignature,
    json_tag: &'static str,
    cbor_hex: &'static str,
}

const CASES: &[ManifestSignatureCase] = &[
    ManifestSignatureCase {
        value: ManifestSignature::Ed25519,
        json_tag: r#""Ed25519""#,
        cbor_hex: "6745643235353139",
    },
    ManifestSignatureCase {
        value: ManifestSignature::RsaPss,
        json_tag: r#""RsaPss""#,
        cbor_hex: "66527361507373",
    },
    ManifestSignatureCase {
        value: ManifestSignature::EcdsaP256,
        json_tag: r#""EcdsaP256""#,
        cbor_hex: "69456364736150323536",
    },
];

#[test]
fn manifest_signature_json_tags_are_stable_and_roundtrip() -> TestResult {
    for case in CASES {
        let encoded = serde_json::to_string(&case.value)?;
        assert_eq!(encoded, case.json_tag);

        let decoded: ManifestSignature = serde_json::from_str(case.json_tag)?;
        assert_eq!(decoded, case.value);
    }

    Ok(())
}

#[test]
fn manifest_signature_cbor_tags_are_stable_and_roundtrip() -> TestResult {
    for case in CASES {
        let mut encoded = Vec::new();
        ciborium::into_writer(&case.value, &mut encoded)?;
        assert_eq!(hex::encode(&encoded), case.cbor_hex);

        let decoded: ManifestSignature = ciborium::from_reader(encoded.as_slice())?;
        assert_eq!(decoded, case.value);
    }

    Ok(())
}

#[test]
fn manifest_signature_rejects_unknown_json_tags() {
    for invalid in [
        r#""ed25519""#,
        r#""RSA-PSS""#,
        r#""EcdsaP384""#,
        r#""rsa_pss""#,
    ] {
        assert!(
            serde_json::from_str::<ManifestSignature>(invalid).is_err(),
            "{invalid}"
        );
    }
}
