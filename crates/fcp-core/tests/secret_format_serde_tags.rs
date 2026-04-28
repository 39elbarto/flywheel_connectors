use fcp_core::SecretFormat;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct SecretFormatCase {
    value: SecretFormat,
    json_tag: &'static str,
    cbor_tag: &'static [u8],
}

const CASES: &[SecretFormatCase] = &[
    SecretFormatCase {
        value: SecretFormat::Raw,
        json_tag: r#""raw""#,
        cbor_tag: &[0x63, b'r', b'a', b'w'],
    },
    SecretFormatCase {
        value: SecretFormat::Pem,
        json_tag: r#""pem""#,
        cbor_tag: &[0x63, b'p', b'e', b'm'],
    },
    SecretFormatCase {
        value: SecretFormat::Der,
        json_tag: r#""der""#,
        cbor_tag: &[0x63, b'd', b'e', b'r'],
    },
    SecretFormatCase {
        value: SecretFormat::Base64,
        json_tag: r#""base64""#,
        cbor_tag: &[0x66, b'b', b'a', b's', b'e', b'6', b'4'],
    },
];

#[test]
fn secret_format_json_tags_are_stable_and_roundtrip() -> TestResult {
    for case in CASES {
        let encoded = serde_json::to_string(&case.value)?;
        assert_eq!(encoded, case.json_tag);

        let decoded: SecretFormat = serde_json::from_str(case.json_tag)?;
        assert_eq!(decoded, case.value);
    }

    Ok(())
}

#[test]
fn secret_format_cbor_tags_are_stable_and_roundtrip() -> TestResult {
    for case in CASES {
        let mut encoded = Vec::new();
        ciborium::into_writer(&case.value, &mut encoded)?;
        assert_eq!(encoded.as_slice(), case.cbor_tag);

        let decoded: SecretFormat = ciborium::from_reader(case.cbor_tag)?;
        assert_eq!(decoded, case.value);

        let redecoded: SecretFormat = ciborium::from_reader(encoded.as_slice())?;
        assert_eq!(redecoded, case.value);
    }

    Ok(())
}
