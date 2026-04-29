//! Pin `HostFingerprint` Display + FromStr roundtrip and format invariants.

use std::str::FromStr;

use fcp_core::{HostFingerprint, HostFingerprintParseError};

const ZERO_FINGERPRINT: &str =
    "blake3:0000000000000000000000000000000000000000000000000000000000000000";
const MIXED_BYTES_FINGERPRINT: &str =
    "blake3:00112233445566778899aabbccddeeff102132435465768798a9babbdcdef001";
const ALL_FF_FINGERPRINT: &str =
    "blake3:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

const VALID_FINGERPRINTS: &[&str] = &[
    ZERO_FINGERPRINT,
    MIXED_BYTES_FINGERPRINT,
    ALL_FF_FINGERPRINT,
];

#[test]
fn display_emits_blake3_prefix_and_lowercase_hex_digest() {
    let fingerprint = HostFingerprint::from_digest_bytes([0xab; HostFingerprint::DIGEST_LEN]);
    let display = fingerprint.to_string();

    assert_eq!(
        display,
        format!("{}{}", HostFingerprint::PREFIX, "ab".repeat(32))
    );
    assert_eq!(display.len(), HostFingerprint::DISPLAY_LEN);
    assert!(display.starts_with(HostFingerprint::PREFIX));

    let digest = display
        .strip_prefix(HostFingerprint::PREFIX)
        .expect("Display includes prefix");
    assert_eq!(digest.len(), HostFingerprint::HEX_LEN);
    assert!(
        digest
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "HostFingerprint Display must use lowercase hex: {display}"
    );
}

#[test]
fn display_fromstr_roundtrip_preserves_bytes() {
    for input in VALID_FINGERPRINTS {
        let parsed = HostFingerprint::from_str(input).expect("valid fingerprint parses");
        let displayed = parsed.to_string();
        let reparsed = HostFingerprint::from_str(&displayed).expect("Display parses");

        assert_eq!(displayed, *input);
        assert_eq!(parsed, reparsed);
        assert_eq!(parsed.as_bytes(), reparsed.as_bytes());
    }
}

#[test]
fn parse_rejects_noncanonical_format() {
    let raw_hex_without_prefix = &ZERO_FINGERPRINT[HostFingerprint::PREFIX.len()..];
    assert!(matches!(
        HostFingerprint::from_str(raw_hex_without_prefix),
        Err(HostFingerprintParseError::MissingPrefix)
    ));
    assert!(matches!(
        HostFingerprint::from_str(
            "BLAKE3:0000000000000000000000000000000000000000000000000000000000000000"
        ),
        Err(HostFingerprintParseError::MissingPrefix)
    ));
    assert!(matches!(
        HostFingerprint::from_str(
            "blake3:000000000000000000000000000000000000000000000000000000000000000"
        ),
        Err(HostFingerprintParseError::WrongLength { actual: 63 })
    ));
    assert!(matches!(
        HostFingerprint::from_str(
            "blake3:00000000000000000000000000000000000000000000000000000000000000000"
        ),
        Err(HostFingerprintParseError::WrongLength { actual: 65 })
    ));
    assert!(matches!(
        HostFingerprint::from_str(
            "blake3:000000000000000000000000000000000000000000000000000000000000000G"
        ),
        Err(HostFingerprintParseError::UppercaseNotAllowed)
    ));
    assert!(matches!(
        HostFingerprint::from_str(
            "blake3:000000000000000000000000000000000000000000000000000000000000000g"
        ),
        Err(HostFingerprintParseError::InvalidHex)
    ));
}

#[test]
fn from_host_public_key_is_deterministic_and_key_sensitive() {
    let key_a = [0x11; 32];
    let key_b = [0x22; 32];

    let first = HostFingerprint::from_host_public_key(&key_a);
    let second = HostFingerprint::from_host_public_key(&key_a);
    let different = HostFingerprint::from_host_public_key(&key_b);

    assert_eq!(first, second);
    assert_ne!(first, different);
    assert_eq!(
        HostFingerprint::from_str(&first.to_string()).expect("Display parses"),
        first
    );
}

#[test]
fn serde_json_uses_the_display_string_form() {
    let fingerprint = HostFingerprint::from_str(MIXED_BYTES_FINGERPRINT).expect("valid");
    let json = serde_json::to_string(&fingerprint).expect("serialize");
    assert_eq!(json, format!("\"{MIXED_BYTES_FINGERPRINT}\""));

    let decoded: HostFingerprint = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded, fingerprint);
    assert_eq!(decoded.to_string(), MIXED_BYTES_FINGERPRINT);
}
