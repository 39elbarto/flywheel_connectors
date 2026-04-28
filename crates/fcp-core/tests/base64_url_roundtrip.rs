use base64::{Engine as _, engine::general_purpose::STANDARD};
use fcp_core::util::base64_url;

fn bytes_for_len(len: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(len);
    for index in 0..len {
        bytes.push(index.wrapping_mul(73).wrapping_add(len) as u8);
    }

    if len >= 1 {
        bytes[0] = 0xfb;
    }
    if len >= 2 {
        bytes[1] = 0xff;
    }
    if len >= 3 {
        bytes[2] = 0xff;
    }

    bytes
}

fn assert_url_safe_base64_roundtrip(len: usize) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = bytes_for_len(len);
    let encoded = base64_url::encode(&bytes);
    let standard = STANDARD.encode(&bytes);
    let expected_url_safe = standard
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_");

    assert_eq!(encoded, expected_url_safe);
    assert!(!encoded.contains('+'));
    assert!(!encoded.contains('/'));

    if standard.contains('+') {
        assert!(encoded.contains('-'));
    }
    if standard.contains('/') {
        assert!(encoded.contains('_'));
    }

    let decoded = base64_url::decode(&encoded)?;
    assert_eq!(decoded, bytes);

    Ok(())
}

#[test]
fn base64_url_roundtrip_empty_byte_array() -> Result<(), Box<dyn std::error::Error>> {
    assert_url_safe_base64_roundtrip(0)
}

#[test]
fn base64_url_roundtrip_one_byte_array() -> Result<(), Box<dyn std::error::Error>> {
    assert_url_safe_base64_roundtrip(1)
}

#[test]
fn base64_url_roundtrip_two_byte_array() -> Result<(), Box<dyn std::error::Error>> {
    assert_url_safe_base64_roundtrip(2)
}

#[test]
fn base64_url_roundtrip_three_byte_array() -> Result<(), Box<dyn std::error::Error>> {
    assert_url_safe_base64_roundtrip(3)
}

#[test]
fn base64_url_roundtrip_256_byte_array() -> Result<(), Box<dyn std::error::Error>> {
    assert_url_safe_base64_roundtrip(256)
}

#[test]
fn base64_url_roundtrip_1024_byte_array() -> Result<(), Box<dyn std::error::Error>> {
    assert_url_safe_base64_roundtrip(1_024)
}
