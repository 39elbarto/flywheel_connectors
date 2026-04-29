//! Pin the fcp-core symbol-store handle Display + serde surface.
//!
//! There is no literal `SymbolStoreHandle` type in fcp-core. Stored objects are
//! addressed by `ObjectId`, so this test pins the handle form operators and
//! wire consumers see when symbol-store references cross API boundaries.

use ciborium::value::Value as CborValue;
use fcp_core::ObjectId;
use std::str::FromStr;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn symbol_store_handle() -> ObjectId {
    let mut bytes = [0u8; 32];
    for (idx, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::try_from(idx).expect("idx fits in u8");
    }
    ObjectId::from_bytes(bytes)
}

#[test]
fn symbol_store_handle_display_is_bare_lowercase_hex() {
    let handle = symbol_store_handle();
    let displayed = handle.to_string();

    assert_eq!(
        displayed,
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    );
    assert_eq!(displayed.len(), 64);
    assert!(
        displayed
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && (ch.is_ascii_digit() || ch.is_ascii_lowercase())),
        "ObjectId Display must stay lowercase hex"
    );
    assert!(
        !displayed.starts_with("objectid:"),
        "Display stays bare hex; prefixed form is explicit via to_prefixed_string()"
    );
}

#[test]
fn symbol_store_handle_display_and_prefixed_forms_parse_back() {
    let handle = symbol_store_handle();

    assert_eq!(ObjectId::from_str(&handle.to_string()), Ok(handle));
    assert_eq!(ObjectId::from_str(&handle.to_prefixed_string()), Ok(handle));
}

#[test]
fn symbol_store_handle_json_serde_uses_display_hex_and_roundtrips() -> TestResult {
    let handle = symbol_store_handle();
    let json = serde_json::to_string(&handle)?;

    assert_eq!(json, format!("\"{handle}\""));

    let decoded: ObjectId = serde_json::from_str(&json)?;
    assert_eq!(decoded, handle);
    assert_eq!(decoded.to_string(), handle.to_string());

    Ok(())
}

#[test]
fn symbol_store_handle_cbor_serde_uses_bytes_and_roundtrips() -> TestResult {
    let handle = symbol_store_handle();
    let mut encoded = Vec::new();
    ciborium::into_writer(&handle, &mut encoded)?;

    let value: CborValue = ciborium::from_reader(encoded.as_slice())?;
    match value {
        CborValue::Bytes(bytes) => assert_eq!(bytes.as_slice(), handle.as_bytes().as_slice()),
        other => panic!("ObjectId must CBOR-encode as bytes, got {other:?}"),
    }

    let mut encoded_again = Vec::new();
    ciborium::into_writer(&handle, &mut encoded_again)?;
    let decoded: ObjectId = ciborium::from_reader(encoded_again.as_slice())?;
    assert_eq!(decoded, handle);
    assert_eq!(decoded.to_string(), handle.to_string());

    Ok(())
}
