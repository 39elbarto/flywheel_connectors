use std::str::FromStr;

use fcp_core::{ObjectId, ObjectIdParseError};

fn provenance_id(label: &str) -> ObjectId {
    ObjectId::from_unscoped_bytes(label.as_bytes())
}

#[test]
fn provenance_object_id_display_then_fromstr_roundtrips() {
    for id in [
        provenance_id("owner-origin-provenance"),
        provenance_id("public-taint-provenance"),
        provenance_id("approval-elevation-provenance"),
        ObjectId::from_bytes([0xab; 32]),
    ] {
        let display = id.to_string();

        assert_eq!(display.len(), 64);
        assert!(display.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(ObjectId::from_str(&display), Ok(id));
    }
}

#[test]
fn provenance_object_id_prefixed_form_parses_to_same_value() {
    let id = provenance_id("sanitizer-receipt-provenance");

    let from_display = ObjectId::from_str(&id.to_string()).expect("display form parses");
    let from_prefixed =
        ObjectId::from_str(&id.to_prefixed_string()).expect("objectid-prefixed form parses");

    assert_eq!(from_display, id);
    assert_eq!(from_prefixed, id);
    assert_eq!(from_display, from_prefixed);
}

#[test]
fn provenance_object_id_equality_survives_construction_paths() {
    let bytes = [0x42; 32];
    let from_bytes = ObjectId::from_bytes(bytes);
    let from_display = ObjectId::from_str(&from_bytes.to_string()).expect("display form parses");
    let from_prefixed =
        ObjectId::from_str(&from_bytes.to_prefixed_string()).expect("prefixed form parses");

    assert_eq!(from_bytes, from_display);
    assert_eq!(from_bytes, from_prefixed);
    assert_eq!(from_bytes.as_bytes(), &bytes);
}

#[test]
fn provenance_object_id_fromstr_rejects_invalid_inputs() {
    assert_eq!(
        ObjectId::from_str("objectid:gg"),
        Err(ObjectIdParseError::InvalidHex)
    );
    assert_eq!(
        ObjectId::from_str("objectid:aabb"),
        Err(ObjectIdParseError::WrongLength { actual: 2 })
    );
}
