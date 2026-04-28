use std::str::FromStr;

use fcp_core::util::ByteSize;

#[test]
fn byte_size_boundaries_roundtrip_through_display_and_from_str() {
    let cases = [
        ("1B", 1_u64),
        ("1KiB", 1024),
        ("1MiB", 1024 * 1024),
        ("1GiB", 1024 * 1024 * 1024),
    ];

    for (text, expected_bytes) in cases {
        let parsed = ByteSize::from_str(text).unwrap();
        assert_eq!(parsed.as_bytes(), expected_bytes);
        assert_eq!(parsed.to_string(), text);

        let displayed = ByteSize::from_bytes(expected_bytes).to_string();
        assert_eq!(displayed, text);

        let reparsed = ByteSize::from_str(&displayed).unwrap();
        assert_eq!(reparsed, ByteSize::from_bytes(expected_bytes));
    }
}
