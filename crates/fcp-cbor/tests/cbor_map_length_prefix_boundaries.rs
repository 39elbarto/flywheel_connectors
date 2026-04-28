use std::collections::BTreeMap;

use fcp_cbor::to_canonical_cbor;

fn map_with_entries(len: usize) -> Result<BTreeMap<u32, u32>, std::num::TryFromIntError> {
    (0..len)
        .map(|index| {
            let key = u32::try_from(index)?;
            Ok((key, key.wrapping_mul(3).wrapping_add(1)))
        })
        .collect()
}

fn assert_map_length_prefix_boundary(
    len: usize,
    expected_prefix_hex: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let value = map_with_entries(len)?;
    let encoded = to_canonical_cbor(&value)?;
    let prefix_len = expected_prefix_hex.len() / 2;

    assert_eq!(
        hex::encode(&encoded[..prefix_len]),
        expected_prefix_hex,
        "map length {len} did not use the expected CBOR length-prefix bytes",
    );

    let decoded: BTreeMap<u32, u32> = ciborium::de::from_reader(encoded.as_slice())?;
    assert_eq!(
        decoded, value,
        "map length {len} did not roundtrip from CBOR"
    );

    Ok(())
}

#[test]
fn map_length_prefix_boundary_0() -> Result<(), Box<dyn std::error::Error>> {
    assert_map_length_prefix_boundary(0, "a0")
}

#[test]
fn map_length_prefix_boundary_23() -> Result<(), Box<dyn std::error::Error>> {
    assert_map_length_prefix_boundary(23, "b7")
}

#[test]
fn map_length_prefix_boundary_24() -> Result<(), Box<dyn std::error::Error>> {
    assert_map_length_prefix_boundary(24, "b818")
}

#[test]
fn map_length_prefix_boundary_255() -> Result<(), Box<dyn std::error::Error>> {
    assert_map_length_prefix_boundary(255, "b8ff")
}

#[test]
fn map_length_prefix_boundary_256() -> Result<(), Box<dyn std::error::Error>> {
    assert_map_length_prefix_boundary(256, "b90100")
}

#[test]
fn map_length_prefix_boundary_65535() -> Result<(), Box<dyn std::error::Error>> {
    assert_map_length_prefix_boundary(65_535, "b9ffff")
}

#[test]
fn map_length_prefix_boundary_65536() -> Result<(), Box<dyn std::error::Error>> {
    assert_map_length_prefix_boundary(65_536, "ba00010000")
}
