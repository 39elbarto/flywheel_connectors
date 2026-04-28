use ciborium::value::Value;
use fcp_cbor::to_canonical_cbor;

fn assert_bool_simple_value(
    value: bool,
    expected_hex: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let encoded = to_canonical_cbor(&value)?;

    assert_eq!(
        hex::encode(&encoded),
        expected_hex,
        "bool value {value} did not use the expected single-byte CBOR simple-value encoding",
    );

    let decoded: bool = ciborium::de::from_reader(encoded.as_slice())?;
    assert_eq!(decoded, value);

    Ok(())
}

#[test]
fn simple_value_true_encodes_as_f5() -> Result<(), Box<dyn std::error::Error>> {
    assert_bool_simple_value(true, "f5")
}

#[test]
fn simple_value_false_encodes_as_f4() -> Result<(), Box<dyn std::error::Error>> {
    assert_bool_simple_value(false, "f4")
}

#[test]
fn simple_value_null_encodes_as_f6() -> Result<(), Box<dyn std::error::Error>> {
    let encoded = to_canonical_cbor(&Option::<u8>::None)?;

    assert_eq!(
        hex::encode(&encoded),
        "f6",
        "null did not use the expected single-byte CBOR simple-value encoding",
    );

    let decoded: Option<u8> = ciborium::de::from_reader(encoded.as_slice())?;
    assert_eq!(decoded, None);

    let decoded_value: Value = ciborium::de::from_reader(encoded.as_slice())?;
    assert_eq!(decoded_value, Value::Null);

    Ok(())
}

#[test]
fn simple_value_undefined_decodes_from_f7() -> Result<(), Box<dyn std::error::Error>> {
    let encoded = hex::decode("f7")?;

    assert_eq!(
        hex::encode(&encoded),
        "f7",
        "undefined did not use the expected single-byte CBOR simple-value encoding",
    );

    let decoded: Option<u8> = ciborium::de::from_reader(encoded.as_slice())?;
    assert_eq!(decoded, None);

    let decoded_value: Value = ciborium::de::from_reader(encoded.as_slice())?;
    assert_eq!(decoded_value, Value::Null);

    Ok(())
}
