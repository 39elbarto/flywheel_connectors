use fcp_core::HashAlgorithm;

#[test]
fn hash_algorithm_json_tags_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    for (algorithm, expected_json) in [
        (HashAlgorithm::Blake3_256, "\"blake3-256\""),
        (HashAlgorithm::Sha256, "\"sha256\""),
        (HashAlgorithm::Sha384, "\"sha384\""),
        (HashAlgorithm::Sha512, "\"sha512\""),
    ] {
        let encoded = serde_json::to_string(&algorithm)?;
        assert_eq!(encoded, expected_json);

        let decoded = serde_json::from_str::<HashAlgorithm>(expected_json)?;
        assert_eq!(decoded, algorithm);
        assert_eq!(decoded.as_str(), expected_json.trim_matches('"'));
    }

    Ok(())
}

#[test]
fn hash_algorithm_cbor_tags_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    for (algorithm, expected_hex) in [
        (HashAlgorithm::Blake3_256, "6a626c616b65332d323536"),
        (HashAlgorithm::Sha256, "66736861323536"),
        (HashAlgorithm::Sha384, "66736861333834"),
        (HashAlgorithm::Sha512, "66736861353132"),
    ] {
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&algorithm, &mut encoded)?;

        assert_eq!(hex::encode(&encoded), expected_hex);

        let decoded = ciborium::de::from_reader::<HashAlgorithm, _>(&encoded[..])?;
        assert_eq!(decoded, algorithm);
    }

    Ok(())
}

#[test]
fn hash_algorithm_rejects_unknown_json_tags() {
    for invalid in ["\"blake3\"", "\"sha-256\"", "\"SHA256\"", "\"md5\""] {
        assert!(
            serde_json::from_str::<HashAlgorithm>(invalid).is_err(),
            "{invalid}"
        );
    }
}
