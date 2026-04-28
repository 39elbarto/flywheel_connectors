use fcp_core::ObjectId;

const OBJECT_ID_HASH_BYTES: usize = 32;

#[test]
fn same_input_bytes_produce_identical_content_address_hash() {
    let content = b"fcp-core content-addressing determinism vector";
    let expected = ObjectId::from_unscoped_bytes(content);

    for _ in 0..32 {
        assert_eq!(ObjectId::from_unscoped_bytes(content), expected);
    }
}

#[test]
fn one_byte_perturbation_changes_content_address_hash() {
    let content = b"fcp-core content-addressing perturbation vector";
    let mut perturbed = content.to_vec();
    let last_index = perturbed.len() - 1;
    perturbed[last_index] ^= 0x01;

    let original_hash = ObjectId::from_unscoped_bytes(content);
    let perturbed_hash = ObjectId::from_unscoped_bytes(&perturbed);

    assert_ne!(original_hash, perturbed_hash);
}

#[test]
fn content_address_hash_is_fixed_length() {
    let large_content = [0xA5_u8; 4096];
    let cases: [&[u8]; 5] = [
        b"",
        b"a",
        b"short content",
        b"fcp-core content-addressing fixed-length vector",
        &large_content,
    ];

    for content in cases {
        let object_id = ObjectId::from_unscoped_bytes(content);

        assert_eq!(object_id.as_bytes().len(), OBJECT_ID_HASH_BYTES);
    }
}
