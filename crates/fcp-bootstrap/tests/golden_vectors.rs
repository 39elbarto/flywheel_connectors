//! Golden vector tests for FCP2 bootstrap.
//!
//! These tests verify that bootstrap outputs match expected golden vectors,
//! ensuring determinism and backwards compatibility.

use fcp_bootstrap::{
    EncryptedShare, FrostCommitment, GenesisState, ParticipantId, RecoveryPhrase, ThresholdCeremony,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

/// Well-known test mnemonic (DO NOT USE FOR REAL KEYS).
const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

/// Expected fingerprint for the test mnemonic (deterministic genesis).
const EXPECTED_FINGERPRINT: &str = include_str!("vectors/expected_fingerprint.txt");

/// Expected genesis CBOR for the test mnemonic.
const EXPECTED_GENESIS_CBOR: &[u8] = include_bytes!("vectors/genesis.cbor");

/// Expected threshold owner key for the seeded FROST ceremony below.
const EXPECTED_THRESHOLD_OWNER_KEY: &str =
    "99e234bf90ee0d62e120bd6d484b67800bc0fa9492c54d56aecf9013929287e3";

/// Expected threshold owner signature for the seeded FROST ceremony below.
const EXPECTED_THRESHOLD_OWNER_SIGNATURE: &str = "495b6ed3859750720b65e1391c7ab122c196ee719f9ddccadc9a88e021ae04cd4503454d4a4a3757a500c6e79ec7178ba6ebd3f7aa055f5a4dbb6a0e7c550b0c";

#[test]
fn test_recovery_phrase_deterministic_keypair() {
    // The same mnemonic should always produce the same keypair
    let phrase1 = RecoveryPhrase::from_mnemonic(TEST_MNEMONIC).unwrap();
    let phrase2 = RecoveryPhrase::from_mnemonic(TEST_MNEMONIC).unwrap();

    let keypair1 = phrase1.derive_owner_keypair();
    let keypair2 = phrase2.derive_owner_keypair();

    assert_eq!(keypair1.public().to_bytes(), keypair2.public().to_bytes());
}

#[test]
fn test_genesis_fingerprint_matches_golden() {
    let phrase = RecoveryPhrase::from_mnemonic(TEST_MNEMONIC).unwrap();
    let keypair = phrase.derive_owner_keypair();

    let genesis = GenesisState::create_deterministic(&keypair.public());
    let fingerprint = genesis.fingerprint();

    let expected = EXPECTED_FINGERPRINT.trim();
    assert_eq!(
        fingerprint, expected,
        "Genesis fingerprint changed! Was: {fingerprint}, Expected: {expected}"
    );
}

#[test]
fn test_genesis_cbor_matches_golden() {
    let phrase = RecoveryPhrase::from_mnemonic(TEST_MNEMONIC).unwrap();
    let keypair = phrase.derive_owner_keypair();

    let genesis = GenesisState::create_deterministic(&keypair.public());
    let cbor = genesis.to_cbor().unwrap();

    // Compare CBOR bytes
    assert_eq!(
        cbor.as_slice(),
        EXPECTED_GENESIS_CBOR,
        "Genesis CBOR changed! Length was: {}, expected: {}",
        cbor.len(),
        EXPECTED_GENESIS_CBOR.len()
    );
}

#[test]
fn test_genesis_cbor_roundtrip_preserves_all_fields() {
    let phrase = RecoveryPhrase::from_mnemonic(TEST_MNEMONIC).unwrap();
    let keypair = phrase.derive_owner_keypair();

    let genesis = GenesisState::create_deterministic(&keypair.public());
    let cbor = genesis.to_cbor().unwrap();
    let restored = GenesisState::from_cbor(&cbor).unwrap();

    // Verify all fields are preserved
    assert_eq!(genesis.schema_version, restored.schema_version);
    assert_eq!(genesis.owner_public_key, restored.owner_public_key);
    assert_eq!(genesis.created_at, restored.created_at);
    assert_eq!(genesis.initial_zones.len(), restored.initial_zones.len());

    for (orig, rest) in genesis
        .initial_zones
        .iter()
        .zip(restored.initial_zones.iter())
    {
        assert_eq!(orig.zone_id, rest.zone_id);
        assert_eq!(orig.name, rest.name);
        assert_eq!(orig.integrity_level, rest.integrity_level);
        assert_eq!(orig.confidentiality_level, rest.confidentiality_level);
    }
}

#[test]
fn test_genesis_owner_key_is_canonical() {
    let phrase = RecoveryPhrase::from_mnemonic(TEST_MNEMONIC).unwrap();
    let keypair = phrase.derive_owner_keypair();

    let genesis = GenesisState::create_deterministic(&keypair.public());

    // Owner key should be exactly 32 bytes (Ed25519 compressed point)
    assert_eq!(genesis.owner_public_key.len(), 32);

    // Key should be recoverable as a valid verifying key
    let verifying_key = genesis.owner_verifying_key().unwrap();
    assert_eq!(verifying_key.to_bytes(), genesis.owner_public_key);
}

#[test]
fn test_genesis_has_all_required_zones() {
    let phrase = RecoveryPhrase::from_mnemonic(TEST_MNEMONIC).unwrap();
    let keypair = phrase.derive_owner_keypair();

    let genesis = GenesisState::create_deterministic(&keypair.public());

    let required_zones = ["z:owner", "z:private", "z:work", "z:community", "z:public"];

    for zone_id in required_zones {
        assert!(
            genesis.initial_zones.iter().any(|z| z.zone_id == zone_id),
            "Missing required zone: {zone_id}"
        );
    }
}

#[test]
fn test_zone_integrity_levels_are_ordered() {
    let phrase = RecoveryPhrase::from_mnemonic(TEST_MNEMONIC).unwrap();
    let keypair = phrase.derive_owner_keypair();

    let genesis = GenesisState::create_deterministic(&keypair.public());

    // z:owner should have highest integrity
    let owner_zone = genesis
        .initial_zones
        .iter()
        .find(|z| z.zone_id == "z:owner")
        .unwrap();
    let public_zone = genesis
        .initial_zones
        .iter()
        .find(|z| z.zone_id == "z:public")
        .unwrap();

    assert!(
        owner_zone.integrity_level > public_zone.integrity_level,
        "z:owner should have higher integrity than z:public"
    );
}

#[test]
fn test_key_material_is_not_logged() {
    // This test ensures sensitive key material doesn't appear in Debug output
    let phrase = RecoveryPhrase::from_mnemonic(TEST_MNEMONIC).unwrap();
    let keypair = phrase.derive_owner_keypair();

    let debug_output = format!("{phrase:?}");
    assert!(
        !debug_output.contains("abandon"),
        "Recovery phrase words leaked in Debug output"
    );

    let keypair_debug = format!("{keypair:?}");
    // The debug output should only contain the public key, not private material
    assert!(
        keypair_debug.contains("public_key"),
        "OwnerKeypair debug should show public_key"
    );
}

#[test]
fn test_threshold_owner_signature_matches_golden_vector() {
    let mut ceremony = ThresholdCeremony::new(2, 3);
    let mut split_rng = ChaCha20Rng::seed_from_u64(20_260_307);
    for index in 1..=3 {
        ceremony
            .add_participant(ParticipantId {
                index,
                name: format!("device-{index}"),
                public_key: [u8::try_from(index).unwrap(); 32],
            })
            .unwrap();
    }
    for index in 1..=3 {
        ceremony
            .add_commitment(FrostCommitment {
                participant_index: index,
                commitment: vec![u8::try_from(index).unwrap(); 32],
                proof: vec![0xBB; 64],
            })
            .unwrap();
    }
    for index in 1..=3 {
        ceremony
            .add_shares_with_rng(
                index,
                vec![EncryptedShare {
                    from_index: index,
                    to_index: index,
                    ciphertext: vec![u8::try_from(index).unwrap(); 32],
                }],
                &mut split_rng,
            )
            .unwrap();
    }

    let mut rng = ChaCha20Rng::seed_from_u64(20_260_307);
    let artifact = ceremony
        .sign_with_participants_and_rng(
            &[1, 3],
            b"FCP2-THRESHOLD-OWNER",
            b"golden-vector-threshold-owner",
            &mut rng,
        )
        .unwrap();
    let owner_key = ceremony.owner_verifying_key().unwrap();

    assert_eq!(
        hex::encode(owner_key.to_bytes()),
        EXPECTED_THRESHOLD_OWNER_KEY,
        "threshold owner key changed unexpectedly"
    );
    assert_eq!(
        hex::encode(artifact.signature.to_bytes()),
        EXPECTED_THRESHOLD_OWNER_SIGNATURE,
        "threshold owner signature changed unexpectedly"
    );

    assert!(
        ceremony
            .verify_signature_artifact(
                &artifact,
                b"FCP2-THRESHOLD-OWNER",
                b"golden-vector-threshold-owner",
            )
            .is_ok()
    );
}
