//! Golden vector tests for FCPS frames and `SymbolEnvelope` encryption.
//!
//! These tests provide deterministic vectors for interoperability testing
//! and regression detection of the FCPS wire format.

use fcp_prelude::{ObjectId, TailscaleNodeId, ZoneIdHash, ZoneKeyId};
use fcp_crypto::AeadKey;
use fcp_protocol::{
    FCPS_HEADER_LEN,
    FCPS_MAGIC,
    FCPS_VERSION,
    FcpsFrame,
    FcpsFrameHeader,
    FrameFlags,
    SYMBOL_RECORD_OVERHEAD,
    // SymbolEnvelope exports
    SymbolContext,
    SymbolRecord,
    ZoneKeyAlgorithm,
    build_symbol_aad,
    decrypt_symbol,
    derive_nonce12,
    derive_nonce24,
    derive_sender_subkey,
    encrypt_symbol,
};

// =============================================================================
// FCPS Frame Header Golden Vectors
// =============================================================================

#[test]
fn golden_fcps_header_encode() {
    // Deterministic header with known values
    let header = FcpsFrameHeader {
        version: FCPS_VERSION,
        flags: FrameFlags::ENCRYPTED | FrameFlags::RAPTORQ,
        symbol_count: 2,
        total_payload_len: u32::try_from(2 * (SYMBOL_RECORD_OVERHEAD + 64))
            .expect("payload length fits in u32"), // 172 bytes
        object_id: ObjectId::from_bytes([0x11; 32]),
        symbol_size: 64,
        zone_key_id: ZoneKeyId::from_bytes([0x22; 8]),
        zone_id_hash: ZoneIdHash::from_bytes([0x33; 32]),
        epoch_id: 1000,
        sender_instance_id: 0xDEAD_BEEF,
        frame_seq: 42,
    };

    let encoded = header.encode();
    assert_eq!(encoded.len(), FCPS_HEADER_LEN);

    // Verify magic bytes
    assert_eq!(&encoded[0..4], &FCPS_MAGIC, "magic bytes mismatch");

    // Verify version (u16 LE)
    assert_eq!(&encoded[4..6], &[0x01, 0x00], "version mismatch");

    // Verify flags: ENCRYPTED (0x04) | RAPTORQ (0x0400) = 0x0404
    assert_eq!(&encoded[6..8], &[0x04, 0x04], "flags mismatch");

    // Verify symbol_count: 2 (u32 LE)
    assert_eq!(
        &encoded[8..12],
        &[0x02, 0x00, 0x00, 0x00],
        "symbol_count mismatch"
    );

    // Verify total_payload_len: 172 (u32 LE) = 0xAC
    assert_eq!(
        &encoded[12..16],
        &[0xAC, 0x00, 0x00, 0x00],
        "total_payload_len mismatch"
    );

    // Verify object_id (32 bytes of 0x11)
    assert_eq!(&encoded[16..48], &[0x11; 32], "object_id mismatch");

    // Verify symbol_size: 64 (u16 LE)
    assert_eq!(&encoded[48..50], &[0x40, 0x00], "symbol_size mismatch");

    // Verify zone_key_id (8 bytes of 0x22)
    assert_eq!(&encoded[50..58], &[0x22; 8], "zone_key_id mismatch");

    // Verify zone_id_hash (32 bytes of 0x33)
    assert_eq!(&encoded[58..90], &[0x33; 32], "zone_id_hash mismatch");

    // Verify epoch_id: 1000 (u64 LE) = 0x3E8
    assert_eq!(
        &encoded[90..98],
        &[0xE8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        "epoch_id mismatch"
    );

    // Verify sender_instance_id: 0xDEAD_BEEF (u64 LE)
    assert_eq!(
        &encoded[98..106],
        &[0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00],
        "sender_instance_id mismatch"
    );

    // Verify frame_seq: 42 (u64 LE)
    assert_eq!(
        &encoded[106..114],
        &[0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        "frame_seq mismatch"
    );
}

#[test]
fn golden_fcps_header_decode() {
    // Pre-computed header bytes (from golden_fcps_header_encode)
    #[rustfmt::skip]
    let header_bytes: [u8; 114] = [
        // Magic: "FCPS"
        0x46, 0x43, 0x50, 0x53,
        // Version: 1 (u16 LE)
        0x01, 0x00,
        // Flags: ENCRYPTED | RAPTORQ = 0x0404
        0x04, 0x04,
        // Symbol count: 2 (u32 LE)
        0x02, 0x00, 0x00, 0x00,
        // Total payload len: 172 (u32 LE)
        0xAC, 0x00, 0x00, 0x00,
        // Object ID: 32 bytes of 0x11
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        // Symbol size: 64 (u16 LE)
        0x40, 0x00,
        // Zone key ID: 8 bytes of 0x22
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        // Zone ID hash: 32 bytes of 0x33
        0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
        0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
        0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
        0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
        // Epoch ID: 1000 (u64 LE)
        0xE8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // Sender instance ID: 0xDEADBEEF (u64 LE)
        0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00,
        // Frame seq: 42 (u64 LE)
        0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let header = FcpsFrameHeader::decode(&header_bytes).expect("should decode");

    assert_eq!(header.version, 1);
    assert_eq!(header.flags, FrameFlags::ENCRYPTED | FrameFlags::RAPTORQ);
    assert_eq!(header.symbol_count, 2);
    assert_eq!(header.total_payload_len, 172);
    assert_eq!(header.object_id, ObjectId::from_bytes([0x11; 32]));
    assert_eq!(header.symbol_size, 64);
    assert_eq!(header.zone_key_id, ZoneKeyId::from_bytes([0x22; 8]));
    assert_eq!(header.zone_id_hash, ZoneIdHash::from_bytes([0x33; 32]));
    assert_eq!(header.epoch_id, 1000);
    assert_eq!(header.sender_instance_id, 0xDEAD_BEEF);
    assert_eq!(header.frame_seq, 42);
}

#[test]
fn golden_frame_flags_encoding() {
    // Test individual flag values
    assert_eq!(FrameFlags::REQUIRES_ACK.bits(), 0x0001);
    assert_eq!(FrameFlags::COMPRESSED.bits(), 0x0002);
    assert_eq!(FrameFlags::ENCRYPTED.bits(), 0x0004);
    assert_eq!(FrameFlags::RESPONSE.bits(), 0x0008);
    assert_eq!(FrameFlags::ERROR.bits(), 0x0010);
    assert_eq!(FrameFlags::STREAMING.bits(), 0x0020);
    assert_eq!(FrameFlags::STREAM_END.bits(), 0x0040);
    assert_eq!(FrameFlags::HAS_CAP_TOKEN.bits(), 0x0080);
    assert_eq!(FrameFlags::ZONE_CROSSING.bits(), 0x0100);
    assert_eq!(FrameFlags::PRIORITY.bits(), 0x0200);
    assert_eq!(FrameFlags::RAPTORQ.bits(), 0x0400);
    assert_eq!(FrameFlags::CONTROL_PLANE.bits(), 0x0800);

    // Default flags
    let default = FrameFlags::default();
    assert_eq!(default.bits(), 0x0404); // ENCRYPTED | RAPTORQ
}

// =============================================================================
// Symbol Record Golden Vectors
// =============================================================================

#[test]
fn golden_symbol_record_encode() {
    let record = SymbolRecord {
        esi: 0x1234_5678,
        k: 100,
        data: vec![0xAB; 64],
        auth_tag: [0xCD; 16],
    };

    let encoded = record.encode();
    assert_eq!(encoded.len(), SYMBOL_RECORD_OVERHEAD + 64);

    // ESI (u32 LE)
    assert_eq!(&encoded[0..4], &[0x78, 0x56, 0x34, 0x12]);
    // K (u16 LE)
    assert_eq!(&encoded[4..6], &[0x64, 0x00]);
    // Data (64 bytes of 0xAB)
    assert_eq!(&encoded[6..70], &[0xAB; 64]);
    // Auth tag (16 bytes of 0xCD)
    assert_eq!(&encoded[70..86], &[0xCD; 16]);
}

#[test]
fn golden_symbol_record_decode() {
    #[rustfmt::skip]
    let record_bytes: Vec<u8> = [
        // ESI: 0x1234_5678 (u32 LE)
        0x78, 0x56, 0x34, 0x12,
        // K: 100 (u16 LE)
        0x64, 0x00,
    ].iter()
        .chain(&[0xAB; 64])  // Data
        .chain(&[0xCD; 16])  // Auth tag
        .copied()
        .collect();

    let record = SymbolRecord::decode(&record_bytes, 64).expect("should decode");

    assert_eq!(record.esi, 0x1234_5678);
    assert_eq!(record.k, 100);
    assert_eq!(record.data, vec![0xAB; 64]);
    assert_eq!(record.auth_tag, [0xCD; 16]);
}

// =============================================================================
// Nonce Derivation Golden Vectors
// =============================================================================

#[test]
fn golden_nonce12_derivation() {
    // Nonce12 layout:
    // - Bytes 0-7: frame_seq (u64 LE)
    // - Bytes 8-11: ESI (u32 LE)

    // Vector 1: Simple values (frame_seq=1, esi=0)
    let nonce = derive_nonce12(1, 0);
    assert_eq!(
        nonce.as_bytes(),
        &[
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // frame_seq = 1 (LE)
            0x00, 0x00, 0x00, 0x00 // esi = 0 (LE)
        ]
    );

    // Vector 2: Large values
    let nonce = derive_nonce12(0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF);
    assert_eq!(
        nonce.as_bytes(),
        &[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // frame_seq = MAX
            0xFF, 0xFF, 0xFF, 0xFF // esi = MAX
        ]
    );

    // Vector 3: Specific test case (frame_seq=0x0102_0304_0506_0708, esi=0x0A0B_0C0D)
    let nonce = derive_nonce12(0x0102_0304_0506_0708, 0x0A0B_0C0D);
    assert_eq!(
        nonce.as_bytes(),
        &[
            0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // frame_seq (LE)
            0x0D, 0x0C, 0x0B, 0x0A // esi (LE)
        ]
    );
}

#[test]
fn golden_nonce24_derivation() {
    // Vector 1: Simple values
    let nonce = derive_nonce24(1, 2, 3);
    #[rustfmt::skip]
    assert_eq!(
        nonce.as_bytes(),
        &[
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // sender_instance_id
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // frame_seq
            0x03, 0x00, 0x00, 0x00,                          // ESI
            0x00, 0x00, 0x00, 0x00,                          // padding
        ]
    );

    // Vector 2: Large values
    let nonce = derive_nonce24(0xDEAD_BEEF_CAFE_BABE, 0x1234_5678_9ABC_DEF0, 0xFEDC_BA98);
    #[rustfmt::skip]
    assert_eq!(
        nonce.as_bytes(),
        &[
            0xBE, 0xBA, 0xFE, 0xCA, 0xEF, 0xBE, 0xAD, 0xDE,  // sender_instance_id
            0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12,  // frame_seq
            0x98, 0xBA, 0xDC, 0xFE,                          // ESI
            0x00, 0x00, 0x00, 0x00,                          // padding
        ]
    );
}

// =============================================================================
// Subkey Derivation Golden Vector
// =============================================================================

#[test]
fn golden_subkey_derivation() {
    // Fixed zone key for reproducibility
    let zone_key = AeadKey::from_bytes([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F,
    ]);

    let zone_key_id = ZoneKeyId::from_bytes([0x44; 8]);
    let sender_node_id = TailscaleNodeId::new("node-golden");
    let sender_instance_id: u64 = 0x1234_5678_9ABC_DEF0;

    let subkey = derive_sender_subkey(&zone_key, &zone_key_id, &sender_node_id, sender_instance_id);

    // The subkey should be deterministic
    let subkey2 =
        derive_sender_subkey(&zone_key, &zone_key_id, &sender_node_id, sender_instance_id);
    assert_eq!(subkey.as_bytes(), subkey2.as_bytes());

    // Different sender_instance_id should yield different subkey
    let subkey_other = derive_sender_subkey(&zone_key, &zone_key_id, &sender_node_id, 0);
    assert_ne!(subkey.as_bytes(), subkey_other.as_bytes());

    // Log the derived subkey for reference (HKDF output is deterministic)
    // This vector can be used by other implementations
    eprintln!("Golden subkey (hex): {}", hex::encode(subkey.as_bytes()));
}

// =============================================================================
// AAD Construction Golden Vector
// =============================================================================

#[test]
fn golden_aad_construction() {
    let ctx = SymbolContext {
        object_id: ObjectId::from_bytes([0x11; 32]),
        esi: 42,
        k: 10,
        zone_id_hash: ZoneIdHash::from_bytes([0x22; 32]),
        zone_key_id: ZoneKeyId::from_bytes([0x33; 8]),
        epoch_id: 1000,
        sender_node_id: TailscaleNodeId::new("node-test"),
        sender_instance_id: 0xDEAD_BEEF,
        frame_seq: 123,
    };

    let aad = build_symbol_aad(&ctx);
    assert_eq!(aad.len(), 86);

    #[rustfmt::skip]
    let expected_aad: [u8; 86] = [
        // object_id (32 bytes)
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        // ESI: 42 (u32 LE)
        0x2A, 0x00, 0x00, 0x00,
        // K: 10 (u16 LE)
        0x0A, 0x00,
        // zone_id_hash (32 bytes)
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        // zone_key_id (8 bytes)
        0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
        // epoch_id: 1000 (u64 LE)
        0xE8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    assert_eq!(aad, expected_aad);
}

// =============================================================================
// Full Frame Round-Trip Golden Vector
// =============================================================================

#[test]
fn golden_full_frame_roundtrip() {
    let header = FcpsFrameHeader {
        version: FCPS_VERSION,
        flags: FrameFlags::ENCRYPTED | FrameFlags::RAPTORQ,
        symbol_count: 2,
        total_payload_len: u32::try_from(2 * (SYMBOL_RECORD_OVERHEAD + 32))
            .expect("payload length fits in u32"), // 108 bytes
        object_id: ObjectId::from_bytes([0xAA; 32]),
        symbol_size: 32,
        zone_key_id: ZoneKeyId::from_bytes([0xBB; 8]),
        zone_id_hash: ZoneIdHash::from_bytes([0xCC; 32]),
        epoch_id: 999,
        sender_instance_id: 0x1111_2222,
        frame_seq: 1,
    };

    let symbols = vec![
        SymbolRecord {
            esi: 0,
            k: 5,
            data: vec![0xDE; 32],
            auth_tag: [0xEF; 16],
        },
        SymbolRecord {
            esi: 1,
            k: 5,
            data: vec![0xFE; 32],
            auth_tag: [0xED; 16],
        },
    ];

    let frame = FcpsFrame { header, symbols };
    let encoded = frame.encode().expect("encode");

    // 114 (header) + 54*2 (symbols) = 222 bytes
    assert_eq!(encoded.len(), 114 + 108);

    let decoded = FcpsFrame::decode(&encoded, 1200).expect("should decode");
    assert_eq!(decoded, frame);
}

// =============================================================================
// SymbolEnvelope AEAD Golden Vectors
// =============================================================================

#[test]
fn golden_symbol_encryption_chacha20() {
    // Fixed key and context for reproducibility
    let zone_key = AeadKey::from_bytes([0x42; 32]);
    let ctx = SymbolContext {
        object_id: ObjectId::from_bytes([0x11; 32]),
        esi: 0,
        k: 10,
        zone_id_hash: ZoneIdHash::from_bytes([0x22; 32]),
        zone_key_id: ZoneKeyId::from_bytes([0x33; 8]),
        epoch_id: 1000,
        sender_node_id: TailscaleNodeId::new("node-test"),
        sender_instance_id: 0xDEAD_BEEF,
        frame_seq: 1,
    };

    let plaintext = b"Hello, FCP2 World!";

    let (ciphertext, auth_tag) = encrypt_symbol(
        &zone_key,
        ZoneKeyAlgorithm::ChaCha20Poly1305,
        &ctx,
        plaintext,
    )
    .expect("encryption should succeed");

    // Verify round-trip
    let decrypted = decrypt_symbol(
        &zone_key,
        ZoneKeyAlgorithm::ChaCha20Poly1305,
        &ctx,
        &ciphertext,
        &auth_tag,
    )
    .expect("decryption should succeed");

    assert_eq!(decrypted, plaintext);

    // Log ciphertext for cross-implementation testing
    eprintln!("Plaintext (hex): {}", hex::encode(plaintext));
    eprintln!("Ciphertext (hex): {}", hex::encode(&ciphertext));
    eprintln!("Auth tag (hex): {}", hex::encode(auth_tag));
}

#[test]
fn golden_symbol_encryption_xchacha20() {
    // Fixed key and context for reproducibility
    let zone_key = AeadKey::from_bytes([0x42; 32]);
    let ctx = SymbolContext {
        object_id: ObjectId::from_bytes([0x11; 32]),
        esi: 0,
        k: 10,
        zone_id_hash: ZoneIdHash::from_bytes([0x22; 32]),
        zone_key_id: ZoneKeyId::from_bytes([0x33; 8]),
        epoch_id: 1000,
        sender_node_id: TailscaleNodeId::new("node-test"),
        sender_instance_id: 0xDEAD_BEEF,
        frame_seq: 1,
    };

    let plaintext = b"Hello, XChaCha20 World!";

    let (ciphertext, auth_tag) = encrypt_symbol(
        &zone_key,
        ZoneKeyAlgorithm::XChaCha20Poly1305,
        &ctx,
        plaintext,
    )
    .expect("encryption should succeed");

    // Verify round-trip
    let decrypted = decrypt_symbol(
        &zone_key,
        ZoneKeyAlgorithm::XChaCha20Poly1305,
        &ctx,
        &ciphertext,
        &auth_tag,
    )
    .expect("decryption should succeed");

    assert_eq!(decrypted, plaintext);

    // Log ciphertext for cross-implementation testing
    eprintln!("Plaintext (hex): {}", hex::encode(plaintext));
    eprintln!("Ciphertext (hex): {}", hex::encode(&ciphertext));
    eprintln!("Auth tag (hex): {}", hex::encode(auth_tag));
}

// =============================================================================
// Algorithm Selection Tests
// =============================================================================

#[test]
#[allow(clippy::similar_names)] // chacha20 vs xchacha20 names are intentionally similar
fn algorithm_selection_produces_different_ciphertexts() {
    // The same plaintext encrypted with different algorithms should produce
    // different ciphertexts (due to different nonces and cipher internals)
    let zone_key = AeadKey::from_bytes([0x42; 32]);
    let ctx = SymbolContext {
        object_id: ObjectId::from_bytes([0x11; 32]),
        esi: 0,
        k: 10,
        zone_id_hash: ZoneIdHash::from_bytes([0x22; 32]),
        zone_key_id: ZoneKeyId::from_bytes([0x33; 8]),
        epoch_id: 1000,
        sender_node_id: TailscaleNodeId::new("node-test"),
        sender_instance_id: 0xDEAD_BEEF,
        frame_seq: 1,
    };

    let plaintext = b"Same plaintext for both algorithms";

    let (standard_ciphertext, standard_tag) = encrypt_symbol(
        &zone_key,
        ZoneKeyAlgorithm::ChaCha20Poly1305,
        &ctx,
        plaintext,
    )
    .expect("chacha encrypt");

    let (extended_ciphertext, extended_tag) = encrypt_symbol(
        &zone_key,
        ZoneKeyAlgorithm::XChaCha20Poly1305,
        &ctx,
        plaintext,
    )
    .expect("xchacha encrypt");

    // Ciphertexts should differ (different nonces/algorithms)
    assert_ne!(standard_ciphertext, extended_ciphertext);
    assert_ne!(standard_tag, extended_tag);

    // Both should decrypt correctly with their respective algorithms
    let standard_plaintext = decrypt_symbol(
        &zone_key,
        ZoneKeyAlgorithm::ChaCha20Poly1305,
        &ctx,
        &standard_ciphertext,
        &standard_tag,
    )
    .expect("chacha decrypt");

    let extended_plaintext = decrypt_symbol(
        &zone_key,
        ZoneKeyAlgorithm::XChaCha20Poly1305,
        &ctx,
        &extended_ciphertext,
        &extended_tag,
    )
    .expect("xchacha decrypt");

    assert_eq!(standard_plaintext, plaintext);
    assert_eq!(extended_plaintext, plaintext);
}

#[test]
fn cross_algorithm_decrypt_fails() {
    // Decrypting with the wrong algorithm should fail
    let zone_key = AeadKey::from_bytes([0x42; 32]);
    let ctx = SymbolContext {
        object_id: ObjectId::from_bytes([0x11; 32]),
        esi: 0,
        k: 10,
        zone_id_hash: ZoneIdHash::from_bytes([0x22; 32]),
        zone_key_id: ZoneKeyId::from_bytes([0x33; 8]),
        epoch_id: 1000,
        sender_node_id: TailscaleNodeId::new("node-test"),
        sender_instance_id: 0xDEAD_BEEF,
        frame_seq: 1,
    };

    let plaintext = b"Test plaintext";

    let (ct, tag) = encrypt_symbol(
        &zone_key,
        ZoneKeyAlgorithm::ChaCha20Poly1305,
        &ctx,
        plaintext,
    )
    .expect("encrypt");

    // Try to decrypt with XChaCha20 (wrong algorithm)
    let result = decrypt_symbol(
        &zone_key,
        ZoneKeyAlgorithm::XChaCha20Poly1305,
        &ctx,
        &ct,
        &tag,
    );

    assert!(result.is_err());
}

#[test]
fn symbol_decrypt_wrong_key_fails() {
    // Decrypting with a different key should fail
    let zone_key = AeadKey::from_bytes([0x42; 32]);
    let wrong_key = AeadKey::from_bytes([0xFF; 32]);
    let ctx = SymbolContext {
        object_id: ObjectId::from_bytes([0x11; 32]),
        esi: 0,
        k: 10,
        zone_id_hash: ZoneIdHash::from_bytes([0x22; 32]),
        zone_key_id: ZoneKeyId::from_bytes([0x33; 8]),
        epoch_id: 1000,
        sender_node_id: TailscaleNodeId::new("node-test"),
        sender_instance_id: 0xDEAD_BEEF,
        frame_seq: 1,
    };

    let plaintext = b"Secret symbol data";

    // Encrypt with correct key
    let (ciphertext, auth_tag) = encrypt_symbol(
        &zone_key,
        ZoneKeyAlgorithm::ChaCha20Poly1305,
        &ctx,
        plaintext,
    )
    .expect("encryption should succeed");

    // Try to decrypt with wrong key
    let result = decrypt_symbol(
        &wrong_key,
        ZoneKeyAlgorithm::ChaCha20Poly1305,
        &ctx,
        &ciphertext,
        &auth_tag,
    );

    assert!(
        result.is_err(),
        "decryption with wrong key should fail AEAD"
    );
}

// =============================================================================
// DoS Resistance and Memory Bounds Tests
// =============================================================================

#[test]
fn reject_invalid_symbol_count_zero_with_payload() {
    // A frame claiming zero symbols but containing payload bytes is invalid
    let header = FcpsFrameHeader {
        version: FCPS_VERSION,
        flags: FrameFlags::ENCRYPTED | FrameFlags::RAPTORQ,
        symbol_count: 0,
        total_payload_len: 100, // Claims 100 bytes but zero symbols
        object_id: ObjectId::from_bytes([0xAA; 32]),
        symbol_size: 64,
        zone_key_id: ZoneKeyId::from_bytes([0xBB; 8]),
        zone_id_hash: ZoneIdHash::from_bytes([0xCC; 32]),
        epoch_id: 1,
        sender_instance_id: 1,
        frame_seq: 1,
    };

    // Build a frame with header + payload that doesn't match symbol_count
    let mut frame_bytes = header.encode().to_vec();
    frame_bytes.extend_from_slice(&[0u8; 100]);

    let err = FcpsFrame::decode(&frame_bytes, 2000)
        .expect_err("should reject zero symbol_count with payload");
    // Should fail due to length mismatch (0 symbols * symbol_size != 100)
    assert!(matches!(
        err,
        fcp_protocol::FrameError::LengthMismatch { .. }
    ));
}

#[test]
fn reject_symbol_count_overflow() {
    // A frame claiming u32::MAX symbols would overflow any reasonable allocation
    let header = FcpsFrameHeader {
        version: FCPS_VERSION,
        flags: FrameFlags::ENCRYPTED | FrameFlags::RAPTORQ,
        symbol_count: u32::MAX,
        total_payload_len: 0, // Impossible to match with MAX symbols
        object_id: ObjectId::from_bytes([0xAA; 32]),
        symbol_size: 64,
        zone_key_id: ZoneKeyId::from_bytes([0xBB; 8]),
        zone_id_hash: ZoneIdHash::from_bytes([0xCC; 32]),
        epoch_id: 1,
        sender_instance_id: 1,
        frame_seq: 1,
    };

    let frame_bytes = header.encode();
    let err =
        FcpsFrame::decode(&frame_bytes, 2000).expect_err("should reject symbol count overflow");
    // May fail with SymbolCountOverflow or LengthMismatch depending on validation order
    assert!(
        matches!(err, fcp_protocol::FrameError::SymbolCountOverflow)
            || matches!(err, fcp_protocol::FrameError::LengthMismatch { .. })
            || matches!(err, fcp_protocol::FrameError::TooShort { .. })
    );
}

#[test]
fn reject_frame_exceeding_mtu() {
    // Build a frame that is legitimately larger than MTU
    let header = FcpsFrameHeader {
        version: FCPS_VERSION,
        flags: FrameFlags::ENCRYPTED | FrameFlags::RAPTORQ,
        symbol_count: 2,
        total_payload_len: 2 * u32::try_from(SYMBOL_RECORD_OVERHEAD + 1024).unwrap(), // 2 symbols * (22 + 1024)
        object_id: ObjectId::from_bytes([0xAA; 32]),
        symbol_size: 1024,
        zone_key_id: ZoneKeyId::from_bytes([0xBB; 8]),
        zone_id_hash: ZoneIdHash::from_bytes([0xCC; 32]),
        epoch_id: 1,
        sender_instance_id: 1,
        frame_seq: 1,
    };

    // Build a complete frame with symbols
    let symbols = vec![
        SymbolRecord {
            esi: 0,
            k: 5,
            data: vec![0xAB; 1024],
            auth_tag: [0xCD; 16],
        },
        SymbolRecord {
            esi: 1,
            k: 5,
            data: vec![0xAB; 1024],
            auth_tag: [0xCD; 16],
        },
    ];

    let frame = FcpsFrame { header, symbols };
    let frame_bytes = frame.encode().expect("encode");

    // Frame is 114 (header) + 2 * (22 + 1024) = 114 + 2092 = 2206 bytes
    // Use a small MTU that's less than the frame size
    let err = FcpsFrame::decode(&frame_bytes, 500).expect_err("should reject frame exceeding MTU");
    assert!(
        matches!(err, fcp_protocol::FrameError::ExceedsMtu { .. }),
        "Expected ExceedsMtu error, got: {err:?}"
    );
}

#[test]
fn memory_bounds_on_malformed_symbol_record() {
    // A symbol record with claimed data length exceeding available bytes
    // This tests that we don't over-read or allocate based on untrusted lengths
    let header = FcpsFrameHeader {
        version: FCPS_VERSION,
        flags: FrameFlags::ENCRYPTED | FrameFlags::RAPTORQ,
        symbol_count: 1,
        total_payload_len: 10, // Claims 10 bytes but symbol needs more
        object_id: ObjectId::from_bytes([0xAA; 32]),
        symbol_size: 1024, // Symbol would need ~1040 bytes
        zone_key_id: ZoneKeyId::from_bytes([0xBB; 8]),
        zone_id_hash: ZoneIdHash::from_bytes([0xCC; 32]),
        epoch_id: 1,
        sender_instance_id: 1,
        frame_seq: 1,
    };

    let mut frame_bytes = header.encode().to_vec();
    frame_bytes.extend_from_slice(&[0u8; 10]); // Only 10 bytes of "payload"

    let err =
        FcpsFrame::decode(&frame_bytes, 2000).expect_err("should reject malformed symbol record");
    assert!(
        matches!(err, fcp_protocol::FrameError::LengthMismatch { .. })
            || matches!(err, fcp_protocol::FrameError::TooShort { .. })
    );
}

#[test]
fn memory_bounds_truncated_header() {
    // A truncated header should be rejected without crashing
    let truncated = [0x46, 0x43, 0x50, 0x53, 0x01, 0x00]; // Just magic + version
    let err = FcpsFrameHeader::decode(&truncated).expect_err("should reject truncated header");
    assert!(matches!(err, fcp_protocol::FrameError::TooShort { .. }));
}

#[test]
fn memory_bounds_symbol_record_too_short() {
    // A symbol record buffer shorter than the overhead should be rejected
    let short_record = [0u8; 5]; // Less than SYMBOL_RECORD_OVERHEAD (6)
    let err =
        SymbolRecord::decode(&short_record, 64).expect_err("should reject short symbol record");
    assert!(matches!(err, fcp_protocol::FrameError::TooShort { .. }));
}

// =============================================================================
// Generator functions for creating reference vectors
// =============================================================================

#[test]
fn generate_fcps_reference_vectors() {
    // This test generates reference vectors that can be used by other
    // implementations for interoperability testing.

    eprintln!("\n=== FCPS Reference Vectors ===\n");

    // Header vector
    let header = FcpsFrameHeader {
        version: 1,
        flags: FrameFlags::ENCRYPTED | FrameFlags::RAPTORQ,
        symbol_count: 1,
        total_payload_len: 38,
        object_id: ObjectId::from_bytes([0x01; 32]),
        symbol_size: 16,
        zone_key_id: ZoneKeyId::from_bytes([0x02; 8]),
        zone_id_hash: ZoneIdHash::from_bytes([0x03; 32]),
        epoch_id: 100,
        sender_instance_id: 0x1234_5678,
        frame_seq: 1,
    };
    eprintln!("Header bytes:\n{}", hex::encode(header.encode()));

    // Symbol record vector
    let record = SymbolRecord {
        esi: 0,
        k: 5,
        data: vec![0xFF; 16],
        auth_tag: [0xAA; 16],
    };
    eprintln!("\nSymbol record bytes:\n{}", hex::encode(record.encode()));

    // Nonce vectors
    let nonce12 = derive_nonce12(100, 42);
    eprintln!(
        "\nNonce12 (frame_seq=100, esi=42):\n{}",
        hex::encode(nonce12.as_bytes())
    );

    let nonce24 = derive_nonce24(0x1234_5678_90AB_CDEF, 100, 42);
    eprintln!(
        "\nNonce24 (sender=0x1234_5678_90AB_CDEF, frame_seq=100, esi=42):\n{}",
        hex::encode(nonce24.as_bytes())
    );

    eprintln!("\n=== End Reference Vectors ===\n");
}
