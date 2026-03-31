//! FCPC Golden Vectors for interoperability testing.
//!
//! These vectors ensure that FCPC frame encoding, AEAD, and header parsing
//! produce exact byte sequences that can be validated across implementations.
//!
//! Format reference: `FCP_Specification_V3.md` §9.2 and §9.3

use fcp_protocol::{
    FCPC_HEADER_LEN, FCPC_MAGIC, FCPC_TAG_LEN, FCPC_VERSION, FcpcFrame, FcpcFrameFlags,
    FcpcFrameHeader, MeshSessionId, SessionDirection,
};

// ============================================================================
// Test Constants
// ============================================================================

/// Known session ID for golden vectors.
const GOLDEN_SESSION_ID: [u8; 16] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
];

/// Known encryption key for golden vectors.
const GOLDEN_K_CTX: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
];

// ============================================================================
// Header Encoding Golden Vectors
// ============================================================================

#[test]
fn header_encode_golden_vector_seq_0() {
    // Header with seq=0, flags=ENCRYPTED (0x0001), len=0
    let header = FcpcFrameHeader {
        version: FCPC_VERSION,
        session_id: MeshSessionId(GOLDEN_SESSION_ID),
        seq: 0,
        flags: FcpcFrameFlags::ENCRYPTED,
        len: 0,
    };

    let encoded = header.encode();

    // Verify exact bytes
    assert_eq!(encoded.len(), FCPC_HEADER_LEN);

    // Magic: "FCPC"
    assert_eq!(&encoded[0..4], &FCPC_MAGIC);

    // Version: 1 (LE)
    assert_eq!(&encoded[4..6], &[0x01, 0x00]);

    // Session ID
    assert_eq!(&encoded[6..22], &GOLDEN_SESSION_ID);

    // Sequence: 0 (LE u64)
    assert_eq!(
        &encoded[22..30],
        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    );

    // Flags: ENCRYPTED = 0x0001 (LE)
    assert_eq!(&encoded[30..32], &[0x01, 0x00]);

    // Length: 0 (LE u32)
    assert_eq!(&encoded[32..36], &[0x00, 0x00, 0x00, 0x00]);
}

#[test]
fn header_encode_golden_vector_seq_max() {
    // Header with max sequence number
    let header = FcpcFrameHeader {
        version: FCPC_VERSION,
        session_id: MeshSessionId(GOLDEN_SESSION_ID),
        seq: u64::MAX,
        flags: FcpcFrameFlags::ENCRYPTED,
        len: 1024,
    };

    let encoded = header.encode();

    // Sequence: u64::MAX (LE)
    assert_eq!(
        &encoded[22..30],
        &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
    );

    // Length: 1024 = 0x0400 (LE u32)
    assert_eq!(&encoded[32..36], &[0x00, 0x04, 0x00, 0x00]);
}

#[test]
fn header_encode_golden_vector_all_flags() {
    // Header with both ENCRYPTED and COMPRESSED flags
    let header = FcpcFrameHeader {
        version: FCPC_VERSION,
        session_id: MeshSessionId(GOLDEN_SESSION_ID),
        seq: 42,
        flags: FcpcFrameFlags::ENCRYPTED | FcpcFrameFlags::COMPRESSED,
        len: 256,
    };

    let encoded = header.encode();

    // Flags: ENCRYPTED | COMPRESSED = 0x0003 (LE)
    assert_eq!(&encoded[30..32], &[0x03, 0x00]);

    // Length: 256 = 0x0100 (LE u32)
    assert_eq!(&encoded[32..36], &[0x00, 0x01, 0x00, 0x00]);
}

// ============================================================================
// Header Decode Golden Vectors
// ============================================================================

#[test]
fn header_decode_golden_vector() {
    // Construct known header bytes
    let mut bytes = [0u8; FCPC_HEADER_LEN];
    bytes[0..4].copy_from_slice(&FCPC_MAGIC);
    bytes[4..6].copy_from_slice(&1u16.to_le_bytes()); // version
    bytes[6..22].copy_from_slice(&GOLDEN_SESSION_ID);
    bytes[22..30].copy_from_slice(&100u64.to_le_bytes()); // seq
    bytes[30..32].copy_from_slice(&1u16.to_le_bytes()); // flags
    bytes[32..36].copy_from_slice(&512u32.to_le_bytes()); // len

    let header = FcpcFrameHeader::decode(&bytes).expect("decode should succeed");

    assert_eq!(header.version, 1);
    assert_eq!(header.session_id.as_bytes(), &GOLDEN_SESSION_ID);
    assert_eq!(header.seq, 100);
    assert_eq!(header.flags, FcpcFrameFlags::ENCRYPTED);
    assert_eq!(header.len, 512);
}

#[test]
fn header_roundtrip_deterministic() {
    let original = FcpcFrameHeader {
        version: FCPC_VERSION,
        session_id: MeshSessionId(GOLDEN_SESSION_ID),
        seq: 12345,
        flags: FcpcFrameFlags::ENCRYPTED,
        len: 999,
    };

    let encoded = original.encode();
    let decoded = FcpcFrameHeader::decode(&encoded).expect("decode should succeed");

    assert_eq!(original.version, decoded.version);
    assert_eq!(original.session_id, decoded.session_id);
    assert_eq!(original.seq, decoded.seq);
    assert_eq!(original.flags, decoded.flags);
    assert_eq!(original.len, decoded.len);
}

// ============================================================================
// Frame Seal/Open Golden Vectors
// ============================================================================

#[test]
fn frame_seal_empty_payload_golden_vector() {
    let session_id = MeshSessionId(GOLDEN_SESSION_ID);
    let plaintext = b"";

    let dir = SessionDirection::InitiatorToResponder;
    let frame = FcpcFrame::seal(
        session_id,
        0,
        dir,
        FcpcFrameFlags::default(),
        plaintext,
        &GOLDEN_K_CTX,
    )
    .expect("seal should succeed");

    let encoded = frame.encode();

    // Total size: header (36) + ciphertext (0) + tag (16)
    assert_eq!(encoded.len(), FCPC_HEADER_LEN + FCPC_TAG_LEN);

    // Verify header portion
    assert_eq!(&encoded[0..4], &FCPC_MAGIC);

    // Verify we can decode and open
    let decoded = FcpcFrame::decode(&encoded).expect("decode should succeed");
    let opened = decoded
        .open(dir, &GOLDEN_K_CTX)
        .expect("open should succeed");
    assert_eq!(opened, plaintext);
}

#[test]
fn frame_seal_known_payload_golden_vector() {
    let session_id = MeshSessionId(GOLDEN_SESSION_ID);
    let plaintext = b"Hello, FCPC!";
    let seq = 1;
    let dir = SessionDirection::InitiatorToResponder;

    let frame = FcpcFrame::seal(
        session_id,
        seq,
        dir,
        FcpcFrameFlags::default(),
        plaintext,
        &GOLDEN_K_CTX,
    )
    .expect("seal should succeed");

    let encoded = frame.encode();

    // Total size: header (36) + ciphertext (12) + tag (16)
    assert_eq!(encoded.len(), FCPC_HEADER_LEN + 12 + FCPC_TAG_LEN);

    // Header checks
    assert_eq!(&encoded[0..4], &FCPC_MAGIC);
    assert_eq!(&encoded[4..6], &1u16.to_le_bytes()); // version
    assert_eq!(&encoded[6..22], &GOLDEN_SESSION_ID);
    assert_eq!(&encoded[22..30], &1u64.to_le_bytes()); // seq = 1

    // Verify ciphertext length in header
    assert_eq!(&encoded[32..36], &12u32.to_le_bytes());

    // Verify we can decode and open
    let decoded = FcpcFrame::decode(&encoded).expect("decode should succeed");
    let opened = decoded
        .open(dir, &GOLDEN_K_CTX)
        .expect("open should succeed");
    assert_eq!(opened, plaintext);
}

#[test]
fn frame_different_seq_produces_different_ciphertext() {
    let session_id = MeshSessionId(GOLDEN_SESSION_ID);
    let plaintext = b"Same message";
    let dir = SessionDirection::InitiatorToResponder;

    let frame1 = FcpcFrame::seal(
        session_id,
        0,
        dir,
        FcpcFrameFlags::default(),
        plaintext,
        &GOLDEN_K_CTX,
    )
    .expect("seal should succeed");

    let frame2 = FcpcFrame::seal(
        session_id,
        1,
        dir,
        FcpcFrameFlags::default(),
        plaintext,
        &GOLDEN_K_CTX,
    )
    .expect("seal should succeed");

    // Different seq should produce different nonce, hence different ciphertext
    assert_ne!(frame1.ciphertext, frame2.ciphertext);
    assert_ne!(frame1.tag, frame2.tag);
}

#[test]
fn frame_different_session_produces_different_ciphertext() {
    let session1 = MeshSessionId([0x11; 16]);
    let session2 = MeshSessionId([0x22; 16]);
    let plaintext = b"Same message";
    let dir = SessionDirection::InitiatorToResponder;

    let frame1 = FcpcFrame::seal(
        session1,
        0,
        dir,
        FcpcFrameFlags::default(),
        plaintext,
        &GOLDEN_K_CTX,
    )
    .expect("seal should succeed");

    let frame2 = FcpcFrame::seal(
        session2,
        0,
        dir,
        FcpcFrameFlags::default(),
        plaintext,
        &GOLDEN_K_CTX,
    )
    .expect("seal should succeed");

    // Different session_id means different AAD, hence different tag
    assert_ne!(frame1.tag, frame2.tag);
}

// ============================================================================
// AAD Binding Verification
// ============================================================================

#[test]
fn aad_binds_session_id() {
    let session_id = MeshSessionId(GOLDEN_SESSION_ID);
    let plaintext = b"test payload";
    let dir = SessionDirection::InitiatorToResponder;

    let frame = FcpcFrame::seal(
        session_id,
        0,
        dir,
        FcpcFrameFlags::default(),
        plaintext,
        &GOLDEN_K_CTX,
    )
    .expect("seal should succeed");

    // Tamper with session_id in the frame
    let mut tampered = frame;
    tampered.header.session_id = MeshSessionId([0xFF; 16]);

    // Open should fail because AAD doesn't match
    let result = tampered.open(dir, &GOLDEN_K_CTX);
    assert!(result.is_err(), "tampered session_id should fail AEAD");
}

#[test]
fn aad_binds_seq() {
    let session_id = MeshSessionId(GOLDEN_SESSION_ID);
    let plaintext = b"test payload";
    let dir = SessionDirection::InitiatorToResponder;

    let frame = FcpcFrame::seal(
        session_id,
        0,
        dir,
        FcpcFrameFlags::default(),
        plaintext,
        &GOLDEN_K_CTX,
    )
    .expect("seal should succeed");

    // Tamper with seq in the frame
    let mut tampered = frame;
    tampered.header.seq = 999;

    // Open should fail because nonce and AAD are wrong
    let result = tampered.open(dir, &GOLDEN_K_CTX);
    assert!(result.is_err(), "tampered seq should fail AEAD");
}

#[test]
fn aad_binds_flags() {
    let session_id = MeshSessionId(GOLDEN_SESSION_ID);
    let plaintext = b"test payload";
    let dir = SessionDirection::InitiatorToResponder;

    let frame = FcpcFrame::seal(
        session_id,
        0,
        dir,
        FcpcFrameFlags::ENCRYPTED,
        plaintext,
        &GOLDEN_K_CTX,
    )
    .expect("seal should succeed");

    // Tamper with flags in the frame
    let mut tampered = frame;
    tampered.header.flags = FcpcFrameFlags::ENCRYPTED | FcpcFrameFlags::COMPRESSED;

    // Open should fail because AAD doesn't match
    let result = tampered.open(dir, &GOLDEN_K_CTX);
    assert!(result.is_err(), "tampered flags should fail AEAD");
}

// ============================================================================
// Invalid Frame Detection
// ============================================================================

#[test]
fn decode_rejects_wrong_magic() {
    let mut bytes = [0u8; FCPC_HEADER_LEN + FCPC_TAG_LEN];
    bytes[0..4].copy_from_slice(b"FCPS"); // Wrong magic
    bytes[4..6].copy_from_slice(&1u16.to_le_bytes());
    bytes[6..22].copy_from_slice(&GOLDEN_SESSION_ID);

    let result = FcpcFrame::decode(&bytes);
    assert!(result.is_err(), "wrong magic should be rejected");
}

#[test]
fn decode_rejects_unsupported_version() {
    let mut bytes = [0u8; FCPC_HEADER_LEN + FCPC_TAG_LEN];
    bytes[0..4].copy_from_slice(&FCPC_MAGIC);
    bytes[4..6].copy_from_slice(&2u16.to_le_bytes()); // Version 2 (unsupported)
    bytes[6..22].copy_from_slice(&GOLDEN_SESSION_ID);

    let result = FcpcFrameHeader::decode(&bytes);
    assert!(result.is_err(), "unsupported version should be rejected");
}

#[test]
fn decode_rejects_truncated_header() {
    let bytes = [0u8; FCPC_HEADER_LEN - 1]; // One byte short
    let result = FcpcFrameHeader::decode(&bytes);
    assert!(result.is_err(), "truncated header should be rejected");
}

#[test]
fn decode_rejects_truncated_frame() {
    // Frame with no tag
    let bytes = [0u8; FCPC_HEADER_LEN + 1]; // Header + 1 byte, no tag
    let result = FcpcFrame::decode(&bytes);
    assert!(result.is_err(), "truncated frame should be rejected");
}

// ============================================================================
// Byte-level Verification Helpers
// ============================================================================

/// Verify that the frame wire format matches the spec exactly.
#[test]
fn frame_wire_format_spec_compliance() {
    let session_id = MeshSessionId([0xAB; 16]);
    let plaintext = b"spec compliance test";
    let seq = 0x1234_5678_9ABC_DEF0_u64;

    let frame = FcpcFrame::seal(
        session_id,
        seq,
        SessionDirection::InitiatorToResponder,
        FcpcFrameFlags::ENCRYPTED,
        plaintext,
        &GOLDEN_K_CTX,
    )
    .expect("seal should succeed");

    let encoded = frame.encode();

    // Byte-by-byte verification of header structure:
    // [0..4]: Magic "FCPC"
    assert_eq!(&encoded[0..4], b"FCPC");

    // [4..6]: Version (u16 LE)
    assert_eq!(u16::from_le_bytes([encoded[4], encoded[5]]), 1);

    // [6..22]: Session ID (16 bytes)
    assert_eq!(&encoded[6..22], &[0xAB; 16]);

    // [22..30]: Sequence (u64 LE)
    let seq_bytes: [u8; 8] = encoded[22..30].try_into().unwrap();
    assert_eq!(u64::from_le_bytes(seq_bytes), seq);

    // [30..32]: Flags (u16 LE)
    let flags_bits = u16::from_le_bytes([encoded[30], encoded[31]]);
    assert_eq!(flags_bits, FcpcFrameFlags::ENCRYPTED.bits());

    // [32..36]: Length (u32 LE) - should be plaintext.len() (AEAD doesn't change length for ciphertext excluding tag)
    let len = u32::from_le_bytes(encoded[32..36].try_into().unwrap());
    assert_eq!(len as usize, plaintext.len());

    // [36..36+len]: Ciphertext
    // [36+len..36+len+16]: Tag
    assert_eq!(
        encoded.len(),
        FCPC_HEADER_LEN + plaintext.len() + FCPC_TAG_LEN
    );
}

#[test]
fn frame_deterministic_encoding() {
    let session_id = MeshSessionId(GOLDEN_SESSION_ID);
    let plaintext = b"determinism test";
    let seq = 42;

    // Seal the same message twice with same parameters
    let frame1 = FcpcFrame::seal(
        session_id,
        seq,
        SessionDirection::InitiatorToResponder,
        FcpcFrameFlags::default(),
        plaintext,
        &GOLDEN_K_CTX,
    )
    .expect("seal should succeed");

    let frame2 = FcpcFrame::seal(
        session_id,
        seq,
        SessionDirection::InitiatorToResponder,
        FcpcFrameFlags::default(),
        plaintext,
        &GOLDEN_K_CTX,
    )
    .expect("seal should succeed");

    // Both should produce identical output (deterministic AEAD)
    assert_eq!(frame1.encode(), frame2.encode());
}

#[test]
fn frame_open_wrong_key_fails() {
    let session_id = MeshSessionId(GOLDEN_SESSION_ID);
    let plaintext = b"secret message";
    let dir = SessionDirection::InitiatorToResponder;

    let frame = FcpcFrame::seal(
        session_id,
        1,
        dir,
        FcpcFrameFlags::default(),
        plaintext,
        &GOLDEN_K_CTX,
    )
    .expect("seal should succeed");

    // Try to open with a different key
    let wrong_key: [u8; 32] = [
        0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1,
        0xF0, 0xEF, 0xEE, 0xED, 0xEC, 0xEB, 0xEA, 0xE9, 0xE8, 0xE7, 0xE6, 0xE5, 0xE4, 0xE3, 0xE2,
        0xE1, 0xE0,
    ];

    let result = frame.open(dir, &wrong_key);
    assert!(result.is_err(), "open with wrong key should fail AEAD");
}

// ============================================================================
// Replay Window Tests
// ============================================================================

#[test]
fn replay_window_accepts_new_sequence() {
    let session_id = MeshSessionId(GOLDEN_SESSION_ID);
    let dir = SessionDirection::InitiatorToResponder;
    let frame = FcpcFrame::seal(
        session_id,
        1,
        dir,
        FcpcFrameFlags::default(),
        b"msg",
        &GOLDEN_K_CTX,
    )
    .expect("seal should succeed");

    let mut window = fcp_protocol::default_replay_window();
    frame
        .check_replay(&mut window)
        .expect("new sequence should be accepted");
}

#[test]
fn replay_window_rejects_duplicate() {
    let session_id = MeshSessionId(GOLDEN_SESSION_ID);
    let dir = SessionDirection::InitiatorToResponder;
    let frame = FcpcFrame::seal(
        session_id,
        1,
        dir,
        FcpcFrameFlags::default(),
        b"msg",
        &GOLDEN_K_CTX,
    )
    .expect("seal should succeed");

    let mut window = fcp_protocol::default_replay_window();
    frame.check_replay(&mut window).expect("first accepted");
    let err = frame
        .check_replay(&mut window)
        .expect_err("duplicate should be rejected");
    assert!(matches!(
        err,
        fcp_protocol::FcpcError::ReplayRejected { .. }
    ));
}

#[test]
fn replay_window_accepts_out_of_order_within_window() {
    let session_id = MeshSessionId(GOLDEN_SESSION_ID);
    let dir = SessionDirection::InitiatorToResponder;

    let frame100 = FcpcFrame::seal(
        session_id,
        100,
        dir,
        FcpcFrameFlags::default(),
        b"m1",
        &GOLDEN_K_CTX,
    )
    .expect("seal should succeed");
    let frame90 = FcpcFrame::seal(
        session_id,
        90,
        dir,
        FcpcFrameFlags::default(),
        b"m2",
        &GOLDEN_K_CTX,
    )
    .expect("seal should succeed");

    let mut window = fcp_protocol::default_replay_window();

    // Accept 100 first
    frame100
        .check_replay(&mut window)
        .expect("seq 100 accepted");

    // Accept 90 (within window)
    frame90
        .check_replay(&mut window)
        .expect("seq 90 accepted (within window)");
}

#[test]
fn replay_window_rejects_stale_sequence() {
    let session_id = MeshSessionId(GOLDEN_SESSION_ID);
    let dir = SessionDirection::InitiatorToResponder;

    // Push the window forward past what seq=1 would be in
    let frame_high = FcpcFrame::seal(
        session_id,
        1000,
        dir,
        FcpcFrameFlags::default(),
        b"high",
        &GOLDEN_K_CTX,
    )
    .expect("seal should succeed");
    let frame_stale = FcpcFrame::seal(
        session_id,
        1,
        dir,
        FcpcFrameFlags::default(),
        b"stale",
        &GOLDEN_K_CTX,
    )
    .expect("seal should succeed");

    let mut window = fcp_protocol::default_replay_window();

    // Accept high sequence to advance window
    frame_high.check_replay(&mut window).expect("high accepted");

    // seq=1 is now too old (outside the 128-entry window)
    let err = frame_stale
        .check_replay(&mut window)
        .expect_err("stale sequence should be rejected");
    assert!(matches!(
        err,
        fcp_protocol::FcpcError::ReplayRejected { .. }
    ));
}

// ============================================================================
// DoS Resistance Tests
// ============================================================================

#[test]
fn dos_reject_payload_too_large() {
    let session_id = MeshSessionId(GOLDEN_SESSION_ID);
    let dir = SessionDirection::InitiatorToResponder;
    let frame = FcpcFrame::seal(
        session_id,
        1,
        dir,
        FcpcFrameFlags::default(),
        b"data",
        &GOLDEN_K_CTX,
    )
    .expect("seal should succeed");

    let bytes = frame.encode();

    // Very strict limit that rejects any payload
    let err = FcpcFrame::decode_with_limit(&bytes, 1).expect_err("should reject large payload");
    assert!(matches!(
        err,
        fcp_protocol::FcpcError::PayloadTooLarge { .. }
    ));
}

#[test]
fn dos_reject_truncated_tag() {
    let session_id = MeshSessionId(GOLDEN_SESSION_ID);
    let frame = FcpcFrame::seal(
        session_id,
        1,
        SessionDirection::InitiatorToResponder,
        FcpcFrameFlags::default(),
        b"data",
        &GOLDEN_K_CTX,
    )
    .expect("seal should succeed");

    let mut bytes = frame.encode();
    bytes.truncate(bytes.len() - 1); // Remove last byte of tag

    let err = FcpcFrame::decode(&bytes).expect_err("should reject truncated tag");
    assert!(matches!(
        err,
        fcp_protocol::FcpcError::LengthMismatch { .. }
    ));
}

#[test]
fn dos_tampered_ciphertext_fails_aead() {
    let session_id = MeshSessionId(GOLDEN_SESSION_ID);
    let dir = SessionDirection::InitiatorToResponder;
    let frame = FcpcFrame::seal(
        session_id,
        1,
        dir,
        FcpcFrameFlags::default(),
        b"secret",
        &GOLDEN_K_CTX,
    )
    .expect("seal should succeed");

    // Tamper with ciphertext
    let mut tampered_frame = frame;
    if !tampered_frame.ciphertext.is_empty() {
        tampered_frame.ciphertext[0] ^= 0xFF;
    }

    let err = tampered_frame
        .open(dir, &GOLDEN_K_CTX)
        .expect_err("tampered ciphertext should fail");
    assert!(matches!(err, fcp_protocol::FcpcError::Crypto(_)));
}

#[test]
fn dos_tampered_tag_fails_aead() {
    let session_id = MeshSessionId(GOLDEN_SESSION_ID);
    let frame = FcpcFrame::seal(
        session_id,
        1,
        SessionDirection::InitiatorToResponder,
        FcpcFrameFlags::default(),
        b"secret",
        &GOLDEN_K_CTX,
    )
    .expect("seal should succeed");

    // Tamper with tag
    let mut tampered_frame = frame;
    tampered_frame.tag[0] ^= 0xFF;

    let err = tampered_frame
        .open(SessionDirection::InitiatorToResponder, &GOLDEN_K_CTX)
        .expect_err("tampered tag should fail");
    assert!(matches!(err, fcp_protocol::FcpcError::Crypto(_)));
}

// ============================================================================
// Reference Vector Generation
// ============================================================================

#[test]
fn generate_fcpc_reference_vectors() {
    // This test generates reference vectors that can be used by other
    // implementations for interoperability testing.

    eprintln!("\n=== FCPC Reference Vectors ===\n");

    // Header vector
    let header = FcpcFrameHeader {
        version: 1,
        session_id: MeshSessionId(GOLDEN_SESSION_ID),
        seq: 100,
        flags: FcpcFrameFlags::ENCRYPTED,
        len: 28,
    };
    eprintln!("Header bytes (hex):\n{}", hex::encode(header.encode()));

    // Full frame vector
    let session_id = MeshSessionId(GOLDEN_SESSION_ID);
    let plaintext = b"FCP2 Control Plane Reference";

    let frame = FcpcFrame::seal(
        session_id,
        100,
        SessionDirection::InitiatorToResponder,
        FcpcFrameFlags::default(),
        plaintext,
        &GOLDEN_K_CTX,
    )
    .expect("seal should succeed");

    eprintln!("\nSession ID (hex): {}", hex::encode(session_id.as_bytes()));
    eprintln!("k_ctx (hex): {}", hex::encode(GOLDEN_K_CTX));
    eprintln!("Seq: 100");
    eprintln!("Plaintext: {}", String::from_utf8_lossy(plaintext));
    eprintln!("Plaintext (hex): {}", hex::encode(plaintext));
    eprintln!("Encoded frame (hex): {}", hex::encode(frame.encode()));
    eprintln!("Ciphertext (hex): {}", hex::encode(&frame.ciphertext));
    eprintln!("Auth tag (hex): {}", hex::encode(frame.tag));

    eprintln!("\n=== End FCPC Reference Vectors ===\n");
}
