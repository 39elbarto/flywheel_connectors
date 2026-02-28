//! FCPS datagram envelope golden vectors.
//!
//! These vectors test the FCPS datagram encoding/decoding and MAC verification.
//!
//! # Wire Format (NORMATIVE)
//!
//! ```text
//! FCPS DATAGRAM ENVELOPE
//!
//!   Bytes 0-15:   Session ID (16 bytes)
//!   Bytes 16-23:  Sequence number (u64 LE)
//!   Bytes 24-39:  MAC (16 bytes, truncated HMAC-SHA256 or BLAKE3-keyed)
//!   Bytes 40+:    Frame bytes (variable, may be empty)
//!
//!   Fixed header: 40 bytes (FCPS_DATAGRAM_HEADER_LEN)
//!   Default max datagram: 1200 bytes (DEFAULT_MAX_DATAGRAM_BYTES)
//! ```
//!
//! # MAC Computation (NORMATIVE)
//!
//! ```text
//! mac_input = session_id || direction_byte || seq_le || frame_bytes
//!
//! Suite1: HMAC-SHA256(mac_key, mac_input)[0..16]
//! Suite2: BLAKE3_keyed(mac_key, mac_input)[0..16]
//! ```

use serde::{Deserialize, Serialize};

/// Golden vector for FCPS datagram envelope encoding/decoding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatagramGoldenVector {
    /// Human-readable description of the test case.
    pub description: String,
    /// Session ID (16 bytes hex).
    pub session_id: String,
    /// Sequence number.
    pub seq: u64,
    /// MAC (16 bytes hex).
    pub mac: String,
    /// Frame payload bytes (hex, may be empty).
    pub frame_bytes: String,
    /// Expected full encoded datagram (hex).
    pub expected_encoded: String,
}

/// Golden vector for FCPS datagram MAC computation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatagramMacGoldenVector {
    /// Human-readable description of the test case.
    pub description: String,
    /// Crypto suite name ("Suite1" for HMAC-SHA256, "Suite2" for BLAKE3-keyed).
    pub suite: String,
    /// MAC key (32 bytes hex).
    pub mac_key: String,
    /// Session ID (16 bytes hex).
    pub session_id: String,
    /// Direction: "InitiatorToResponder" (0x00) or "ResponderToInitiator" (0x01).
    pub direction: String,
    /// Sequence number.
    pub seq: u64,
    /// Frame payload bytes (hex).
    pub frame_bytes: String,
    /// Expected MAC (16 bytes hex).
    pub expected_mac: String,
}

/// Golden vector for datagram decode error cases.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatagramErrorVector {
    /// Human-readable description of the test case.
    pub description: String,
    /// Raw input bytes (hex).
    pub input_bytes: String,
    /// Max datagram limit to apply.
    pub max_datagram_bytes: u16,
    /// Expected error kind: "TooShort" or "TooLarge".
    pub expected_error: String,
}

impl DatagramGoldenVector {
    /// Load all datagram encoding golden vectors.
    #[must_use]
    pub fn load_all() -> Vec<Self> {
        vec![
            Self::vector_1_minimal_empty_frame(),
            Self::vector_2_with_payload(),
            Self::vector_3_max_seq(),
        ]
    }

    /// Vector 1: Minimal datagram with empty frame (header-only).
    #[must_use]
    pub fn vector_1_minimal_empty_frame() -> Self {
        // session_id = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        //               0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]
        let session_id = "deadbeefcafebabe0123456789abcdef";
        let seq: u64 = 0;
        let mac = "00000000000000000000000000000000";
        let frame_bytes = "";

        // Expected encoding: session_id(16) || seq_le(8) || mac(16) = 40 bytes
        let mut expected = String::new();
        expected.push_str(session_id);
        expected.push_str(&hex::encode(seq.to_le_bytes()));
        expected.push_str(mac);

        Self {
            description: "Minimal datagram with empty frame (header-only, 40 bytes)".into(),
            session_id: session_id.into(),
            seq,
            mac: mac.into(),
            frame_bytes: frame_bytes.into(),
            expected_encoded: expected,
        }
    }

    /// Vector 2: Datagram with a small frame payload.
    #[must_use]
    pub fn vector_2_with_payload() -> Self {
        let session_id = "0102030405060708090a0b0c0d0e0f10";
        let seq: u64 = 42;
        let mac = "abababababababababababababababab";
        let frame_bytes = "48656c6c6f2c20464350532100"; // "Hello, FCPS!\0"

        let mut expected = String::new();
        expected.push_str(session_id);
        expected.push_str(&hex::encode(seq.to_le_bytes()));
        expected.push_str(mac);
        expected.push_str(frame_bytes);

        Self {
            description: "Datagram with 'Hello, FCPS!' payload (seq=42)".into(),
            session_id: session_id.into(),
            seq,
            mac: mac.into(),
            frame_bytes: frame_bytes.into(),
            expected_encoded: expected,
        }
    }

    /// Vector 3: Datagram with max sequence number.
    #[must_use]
    pub fn vector_3_max_seq() -> Self {
        let session_id = "ffffffffffffffffffffffffffffffff";
        let seq: u64 = u64::MAX;
        let mac = "0123456789abcdef0123456789abcdef";
        let frame_bytes = "deadbeef";

        let mut expected = String::new();
        expected.push_str(session_id);
        expected.push_str(&hex::encode(seq.to_le_bytes()));
        expected.push_str(mac);
        expected.push_str(frame_bytes);

        Self {
            description: "Datagram with max seq (u64::MAX) and small payload".into(),
            session_id: session_id.into(),
            seq,
            mac: mac.into(),
            frame_bytes: frame_bytes.into(),
            expected_encoded: expected,
        }
    }
}

impl DatagramMacGoldenVector {
    /// Load all datagram MAC golden vectors.
    #[must_use]
    pub fn load_all() -> Vec<Self> {
        use fcp_protocol::{
            MeshSessionId, SessionCryptoSuite, SessionDirection, compute_session_mac,
        };

        let mac_key_hex = "0101010101010101010101010101010101010101010101010101010101010101";
        let mac_key_bytes = hex::decode(mac_key_hex).unwrap();
        let mac_key: [u8; 32] = mac_key_bytes.try_into().unwrap();

        let session_id_hex = "deadbeefcafebabe0123456789abcdef";
        let session_id_bytes: [u8; 16] = hex::decode(session_id_hex).unwrap().try_into().unwrap();
        let session_id = MeshSessionId(session_id_bytes);

        let frame_payload = b"test-frame-payload";

        // Suite1 / Initiator-to-Responder
        let mac_s1_i2r = compute_session_mac(
            SessionCryptoSuite::Suite1,
            &mac_key,
            &session_id,
            SessionDirection::InitiatorToResponder,
            1,
            frame_payload,
        )
        .unwrap();

        // Suite1 / Responder-to-Initiator
        let mac_s1_r2i = compute_session_mac(
            SessionCryptoSuite::Suite1,
            &mac_key,
            &session_id,
            SessionDirection::ResponderToInitiator,
            1,
            frame_payload,
        )
        .unwrap();

        // Suite2 / Initiator-to-Responder
        let mac_s2_i2r = compute_session_mac(
            SessionCryptoSuite::Suite2,
            &mac_key,
            &session_id,
            SessionDirection::InitiatorToResponder,
            1,
            frame_payload,
        )
        .unwrap();

        // Suite2 / Responder-to-Initiator (seq=1000)
        let mac_s2_r2i_1000 = compute_session_mac(
            SessionCryptoSuite::Suite2,
            &mac_key,
            &session_id,
            SessionDirection::ResponderToInitiator,
            1000,
            frame_payload,
        )
        .unwrap();

        vec![
            Self {
                description: "Suite1 HMAC-SHA256 MAC, initiator-to-responder, seq=1".into(),
                suite: "Suite1".into(),
                mac_key: mac_key_hex.into(),
                session_id: session_id_hex.into(),
                direction: "InitiatorToResponder".into(),
                seq: 1,
                frame_bytes: hex::encode(frame_payload),
                expected_mac: hex::encode(mac_s1_i2r),
            },
            Self {
                description: "Suite1 HMAC-SHA256 MAC, responder-to-initiator, seq=1".into(),
                suite: "Suite1".into(),
                mac_key: mac_key_hex.into(),
                session_id: session_id_hex.into(),
                direction: "ResponderToInitiator".into(),
                seq: 1,
                frame_bytes: hex::encode(frame_payload),
                expected_mac: hex::encode(mac_s1_r2i),
            },
            Self {
                description: "Suite2 BLAKE3-keyed MAC, initiator-to-responder, seq=1".into(),
                suite: "Suite2".into(),
                mac_key: mac_key_hex.into(),
                session_id: session_id_hex.into(),
                direction: "InitiatorToResponder".into(),
                seq: 1,
                frame_bytes: hex::encode(frame_payload),
                expected_mac: hex::encode(mac_s2_i2r),
            },
            Self {
                description: "Suite2 BLAKE3-keyed MAC, responder-to-initiator, seq=1000".into(),
                suite: "Suite2".into(),
                mac_key: mac_key_hex.into(),
                session_id: session_id_hex.into(),
                direction: "ResponderToInitiator".into(),
                seq: 1000,
                frame_bytes: hex::encode(frame_payload),
                expected_mac: hex::encode(mac_s2_r2i_1000),
            },
        ]
    }
}

impl DatagramErrorVector {
    /// Load all datagram error case vectors.
    #[must_use]
    pub fn load_all() -> Vec<Self> {
        vec![
            Self {
                description: "Empty input (0 bytes) rejected as too short".into(),
                input_bytes: String::new(),
                max_datagram_bytes: 1200,
                expected_error: "TooShort".into(),
            },
            Self {
                description: "39 bytes (one byte short of header) rejected".into(),
                input_bytes: hex::encode([0u8; 39]),
                max_datagram_bytes: 1200,
                expected_error: "TooShort".into(),
            },
            Self {
                description: "1201 bytes exceeds default 1200 limit".into(),
                input_bytes: hex::encode([0u8; 1201]),
                max_datagram_bytes: 1200,
                expected_error: "TooLarge".into(),
            },
            Self {
                description: "101 bytes exceeds custom 100-byte limit".into(),
                input_bytes: hex::encode([0u8; 101]),
                max_datagram_bytes: 100,
                expected_error: "TooLarge".into(),
            },
        ]
    }
}
