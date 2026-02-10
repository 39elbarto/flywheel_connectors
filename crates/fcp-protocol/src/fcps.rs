//! FCPS (Flywheel Connector Protocol - Symbol) frame parsing and serialization.
//!
//! Implements the normative data-plane frame format defined in `FCP_Specification_V2.md` §4.3.
//!
//! # Wire Format
//!
//! ```text
//! FCPS FRAME FORMAT (Symbol-Native)
//!
//!   Bytes 0-3:    Magic (0x46 0x43 0x50 0x53 = "FCPS")
//!   Bytes 4-5:    Version (u16 LE)
//!   Bytes 6-7:    Flags (u16 LE)
//!   Bytes 8-11:   Symbol Count (u32 LE)
//!   Bytes 12-15:  Total Payload Length (u32 LE)
//!   Bytes 16-47:  Object ID (32 bytes)
//!   Bytes 48-49:  Symbol Size (u16 LE, default 1024)
//!   Bytes 50-57:  Zone Key ID (8 bytes, for rotation)
//!   Bytes 58-89:  Zone ID hash (32 bytes, BLAKE3; see section 3.4)
//!   Bytes 90-97:  Epoch ID (u64 LE)
//!   Bytes 98-105: Sender Instance ID (u64 LE, reboot-safety for nonces)
//!   Bytes 106-113: Frame Seq (u64 LE, per-sender monotonic)
//!   Bytes 114+:   Symbol payloads (concatenated)
//!
//!   Fixed header: 114 bytes
//!   Each symbol: 4 (ESI) + 2 (K) + N (data) + 16 (auth_tag)
//! ```

use bitflags::bitflags;
use fcp_core::{ObjectHeader, ObjectId, TailscaleNodeId, ZoneId, ZoneIdHash, ZoneKeyId};
use fcp_crypto::{CryptoError, Ed25519Signature, Ed25519SigningKey, Ed25519VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// FCPS magic bytes: "FCPS"
pub const FCPS_MAGIC: [u8; 4] = [0x46, 0x43, 0x50, 0x53];

/// Current FCPS version.
pub const FCPS_VERSION: u16 = 1;

/// Fixed header length in bytes.
pub const FCPS_HEADER_LEN: usize = 114;

/// Default symbol size in bytes.
pub const DEFAULT_SYMBOL_SIZE: u16 = 1024;

/// Per-symbol overhead: ESI (4) + K (2) + `auth_tag` (16) = 22 bytes
pub const SYMBOL_RECORD_OVERHEAD: usize = 22;

bitflags! {
    /// FCPS frame flags (NORMATIVE).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FrameFlags: u16 {
        /// Requires acknowledgment from receiver.
        const REQUIRES_ACK      = 0b0000_0000_0001;
        /// Payload is zstd compressed.
        const COMPRESSED        = 0b0000_0000_0010;
        /// Symbols are zone-encrypted.
        const ENCRYPTED         = 0b0000_0000_0100;
        /// Response to a previous request.
        const RESPONSE          = 0b0000_0000_1000;
        /// Error response frame.
        const ERROR             = 0b0000_0001_0000;
        /// Part of a streaming transfer.
        const STREAMING         = 0b0000_0010_0000;
        /// Final frame in a stream.
        const STREAM_END        = 0b0000_0100_0000;
        /// Contains an embedded capability token.
        const HAS_CAP_TOKEN     = 0b0000_1000_0000;
        /// Frame crosses zone boundaries.
        const ZONE_CROSSING     = 0b0001_0000_0000;
        /// High priority frame.
        const PRIORITY          = 0b0010_0000_0000;
        /// RaptorQ encoded (default for fountain codes).
        const RAPTORQ           = 0b0100_0000_0000;
        /// Control plane object (routed differently).
        const CONTROL_PLANE     = 0b1000_0000_0000;
    }
}

impl Default for FrameFlags {
    fn default() -> Self {
        // Default: encrypted + RaptorQ encoded
        Self::ENCRYPTED | Self::RAPTORQ
    }
}

/// FCPS frame parsing and validation errors.
#[derive(Debug, Error)]
pub enum FrameError {
    #[error("frame too short (len {len}, min {min})")]
    TooShort { len: usize, min: usize },

    #[error("frame exceeds MTU (len {len}, max {max})")]
    ExceedsMtu { len: usize, max: usize },

    #[error("invalid magic bytes (expected FCPS, got {got:?})")]
    InvalidMagic { got: [u8; 4] },

    #[error("unsupported version {version}")]
    UnsupportedVersion { version: u16 },

    #[error("payload length mismatch (claimed {claimed}, computed {computed})")]
    LengthMismatch { claimed: usize, computed: usize },

    #[error("frame size mismatch (header + payload != frame len)")]
    FrameSizeMismatch,

    #[error("symbol count overflow")]
    SymbolCountOverflow,

    #[error("invalid symbol size (must be > 0)")]
    InvalidSymbolSize,

    #[error("invalid utf-8 string")]
    InvalidUtf8,
}

/// Parsed FCPS frame header (114 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FcpsFrameHeader {
    /// Protocol version (currently 1).
    pub version: u16,
    /// Frame flags.
    pub flags: FrameFlags,
    /// Number of symbol records in the payload.
    pub symbol_count: u32,
    /// Total payload length in bytes.
    pub total_payload_len: u32,
    /// Content-addressed object ID (32 bytes).
    pub object_id: ObjectId,
    /// Symbol size in bytes (default 1024).
    pub symbol_size: u16,
    /// Zone key ID for key rotation (8 bytes).
    pub zone_key_id: ZoneKeyId,
    /// Zone ID hash (32 bytes, BLAKE3).
    pub zone_id_hash: ZoneIdHash,
    /// Epoch ID for replay protection (u64 LE in wire format).
    pub epoch_id: u64,
    /// Sender instance ID (random u64 at startup, for reboot safety).
    pub sender_instance_id: u64,
    /// Per-sender monotonic frame sequence number.
    pub frame_seq: u64,
}

impl FcpsFrameHeader {
    /// Encode the header to bytes (114 bytes).
    #[must_use]
    pub fn encode(&self) -> [u8; FCPS_HEADER_LEN] {
        let mut buf = [0u8; FCPS_HEADER_LEN];

        buf[0..4].copy_from_slice(&FCPS_MAGIC);
        buf[4..6].copy_from_slice(&self.version.to_le_bytes());
        buf[6..8].copy_from_slice(&self.flags.bits().to_le_bytes());
        buf[8..12].copy_from_slice(&self.symbol_count.to_le_bytes());
        buf[12..16].copy_from_slice(&self.total_payload_len.to_le_bytes());
        buf[16..48].copy_from_slice(self.object_id.as_bytes());
        buf[48..50].copy_from_slice(&self.symbol_size.to_le_bytes());
        buf[50..58].copy_from_slice(self.zone_key_id.as_bytes());
        buf[58..90].copy_from_slice(self.zone_id_hash.as_bytes());
        buf[90..98].copy_from_slice(&self.epoch_id.to_le_bytes());
        buf[98..106].copy_from_slice(&self.sender_instance_id.to_le_bytes());
        buf[106..114].copy_from_slice(&self.frame_seq.to_le_bytes());

        buf
    }

    /// Decode a header from bytes.
    ///
    /// # Errors
    /// Returns `FrameError` if the header is malformed.
    pub fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        if bytes.len() < FCPS_HEADER_LEN {
            return Err(FrameError::TooShort {
                len: bytes.len(),
                min: FCPS_HEADER_LEN,
            });
        }

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&bytes[0..4]);
        if magic != FCPS_MAGIC {
            return Err(FrameError::InvalidMagic { got: magic });
        }

        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        if version != FCPS_VERSION {
            return Err(FrameError::UnsupportedVersion { version });
        }

        let flags_bits = u16::from_le_bytes([bytes[6], bytes[7]]);
        let flags = FrameFlags::from_bits_truncate(flags_bits);

        let symbol_count_bytes: [u8; 4] =
            bytes[8..12].try_into().map_err(|_| FrameError::TooShort {
                len: bytes.len(),
                min: FCPS_HEADER_LEN,
            })?;
        let symbol_count = u32::from_le_bytes(symbol_count_bytes);
        let total_payload_len_bytes: [u8; 4] =
            bytes[12..16].try_into().map_err(|_| FrameError::TooShort {
                len: bytes.len(),
                min: FCPS_HEADER_LEN,
            })?;
        let total_payload_len = u32::from_le_bytes(total_payload_len_bytes);

        let mut object_id_bytes = [0u8; 32];
        object_id_bytes.copy_from_slice(&bytes[16..48]);
        let object_id = ObjectId::from_bytes(object_id_bytes);

        let symbol_size = u16::from_le_bytes([bytes[48], bytes[49]]);
        if symbol_size == 0 {
            return Err(FrameError::InvalidSymbolSize);
        }

        let mut zone_key_id_bytes = [0u8; 8];
        zone_key_id_bytes.copy_from_slice(&bytes[50..58]);
        let zone_key_id = ZoneKeyId::from_bytes(zone_key_id_bytes);

        let mut zone_id_hash_bytes = [0u8; 32];
        zone_id_hash_bytes.copy_from_slice(&bytes[58..90]);
        let zone_id_hash = ZoneIdHash::from_bytes(zone_id_hash_bytes);

        let epoch_id_bytes: [u8; 8] =
            bytes[90..98].try_into().map_err(|_| FrameError::TooShort {
                len: bytes.len(),
                min: FCPS_HEADER_LEN,
            })?;
        let sender_instance_id_bytes: [u8; 8] =
            bytes[98..106]
                .try_into()
                .map_err(|_| FrameError::TooShort {
                    len: bytes.len(),
                    min: FCPS_HEADER_LEN,
                })?;
        let frame_seq_bytes: [u8; 8] =
            bytes[106..114]
                .try_into()
                .map_err(|_| FrameError::TooShort {
                    len: bytes.len(),
                    min: FCPS_HEADER_LEN,
                })?;
        let epoch_id = u64::from_le_bytes(epoch_id_bytes);
        let sender_instance_id = u64::from_le_bytes(sender_instance_id_bytes);
        let frame_seq = u64::from_le_bytes(frame_seq_bytes);

        Ok(Self {
            version,
            flags,
            symbol_count,
            total_payload_len,
            object_id,
            symbol_size,
            zone_key_id,
            zone_id_hash,
            epoch_id,
            sender_instance_id,
            frame_seq,
        })
    }
}

/// Symbol record within an FCPS frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolRecord {
    /// Encoding Symbol ID (position in fountain code).
    pub esi: u32,
    /// Total source symbols needed (K).
    pub k: u16,
    /// Encrypted symbol payload.
    pub data: Vec<u8>,
    /// AEAD authentication tag (16 bytes).
    pub auth_tag: [u8; 16],
}

impl SymbolRecord {
    /// Wire size of this record.
    #[must_use]
    pub fn wire_size(&self) -> usize {
        SYMBOL_RECORD_OVERHEAD + self.data.len()
    }

    /// Encode the record to bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.wire_size());
        buf.extend_from_slice(&self.esi.to_le_bytes());
        buf.extend_from_slice(&self.k.to_le_bytes());
        buf.extend_from_slice(&self.data);
        buf.extend_from_slice(&self.auth_tag);
        buf
    }

    /// Decode a symbol record from bytes given the expected symbol size.
    ///
    /// # Errors
    /// Returns `FrameError::TooShort` if buffer is insufficient.
    pub fn decode(bytes: &[u8], symbol_size: u16) -> Result<Self, FrameError> {
        let expected_len = SYMBOL_RECORD_OVERHEAD + symbol_size as usize;
        if bytes.len() < expected_len {
            return Err(FrameError::TooShort {
                len: bytes.len(),
                min: expected_len,
            });
        }

        let esi_bytes: [u8; 4] = bytes[0..4].try_into().map_err(|_| FrameError::TooShort {
            len: bytes.len(),
            min: expected_len,
        })?;
        let k_bytes: [u8; 2] = bytes[4..6].try_into().map_err(|_| FrameError::TooShort {
            len: bytes.len(),
            min: expected_len,
        })?;
        let esi = u32::from_le_bytes(esi_bytes);
        let k = u16::from_le_bytes(k_bytes);

        let data_end = 6 + symbol_size as usize;
        let data = bytes[6..data_end].to_vec();

        let mut auth_tag = [0u8; 16];
        auth_tag.copy_from_slice(&bytes[data_end..data_end + 16]);

        Ok(Self {
            esi,
            k,
            data,
            auth_tag,
        })
    }
}

/// Complete FCPS frame (header + symbol records).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FcpsFrame {
    /// Frame header.
    pub header: FcpsFrameHeader,
    /// Symbol records.
    pub symbols: Vec<SymbolRecord>,
}

impl FcpsFrame {
    /// Encode the complete frame to bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let header_bytes = self.header.encode();
        let payload_len: usize = self.symbols.iter().map(SymbolRecord::wire_size).sum();

        // Ensure header claim matches actual payload
        debug_assert_eq!(
            self.header.total_payload_len as usize, payload_len,
            "header.total_payload_len mismatch"
        );

        let mut buf = Vec::with_capacity(FCPS_HEADER_LEN + payload_len);
        buf.extend_from_slice(&header_bytes);
        for symbol in &self.symbols {
            buf.extend_from_slice(&symbol.encode());
        }
        buf
    }

    /// Decode a complete frame from bytes with MTU enforcement.
    ///
    /// # Errors
    /// Returns `FrameError` if the frame is malformed or exceeds MTU.
    pub fn decode(bytes: &[u8], max_datagram_bytes: usize) -> Result<Self, FrameError> {
        if bytes.len() > max_datagram_bytes {
            return Err(FrameError::ExceedsMtu {
                len: bytes.len(),
                max: max_datagram_bytes,
            });
        }

        let header = FcpsFrameHeader::decode(bytes)?;
        validate_frame_lengths(bytes, &header)?;

        let mut symbols = Vec::with_capacity(header.symbol_count as usize);
        let record_size = SYMBOL_RECORD_OVERHEAD + header.symbol_size as usize;
        let mut offset = FCPS_HEADER_LEN;

        for _ in 0..header.symbol_count {
            let record = SymbolRecord::decode(&bytes[offset..], header.symbol_size)?;
            symbols.push(record);
            offset += record_size;
        }

        Ok(Self { header, symbols })
    }
}

/// Validate FCPS frame lengths for `DoS` resistance (NORMATIVE).
///
/// # Errors
/// Returns `FrameError` if computed lengths do not match declared values.
pub fn validate_frame_lengths(bytes: &[u8], header: &FcpsFrameHeader) -> Result<(), FrameError> {
    // Check for overflow when computing expected payload
    let record_size = SYMBOL_RECORD_OVERHEAD
        .checked_add(header.symbol_size as usize)
        .ok_or(FrameError::SymbolCountOverflow)?;

    let expected_payload = (header.symbol_count as usize)
        .checked_mul(record_size)
        .ok_or(FrameError::SymbolCountOverflow)?;

    if header.total_payload_len as usize != expected_payload {
        return Err(FrameError::LengthMismatch {
            claimed: header.total_payload_len as usize,
            computed: expected_payload,
        });
    }

    let expected_total = FCPS_HEADER_LEN
        .checked_add(expected_payload)
        .ok_or(FrameError::SymbolCountOverflow)?;

    if bytes.len() != expected_total {
        return Err(FrameError::FrameSizeMismatch);
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// DecodeStatus - Flow Control Feedback (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum number of missing ESI hints allowed (bounded for `DoS` resistance).
pub const MAX_MISSING_HINT_ENTRIES: usize = 100;

/// Default limit for unauthenticated symbol requests (NORMATIVE).
pub const DEFAULT_MAX_SYMBOLS_UNAUTHENTICATED: u32 = 32;

/// Decode status feedback for flow control (NORMATIVE).
///
/// Enables receivers to tell senders how many symbols have been received and
/// how many more are needed to complete decoding. This supports targeted repair
/// and flow control in the symbol distribution layer.
///
/// # Anti-Amplification Rule (NORMATIVE)
///
/// `MeshNodes` MUST NOT send more than N symbols in response to a request unless:
/// 1. The requester is authenticated (session MAC or node signature), AND
/// 2. The request includes a bounded `missing_hint` or comparable proof-of-need
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodeStatus {
    /// Object header for context.
    pub header: ObjectHeader,
    /// Content-addressed object ID.
    pub object_id: ObjectId,
    /// Zone for the object.
    pub zone_id: ZoneId,
    /// Zone key ID (for key rotation).
    pub zone_key_id: ZoneKeyId,
    /// Epoch ID for replay protection.
    pub epoch_id: u64,
    /// Unique symbols received so far for this object.
    pub received_unique: u32,
    /// Target required to decode (K-prime).
    /// K-prime is approximately K × 1.002 for `RaptorQ`.
    pub needed: u32,
    /// Success flag: true if object has been fully decoded.
    pub complete: bool,
    /// Optional hint about missing ESIs for targeted repair.
    /// MUST be bounded (max `MAX_MISSING_HINT_ENTRIES` entries).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub missing_hint: Option<Vec<u32>>,
    /// Ed25519 signature by the receiving node over the status.
    pub signature: Ed25519Signature,
}

impl DecodeStatus {
    /// Compute the signature transcript bytes (signature excluded).
    #[must_use]
    pub fn transcript_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"FCP2-DECODE-STATUS-V1");
        buf.extend_from_slice(self.object_id.as_bytes());
        buf.extend_from_slice(self.zone_id.as_bytes());
        buf.extend_from_slice(self.zone_key_id.as_bytes());
        buf.extend_from_slice(&self.epoch_id.to_le_bytes());
        buf.extend_from_slice(&self.received_unique.to_le_bytes());
        buf.extend_from_slice(&self.needed.to_le_bytes());
        buf.push(u8::from(self.complete));

        // Include missing_hint count and entries if present
        if let Some(ref hints) = self.missing_hint {
            let hint_len = u32::try_from(hints.len()).unwrap_or(u32::MAX);
            buf.extend_from_slice(&hint_len.to_le_bytes());
            for esi in hints {
                buf.extend_from_slice(&esi.to_le_bytes());
            }
        } else {
            buf.extend_from_slice(&0u32.to_le_bytes());
        }

        buf
    }

    /// Sign the decode status in-place.
    pub fn sign(&mut self, signing_key: &Ed25519SigningKey) {
        let transcript = self.transcript_bytes();
        self.signature = signing_key.sign(&transcript);
    }

    /// Verify the decode status signature.
    ///
    /// # Errors
    /// Returns `CryptoError` if signature verification fails.
    pub fn verify(&self, verifying_key: &Ed25519VerifyingKey) -> Result<(), CryptoError> {
        let transcript = self.transcript_bytes();
        verifying_key.verify(&transcript, &self.signature)
    }

    /// Validate that `missing_hint` is bounded (`DoS` resistance).
    ///
    /// # Errors
    /// Returns `FrameError::SymbolCountOverflow` if hint exceeds maximum entries.
    pub fn validate_hint_bounds(&self) -> Result<(), FrameError> {
        if let Some(ref hints) = self.missing_hint {
            if hints.len() > MAX_MISSING_HINT_ENTRIES {
                return Err(FrameError::SymbolCountOverflow);
            }
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SymbolAck - Stop Condition (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// Symbol acknowledgment for stop condition (NORMATIVE).
///
/// Sent by a receiver to tell the sender to stop transmitting symbols for
/// an object. This is typically sent when the object has been fully
/// reconstructed or when the receiver no longer needs the object.
///
/// # Wire Format
///
/// This is a control-plane object (ephemeral retention) sent via FCPC.
///
/// # Example
///
/// ```rust,ignore
/// use fcp_protocol::fcps::SymbolAck;
///
/// let ack = SymbolAck::new(header, object_id, zone_id, zone_key_id, epoch_id, reason);
/// ack.sign(&signing_key);
/// // Send via FCPC control plane
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolAck {
    /// Object header for context.
    pub header: ObjectHeader,
    /// Content-addressed object ID.
    pub object_id: ObjectId,
    /// Zone for the object.
    pub zone_id: ZoneId,
    /// Zone key ID (for key rotation).
    pub zone_key_id: ZoneKeyId,
    /// Epoch ID for replay protection.
    pub epoch_id: u64,
    /// Reason for the acknowledgment.
    pub reason: SymbolAckReason,
    /// Final count of unique symbols received (for metrics).
    pub final_symbol_count: u32,
    /// Ed25519 signature by the receiving node.
    pub signature: Ed25519Signature,
}

/// Reason for symbol acknowledgment (NORMATIVE).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolAckReason {
    /// Object successfully reconstructed.
    Complete,
    /// Receiver no longer needs the object (cancelled).
    Cancelled,
    /// Receiver detected duplicate/redundant transmission.
    Duplicate,
    /// Receiver's decode budget exceeded.
    BudgetExceeded,
}

impl SymbolAck {
    /// Create a new symbol acknowledgment.
    #[must_use]
    pub fn new(
        header: ObjectHeader,
        object_id: ObjectId,
        zone_id: ZoneId,
        zone_key_id: ZoneKeyId,
        epoch_id: u64,
        reason: SymbolAckReason,
        final_symbol_count: u32,
    ) -> Self {
        Self {
            header,
            object_id,
            zone_id,
            zone_key_id,
            epoch_id,
            reason,
            final_symbol_count,
            signature: Ed25519Signature::from_bytes(&[0u8; 64]),
        }
    }

    /// Compute the signature transcript bytes (signature excluded).
    #[must_use]
    pub fn transcript_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"FCP2-SYMBOL-ACK-V1");
        buf.extend_from_slice(self.object_id.as_bytes());
        buf.extend_from_slice(self.zone_id.as_bytes());
        buf.extend_from_slice(self.zone_key_id.as_bytes());
        buf.extend_from_slice(&self.epoch_id.to_le_bytes());
        buf.push(self.reason as u8);
        buf.extend_from_slice(&self.final_symbol_count.to_le_bytes());
        buf
    }

    /// Sign the symbol acknowledgment in-place.
    pub fn sign(&mut self, signing_key: &Ed25519SigningKey) {
        let transcript = self.transcript_bytes();
        self.signature = signing_key.sign(&transcript);
    }

    /// Verify the symbol acknowledgment signature.
    ///
    /// # Errors
    /// Returns `CryptoError` if signature verification fails.
    pub fn verify(&self, verifying_key: &Ed25519VerifyingKey) -> Result<(), CryptoError> {
        let transcript = self.transcript_bytes();
        verifying_key.verify(&transcript, &self.signature)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SymbolRequest - Bounded Request (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// Default maximum symbols for authenticated requests (NORMATIVE).
pub const DEFAULT_MAX_SYMBOLS_AUTHENTICATED: u32 = 1000;

/// Bounded symbol request (NORMATIVE).
///
/// A requester MUST bound requests with `max_symbols` and/or `missing_hint`.
/// A responder MUST NOT send more than `max_symbols` symbols in response.
///
/// # Anti-Amplification Rule (NORMATIVE)
///
/// Unauthenticated requests MUST be capped tighter (default 32 symbols)
/// unless zone policy allows. Accounting: request processing counts against
/// the requester's `PeerBudget` (bytes + CPU + inflight decodes).
///
/// # Wire Format
///
/// This is a control-plane object sent via FCPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolRequest {
    /// Object header for context.
    pub header: ObjectHeader,
    /// Content-addressed object ID being requested.
    pub object_id: ObjectId,
    /// Zone for the object.
    pub zone_id: ZoneId,
    /// Zone key ID (for key rotation).
    pub zone_key_id: ZoneKeyId,
    /// Epoch ID for replay protection.
    pub epoch_id: u64,
    /// Maximum symbols the requester wants (NORMATIVE bound).
    pub max_symbols: u32,
    /// Optional hint about specific ESIs needed (proof-of-need).
    /// MUST be bounded (max `MAX_MISSING_HINT_ENTRIES` entries).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub missing_hint: Option<Vec<u32>>,
    /// Current unique symbols the requester already has.
    pub current_symbols: u32,
    /// Ed25519 signature by the requesting node.
    pub signature: Ed25519Signature,
}

impl SymbolRequest {
    /// Create a new symbol request.
    #[must_use]
    pub fn new(
        header: ObjectHeader,
        object_id: ObjectId,
        zone_id: ZoneId,
        zone_key_id: ZoneKeyId,
        epoch_id: u64,
        max_symbols: u32,
        current_symbols: u32,
    ) -> Self {
        Self {
            header,
            object_id,
            zone_id,
            zone_key_id,
            epoch_id,
            max_symbols,
            missing_hint: None,
            current_symbols,
            signature: Ed25519Signature::from_bytes(&[0u8; 64]),
        }
    }

    /// Create a request with specific missing symbols (targeted repair).
    #[must_use]
    pub fn with_missing_hint(mut self, hint: Vec<u32>) -> Self {
        self.missing_hint = Some(hint);
        self
    }

    /// Compute the signature transcript bytes (signature excluded).
    #[must_use]
    pub fn transcript_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"FCP2-SYMBOL-REQ-V1");
        buf.extend_from_slice(self.object_id.as_bytes());
        buf.extend_from_slice(self.zone_id.as_bytes());
        buf.extend_from_slice(self.zone_key_id.as_bytes());
        buf.extend_from_slice(&self.epoch_id.to_le_bytes());
        buf.extend_from_slice(&self.max_symbols.to_le_bytes());
        buf.extend_from_slice(&self.current_symbols.to_le_bytes());

        // Include missing_hint count and entries if present
        if let Some(ref hints) = self.missing_hint {
            let hint_len = u32::try_from(hints.len()).unwrap_or(u32::MAX);
            buf.extend_from_slice(&hint_len.to_le_bytes());
            for esi in hints {
                buf.extend_from_slice(&esi.to_le_bytes());
            }
        } else {
            buf.extend_from_slice(&0u32.to_le_bytes());
        }

        buf
    }

    /// Sign the symbol request in-place.
    pub fn sign(&mut self, signing_key: &Ed25519SigningKey) {
        let transcript = self.transcript_bytes();
        self.signature = signing_key.sign(&transcript);
    }

    /// Verify the symbol request signature.
    ///
    /// # Errors
    /// Returns `CryptoError` if signature verification fails.
    pub fn verify(&self, verifying_key: &Ed25519VerifyingKey) -> Result<(), CryptoError> {
        let transcript = self.transcript_bytes();
        verifying_key.verify(&transcript, &self.signature)
    }

    /// Validate that `missing_hint` is bounded (`DoS` resistance).
    ///
    /// # Errors
    /// Returns `FrameError::SymbolCountOverflow` if hint exceeds maximum entries.
    pub fn validate_hint_bounds(&self) -> Result<(), FrameError> {
        if let Some(ref hints) = self.missing_hint {
            if hints.len() > MAX_MISSING_HINT_ENTRIES {
                return Err(FrameError::SymbolCountOverflow);
            }
        }
        Ok(())
    }

    /// Validate the request bounds (NORMATIVE).
    ///
    /// # Errors
    /// Returns `FrameError` if bounds are violated.
    pub fn validate_bounds(&self, is_authenticated: bool) -> Result<(), FrameError> {
        self.validate_hint_bounds()?;

        // Unauthenticated requests have stricter limits
        let max_allowed = if is_authenticated {
            DEFAULT_MAX_SYMBOLS_AUTHENTICATED
        } else {
            DEFAULT_MAX_SYMBOLS_UNAUTHENTICATED
        };

        if self.max_symbols > max_allowed {
            return Err(FrameError::SymbolCountOverflow);
        }

        Ok(())
    }

    /// Check if the request has proof-of-need (missing_hint present).
    #[must_use]
    pub const fn has_proof_of_need(&self) -> bool {
        self.missing_hint.is_some()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SignedFcpsFrame - Degraded/Bootstrap Mode (NORMATIVE when used)
// ─────────────────────────────────────────────────────────────────────────────

/// Signed FCPS frame for degraded/bootstrap mode (NORMATIVE when used).
///
/// This is a **non-default** path for when session MACs are unavailable,
/// such as during initial bootstrap or in degraded network conditions.
///
/// The signature covers: `"FCP2-FRAME-SIG-V1" || source_id || timestamp || frame_bytes`
#[derive(Debug, Clone)]
pub struct SignedFcpsFrame {
    /// The FCPS frame.
    pub frame: FcpsFrame,
    /// Source node ID (Tailscale node identifier).
    pub source_id: TailscaleNodeId,
    /// Unix timestamp (seconds since epoch).
    pub timestamp: u64,
    /// Ed25519 signature over the transcript.
    pub signature: Ed25519Signature,
}

impl SignedFcpsFrame {
    /// Domain separator for frame signatures.
    pub const SIGNATURE_DOMAIN: &'static [u8] = b"FCP2-FRAME-SIG-V1";

    /// Create a new signed frame.
    ///
    /// # Arguments
    ///
    /// * `frame` - The FCPS frame to sign
    /// * `source_id` - The source node's Tailscale ID
    /// * `timestamp` - Unix timestamp in seconds
    /// * `signing_key` - Ed25519 signing key
    #[must_use]
    pub fn new(
        frame: FcpsFrame,
        source_id: TailscaleNodeId,
        timestamp: u64,
        signing_key: &Ed25519SigningKey,
    ) -> Self {
        let frame_bytes = frame.encode();
        let transcript = Self::build_transcript(&source_id, timestamp, &frame_bytes);
        let signature = signing_key.sign(&transcript);

        Self {
            frame,
            source_id,
            timestamp,
            signature,
        }
    }

    /// Build the signature transcript.
    fn build_transcript(
        source_id: &TailscaleNodeId,
        timestamp: u64,
        frame_bytes: &[u8],
    ) -> Vec<u8> {
        let mut transcript = Vec::new();
        transcript.extend_from_slice(Self::SIGNATURE_DOMAIN);
        transcript.extend_from_slice(source_id.as_str().as_bytes());
        transcript.extend_from_slice(&timestamp.to_le_bytes());
        transcript.extend_from_slice(frame_bytes);
        transcript
    }

    /// Verify the frame signature.
    ///
    /// # Errors
    /// Returns `CryptoError` if signature verification fails.
    pub fn verify(&self, verifying_key: &Ed25519VerifyingKey) -> Result<(), CryptoError> {
        let frame_bytes = self.frame.encode();
        let transcript = Self::build_transcript(&self.source_id, self.timestamp, &frame_bytes);
        verifying_key.verify(&transcript, &self.signature)
    }

    /// Encode the signed frame to bytes.
    ///
    /// Wire format:
    /// - `source_id` length (u16 LE)
    /// - `source_id` bytes
    /// - timestamp (u64 LE)
    /// - signature (64 bytes)
    /// - frame bytes
    ///
    /// # Panics
    ///
    /// Panics if `source_id` exceeds `u16::MAX` bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let frame_bytes = self.frame.encode();
        let source_id_bytes = self.source_id.as_str().as_bytes();

        assert!(
            u16::try_from(source_id_bytes.len()).is_ok(),
            "source_id too long: {} bytes (max {})",
            source_id_bytes.len(),
            u16::MAX
        );

        let mut out = Vec::with_capacity(2 + source_id_bytes.len() + 8 + 64 + frame_bytes.len());

        let source_id_len = u16::try_from(source_id_bytes.len()).unwrap();
        out.extend_from_slice(&source_id_len.to_le_bytes());
        out.extend_from_slice(source_id_bytes);
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out.extend_from_slice(&self.signature.to_bytes());
        out.extend_from_slice(&frame_bytes);

        out
    }

    /// Decode a signed frame from bytes.
    ///
    /// # Errors
    /// Returns `FrameError` if the frame is malformed.
    pub fn decode(bytes: &[u8], max_datagram_bytes: usize) -> Result<Self, FrameError> {
        // Minimum: 2 (source_id_len) + 1 (min source_id) + 8 (timestamp) + 64 (sig) + 114 (min frame)
        const MIN_LEN: usize = 2 + 1 + 8 + 64 + FCPS_HEADER_LEN;

        if bytes.len() < MIN_LEN {
            return Err(FrameError::TooShort {
                len: bytes.len(),
                min: MIN_LEN,
            });
        }

        let source_id_len = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
        if source_id_len == 0 || bytes.len() < 2 + source_id_len + 8 + 64 + FCPS_HEADER_LEN {
            return Err(FrameError::TooShort {
                len: bytes.len(),
                min: 2 + source_id_len + 8 + 64 + FCPS_HEADER_LEN,
            });
        }

        let source_id_end = 2 + source_id_len;
        let source_id_str =
            std::str::from_utf8(&bytes[2..source_id_end]).map_err(|_| FrameError::InvalidUtf8)?;
        let source_id = TailscaleNodeId::new(source_id_str);

        let timestamp_start = source_id_end;
        let timestamp_bytes: [u8; 8] = bytes[timestamp_start..timestamp_start + 8]
            .try_into()
            .map_err(|_| FrameError::TooShort {
                len: bytes.len(),
                min: timestamp_start + 8,
            })?;
        let timestamp = u64::from_le_bytes(timestamp_bytes);

        let sig_start = timestamp_start + 8;
        let signature =
            Ed25519Signature::from_bytes(bytes[sig_start..sig_start + 64].try_into().map_err(
                |_| FrameError::TooShort {
                    len: bytes.len(),
                    min: sig_start + 64,
                },
            )?);

        let frame_start = sig_start + 64;
        let frame = FcpsFrame::decode(&bytes[frame_start..], max_datagram_bytes)?;

        Ok(Self {
            frame,
            source_id,
            timestamp,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_header() -> FcpsFrameHeader {
        FcpsFrameHeader {
            version: FCPS_VERSION,
            flags: FrameFlags::ENCRYPTED | FrameFlags::RAPTORQ,
            symbol_count: 2,
            total_payload_len: u32::try_from(2 * (SYMBOL_RECORD_OVERHEAD + 64))
                .expect("payload length fits in u32"),
            object_id: ObjectId::from_bytes([0x11; 32]),
            symbol_size: 64,
            zone_key_id: ZoneKeyId::from_bytes([0x22; 8]),
            zone_id_hash: ZoneIdHash::from_bytes([0x33; 32]),
            epoch_id: 1000,
            sender_instance_id: 0xDEAD_BEEF,
            frame_seq: 42,
        }
    }

    fn test_symbol(esi: u32, symbol_size: u16) -> SymbolRecord {
        SymbolRecord {
            esi,
            k: 10,
            data: vec![0xAA; symbol_size as usize],
            auth_tag: [0xBB; 16],
        }
    }

    #[test]
    fn header_encode_decode_round_trip() {
        let header = test_header();
        let encoded = header.encode();
        assert_eq!(encoded.len(), FCPS_HEADER_LEN);

        let decoded = FcpsFrameHeader::decode(&encoded).expect("decode");
        assert_eq!(decoded, header);
    }

    #[test]
    fn header_magic_validation() {
        let mut bad = [0u8; FCPS_HEADER_LEN];
        bad[0..4].copy_from_slice(b"XXXX");
        let err = FcpsFrameHeader::decode(&bad).expect_err("should fail");
        assert!(matches!(err, FrameError::InvalidMagic { .. }));
    }

    #[test]
    fn header_version_validation() {
        let mut header = test_header();
        header.version = 99;
        let mut encoded = header.encode();
        encoded[4..6].copy_from_slice(&99u16.to_le_bytes());
        let err = FcpsFrameHeader::decode(&encoded).expect_err("should fail");
        assert!(matches!(
            err,
            FrameError::UnsupportedVersion { version: 99 }
        ));
    }

    #[test]
    fn symbol_record_encode_decode() {
        let record = test_symbol(5, 64);
        let encoded = record.encode();
        assert_eq!(encoded.len(), SYMBOL_RECORD_OVERHEAD + 64);

        let decoded = SymbolRecord::decode(&encoded, 64).expect("decode");
        assert_eq!(decoded, record);
    }

    #[test]
    fn frame_encode_decode_round_trip() {
        let header = test_header();
        let symbols = vec![test_symbol(0, 64), test_symbol(1, 64)];
        let frame = FcpsFrame { header, symbols };

        let encoded = frame.encode();
        let expected_len = FCPS_HEADER_LEN + 2 * (SYMBOL_RECORD_OVERHEAD + 64);
        assert_eq!(encoded.len(), expected_len);

        let decoded = FcpsFrame::decode(&encoded, 2000).expect("decode");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn frame_rejects_mtu_violation() {
        let header = test_header();
        let symbols = vec![test_symbol(0, 64), test_symbol(1, 64)];
        let frame = FcpsFrame { header, symbols };
        let encoded = frame.encode();

        let err = FcpsFrame::decode(&encoded, 100).expect_err("should fail");
        assert!(matches!(err, FrameError::ExceedsMtu { .. }));
    }

    #[test]
    fn frame_rejects_length_mismatch() {
        let mut header = test_header();
        header.total_payload_len = 999; // Wrong value
        let symbols = vec![test_symbol(0, 64), test_symbol(1, 64)];
        let _frame = FcpsFrame {
            header: header.clone(),
            symbols,
        };

        // Build with correct payload but wrong header
        let mut buf = Vec::new();
        buf.extend_from_slice(&header.encode());
        buf.extend_from_slice(&test_symbol(0, 64).encode());
        buf.extend_from_slice(&test_symbol(1, 64).encode());

        let err = FcpsFrame::decode(&buf, 2000).expect_err("should fail");
        assert!(matches!(err, FrameError::LengthMismatch { .. }));
    }

    #[test]
    fn frame_flags_defaults() {
        let flags = FrameFlags::default();
        assert!(flags.contains(FrameFlags::ENCRYPTED));
        assert!(flags.contains(FrameFlags::RAPTORQ));
        assert!(!flags.contains(FrameFlags::CONTROL_PLANE));
    }

    #[test]
    fn frame_flags_all_bits() {
        let all = FrameFlags::all();
        assert!(all.contains(FrameFlags::REQUIRES_ACK));
        assert!(all.contains(FrameFlags::COMPRESSED));
        assert!(all.contains(FrameFlags::ENCRYPTED));
        assert!(all.contains(FrameFlags::RESPONSE));
        assert!(all.contains(FrameFlags::ERROR));
        assert!(all.contains(FrameFlags::STREAMING));
        assert!(all.contains(FrameFlags::STREAM_END));
        assert!(all.contains(FrameFlags::HAS_CAP_TOKEN));
        assert!(all.contains(FrameFlags::ZONE_CROSSING));
        assert!(all.contains(FrameFlags::PRIORITY));
        assert!(all.contains(FrameFlags::RAPTORQ));
        assert!(all.contains(FrameFlags::CONTROL_PLANE));
    }

    #[test]
    fn validate_frame_rejects_inconsistent_lengths() {
        // Test that mismatched header claims are rejected
        let mut header = test_header();
        header.symbol_count = u32::MAX;
        header.symbol_size = u16::MAX;

        let fake_bytes = [0u8; FCPS_HEADER_LEN];
        let err = validate_frame_lengths(&fake_bytes, &header).expect_err("should fail");
        // May fail with LengthMismatch or SymbolCountOverflow depending on platform
        assert!(
            matches!(err, FrameError::SymbolCountOverflow)
                || matches!(err, FrameError::LengthMismatch { .. })
                || matches!(err, FrameError::FrameSizeMismatch)
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SignedFcpsFrame Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn signed_frame_sign_and_verify() {
        let signing_key = Ed25519SigningKey::generate();
        let header = test_header();
        let symbols = vec![test_symbol(0, 64), test_symbol(1, 64)];
        let frame = FcpsFrame { header, symbols };

        let source_id = TailscaleNodeId::new("node-test");
        let timestamp = 1_704_067_200;

        let signed = SignedFcpsFrame::new(frame, source_id, timestamp, &signing_key);

        // Verify should succeed with correct key
        signed
            .verify(&signing_key.verifying_key())
            .expect("verify ok");
    }

    #[test]
    fn signed_frame_rejects_wrong_key() {
        let signing_key = Ed25519SigningKey::generate();
        let wrong_key = Ed25519SigningKey::generate();

        let header = test_header();
        // Use 2 symbols to match header.symbol_count
        let symbols = vec![test_symbol(0, 64), test_symbol(1, 64)];
        let frame = FcpsFrame { header, symbols };

        let source_id = TailscaleNodeId::new("node-wrong-key");
        let signed = SignedFcpsFrame::new(frame, source_id, 1000, &signing_key);

        // Verify should fail with wrong key
        assert!(signed.verify(&wrong_key.verifying_key()).is_err());
    }

    #[test]
    fn signed_frame_encode_decode_roundtrip() {
        let signing_key = Ed25519SigningKey::generate();
        let header = test_header();
        let symbols = vec![test_symbol(0, 64), test_symbol(1, 64)];
        let frame = FcpsFrame {
            header: header.clone(),
            symbols,
        };

        let source_id = TailscaleNodeId::new("node-roundtrip");
        let timestamp = 1_704_067_200;

        let signed = SignedFcpsFrame::new(frame, source_id.clone(), timestamp, &signing_key);
        let encoded = signed.encode();

        let decoded = SignedFcpsFrame::decode(&encoded, 2000).expect("decode ok");

        assert_eq!(decoded.source_id.as_str(), source_id.as_str());
        assert_eq!(decoded.timestamp, timestamp);
        assert_eq!(decoded.frame.header, header);
        assert_eq!(decoded.frame.symbols.len(), 2);

        // Verify signature is still valid after decode
        decoded
            .verify(&signing_key.verifying_key())
            .expect("verify after decode");
    }

    #[test]
    fn signed_frame_decode_rejects_short_input() {
        let too_short = vec![0u8; 50];
        let err = SignedFcpsFrame::decode(&too_short, 2000).expect_err("should fail");
        assert!(matches!(err, FrameError::TooShort { .. }));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DecodeStatus Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn decode_status_sign_and_verify() {
        use fcp_cbor::SchemaId;
        use fcp_core::Provenance;
        use semver::Version;

        let signing_key = Ed25519SigningKey::generate();
        let zone_id: ZoneId = "z:test".parse().expect("zone parse");

        let header = ObjectHeader {
            schema: SchemaId::new("fcp.test", "TestObject", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 1_704_067_200,
            provenance: Provenance::new(zone_id.clone()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };

        let mut status = DecodeStatus {
            header,
            object_id: ObjectId::from_bytes([0x11; 32]),
            zone_id,
            zone_key_id: ZoneKeyId::from_bytes([0x22; 8]),
            epoch_id: 1000,
            received_unique: 500,
            needed: 1003,
            complete: false,
            missing_hint: Some(vec![10, 20, 30]),
            signature: Ed25519Signature::from_bytes(&[0u8; 64]),
        };

        status.sign(&signing_key);
        status
            .verify(&signing_key.verifying_key())
            .expect("verify ok");
    }

    #[test]
    fn decode_status_rejects_wrong_key() {
        use fcp_cbor::SchemaId;
        use fcp_core::Provenance;
        use semver::Version;

        let signing_key = Ed25519SigningKey::generate();
        let wrong_key = Ed25519SigningKey::generate();
        let zone_id: ZoneId = "z:test2".parse().expect("zone parse");

        let header = ObjectHeader {
            schema: SchemaId::new("fcp.test", "TestObject", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 1_704_067_200,
            provenance: Provenance::new(zone_id.clone()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };

        let mut status = DecodeStatus {
            header,
            object_id: ObjectId::from_bytes([0x33; 32]),
            zone_id,
            zone_key_id: ZoneKeyId::from_bytes([0x44; 8]),
            epoch_id: 2000,
            received_unique: 100,
            needed: 200,
            complete: true,
            missing_hint: None,
            signature: Ed25519Signature::from_bytes(&[0u8; 64]),
        };

        status.sign(&signing_key);
        assert!(status.verify(&wrong_key.verifying_key()).is_err());
    }

    #[test]
    fn decode_status_validates_hint_bounds() {
        use fcp_cbor::SchemaId;
        use fcp_core::Provenance;
        use semver::Version;

        let zone_id: ZoneId = "z:bounds".parse().expect("zone parse");
        let header = ObjectHeader {
            schema: SchemaId::new("fcp.test", "TestObject", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 0,
            provenance: Provenance::new(zone_id.clone()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };

        // Valid: exactly at the limit
        let status_ok = DecodeStatus {
            header: header.clone(),
            object_id: ObjectId::from_bytes([0; 32]),
            zone_id: zone_id.clone(),
            zone_key_id: ZoneKeyId::from_bytes([0; 8]),
            epoch_id: 0,
            received_unique: 0,
            needed: 100,
            complete: false,
            missing_hint: Some(vec![0; MAX_MISSING_HINT_ENTRIES]),
            signature: Ed25519Signature::from_bytes(&[0u8; 64]),
        };
        status_ok.validate_hint_bounds().expect("at limit is ok");

        // Invalid: exceeds limit
        let status_bad = DecodeStatus {
            header,
            object_id: ObjectId::from_bytes([0; 32]),
            zone_id,
            zone_key_id: ZoneKeyId::from_bytes([0; 8]),
            epoch_id: 0,
            received_unique: 0,
            needed: 100,
            complete: false,
            missing_hint: Some(vec![0; MAX_MISSING_HINT_ENTRIES + 1]),
            signature: Ed25519Signature::from_bytes(&[0u8; 64]),
        };
        assert!(status_bad.validate_hint_bounds().is_err());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SymbolAck Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn symbol_ack_sign_and_verify() {
        use fcp_cbor::SchemaId;
        use fcp_core::Provenance;
        use semver::Version;

        let signing_key = Ed25519SigningKey::generate();
        let zone_id: ZoneId = "z:ack-test".parse().expect("zone parse");

        let header = ObjectHeader {
            schema: SchemaId::new("fcp.protocol", "SymbolAck", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 1_704_067_200,
            provenance: Provenance::new(zone_id.clone()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };

        let mut ack = SymbolAck::new(
            header,
            ObjectId::from_bytes([0x11; 32]),
            zone_id,
            ZoneKeyId::from_bytes([0x22; 8]),
            1000,
            SymbolAckReason::Complete,
            500,
        );

        ack.sign(&signing_key);
        ack.verify(&signing_key.verifying_key()).expect("verify ok");
    }

    #[test]
    fn symbol_ack_rejects_wrong_key() {
        use fcp_cbor::SchemaId;
        use fcp_core::Provenance;
        use semver::Version;

        let signing_key = Ed25519SigningKey::generate();
        let wrong_key = Ed25519SigningKey::generate();
        let zone_id: ZoneId = "z:ack-wrong".parse().expect("zone parse");

        let header = ObjectHeader {
            schema: SchemaId::new("fcp.protocol", "SymbolAck", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 1_704_067_200,
            provenance: Provenance::new(zone_id.clone()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };

        let mut ack = SymbolAck::new(
            header,
            ObjectId::from_bytes([0x33; 32]),
            zone_id,
            ZoneKeyId::from_bytes([0x44; 8]),
            2000,
            SymbolAckReason::Cancelled,
            250,
        );

        ack.sign(&signing_key);
        assert!(ack.verify(&wrong_key.verifying_key()).is_err());
    }

    #[test]
    fn symbol_ack_reason_variants() {
        // Ensure all reason variants map to distinct u8 values
        assert_ne!(SymbolAckReason::Complete as u8, SymbolAckReason::Cancelled as u8);
        assert_ne!(SymbolAckReason::Complete as u8, SymbolAckReason::Duplicate as u8);
        assert_ne!(SymbolAckReason::Complete as u8, SymbolAckReason::BudgetExceeded as u8);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SymbolRequest Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn symbol_request_sign_and_verify() {
        use fcp_cbor::SchemaId;
        use fcp_core::Provenance;
        use semver::Version;

        let signing_key = Ed25519SigningKey::generate();
        let zone_id: ZoneId = "z:req-test".parse().expect("zone parse");

        let header = ObjectHeader {
            schema: SchemaId::new("fcp.protocol", "SymbolRequest", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 1_704_067_200,
            provenance: Provenance::new(zone_id.clone()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };

        let mut request = SymbolRequest::new(
            header,
            ObjectId::from_bytes([0x11; 32]),
            zone_id,
            ZoneKeyId::from_bytes([0x22; 8]),
            1000,
            100, // max_symbols
            50,  // current_symbols
        );

        request.sign(&signing_key);
        request.verify(&signing_key.verifying_key()).expect("verify ok");
    }

    #[test]
    fn symbol_request_with_missing_hint() {
        use fcp_cbor::SchemaId;
        use fcp_core::Provenance;
        use semver::Version;

        let signing_key = Ed25519SigningKey::generate();
        let zone_id: ZoneId = "z:req-hint".parse().expect("zone parse");

        let header = ObjectHeader {
            schema: SchemaId::new("fcp.protocol", "SymbolRequest", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 1_704_067_200,
            provenance: Provenance::new(zone_id.clone()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };

        let mut request = SymbolRequest::new(
            header,
            ObjectId::from_bytes([0x55; 32]),
            zone_id,
            ZoneKeyId::from_bytes([0x66; 8]),
            3000,
            50,
            25,
        )
        .with_missing_hint(vec![10, 20, 30, 40, 50]);

        assert!(request.has_proof_of_need());
        request.validate_hint_bounds().expect("within bounds");

        request.sign(&signing_key);
        request.verify(&signing_key.verifying_key()).expect("verify ok");
    }

    #[test]
    fn symbol_request_validates_hint_bounds() {
        use fcp_cbor::SchemaId;
        use fcp_core::Provenance;
        use semver::Version;

        let zone_id: ZoneId = "z:req-bounds".parse().expect("zone parse");
        let header = ObjectHeader {
            schema: SchemaId::new("fcp.protocol", "SymbolRequest", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 0,
            provenance: Provenance::new(zone_id.clone()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };

        // Valid: exactly at limit
        let request_ok = SymbolRequest::new(
            header.clone(),
            ObjectId::from_bytes([0; 32]),
            zone_id.clone(),
            ZoneKeyId::from_bytes([0; 8]),
            0,
            32,
            0,
        )
        .with_missing_hint(vec![0; MAX_MISSING_HINT_ENTRIES]);
        request_ok.validate_hint_bounds().expect("at limit ok");

        // Invalid: exceeds hint limit
        let request_bad = SymbolRequest::new(
            header,
            ObjectId::from_bytes([0; 32]),
            zone_id,
            ZoneKeyId::from_bytes([0; 8]),
            0,
            32,
            0,
        )
        .with_missing_hint(vec![0; MAX_MISSING_HINT_ENTRIES + 1]);
        assert!(request_bad.validate_hint_bounds().is_err());
    }

    #[test]
    fn symbol_request_validates_max_symbols_unauthenticated() {
        use fcp_cbor::SchemaId;
        use fcp_core::Provenance;
        use semver::Version;

        let zone_id: ZoneId = "z:req-unauth".parse().expect("zone parse");
        let header = ObjectHeader {
            schema: SchemaId::new("fcp.protocol", "SymbolRequest", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 0,
            provenance: Provenance::new(zone_id.clone()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };

        // Valid for unauthenticated: at default limit
        let request_ok = SymbolRequest::new(
            header.clone(),
            ObjectId::from_bytes([0; 32]),
            zone_id.clone(),
            ZoneKeyId::from_bytes([0; 8]),
            0,
            DEFAULT_MAX_SYMBOLS_UNAUTHENTICATED,
            0,
        );
        request_ok.validate_bounds(false).expect("unauth at limit ok");

        // Invalid for unauthenticated: exceeds limit
        let request_bad = SymbolRequest::new(
            header.clone(),
            ObjectId::from_bytes([0; 32]),
            zone_id.clone(),
            ZoneKeyId::from_bytes([0; 8]),
            0,
            DEFAULT_MAX_SYMBOLS_UNAUTHENTICATED + 1,
            0,
        );
        assert!(request_bad.validate_bounds(false).is_err());

        // Valid for authenticated: higher limit allowed
        let request_auth = SymbolRequest::new(
            header,
            ObjectId::from_bytes([0; 32]),
            zone_id,
            ZoneKeyId::from_bytes([0; 8]),
            0,
            DEFAULT_MAX_SYMBOLS_AUTHENTICATED,
            0,
        );
        request_auth.validate_bounds(true).expect("auth at limit ok");
    }

    #[test]
    fn symbol_request_proof_of_need_detection() {
        use fcp_cbor::SchemaId;
        use fcp_core::Provenance;
        use semver::Version;

        let zone_id: ZoneId = "z:req-pon".parse().expect("zone parse");
        let header = ObjectHeader {
            schema: SchemaId::new("fcp.protocol", "SymbolRequest", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 0,
            provenance: Provenance::new(zone_id.clone()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };

        // No hint = no proof of need
        let request_no_hint = SymbolRequest::new(
            header.clone(),
            ObjectId::from_bytes([0; 32]),
            zone_id.clone(),
            ZoneKeyId::from_bytes([0; 8]),
            0,
            32,
            0,
        );
        assert!(!request_no_hint.has_proof_of_need());

        // With hint = has proof of need
        let request_with_hint = SymbolRequest::new(
            header,
            ObjectId::from_bytes([0; 32]),
            zone_id,
            ZoneKeyId::from_bytes([0; 8]),
            0,
            32,
            0,
        )
        .with_missing_hint(vec![1, 2, 3]);
        assert!(request_with_hint.has_proof_of_need());
    }
}
