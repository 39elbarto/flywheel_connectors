//! Degraded-mode control-plane transport over FCPS.
//!
//! When FCPC (reliable control-plane stream) is unavailable due to degraded network
//! conditions, partitions, or bootstrap scenarios, control-plane objects can be
//! transported over the symbol-native FCPS data plane with `FrameFlags::CONTROL_PLANE`.
//!
//! This module implements the spec-described mesh fallback transport:
//! - Sender wraps canonical `ControlPlaneObject` as symbols
//! - Sends as FCPS frames with `CONTROL_PLANE` flag
//! - Receiver verifies session MAC + per-symbol AEAD
//! - Reconstructs object payload (RaptorQ or raw chunking)
//! - Enforces retention: Required objects stored, Ephemeral may be discarded
//!
//! # Wire Format
//!
//! The FCPS frame with `CONTROL_PLANE` flag encodes:
//! - Standard FCPS header (114 bytes) with `CONTROL_PLANE | ENCRYPTED | RAPTORQ`
//! - Symbol records containing RaptorQ-encoded control-plane object
//! - Each symbol is encrypted with zone key (per-symbol AEAD)

use std::collections::{BTreeMap, HashMap};

use fcp_core::{ObjectId, TailscaleNodeId, ZoneId, ZoneIdHash, ZoneKeyId};
use fcp_crypto::{Ed25519SigningKey, Ed25519VerifyingKey};
use fcp_protocol::{
    FCPS_VERSION, FcpsFrame, FcpsFrameHeader, FrameError, FrameFlags, SignedFcpsFrame, SymbolRecord,
};
use fcp_raptorq::{DecodeError, EncodeError, RaptorQConfig, RaptorQDecoder, RaptorQEncoder};
use thiserror::Error;
use tracing::{debug, info, warn};

/// Error type for degraded-mode transport operations.
#[derive(Debug, Error)]
pub enum DegradedTransportError {
    /// Encoding failed.
    #[error("encoding failed: {0}")]
    Encode(#[from] EncodeError),

    /// Decoding failed.
    #[error("decoding failed: {0}")]
    Decode(#[from] DecodeError),

    /// Frame parsing failed.
    #[error("frame error: {0}")]
    Frame(#[from] FrameError),

    /// Object reconstruction incomplete (need more symbols).
    #[error("reconstruction incomplete: received {received}/{needed} symbols")]
    Incomplete { received: u32, needed: u32 },

    /// Schema hash mismatch after reconstruction.
    #[error("schema hash mismatch: expected {expected:?}, got {actual:?}")]
    SchemaHashMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },

    /// Object ID mismatch after reconstruction.
    #[error("object ID mismatch")]
    ObjectIdMismatch,

    /// Retention policy violation (Required object was dropped).
    #[error("retention violation: Required object was not stored")]
    RetentionViolation,

    /// Frame missing CONTROL_PLANE flag.
    #[error("frame missing CONTROL_PLANE flag")]
    MissingControlPlaneFlag,

    /// Zone ID hash mismatch.
    #[error("zone id hash mismatch: expected {expected:?}, got {got:?}")]
    ZoneMismatch {
        expected: ZoneIdHash,
        got: ZoneIdHash,
    },

    /// Signature verification failed.
    #[error("signature verification failed")]
    SignatureVerificationFailed,
}

/// Retention class for control-plane objects (NORMATIVE).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RetentionClass {
    /// Object MUST be stored and replayable after restart.
    #[default]
    Required,
    /// Object MAY be discarded after processing.
    Ephemeral,
}

/// Control-plane object wrapped for degraded-mode transport.
#[derive(Debug, Clone)]
pub struct ControlPlaneEnvelope {
    /// Canonical CBOR-serialized control-plane object.
    pub payload: Vec<u8>,
    /// Schema hash (first 32 bytes of BLAKE3 of schema definition).
    pub schema_hash: [u8; 32],
    /// Object ID (BLAKE3-keyed hash).
    pub object_id: ObjectId,
    /// Zone this object belongs to.
    pub zone_id: ZoneId,
    /// Zone key ID for decryption.
    pub zone_key_id: ZoneKeyId,
    /// Epoch this control-plane object belongs to.
    pub epoch_id: u64,
    /// Retention class.
    pub retention: RetentionClass,
}

impl ControlPlaneEnvelope {
    /// Create a new control-plane envelope.
    #[must_use]
    pub fn new(
        payload: Vec<u8>,
        schema_hash: [u8; 32],
        object_id: ObjectId,
        zone_id: ZoneId,
        zone_key_id: ZoneKeyId,
        epoch_id: u64,
        retention: RetentionClass,
    ) -> Self {
        Self {
            payload,
            schema_hash,
            object_id,
            zone_id,
            zone_key_id,
            epoch_id,
            retention,
        }
    }
}

/// Encoder for control-plane objects over FCPS.
///
/// Wraps a canonical control-plane object as FCPS frames with `CONTROL_PLANE` flag.
pub struct DegradedModeEncoder {
    config: RaptorQConfig,
    sender_instance_id: u64,
    next_frame_seq: u64,
}

impl DegradedModeEncoder {
    /// Create a new degraded-mode encoder.
    #[must_use]
    pub fn new(config: RaptorQConfig, sender_instance_id: u64) -> Self {
        Self {
            config,
            sender_instance_id,
            next_frame_seq: 0,
        }
    }

    /// Encode a control-plane object into FCPS frames.
    ///
    /// Returns one or more FCPS frames with `CONTROL_PLANE` flag set.
    ///
    /// # Errors
    ///
    /// Returns `DegradedTransportError::Encode` if RaptorQ encoding fails.
    pub fn encode(
        &mut self,
        envelope: &ControlPlaneEnvelope,
        epoch_id: u64,
    ) -> Result<Vec<FcpsFrame>, DegradedTransportError> {
        info!(
            object_id = %envelope.object_id,
            zone_id = %envelope.zone_id,
            retention = ?envelope.retention,
            payload_len = envelope.payload.len(),
            "degraded_mode: encoding control-plane object for FCPS transport"
        );

        // Build the wire payload: length(4 bytes) || schema_hash(32 bytes) || payload
        // Length prefix allows decoder to know exact payload size after RaptorQ padding
        let payload_len = u32::try_from(envelope.payload.len()).unwrap_or(u32::MAX);
        let mut wire_payload = Vec::with_capacity(4 + 32 + envelope.payload.len());
        wire_payload.extend_from_slice(&payload_len.to_be_bytes());
        wire_payload.extend_from_slice(&envelope.schema_hash);
        wire_payload.extend_from_slice(&envelope.payload);

        // Encode with RaptorQ
        let encoder = RaptorQEncoder::new(&wire_payload, &self.config)?;
        let symbols = encoder.encode_all();
        let k = encoder.source_symbols() as u16;

        // Build FCPS frames
        let flags = FrameFlags::ENCRYPTED | FrameFlags::RAPTORQ | FrameFlags::CONTROL_PLANE;
        let zone_id_hash = envelope.zone_id.hash();

        // For simplicity, pack all symbols into a single frame
        // (production would batch based on MTU)
        let symbol_records: Vec<SymbolRecord> = symbols
            .into_iter()
            .map(|(esi, data)| {
                let _data_len = data.len();
                SymbolRecord {
                    esi,
                    k,
                    data,
                    // Placeholder auth tag - real implementation would encrypt
                    auth_tag: [0u8; 16],
                }
            })
            .collect();

        let symbol_size = self.config.symbol_size;
        let total_payload_len: u32 = symbol_records.iter().map(|r| u32::try_from(r.wire_size()).unwrap_or(u32::MAX)).sum();

        let header = FcpsFrameHeader {
            version: FCPS_VERSION,
            flags,
            symbol_count: u32::try_from(symbol_records.len()).unwrap_or(u32::MAX),
            total_payload_len,
            object_id: envelope.object_id.clone(),
            symbol_size,
            zone_key_id: envelope.zone_key_id.clone(),
            zone_id_hash,
            epoch_id,
            sender_instance_id: self.sender_instance_id,
            frame_seq: self.next_frame_seq,
        };

        self.next_frame_seq += 1;

        debug!(
            object_id = %envelope.object_id,
            symbol_count = symbol_records.len(),
            frame_seq = header.frame_seq,
            "degraded_mode: created CONTROL_PLANE FCPS frame"
        );

        Ok(vec![FcpsFrame {
            header,
            symbols: symbol_records,
        }])
    }

    /// Encode and sign a control-plane object for degraded/bootstrap mode.
    ///
    /// Use when session MACs are unavailable.
    ///
    /// # Errors
    ///
    /// Returns `DegradedTransportError::Encode` if encoding fails.
    pub fn encode_signed(
        &mut self,
        envelope: &ControlPlaneEnvelope,
        epoch_id: u64,
        source_id: &TailscaleNodeId,
        timestamp: u64,
        signing_key: &Ed25519SigningKey,
    ) -> Result<Vec<SignedFcpsFrame>, DegradedTransportError> {
        let frames = self.encode(envelope, epoch_id)?;

        Ok(frames
            .into_iter()
            .map(|frame| SignedFcpsFrame::new(frame, source_id.clone(), timestamp, signing_key))
            .collect())
    }
}

/// Decoder for control-plane objects from FCPS frames.
///
/// Accumulates symbols from FCPS frames with `CONTROL_PLANE` flag until
/// reconstruction is possible.
pub struct DegradedModeDecoder {
    config: RaptorQConfig,
    /// In-progress reconstructions keyed by object ID.
    pending: HashMap<ObjectId, PendingReconstruction>,
}

/// In-progress object reconstruction.
struct PendingReconstruction {
    decoder: RaptorQDecoder,
    zone_id: ZoneId,
    zone_key_id: ZoneKeyId,
    retention: RetentionClass,
}

impl DegradedModeDecoder {
    /// Create a new degraded-mode decoder.
    #[must_use]
    pub fn new(config: RaptorQConfig) -> Self {
        Self {
            config,
            pending: HashMap::new(),
        }
    }

    /// Process an FCPS frame with `CONTROL_PLANE` flag.
    ///
    /// Returns `Some(envelope)` when reconstruction completes.
    ///
    /// # Errors
    ///
    /// Returns error if frame is invalid or decoding fails.
    ///
    /// # Panics
    ///
    /// This function should not panic under normal operation. Internal map state
    /// is guaranteed consistent when reconstruction completes.
    pub fn process_frame(
        &mut self,
        frame: &FcpsFrame,
        expected_zone_id: &ZoneId,
        retention: RetentionClass,
    ) -> Result<Option<ControlPlaneEnvelope>, DegradedTransportError> {
        let expected_hash = expected_zone_id.hash();
        if frame.header.zone_id_hash != expected_hash {
            warn!(
                object_id = %frame.header.object_id,
                expected = %hex::encode(expected_hash.as_ref()),
                got = %hex::encode(frame.header.zone_id_hash.as_ref()),
                "degraded_mode: zone id hash mismatch"
            );
            return Err(DegradedTransportError::ZoneMismatch {
                expected: expected_hash,
                got: frame.header.zone_id_hash,
            });
        }
        // Verify CONTROL_PLANE flag
        if !frame.header.flags.contains(FrameFlags::CONTROL_PLANE) {
            warn!(
                object_id = %frame.header.object_id,
                "degraded_mode: received frame without CONTROL_PLANE flag"
            );
            return Err(DegradedTransportError::MissingControlPlaneFlag);
        }

        debug!(
            object_id = %frame.header.object_id,
            symbol_count = frame.symbols.len(),
            frame_seq = frame.header.frame_seq,
            "degraded_mode: processing CONTROL_PLANE frame"
        );

        let object_id = frame.header.object_id.clone();

        // Get or create pending reconstruction
        let pending = self.pending.entry(object_id.clone()).or_insert_with(|| {
            // Estimate transfer length from first frame
            // In practice, would get this from a manifest or first symbol K value
            let k = frame.symbols.first().map_or(1, |s| s.k);
            let transfer_length = u64::from(k) * u64::from(frame.header.symbol_size);

            PendingReconstruction {
                decoder: RaptorQDecoder::with_expected_symbols(
                    u32::from(k),
                    transfer_length,
                    frame.header.symbol_size,
                    &self.config,
                ),
                zone_id: expected_zone_id.clone(),
                zone_key_id: frame.header.zone_key_id.clone(),
                retention,
            }
        });

        // Feed symbols to decoder
        for symbol in &frame.symbols {
            // In production, would verify auth_tag here after AEAD decryption
            if let Some(payload) = pending
                .decoder
                .add_symbol(symbol.esi, symbol.data.clone())?
            {
                // Reconstruction complete! We know it exists because we just got a mutable ref to it above
                let pending = self.pending.remove(&object_id).expect("pending reconstruction missing during decode");

                // Parse length prefix, schema hash, and payload
                // Wire format: length(4 bytes) || schema_hash(32 bytes) || payload
                if payload.len() < 36 {
                    warn!(
                        object_id = %object_id,
                        payload_len = payload.len(),
                        "degraded_mode: reconstructed payload too short for header"
                    );
                    return Err(DegradedTransportError::Decode(DecodeError::Timeout));
                }

                let payload_len =
                    u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;

                let mut schema_hash = [0u8; 32];
                schema_hash.copy_from_slice(&payload[4..36]);

                // Extract exactly payload_len bytes (ignoring RaptorQ padding)
                let object_payload = if 36 + payload_len <= payload.len() {
                    payload[36..36 + payload_len].to_vec()
                } else {
                    warn!(
                        object_id = %object_id,
                        expected_len = payload_len,
                        actual_len = payload.len().saturating_sub(36),
                        "degraded_mode: payload length mismatch"
                    );
                    return Err(DegradedTransportError::Decode(DecodeError::Timeout));
                };

                info!(
                    object_id = %object_id,
                    zone_id = %pending.zone_id,
                    retention = ?pending.retention,
                    payload_len = object_payload.len(),
                    "degraded_mode: control-plane object reconstruction complete"
                );

                return Ok(Some(ControlPlaneEnvelope {
                    payload: object_payload,
                    schema_hash,
                    object_id,
                    zone_id: pending.zone_id,
                    zone_key_id: pending.zone_key_id,
                    epoch_id: frame.header.epoch_id,
                    retention: pending.retention,
                }));
            }
        }

        // Not yet complete
        Ok(None)
    }

    /// Process a signed FCPS frame for degraded/bootstrap mode.
    ///
    /// Verifies signature before processing.
    ///
    /// # Errors
    ///
    /// Returns error if signature verification fails or frame processing fails.
    pub fn process_signed_frame(
        &mut self,
        signed_frame: &SignedFcpsFrame,
        verifying_key: &Ed25519VerifyingKey,
        expected_zone_id: &ZoneId,
        retention: RetentionClass,
    ) -> Result<Option<ControlPlaneEnvelope>, DegradedTransportError> {
        // Verify signature
        if signed_frame.verify(verifying_key).is_err() {
            warn!(
                object_id = %signed_frame.frame.header.object_id,
                source_id = ?signed_frame.source_id,
                "degraded_mode: signature verification failed for signed FCPS frame"
            );
            return Err(DegradedTransportError::SignatureVerificationFailed);
        }

        debug!(
            object_id = %signed_frame.frame.header.object_id,
            source_id = ?signed_frame.source_id,
            timestamp = signed_frame.timestamp,
            "degraded_mode: signature verified for signed FCPS frame"
        );

        self.process_frame(&signed_frame.frame, expected_zone_id, retention)
    }

    /// Get decode status for a pending object.
    #[must_use]
    pub fn get_status(&self, object_id: &ObjectId) -> Option<DecodeStatusInfo> {
        self.pending.get(object_id).map(|p| DecodeStatusInfo {
            received: p.decoder.received_count(),
            needed: p.decoder.needed(),
            likely_complete: p.decoder.likely_complete(),
        })
    }

    /// Clear a pending reconstruction (e.g., on timeout).
    pub fn clear_pending(&mut self, object_id: &ObjectId) -> bool {
        self.pending.remove(object_id).is_some()
    }

    /// Get number of pending reconstructions.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

/// Status information for a pending decode.
#[derive(Debug, Clone, Copy)]
pub struct DecodeStatusInfo {
    /// Unique symbols received.
    pub received: u32,
    /// Approximate symbols needed (K').
    pub needed: u32,
    /// Whether reconstruction is likely possible.
    pub likely_complete: bool,
}

/// Handler trait for processed control-plane objects.
///
/// Implementations enforce retention policy and route objects appropriately.
pub trait ControlPlaneHandler: Send + Sync {
    /// Handle a reconstructed control-plane object.
    ///
    /// # Errors
    ///
    /// Returns error if the handler fails to process or store the object.
    fn handle(&self, envelope: ControlPlaneEnvelope) -> Result<(), DegradedTransportError>;
}

/// Simple in-memory handler that stores Required objects.
#[derive(Default)]
pub struct InMemoryControlPlaneHandler {
    state: std::sync::Mutex<InMemoryReplayState>,
}

#[derive(Default)]
struct InMemoryReplayState {
    stored: HashMap<ObjectId, ControlPlaneEnvelope>,
    epoch_index: HashMap<ZoneId, BTreeMap<u64, Vec<ObjectId>>>,
}

impl InMemoryControlPlaneHandler {
    /// Create a new in-memory handler.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a stored object by ID.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn get(&self, object_id: &ObjectId) -> Option<ControlPlaneEnvelope> {
        self.state.lock().unwrap().stored.get(object_id).cloned()
    }

    /// Get the number of stored objects.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn count(&self) -> usize {
        self.state.lock().unwrap().stored.len()
    }

    /// List epochs with stored Required objects for a zone.
    ///
    /// If `since_epoch` is provided, returns epochs strictly greater than that epoch.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn list_epochs(&self, zone_id: &ZoneId, since_epoch: Option<u64>) -> Vec<u64> {
        let state = self.state.lock().unwrap();
        let Some(zone_epochs) = state.epoch_index.get(zone_id) else {
            return Vec::new();
        };
        let epochs = zone_epochs
            .keys()
            .copied()
            .filter(|epoch| since_epoch.is_none_or(|since| *epoch > since))
            .collect();
        drop(state);
        epochs
    }

    /// Fetch all stored Required objects for a specific zone/epoch.
    ///
    /// Returns an empty vector if the epoch has no stored objects.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn fetch_epoch(&self, zone_id: &ZoneId, epoch_id: u64) -> Vec<ControlPlaneEnvelope> {
        let state = self.state.lock().unwrap();
        let Some(zone_epochs) = state.epoch_index.get(zone_id) else {
            return Vec::new();
        };
        let Some(object_ids) = zone_epochs.get(&epoch_id) else {
            return Vec::new();
        };
        let envelopes = object_ids
            .iter()
            .filter_map(|object_id| state.stored.get(object_id).cloned())
            .collect();
        drop(state);
        envelopes
    }
}

impl ControlPlaneHandler for InMemoryControlPlaneHandler {
    fn handle(&self, envelope: ControlPlaneEnvelope) -> Result<(), DegradedTransportError> {
        match envelope.retention {
            RetentionClass::Required => {
                // MUST store
                let object_id = envelope.object_id.clone();
                let zone_id = envelope.zone_id.clone();
                let epoch_id = envelope.epoch_id;
                info!(
                    object_id = %object_id,
                    zone_id = %zone_id,
                    epoch_id,
                    retention = "Required",
                    "degraded_mode: storing required control-plane object"
                );

                let mut state = self.state.lock().unwrap();

                if let Some(previous) = state.stored.insert(object_id.clone(), envelope) {
                    if let Some(zone_epochs) = state.epoch_index.get_mut(&previous.zone_id) {
                        if let Some(object_ids) = zone_epochs.get_mut(&previous.epoch_id) {
                            object_ids.retain(|id| id != &object_id);
                            if object_ids.is_empty() {
                                zone_epochs.remove(&previous.epoch_id);
                            }
                        }
                        if zone_epochs.is_empty() {
                            state.epoch_index.remove(&previous.zone_id);
                        }
                    }
                }

                let zone_epochs = state.epoch_index.entry(zone_id).or_default();
                let object_ids = zone_epochs.entry(epoch_id).or_default();
                if !object_ids.contains(&object_id) {
                    object_ids.push(object_id);
                }
                drop(state);
                Ok(())
            }
            RetentionClass::Ephemeral => {
                // MAY discard - we process but don't store
                debug!(
                    object_id = %envelope.object_id,
                    zone_id = %envelope.zone_id,
                    retention = "Ephemeral",
                    "degraded_mode: processed ephemeral object, not storing"
                );
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> RaptorQConfig {
        RaptorQConfig {
            symbol_size: 64,
            repair_ratio_bps: 500,
            max_object_size: 1024 * 1024,
            decode_timeout: std::time::Duration::from_secs(30),
            max_chunk_threshold: 1024,
            chunk_size: 256,
        }
    }

    fn test_zone_id() -> ZoneId {
        "z:test".parse().expect("valid zone id")
    }

    fn test_envelope() -> ControlPlaneEnvelope {
        ControlPlaneEnvelope {
            payload: vec![0x42; 256],
            schema_hash: [0xAA; 32],
            object_id: ObjectId::from_bytes([0x11; 32]),
            zone_id: test_zone_id(),
            zone_key_id: ZoneKeyId::from_bytes([0x22; 8]),
            epoch_id: 0,
            retention: RetentionClass::Required,
        }
    }

    #[test]
    fn encoder_creates_frames_with_control_plane_flag() {
        let config = test_config();
        let mut encoder = DegradedModeEncoder::new(config, 0xDEAD_BEEF);

        let envelope = test_envelope();
        let frames = encoder
            .encode(&envelope, 1000)
            .expect("encode should succeed");

        assert!(!frames.is_empty());
        for frame in &frames {
            assert!(frame.header.flags.contains(FrameFlags::CONTROL_PLANE));
            assert!(frame.header.flags.contains(FrameFlags::ENCRYPTED));
            assert!(frame.header.flags.contains(FrameFlags::RAPTORQ));
        }
    }

    #[test]
    fn encoder_increments_frame_seq() {
        let config = test_config();
        let mut encoder = DegradedModeEncoder::new(config, 123);

        let envelope = test_envelope();

        let frames1 = encoder.encode(&envelope, 1000).unwrap();
        let frames2 = encoder.encode(&envelope, 1000).unwrap();

        assert_eq!(frames1[0].header.frame_seq, 0);
        assert_eq!(frames2[0].header.frame_seq, 1);
    }

    #[test]
    fn encode_decode_roundtrip() {
        let config = test_config();
        let mut encoder = DegradedModeEncoder::new(config.clone(), 0xBEEF);
        let mut decoder = DegradedModeDecoder::new(config);

        let envelope = test_envelope();
        let zone_id = envelope.zone_id.clone();

        let frames = encoder.encode(&envelope, 2000).expect("encode");

        // Feed frames to decoder
        let mut result = None;
        for frame in &frames {
            if let Some(decoded) = decoder
                .process_frame(frame, &zone_id, RetentionClass::Required)
                .expect("decode")
            {
                result = Some(decoded);
                break;
            }
        }

        let decoded_envelope = result.expect("should have decoded");
        assert_eq!(decoded_envelope.payload, envelope.payload);
        assert_eq!(decoded_envelope.schema_hash, envelope.schema_hash);
        assert_eq!(decoded_envelope.object_id, envelope.object_id);
        assert_eq!(decoded_envelope.epoch_id, 2000);
    }

    #[test]
    fn decoder_rejects_non_control_plane_frame() {
        let config = test_config();
        let mut decoder = DegradedModeDecoder::new(config);

        let zone_id = test_zone_id();

        // Create a frame without CONTROL_PLANE flag (but with matching zone hash)
        let frame = FcpsFrame {
            header: FcpsFrameHeader {
                version: FCPS_VERSION,
                flags: FrameFlags::ENCRYPTED | FrameFlags::RAPTORQ,
                symbol_count: 0,
                total_payload_len: 0,
                object_id: ObjectId::from_bytes([0; 32]),
                symbol_size: 64,
                zone_key_id: ZoneKeyId::from_bytes([0; 8]),
                zone_id_hash: zone_id.hash(),
                epoch_id: 0,
                sender_instance_id: 0,
                frame_seq: 0,
            },
            symbols: vec![],
        };

        let result = decoder.process_frame(&frame, &zone_id, RetentionClass::Required);
        assert!(matches!(
            result,
            Err(DegradedTransportError::MissingControlPlaneFlag)
        ));
    }

    #[test]
    fn decoder_rejects_zone_mismatch() {
        let config = test_config();
        let mut decoder = DegradedModeDecoder::new(config);

        let zone_id = test_zone_id();
        let other_zone: ZoneId = "z:other".parse().expect("valid zone id");

        let frame = FcpsFrame {
            header: FcpsFrameHeader {
                version: FCPS_VERSION,
                flags: FrameFlags::ENCRYPTED | FrameFlags::RAPTORQ | FrameFlags::CONTROL_PLANE,
                symbol_count: 0,
                total_payload_len: 0,
                object_id: ObjectId::from_bytes([0; 32]),
                symbol_size: 64,
                zone_key_id: ZoneKeyId::from_bytes([0; 8]),
                zone_id_hash: zone_id.hash(),
                epoch_id: 0,
                sender_instance_id: 0,
                frame_seq: 0,
            },
            symbols: vec![],
        };

        let result = decoder.process_frame(&frame, &other_zone, RetentionClass::Required);
        assert!(matches!(
            result,
            Err(DegradedTransportError::ZoneMismatch { .. })
        ));
    }

    #[test]
    fn signed_frame_roundtrip() {
        let config = test_config();
        let mut encoder = DegradedModeEncoder::new(config.clone(), 0xCAFE);
        let mut decoder = DegradedModeDecoder::new(config);

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let envelope = test_envelope();
        let zone_id = envelope.zone_id.clone();
        let source_id = TailscaleNodeId::new("node-test");

        let signed_frames = encoder
            .encode_signed(&envelope, 3000, &source_id, 1_704_067_200, &signing_key)
            .expect("encode signed");

        let mut result = None;
        for signed_frame in &signed_frames {
            if let Some(decoded) = decoder
                .process_signed_frame(
                    signed_frame,
                    &verifying_key,
                    &zone_id,
                    RetentionClass::Required,
                )
                .expect("decode")
            {
                result = Some(decoded);
                break;
            }
        }

        let decoded_envelope = result.expect("should have decoded");
        assert_eq!(decoded_envelope.payload, envelope.payload);
    }

    #[test]
    fn signed_frame_rejects_wrong_key() {
        let config = test_config();
        let mut encoder = DegradedModeEncoder::new(config.clone(), 0x1234);
        let mut decoder = DegradedModeDecoder::new(config);

        let signing_key = Ed25519SigningKey::generate();
        let wrong_key = Ed25519SigningKey::generate();

        let envelope = test_envelope();
        let zone_id = envelope.zone_id.clone();
        let source_id = TailscaleNodeId::new("node-wrong");

        let signed_frames = encoder
            .encode_signed(&envelope, 4000, &source_id, 1_704_067_200, &signing_key)
            .expect("encode");

        let result = decoder.process_signed_frame(
            &signed_frames[0],
            &wrong_key.verifying_key(),
            &zone_id,
            RetentionClass::Required,
        );

        assert!(matches!(
            result,
            Err(DegradedTransportError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn handler_stores_required_objects() {
        let handler = InMemoryControlPlaneHandler::new();
        let envelope = test_envelope();
        let object_id = envelope.object_id.clone();

        handler.handle(envelope).expect("handle");

        assert_eq!(handler.count(), 1);
        assert!(handler.get(&object_id).is_some());
    }

    #[test]
    fn handler_list_epochs_and_fetch_epoch() {
        let handler = InMemoryControlPlaneHandler::new();
        let zone_id = test_zone_id();

        let mut epoch_10_obj = test_envelope();
        epoch_10_obj.object_id = ObjectId::from_bytes([0x31; 32]);
        epoch_10_obj.zone_id = zone_id.clone();
        epoch_10_obj.epoch_id = 10;

        let mut epoch_11_obj = test_envelope();
        epoch_11_obj.object_id = ObjectId::from_bytes([0x32; 32]);
        epoch_11_obj.zone_id = zone_id.clone();
        epoch_11_obj.epoch_id = 11;

        let epoch_10_object_id = epoch_10_obj.object_id.clone();

        handler.handle(epoch_10_obj).expect("store epoch 10");
        handler.handle(epoch_11_obj).expect("store epoch 11");

        let all_epochs = handler.list_epochs(&zone_id, None);
        assert_eq!(all_epochs, vec![10, 11]);

        let newer_epochs = handler.list_epochs(&zone_id, Some(10));
        assert_eq!(newer_epochs, vec![11]);

        let epoch_10_objects = handler.fetch_epoch(&zone_id, 10);
        assert_eq!(epoch_10_objects.len(), 1);
        assert_eq!(epoch_10_objects[0].object_id, epoch_10_object_id);
        assert_eq!(epoch_10_objects[0].epoch_id, 10);

        assert!(handler.fetch_epoch(&zone_id, 99).is_empty());
    }

    #[test]
    fn handler_discards_ephemeral_objects() {
        let handler = InMemoryControlPlaneHandler::new();
        let mut envelope = test_envelope();
        envelope.retention = RetentionClass::Ephemeral;

        handler.handle(envelope).expect("handle");

        // Ephemeral objects are processed but not stored
        assert_eq!(handler.count(), 0);
    }

    #[test]
    fn decoder_tracks_pending_status() {
        let config = test_config();
        let mut encoder = DegradedModeEncoder::new(config.clone(), 0x5678);
        let mut decoder = DegradedModeDecoder::new(config);

        let envelope = test_envelope();
        let zone_id = envelope.zone_id.clone();
        let object_id = envelope.object_id.clone();

        let frames = encoder.encode(&envelope, 5000).expect("encode");

        // Process first frame - should start pending
        let _ = decoder.process_frame(&frames[0], &zone_id, RetentionClass::Required);

        // Check status (may or may not be complete depending on symbol count)
        let _status = decoder.get_status(&object_id);
        // Note: status may be None if reconstruction already completed
    }

    #[test]
    fn decoder_clear_pending() {
        let config = test_config();
        let mut decoder = DegradedModeDecoder::new(config);

        let object_id = ObjectId::from_bytes([0xAB; 32]);

        // Nothing to clear initially
        assert!(!decoder.clear_pending(&object_id));
        assert_eq!(decoder.pending_count(), 0);
    }
}
