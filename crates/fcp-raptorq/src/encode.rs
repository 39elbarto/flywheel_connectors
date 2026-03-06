//! `RaptorQ` encoder implementation.

// Allow truncation casts - symbol counts are bounded by protocol
#![allow(clippy::cast_possible_truncation)]

use asupersync::raptorq::systematic::SystematicEncoder;

use crate::chunk::{ChunkedObjectManifest, RawChunk};
use crate::config::RaptorQConfig;
use crate::error::EncodeError;
use crate::oti::ObjectTransmissionInformation;

/// `RaptorQ` encoder for producing symbols from a payload.
pub struct RaptorQEncoder {
    inner: SystematicEncoder,
    /// Original source symbol data (each exactly `symbol_size` bytes, last may be zero-padded).
    source_data: Vec<Vec<u8>>,
    config: RaptorQConfig,
    payload_len: usize,
}

impl RaptorQEncoder {
    /// Create encoder for a payload.
    ///
    /// # Errors
    ///
    /// Returns `EncodeError::PayloadTooLarge` if payload exceeds max object size.
    /// Returns `EncodeError::EmptyPayload` if payload is empty.
    ///
    /// # Panics
    ///
    /// Panics if `SystematicEncoder::new` fails for a non-empty, within-limits payload
    /// (should not happen in practice).
    pub fn new(payload: &[u8], config: &RaptorQConfig) -> Result<Self, EncodeError> {
        if payload.is_empty() {
            return Err(EncodeError::EmptyPayload);
        }

        if payload.len() > config.max_object_size as usize {
            return Err(EncodeError::PayloadTooLarge {
                size: payload.len(),
                max: config.max_object_size as usize,
            });
        }

        let symbol_size = usize::from(config.symbol_size);

        // Split payload into symbol-sized chunks, zero-padding the last one
        let source_symbols: Vec<Vec<u8>> = payload
            .chunks(symbol_size)
            .map(|chunk| {
                if chunk.len() == symbol_size {
                    chunk.to_vec()
                } else {
                    let mut padded = vec![0u8; symbol_size];
                    padded[..chunk.len()].copy_from_slice(chunk);
                    padded
                }
            })
            .collect();

        let inner = SystematicEncoder::new(&source_symbols, symbol_size, 0)
            .expect("SystematicEncoder::new failed for valid payload");

        Ok(Self {
            inner,
            source_data: source_symbols,
            config: config.clone(),
            payload_len: payload.len(),
        })
    }

    /// Get K (number of source symbols).
    #[must_use]
    pub fn source_symbols(&self) -> u32 {
        self.config.source_symbols(self.payload_len)
    }

    /// Get the number of repair symbols that will be generated.
    #[must_use]
    pub fn repair_symbols(&self) -> u32 {
        self.config.repair_symbols(self.source_symbols())
    }

    /// Get total symbols (source + repair).
    #[must_use]
    pub fn total_symbols(&self) -> u32 {
        self.source_symbols() + self.repair_symbols()
    }

    /// Generate all source + repair symbols.
    ///
    /// Returns a vector of (ESI, `symbol_data`) tuples.
    /// Source symbols have ESI 0..K-1, repair symbols have ESI K'..K'+R-1
    /// (K' is the RFC 6330 extended source block size, always >= K).
    #[must_use]
    pub fn encode_all(&self) -> Vec<(u32, Vec<u8>)> {
        let repair_count = self.repair_symbols();
        let k_prime = self.inner.params().k_prime as u32;

        let mut result = Vec::with_capacity(self.source_data.len() + repair_count as usize);

        // Source symbols (ESI 0..K): systematic — original data passed through
        for (esi, data) in self.source_data.iter().enumerate() {
            result.push((esi as u32, data.clone()));
        }

        // Repair symbols (ESI K'..K'+repair): RFC 6330 requires repair ISIs
        // start at K' (after the virtual padding range K..K').
        for i in 0..repair_count {
            let esi = k_prime + i;
            let data = self.inner.repair_symbol(esi);
            result.push((esi, data));
        }

        result
    }

    /// Generate source symbols only.
    #[must_use]
    pub fn encode_source(&self) -> Vec<(u32, Vec<u8>)> {
        self.source_data
            .iter()
            .enumerate()
            .map(|(esi, data)| (esi as u32, data.clone()))
            .collect()
    }

    /// Get the object transmission information for this encoding.
    #[must_use]
    pub const fn transmission_info(&self) -> ObjectTransmissionInformation {
        ObjectTransmissionInformation::new(
            self.payload_len as u64,
            self.config.symbol_size,
            1,
            1,
            8,
        )
    }

    /// Get the payload length.
    #[must_use]
    pub const fn payload_len(&self) -> usize {
        self.payload_len
    }

    /// Get K' (RFC 6330 extended source block size, always >= K).
    #[must_use]
    pub const fn inner_k_prime(&self) -> u32 {
        self.inner.params().k_prime as u32
    }

    /// Get the symbol size.
    #[must_use]
    pub const fn symbol_size(&self) -> u16 {
        self.config.symbol_size
    }
}

/// Encoding decision based on payload size.
#[derive(Clone, Debug)]
pub enum EncodingDecision {
    /// Small object: encode directly with `RaptorQ`.
    Direct {
        /// Encoded symbols (ESI, data).
        symbols: Vec<(u32, Vec<u8>)>,
        /// Object transmission info for decoding.
        transmission_info: ObjectTransmissionInformation,
    },
    /// Large object: use chunked manifest.
    Chunked {
        /// The manifest referencing chunks.
        manifest: ChunkedObjectManifest,
        /// The raw chunks to store separately.
        chunks: Vec<RawChunk>,
    },
}

impl EncodingDecision {
    /// Decide encoding strategy for a payload.
    ///
    /// # Errors
    ///
    /// Returns `EncodeError::PayloadTooLarge` if payload exceeds max object size.
    pub fn for_payload(payload: &[u8], config: &RaptorQConfig) -> Result<Self, EncodeError> {
        if payload.is_empty() {
            // Empty payloads use direct encoding with no symbols
            return Ok(Self::Direct {
                symbols: vec![],
                transmission_info: ObjectTransmissionInformation::new(
                    0,
                    config.symbol_size,
                    1,
                    1,
                    8,
                ),
            });
        }

        if payload.len() > config.max_object_size as usize {
            return Err(EncodeError::PayloadTooLarge {
                size: payload.len(),
                max: config.max_object_size as usize,
            });
        }

        if config.requires_chunking(payload.len()) {
            // Large object: use chunking
            let (manifest, chunks) =
                ChunkedObjectManifest::from_payload(payload, config.chunk_size);
            Ok(Self::Chunked { manifest, chunks })
        } else {
            // Small object: direct RaptorQ
            let encoder = RaptorQEncoder::new(payload, config)?;
            let symbols = encoder.encode_all();
            let transmission_info = encoder.transmission_info();
            Ok(Self::Direct {
                symbols,
                transmission_info,
            })
        }
    }

    /// Check if this is a direct encoding.
    #[must_use]
    pub const fn is_direct(&self) -> bool {
        matches!(self, Self::Direct { .. })
    }

    /// Check if this is a chunked encoding.
    #[must_use]
    pub const fn is_chunked(&self) -> bool {
        matches!(self, Self::Chunked { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> RaptorQConfig {
        RaptorQConfig {
            symbol_size: 64, // Small symbols for testing
            repair_ratio_bps: 500,
            max_object_size: 1024 * 1024,
            decode_timeout: std::time::Duration::from_secs(30),
            max_chunk_threshold: 1024, // 1KB threshold for testing
            chunk_size: 256,           // 256 byte chunks for testing
        }
    }

    #[test]
    fn encoder_creation() {
        let config = test_config();
        let payload = vec![42u8; 512];
        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();

        assert_eq!(encoder.payload_len(), 512);
        assert_eq!(encoder.symbol_size(), 64);
        // 512 bytes / 64 byte symbols = 8 source symbols
        assert_eq!(encoder.source_symbols(), 8);
    }

    #[test]
    fn encoder_empty_payload_rejected() {
        let config = test_config();
        let result = RaptorQEncoder::new(&[], &config);
        assert!(matches!(result, Err(EncodeError::EmptyPayload)));
    }

    #[test]
    fn encoder_oversized_payload_rejected() {
        let config = test_config();
        let oversized = vec![0u8; 2 * 1024 * 1024]; // 2MB, over 1MB limit
        let result = RaptorQEncoder::new(&oversized, &config);
        assert!(matches!(result, Err(EncodeError::PayloadTooLarge { .. })));
    }

    #[test]
    fn encoder_repair_symbols() {
        let config = test_config();
        let payload = vec![42u8; 640]; // 10 source symbols
        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();

        assert_eq!(encoder.source_symbols(), 10);
        // 5% of 10 = 0 (rounds down)
        assert_eq!(encoder.repair_symbols(), 0);

        // Larger payload for meaningful repair count
        let payload = vec![42u8; 6400]; // 100 source symbols
        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        assert_eq!(encoder.source_symbols(), 100);
        // 5% of 100 = 5 repair symbols
        assert_eq!(encoder.repair_symbols(), 5);
    }

    #[test]
    fn encoder_encode_all() {
        let config = test_config();
        let payload = vec![42u8; 512];
        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();

        let symbols = encoder.encode_all();
        assert!(!symbols.is_empty());

        // Check that symbols have correct structure
        for (esi, data) in &symbols {
            assert!(!data.is_empty(), "Symbol {esi} should have data");
        }
    }

    #[test]
    fn encoder_encode_source() {
        let config = test_config();
        let payload = vec![42u8; 512];
        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();

        let source_symbols = encoder.encode_source();
        // Should have source symbols only
        assert!(!source_symbols.is_empty());
    }

    #[test]
    fn encoding_decision_direct_small_payload() {
        let config = test_config();
        let payload = vec![42u8; 512]; // Under 1KB threshold

        let decision = EncodingDecision::for_payload(&payload, &config).unwrap();
        assert!(decision.is_direct());
        assert!(!decision.is_chunked());

        if let EncodingDecision::Direct { symbols, .. } = decision {
            assert!(!symbols.is_empty());
        }
    }

    #[test]
    fn encoding_decision_chunked_large_payload() {
        let config = test_config();
        let payload = vec![42u8; 2048]; // Over 1KB threshold

        let decision = EncodingDecision::for_payload(&payload, &config).unwrap();
        assert!(decision.is_chunked());
        assert!(!decision.is_direct());

        if let EncodingDecision::Chunked { manifest, chunks } = decision {
            assert_eq!(manifest.total_len, 2048);
            // 2048 / 256 = 8 chunks
            assert_eq!(chunks.len(), 8);
        }
    }

    #[test]
    fn encoding_decision_empty_payload() {
        let config = test_config();
        let decision = EncodingDecision::for_payload(&[], &config).unwrap();

        assert!(decision.is_direct());
        if let EncodingDecision::Direct { symbols, .. } = decision {
            assert!(symbols.is_empty());
        }
    }

    #[test]
    fn encoding_decision_oversized_rejected() {
        let config = test_config();
        let oversized = vec![0u8; 2 * 1024 * 1024];

        let result = EncodingDecision::for_payload(&oversized, &config);
        assert!(matches!(result, Err(EncodeError::PayloadTooLarge { .. })));
    }

    #[test]
    fn encoding_decision_boundary() {
        let config = test_config();

        // Exactly at threshold - should be direct
        let payload = vec![42u8; 1024];
        let decision = EncodingDecision::for_payload(&payload, &config).unwrap();
        assert!(decision.is_direct());

        // One byte over - should be chunked
        let payload = vec![42u8; 1025];
        let decision = EncodingDecision::for_payload(&payload, &config).unwrap();
        assert!(decision.is_chunked());
    }

    #[test]
    fn encode_decode_roundtrip() {
        let config = test_config();
        let payload: Vec<u8> = (0..512_u32)
            .map(|i| u8::try_from(i % 256).expect("payload byte fits u8"))
            .collect();

        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let symbols = encoder.encode_all();
        let oti = encoder.transmission_info();

        // Create decoder and feed all symbols
        let mut decoder = crate::RaptorQDecoder::new(oti, &config);
        for (esi, data) in symbols {
            if let Ok(Some(decoded)) = decoder.add_symbol(esi, data) {
                assert_eq!(&decoded[..payload.len()], &payload[..]);
                return;
            }
        }

        panic!("Failed to decode payload");
    }

    #[test]
    fn test_encode_source_returns_symbols() {
        let config = RaptorQConfig::default();
        let payload = vec![0u8; 1024]; // Should match symbol size (1024) -> 1 source symbol
        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();

        let source = encoder.encode_source();
        assert!(!source.is_empty(), "encode_source returned empty vector");
        assert_eq!(source.len(), 1, "expected 1 source symbol");
    }

    #[test]
    fn test_encode_all_returns_source_and_repair() {
        let config = RaptorQConfig {
            repair_ratio_bps: 10000, // 100% overhead -> 1 source, 1 repair
            ..RaptorQConfig::default()
        };
        let payload = vec![0u8; 1024];
        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();

        let all = encoder.encode_all();
        // 1 source + 1 repair = 2 total
        assert_eq!(
            all.len(),
            2,
            "expected 2 symbols (1 source + 1 repair), got {}",
            all.len()
        );
    }

    // ── Encoder accessor methods ─────────────────────────────────────────

    #[test]
    fn encoder_total_symbols() {
        let config = test_config();
        let payload = vec![42u8; 6400]; // 100 source symbols
        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();

        let total = encoder.total_symbols();
        assert_eq!(total, encoder.source_symbols() + encoder.repair_symbols());
    }

    #[test]
    fn encoder_inner_k_prime() {
        let config = test_config();
        let payload = vec![42u8; 512];
        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();

        let k_prime = encoder.inner_k_prime();
        // K' >= K (always, per RFC 6330)
        assert!(k_prime >= encoder.source_symbols());
    }

    #[test]
    fn encoder_transmission_info() {
        let config = test_config();
        let payload = vec![42u8; 512];
        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();

        let oti = encoder.transmission_info();
        assert_eq!(oti.transfer_length(), 512);
        assert_eq!(oti.symbol_size(), 64);
    }

    #[test]
    fn encoder_single_byte_payload() {
        let config = test_config();
        let payload = vec![0xAB];
        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();

        assert_eq!(encoder.payload_len(), 1);
        assert_eq!(encoder.source_symbols(), 1);
        assert_eq!(encoder.symbol_size(), 64);

        let source = encoder.encode_source();
        assert_eq!(source.len(), 1);
        // Symbol should be 64 bytes (zero-padded)
        assert_eq!(source[0].1.len(), 64);
        // First byte preserved
        assert_eq!(source[0].1[0], 0xAB);
    }

    #[test]
    fn encoder_payload_exactly_one_symbol() {
        let config = test_config();
        let payload = vec![0xFF; 64]; // Exactly one symbol
        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();

        assert_eq!(encoder.source_symbols(), 1);
        let source = encoder.encode_source();
        assert_eq!(source.len(), 1);
        assert_eq!(source[0].1, vec![0xFF; 64]);
    }

    #[test]
    fn encoder_source_esis_sequential() {
        let config = test_config();
        let payload = vec![42u8; 256]; // 4 source symbols
        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();

        let source = encoder.encode_source();
        for (i, (esi, _)) in source.iter().enumerate() {
            assert_eq!(*esi, i as u32, "source ESI {esi} should be {i}");
        }
    }

    // ── EncodingDecision trait coverage ──────────────────────────────────

    #[test]
    fn encoding_decision_direct_debug() {
        let config = test_config();
        let decision = EncodingDecision::for_payload(&[42u8; 100], &config).unwrap();
        let debug = format!("{decision:?}");
        assert!(debug.contains("Direct"));
    }

    #[test]
    fn encoding_decision_chunked_debug() {
        let config = test_config();
        let decision = EncodingDecision::for_payload(&[42u8; 2048], &config).unwrap();
        let debug = format!("{decision:?}");
        assert!(debug.contains("Chunked"));
    }

    #[test]
    fn encoding_decision_clone() {
        let config = test_config();
        let decision = EncodingDecision::for_payload(&[42u8; 100], &config).unwrap();
        let moved = decision;
        assert!(moved.is_direct());
    }

    #[test]
    fn encode_decode_roundtrip_small() {
        let config = test_config();
        let payload = vec![7u8; 64]; // Exactly one symbol

        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let symbols = encoder.encode_all();
        let oti = encoder.transmission_info();

        let mut decoder = crate::RaptorQDecoder::new(oti, &config);
        for (esi, data) in symbols {
            if let Ok(Some(decoded)) = decoder.add_symbol(esi, data) {
                assert_eq!(decoded, payload);
                return;
            }
        }

        panic!("Failed to decode single-symbol payload");
    }
}
