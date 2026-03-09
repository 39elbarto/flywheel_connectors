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

    // ── Encoder payload boundary tests ─────────────────────────────────────

    #[test]
    fn encoder_payload_at_small_max() {
        // Use a config with a small max_object_size to avoid slow encoding
        let config = RaptorQConfig {
            symbol_size: 64,
            repair_ratio_bps: 500,
            max_object_size: 2048,
            decode_timeout: std::time::Duration::from_secs(30),
            max_chunk_threshold: 1024,
            chunk_size: 256,
        };
        let payload = vec![42u8; 2048]; // Exactly at limit
        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        assert_eq!(encoder.payload_len(), 2048);
    }

    #[test]
    fn encoder_payload_one_over_max() {
        let config = RaptorQConfig {
            symbol_size: 64,
            repair_ratio_bps: 500,
            max_object_size: 2048,
            decode_timeout: std::time::Duration::from_secs(30),
            max_chunk_threshold: 1024,
            chunk_size: 256,
        };
        let payload = vec![42u8; 2049]; // One over limit
        let result = RaptorQEncoder::new(&payload, &config);
        assert!(matches!(result, Err(EncodeError::PayloadTooLarge { .. })));
    }

    #[test]
    fn encoder_payload_not_symbol_aligned() {
        let config = test_config(); // symbol_size = 64
        let payload = vec![42u8; 100]; // 100 bytes, not aligned to 64
        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        // ceil(100 / 64) = 2 source symbols
        assert_eq!(encoder.source_symbols(), 2);

        // Source symbols should be zero-padded
        let source = encoder.encode_source();
        assert_eq!(source.len(), 2);
        assert_eq!(source[0].1.len(), 64); // First symbol: full 64 bytes
        assert_eq!(source[1].1.len(), 64); // Second symbol: 36 real + 28 zero-padded
        // Verify zero-padding in last symbol
        for &byte in &source[1].1[36..] {
            assert_eq!(byte, 0, "expected zero-padding in last symbol");
        }
    }

    #[test]
    fn encoder_encode_all_includes_source_and_repair() {
        let config = RaptorQConfig {
            symbol_size: 64,
            repair_ratio_bps: 5000, // 50% overhead for clear repair count
            max_object_size: 1024 * 1024,
            decode_timeout: std::time::Duration::from_secs(30),
            max_chunk_threshold: 1024,
            chunk_size: 256,
        };
        let payload = vec![42u8; 640]; // 10 source symbols
        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();

        assert_eq!(encoder.source_symbols(), 10);
        assert_eq!(encoder.repair_symbols(), 5); // 50% of 10

        let all = encoder.encode_all();
        assert_eq!(all.len(), 15); // 10 source + 5 repair
    }

    #[test]
    fn encoder_source_data_preserved() {
        let config = test_config();
        let payload: Vec<u8> = (0..128_u8).collect(); // 2 symbols
        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let source = encoder.encode_source();

        // First symbol should be bytes 0..64
        assert_eq!(&source[0].1[..64], &payload[..64]);
        // Second symbol should be bytes 64..128
        assert_eq!(&source[1].1[..64], &payload[64..128]);
    }

    #[test]
    fn encoder_transmission_info_fields() {
        let config = test_config();
        let payload = vec![0u8; 300];
        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let oti = encoder.transmission_info();

        assert_eq!(oti.transfer_length(), 300);
        assert_eq!(oti.symbol_size(), 64);
        assert_eq!(oti.source_blocks(), 1);
        assert_eq!(oti.sub_blocks(), 1);
        assert_eq!(oti.symbol_alignment(), 8);
    }

    #[test]
    fn encoder_k_prime_ge_k() {
        // K' should always be >= K per RFC 6330
        let config = test_config();
        for size in [64, 128, 256, 512, 1024] {
            let payload = vec![42u8; size];
            let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
            assert!(
                encoder.inner_k_prime() >= encoder.source_symbols(),
                "K' ({}) < K ({}) for payload size {size}",
                encoder.inner_k_prime(),
                encoder.source_symbols(),
            );
        }
    }

    // ── EncodingDecision additional tests ──────────────────────────────────

    #[test]
    fn encoding_decision_chunked_manifest_fields() {
        let config = test_config();
        let payload = vec![42u8; 4096]; // Over 1KB threshold

        let decision = EncodingDecision::for_payload(&payload, &config).unwrap();
        if let EncodingDecision::Chunked { manifest, chunks } = decision {
            assert_eq!(manifest.total_len, 4096);
            assert_eq!(manifest.chunk_size, 256);
            // 4096 / 256 = 16 chunks
            assert_eq!(chunks.len(), 16);
            assert_eq!(manifest.chunk_count(), 16);
            // Verify manifest hash matches payload
            assert!(manifest.verify_hash(&payload));
        } else {
            panic!("expected Chunked decision");
        }
    }

    #[test]
    fn encoding_decision_direct_has_symbols_and_oti() {
        let config = test_config();
        let payload = vec![42u8; 256]; // Under threshold

        let decision = EncodingDecision::for_payload(&payload, &config).unwrap();
        if let EncodingDecision::Direct {
            symbols,
            transmission_info,
        } = decision
        {
            assert!(!symbols.is_empty());
            assert_eq!(transmission_info.transfer_length(), 256);
            assert_eq!(transmission_info.symbol_size(), 64);
        } else {
            panic!("expected Direct decision");
        }
    }

    #[test]
    fn encode_decode_roundtrip_varying_sizes() {
        let config = test_config();
        for size in [1_usize, 32, 63, 64, 65, 128, 255, 256, 512, 1024] {
            let payload: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
            let symbols = encoder.encode_all();
            let oti = encoder.transmission_info();

            let mut dec = crate::RaptorQDecoder::new(oti, &config);
            let mut result = None;
            for (esi, data) in symbols {
                if let Ok(Some(d)) = dec.add_symbol(esi, data) {
                    result = Some(d);
                    break;
                }
            }
            let output = result.unwrap_or_else(|| {
                panic!("Failed to decode payload of size {size}");
            });
            assert_eq!(
                &output[..payload.len()],
                &payload[..],
                "roundtrip failed for size {size}"
            );
        }
    }

    // ── Additional encoding tests ─────────────────────────────────────────

    #[test]
    fn encoding_decision_direct_empty_has_oti() {
        let config = test_config();
        let decision = EncodingDecision::for_payload(&[], &config).unwrap();
        if let EncodingDecision::Direct {
            symbols,
            transmission_info,
        } = decision
        {
            assert!(symbols.is_empty());
            assert_eq!(transmission_info.transfer_length(), 0);
            assert_eq!(transmission_info.symbol_size(), 64);
            assert_eq!(transmission_info.source_blocks(), 1);
            assert_eq!(transmission_info.sub_blocks(), 1);
            assert_eq!(transmission_info.symbol_alignment(), 8);
        } else {
            panic!("expected Direct decision for empty payload");
        }
    }

    #[test]
    fn encoding_decision_chunked_has_correct_chunk_count() {
        let config = test_config(); // chunk_size = 256, threshold = 1024
        let payload = vec![42u8; 3000];
        let decision = EncodingDecision::for_payload(&payload, &config).unwrap();
        if let EncodingDecision::Chunked { manifest, chunks } = decision {
            // 3000 / 256 = 11.71 -> 12 chunks
            assert_eq!(manifest.chunk_count(), 12);
            assert_eq!(chunks.len(), 12);
        } else {
            panic!("expected Chunked decision");
        }
    }

    #[test]
    fn encoding_decision_at_max_object_size() {
        let config = RaptorQConfig {
            symbol_size: 64,
            repair_ratio_bps: 500,
            max_object_size: 2048,
            decode_timeout: std::time::Duration::from_secs(30),
            max_chunk_threshold: 4096, // above max_object_size
            chunk_size: 256,
        };
        let payload = vec![42u8; 2048];
        let decision = EncodingDecision::for_payload(&payload, &config).unwrap();
        assert!(decision.is_direct());
    }

    #[test]
    fn encoding_decision_over_max_object_size() {
        let config = RaptorQConfig {
            symbol_size: 64,
            repair_ratio_bps: 500,
            max_object_size: 2048,
            decode_timeout: std::time::Duration::from_secs(30),
            max_chunk_threshold: 4096,
            chunk_size: 256,
        };
        let payload = vec![42u8; 2049];
        let result = EncodingDecision::for_payload(&payload, &config);
        assert!(matches!(result, Err(EncodeError::PayloadTooLarge { .. })));
    }

    #[test]
    fn encoder_encode_all_esis_are_valid() {
        let config = test_config();
        let payload = vec![42u8; 640]; // 10 source symbols
        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let all = encoder.encode_all();

        // Source ESIs are 0..K
        let k = encoder.source_symbols();
        for (esi, _) in &all[..k as usize] {
            assert!(*esi < k, "source ESI {esi} should be < K={k}");
        }
    }

    #[test]
    fn encoder_symbol_sizes_are_consistent() {
        let config = test_config();
        let payload = vec![42u8; 512];
        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let all = encoder.encode_all();

        for (esi, data) in &all {
            assert_eq!(
                data.len(),
                usize::from(encoder.symbol_size()),
                "symbol {esi} has wrong size"
            );
        }
    }

    #[test]
    fn encoding_decision_clone_direct() {
        let config = test_config();
        let decision = EncodingDecision::for_payload(&[42u8; 100], &config).unwrap();
        let cloned = decision.clone();
        assert!(decision.is_direct());
        assert!(cloned.is_direct());
    }

    #[test]
    fn encoding_decision_clone_chunked() {
        let config = test_config();
        let decision = EncodingDecision::for_payload(&[42u8; 2048], &config).unwrap();
        let cloned = decision.clone();
        assert!(decision.is_chunked());
        assert!(cloned.is_chunked());
    }

    #[test]
    fn encoder_two_symbol_payload() {
        let config = test_config(); // symbol_size = 64
        let payload = vec![0xAB; 128]; // exactly 2 symbols
        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        assert_eq!(encoder.source_symbols(), 2);
        assert_eq!(encoder.payload_len(), 128);

        let source = encoder.encode_source();
        assert_eq!(source.len(), 2);
        assert_eq!(source[0].0, 0);
        assert_eq!(source[1].0, 1);
    }

    #[test]
    fn encoder_three_symbol_boundary() {
        let config = test_config(); // symbol_size = 64
        let payload = vec![0xCD; 129]; // 3 symbols (ceil 129/64)
        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        assert_eq!(encoder.source_symbols(), 3);

        let source = encoder.encode_source();
        assert_eq!(source.len(), 3);
        // Last symbol should be zero-padded
        // 129 - 128 = 1 real byte in last symbol
        assert_eq!(source[2].1[0], 0xCD);
        for &byte in &source[2].1[1..] {
            assert_eq!(byte, 0, "expected zero padding");
        }
    }

    // ── Additional encoder tests (batch 2) ────────────────────────────────

    #[test]
    fn encoder_encode_source_esis_start_at_zero() {
        let config = test_config();
        let payload = vec![42u8; 320]; // 5 symbols
        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let source = encoder.encode_source();
        assert_eq!(source[0].0, 0);
    }

    #[test]
    fn encoder_encode_all_repair_esis_start_at_k_prime() {
        let config = RaptorQConfig {
            symbol_size: 64,
            repair_ratio_bps: 10000, // 100% overhead
            max_object_size: 1024 * 1024,
            decode_timeout: std::time::Duration::from_secs(30),
            max_chunk_threshold: 1024,
            chunk_size: 256,
        };
        let payload = vec![42u8; 640]; // 10 source symbols
        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let k = encoder.source_symbols();
        let k_prime = encoder.inner_k_prime();
        let all = encoder.encode_all();

        // Repair symbols start after source symbols
        for (esi, _) in &all[k as usize..] {
            assert!(
                *esi >= k_prime,
                "repair ESI {esi} should be >= K'={k_prime}"
            );
        }
    }

    #[test]
    fn encoder_total_symbols_equals_source_plus_repair() {
        let config = test_config();
        let payload = vec![42u8; 6400];
        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        assert_eq!(
            encoder.total_symbols(),
            encoder.source_symbols() + encoder.repair_symbols()
        );
    }

    #[test]
    fn encoding_decision_is_direct_and_is_chunked_are_exclusive() {
        let config = test_config();
        let direct = EncodingDecision::for_payload(&[42u8; 100], &config).unwrap();
        assert!(direct.is_direct());
        assert!(!direct.is_chunked());

        let chunked = EncodingDecision::for_payload(&[42u8; 2048], &config).unwrap();
        assert!(chunked.is_chunked());
        assert!(!chunked.is_direct());
    }

    #[test]
    fn encoder_with_default_config() {
        let config = RaptorQConfig::default();
        let payload = vec![0u8; 2048]; // 2 symbols at 1024 each
        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        assert_eq!(encoder.source_symbols(), 2);
        assert_eq!(encoder.symbol_size(), 1024);
        assert_eq!(encoder.payload_len(), 2048);
    }

    #[test]
    fn encoding_decision_chunked_chunks_reconstruct() {
        let config = test_config();
        let payload: Vec<u8> = (0..2048_u32).map(|i| (i % 256) as u8).collect();
        let decision = EncodingDecision::for_payload(&payload, &config).unwrap();
        if let EncodingDecision::Chunked { manifest, chunks } = decision {
            let reconstructed = manifest.reconstruct(&chunks).unwrap();
            assert_eq!(reconstructed, payload);
        } else {
            panic!("expected Chunked decision");
        }
    }

    #[test]
    fn encoder_zero_repair_ratio() {
        let config = RaptorQConfig {
            symbol_size: 64,
            repair_ratio_bps: 0,
            max_object_size: 1024 * 1024,
            decode_timeout: std::time::Duration::from_secs(30),
            max_chunk_threshold: 1024,
            chunk_size: 256,
        };
        let payload = vec![42u8; 640]; // 10 source symbols
        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        assert_eq!(encoder.repair_symbols(), 0);
        assert_eq!(encoder.total_symbols(), 10);

        let all = encoder.encode_all();
        assert_eq!(all.len(), 10); // Only source symbols
    }

    #[test]
    fn encoding_decision_debug_format_empty() {
        let config = test_config();
        let decision = EncodingDecision::for_payload(&[], &config).unwrap();
        let debug = format!("{decision:?}");
        assert!(debug.contains("Direct"));
    }

    #[test]
    fn encoder_transmission_info_is_const() {
        let config = test_config();
        let payload = vec![42u8; 256];
        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let oti1 = encoder.transmission_info();
        let oti2 = encoder.transmission_info();
        assert_eq!(oti1, oti2);
    }

    #[test]
    fn encoder_all_symbols_have_consistent_size() {
        let config = test_config();
        let payload = vec![42u8; 300]; // Not aligned to 64
        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let all = encoder.encode_all();
        let expected_size = usize::from(encoder.symbol_size());
        for (esi, data) in &all {
            assert_eq!(
                data.len(),
                expected_size,
                "symbol ESI={esi} has size {} instead of {expected_size}",
                data.len()
            );
        }
    }

    #[test]
    fn encoding_decision_at_exactly_threshold_is_direct() {
        let config = test_config(); // threshold = 1024
        let payload = vec![42u8; 1024];
        let decision = EncodingDecision::for_payload(&payload, &config).unwrap();
        assert!(decision.is_direct(), "payload at threshold should be direct");
    }

    #[test]
    fn encoding_decision_one_over_threshold_is_chunked() {
        let config = test_config(); // threshold = 1024
        let payload = vec![42u8; 1025];
        let decision = EncodingDecision::for_payload(&payload, &config).unwrap();
        assert!(
            decision.is_chunked(),
            "payload over threshold should be chunked"
        );
    }
}
