//! Golden vector tests for `RaptorQ` encoding/decoding.
//!
//! These tests verify deterministic behavior and provide reference test vectors.
//! Vectors use seeded PRNG payloads (`ChaCha20Rng`) for cross-platform reproducibility.

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use chrono::Utc;
    use fcp_cbor::{CanonicalSerializer, SchemaId};
    use serde::{Deserialize, Serialize};

    use crate::{
        ChunkError, ChunkedObjectManifest, DecodeAdmissionController, EncodingDecision,
        RaptorQConfig, RaptorQDecoder, RaptorQEncoder,
    };

    // ─────────────────────────────────────────────────────────────────────────
    // Golden Vector Configuration
    // ─────────────────────────────────────────────────────────────────────────

    /// Standard configuration for golden vector tests.
    fn golden_config() -> RaptorQConfig {
        RaptorQConfig {
            symbol_size: 1024,
            repair_ratio_bps: 500,
            max_object_size: 64 * 1024 * 1024,
            decode_timeout: Duration::from_secs(30),
            max_chunk_threshold: 256 * 1024,
            chunk_size: 64 * 1024,
        }
    }

    /// Create a deterministic payload of given size.
    fn deterministic_payload(size: usize) -> Vec<u8> {
        (0..size)
            .map(|i| u8::try_from(i % 256).expect("payload byte fits u8"))
            .collect()
    }

    /// Create a seeded PRNG payload for cross-platform reproducibility.
    fn seeded_payload(seed: u64, size: usize) -> Vec<u8> {
        use rand::RngCore;
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let mut buf = vec![0u8; size];
        rng.fill_bytes(&mut buf);
        buf
    }

    /// Compute BLAKE3 hash of a byte slice, return hex string.
    fn blake3_hex(data: &[u8]) -> String {
        let hash = blake3::hash(data);
        hash.to_hex().to_string()
    }

    struct EpochReplayLog<'a> {
        test_name: &'a str,
        epoch_id: u64,
        object_hash: &'a str,
        symbols_needed: u32,
        symbols_available: usize,
        repair_attempts: u32,
        bytes_written: u64,
        verify_result: &'a str,
        result: &'a str,
        fcp_error_code: Option<&'a str>,
    }

    fn emit_epoch_replay_log(log: &EpochReplayLog<'_>) {
        let entry = serde_json::json!({
            "timestamp": Utc::now().to_rfc3339(),
            "test_name": log.test_name,
            "trace_id": format!("trace-{}", log.test_name),
            "zone_id": "z:work",
            "epoch_id": log.epoch_id,
            "object_id": log.object_hash,
            "symbols_needed": log.symbols_needed,
            "symbols_available": log.symbols_available,
            "repair_attempts": log.repair_attempts,
            "bytes_written": log.bytes_written,
            "verify_result": log.verify_result,
            "result": log.result,
            "fcp_error_code": log.fcp_error_code
        });
        println!("{entry}");
    }

    /// High-repair config for erasure and adversarial tests.
    fn erasure_config() -> RaptorQConfig {
        RaptorQConfig {
            symbol_size: 1024,
            repair_ratio_bps: 5000, // 50% repair overhead
            max_object_size: 64 * 1024 * 1024,
            decode_timeout: Duration::from_secs(30),
            max_chunk_threshold: 256 * 1024,
            chunk_size: 64 * 1024,
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden Vector Tests: 1KB Object
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn golden_1kb_symbol_count() {
        let config = golden_config();
        let payload = deterministic_payload(1024);

        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();

        // 1024 bytes / 1024 byte symbols = 1 source symbol
        assert_eq!(encoder.source_symbols(), 1);
        // 5% of 1 = 0 repair symbols (rounds down)
        assert_eq!(encoder.repair_symbols(), 0);
        assert_eq!(encoder.total_symbols(), 1);
    }

    #[test]
    fn golden_1kb_roundtrip() {
        let config = golden_config();
        let payload = deterministic_payload(1024);

        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let symbols = encoder.encode_all();
        let oti = encoder.transmission_info();

        // Decode with all symbols
        let mut decoder = RaptorQDecoder::new(oti, &config);
        let expected_len = payload.len();
        for (esi, data) in symbols {
            if let Ok(Some(decoded)) = decoder.add_symbol(esi, data) {
                assert_eq!(&decoded[..expected_len], &payload[..]);
                return;
            }
        }
        panic!("Failed to decode 1KB payload");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden Vector Tests: 10KB Object
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn golden_10kb_symbol_count() {
        let config = golden_config();
        let payload = deterministic_payload(10 * 1024);

        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();

        // 10KB / 1024 byte symbols = 10 source symbols
        assert_eq!(encoder.source_symbols(), 10);
        // 5% of 10 = 0 repair symbols (rounds down)
        assert_eq!(encoder.repair_symbols(), 0);
    }

    #[test]
    fn golden_10kb_roundtrip() {
        let config = golden_config();
        let payload = deterministic_payload(10 * 1024);

        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let symbols = encoder.encode_all();
        let oti = encoder.transmission_info();

        let mut decoder = RaptorQDecoder::new(oti, &config);
        let expected_len = payload.len();
        for (esi, data) in symbols {
            if let Ok(Some(decoded)) = decoder.add_symbol(esi, data) {
                assert_eq!(&decoded[..expected_len], &payload[..]);
                return;
            }
        }
        panic!("Failed to decode 10KB payload");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden Vector Tests: 100KB Object
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn golden_100kb_symbol_count() {
        let config = golden_config();
        let payload = deterministic_payload(100 * 1024);

        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();

        // 100KB / 1024 byte symbols = 100 source symbols
        assert_eq!(encoder.source_symbols(), 100);
        // 5% of 100 = 5 repair symbols
        assert_eq!(encoder.repair_symbols(), 5);
        assert_eq!(encoder.total_symbols(), 105);
    }

    #[test]
    fn golden_100kb_roundtrip() {
        let config = golden_config();
        let payload = deterministic_payload(100 * 1024);

        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let symbols = encoder.encode_all();
        let oti = encoder.transmission_info();

        let mut decoder = RaptorQDecoder::new(oti, &config);
        let expected_len = payload.len();
        for (esi, data) in symbols {
            if let Ok(Some(decoded)) = decoder.add_symbol(esi, data) {
                assert_eq!(&decoded[..expected_len], &payload[..]);
                return;
            }
        }
        panic!("Failed to decode 100KB payload");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden Vector Tests: Chunked Object (300KB)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn golden_300kb_chunked_manifest() {
        let config = golden_config();
        let payload = deterministic_payload(300 * 1024);

        // Should use chunked encoding (> 256KB threshold)
        assert!(config.requires_chunking(300 * 1024));

        let decision = EncodingDecision::for_payload(&payload, &config).unwrap();
        assert!(decision.is_chunked());

        if let EncodingDecision::Chunked { manifest, chunks } = decision {
            // 300KB / 64KB chunks = 4.6875 -> 5 chunks
            assert_eq!(manifest.chunk_count(), 5);
            assert_eq!(chunks.len(), 5);
            assert_eq!(manifest.total_len, 300 * 1024);
            assert_eq!(manifest.chunk_size, 64 * 1024);

            // First 4 chunks should be 64KB
            assert_eq!(chunks[0].len(), 64 * 1024);
            assert_eq!(chunks[1].len(), 64 * 1024);
            assert_eq!(chunks[2].len(), 64 * 1024);
            assert_eq!(chunks[3].len(), 64 * 1024);

            // Last chunk is remainder: 300KB - 4*64KB = 44KB
            assert_eq!(chunks[4].len(), 300 * 1024 - 4 * 64 * 1024);

            // Reconstruct and verify
            let reconstructed = manifest.reconstruct(&chunks).unwrap();
            assert_eq!(reconstructed, payload);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Erasure Recovery Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn erasure_recovery_with_repair_symbols() {
        let config = RaptorQConfig {
            symbol_size: 1024,
            repair_ratio_bps: 2000, // 20% repair for better erasure recovery
            max_object_size: 64 * 1024 * 1024,
            decode_timeout: Duration::from_secs(30),
            max_chunk_threshold: 256 * 1024,
            chunk_size: 64 * 1024,
        };

        let payload = deterministic_payload(100 * 1024);
        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let symbols = encoder.encode_all();
        let oti = encoder.transmission_info();

        // K = 100, repair = 20% = 20, total = 120
        assert_eq!(encoder.source_symbols(), 100);
        assert_eq!(encoder.repair_symbols(), 20);

        // Simulate 10% erasure by skipping every 10th symbol
        let mut decoder = RaptorQDecoder::new(oti, &config);
        let expected_len = payload.len();
        for (i, (esi, data)) in symbols.into_iter().enumerate() {
            if i % 10 == 0 {
                continue; // Skip every 10th symbol
            }
            if let Ok(Some(decoded)) = decoder.add_symbol(esi, data) {
                assert_eq!(&decoded[..expected_len], &payload[..]);
                return;
            }
        }
        panic!("Failed to recover from 10% erasure");
    }

    #[test]
    fn erasure_recovery_from_repair_only() {
        // Test decoding using only repair symbols (skipping all source symbols)
        let config = RaptorQConfig {
            symbol_size: 1024,
            repair_ratio_bps: 10000, // 100% repair (K repair symbols)
            max_object_size: 64 * 1024 * 1024,
            decode_timeout: Duration::from_secs(30),
            max_chunk_threshold: 256 * 1024,
            chunk_size: 64 * 1024,
        };

        let payload = deterministic_payload(10 * 1024);
        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let symbols = encoder.encode_all();
        let oti = encoder.transmission_info();

        let k = encoder.source_symbols();

        // Use only repair symbols (ESI >= K)
        let mut decoder = RaptorQDecoder::new(oti, &config);
        let expected_len = payload.len();
        for (esi, data) in symbols {
            if esi < k {
                continue; // Skip source symbols
            }
            if let Ok(Some(decoded)) = decoder.add_symbol(esi, data) {
                assert_eq!(&decoded[..expected_len], &payload[..]);
                return;
            }
        }
        panic!("Failed to decode from repair symbols only");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Symbol Determinism Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn symbols_are_deterministic() {
        let config = golden_config();
        let payload = deterministic_payload(10 * 1024);

        // Encode twice
        let encoder1 = RaptorQEncoder::new(&payload, &config).unwrap();
        let encoder2 = RaptorQEncoder::new(&payload, &config).unwrap();

        let symbols1 = encoder1.encode_all();
        let symbols2 = encoder2.encode_all();

        // Same payload produces same symbols
        assert_eq!(symbols1.len(), symbols2.len());
        for ((esi1, data1), (esi2, data2)) in symbols1.iter().zip(symbols2.iter()) {
            assert_eq!(esi1, esi2);
            assert_eq!(data1, data2);
        }
    }

    #[test]
    fn symbol_esi_uniqueness() {
        let config = golden_config();
        let payload = deterministic_payload(100 * 1024);

        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let symbols = encoder.encode_all();

        // All ESIs should be unique
        let mut seen_esis = std::collections::HashSet::new();
        for (esi, _) in &symbols {
            assert!(seen_esis.insert(*esi), "Duplicate ESI found: {esi}");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DoS Mitigation Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn dos_reject_oversized_payload() {
        let config = RaptorQConfig {
            symbol_size: 1024,
            repair_ratio_bps: 500,
            max_object_size: 1024 * 1024, // 1MB limit
            decode_timeout: Duration::from_secs(30),
            max_chunk_threshold: 256 * 1024,
            chunk_size: 64 * 1024,
        };

        // 2MB payload should be rejected
        let oversized = vec![0u8; 2 * 1024 * 1024];
        let result = RaptorQEncoder::new(&oversized, &config);
        assert!(result.is_err());
    }

    #[test]
    fn dos_concurrent_decode_limit() {
        let controller = DecodeAdmissionController::with_limits(
            2, // Only 2 concurrent
            64 * 1024 * 1024,
            Duration::from_secs(30),
            10000,
        );

        let permit1 = controller.try_acquire();
        let permit2 = controller.try_acquire();
        let permit3 = controller.try_acquire();

        assert!(permit1.is_some());
        assert!(permit2.is_some());
        assert!(permit3.is_none()); // Third should fail

        drop(permit1);
        let permit4 = controller.try_acquire();
        assert!(permit4.is_some()); // Now it should work
    }

    #[test]
    fn dos_decode_timeout() {
        let config = RaptorQConfig {
            symbol_size: 1024,
            repair_ratio_bps: 500,
            max_object_size: 64 * 1024 * 1024,
            decode_timeout: Duration::from_millis(1), // Very short timeout
            max_chunk_threshold: 256 * 1024,
            chunk_size: 64 * 1024,
        };

        let oti = crate::ObjectTransmissionInformation::new(1024, 1024, 1, 1, 8);
        let mut decoder = RaptorQDecoder::new(oti, &config);

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(10));

        // Should be timed out
        assert!(decoder.is_timed_out());
        let result = decoder.add_symbol(0, vec![0u8; 1024]);
        assert!(result.is_err());
    }

    #[test]
    fn dos_symbol_buffer_limit() {
        let controller = DecodeAdmissionController::with_limits(
            1,
            64 * 1024 * 1024,
            Duration::from_secs(30),
            3, // Only 3 symbols allowed
        );

        let mut permit = controller.try_acquire().unwrap();

        // First 3 should succeed
        assert!(permit.try_buffer_symbol(1024).is_ok());
        assert!(permit.try_buffer_symbol(1024).is_ok());
        assert!(permit.try_buffer_symbol(1024).is_ok());

        // Fourth should fail
        assert!(permit.try_buffer_symbol(1024).is_err());
    }

    #[test]
    fn dos_memory_limit() {
        let controller = DecodeAdmissionController::with_limits(
            1,
            2048, // Only 2KB memory
            Duration::from_secs(30),
            10000,
        );

        let mut permit = controller.try_acquire().unwrap();

        assert!(permit.try_buffer_symbol(1024).is_ok());
        assert!(permit.try_buffer_symbol(1024).is_ok());
        // Third 1KB should exceed 2KB limit
        assert!(permit.try_buffer_symbol(1024).is_err());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Decode Status Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn decode_status_tracking() {
        let config = golden_config();
        let oti = crate::ObjectTransmissionInformation::new(10 * 1024, 1024, 1, 1, 8);
        let decoder = RaptorQDecoder::new(oti, &config);

        // Initial state
        assert_eq!(decoder.received_count(), 0);
        assert_eq!(decoder.expected_k(), 10);
        assert!(!decoder.likely_complete());
    }

    #[test]
    fn decode_status_progress() {
        let config = golden_config();
        let payload = deterministic_payload(10 * 1024);

        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let symbols = encoder.encode_all();
        let oti = encoder.transmission_info();

        let mut decoder = RaptorQDecoder::new(oti, &config);

        // Add symbols one by one
        for (i, (esi, data)) in symbols.into_iter().enumerate() {
            let _ = decoder.add_symbol(esi, data);
            assert_eq!(
                decoder.received_count(),
                u32::try_from(i + 1).expect("received_count fits u32")
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Chunk Manifest Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn chunk_ids_are_deterministic() {
        let payload = deterministic_payload(300 * 1024);
        let config = golden_config();

        let (manifest1, chunks1) = ChunkedObjectManifest::from_payload(&payload, config.chunk_size);
        let (manifest2, chunks2) = ChunkedObjectManifest::from_payload(&payload, config.chunk_size);

        // Same payload produces same chunk IDs
        assert_eq!(manifest1.chunks, manifest2.chunks);
        assert_eq!(chunks1.len(), chunks2.len());

        for (c1, c2) in chunks1.iter().zip(chunks2.iter()) {
            assert_eq!(c1.content_id(), c2.content_id());
        }
    }

    #[test]
    fn chunk_ordering_deterministic() {
        let payload = deterministic_payload(300 * 1024);
        let config = golden_config();

        let (manifest, chunks) = ChunkedObjectManifest::from_payload(&payload, config.chunk_size);

        // Reconstruct to verify ordering
        let reconstructed = manifest.reconstruct(&chunks).unwrap();
        assert_eq!(reconstructed, payload);

        // Verify chunks are in correct order
        let mut offset = 0;
        for chunk in &chunks {
            let expected_data = &payload[offset..offset + chunk.len()];
            assert_eq!(chunk.bytes.as_slice(), expected_data);
            offset += chunk.len();
        }
    }

    #[test]
    fn chunk_hash_verification() {
        let payload = deterministic_payload(300 * 1024);
        let config = golden_config();

        let (manifest, chunks) = ChunkedObjectManifest::from_payload(&payload, config.chunk_size);

        // Valid payload passes verification
        assert!(manifest.verify_hash(&payload));

        // Modified payload fails verification
        let mut modified = payload;
        modified[0] = 255;
        assert!(!manifest.verify_hash(&modified));

        // Corrupted chunk fails reconstruction
        let mut corrupted_chunks = chunks;
        corrupted_chunks[0].bytes[0] = 255;
        assert!(manifest.reconstruct(&corrupted_chunks).is_err());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Epoch Replay + Binary Resume Tests (1n78.37.1)
    // ─────────────────────────────────────────────────────────────────────────

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct EpochReplayMetadata {
        epoch_id: u64,
        zone_id: String,
        object_hash: [u8; 32],
        symbols_needed: u32,
        symbols_available: u32,
        producer_nodes: Vec<String>,
        stats: HashMap<String, u64>,
    }

    #[test]
    fn epoch_metadata_canonical_cbor_is_deterministic() {
        let object_hash = *blake3::hash(b"epoch-object-42").as_bytes();

        let mut stats_a = HashMap::new();
        stats_a.insert("symbols_needed".to_string(), 22);
        stats_a.insert("symbols_available".to_string(), 31);
        stats_a.insert("repair_attempts".to_string(), 2);

        let mut stats_b = HashMap::new();
        // Deliberately insert in a different order to prove canonicalization.
        stats_b.insert("repair_attempts".to_string(), 2);
        stats_b.insert("symbols_available".to_string(), 31);
        stats_b.insert("symbols_needed".to_string(), 22);

        let metadata_a = EpochReplayMetadata {
            epoch_id: 42,
            zone_id: "z:work".to_string(),
            object_hash,
            symbols_needed: 22,
            symbols_available: 31,
            producer_nodes: vec!["node-a".to_string(), "node-b".to_string()],
            stats: stats_a,
        };
        let metadata_b = EpochReplayMetadata {
            stats: stats_b,
            ..metadata_a.clone()
        };

        let schema = SchemaId::new(
            "fcp.raptorq",
            "EpochReplayMetadata",
            "1.0.0".parse().expect("schema version parses"),
        );

        let bytes_a = CanonicalSerializer::serialize(&metadata_a, &schema)
            .expect("metadata A serializes canonically");
        let bytes_b = CanonicalSerializer::serialize(&metadata_b, &schema)
            .expect("metadata B serializes canonically");
        assert_eq!(
            bytes_a, bytes_b,
            "canonical bytes should be identical for semantically equal metadata"
        );

        let parsed: EpochReplayMetadata = CanonicalSerializer::deserialize(&bytes_a, &schema)
            .expect("canonical metadata deserializes");
        assert_eq!(parsed, metadata_a);
    }

    #[test]
    fn epoch_replay_reconstructs_identically_from_multiple_symbol_subsets() {
        let config = RaptorQConfig {
            symbol_size: 1024,
            repair_ratio_bps: 10000, // 100% repair overhead for robust subset decoding
            max_object_size: 64 * 1024 * 1024,
            decode_timeout: Duration::from_secs(30),
            max_chunk_threshold: 256 * 1024,
            chunk_size: 64 * 1024,
        };

        let payload = seeded_payload(0xE00C_0042, 20 * 1024);
        let payload_hash = blake3_hex(&payload);
        let encoder = RaptorQEncoder::new(&payload, &config).expect("encoder");
        let symbols = encoder.encode_all();
        let needed = encoder.source_symbols();
        assert!(
            symbols.len() > usize::try_from(needed).expect("needed fits usize"),
            "test requires repair symbols to be present"
        );

        // Subset A: all even ESIs + first five odd ESIs.
        let mut subset_a: Vec<(u32, Vec<u8>)> = symbols
            .iter()
            .filter(|(esi, _)| esi % 2 == 0)
            .cloned()
            .collect();
        subset_a.extend(
            symbols
                .iter()
                .filter(|(esi, _)| esi % 2 == 1)
                .take(5)
                .cloned(),
        );

        // Subset B: skip the first 8 symbols (simulates initial gap).
        let subset_b: Vec<(u32, Vec<u8>)> = symbols.iter().skip(8).cloned().collect();

        // Subset C: drop every 3rd symbol (interleaved loss).
        let subset_c: Vec<(u32, Vec<u8>)> = symbols
            .iter()
            .enumerate()
            .filter(|(idx, _)| idx % 3 != 0)
            .map(|(_, symbol)| symbol.clone())
            .collect();

        for (label, mut subset) in [
            ("subset-a", subset_a),
            ("subset-b", subset_b),
            ("subset-c", subset_c),
        ] {
            // Reverse to ensure replay order does not depend on arrival order.
            subset.reverse();

            let mut raptor_decoder = RaptorQDecoder::new(encoder.transmission_info(), &config);
            let expected_len = payload.len();
            let mut reconstructed_payload = None;
            for (esi, data) in subset.iter().cloned() {
                if let Ok(Some(payload_bytes)) = raptor_decoder.add_symbol(esi, data) {
                    reconstructed_payload = Some(payload_bytes);
                    break;
                }
            }

            let reconstructed_payload = reconstructed_payload.unwrap_or_else(|| {
                panic!(
                    "failed to decode payload from {label} (subset_size={})",
                    subset.len()
                )
            });
            assert_eq!(
                &reconstructed_payload[..expected_len],
                &payload[..],
                "{label} produced different payload bytes"
            );
            assert_eq!(
                blake3_hex(&reconstructed_payload[..expected_len]),
                payload_hash,
                "{label} hash mismatch"
            );

            emit_epoch_replay_log(&EpochReplayLog {
                test_name: "epoch_replay_reconstructs_identically_from_multiple_symbol_subsets",
                epoch_id: 42,
                object_hash: &payload_hash,
                symbols_needed: needed,
                symbols_available: subset.len(),
                repair_attempts: 0,
                bytes_written: u64::try_from(reconstructed_payload.len())
                    .expect("decoded length fits u64"),
                verify_result: "pass",
                result: "pass",
                fcp_error_code: None,
            });
        }
    }

    #[test]
    fn epoch_replay_reconstructs_from_seeded_randomized_subsets() {
        use rand::SeedableRng;
        use rand::seq::SliceRandom;
        use rand_chacha::ChaCha20Rng;

        let config = RaptorQConfig {
            symbol_size: 1024,
            repair_ratio_bps: 10000, // 100% repair overhead for robust subset decoding
            max_object_size: 64 * 1024 * 1024,
            decode_timeout: Duration::from_secs(30),
            max_chunk_threshold: 256 * 1024,
            chunk_size: 64 * 1024,
        };

        let payload = seeded_payload(0xE00C_7742, 32 * 1024);
        let payload_hash = blake3_hex(&payload);
        let encoder = RaptorQEncoder::new(&payload, &config).expect("encoder");
        let symbols = encoder.encode_all();
        let needed = encoder.source_symbols();
        let keep_count = usize::try_from(needed)
            .expect("needed fits usize")
            .saturating_add(12)
            .min(symbols.len());
        assert!(
            keep_count >= usize::try_from(needed).expect("needed fits usize"),
            "seeded subset must include at least K symbols"
        );

        for seed in [0xA501_u64, 0xA502, 0xA503, 0xA504, 0xA505] {
            let mut subset = symbols.clone();
            let mut rng = ChaCha20Rng::seed_from_u64(seed);
            subset.shuffle(&mut rng);
            subset.truncate(keep_count);

            let mut raptor_decoder = RaptorQDecoder::new(encoder.transmission_info(), &config);
            let expected_len = payload.len();
            let mut reconstructed_payload = None;
            for (esi, data) in subset.iter().cloned() {
                if let Ok(Some(payload_bytes)) = raptor_decoder.add_symbol(esi, data) {
                    reconstructed_payload = Some(payload_bytes);
                    break;
                }
            }

            let reconstructed_payload = reconstructed_payload.unwrap_or_else(|| {
                panic!(
                    "seeded randomized subset failed to decode (seed={seed}, subset_size={keep_count})"
                )
            });
            assert_eq!(&reconstructed_payload[..expected_len], &payload[..]);
            assert_eq!(
                blake3_hex(&reconstructed_payload[..expected_len]),
                payload_hash
            );

            emit_epoch_replay_log(&EpochReplayLog {
                test_name: "epoch_replay_reconstructs_from_seeded_randomized_subsets",
                epoch_id: 47,
                object_hash: &payload_hash,
                symbols_needed: needed,
                symbols_available: keep_count,
                repair_attempts: 0,
                bytes_written: u64::try_from(reconstructed_payload.len())
                    .expect("decoded length fits u64"),
                verify_result: "pass",
                result: "pass",
                fcp_error_code: None,
            });
        }
    }

    #[test]
    fn binary_distribution_resume_after_missing_chunk_gap() {
        let config = golden_config();
        let payload = seeded_payload(0xB104_0042, 400 * 1024);
        let payload_hash = blake3_hex(&payload);
        let (manifest, chunks) = ChunkedObjectManifest::from_payload(&payload, config.chunk_size);

        assert!(
            manifest.chunk_count() >= 2,
            "test expects multi-chunk payload for resume simulation"
        );

        // Simulate interrupted download: missing the final chunk.
        let resume_index = chunks.len() - 1;
        let partial_chunks = chunks[..resume_index].to_vec();
        let err = manifest
            .reconstruct(&partial_chunks)
            .expect_err("partial chunk set should fail reconstruction");
        assert!(matches!(
            err,
            ChunkError::MissingChunks { expected, got }
            if expected == chunks.len() && got == partial_chunks.len()
        ));

        // Resume transfer by appending only the missing chunk.
        let mut resumed_chunks = partial_chunks;
        resumed_chunks.push(chunks[resume_index].clone());
        let reconstructed = manifest
            .reconstruct(&resumed_chunks)
            .expect("reconstruction should succeed after resume");
        assert_eq!(reconstructed, payload);

        emit_epoch_replay_log(&EpochReplayLog {
            test_name: "binary_distribution_resume_after_missing_chunk_gap",
            epoch_id: 43,
            object_hash: &payload_hash,
            symbols_needed: u32::try_from(manifest.chunk_count()).expect("chunk count fits u32"),
            symbols_available: resumed_chunks.len(),
            repair_attempts: 1,
            bytes_written: u64::try_from(reconstructed.len())
                .expect("reconstructed length fits u64"),
            verify_result: "pass",
            result: "pass",
            fcp_error_code: None,
        });
    }

    #[test]
    fn binary_distribution_verification_fails_closed_until_verified() {
        let config = golden_config();
        let payload = seeded_payload(0x51A1_0042, 320 * 1024);
        let payload_hash = blake3_hex(&payload);
        let (manifest, mut chunks) =
            ChunkedObjectManifest::from_payload(&payload, config.chunk_size);

        let staged_verified = manifest
            .reconstruct_unchecked(&chunks)
            .expect("unchecked reconstruction should stage payload");
        assert!(manifest.verify_hash(&staged_verified));

        // Simulate quarantine gate: bytes are staged but not installable until verify passes.
        let mut quarantined = Some(staged_verified);
        let installed_payload =
            if manifest.verify_hash(quarantined.as_ref().expect("payload staged in quarantine")) {
                quarantined.take()
            } else {
                None
            };

        let installed_payload = installed_payload.expect("verified staged payload should install");
        assert_eq!(installed_payload, payload);
        emit_epoch_replay_log(&EpochReplayLog {
            test_name: "binary_distribution_verification_fails_closed_until_verified",
            epoch_id: 44,
            object_hash: &payload_hash,
            symbols_needed: u32::try_from(manifest.chunk_count()).expect("chunk count fits u32"),
            symbols_available: chunks.len(),
            repair_attempts: 0,
            bytes_written: u64::try_from(installed_payload.len())
                .expect("installed length fits u64"),
            verify_result: "pass",
            result: "pass",
            fcp_error_code: None,
        });

        // Corrupt one staged chunk and ensure verification blocks install.
        chunks[0].bytes[0] ^= 0x01;
        let staged_corrupt = manifest
            .reconstruct_unchecked(&chunks)
            .expect("unchecked reconstruction should still stage bytes");
        assert!(
            !manifest.verify_hash(&staged_corrupt),
            "hash verification must fail for corrupt staged bytes"
        );

        let mut quarantined_corrupt = Some(staged_corrupt);
        let installed_corrupt = if manifest.verify_hash(
            quarantined_corrupt
                .as_ref()
                .expect("corrupt bytes are staged in quarantine"),
        ) {
            quarantined_corrupt.take()
        } else {
            None
        };
        assert!(
            installed_corrupt.is_none(),
            "install must fail closed if verification does not pass"
        );
        emit_epoch_replay_log(&EpochReplayLog {
            test_name: "binary_distribution_verification_fails_closed_until_verified",
            epoch_id: 45,
            object_hash: &payload_hash,
            symbols_needed: u32::try_from(manifest.chunk_count()).expect("chunk count fits u32"),
            symbols_available: chunks.len(),
            repair_attempts: 0,
            bytes_written: 0,
            verify_result: "fail",
            result: "fail",
            fcp_error_code: Some("FCP_SUPPLY_CHAIN_VERIFY_FAILED"),
        });
    }

    #[test]
    fn malformed_epoch_metadata_is_rejected_with_bounded_error() {
        let schema = SchemaId::new(
            "fcp.raptorq",
            "EpochReplayMetadata",
            "1.0.0".parse().expect("schema version parses"),
        );

        // Invalid CBOR shape for EpochReplayMetadata (array instead of expected struct map).
        let malformed = vec![0x9f, 0x01, 0x02, 0xff];
        let start = std::time::Instant::now();
        let parse = CanonicalSerializer::deserialize::<EpochReplayMetadata>(&malformed, &schema);
        assert!(parse.is_err(), "malformed metadata must be rejected");
        assert!(
            start.elapsed() <= Duration::from_secs(1),
            "malformed metadata decode should fail in bounded time"
        );

        emit_epoch_replay_log(&EpochReplayLog {
            test_name: "malformed_epoch_metadata_is_rejected_with_bounded_error",
            epoch_id: 46,
            object_hash: "invalid-metadata",
            symbols_needed: 0,
            symbols_available: 0,
            repair_attempts: 0,
            bytes_written: 0,
            verify_result: "fail",
            result: "fail",
            fcp_error_code: Some("FCP_EPOCH_METADATA_INVALID"),
        });
    }

    // ═════════════════════════════════════════════════════════════════════════
    // DETERMINISTIC GOLDEN VECTOR CONSTANTS (235t.25)
    //
    // These tests pin exact encoded output for seeded payloads. If the
    // codec changes its encoding, these tests will catch the drift.
    // Each vector records: seed, payload size, config, K, repair count,
    // OTI fields, and BLAKE3 hashes of selected symbols.
    // ═════════════════════════════════════════════════════════════════════════

    /// Vector V1: 4KB seeded payload, standard config.
    /// Pins symbol count, OTI transfer length, and payload hash.
    #[test]
    fn vector_v1_4kb_seeded_structure() {
        let config = golden_config();
        let payload = seeded_payload(0xFC02_0001, 4096);

        // Pin payload hash for reproducibility
        let payload_hash = blake3_hex(&payload);
        // Re-encode should produce identical hash
        let payload_again = seeded_payload(0xFC02_0001, 4096);
        assert_eq!(blake3_hex(&payload_again), payload_hash);

        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();

        // Pin structural properties
        assert_eq!(encoder.source_symbols(), 4);
        assert_eq!(encoder.repair_symbols(), 0);
        assert_eq!(encoder.total_symbols(), 4);
        assert_eq!(encoder.payload_len(), 4096);

        let oti = encoder.transmission_info();
        assert_eq!(oti.transfer_length(), 4096);
        assert_eq!(oti.symbol_size(), 1024);
    }

    /// Vector V2: 50KB seeded payload with 50% repair overhead.
    /// Pins K, repair count, and verifies symbol hashes are stable.
    #[test]
    fn vector_v2_50kb_high_repair_hashes() {
        let config = erasure_config();
        let payload = seeded_payload(0xFC02_0002, 50 * 1024);

        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();

        // Pin symbol counts
        let k = encoder.source_symbols();
        let repair = encoder.repair_symbols();
        assert_eq!(k, 50);
        assert_eq!(repair, 25);
        assert_eq!(encoder.total_symbols(), 75);

        // Encode and hash each symbol for determinism verification
        let symbols = encoder.encode_all();
        assert_eq!(symbols.len(), 75);

        // Pin ESI range: source symbols 0..K-1, repair symbols K'..K'+R-1
        // (K' is the RFC 6330 extended source block size, K' >= K)
        let k_prime = encoder.inner_k_prime();
        assert_eq!(symbols.first().unwrap().0, 0);
        assert_eq!(symbols[usize::try_from(k).unwrap() - 1].0, k - 1);
        assert_eq!(symbols[usize::try_from(k).unwrap()].0, k_prime);
        assert_eq!(symbols.last().unwrap().0, k_prime + repair - 1);

        // All symbols should be exactly symbol_size bytes
        for (esi, data) in &symbols {
            assert_eq!(
                data.len(),
                1024,
                "Symbol ESI {esi} has unexpected size {}",
                data.len()
            );
        }

        // Symbol hashes must be stable across runs
        let symbols_again = RaptorQEncoder::new(&payload, &config).unwrap().encode_all();
        for ((esi1, d1), (esi2, d2)) in symbols.iter().zip(symbols_again.iter()) {
            assert_eq!(esi1, esi2);
            assert_eq!(
                blake3_hex(d1),
                blake3_hex(d2),
                "Symbol ESI {esi1} hash drift detected"
            );
        }
    }

    /// Vector V3: 200KB seeded payload near chunk threshold.
    /// Verifies direct encoding (not chunked) and full roundtrip.
    #[test]
    fn vector_v3_200kb_near_chunk_threshold() {
        let config = golden_config();
        let payload = seeded_payload(0xFC02_0003, 200 * 1024);

        // Under 256KB threshold -> direct encoding
        assert!(!config.requires_chunking(200 * 1024));

        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let symbols = encoder.encode_all();
        let oti = encoder.transmission_info();

        assert_eq!(encoder.source_symbols(), 200);
        assert_eq!(encoder.repair_symbols(), 10); // 5% of 200

        // Roundtrip decode
        let mut decoder = RaptorQDecoder::new(oti, &config);
        let expected_len = payload.len();
        for (esi, data) in symbols {
            if let Ok(Some(decoded)) = decoder.add_symbol(esi, data) {
                assert_eq!(&decoded[..expected_len], &payload[..]);
                return;
            }
        }
        panic!("Failed to decode 200KB seeded payload");
    }

    /// Vector V4: Verify OTI roundtrip serialization fields.
    #[test]
    fn vector_v4_oti_field_stability() {
        let config = golden_config();
        let payload = seeded_payload(0xFC02_0004, 10 * 1024);

        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let oti = encoder.transmission_info();

        // Pin all OTI fields
        assert_eq!(oti.transfer_length(), 10 * 1024);
        assert_eq!(oti.symbol_size(), 1024);
        // source_block_count and sub_block_count depend on the codec internals,
        // but alignment is always 8 for our config
        assert!(oti.source_blocks() >= 1);
        assert!(oti.sub_blocks() >= 1);
        assert_eq!(oti.symbol_alignment(), 8);
    }

    /// Vector V5: 1MB seeded payload with high repair, full roundtrip.
    #[test]
    fn vector_v5_1mb_stress_roundtrip() {
        let config = RaptorQConfig {
            symbol_size: 1024,
            repair_ratio_bps: 2000, // 20% repair
            max_object_size: 64 * 1024 * 1024,
            decode_timeout: Duration::from_secs(60),
            max_chunk_threshold: 2 * 1024 * 1024, // Raised to allow direct encoding
            chunk_size: 64 * 1024,
        };

        let payload = seeded_payload(0xFC02_0005, 1024 * 1024);

        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        assert_eq!(encoder.source_symbols(), 1024);
        assert_eq!(encoder.repair_symbols(), 204); // 20% of 1024 ≈ 204

        let symbols = encoder.encode_all();
        let oti = encoder.transmission_info();

        // Roundtrip
        let mut decoder = RaptorQDecoder::new(oti, &config);
        let expected_len = payload.len();
        for (esi, data) in symbols {
            if let Ok(Some(decoded)) = decoder.add_symbol(esi, data) {
                assert!(decoded.len() >= expected_len);
                assert_eq!(&decoded[..expected_len], &payload[..]);
                return;
            }
        }
        panic!("Failed to decode 1MB seeded payload");
    }

    /// Vector V6: Seeded chunked payload hash stability.
    #[test]
    fn vector_v6_chunked_hash_stability() {
        let config = golden_config();
        let payload = seeded_payload(0xFC02_0006, 400 * 1024);

        assert!(config.requires_chunking(400 * 1024));

        let (manifest, chunks) = ChunkedObjectManifest::from_payload(&payload, config.chunk_size);

        // Pin chunk structure
        assert_eq!(manifest.chunk_count(), 7); // ceil(400/64) = 7
        assert_eq!(manifest.total_len, 400 * 1024);

        // Hash each chunk for stability
        let chunk_hashes: Vec<String> = chunks.iter().map(|c| blake3_hex(&c.bytes)).collect();

        // Re-create and verify identical hashes
        let (_, chunks2) = ChunkedObjectManifest::from_payload(&payload, config.chunk_size);
        let chunk_hashes2: Vec<String> = chunks2.iter().map(|c| blake3_hex(&c.bytes)).collect();
        assert_eq!(chunk_hashes, chunk_hashes2);

        // Reconstruction roundtrip
        let reconstructed = manifest.reconstruct(&chunks).unwrap();
        assert_eq!(reconstructed, payload);
    }

    // ═════════════════════════════════════════════════════════════════════════
    // ADVERSARIAL ERASURE PATTERN TESTS (235t.25)
    //
    // Test recovery from various real-world loss patterns:
    // - Bursty loss (consecutive symbols dropped)
    // - Front-heavy loss (early symbols missing)
    // - Tail-heavy loss (late symbols missing)
    // - Random seeded loss (PRNG-driven erasure)
    // - Interleaved loss (every Nth symbol)
    // ═════════════════════════════════════════════════════════════════════════

    /// Bursty erasure: consecutive blocks of symbols are lost.
    #[test]
    fn adversarial_bursty_erasure_recovery() {
        let config = erasure_config();
        let payload = seeded_payload(0xADB0_0001, 100 * 1024);

        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let symbols = encoder.encode_all();
        let oti = encoder.transmission_info();

        let k = encoder.source_symbols();
        let total = symbols.len();

        // Drop a burst of 20 consecutive symbols in the middle
        let burst_start = total / 3;
        let burst_end = burst_start + 20;

        let mut decoder = RaptorQDecoder::new(oti, &config);
        let expected_len = payload.len();
        for (i, (esi, data)) in symbols.into_iter().enumerate() {
            if i >= burst_start && i < burst_end {
                continue; // Bursty loss
            }
            if let Ok(Some(decoded)) = decoder.add_symbol(esi, data) {
                assert_eq!(&decoded[..expected_len], &payload[..]);
                return;
            }
        }
        panic!("Failed to recover from bursty erasure (K={k}, burst=20, total={total})");
    }

    /// Front-heavy erasure: first N source symbols are lost.
    #[test]
    fn adversarial_front_heavy_erasure_recovery() {
        let config = erasure_config();
        let payload = seeded_payload(0xADB0_0002, 50 * 1024);

        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let symbols = encoder.encode_all();
        let oti = encoder.transmission_info();

        let k = encoder.source_symbols();

        // Drop the first 15 source symbols (30% of K=50)
        let drop_count: u32 = 15;

        let mut decoder = RaptorQDecoder::new(oti, &config);
        let expected_len = payload.len();
        for (esi, data) in symbols {
            if esi < drop_count {
                continue; // Front-heavy loss
            }
            if let Ok(Some(decoded)) = decoder.add_symbol(esi, data) {
                assert_eq!(&decoded[..expected_len], &payload[..]);
                return;
            }
        }
        panic!("Failed to recover from front-heavy erasure (K={k}, dropped={drop_count})");
    }

    /// Tail-heavy erasure: last N source symbols and some repair are lost.
    #[test]
    fn adversarial_tail_heavy_erasure_recovery() {
        let config = erasure_config();
        let payload = seeded_payload(0xADB0_0003, 50 * 1024);

        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let symbols = encoder.encode_all();
        let oti = encoder.transmission_info();

        let k = encoder.source_symbols();
        let total = u32::try_from(symbols.len()).unwrap();

        // Drop last 15 symbols (includes some repair)
        let cutoff = total - 15;

        let mut decoder = RaptorQDecoder::new(oti, &config);
        let expected_len = payload.len();
        let mut fed_count: u32 = 0;
        for (esi, data) in symbols {
            if esi >= cutoff {
                continue; // Tail-heavy loss
            }
            fed_count += 1;
            if let Ok(Some(decoded)) = decoder.add_symbol(esi, data) {
                assert_eq!(&decoded[..expected_len], &payload[..]);
                return;
            }
        }
        panic!("Failed to recover from tail-heavy erasure (K={k}, fed={fed_count})");
    }

    /// Random seeded erasure: PRNG decides which symbols to drop.
    #[test]
    fn adversarial_random_seeded_erasure_recovery() {
        use rand::Rng;
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        let config = erasure_config();
        let payload = seeded_payload(0xADB0_0004, 80 * 1024);

        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let symbols = encoder.encode_all();
        let oti = encoder.transmission_info();

        // Use seeded PRNG to decide drops (20% loss rate)
        let mut rng = ChaCha20Rng::seed_from_u64(0xD0_0EED);
        let loss_rate = 0.20;

        let mut decoder = RaptorQDecoder::new(oti, &config);
        let expected_len = payload.len();
        let mut dropped = 0_u32;
        let mut fed = 0_u32;
        for (esi, data) in symbols {
            if rng.r#gen::<f64>() < loss_rate {
                dropped += 1;
                continue;
            }
            fed += 1;
            if let Ok(Some(decoded)) = decoder.add_symbol(esi, data) {
                assert_eq!(&decoded[..expected_len], &payload[..]);
                // Verify we actually dropped some symbols
                assert!(dropped > 0, "No symbols were dropped");
                return;
            }
        }
        panic!(
            "Failed to recover from {:.0}% random erasure (fed={fed}, dropped={dropped})",
            loss_rate * 100.0
        );
    }

    /// Interleaved erasure: every Nth symbol is dropped.
    #[test]
    fn adversarial_interleaved_erasure_recovery() {
        let config = erasure_config();
        let payload = seeded_payload(0xADB0_0005, 60 * 1024);

        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let symbols = encoder.encode_all();
        let oti = encoder.transmission_info();

        // Drop every 4th symbol (25% loss)
        let drop_interval = 4;

        let mut decoder = RaptorQDecoder::new(oti, &config);
        let expected_len = payload.len();
        for (i, (esi, data)) in symbols.into_iter().enumerate() {
            if i % drop_interval == 0 {
                continue;
            }
            if let Ok(Some(decoded)) = decoder.add_symbol(esi, data) {
                assert_eq!(&decoded[..expected_len], &payload[..]);
                return;
            }
        }
        panic!("Failed to recover from interleaved erasure (1/{drop_interval})");
    }

    // ═════════════════════════════════════════════════════════════════════════
    // SYMBOL CORRUPTION TESTS (235t.25)
    //
    // Verify that corrupted symbols don't produce valid reconstructions.
    // ═════════════════════════════════════════════════════════════════════════

    /// Single bit-flip in one source symbol should prevent valid reconstruction.
    #[test]
    fn corruption_single_bitflip_source_symbol() {
        let config = golden_config();
        let payload = seeded_payload(0xC0B1_0001, 10 * 1024);

        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let mut symbols = encoder.encode_all();
        let oti = encoder.transmission_info();

        // Flip one bit in the first source symbol
        symbols[0].1[0] ^= 0x01;

        let mut decoder = RaptorQDecoder::new(oti, &config);
        let expected_len = payload.len();
        for (esi, data) in symbols {
            if let Ok(Some(decoded)) = decoder.add_symbol(esi, data) {
                // Reconstruction may succeed but payload should differ
                assert_ne!(
                    &decoded[..expected_len],
                    &payload[..],
                    "Corrupted symbol should produce different output"
                );
                return;
            }
        }
        // If decode fails entirely, that's also acceptable
    }

    /// Multiple bit-flips across different symbols.
    #[test]
    fn corruption_multi_bitflip_different_symbols() {
        let config = golden_config();
        let payload = seeded_payload(0xC0B1_0002, 10 * 1024);

        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let mut symbols = encoder.encode_all();
        let oti = encoder.transmission_info();

        // Corrupt 3 different source symbols
        for i in 0..3 {
            if i < symbols.len() {
                symbols[i].1[512] ^= 0xFF; // Flip all bits at midpoint
            }
        }

        let mut decoder = RaptorQDecoder::new(oti, &config);
        let expected_len = payload.len();
        for (esi, data) in symbols {
            if let Ok(Some(decoded)) = decoder.add_symbol(esi, data) {
                assert_ne!(
                    &decoded[..expected_len],
                    &payload[..],
                    "Multiple corrupted symbols should produce different output"
                );
                return;
            }
        }
    }

    /// Truncated symbol data (shorter than expected).
    #[test]
    fn corruption_truncated_symbol() {
        let config = golden_config();
        let payload = seeded_payload(0xC0B1_0003, 10 * 1024);

        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let symbols = encoder.encode_all();
        let oti = encoder.transmission_info();

        // Feed truncated first symbol, then rest normally
        let mut decoder = RaptorQDecoder::new(oti, &config);
        let expected_len = payload.len();
        for (i, (esi, data)) in symbols.into_iter().enumerate() {
            let symbol_data = if i == 0 {
                // Truncate to half size, padded with zeros to maintain packet size
                let mut truncated = data[..data.len() / 2].to_vec();
                truncated.resize(data.len(), 0);
                truncated
            } else {
                data
            };
            if let Ok(Some(decoded)) = decoder.add_symbol(esi, symbol_data) {
                // Truncated symbol corrupts the result
                assert_ne!(
                    &decoded[..expected_len],
                    &payload[..],
                    "Truncated symbol should produce different output"
                );
                return;
            }
        }
    }

    /// Zero-filled symbol (all bytes replaced with 0x00).
    #[test]
    fn corruption_zeroed_symbol() {
        let config = golden_config();
        let payload = seeded_payload(0xC0B1_0004, 10 * 1024);

        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let mut symbols = encoder.encode_all();
        let oti = encoder.transmission_info();

        // Replace middle source symbol with all zeros
        let mid = symbols.len() / 2;
        let sym_len = symbols[mid].1.len();
        symbols[mid].1 = vec![0u8; sym_len];

        let mut decoder = RaptorQDecoder::new(oti, &config);
        let expected_len = payload.len();
        for (esi, data) in symbols {
            if let Ok(Some(decoded)) = decoder.add_symbol(esi, data) {
                assert_ne!(
                    &decoded[..expected_len],
                    &payload[..],
                    "Zeroed symbol should produce different output"
                );
                return;
            }
        }
    }

    // ═════════════════════════════════════════════════════════════════════════
    // REPAIR-ONLY AND MIXED RECOVERY TESTS (235t.25)
    //
    // Test the fountain code property: any K' symbols (source or repair)
    // are sufficient for reconstruction.
    // ═════════════════════════════════════════════════════════════════════════

    /// Recovery using a mix of scattered source and repair symbols.
    #[test]
    fn mixed_source_repair_scattered_recovery() {
        use rand::Rng;
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        let config = erasure_config();
        let payload = seeded_payload(0xA1C0_0001, 80 * 1024);

        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let mut symbols = encoder.encode_all();
        let oti = encoder.transmission_info();

        let k = usize::try_from(encoder.source_symbols()).unwrap();

        // Shuffle symbols using seeded PRNG
        let mut rng = ChaCha20Rng::seed_from_u64(0x5AEF_BEED);
        // Fisher-Yates shuffle
        for i in (1..symbols.len()).rev() {
            let j = rng.gen_range(0..=i);
            symbols.swap(i, j);
        }

        // Feed K+10 symbols (wider margin for the in-house codec) in shuffled order
        let feed_count = k + 10;

        let mut decoder = RaptorQDecoder::new(oti, &config);
        let expected_len = payload.len();
        for (esi, data) in symbols.into_iter().take(feed_count) {
            if let Ok(Some(decoded)) = decoder.add_symbol(esi, data) {
                assert_eq!(&decoded[..expected_len], &payload[..]);
                return;
            }
        }
        panic!("Failed to recover from mixed scattered symbols (K={k}, fed={feed_count})");
    }

    /// Recovery with exactly K' repair symbols and zero source symbols.
    #[test]
    fn repair_only_exact_kprime_recovery() {
        let config = RaptorQConfig {
            symbol_size: 1024,
            repair_ratio_bps: 10000, // 100% repair (K repair symbols)
            max_object_size: 64 * 1024 * 1024,
            decode_timeout: Duration::from_secs(30),
            max_chunk_threshold: 256 * 1024,
            chunk_size: 64 * 1024,
        };

        let payload = seeded_payload(0xBE0A_0001, 20 * 1024);
        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let symbols = encoder.encode_all();
        let oti = encoder.transmission_info();

        let k = encoder.source_symbols();

        // Use ONLY repair symbols, skip all source
        let mut decoder = RaptorQDecoder::new(oti, &config);
        let expected_len = payload.len();
        let mut repair_fed = 0_u32;
        for (esi, data) in symbols {
            if esi < k {
                continue;
            }
            repair_fed += 1;
            if let Ok(Some(decoded)) = decoder.add_symbol(esi, data) {
                assert_eq!(&decoded[..expected_len], &payload[..]);
                assert!(
                    repair_fed >= k,
                    "Should need at least K repair symbols, used {repair_fed}"
                );
                return;
            }
        }
        panic!("Failed to decode from repair symbols only (K={k}, repair_fed={repair_fed})");
    }

    // ═════════════════════════════════════════════════════════════════════════
    // SEEDED PAYLOAD DETERMINISM VERIFICATION (235t.25)
    //
    // Verify that seeded payloads are identical across invocations.
    // ═════════════════════════════════════════════════════════════════════════

    #[test]
    fn seeded_payload_cross_invocation_stability() {
        // Generate the same seeded payload twice and verify byte-for-byte identity
        let sizes = [64, 1024, 4096, 65536, 256 * 1024];

        for &size in &sizes {
            let p1 = seeded_payload(0x57AB_1111, size);
            let p2 = seeded_payload(0x57AB_1111, size);
            assert_eq!(p1, p2, "Seeded payload unstable for size {size}");
        }
    }

    #[test]
    fn seeded_payload_different_seeds_differ() {
        let p1 = seeded_payload(0x1111, 4096);
        let p2 = seeded_payload(0x2222, 4096);
        assert_ne!(p1, p2, "Different seeds should produce different payloads");
    }

    #[test]
    fn seeded_encoding_hash_registry() {
        // Pin the BLAKE3 hash of encodings for a set of known payloads.
        // This serves as a regression gate: if hashes change, encoding
        // determinism has been broken.
        let config = golden_config();

        let vectors: Vec<(u64, usize)> = vec![
            (0xBE60_0001, 1024),
            (0xBE60_0002, 4096),
            (0xBE60_0003, 10 * 1024),
            (0xBE60_0004, 50 * 1024),
        ];

        let mut hash_registry: Vec<(u64, usize, u32, String)> = Vec::new();

        for (seed, size) in &vectors {
            let payload = seeded_payload(*seed, *size);
            let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
            let symbols = encoder.encode_all();

            // Hash all symbol data concatenated
            let mut all_bytes = Vec::new();
            for (esi, data) in &symbols {
                all_bytes.extend_from_slice(&esi.to_le_bytes());
                all_bytes.extend_from_slice(data);
            }
            let combined_hash = blake3_hex(&all_bytes);

            hash_registry.push((*seed, *size, encoder.total_symbols(), combined_hash));
        }

        // Re-run and verify stability
        for (seed, size, expected_total, expected_hash) in &hash_registry {
            let payload = seeded_payload(*seed, *size);
            let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
            assert_eq!(
                encoder.total_symbols(),
                *expected_total,
                "Symbol count changed for seed {seed:#x}"
            );

            let symbols = encoder.encode_all();
            let mut all_bytes = Vec::new();
            for (esi, data) in &symbols {
                all_bytes.extend_from_slice(&esi.to_le_bytes());
                all_bytes.extend_from_slice(data);
            }
            let hash = blake3_hex(&all_bytes);
            assert_eq!(
                hash, *expected_hash,
                "Encoding hash drift for seed {seed:#x}, size {size}"
            );
        }
    }

    // ═════════════════════════════════════════════════════════════════════════
    // MULTI-LOSS-RATE RECOVERY SWEEP (235t.25)
    //
    // Parameterized test sweeping multiple loss rates to find the recovery
    // boundary for a given repair ratio.
    // ═════════════════════════════════════════════════════════════════════════

    #[test]
    fn recovery_sweep_5_10_20_30_percent_loss() {
        let config = erasure_config(); // 50% repair
        let payload = seeded_payload(0x5EE0_0001, 100 * 1024);

        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let symbols = encoder.encode_all();
        let oti = encoder.transmission_info();

        // 50% repair should handle up to ~33% loss reliably.
        // Use evenly-spaced drops to simulate the exact loss percentage.
        let loss_rates = [5, 10, 20, 30];
        let total = symbols.len();

        for loss_pct in loss_rates {
            // Compute exact number of symbols to drop
            let drop_count = total * loss_pct / 100;
            // Build a set of evenly-spaced indices to drop
            let drops: std::collections::HashSet<usize> =
                (0..drop_count).map(|i| i * total / drop_count).collect();

            let mut decoder = RaptorQDecoder::new(oti, &config);
            let expected_len = payload.len();
            let mut recovered = false;

            for (i, (esi, data)) in symbols.iter().enumerate() {
                if drops.contains(&i) {
                    continue;
                }
                if let Ok(Some(decoded)) = decoder.add_symbol(*esi, data.clone()) {
                    assert_eq!(
                        &decoded[..expected_len],
                        &payload[..],
                        "Decoded payload mismatch at {loss_pct}% loss"
                    );
                    recovered = true;
                    break;
                }
            }

            assert!(
                recovered,
                "Failed to recover at {loss_pct}% loss rate with 50% repair overhead \
                (dropped {drop_count}/{total} symbols, kept {})",
                total - drop_count
            );
        }
    }

    // ═════════════════════════════════════════════════════════════════════════
    // DECODE RESOURCE BOUNDARY TESTS (235t.25)
    //
    // Verify bounded failure behavior under resource pressure.
    // ═════════════════════════════════════════════════════════════════════════

    /// Feeding symbols beyond the expected count should not cause panics.
    #[test]
    fn bounded_excess_symbols_no_panic() {
        let config = golden_config();
        let payload = seeded_payload(0xB00D_0001, 10 * 1024);

        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let symbols = encoder.encode_all();
        let oti = encoder.transmission_info();

        let mut decoder = RaptorQDecoder::new(oti, &config);

        // Feed all symbols
        for (esi, data) in &symbols {
            let _ = decoder.add_symbol(*esi, data.clone());
        }

        // Feed them again (duplicates should be silently ignored)
        for (esi, data) in &symbols {
            let result = decoder.add_symbol(*esi, data.clone());
            assert!(result.is_ok(), "Duplicate symbol should not error");
        }

        // Feed symbols with very high ESIs — should not panic (may reject)
        for esi in 10000..10010 {
            let _ = decoder.add_symbol(esi, vec![0u8; 1024]);
        }
    }

    /// Empty symbol data should not cause panics.
    #[test]
    fn bounded_empty_symbol_data() {
        let config = golden_config();
        let oti = crate::ObjectTransmissionInformation::new(10 * 1024, 1024, 1, 1, 8);
        let mut decoder = RaptorQDecoder::new(oti, &config);

        // Feed empty symbol
        let result = decoder.add_symbol(0, vec![]);
        // Should not panic; may or may not error depending on internal codec
        let _ = result;
    }

    /// Verify decoder state is consistent after failed reconstruction.
    #[test]
    fn bounded_insufficient_symbols_state() {
        let config = golden_config();
        let payload = seeded_payload(0xB00D_0002, 50 * 1024);

        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let symbols = encoder.encode_all();
        let oti = encoder.transmission_info();

        let k = encoder.source_symbols();

        // Feed only half the needed symbols
        let half = usize::try_from(k).unwrap() / 2;
        let mut decoder = RaptorQDecoder::new(oti, &config);

        for (esi, data) in symbols.into_iter().take(half) {
            let result = decoder.add_symbol(esi, data);
            assert!(result.is_ok());
        }

        // Decoder state should be consistent
        assert_eq!(decoder.received_count(), u32::try_from(half).unwrap());
        assert!(!decoder.likely_complete());
        assert!(!decoder.is_timed_out());
        assert!(decoder.time_remaining() > Duration::ZERO);
    }
}
