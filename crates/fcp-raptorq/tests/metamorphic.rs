//! Metamorphic tests for `fcp-raptorq` encode/decode invariants.

use std::time::Duration;

use fcp_raptorq::{RaptorQConfig, RaptorQDecoder, RaptorQEncoder};
use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

const fn metamorphic_config() -> RaptorQConfig {
    RaptorQConfig {
        symbol_size: 64,
        repair_ratio_bps: 5000,
        max_object_size: 64 * 1024,
        decode_timeout: Duration::from_secs(30),
        max_chunk_threshold: 256 * 1024,
        chunk_size: 64 * 1024,
    }
}

const fn high_redundancy_config() -> RaptorQConfig {
    RaptorQConfig {
        symbol_size: 64,
        repair_ratio_bps: 20000,
        max_object_size: 64 * 1024,
        decode_timeout: Duration::from_secs(30),
        max_chunk_threshold: 256 * 1024,
        chunk_size: 64 * 1024,
    }
}

fn deterministic_payload(size: usize) -> Vec<u8> {
    (0..size)
        .map(|idx| u8::try_from((idx * 17 + 31) % 251).expect("payload byte fits"))
        .collect()
}

fn decode_payload(
    config: &RaptorQConfig,
    encoder: &RaptorQEncoder,
    symbols: &[(u32, Vec<u8>)],
) -> Vec<u8> {
    let mut decoder = RaptorQDecoder::new(encoder.transmission_info(), config);
    for (esi, data) in symbols {
        match decoder.add_symbol(*esi, data.clone()) {
            Ok(Some(decoded)) => return decoded,
            Ok(None) => {}
            Err(err) => panic!("metamorphic decode input should stay valid, got {err:?}"),
        }
    }

    panic!(
        "metamorphic decode should succeed after {} symbols",
        symbols.len()
    );
}

fn shuffled_symbols(symbols: &[(u32, Vec<u8>)], seed: u64) -> Vec<(u32, Vec<u8>)> {
    let mut shuffled = symbols.to_vec();
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    shuffled.shuffle(&mut rng);
    shuffled
}

#[test]
fn mr1_encode_decode_roundtrip_preserves_payload() {
    let config = metamorphic_config();

    for payload_len in [1_usize, 63, 64, 65, 511, 777, 2048, 4093] {
        let payload = deterministic_payload(payload_len);
        let encoder = RaptorQEncoder::new(&payload, &config).expect("encode payload");
        let decoded = decode_payload(&config, &encoder, &encoder.encode_all());

        assert_eq!(
            decoded, payload,
            "MR1 failed for payload_len={payload_len}: encode(x) then decode must equal x"
        );
    }
}

#[test]
fn mr2_decode_is_invariant_under_symbol_order() {
    let config = metamorphic_config();
    let payload = deterministic_payload(50 * usize::from(config.symbol_size) + 13);
    let encoder = RaptorQEncoder::new(&payload, &config).expect("encode payload");
    let canonical = encoder.encode_all();
    let reversed: Vec<_> = canonical.iter().cloned().rev().collect();
    let shuffled = shuffled_symbols(&canonical, 0xA460_0402);

    let decoded_canonical = decode_payload(&config, &encoder, &canonical);
    let decoded_reversed = decode_payload(&config, &encoder, &reversed);
    let decoded_shuffled = decode_payload(&config, &encoder, &shuffled);

    assert_eq!(decoded_canonical, payload, "canonical order must decode");
    assert_eq!(
        decoded_reversed, decoded_canonical,
        "MR2 failed: reversing symbol arrival order changed decoded payload"
    );
    assert_eq!(
        decoded_shuffled, decoded_canonical,
        "MR2 failed: shuffled symbol arrival order changed decoded payload"
    );
}

#[test]
fn mr3_loss_recovery_up_to_k_symbols() {
    let config = high_redundancy_config();
    let payload = deterministic_payload(32 * usize::from(config.symbol_size) + 7);
    let encoder = RaptorQEncoder::new(&payload, &config).expect("encode payload");
    let all_symbols = shuffled_symbols(&encoder.encode_all(), 0xA460_0403);
    let k = usize::try_from(encoder.source_symbols()).expect("K fits usize");

    for loss_count in [0_usize, 1, k / 3, k / 2, k] {
        let surviving = &all_symbols[loss_count..];
        let decoded = decode_payload(&config, &encoder, surviving);

        assert_eq!(
            decoded, payload,
            "MR3 failed after dropping {loss_count} symbols out of {} (K={k})",
            all_symbols.len()
        );
    }
}
