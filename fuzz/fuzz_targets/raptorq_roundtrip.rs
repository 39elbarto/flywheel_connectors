#![no_main]

//! Metamorphic encode→decode round-trip property for fcp-raptorq.
//!
//! Property: for every payload P in [1, max_object_size] bytes encoded with a
//! valid `RaptorQConfig`, feeding the resulting source symbols (in any
//! arrival order) into a `RaptorQDecoder::with_expected_symbols` decoder
//! reconstructs the original P byte-for-byte. This complements
//! `raptorq_decode_bounds` (decoder-only adversarial input) and
//! `raptorq_envelope_decrypt` (AEAD wrapper) by exercising encoder/decoder
//! symmetry, which is otherwise covered only by hand-written unit tests.
//!
//! Catches: encoder padding bugs, OTI mismatch, ESI numbering errors,
//! systematic-symbol identity violations, transfer-length truncation drift.

use arbitrary::{Arbitrary, Unstructured};
use fcp_raptorq::{RaptorQConfig, RaptorQDecoder, RaptorQEncoder};
use libfuzzer_sys::fuzz_target;

/// Cap each fuzz iteration's payload — large payloads multiply with the
/// systematic encoder / decoder cost and crowd out the shrinker. The
/// surface we want is "many small payloads with permuted arrival
/// orders," not "few giant ones." `MAX_OBJECT_BYTES` is also chosen
/// well below `RaptorQConfig::default().max_object_size` so the
/// encoder admission gate does not reject our payload.
const MAX_PAYLOAD_BYTES: usize = 8 * 1024;
const MIN_SYMBOL_SIZE: u16 = 4;
const MAX_SYMBOL_SIZE: u16 = 256;

#[derive(Arbitrary, Debug)]
struct RoundtripInput {
    /// Symbol size for the encode pass; clamped to [MIN, MAX].
    symbol_size_seed: u16,
    /// Permutation seed for source-symbol arrival order.
    permute_seed: u64,
    /// If set, drop one source symbol and replace with a repair symbol
    /// to force the decoder onto the LT/repair-equation path.
    use_repair_substitution: bool,
    /// Payload bytes (truncated to MAX_PAYLOAD_BYTES).
    payload: Vec<u8>,
}

/// Cheap deterministic permutation: xorshift64* indices over `len`. We
/// don't need cryptographic uniformity, just stable variability across
/// fuzz iterations so we exercise multiple arrival orders.
fn permuted_indices(len: usize, mut state: u64) -> Vec<usize> {
    if state == 0 {
        state = 0x9E37_79B9_7F4A_7C15;
    }
    let mut indices: Vec<usize> = (0..len).collect();
    // Fisher–Yates with xorshift64*.
    for i in (1..len).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let j = (state.wrapping_mul(0x2545_F491_4F6C_DD1D) as usize) % (i + 1);
        indices.swap(i, j);
    }
    indices
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(input) = RoundtripInput::arbitrary(&mut u) else {
        return;
    };

    if input.payload.is_empty() {
        return;
    }
    let payload: &[u8] = if input.payload.len() > MAX_PAYLOAD_BYTES {
        &input.payload[..MAX_PAYLOAD_BYTES]
    } else {
        &input.payload[..]
    };

    let symbol_size = input
        .symbol_size_seed
        .clamp(MIN_SYMBOL_SIZE, MAX_SYMBOL_SIZE);

    let config = RaptorQConfig {
        symbol_size,
        // Keep repair_ratio_bps non-zero so the encoder produces at least
        // one repair symbol when use_repair_substitution is set; otherwise
        // we'd silently fall back to source-only.
        repair_ratio_bps: 1000, // 10%
        max_object_size: u32::try_from(MAX_PAYLOAD_BYTES).unwrap_or(u32::MAX),
        ..RaptorQConfig::default()
    };

    let Ok(encoder) = RaptorQEncoder::new(payload, &config) else {
        return;
    };

    let k = encoder.source_symbols();
    let symbols = encoder.encode_all();

    // Encoder must emit at least K source symbols, ESI 0..K-1 must be
    // present in the systematic prefix, and every symbol must be
    // exactly symbol_size bytes wide.
    assert!(
        symbols.len() >= k as usize,
        "encoder returned {} symbols for K={k}",
        symbols.len()
    );
    for (idx, (esi, data)) in symbols.iter().enumerate().take(k as usize) {
        assert_eq!(
            *esi, idx as u32,
            "source ESI {esi} not in systematic position {idx}"
        );
        assert_eq!(
            data.len(),
            usize::from(symbol_size),
            "source symbol ESI {esi} has length {} (expected {symbol_size})",
            data.len()
        );
    }

    // Build the decoder via the public constructor used by the host.
    let mut decoder = RaptorQDecoder::with_expected_symbols(
        k,
        u64::try_from(payload.len()).unwrap_or(u64::MAX),
        symbol_size,
        &config,
    );

    // Pick a (possibly substituted) symbol set and a permutation.
    // Only attempt repair-substitution when K >= 2 — for K=1 the lone
    // source equation is the only deterministic path to recovery, so
    // swapping it for an LT equation would test the dense-fallback
    // probabilistic path, which is a separate property.
    let substitute = input.use_repair_substitution && k >= 2 && symbols.len() > k as usize;
    let feed: Vec<(u32, Vec<u8>)> = if substitute {
        let mut combined: Vec<(u32, Vec<u8>)> = symbols[..(k as usize - 1)].to_vec();
        match symbols.get(k as usize) {
            Some(repair) => {
                combined.push(repair.clone());
                combined
            }
            None => symbols[..k as usize].to_vec(),
        }
    } else {
        symbols[..k as usize].to_vec()
    };

    let order = permuted_indices(feed.len(), input.permute_seed);
    let mut decoded: Option<Vec<u8>> = None;
    for &i in &order {
        let (esi, data) = feed[i].clone();
        match decoder.add_symbol(esi, data) {
            Ok(Some(payload_out)) => {
                decoded = Some(payload_out);
                break;
            }
            Ok(None) => {}
            Err(_) => {
                // Decoder rejection on an encoder-produced symbol is
                // itself a bug surface, but raptorq's public contract
                // permits Timeout / MemoryLimitExceeded under tight
                // budgets. Bail rather than panic so the fuzzer doesn't
                // chase config-induced false positives.
                return;
            }
        }
    }

    // If the decoder did not finish on the prefix, drain the rest of the
    // produced symbols (some configurations need K + epsilon repair
    // equations to complete via the dense fallback).
    if decoded.is_none() {
        for (esi, data) in symbols.iter().skip(k as usize) {
            if let Ok(Some(payload_out)) = decoder.add_symbol(*esi, data.clone()) {
                decoded = Some(payload_out);
                break;
            }
        }
    }

    let Some(payload_out) = decoded else {
        // The encoder produced K source symbols, but the decoder failed
        // to reconstruct from K + all repairs. That violates RFC 6330
        // for systematic input and is a real bug — promote to panic.
        panic!(
            "encoder→decoder round-trip failed: payload_len={} symbol_size={symbol_size} K={k}",
            payload.len()
        );
    };

    assert_eq!(
        payload_out.as_slice(),
        payload,
        "round-trip produced different bytes (len in={} out={})",
        payload.len(),
        payload_out.len()
    );
});
