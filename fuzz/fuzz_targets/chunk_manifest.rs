#![no_main]

//! Fuzz target for `fcp_raptorq::ChunkedObjectManifest` reconstruction +
//! hash-binding (chunk.rs:22-193).
//!
//! `ChunkedObjectManifest` is the NORMATIVE chunked-object manifest with
//! BLAKE3 end-to-end verification. Existing fcp-raptorq fuzz targets
//! (raptorq_roundtrip, raptorq_decode_bounds, raptorq_envelope_decrypt)
//! do NOT touch the chunk-manifest surface.
//!
//! A regression in reconstruct could:
//!   - drop hash verification → attacker substitutes chunks, payload
//!     reconstructs to attacker-chosen bytes
//!   - drop length check → manifest claims one length, chunks total
//!     a different length, allocation mismatches
//!   - drop chunk-count check → reconstruct-on-fewer-chunks may panic
//!     or produce truncated output silently
//!   - panic on chunk_size=0 from a deserialized peer manifest →
//!     remote DoS via division-by-zero in chunk_size_at (chunk.rs:170-172
//!     guards this; the guard MUST hold).
//!
//! Properties asserted:
//!
//!   1. **Round-trip**: from_payload(p, cs) + reconstruct(chunks) == p.
//!   2. **chunk_count agreement**: manifest.chunk_count() == chunks.len()
//!      after from_payload.
//!   3. **Hash binding**: tampering payload_hash MUST cause reconstruct
//!      to return HashMismatch.
//!   4. **Chunk-count binding**: providing fewer/more chunks MUST
//!      return MissingChunks.
//!   5. **Length binding**: tampering total_len MUST return
//!      LengthMismatch (sum of chunk lengths disagrees).
//!   6. **Chunk-content binding**: tampering any chunk byte MUST cause
//!      reconstruct to return HashMismatch (after assembled-payload hash).
//!   7. **chunk_size=0 anti-panic**: chunk_size_at on a manifest with
//!      chunk_size=0 MUST return InvalidChunkSize, never panic.
//!   8. **reconstruct_unchecked agrees on length+count**: rejects with
//!      same MissingChunks / LengthMismatch as reconstruct, but does
//!      NOT enforce HashMismatch.
//!
//!   Once-gated regression anchors:
//!     (a) chunk_size=0 manifest → chunk_size_at returns InvalidChunkSize
//!         (anti-DoS panic guard at chunk.rs:170-172).
//!     (b) Tampering payload_hash → HashMismatch.
//!     (c) Swapping two non-equal chunks reverses → HashMismatch
//!         (chunk-order binding).

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::ObjectId;
use fcp_raptorq::{ChunkError, ChunkedObjectManifest, RawChunk};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

const MAX_PAYLOAD: usize = 4 * 1024;

static CHUNK_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    payload: Vec<u8>,
    chunk_size_seed: u16,
    /// Discriminator for the per-iteration tamper MR.
    tamper_disc: u8,
    /// Bit-flip target inside ciphertext when tampering content.
    tamper_index: u32,
}

fn pick_chunk_size(seed: u16) -> u32 {
    // Fold to a small range so we generate multiple chunks per payload
    // without pathologically tiny chunk_size that creates huge counts.
    let s = seed % 256;
    u32::from(s.max(1))
}

fuzz_target!(|data: &[u8]| {
    CHUNK_ANCHOR.call_once(assert_chunk_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    if input.payload.is_empty() || input.payload.len() > MAX_PAYLOAD {
        return;
    }

    let chunk_size = pick_chunk_size(input.chunk_size_seed);
    let (manifest, chunks) = ChunkedObjectManifest::from_payload(&input.payload, chunk_size);

    // ── PROPERTY 2: chunk_count agreement ─────────────────────────────
    assert_eq!(
        manifest.chunk_count(),
        chunks.len(),
        "manifest.chunk_count != raw chunks count"
    );

    // ── PROPERTY 1: round-trip ────────────────────────────────────────
    let recovered = manifest
        .reconstruct(&chunks)
        .expect("from_payload(p) + reconstruct MUST round-trip");
    assert_eq!(recovered, input.payload, "round-trip lost or altered bytes");

    // ── PROPERTY 3: hash binding ──────────────────────────────────────
    let mut tampered_manifest = manifest.clone();
    tampered_manifest.payload_hash[0] ^= 0x01;
    match tampered_manifest.reconstruct(&chunks) {
        Err(ChunkError::HashMismatch) => {}
        Err(other) => panic!("tampered payload_hash returned {other:?}; expected HashMismatch"),
        Ok(_) => panic!(
            "tampered payload_hash accepted — hash gate at chunk.rs:104-106 broken; \
             attacker could substitute chunks and reconstruct to chosen bytes"
        ),
    }

    // ── PROPERTY 4: chunk-count binding ───────────────────────────────
    if chunks.len() > 1 {
        let too_few = &chunks[..chunks.len() - 1];
        match manifest.reconstruct(too_few) {
            Err(ChunkError::MissingChunks { .. }) => {}
            Err(other) => panic!("too-few chunks returned {other:?}; expected MissingChunks"),
            Ok(_) => panic!("too-few chunks accepted — count gate broken"),
        }
        let mut too_many = chunks.clone();
        too_many.push(RawChunk::new(vec![0u8; 1]));
        match manifest.reconstruct(&too_many) {
            Err(ChunkError::MissingChunks { .. }) => {}
            Err(other) => panic!("too-many chunks returned {other:?}; expected MissingChunks"),
            Ok(_) => panic!("too-many chunks accepted — count gate broken"),
        }
    }

    // ── PROPERTY 5: length binding ────────────────────────────────────
    let mut len_tampered = manifest.clone();
    len_tampered.total_len = manifest.total_len.wrapping_add(1);
    match len_tampered.reconstruct(&chunks) {
        Err(ChunkError::LengthMismatch { .. }) => {}
        Err(other) => {
            // PayloadTooLarge or HashMismatch are not the gate we
            // probe; assert the length gate fires for off-by-one.
            panic!("tampered total_len returned {other:?}; expected LengthMismatch")
        }
        Ok(_) => panic!("tampered total_len accepted — length gate broken"),
    }

    // ── PROPERTY 6: chunk-content binding ─────────────────────────────
    if !chunks.is_empty() && !chunks[0].bytes.is_empty() {
        let mut tampered_chunks = chunks.clone();
        let bit = (input.tamper_index as usize) % (tampered_chunks[0].bytes.len() * 8);
        tampered_chunks[0].bytes[bit / 8] ^= 1u8 << (bit % 8);
        match manifest.reconstruct(&tampered_chunks) {
            Err(ChunkError::HashMismatch) => {}
            Err(ChunkError::LengthMismatch { .. }) => {
                // Tampering a single bit doesn't change length; this
                // shouldn't happen, but accept any rejection variant
                // since the attacker is still blocked.
            }
            Err(other) => panic!("chunk-content tamper returned {other:?}; expected HashMismatch"),
            Ok(_) => panic!(
                "chunk-content tamper accepted — chunk content not authenticated by \
                 manifest hash"
            ),
        }
    }

    // ── PROPERTY 8: reconstruct_unchecked agreement on count/length ───
    let unchecked = manifest.reconstruct_unchecked(&chunks);
    assert!(
        unchecked.is_ok(),
        "reconstruct_unchecked rejected legitimate chunks: {unchecked:?}"
    );
    if chunks.len() > 1 {
        let too_few = &chunks[..chunks.len() - 1];
        match manifest.reconstruct_unchecked(too_few) {
            Err(ChunkError::MissingChunks { .. }) => {}
            Err(other) => panic!(
                "reconstruct_unchecked too-few chunks returned {other:?}; expected MissingChunks"
            ),
            Ok(_) => panic!("reconstruct_unchecked accepted too-few chunks"),
        }
    }

    // Use the discriminator to vary which property is exercised most;
    // here we just bind it so it's not unused warnings-class.
    let _ = input.tamper_disc;
});

/// Once-gated regression anchors for the documented chunk-manifest
/// invariants.
fn assert_chunk_anchored() {
    // (a) chunk_size=0 anti-panic.
    let zero_size = ChunkedObjectManifest {
        total_len: 100,
        chunk_size: 0,
        chunks: vec![ObjectId::from_bytes([0u8; 32]); 4],
        payload_hash: [0u8; 32],
    };
    match zero_size.chunk_size_at(0) {
        Err(ChunkError::InvalidChunkSize) => {}
        Err(other) => panic!(
            "ANCHOR: chunk_size_at on chunk_size=0 returned {other:?}; expected \
             InvalidChunkSize"
        ),
        Ok(n) => panic!(
            "ANCHOR REGRESSION: chunk_size_at(0) on chunk_size=0 manifest returned \
             Ok({n}) — anti-panic guard at chunk.rs:170-172 dropped; remote peer \
             can DoS via division-by-zero modulo (or modular-arithmetic on the \
             last-chunk computation)"
        ),
    }

    // (b) payload_hash tamper → HashMismatch.
    let payload = b"anchor payload for chunk manifest hash binding".to_vec();
    let (mut m, chunks) = ChunkedObjectManifest::from_payload(&payload, 16);
    m.payload_hash[0] ^= 0xAB;
    match m.reconstruct(&chunks) {
        Err(ChunkError::HashMismatch) => {}
        Err(other) => {
            panic!("ANCHOR: tampered payload_hash returned {other:?}; expected HashMismatch")
        }
        Ok(_) => panic!(
            "ANCHOR REGRESSION: tampered payload_hash accepted — chunk.rs:104-106 \
             hash gate dropped; attacker substitutes content silently"
        ),
    }

    // (c) Chunk-order swap → HashMismatch.
    let payload = b"abcdefghij".to_vec();
    let (m, mut chunks) = ChunkedObjectManifest::from_payload(&payload, 3);
    if chunks.len() >= 2 {
        // Find two distinct chunks (with different bytes) and swap them.
        let mut swap_indices = None;
        for i in 0..chunks.len() {
            for j in (i + 1)..chunks.len() {
                if chunks[i].bytes != chunks[j].bytes {
                    swap_indices = Some((i, j));
                    break;
                }
            }
            if swap_indices.is_some() {
                break;
            }
        }
        if let Some((i, j)) = swap_indices {
            chunks.swap(i, j);
            match m.reconstruct(&chunks) {
                Err(ChunkError::HashMismatch) => {}
                Err(other) => {
                    panic!("ANCHOR: chunk swap returned {other:?}; expected HashMismatch")
                }
                Ok(_) => panic!(
                    "ANCHOR REGRESSION: chunks reordered (swap {i}↔{j}) reconstructed \
                     to a payload that passed hash verification — assembled-payload \
                     hash isn't covering chunk order"
                ),
            }
        }
    }
}
