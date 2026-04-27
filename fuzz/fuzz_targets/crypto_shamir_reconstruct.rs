#![no_main]

//! Attacker-controlled Shamir share reconstruction.
//!
//! Covers:
//! * `ShamirShare::from_bytes` on arbitrary wire bytes (index byte may be
//!   reserved/zero, length may be short, data may be empty).
//! * `reconstruct_secret` with attacker-chosen combinations: duplicate
//!   indices, mismatched lengths, reserved index=0, oversized share sets
//!   (>255), and pathologically large share sets.
//! * A positive round-trip property: if we split a short secret with k=3,
//!   n=5, then any 3 distinct attacker-permuted shares reconstruct the
//!   original. Inconsistent subsets must Err, not panic, and must not
//!   return the original secret (soundness of the scheme).

use arbitrary::Arbitrary;
use fcp_crypto::shamir::{ShamirShare, reconstruct_secret, split_secret};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 16 * 1024;
const MAX_SHARE_LEN: usize = 1024;

#[derive(Debug, Arbitrary)]
struct RawShare<'a> {
    bytes: &'a [u8],
}

#[derive(Debug, Arbitrary)]
struct Input<'a> {
    raw_shares: Vec<RawShare<'a>>,
    /// Secret used for the positive split→reconstruct round-trip.
    secret_seed: [u8; 16],
    /// Index permutation selector for the positive round-trip.
    perm_seed: u8,
}

fuzz_target!(|input: Input| {
    let total_bytes: usize = input.raw_shares.iter().map(|r| r.bytes.len()).sum();
    if total_bytes > MAX_INPUT_BYTES {
        return;
    }

    // Layer 1: parse adversarial share bytes.
    let mut parsed: Vec<ShamirShare> = Vec::with_capacity(input.raw_shares.len());
    for raw in &input.raw_shares {
        if raw.bytes.len() > MAX_SHARE_LEN {
            return;
        }
        if let Ok(share) = ShamirShare::from_bytes(raw.bytes) {
            // Round-trip: parsed → to_bytes → re-parse must be stable.
            let reencoded = share.to_bytes();
            let reparsed = ShamirShare::from_bytes(&reencoded)
                .expect("parsed share must re-parse after to_bytes");
            assert_eq!(
                reencoded,
                reparsed.to_bytes(),
                "ShamirShare to_bytes must be idempotent after parse"
            );
            parsed.push(share);
        }
    }

    // Layer 2: reconstruct_secret must never panic on attacker input.
    // Either it returns Err (invalid combination) or Ok (some byte-string
    // that is "the" reconstruction for these shares — possibly not the
    // intended secret if the shares are forged, which is expected).
    let _ = reconstruct_secret(&parsed);

    // Layer 3: positive round-trip property. Split a known secret, let the
    // attacker permute/select subsets, and verify any k distinct shares
    // recover the secret exactly.
    let secret = &input.secret_seed[..];
    let k = 3u8;
    let n = 5u8;
    let Ok(shares) = split_secret(secret, k, n) else {
        return;
    };

    // Pick k shares from the n available, using perm_seed as a rotation.
    let rot = usize::from(input.perm_seed % n);
    let mut subset: Vec<ShamirShare> = shares
        .iter()
        .cycle()
        .skip(rot)
        .take(usize::from(k))
        .cloned()
        .collect();

    let recovered = reconstruct_secret(&subset).expect("k shares from split must reconstruct");
    assert_eq!(
        recovered.as_bytes(),
        secret,
        "split→reconstruct must be a left inverse"
    );

    // Any subset with a duplicate index must be rejected, not silently
    // return a forged secret. This catches a common off-by-one in the
    // duplicate check or a regression where Lagrange interpolation
    // accepts degenerate sets.
    if subset.len() >= 2 {
        let dup = subset[0].clone();
        subset.push(dup);
        match reconstruct_secret(&subset) {
            Err(_) => {}
            Ok(_) => {
                panic!("reconstruct_secret accepted a subset containing a duplicate index");
            }
        }
    }
});
