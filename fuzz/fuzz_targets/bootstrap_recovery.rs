#![no_main]
//! Fuzz harness for fcp-bootstrap HKDF-derived recovery material and
//! [`HardwareTokenPin`] constant-time comparison.
//!
//! The user-visible directive was "fuzz HardwareTokenPin + HKDF soft-token".
//! The soft-token harness itself is gated behind `#[cfg(test)]` in
//! `crates/fcp-bootstrap/src/soft_token.rs`, so it cannot be reached from an
//! external `cargo-fuzz` binary. The underlying HKDF-seeded key derivation
//! *is* reachable through the public surface: [`RecoveryPhrase::from_mnemonic`]
//! parses a BIP39 phrase and [`RecoveryPhrase::derive_owner_keypair`] runs
//! HKDF-SHA256 against the mnemonic's entropy to mint the Ed25519 owner key.
//! That is the same HKDF-seeded key derivation the soft-token harness wraps,
//! so fuzzing it exercises the primary attacker-reachable path.
//!
//! We also hit three other bootstrap boundaries:
//!
//! - [`RecoveryPhrase::from_words`] — the wordlist-array form of the parser.
//! - [`ColdRecovery::from_phrase`] — the recovery workflow that runs HKDF
//!   key derivation, deterministic genesis recreation, and optional
//!   fingerprint verification.
//! - [`HardwareTokenPin`] equality — wraps `subtle::ConstantTimeEq` over a
//!   redacted-string wrapper; the fuzzer drives pairs of arbitrary byte
//!   strings through the comparator and confirms the result agrees with
//!   a byte-exact equality check.

use fcp_bootstrap::{ColdRecovery, HardwareTokenPin, RecoveryPhrase};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 4 * 1024;

fn fuzz_hardware_token_pin(a: &[u8], b: &[u8]) {
    // Non-UTF-8 input is coerced via `String::from_utf8_lossy` because
    // `HardwareTokenPin::new` is typed on `impl Into<String>`. That is
    // fine for the comparator fuzzing below — we just need two equal
    // inputs to compare equal and two distinct inputs to compare
    // unequal on the constant-time path.
    let a_str = String::from_utf8_lossy(a).into_owned();
    let b_str = String::from_utf8_lossy(b).into_owned();

    let pin_a = HardwareTokenPin::new(a_str.clone());
    let pin_a_again = HardwareTokenPin::new(a_str.clone());
    let pin_b = HardwareTokenPin::new(b_str.clone());

    // Reflexivity: every pin must equal itself.
    assert!(pin_a == pin_a_again, "HardwareTokenPin equality must be reflexive");

    // Agreement with plain byte-equality: the constant-time comparator
    // must return true iff the underlying strings are identical.
    let by_bytes = a_str == b_str;
    let by_pin = pin_a == pin_b;
    assert_eq!(
        by_pin, by_bytes,
        "constant-time PartialEq disagreed with plain string equality"
    );

    // `is_empty` agrees with the wrapped string emptiness.
    assert_eq!(
        pin_a.is_empty(),
        a_str.is_empty(),
        "HardwareTokenPin::is_empty disagreed with inner string emptiness"
    );

    // Debug formatting must never leak PIN material.
    let debug = format!("{pin_a:?}");
    assert!(
        !debug.contains(&a_str) || a_str.is_empty(),
        "Debug for HardwareTokenPin must redact inner value"
    );
}

fn fuzz_recovery_phrase_parser(input: &str) {
    match RecoveryPhrase::from_mnemonic(input) {
        Ok(phrase) => {
            // Parser said yes — every downstream consumer must therefore
            // succeed (or return a typed error, not panic).
            let rendered = phrase.to_phrase();
            // Round-trip: re-parsing the canonical rendering should
            // succeed and yield the same entropy.
            let reparsed = RecoveryPhrase::from_mnemonic(&rendered)
                .expect("canonical phrase must re-parse");
            assert_eq!(
                phrase.entropy(),
                reparsed.entropy(),
                "parse→render→parse must preserve entropy"
            );

            // HKDF-seeded key derivation — this is the core crypto path
            // the user asked us to fuzz. Must not panic for any parsed
            // mnemonic, regardless of how entropy values are distributed.
            let _keypair = phrase.derive_owner_keypair();

            // ColdRecovery takes the same HKDF-derived material through
            // a fuller workflow (genesis construction + validation +
            // optional fingerprint compare). Exercising both shapes:
            let _ = ColdRecovery::from_phrase(&phrase, None);
            // And an attacker-controlled fingerprint string — must be
            // rejected cleanly (Err), not panic.
            let _ = ColdRecovery::from_phrase(&phrase, Some(""));
            let _ =
                ColdRecovery::from_phrase(&phrase, Some("BLAKE3:not-a-real-fingerprint"));
        }
        Err(err) => {
            // Every error from the parser must implement std::error::Error
            // and produce a non-empty, non-panicking Display.
            let _: &dyn std::error::Error = &err;
            let rendered = err.to_string();
            assert!(
                !rendered.is_empty(),
                "RecoveryPhraseError Display must never be empty"
            );
        }
    }
}

fn fuzz_recovery_phrase_words(words: &[&str]) {
    // `from_words` reconstructs a phrase by joining with spaces, so it
    // shares the `from_mnemonic` path once the join happens. We still
    // want fuzzer coverage of the boundary between word-slice and
    // phrase-string representations, particularly around empty slices
    // and slices with embedded whitespace.
    let _ = RecoveryPhrase::from_words(words);
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    // Layout: split the input on 0x1F into (pin_a, rest), then on 0x1E
    // into (pin_b, mnemonic_raw). This gives the fuzzer three
    // independent surfaces to attack from a single byte stream without
    // introducing a bespoke structured input format.
    let (pin_a, rest) = match data.iter().position(|b| *b == 0x1F) {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => (data, &[][..]),
    };
    let (pin_b, mnemonic_raw) = match rest.iter().position(|b| *b == 0x1E) {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, &[][..]),
    };

    fuzz_hardware_token_pin(pin_a, pin_b);

    if let Ok(mnemonic) = std::str::from_utf8(mnemonic_raw) {
        fuzz_recovery_phrase_parser(mnemonic);

        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        fuzz_recovery_phrase_words(&words);
    }
});
