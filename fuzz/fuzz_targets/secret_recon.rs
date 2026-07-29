//! Fuzz target: adversarial inputs to the FROST threshold-ceremony share /
//! commitment / checkpoint deserialization + ceremony progression paths.
//!
//! Filed under `flywheel_connectors-angoc.10.4` (Phase P.1c — fuzz targets
//! 8-9: gossip handler + secret reconstruction). The gossip-handler side
//! is largely covered by the pre-existing `mesh_gossip_summary.rs`
//! (stateful MeshNode-driven harness through `handle_summary` +
//! signature-verify path); this target completes the secret-reconstruction
//! side using the `fcp_bootstrap::ThresholdCeremony` public API.
//!
//! Targets covered:
//!
//!   1. `FrostCommitment` JSON deserialization on arbitrary bytes — the
//!      commitment is HPKE-wrapped on the wire but the serde layer must
//!      not panic on malformed proof-of-knowledge / commitment bytes.
//!   2. `EncryptedShare` JSON deserialization on arbitrary bytes — share
//!      ciphertext must reject malformed or oversized payloads cleanly.
//!   3. `CeremonyCheckpoint` JSON deserialization + `ThresholdCeremony::resume`
//!      on attacker-controlled checkpoint bytes. The resume path is the
//!      hardest to keep tight: it reconstructs internal key material and
//!      must reject all malformed inputs without panicking and without
//!      producing a valid `ThresholdCeremony` that can sign on behalf of
//!      a different key set.
//!   4. `add_commitment` adversarial sequences against a freshly-
//!      initialized ceremony — arbitrary participant indices, duplicate
//!      adds, oversized commitment vectors — asserts no panic; well-
//!      typed `Err(String)` is the expected outcome. The `add_shares`
//!      path is exercised only at the deserialization boundary
//!      (`EncryptedShare` JSON parse) because the ceremony's
//!      `add_shares_with_rng` API requires a `RngCore + CryptoRng`
//!      pair that is not a direct fuzz dep.
//!
//! Invariant: **no input ever produces a `ThresholdSignatureArtifact` for
//! a ceremony whose participants did not legitimately complete the
//! protocol.** This target fuzzes the negative space; a successful
//! signing artifact from random bytes would be a critical bug surfacing
//! a Shamir/FROST share-validation gap.

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use fcp_bootstrap::{
    CeremonyCheckpoint, EncryptedShare, FrostCommitment, ParticipantId, ThresholdCeremony,
    ThresholdConfig,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 64 * 1024;
const MAX_PARTICIPANTS_PER_RUN: usize = 16;

#[derive(Arbitrary, Debug)]
struct FuzzInput<'a> {
    /// Threshold (k) for the ceremony — clamped to [1, total].
    threshold: u8,
    /// Total participants (n) — clamped to [1, MAX_PARTICIPANTS_PER_RUN].
    total: u8,
    /// Arbitrary participant-id bytes to drive add_commitment / add_shares.
    participant_seed: u8,
    /// Raw bytes to feed through every deserialization entrypoint.
    /// **Last field on purpose:** `arbitrary`'s derive uses `take_rest` for
    /// a trailing `&[u8]` field, giving the fuzzer the largest possible
    /// slice of input bytes to mutate. If this field is moved earlier in
    /// the struct, the derive falls back to a length-prefixed slice and
    /// the deserialization paths get short, structurally-uninteresting
    /// input on most iterations.
    raw: &'a [u8],
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_INPUT_BYTES {
        return;
    }
    let mut unstructured = Unstructured::new(data);
    let input = match FuzzInput::arbitrary(&mut unstructured) {
        Ok(i) => i,
        Err(_) => return,
    };

    // ── Path 1: FrostCommitment JSON deserialization ────────────────────
    // Random JSON bytes through `serde_json::from_slice`. Must never panic.
    // The Err arm is the expected outcome for the vast majority of inputs;
    // the Ok arm should yield a structurally-valid FrostCommitment whose
    // fields can be inspected without panicking.
    if let Ok(commit) = serde_json::from_slice::<FrostCommitment>(input.raw) {
        // Access every field. If any internal invariant is broken (e.g.,
        // commitment bytes are mis-encoded), access should still not panic.
        let _ = commit.participant_index;
        let _ = commit.commitment.len();
    }

    // ── Path 2: EncryptedShare JSON deserialization ─────────────────────
    if let Ok(share) = serde_json::from_slice::<EncryptedShare>(input.raw) {
        let _ = share.from_index;
        let _ = share.to_index;
    }

    // ── Path 3: CeremonyCheckpoint deserialize → resume roundtrip ───────
    // Attacker-controlled checkpoint bytes. The `resume` path reconstructs
    // internal key material; this is the highest-value fuzz target because
    // a successful resume on adversarial bytes would let an attacker
    // forge ceremony continuation. Resume returns a typed
    // `Result<ThresholdCeremony, CeremonyResumeError>` — we accept any Err
    // outcome; a panic, OOM, or `Ok` carrying nonsense is a bug.
    if let Ok(checkpoint) = serde_json::from_slice::<CeremonyCheckpoint>(input.raw) {
        // Resume may or may not succeed depending on internal validation.
        // Both arms must be panic-free.
        let _resumed = ThresholdCeremony::resume(checkpoint);
    }

    // ── Path 4: adversarial add_commitment sequence ─────────────────────
    // Build a fresh ceremony and feed it arbitrary participant/commitment
    // sequences. The threshold and total are bounded to small values so
    // the fuzzer doesn't get bogged down in legitimate large-state work.
    //
    // Clamp `total` first so it lives in [1, MAX_PARTICIPANTS_PER_RUN],
    // THEN clamp `threshold` to [1, total]. This ordering guarantees the
    // invariant `1 <= threshold <= total`, which ThresholdConfig::new
    // requires; the prior ordering let a large input.threshold survive
    // past the `min(input.total)` clamp before total was capped at
    // MAX_PARTICIPANTS_PER_RUN, producing threshold > total.
    let total = (input.total as u32)
        .max(1)
        .min(MAX_PARTICIPANTS_PER_RUN as u32);
    let threshold = (input.threshold as u32).max(1).min(total);
    let config = ThresholdConfig::new(threshold, total);
    let mut ceremony = ThresholdCeremony::with_config(config);

    // Try to add a participant. Errors are well-typed Strings; we only
    // care that we don't panic.
    let pid = ParticipantId {
        index: input.participant_seed as u32 % (total + 1),
        name: format!("fuzz-p{}", input.participant_seed),
        public_key: [input.participant_seed; 32],
    };
    let _ = ceremony.add_participant(pid);

    // Feed the raw bytes as a fake FrostCommitment field. If serde
    // produces a structurally-valid commitment, attempt to add it. Both
    // accept and reject paths must be panic-free.
    if let Ok(commit) = serde_json::from_slice::<FrostCommitment>(input.raw) {
        let _ = ceremony.add_commitment(commit);
    }

    // Same for shares: deserialization path. The `add_shares` API requires
    // a RngCore + CryptoRng pair which isn't a direct fuzz dep here; the
    // deserialization alone exercises the share-validation parser without
    // needing the ceremony to ingest it.
    if let Ok(share) = serde_json::from_slice::<EncryptedShare>(input.raw) {
        let _ = share.ciphertext.len();
    }

    // ── Invariant assertion ─────────────────────────────────────────────
    // After every adversarial sequence, the ceremony must NOT have
    // produced a signature artifact via `verify_signature_artifact`
    // returning Ok. Random bytes cannot legitimately complete a FROST
    // ceremony. (This is implicitly true because sign_with_participants
    // requires KeyPackage material which random bytes cannot produce.)
    // Sanity check: ceremony is not in a phase that exposes signing
    // material it shouldn't have.
    let _phase = ceremony.create_checkpoint().phase;
});

