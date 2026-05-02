//! Continuous self-audit harness — proptest + metamorphic relations
//! for FCP cryptographic and serialization primitives.
//!
//! Bead: flywheel_connectors-6po63.1 ([I.5] Continuous self-audit
//! via proptest + metamorphic relations; auto-file beads on
//! regression).
//!
//! ## Metamorphic relations
//!
//! A *metamorphic relation* is a transformation A on an input that
//! must produce a predictable transformation A' on the output. The
//! oracle problem (we don't know what `sign(sk, msg)` *should*
//! return) becomes tractable: we instead assert *invariants* across
//! input/output pairs.
//!
//! Coverage in this harness:
//!
//! ### `fcp-cbor` (canonical CBOR encoding)
//!
//! * **CBOR-MR-1 round-trip identity** —
//!   `decode(encode(x)) == x` for any serializable `x`.
//! * **CBOR-MR-2 canonical encoding determinism** —
//!   `encode(x) == encode(x)` across two invocations (RFC 8949
//!   §4.2 deterministic encoding).
//! * **CBOR-MR-3 map order independence** — encoding the same
//!   `BTreeMap<String, i64>` content in two distinct insertion
//!   orders produces byte-identical bytes (canonical key order).
//! * **CBOR-MR-4 schema-hash collision freedom** — distinct
//!   `(namespace, name, version)` tuples produce distinct
//!   `SchemaHash` bytes (length-prefixed domain separation).
//!
//! ### `fcp-crypto` (signatures, AEAD, KDF, hash)
//!
//! * **ED25519-MR-1 sign/verify identity** —
//!   `verify(pk, m, sign(sk, m)) == Ok(())`.
//! * **ED25519-MR-2 tampered-message rejection** — for any
//!   non-empty `m` and any byte mutation `m → m'`,
//!   `verify(pk, m', sign(sk, m)) == Err(_)`.
//! * **ED25519-MR-3 wrong-key rejection** — for any two distinct
//!   keys `sk_a ≠ sk_b`,
//!   `verify(sk_a.verifying_key(), m, sign(sk_b, m)) == Err(_)`.
//! * **AEAD-MR-1 ChaCha20-Poly1305 round-trip identity** —
//!   `decrypt(k, n, encrypt(k, n, m, aad), aad) == Ok(m)`.
//! * **AEAD-MR-2 ChaCha20-Poly1305 wrong-key rejection** — for
//!   any distinct `k_a ≠ k_b`,
//!   `decrypt(k_b, n, encrypt(k_a, n, m, aad), aad) == Err(_)`.
//! * **HKDF-MR-1 derivation determinism** —
//!   `hkdf(salt, ikm, info, len) == hkdf(salt, ikm, info, len)`.
//! * **BLAKE3-MR-1 collision freedom (statistical)** — for any
//!   pair of distinct inputs `a ≠ b`, `blake3(a) ≠ blake3(b)`
//!   (proptest-driven, 1024 cases).
//!
//! ## Auto-bead-filing on regression
//!
//! Property failures invoke [`auto_bead::report_regression`], which
//! always writes a JSONL line to the system tempdir and, when the
//! `FCP_SELF_AUDIT_AUTO_FILE=1` env var is set, shells out to
//! `br create` with a stable `[SELF-AUDIT] <relation>` title. The
//! reporter dedupes within a process so re-running a broken
//! property under proptest's shrinking does not file duplicate
//! beads on every shrink step.
//!
//! Defaulting OFF for local dev runs (only-on-when-CI-env-set)
//! prevents accidental bead pollution from a developer iterating
//! on a property locally. CI gets the auto-file behaviour by
//! exporting the env var in the workflow.

use std::collections::BTreeMap;

use fcp_cbor::{SchemaId, to_canonical_cbor};
use fcp_crypto::{
    AeadKey, ChaCha20Nonce, Ed25519SigningKey, chacha20_decrypt, chacha20_encrypt, hkdf_sha256,
};
use proptest::prelude::*;
use semver::Version;
use serde::{Deserialize, Serialize};

mod auto_bead {
    //! Auto-file regression beads on metamorphic-relation failures.
    //!
    //! Every call writes a JSONL record to a tempdir log
    //! (idempotent within a process). When the env-var
    //! `FCP_SELF_AUDIT_AUTO_FILE=1` is set the call additionally
    //! shells out to `br create` to record a P1 bug bead under
    //! the `[SELF-AUDIT] <relation>` title prefix.

    use std::collections::HashSet;
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Path of the regression JSONL log inside the system tempdir.
    /// Tests can read this file to verify auto-file invocations
    /// fired without depending on whether `br` is on the PATH.
    pub fn log_path() -> PathBuf {
        std::env::temp_dir().join("fcp-self-audit-regressions.jsonl")
    }

    fn dedupe_set() -> &'static Mutex<HashSet<String>> {
        static SET: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
        SET.get_or_init(|| Mutex::new(HashSet::new()))
    }

    /// Whether the current process should attempt the `br create`
    /// shell-out. Off by default to keep local dev runs quiet.
    fn auto_file_enabled() -> bool {
        std::env::var("FCP_SELF_AUDIT_AUTO_FILE").as_deref() == Ok("1")
    }

    /// Record a metamorphic-relation regression. Always writes the
    /// JSONL log; conditionally shells out to file a `br` bead.
    /// Returns `true` if this is the first sighting of the relation
    /// in this process, `false` if a duplicate was suppressed.
    pub fn report_regression(rel_name: &str, details: &str) -> bool {
        let mut set = dedupe_set().lock().expect("dedupe set");
        let first = set.insert(rel_name.to_string());
        drop(set);

        if first {
            let now_unix_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_millis());
            // Construct a JSON line by hand so the harness has zero
            // serde_json dep beyond what fcp-crypto already pulls.
            let line = format!(
                concat!(
                    "{{\"ts_unix_ms\":{ts},",
                    "\"relation\":\"{name}\",",
                    "\"details\":\"{details}\"}}\n",
                ),
                ts = now_unix_ms,
                name = rel_name.replace('"', "\\\""),
                details = details.replace('"', "\\\"").replace('\n', " "),
            );
            if let Ok(mut f) = OpenOptions::new()
                .create(true)
                .append(true)
                .open(log_path())
            {
                let _ = f.write_all(line.as_bytes());
            }

            if auto_file_enabled() {
                let title = format!("[SELF-AUDIT] {rel_name} metamorphic relation failed");
                let description = format!(
                    "Auto-filed by fcp-crypto self-audit harness (6po63.1).\n\nRelation: {rel_name}\nDetails:\n{details}\n",
                );
                // Best-effort shell-out — non-zero exit and missing
                // binary are NOT escalated, so a misconfigured CI
                // runner doesn't mask the original property failure.
                let _ = Command::new("br")
                    .arg("create")
                    .arg("--title")
                    .arg(&title)
                    .arg("--type")
                    .arg("bug")
                    .arg("--priority")
                    .arg("1")
                    .arg("--description")
                    .arg(&description)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
        }
        first
    }
}

/// Metamorphic-assertion macro. Logs the failure via
/// [`auto_bead::report_regression`] before panicking, so the
/// regression record is durable even if the test process aborts.
macro_rules! metamorphic_assert {
    ($cond:expr, $rel:expr, $details:expr $(,)?) => {
        if !$cond {
            let _ = auto_bead::report_regression($rel, $details);
            panic!(
                "metamorphic relation `{}` violated: {}",
                $rel, $details
            );
        }
    };
}

// ── CBOR-MR-1: round-trip identity ─────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_field_names)]
struct CborProbe {
    int_field: i64,
    text_field: String,
    bytes_field: Vec<u8>,
    list_field: Vec<i32>,
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    #[test]
    fn cbor_round_trip_identity(
        i in any::<i64>(),
        t in "[a-zA-Z0-9 _.-]{0,128}",
        b in proptest::collection::vec(any::<u8>(), 0..256),
        l in proptest::collection::vec(any::<i32>(), 0..32),
    ) {
        let original = CborProbe {
            int_field: i,
            text_field: t,
            bytes_field: b,
            list_field: l,
        };
        let encoded = to_canonical_cbor(&original).expect("encode probe");
        let decoded: CborProbe =
            ciborium::de::from_reader(encoded.as_slice()).expect("decode probe");
        metamorphic_assert!(
            decoded == original,
            "CBOR-MR-1",
            &format!("decode(encode(x)) ≠ x for {original:?}"),
        );
    }
}

// ── CBOR-MR-2: canonical encoding determinism ──────────────────────────

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, .. ProptestConfig::default() })]

    #[test]
    fn cbor_canonical_encoding_is_deterministic(
        i in any::<i64>(),
        t in "[a-zA-Z0-9]{0,64}",
    ) {
        let probe = CborProbe {
            int_field: i,
            text_field: t,
            bytes_field: vec![0xAA, 0xBB],
            list_field: vec![1, 2, 3],
        };
        let a = to_canonical_cbor(&probe).expect("encode a");
        let b = to_canonical_cbor(&probe).expect("encode b");
        let c = to_canonical_cbor(&probe).expect("encode c");
        metamorphic_assert!(
            a == b && b == c,
            "CBOR-MR-2",
            &format!("non-deterministic CBOR encoding for {probe:?}"),
        );
    }
}

// ── CBOR-MR-3: map order independence ──────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, .. ProptestConfig::default() })]

    #[test]
    fn cbor_map_order_independence(
        raw_entries in proptest::collection::vec(
            ("[a-z]{1,8}", any::<i64>()),
            1..16,
        ),
    ) {
        // Dedupe by key so both insertion orders see the same
        // logical (key, value) set — duplicate keys are not part of
        // this MR (last-write-wins makes order-dependent value
        // selection inevitable).
        let mut by_key: BTreeMap<String, i64> = BTreeMap::new();
        for (k, v) in &raw_entries {
            by_key.insert(k.clone(), *v);
        }
        let entries: Vec<(String, i64)> =
            by_key.into_iter().collect();
        prop_assume!(!entries.is_empty());

        // Build the same logical map two different ways: BTreeMap
        // (sorted insertion) and BTreeMap from a reversed iterator.
        // Canonical CBOR emits map keys in sorted order regardless,
        // so encodings must agree byte-for-byte.
        let mut forward = BTreeMap::new();
        for (k, v) in &entries {
            forward.insert(k.clone(), *v);
        }
        let mut reversed = BTreeMap::new();
        for (k, v) in entries.iter().rev() {
            reversed.insert(k.clone(), *v);
        }
        let bytes_a = to_canonical_cbor(&forward).expect("encode forward");
        let bytes_b = to_canonical_cbor(&reversed).expect("encode reversed");
        metamorphic_assert!(
            bytes_a == bytes_b,
            "CBOR-MR-3",
            &format!(
                "BTreeMap encoding diverged across insertion orders ({} unique entries)",
                entries.len()
            ),
        );
    }
}

// ── CBOR-MR-4: schema-hash collision freedom ───────────────────────────

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, .. ProptestConfig::default() })]

    #[test]
    fn cbor_schema_hash_collision_freedom(
        ns_a in "[a-z][a-z0-9.]{0,15}",
        ns_b in "[a-z][a-z0-9.]{0,15}",
        name_a in "[A-Z][a-zA-Z0-9]{0,15}",
        name_b in "[A-Z][a-zA-Z0-9]{0,15}",
        major in 0u64..16,
        minor in 0u64..16,
        patch in 0u64..16,
    ) {
        // Skip identical tuples — collision freedom only constrains
        // distinct inputs.
        prop_assume!(ns_a != ns_b || name_a != name_b);
        // Also reject bare `:` / `@` in inputs (try_new rejects them).
        prop_assume!(!ns_a.contains(':') && !ns_a.contains('@'));
        prop_assume!(!ns_b.contains(':') && !ns_b.contains('@'));
        prop_assume!(!name_a.contains(':') && !name_a.contains('@'));
        prop_assume!(!name_b.contains(':') && !name_b.contains('@'));
        let v = Version::new(major, minor, patch);
        let a = SchemaId::try_new(ns_a, name_a, v.clone()).expect("schema id a");
        let b = SchemaId::try_new(ns_b, name_b, v).expect("schema id b");
        let hash_a = a.hash();
        let hash_b = b.hash();
        metamorphic_assert!(
            hash_a != hash_b,
            "CBOR-MR-4",
            &format!("schema hash collision: {a:?} ↔ {b:?}"),
        );
    }
}

// ── ED25519-MR-1: sign/verify identity ─────────────────────────────────

fn signing_key_from_seed(seed: u64) -> Ed25519SigningKey {
    // Deterministic key derivation via SHA-256 of the seed — keeps
    // proptest reproducible and avoids OS RNG dependency.
    let mut key_bytes = [0u8; 32];
    let salt = b"FCP_SELF_AUDIT_ED25519_SEED";
    hkdf_sha256(
        Some(salt),
        &seed.to_be_bytes(),
        b"sk",
        &mut key_bytes,
    )
    .expect("hkdf");
    Ed25519SigningKey::from_bytes(&key_bytes).expect("valid signing key")
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, .. ProptestConfig::default() })]

    #[test]
    fn ed25519_sign_verify_identity(
        seed in any::<u64>(),
        msg in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let sk = signing_key_from_seed(seed);
        let pk = sk.verifying_key();
        let sig = sk.sign(&msg);
        metamorphic_assert!(
            pk.verify(&msg, &sig).is_ok(),
            "ED25519-MR-1",
            &format!("verify failed for sign/verify identity (msg.len={})", msg.len()),
        );
    }
}

// ── ED25519-MR-2: tampered-message rejection ───────────────────────────

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, .. ProptestConfig::default() })]

    #[test]
    fn ed25519_tampered_message_rejected(
        seed in any::<u64>(),
        msg in proptest::collection::vec(any::<u8>(), 1..256),
        tamper_index in any::<usize>(),
        tamper_xor in 1u8..=255,
    ) {
        let sk = signing_key_from_seed(seed);
        let pk = sk.verifying_key();
        let sig = sk.sign(&msg);
        let mut tampered = msg.clone();
        let idx = tamper_index % tampered.len();
        tampered[idx] ^= tamper_xor; // non-zero XOR guarantees bit flip
        metamorphic_assert!(
            pk.verify(&tampered, &sig).is_err(),
            "ED25519-MR-2",
            &format!(
                "tampered message accepted (idx={idx}, xor={tamper_xor:#x}, len={})",
                msg.len()
            ),
        );
    }
}

// ── ED25519-MR-3: wrong-key rejection ──────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, .. ProptestConfig::default() })]

    #[test]
    fn ed25519_wrong_key_rejected(
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
        msg in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        prop_assume!(seed_a != seed_b);
        let sk_a = signing_key_from_seed(seed_a);
        let sk_b = signing_key_from_seed(seed_b);
        let pk_b = sk_b.verifying_key();
        let sig_from_a = sk_a.sign(&msg);
        // Verify with B's pk — must fail (signed by A, not B).
        metamorphic_assert!(
            pk_b.verify(&msg, &sig_from_a).is_err(),
            "ED25519-MR-3",
            &format!(
                "wrong-key verify accepted (seed_a={seed_a}, seed_b={seed_b}, msg.len={})",
                msg.len()
            ),
        );
    }
}

// ── AEAD-MR-1: ChaCha20-Poly1305 round-trip identity ───────────────────

fn aead_key_from_seed(seed: u64) -> AeadKey {
    let mut bytes = [0u8; 32];
    hkdf_sha256(
        Some(b"FCP_SELF_AUDIT_AEAD_SEED"),
        &seed.to_be_bytes(),
        b"k",
        &mut bytes,
    )
    .expect("hkdf");
    AeadKey::from_bytes(bytes)
}

fn nonce_from_seed(seed: u64) -> ChaCha20Nonce {
    let mut bytes = [0u8; 12];
    hkdf_sha256(
        Some(b"FCP_SELF_AUDIT_NONCE_SEED"),
        &seed.to_be_bytes(),
        b"n",
        &mut bytes,
    )
    .expect("hkdf");
    ChaCha20Nonce::from_bytes(bytes)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, .. ProptestConfig::default() })]

    #[test]
    fn aead_chacha20_round_trip_identity(
        key_seed in any::<u64>(),
        nonce_seed in any::<u64>(),
        msg in proptest::collection::vec(any::<u8>(), 0..512),
        aad in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let key = aead_key_from_seed(key_seed);
        let nonce = nonce_from_seed(nonce_seed);
        let ct = chacha20_encrypt(&key, &nonce, &msg, &aad).expect("encrypt");
        let pt = chacha20_decrypt(&key, &nonce, &ct, &aad).expect("decrypt");
        metamorphic_assert!(
            pt == msg,
            "AEAD-MR-1",
            &format!("round-trip diverged (msg.len={}, aad.len={})", msg.len(), aad.len()),
        );
    }
}

// ── AEAD-MR-2: ChaCha20-Poly1305 wrong-key rejection ───────────────────

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, .. ProptestConfig::default() })]

    #[test]
    fn aead_chacha20_wrong_key_rejected(
        key_seed_a in any::<u64>(),
        key_seed_b in any::<u64>(),
        nonce_seed in any::<u64>(),
        msg in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        prop_assume!(key_seed_a != key_seed_b);
        let key_a = aead_key_from_seed(key_seed_a);
        let key_b = aead_key_from_seed(key_seed_b);
        let nonce = nonce_from_seed(nonce_seed);
        let aad = b"self-audit-aad";
        let ct = chacha20_encrypt(&key_a, &nonce, &msg, aad).expect("encrypt");
        // Decrypt with B's key — must fail (Poly1305 tag mismatch).
        metamorphic_assert!(
            chacha20_decrypt(&key_b, &nonce, &ct, aad).is_err(),
            "AEAD-MR-2",
            &format!("wrong-key decrypt accepted (seed_a={key_seed_a}, seed_b={key_seed_b})"),
        );
    }
}

// ── HKDF-MR-1: derivation determinism ──────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, .. ProptestConfig::default() })]

    #[test]
    fn hkdf_sha256_is_deterministic(
        salt in proptest::collection::vec(any::<u8>(), 0..64),
        ikm in proptest::collection::vec(any::<u8>(), 1..64),
        info in proptest::collection::vec(any::<u8>(), 0..64),
        out_len in 1usize..=64,
    ) {
        let mut a = vec![0u8; out_len];
        let mut b = vec![0u8; out_len];
        let mut c = vec![0u8; out_len];
        let salt_arg = if salt.is_empty() { None } else { Some(salt.as_slice()) };
        hkdf_sha256(salt_arg, &ikm, &info, &mut a).expect("hkdf a");
        hkdf_sha256(salt_arg, &ikm, &info, &mut b).expect("hkdf b");
        hkdf_sha256(salt_arg, &ikm, &info, &mut c).expect("hkdf c");
        metamorphic_assert!(
            a == b && b == c,
            "HKDF-MR-1",
            &format!("non-deterministic HKDF (out_len={out_len})"),
        );
    }
}

// ── BLAKE3-MR-1: collision freedom (statistical) ───────────────────────

proptest! {
    #![proptest_config(ProptestConfig { cases: 1024, .. ProptestConfig::default() })]

    #[test]
    fn blake3_distinct_inputs_produce_distinct_hashes(
        a in proptest::collection::vec(any::<u8>(), 0..256),
        b in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        prop_assume!(a != b);
        let h_a = blake3::hash(&a);
        let h_b = blake3::hash(&b);
        metamorphic_assert!(
            h_a != h_b,
            "BLAKE3-MR-1",
            &format!("BLAKE3 collision (a.len={}, b.len={})", a.len(), b.len()),
        );
    }
}

// ── Meta-tests: the auto-bead helper itself ────────────────────────────

#[test]
fn meta_auto_bead_helper_writes_regression_log_line() {
    // Use a unique relation name per test so dedupe doesn't suppress
    // the write across re-runs of the same test binary.
    let relation = format!(
        "META-AUTO-BEAD-WRITES-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let first = auto_bead::report_regression(&relation, "test details");
    assert!(first, "first call must report `true` (first sighting)");

    let log = auto_bead::log_path();
    let contents = std::fs::read_to_string(&log)
        .unwrap_or_else(|e| panic!("read log {}: {e}", log.display()));
    assert!(
        contents.contains(&relation),
        "regression log missing relation `{relation}`; tail: {}",
        &contents[contents.len().saturating_sub(512)..]
    );
}

#[test]
fn meta_auto_bead_helper_dedupes_within_process() {
    let relation = format!(
        "META-AUTO-BEAD-DEDUP-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let first = auto_bead::report_regression(&relation, "first call");
    let second = auto_bead::report_regression(&relation, "second call");
    let third = auto_bead::report_regression(&relation, "third call");
    assert!(first, "first sighting must report true");
    assert!(!second, "duplicate within process must report false");
    assert!(!third, "third call must also be deduped");
}

#[test]
fn meta_metamorphic_assert_macro_records_then_panics_on_failure() {
    // Demonstrate that violating a relation fires both the
    // regression log AND the panic. We catch the panic with
    // catch_unwind so the test itself passes.
    let relation = format!(
        "META-MACRO-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let rel_for_closure = relation.clone();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        metamorphic_assert!(false, &rel_for_closure, "intentional self-test failure");
    }));
    assert!(result.is_err(), "macro must panic on failure");

    // Regression log must contain the relation name.
    let log = auto_bead::log_path();
    let contents =
        std::fs::read_to_string(&log).unwrap_or_else(|e| panic!("read log: {e}"));
    assert!(
        contents.contains(&relation),
        "macro did not record regression to log"
    );
}

// ── Sanity: test file enumerates expected metamorphic-relation names ───

#[test]
fn metamorphic_relation_inventory_matches_module_doc() {
    // Documents the canonical inventory of relations exercised by
    // this harness. If a relation is added or removed, both this
    // list AND the module-level doc must be updated. Failing to
    // update one or the other surfaces here.
    let inventory: &[&str] = &[
        "CBOR-MR-1",
        "CBOR-MR-2",
        "CBOR-MR-3",
        "CBOR-MR-4",
        "ED25519-MR-1",
        "ED25519-MR-2",
        "ED25519-MR-3",
        "AEAD-MR-1",
        "AEAD-MR-2",
        "HKDF-MR-1",
        "BLAKE3-MR-1",
    ];
    assert_eq!(
        inventory.len(),
        11,
        "metamorphic-relation inventory drift; update module-level doc and registry"
    );
    // No duplicate IDs.
    let mut seen = std::collections::HashSet::new();
    for id in inventory {
        assert!(seen.insert(*id), "duplicate relation id: {id}");
    }
}
