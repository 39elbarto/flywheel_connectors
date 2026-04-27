//! Top-level serialization round-trip conformance harness for fcp-protocol.
//!
//! Aggregates every happy-path golden-vector category exposed by
//! [`fcp_conformance::vectors`] and exercises the round-trip invariant
//!
//!     input struct → serialize → bytes (must match golden)
//!     bytes → deserialize → struct (must match input)
//!
//! via the per-vector [`verify()`] helpers. Some vector categories already
//! have inline `all_vectors_verify` tests in their source module
//! (`src/vectors/{capability,session,session_messages,signing,hpke,
//! holder_proof,core}.rs`), but there was no integration-level gate AND two
//! categories — `FcpcGoldenVector` and `FcpsGoldenVector` — only exercised
//! `verify()` on tampered / negative-path cases. Their happy-path encode
//! bytes were never asserted to round-trip end-to-end.
//!
//! This harness closes that gap and makes serialization conformance a
//! single deterministic gate: one failure in any vector category fails
//! the whole suite. It also prints a markdown compliance matrix (category
//! × vectors × pass/fail) to stderr so a CI log parse can extract the
//! score directly.

use fcp_conformance::{
    CanonicalPayloadGoldenVector, CapabilityTokenGoldenVector, FcpcGoldenVector, FcpsGoldenVector,
    HelloRetryGoldenVector, HolderProofGoldenVector, HpkeSealedBoxGoldenVector,
    ObjectIdGoldenVector, QuorumSortGoldenVector, SessionGoldenVector, SigningBytesGoldenVector,
    TransportLimitsGoldenVector,
};

/// Compliance report row for one vector category.
#[derive(Debug)]
struct CategoryReport {
    name: &'static str,
    priority: &'static str,
    total: usize,
    passed: usize,
    failures: Vec<(String, String)>, // (description, error)
}

impl CategoryReport {
    fn ok(&self) -> bool {
        self.failures.is_empty() && self.passed == self.total
    }
}

fn run_category<V, I, D, F>(
    name: &'static str,
    priority: &'static str,
    vectors: I,
    describe: D,
    verify: F,
) -> CategoryReport
where
    I: IntoIterator<Item = V>,
    D: Fn(&V) -> String,
    F: Fn(&V) -> Result<(), String>,
{
    let mut total = 0;
    let mut passed = 0;
    let mut failures = Vec::new();

    for v in vectors {
        total += 1;
        match verify(&v) {
            Ok(()) => passed += 1,
            Err(e) => failures.push((describe(&v), e)),
        }
    }

    CategoryReport {
        name,
        priority,
        total,
        passed,
        failures,
    }
}

/// FCPC control-plane frame round-trip (MessageFrame).
///
/// Happy-path verify() was not exercised anywhere before this harness
/// landed. Tampering tests in `src/vectors/fcpc.rs` only assert that
/// modified inputs FAIL; they never proved the unmodified golden inputs
/// pass.
#[test]
fn fcpc_message_frame_roundtrip_conformance() {
    let report = run_category(
        "FcpcGoldenVector (FCPC MessageFrame)",
        "MUST",
        FcpcGoldenVector::load_all(),
        |v| v.description.clone(),
        FcpcGoldenVector::verify,
    );
    assert_category_passes(&report);
}

/// FCPS symbol-plane frame round-trip (MessageFrame).
///
/// Same gap as FCPC: the tampering tests covered negative paths only,
/// the happy-path encode/decode round-trip had no integration assertion.
#[test]
fn fcps_message_frame_roundtrip_conformance() {
    let report = run_category(
        "FcpsGoldenVector (FCPS MessageFrame)",
        "MUST",
        FcpsGoldenVector::load_all(),
        |v| v.description.clone(),
        FcpsGoldenVector::verify,
    );
    assert_category_passes(&report);
}

/// COSE_Sign1 capability token round-trip (CapabilityToken).
#[test]
fn capability_token_cose_roundtrip_conformance() {
    let report = run_category(
        "CapabilityTokenGoldenVector (COSE_Sign1)",
        "MUST",
        CapabilityTokenGoldenVector::load_all(),
        |v| v.description.clone(),
        CapabilityTokenGoldenVector::verify,
    );
    assert_category_passes(&report);
}

/// Session handshake derivation + AAD round-trip.
#[test]
fn session_handshake_roundtrip_conformance() {
    let report = run_category(
        "SessionGoldenVector",
        "MUST",
        SessionGoldenVector::load_all(),
        |v| v.description.clone(),
        SessionGoldenVector::verify,
    );
    assert_category_passes(&report);
}

/// Session-level control messages: HelloRetry + TransportLimits.
#[test]
fn session_messages_roundtrip_conformance() {
    let hello = run_category(
        "HelloRetryGoldenVector",
        "MUST",
        HelloRetryGoldenVector::load_all(),
        |v| v.description.clone(),
        HelloRetryGoldenVector::verify,
    );
    let limits = run_category(
        "TransportLimitsGoldenVector",
        "MUST",
        TransportLimitsGoldenVector::load_all(),
        |v| v.description.clone(),
        TransportLimitsGoldenVector::verify,
    );
    assert_category_passes(&hello);
    assert_category_passes(&limits);
}

/// Signing byte layout + quorum sort determinism.
#[test]
fn signing_layout_roundtrip_conformance() {
    let bytes = run_category(
        "SigningBytesGoldenVector",
        "MUST",
        SigningBytesGoldenVector::load_all(),
        |v| v.description.clone(),
        SigningBytesGoldenVector::verify,
    );
    let quorum = run_category(
        "QuorumSortGoldenVector",
        "MUST",
        QuorumSortGoldenVector::load_all(),
        |v| v.description.clone(),
        QuorumSortGoldenVector::verify,
    );
    assert_category_passes(&bytes);
    assert_category_passes(&quorum);
}

/// HPKE sealed-box (X25519+HKDF-SHA256+ChaCha20Poly1305) round-trip.
#[test]
fn hpke_sealed_box_roundtrip_conformance() {
    let report = run_category(
        "HpkeSealedBoxGoldenVector",
        "MUST",
        HpkeSealedBoxGoldenVector::load_all(),
        |v| v.description.clone(),
        HpkeSealedBoxGoldenVector::verify,
    );
    assert_category_passes(&report);
}

/// HolderProof signing-bytes layout + signature round-trip.
#[test]
fn holder_proof_roundtrip_conformance() {
    let report = run_category(
        "HolderProofGoldenVector",
        "MUST",
        HolderProofGoldenVector::load_all(),
        |v| v.description.clone(),
        HolderProofGoldenVector::verify,
    );
    assert_category_passes(&report);
}

/// Core object primitives: canonical CBOR payload + ObjectId derivation.
#[test]
fn core_object_roundtrip_conformance() {
    let payload = run_category(
        "CanonicalPayloadGoldenVector",
        "MUST",
        CanonicalPayloadGoldenVector::load_all(),
        |v| v.description.clone(),
        CanonicalPayloadGoldenVector::verify,
    );
    let id = run_category(
        "ObjectIdGoldenVector",
        "MUST",
        ObjectIdGoldenVector::load_all(),
        |v| v.description.clone(),
        ObjectIdGoldenVector::verify,
    );
    assert_category_passes(&payload);
    assert_category_passes(&id);
}

/// Aggregate compliance matrix. Runs every category once and prints a
/// markdown table so CI / release notes can extract per-category scores.
/// Fails if ANY category has a failure — serialization conformance is a
/// single atomic gate.
#[test]
fn serialization_conformance_matrix() {
    let reports: Vec<CategoryReport> = vec![
        run_category(
            "FcpcGoldenVector (FCPC MessageFrame)",
            "MUST",
            FcpcGoldenVector::load_all(),
            |v| v.description.clone(),
            FcpcGoldenVector::verify,
        ),
        run_category(
            "FcpsGoldenVector (FCPS MessageFrame)",
            "MUST",
            FcpsGoldenVector::load_all(),
            |v| v.description.clone(),
            FcpsGoldenVector::verify,
        ),
        run_category(
            "CapabilityTokenGoldenVector",
            "MUST",
            CapabilityTokenGoldenVector::load_all(),
            |v| v.description.clone(),
            CapabilityTokenGoldenVector::verify,
        ),
        run_category(
            "SessionGoldenVector",
            "MUST",
            SessionGoldenVector::load_all(),
            |v| v.description.clone(),
            SessionGoldenVector::verify,
        ),
        run_category(
            "HelloRetryGoldenVector",
            "MUST",
            HelloRetryGoldenVector::load_all(),
            |v| v.description.clone(),
            HelloRetryGoldenVector::verify,
        ),
        run_category(
            "TransportLimitsGoldenVector",
            "MUST",
            TransportLimitsGoldenVector::load_all(),
            |v| v.description.clone(),
            TransportLimitsGoldenVector::verify,
        ),
        run_category(
            "SigningBytesGoldenVector",
            "MUST",
            SigningBytesGoldenVector::load_all(),
            |v| v.description.clone(),
            SigningBytesGoldenVector::verify,
        ),
        run_category(
            "QuorumSortGoldenVector",
            "MUST",
            QuorumSortGoldenVector::load_all(),
            |v| v.description.clone(),
            QuorumSortGoldenVector::verify,
        ),
        run_category(
            "HpkeSealedBoxGoldenVector",
            "MUST",
            HpkeSealedBoxGoldenVector::load_all(),
            |v| v.description.clone(),
            HpkeSealedBoxGoldenVector::verify,
        ),
        run_category(
            "HolderProofGoldenVector",
            "MUST",
            HolderProofGoldenVector::load_all(),
            |v| v.description.clone(),
            HolderProofGoldenVector::verify,
        ),
        run_category(
            "CanonicalPayloadGoldenVector",
            "MUST",
            CanonicalPayloadGoldenVector::load_all(),
            |v| v.description.clone(),
            CanonicalPayloadGoldenVector::verify,
        ),
        run_category(
            "ObjectIdGoldenVector",
            "MUST",
            ObjectIdGoldenVector::load_all(),
            |v| v.description.clone(),
            ObjectIdGoldenVector::verify,
        ),
    ];

    let total: usize = reports.iter().map(|r| r.total).sum();
    let passed: usize = reports.iter().map(|r| r.passed).sum();
    let failed_rows: Vec<&CategoryReport> = reports.iter().filter(|r| !r.ok()).collect();

    eprintln!("\n# FCP Serialization Conformance Matrix\n");
    eprintln!("| Category | Requirement | Passed | Total | Score |");
    eprintln!("|----------|:-----------:|:------:|:-----:|:-----:|");
    for r in &reports {
        let score = if r.total == 0 {
            "n/a".to_string()
        } else {
            format!("{:.1}%", 100.0 * r.passed as f64 / r.total as f64)
        };
        eprintln!(
            "| {} | {} | {} | {} | {} |",
            r.name, r.priority, r.passed, r.total, score
        );
    }
    let overall = if total == 0 {
        0.0
    } else {
        100.0 * passed as f64 / total as f64
    };
    eprintln!(
        "\n**Overall:** {passed}/{total} vectors pass ({overall:.2}% MUST-clause coverage)\n"
    );

    if !failed_rows.is_empty() {
        eprintln!("## Failures\n");
        for r in failed_rows {
            eprintln!("### {}", r.name);
            for (desc, err) in &r.failures {
                eprintln!("- **{desc}**: {err}");
            }
            eprintln!();
        }
    }

    let total_failures: usize = reports.iter().map(|r| r.failures.len()).sum();
    assert_eq!(
        total_failures,
        0,
        "{total_failures} conformance vectors failed across {} categories",
        reports.iter().filter(|r| !r.ok()).count()
    );
    assert!(
        total > 0,
        "conformance matrix ran zero vectors — harness wiring regression"
    );
}

fn assert_category_passes(r: &CategoryReport) {
    assert!(
        r.total > 0,
        "category {} exposed no vectors (load_all() returned empty)",
        r.name
    );
    if !r.failures.is_empty() {
        let mut msg = format!(
            "category {} failed {}/{} vectors:\n",
            r.name,
            r.failures.len(),
            r.total
        );
        for (desc, err) in &r.failures {
            msg.push_str(&format!("  - {desc}: {err}\n"));
        }
        panic!("{msg}");
    }
}
