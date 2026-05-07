use std::{fs, process::Command};

use serde::Serialize;

use fcp_crypto_pq::{
    DelegationPeriod, LATTICE_REPRESENTATION_VERSION, LatticeParams, LatticePqError,
    LatticePreimage, delegate, operation_hash, trap_gen, verify,
};

#[derive(Debug, Serialize)]
struct EvidenceLog<'a> {
    command_line: &'a str,
    git_revision: String,
    artifact_path: &'a str,
    profile: &'a str,
    representation_version: u16,
    params: LatticeParams,
    matrix_dimensions: MatrixDimensions,
    encoded_lengths: EncodedLengths,
    allocation_estimate: AllocationEstimate,
    redaction: RedactionEvidence,
    deterministic_shake_compatibility: DeterministicShakeCompatibility,
    policy_bridge_compatibility: PolicyBridgeCompatibility,
    result: &'a str,
    skip_reason: Option<&'a str>,
}

const ARTIFACT_PATH: &str = "target/fcp-crypto-pq/representation-profile-evidence.jsonl";

#[derive(Debug, Serialize)]
struct MatrixDimensions {
    n: u32,
    m: u32,
    q: u64,
    coefficient_bytes: usize,
}

#[derive(Debug, Serialize)]
struct EncodedLengths {
    #[serde(rename = "public_matrix_seed_bytes")]
    public_matrix_seed: usize,
    #[serde(rename = "public_matrix_expanded_bytes")]
    public_matrix_expanded: usize,
    #[serde(rename = "trapdoor_storage_bytes")]
    trapdoor_storage: usize,
    #[serde(rename = "preimage_encoded_bytes")]
    preimage_encoded: usize,
}

#[derive(Debug, Serialize)]
struct AllocationEstimate {
    #[serde(rename = "public_matrix_expanded_bytes")]
    public_matrix_expanded: usize,
    #[serde(rename = "max_public_matrix_expanded_bytes")]
    max_public_matrix_expanded: usize,
    #[serde(rename = "preimage_encoded_bytes")]
    preimage_encoded: usize,
    #[serde(rename = "max_preimage_encoded_bytes")]
    max_preimage_encoded: usize,
}

#[derive(Debug, Serialize)]
struct RedactionEvidence {
    master_trapdoor_debug_redacted: bool,
    zone_period_trapdoor_debug_redacted: bool,
    preimage_debug_redacted: bool,
}

#[derive(Debug, Serialize)]
struct DeterministicShakeCompatibility {
    #[serde(rename = "master_public_seed_hex")]
    master_public_seed: String,
    #[serde(rename = "zone_period_seed_hex")]
    zone_period_seed: String,
    #[serde(rename = "operation_hash_hex")]
    operation_hash: String,
}

#[derive(Debug, Serialize)]
struct PolicyBridgeCompatibility {
    preimage_length_matches_profile: bool,
    rejects_legacy_fixed_64_byte_preimage: bool,
}

const fn period() -> DelegationPeriod {
    DelegationPeriod {
        start_secs: 1_700_000_000,
        end_secs: 1_700_003_600,
    }
}

fn evidence_for(profile: &'static str, params: LatticeParams) -> EvidenceLog<'static> {
    let representation = params
        .representation_profile()
        .expect("test profiles must have bounded representation");
    let (master_pub, master_trap) = trap_gen(params).expect("trap_gen scaffold succeeds");
    let zone = [0xA5; 32];
    let (zone_pub, zone_trap) =
        delegate(&master_pub, &master_trap, zone, period(), params).expect("delegate succeeds");
    let preimage = LatticePreimage::fixture_zero(params).expect("fixture preimage length is valid");
    let op_hash = operation_hash(&zone, period(), b"op:read", b"principal:alice");
    let verify_outcome = verify(&zone_pub, op_hash, &preimage, period().start_secs, params);
    let (result, skip_reason) = match verify_outcome {
        Ok(()) => ("passed", None),
        Err(LatticePqError::NotImplemented { .. }) => {
            ("skipped", Some("verify primitive not implemented"))
        }
        Err(_) => ("failed", None),
    };

    let master_debug = format!("{master_trap:?}");
    let zone_debug = format!("{zone_trap:?}");
    let preimage_debug = format!("{preimage:?}");
    let rejects_legacy_fixed_64_byte_preimage = if representation.preimage_encoded_bytes == 64 {
        false
    } else {
        matches!(
            LatticePreimage::from_encoded_bytes(params, vec![0_u8; 64]),
            Err(LatticePqError::InvalidEncodingLength { .. })
        )
    };

    EvidenceLog {
        command_line: "cargo test -p fcp-crypto-pq representation_profile_evidence_jsonl_is_secret_free -- --nocapture",
        git_revision: git_revision(),
        artifact_path: ARTIFACT_PATH,
        profile,
        representation_version: LATTICE_REPRESENTATION_VERSION,
        params,
        matrix_dimensions: MatrixDimensions {
            n: params.n,
            m: params.m,
            q: params.q,
            coefficient_bytes: representation.coefficient_bytes,
        },
        encoded_lengths: EncodedLengths {
            public_matrix_seed: representation.public_matrix_seed_bytes,
            public_matrix_expanded: representation.public_matrix_expanded_bytes,
            trapdoor_storage: representation.trapdoor_storage_bytes,
            preimage_encoded: representation.preimage_encoded_bytes,
        },
        allocation_estimate: AllocationEstimate {
            public_matrix_expanded: representation.public_matrix_expanded_bytes,
            max_public_matrix_expanded: 64 * 1024 * 1024,
            preimage_encoded: representation.preimage_encoded_bytes,
            max_preimage_encoded: 1024 * 1024,
        },
        redaction: RedactionEvidence {
            master_trapdoor_debug_redacted: master_debug.contains("<redacted>")
                && !master_debug.contains("bytes"),
            zone_period_trapdoor_debug_redacted: zone_debug.contains("<redacted>")
                && !zone_debug.contains("bytes"),
            preimage_debug_redacted: preimage_debug.contains("<redacted>")
                && !preimage_debug.contains("bytes"),
        },
        deterministic_shake_compatibility: DeterministicShakeCompatibility {
            master_public_seed: hex::encode(master_pub.hash),
            zone_period_seed: hex::encode(zone_pub.hash),
            operation_hash: hex::encode(op_hash.0),
        },
        policy_bridge_compatibility: PolicyBridgeCompatibility {
            preimage_length_matches_profile: preimage.encoded_len()
                == representation.preimage_encoded_bytes,
            rejects_legacy_fixed_64_byte_preimage,
        },
        result,
        skip_reason,
    }
}

fn git_revision() -> String {
    Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|revision| revision.trim().to_string())
        .filter(|revision| !revision.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn write_jsonl_artifact(lines: &[String]) {
    fs::create_dir_all("target/fcp-crypto-pq").expect("evidence artifact directory is writable");
    let mut jsonl = lines.join("\n");
    jsonl.push('\n');
    fs::write(ARTIFACT_PATH, jsonl).expect("evidence artifact writes");
}

#[test]
fn representation_profile_evidence_jsonl_is_secret_free() {
    let mut lines = Vec::new();
    for (name, params) in [
        ("SMALL_TEST", LatticeParams::SMALL_TEST),
        ("V4_REFERENCE", LatticeParams::V4_REFERENCE),
    ] {
        let evidence = evidence_for(name, params);
        assert_eq!(
            evidence.representation_version,
            LATTICE_REPRESENTATION_VERSION
        );
        assert!(
            evidence.redaction.master_trapdoor_debug_redacted,
            "master trapdoor debug must redact secret material"
        );
        assert!(
            evidence.redaction.zone_period_trapdoor_debug_redacted,
            "zone-period trapdoor debug must redact secret material"
        );
        assert!(
            evidence.redaction.preimage_debug_redacted,
            "preimage debug must redact signature material"
        );
        assert!(
            evidence
                .policy_bridge_compatibility
                .preimage_length_matches_profile,
            "policy bridge must consume the profile-derived preimage length"
        );

        let line = serde_json::to_string(&evidence).expect("evidence log serializes");
        assert!(
            !line.contains("/Users/") && !line.contains("/tmp/"),
            "evidence log must not expose local paths: {line}"
        );
        assert!(
            !line.contains("secret_material"),
            "evidence log must not include debug secret labels: {line}"
        );
        assert!(
            !line.contains("pool-material") && !line.contains("preimage_bytes"),
            "evidence log must not expose secret payload labels: {line}"
        );
        eprintln!("{line}");
        lines.push(line);
    }
    write_jsonl_artifact(&lines);
    assert!(
        fs::metadata(ARTIFACT_PATH)
            .expect("evidence artifact exists")
            .len()
            > 0,
        "evidence artifact must be non-empty"
    );
}
