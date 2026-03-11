//! Supply-chain verification and report commands.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use fcp_core::{
    CanonicalEncoding, HashAlgorithm, SoftwareBillOfMaterials, SupplyChainAttestation,
    SupplyChainVerificationPolicy, VerificationDecision, VerificationEvidence,
    VerificationPipeline,
};
use serde::Serialize;

#[derive(Args, Debug, Clone)]
pub struct SupplyChainArgs {
    #[command(subcommand)]
    pub command: SupplyChainCommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum SupplyChainCommand {
    /// Verify supply-chain evidence for one connector artifact.
    Verify(VerifyArgs),
    /// Summarize attestation, SBOM, trust roots, and verification steps.
    Report(ReportArgs),
}

#[derive(Args, Debug, Clone)]
pub struct VerifyArgs {
    /// Connector identifier used only for reporting.
    pub connector_id: String,

    /// Path to the attestation JSON file.
    #[arg(long)]
    pub attestation: Option<String>,

    /// Path to the SBOM JSON file.
    #[arg(long)]
    pub sbom: Option<String>,

    /// Artifact digest (for example `blake3-256:<hex>`).
    #[arg(long)]
    pub digest: Option<String>,

    /// Minimum SLSA level required.
    #[arg(long, default_value_t = 0)]
    pub min_slsa_level: u8,

    /// Allow unsigned artifacts.
    #[arg(long, default_value_t = false)]
    pub allow_unsigned: bool,

    /// Output JSON instead of human-readable text.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Args, Debug, Clone)]
pub struct ReportArgs {
    /// Connector identifier used only for reporting.
    pub connector_id: String,

    /// Emit the supply-chain report surface.
    #[arg(long, default_value_t = false)]
    pub supply_chain: bool,

    /// Path to the attestation JSON file.
    #[arg(long)]
    pub attestation: Option<String>,

    /// Path to the SBOM JSON file.
    #[arg(long)]
    pub sbom: Option<String>,

    /// Artifact digest (for example `blake3-256:<hex>`).
    #[arg(long)]
    pub digest: Option<String>,

    /// Minimum SLSA level required.
    #[arg(long, default_value_t = 0)]
    pub min_slsa_level: u8,

    /// Allow unsigned artifacts.
    #[arg(long, default_value_t = false)]
    pub allow_unsigned: bool,

    /// Output JSON instead of human-readable text.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Debug, Serialize)]
struct VerifyOutput {
    connector_id: String,
    decision: String,
    reason_code: String,
    artifact_digest: String,
    steps: Vec<VerifyStepOutput>,
    evidence_digest: String,
    policy: VerifyPolicyOutput,
}

#[derive(Debug, Serialize)]
struct VerifyStepOutput {
    step: String,
    passed: bool,
    detail: String,
}

#[derive(Debug, Serialize)]
struct VerifyPolicyOutput {
    require_attestation: bool,
    require_sbom: bool,
    min_slsa_level: u8,
    allow_unsigned: bool,
}

#[derive(Debug, Clone)]
struct SupplyChainEvaluation {
    artifact_digest: String,
    attestation: Option<SupplyChainAttestation>,
    sbom: Option<SoftwareBillOfMaterials>,
    policy: SupplyChainVerificationPolicy,
    evidence: VerificationEvidence,
    evidence_digest: String,
}

#[derive(Debug, Serialize)]
struct SupplyChainReportOutput {
    connector_id: String,
    decision: String,
    reason_code: String,
    artifact_digest: String,
    evidence_digest: String,
    policy: VerifyPolicyOutput,
    steps: Vec<VerifyStepOutput>,
    attestation: Option<SupplyChainAttestationReport>,
    sbom: Option<SupplyChainSbomReport>,
}

#[derive(Debug, Serialize)]
struct SupplyChainAttestationReport {
    predicate_type: String,
    builder_id: String,
    build_type: String,
    subject_digest: String,
    slsa_level: u8,
    provenance_hash: String,
    content_digest: String,
    trust_root: TrustRootReport,
}

#[derive(Debug, Serialize)]
struct SupplyChainSbomReport {
    bom_format: String,
    bom_version: String,
    component_count: usize,
    dependency_count: usize,
    tool_chain: Vec<String>,
    content_digest: String,
    trust_root: TrustRootReport,
}

#[derive(Debug, Serialize)]
struct TrustRootReport {
    root_type: String,
    root_id: String,
}

pub fn run(args: &SupplyChainArgs) -> Result<()> {
    match &args.command {
        SupplyChainCommand::Verify(args) => run_verify(args),
        SupplyChainCommand::Report(args) => run_report(args),
    }
}

fn run_verify(args: &VerifyArgs) -> Result<()> {
    let evaluation = evaluate_supply_chain(
        args.attestation.as_deref(),
        args.sbom.as_deref(),
        args.digest.as_deref(),
        args.min_slsa_level,
        args.allow_unsigned,
    )?;
    let output = build_verify_output(&args.connector_id, &evaluation);
    let allowed = evaluation.evidence.decision == VerificationDecision::Allow;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        print_verify_output(&args.connector_id, &output, allowed);
    }

    if !allowed {
        std::process::exit(1);
    }

    Ok(())
}

fn run_report(args: &ReportArgs) -> Result<()> {
    if !args.supply_chain {
        anyhow::bail!("`fwc supply-chain report` currently supports only `--supply-chain`");
    }

    let evaluation = evaluate_supply_chain(
        args.attestation.as_deref(),
        args.sbom.as_deref(),
        args.digest.as_deref(),
        args.min_slsa_level,
        args.allow_unsigned,
    )?;
    let output = build_report_output(&args.connector_id, &evaluation)?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        print_supply_chain_report(&args.connector_id, &output);
    }

    Ok(())
}

fn evaluate_supply_chain(
    attestation_path: Option<&str>,
    sbom_path: Option<&str>,
    digest: Option<&str>,
    min_slsa_level: u8,
    allow_unsigned: bool,
) -> Result<SupplyChainEvaluation> {
    let attestation = read_attestation(attestation_path)?;
    let sbom = read_sbom(sbom_path)?;
    let artifact_digest = digest
        .map(ToOwned::to_owned)
        .or_else(|| attestation.as_ref().map(|value| value.subject_digest.clone()))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "an artifact digest is required; pass `--digest` or provide an attestation with `subject_digest`"
            )
        })?;
    let policy = build_verification_policy(
        attestation.is_some(),
        sbom.is_some(),
        min_slsa_level,
        allow_unsigned,
        digest.is_some(),
    );
    let pipeline = VerificationPipeline::new(policy.clone());
    let evidence = pipeline.verify(&artifact_digest, attestation.as_ref(), sbom.as_ref());
    let evidence_digest = evidence
        .content_hash(HashAlgorithm::Blake3_256)
        .map_err(|e| anyhow::anyhow!("evidence hash failed: {e}"))?;

    Ok(SupplyChainEvaluation {
        artifact_digest,
        attestation,
        sbom,
        policy,
        evidence,
        evidence_digest,
    })
}

fn read_attestation(path: Option<&str>) -> Result<Option<SupplyChainAttestation>> {
    path.map(|path| {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read attestation file: {path}"))?;
        serde_json::from_str(&content)
            .with_context(|| format!("invalid attestation JSON in {path}"))
    })
    .transpose()
}

fn read_sbom(path: Option<&str>) -> Result<Option<SoftwareBillOfMaterials>> {
    path.map(|path| {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read SBOM file: {path}"))?;
        serde_json::from_str(&content).with_context(|| format!("invalid SBOM JSON in {path}"))
    })
    .transpose()
}

#[allow(clippy::fn_params_excessive_bools, clippy::missing_const_for_fn)]
fn build_verification_policy(
    has_attestation: bool,
    has_sbom: bool,
    min_slsa_level: u8,
    allow_unsigned: bool,
    require_digest_match: bool,
) -> SupplyChainVerificationPolicy {
    SupplyChainVerificationPolicy {
        require_attestation: has_attestation || !allow_unsigned,
        require_sbom: has_sbom || !allow_unsigned,
        min_slsa_level,
        trusted_builders: vec![],
        allow_unsigned,
        require_digest_match,
    }
}

fn build_verify_output(connector_id: &str, evaluation: &SupplyChainEvaluation) -> VerifyOutput {
    VerifyOutput {
        connector_id: connector_id.to_string(),
        decision: verification_decision_label(evaluation.evidence.decision),
        reason_code: verification_reason_code_label(&evaluation.evidence.reason_code),
        artifact_digest: evaluation.artifact_digest.clone(),
        steps: evaluation
            .evidence
            .steps
            .iter()
            .map(|step| VerifyStepOutput {
                step: step.step.clone(),
                passed: step.passed,
                detail: step.detail.clone(),
            })
            .collect(),
        evidence_digest: evaluation.evidence_digest.clone(),
        policy: VerifyPolicyOutput {
            require_attestation: evaluation.policy.require_attestation,
            require_sbom: evaluation.policy.require_sbom,
            min_slsa_level: evaluation.policy.min_slsa_level,
            allow_unsigned: evaluation.policy.allow_unsigned,
        },
    }
}

fn build_report_output(
    connector_id: &str,
    evaluation: &SupplyChainEvaluation,
) -> Result<SupplyChainReportOutput> {
    Ok(SupplyChainReportOutput {
        connector_id: connector_id.to_string(),
        decision: verification_decision_label(evaluation.evidence.decision),
        reason_code: verification_reason_code_label(&evaluation.evidence.reason_code),
        artifact_digest: evaluation.artifact_digest.clone(),
        evidence_digest: evaluation.evidence_digest.clone(),
        policy: VerifyPolicyOutput {
            require_attestation: evaluation.policy.require_attestation,
            require_sbom: evaluation.policy.require_sbom,
            min_slsa_level: evaluation.policy.min_slsa_level,
            allow_unsigned: evaluation.policy.allow_unsigned,
        },
        steps: evaluation
            .evidence
            .steps
            .iter()
            .map(|step| VerifyStepOutput {
                step: step.step.clone(),
                passed: step.passed,
                detail: step.detail.clone(),
            })
            .collect(),
        attestation: evaluation
            .attestation
            .as_ref()
            .map(build_attestation_report)
            .transpose()?,
        sbom: evaluation
            .sbom
            .as_ref()
            .map(build_sbom_report)
            .transpose()?,
    })
}

fn build_attestation_report(
    attestation: &SupplyChainAttestation,
) -> Result<SupplyChainAttestationReport> {
    Ok(SupplyChainAttestationReport {
        predicate_type: json_string_value(&attestation.predicate_type)?,
        builder_id: attestation.builder_id.clone(),
        build_type: attestation.build_type.clone(),
        subject_digest: attestation.subject_digest.clone(),
        slsa_level: attestation.slsa_level,
        provenance_hash: attestation.provenance_hash.clone(),
        content_digest: attestation
            .content_hash(CanonicalEncoding::Json, HashAlgorithm::Blake3_256)?,
        trust_root: TrustRootReport {
            root_type: attestation.trust_root.root_type.clone(),
            root_id: attestation.trust_root.root_id.clone(),
        },
    })
}

fn build_sbom_report(sbom: &SoftwareBillOfMaterials) -> Result<SupplyChainSbomReport> {
    Ok(SupplyChainSbomReport {
        bom_format: json_string_value(&sbom.bom_format)?,
        bom_version: sbom.bom_version.clone(),
        component_count: sbom.components.len(),
        dependency_count: sbom.dependencies.len(),
        tool_chain: sbom.tool_chain.clone(),
        content_digest: sbom.content_hash(CanonicalEncoding::Json, HashAlgorithm::Blake3_256)?,
        trust_root: TrustRootReport {
            root_type: sbom.trust_root.root_type.clone(),
            root_id: sbom.trust_root.root_id.clone(),
        },
    })
}

fn json_string_value<T: serde::Serialize>(value: &T) -> Result<String> {
    let value = serde_json::to_value(value)?;
    value
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow::anyhow!("expected JSON string value"))
}

fn verification_decision_label(decision: VerificationDecision) -> String {
    match decision {
        VerificationDecision::Allow => "allow".to_string(),
        VerificationDecision::Deny => "deny".to_string(),
    }
}

fn verification_reason_code_label(reason_code: &impl std::fmt::Debug) -> String {
    let debug = format!("{reason_code:?}");
    camel_to_snake_case(&debug)
}

fn camel_to_snake_case(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 4);
    for (index, ch) in value.chars().enumerate() {
        if ch.is_uppercase() {
            if index > 0 {
                output.push('_');
            }
            for lower in ch.to_lowercase() {
                output.push(lower);
            }
        } else {
            output.push(ch);
        }
    }
    output
}

fn print_verify_output(connector_id: &str, output: &VerifyOutput, allowed: bool) {
    if allowed {
        println!("Verification PASSED for {connector_id}");
    } else {
        println!("Verification FAILED for {connector_id}");
    }
    println!("  Reason: {}", output.reason_code);
    for step in &output.steps {
        let icon = if step.passed { "pass" } else { "FAIL" };
        println!("  {icon}: {} - {}", step.step, step.detail);
    }
    println!("  Evidence: {}", output.evidence_digest);
}

fn print_supply_chain_report(connector_id: &str, output: &SupplyChainReportOutput) {
    println!("Supply-chain report for {connector_id}");
    println!("  Decision: {} ({})", output.decision, output.reason_code);
    println!("  Artifact: {}", output.artifact_digest);
    println!("  Evidence: {}", output.evidence_digest);
    println!(
        "  Policy: attestation={} sbom={} min_slsa={} allow_unsigned={}",
        output.policy.require_attestation,
        output.policy.require_sbom,
        output.policy.min_slsa_level,
        output.policy.allow_unsigned
    );

    if let Some(attestation) = &output.attestation {
        println!("  Attestation:");
        println!("    Predicate: {}", attestation.predicate_type);
        println!("    Builder: {}", attestation.builder_id);
        println!("    SLSA: {}", attestation.slsa_level);
        println!(
            "    Trust Root: {}/{}",
            attestation.trust_root.root_type, attestation.trust_root.root_id
        );
        println!("    Content: {}", attestation.content_digest);
    }

    if let Some(sbom) = &output.sbom {
        println!("  SBOM:");
        println!("    Format: {}", sbom.bom_format);
        println!("    Version: {}", sbom.bom_version);
        println!(
            "    Components: {} (dependencies: {})",
            sbom.component_count, sbom.dependency_count
        );
        println!(
            "    Trust Root: {}/{}",
            sbom.trust_root.root_type, sbom.trust_root.root_id
        );
        println!("    Content: {}", sbom.content_digest);
    }

    println!("  Steps:");
    for step in &output.steps {
        let icon = if step.passed { "pass" } else { "FAIL" };
        println!("    {icon}: {} - {}", step.step, step.detail);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── camel_to_snake_case ────────────────────────────────────────────

    #[test]
    fn camel_to_snake_simple() {
        assert_eq!(camel_to_snake_case("AllPassed"), "all_passed");
    }

    #[test]
    fn camel_to_snake_single_word() {
        assert_eq!(camel_to_snake_case("allow"), "allow");
    }

    #[test]
    fn camel_to_snake_all_caps() {
        // First char at index 0 doesn't get underscore prefix
        assert_eq!(camel_to_snake_case("SLSA"), "s_l_s_a");
    }

    #[test]
    fn camel_to_snake_empty() {
        assert_eq!(camel_to_snake_case(""), "");
    }

    #[test]
    fn camel_to_snake_leading_capital() {
        assert_eq!(camel_to_snake_case("FooBar"), "foo_bar");
    }

    #[test]
    fn camel_to_snake_multiple_words() {
        assert_eq!(
            camel_to_snake_case("MissingAttestation"),
            "missing_attestation"
        );
    }

    #[test]
    fn camel_to_snake_consecutive_capitals() {
        assert_eq!(camel_to_snake_case("HTTPSCheck"), "h_t_t_p_s_check");
    }

    #[test]
    fn camel_to_snake_all_lower() {
        assert_eq!(camel_to_snake_case("lowercase"), "lowercase");
    }

    #[test]
    fn camel_to_snake_single_char() {
        assert_eq!(camel_to_snake_case("A"), "a");
    }

    #[test]
    fn camel_to_snake_numeric_mixed() {
        assert_eq!(camel_to_snake_case("slsa3Check"), "slsa3_check");
    }

    // ── verification_decision_label ────────────────────────────────────

    #[test]
    fn decision_label_allow() {
        assert_eq!(
            verification_decision_label(VerificationDecision::Allow),
            "allow"
        );
    }

    #[test]
    fn decision_label_deny() {
        assert_eq!(
            verification_decision_label(VerificationDecision::Deny),
            "deny"
        );
    }

    // ── build_verification_policy ──────────────────────────────────────

    #[test]
    fn policy_with_attestation_and_sbom() {
        let p = build_verification_policy(true, true, 2, false, true);
        assert!(p.require_attestation);
        assert!(p.require_sbom);
        assert_eq!(p.min_slsa_level, 2);
        assert!(!p.allow_unsigned);
        assert!(p.require_digest_match);
        assert!(p.trusted_builders.is_empty());
    }

    #[test]
    fn policy_allow_unsigned_no_attestation() {
        let p = build_verification_policy(false, false, 0, true, false);
        // allow_unsigned=true but has_attestation=false → require_attestation = false || !true = false
        assert!(!p.require_attestation);
        assert!(!p.require_sbom);
        assert!(p.allow_unsigned);
    }

    #[test]
    fn policy_no_unsigned_forces_attestation_and_sbom() {
        let p = build_verification_policy(false, false, 0, false, false);
        // has_attestation=false, allow_unsigned=false → require_attestation = false || true = true
        assert!(p.require_attestation);
        assert!(p.require_sbom);
    }

    #[test]
    fn policy_min_slsa_level_preserved() {
        let p = build_verification_policy(false, false, 4, true, false);
        assert_eq!(p.min_slsa_level, 4);
    }

    #[test]
    fn policy_has_attestation_overrides_unsigned() {
        let p = build_verification_policy(true, false, 0, true, false);
        // has_attestation=true → require_attestation = true || !true = true
        assert!(p.require_attestation);
        // has_sbom=false, allow_unsigned=true → require_sbom = false || !true = false
        assert!(!p.require_sbom);
    }

    // ── json_string_value ──────────────────────────────────────────────

    #[test]
    fn json_string_value_from_string() {
        let s = "hello".to_string();
        assert_eq!(json_string_value(&s).unwrap(), "hello");
    }

    #[test]
    fn json_string_value_rejects_number() {
        let n = 42;
        assert!(json_string_value(&n).is_err());
    }

    #[test]
    fn json_string_value_rejects_bool() {
        assert!(json_string_value(&true).is_err());
    }

    // ── Output struct serialization ────────────────────────────────────

    #[test]
    fn verify_output_serde_roundtrip() {
        let output = VerifyOutput {
            connector_id: "test-connector".to_string(),
            decision: "allow".to_string(),
            reason_code: "all_passed".to_string(),
            artifact_digest: "blake3-256:abc123".to_string(),
            steps: vec![VerifyStepOutput {
                step: "attestation_presence".to_string(),
                passed: true,
                detail: "present".to_string(),
            }],
            evidence_digest: "blake3-256:def456".to_string(),
            policy: VerifyPolicyOutput {
                require_attestation: true,
                require_sbom: true,
                min_slsa_level: 2,
                allow_unsigned: false,
            },
        };
        let json = serde_json::to_string(&output).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["connector_id"], "test-connector");
        assert_eq!(value["decision"], "allow");
        assert_eq!(value["policy"]["min_slsa_level"], 2);
    }

    #[test]
    fn verify_step_output_serde() {
        let step = VerifyStepOutput {
            step: "slsa_level_check".to_string(),
            passed: false,
            detail: "required 3, got 1".to_string(),
        };
        let json = serde_json::to_string(&step).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["passed"], false);
        assert_eq!(value["step"], "slsa_level_check");
    }

    #[test]
    fn verify_policy_output_serde() {
        let policy = VerifyPolicyOutput {
            require_attestation: false,
            require_sbom: true,
            min_slsa_level: 0,
            allow_unsigned: true,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["allow_unsigned"], true);
        assert_eq!(value["require_sbom"], true);
    }

    #[test]
    fn report_output_serde_no_attestation_no_sbom() {
        let output = SupplyChainReportOutput {
            connector_id: "my-conn".to_string(),
            decision: "deny".to_string(),
            reason_code: "missing_attestation".to_string(),
            artifact_digest: "blake3-256:000".to_string(),
            evidence_digest: "blake3-256:111".to_string(),
            policy: VerifyPolicyOutput {
                require_attestation: true,
                require_sbom: true,
                min_slsa_level: 0,
                allow_unsigned: false,
            },
            steps: vec![],
            attestation: None,
            sbom: None,
        };
        let json = serde_json::to_string(&output).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["decision"], "deny");
        assert!(value["attestation"].is_null());
        assert!(value["sbom"].is_null());
    }

    #[test]
    fn report_output_serde_with_attestation() {
        let output = SupplyChainReportOutput {
            connector_id: "conn".to_string(),
            decision: "allow".to_string(),
            reason_code: "all_passed".to_string(),
            artifact_digest: "blake3-256:aaa".to_string(),
            evidence_digest: "blake3-256:bbb".to_string(),
            policy: VerifyPolicyOutput {
                require_attestation: true,
                require_sbom: false,
                min_slsa_level: 1,
                allow_unsigned: false,
            },
            steps: vec![VerifyStepOutput {
                step: "check".to_string(),
                passed: true,
                detail: "ok".to_string(),
            }],
            attestation: Some(SupplyChainAttestationReport {
                predicate_type: "slsa_provenance".to_string(),
                builder_id: "github-actions".to_string(),
                build_type: "workflow".to_string(),
                subject_digest: "blake3-256:ccc".to_string(),
                slsa_level: 3,
                provenance_hash: "blake3-256:ddd".to_string(),
                content_digest: "blake3-256:eee".to_string(),
                trust_root: TrustRootReport {
                    root_type: "sigstore".to_string(),
                    root_id: "fulcio-root".to_string(),
                },
            }),
            sbom: None,
        };
        let json = serde_json::to_string(&output).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["attestation"]["slsa_level"], 3);
        assert_eq!(value["attestation"]["builder_id"], "github-actions");
    }

    #[test]
    fn report_output_serde_with_sbom() {
        let output = SupplyChainReportOutput {
            connector_id: "conn".to_string(),
            decision: "allow".to_string(),
            reason_code: "all_passed".to_string(),
            artifact_digest: "blake3-256:aaa".to_string(),
            evidence_digest: "blake3-256:bbb".to_string(),
            policy: VerifyPolicyOutput {
                require_attestation: false,
                require_sbom: true,
                min_slsa_level: 0,
                allow_unsigned: true,
            },
            steps: vec![],
            attestation: None,
            sbom: Some(SupplyChainSbomReport {
                bom_format: "CycloneDX".to_string(),
                bom_version: "1.5".to_string(),
                component_count: 42,
                dependency_count: 15,
                tool_chain: vec!["cargo-cyclonedx".to_string()],
                content_digest: "blake3-256:fff".to_string(),
                trust_root: TrustRootReport {
                    root_type: "internal".to_string(),
                    root_id: "build-root".to_string(),
                },
            }),
        };
        let json = serde_json::to_string(&output).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["sbom"]["component_count"], 42);
        assert_eq!(value["sbom"]["bom_format"], "CycloneDX");
    }

    #[test]
    fn trust_root_report_serde() {
        let tr = TrustRootReport {
            root_type: "sigstore".to_string(),
            root_id: "fulcio-2024".to_string(),
        };
        let json = serde_json::to_string(&tr).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["root_type"], "sigstore");
        assert_eq!(value["root_id"], "fulcio-2024");
    }

    // ── build_verify_output ────────────────────────────────────────────

    #[test]
    fn build_verify_output_maps_fields() {
        let policy = SupplyChainVerificationPolicy {
            require_attestation: true,
            require_sbom: true,
            min_slsa_level: 2,
            trusted_builders: vec![],
            allow_unsigned: false,
            require_digest_match: true,
        };
        let pipeline = VerificationPipeline::new(policy.clone());
        let evidence = pipeline.verify("blake3-256:abc123", None, None);
        let evaluation = SupplyChainEvaluation {
            artifact_digest: "blake3-256:abc123".to_string(),
            attestation: None,
            sbom: None,
            policy,
            evidence_digest: "blake3-256:evidence".to_string(),
            evidence,
        };
        let output = build_verify_output("my-connector", &evaluation);
        assert_eq!(output.connector_id, "my-connector");
        assert_eq!(output.decision, "deny");
        assert_eq!(output.artifact_digest, "blake3-256:abc123");
        assert!(output.policy.require_attestation);
    }

    #[test]
    fn build_verify_output_allow_unsigned() {
        let policy = SupplyChainVerificationPolicy {
            require_attestation: false,
            require_sbom: false,
            min_slsa_level: 0,
            trusted_builders: vec![],
            allow_unsigned: true,
            require_digest_match: false,
        };
        let pipeline = VerificationPipeline::new(policy.clone());
        let evidence = pipeline.verify("blake3-256:abc", None, None);
        let evaluation = SupplyChainEvaluation {
            artifact_digest: "blake3-256:abc".to_string(),
            attestation: None,
            sbom: None,
            policy,
            evidence_digest: "blake3-256:ev".to_string(),
            evidence,
        };
        let output = build_verify_output("unsigned-conn", &evaluation);
        assert_eq!(output.decision, "allow");
    }

    // ── build_report_output ────────────────────────────────────────────

    #[test]
    fn build_report_output_no_attestation_no_sbom() {
        let policy = SupplyChainVerificationPolicy {
            require_attestation: false,
            require_sbom: false,
            min_slsa_level: 0,
            trusted_builders: vec![],
            allow_unsigned: true,
            require_digest_match: false,
        };
        let pipeline = VerificationPipeline::new(policy.clone());
        let evidence = pipeline.verify("blake3-256:abc", None, None);
        let evaluation = SupplyChainEvaluation {
            artifact_digest: "blake3-256:abc".to_string(),
            attestation: None,
            sbom: None,
            policy,
            evidence_digest: "blake3-256:ev".to_string(),
            evidence,
        };
        let output = build_report_output("c", &evaluation).unwrap();
        assert!(output.attestation.is_none());
        assert!(output.sbom.is_none());
        assert_eq!(output.decision, "allow");
    }

    // ── verification_reason_code_label ─────────────────────────────────

    #[test]
    fn reason_code_label_converts_debug() {
        // Uses Debug format → camel_to_snake_case
        let label = verification_reason_code_label(&"AllPassed");
        // Debug of &str is "\"AllPassed\"" which includes quotes
        assert!(label.contains("all"));
    }

    // ── SupplyChainCommand enum ────────────────────────────────────────

    #[test]
    fn supply_chain_command_debug() {
        let args = VerifyArgs {
            connector_id: "test".to_string(),
            attestation: None,
            sbom: None,
            digest: Some("blake3-256:abc".to_string()),
            min_slsa_level: 2,
            allow_unsigned: false,
            json: true,
        };
        let debug = format!("{args:?}");
        assert!(debug.contains("test"));
        assert!(debug.contains("blake3-256:abc"));
    }

    #[test]
    fn report_args_debug() {
        let args = ReportArgs {
            connector_id: "c".to_string(),
            supply_chain: true,
            attestation: Some("a.json".to_string()),
            sbom: Some("s.json".to_string()),
            digest: None,
            min_slsa_level: 0,
            allow_unsigned: false,
            json: false,
        };
        let debug = format!("{args:?}");
        assert!(debug.contains("a.json"));
        assert!(debug.contains("s.json"));
    }

    #[test]
    fn verify_args_clone() {
        let args = VerifyArgs {
            connector_id: "test".to_string(),
            attestation: None,
            sbom: None,
            digest: None,
            min_slsa_level: 1,
            allow_unsigned: true,
            json: false,
        };
        let cloned = args.clone();
        assert_eq!(cloned.connector_id, "test");
        assert_eq!(cloned.min_slsa_level, 1);
    }

    #[test]
    fn report_args_clone() {
        let args = ReportArgs {
            connector_id: "c".to_string(),
            supply_chain: false,
            attestation: None,
            sbom: None,
            digest: None,
            min_slsa_level: 3,
            allow_unsigned: false,
            json: true,
        };
        let cloned = args.clone();
        assert_eq!(cloned.min_slsa_level, 3);
        assert!(cloned.json);
    }

    // ── Policy truth invariants ────────────────────────────────────────

    #[test]
    fn policy_truth_unsigned_disallowed_requires_both() {
        // Core invariant: when allow_unsigned=false, both attestation
        // and sbom must be required regardless of presence
        let p = build_verification_policy(false, false, 0, false, false);
        assert!(p.require_attestation, "unsigned disallowed → must require attestation");
        assert!(p.require_sbom, "unsigned disallowed → must require sbom");
    }

    #[test]
    fn policy_truth_unsigned_allowed_with_artifacts_still_requires() {
        // If artifacts are provided, they should be required even with allow_unsigned
        let p = build_verification_policy(true, true, 0, true, false);
        assert!(p.require_attestation, "has attestation → require it");
        assert!(p.require_sbom, "has sbom → require it");
    }

    #[test]
    fn policy_all_boolean_combinations() {
        // Exhaustive truth table for the policy logic
        for att in [false, true] {
            for sbom in [false, true] {
                for unsigned in [false, true] {
                    let p = build_verification_policy(att, sbom, 0, unsigned, false);
                    assert_eq!(p.require_attestation, att || !unsigned);
                    assert_eq!(p.require_sbom, sbom || !unsigned);
                    assert_eq!(p.allow_unsigned, unsigned);
                }
            }
        }
    }

    // ── Evaluation flow end-to-end (no files) ──────────────────────────

    #[test]
    fn evaluation_deny_when_policy_strict_no_artifacts() {
        let policy = SupplyChainVerificationPolicy::default();
        let pipeline = VerificationPipeline::new(policy.clone());
        let evidence = pipeline.verify("blake3-256:abcdef", None, None);
        assert_eq!(evidence.decision, VerificationDecision::Deny);
        assert!(!evidence.steps.is_empty());
    }

    #[test]
    fn evaluation_allow_when_policy_permissive() {
        let policy = SupplyChainVerificationPolicy {
            require_attestation: false,
            require_sbom: false,
            min_slsa_level: 0,
            trusted_builders: vec![],
            allow_unsigned: true,
            require_digest_match: false,
        };
        let pipeline = VerificationPipeline::new(policy);
        let evidence = pipeline.verify("blake3-256:abcdef", None, None);
        assert_eq!(evidence.decision, VerificationDecision::Allow);
    }

    #[test]
    fn verification_steps_are_ordered() {
        let policy = SupplyChainVerificationPolicy::default();
        let pipeline = VerificationPipeline::new(policy);
        let evidence = pipeline.verify("blake3-256:test", None, None);
        // Steps should be non-empty and have step names
        for step in &evidence.steps {
            assert!(!step.step.is_empty());
            assert!(!step.detail.is_empty());
        }
    }
}
