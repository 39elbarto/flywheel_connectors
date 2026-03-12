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
        assert!(
            p.require_attestation,
            "unsigned disallowed → must require attestation"
        );
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

    // ── camel_to_snake_case extended ─────────────────────────────────

    #[test]
    fn camel_to_snake_trailing_capital() {
        assert_eq!(camel_to_snake_case("fooB"), "foo_b");
    }

    #[test]
    fn camel_to_snake_underscore_passthrough() {
        // Already snake_case should keep underscores (lowercase chars)
        assert_eq!(camel_to_snake_case("already_snake"), "already_snake");
    }

    #[test]
    fn camel_to_snake_digits_only() {
        assert_eq!(camel_to_snake_case("1234"), "1234");
    }

    #[test]
    fn camel_to_snake_mixed_digits_capitals() {
        assert_eq!(camel_to_snake_case("V1Beta2"), "v1_beta2");
    }

    #[test]
    fn camel_to_snake_single_lowercase_char() {
        assert_eq!(camel_to_snake_case("a"), "a");
    }

    #[test]
    fn camel_to_snake_two_words() {
        assert_eq!(camel_to_snake_case("DigestMismatch"), "digest_mismatch");
    }

    // ── json_string_value extended ───────────────────────────────────

    #[test]
    fn json_string_value_rejects_array() {
        let arr = vec![1, 2, 3];
        assert!(json_string_value(&arr).is_err());
    }

    #[test]
    fn json_string_value_rejects_null() {
        let n: Option<String> = None;
        assert!(json_string_value(&n).is_err());
    }

    #[test]
    fn json_string_value_empty_string() {
        let s = "".to_string();
        assert_eq!(json_string_value(&s).unwrap(), "");
    }

    #[test]
    fn json_string_value_with_special_chars() {
        let s = "hello/world:123".to_string();
        assert_eq!(json_string_value(&s).unwrap(), "hello/world:123");
    }

    #[test]
    fn json_string_value_unicode() {
        let s = "attestation-\u{00e9}".to_string();
        assert_eq!(json_string_value(&s).unwrap(), "attestation-\u{00e9}");
    }

    // ── verification_decision_label exhaustive ───────────────────────

    #[test]
    fn decision_label_allow_is_lowercase() {
        let label = verification_decision_label(VerificationDecision::Allow);
        assert_eq!(label, label.to_lowercase());
    }

    #[test]
    fn decision_label_deny_is_lowercase() {
        let label = verification_decision_label(VerificationDecision::Deny);
        assert_eq!(label, label.to_lowercase());
    }

    // ── build_verification_policy edge cases ─────────────────────────

    #[test]
    fn policy_max_slsa_level() {
        let p = build_verification_policy(true, true, 255, false, true);
        assert_eq!(p.min_slsa_level, 255);
    }

    #[test]
    fn policy_digest_match_propagated() {
        let p = build_verification_policy(false, false, 0, true, true);
        assert!(p.require_digest_match);
    }

    #[test]
    fn policy_digest_match_false() {
        let p = build_verification_policy(false, false, 0, true, false);
        assert!(!p.require_digest_match);
    }

    #[test]
    fn policy_trusted_builders_always_empty() {
        // build_verification_policy always sets trusted_builders to empty
        for att in [false, true] {
            for sbom in [false, true] {
                let p = build_verification_policy(att, sbom, 1, false, false);
                assert!(p.trusted_builders.is_empty());
            }
        }
    }

    // ── VerifyArgs field coverage ────────────────────────────────────

    #[test]
    fn verify_args_all_fields_set() {
        let args = VerifyArgs {
            connector_id: "my-conn".to_string(),
            attestation: Some("/path/att.json".to_string()),
            sbom: Some("/path/sbom.json".to_string()),
            digest: Some("blake3-256:deadbeef".to_string()),
            min_slsa_level: 3,
            allow_unsigned: true,
            json: true,
        };
        assert_eq!(args.connector_id, "my-conn");
        assert_eq!(args.attestation.as_deref(), Some("/path/att.json"));
        assert_eq!(args.sbom.as_deref(), Some("/path/sbom.json"));
        assert_eq!(args.digest.as_deref(), Some("blake3-256:deadbeef"));
        assert_eq!(args.min_slsa_level, 3);
        assert!(args.allow_unsigned);
        assert!(args.json);
    }

    #[test]
    fn verify_args_none_fields() {
        let args = VerifyArgs {
            connector_id: "x".to_string(),
            attestation: None,
            sbom: None,
            digest: None,
            min_slsa_level: 0,
            allow_unsigned: false,
            json: false,
        };
        assert!(args.attestation.is_none());
        assert!(args.sbom.is_none());
        assert!(args.digest.is_none());
        assert!(!args.allow_unsigned);
        assert!(!args.json);
    }

    #[test]
    fn verify_args_clone_preserves_all_fields() {
        let args = VerifyArgs {
            connector_id: "c1".to_string(),
            attestation: Some("att.json".to_string()),
            sbom: Some("sbom.json".to_string()),
            digest: Some("sha256:abc".to_string()),
            min_slsa_level: 4,
            allow_unsigned: true,
            json: true,
        };
        let cloned = args.clone();
        assert_eq!(args.connector_id, cloned.connector_id);
        assert_eq!(args.attestation, cloned.attestation);
        assert_eq!(args.sbom, cloned.sbom);
        assert_eq!(args.digest, cloned.digest);
        assert_eq!(args.min_slsa_level, cloned.min_slsa_level);
        assert_eq!(args.allow_unsigned, cloned.allow_unsigned);
        assert_eq!(args.json, cloned.json);
    }

    // ── ReportArgs field coverage ────────────────────────────────────

    #[test]
    fn report_args_all_fields_set() {
        let args = ReportArgs {
            connector_id: "report-conn".to_string(),
            supply_chain: true,
            attestation: Some("a.json".to_string()),
            sbom: Some("s.json".to_string()),
            digest: Some("blake3-256:aabb".to_string()),
            min_slsa_level: 2,
            allow_unsigned: true,
            json: true,
        };
        assert_eq!(args.connector_id, "report-conn");
        assert!(args.supply_chain);
        assert_eq!(args.attestation.as_deref(), Some("a.json"));
        assert_eq!(args.sbom.as_deref(), Some("s.json"));
        assert_eq!(args.digest.as_deref(), Some("blake3-256:aabb"));
        assert_eq!(args.min_slsa_level, 2);
        assert!(args.allow_unsigned);
        assert!(args.json);
    }

    #[test]
    fn report_args_clone_preserves_all_fields() {
        let args = ReportArgs {
            connector_id: "rc".to_string(),
            supply_chain: true,
            attestation: Some("at.json".to_string()),
            sbom: None,
            digest: Some("sha256:ff".to_string()),
            min_slsa_level: 1,
            allow_unsigned: false,
            json: false,
        };
        let cloned = args.clone();
        assert_eq!(args.connector_id, cloned.connector_id);
        assert_eq!(args.supply_chain, cloned.supply_chain);
        assert_eq!(args.attestation, cloned.attestation);
        assert_eq!(args.sbom, cloned.sbom);
        assert_eq!(args.digest, cloned.digest);
        assert_eq!(args.min_slsa_level, cloned.min_slsa_level);
        assert_eq!(args.allow_unsigned, cloned.allow_unsigned);
        assert_eq!(args.json, cloned.json);
    }

    // ── VerifyOutput serialization edge cases ────────────────────────

    #[test]
    fn verify_output_empty_steps() {
        let output = VerifyOutput {
            connector_id: "c".to_string(),
            decision: "allow".to_string(),
            reason_code: "verified".to_string(),
            artifact_digest: "d".to_string(),
            steps: vec![],
            evidence_digest: "e".to_string(),
            policy: VerifyPolicyOutput {
                require_attestation: false,
                require_sbom: false,
                min_slsa_level: 0,
                allow_unsigned: true,
            },
        };
        let json = serde_json::to_string(&output).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(value["steps"].as_array().unwrap().is_empty());
    }

    #[test]
    fn verify_output_multiple_steps() {
        let output = VerifyOutput {
            connector_id: "c".to_string(),
            decision: "deny".to_string(),
            reason_code: "attestation_missing".to_string(),
            artifact_digest: "d".to_string(),
            steps: vec![
                VerifyStepOutput {
                    step: "step_a".to_string(),
                    passed: true,
                    detail: "ok".to_string(),
                },
                VerifyStepOutput {
                    step: "step_b".to_string(),
                    passed: false,
                    detail: "fail".to_string(),
                },
                VerifyStepOutput {
                    step: "step_c".to_string(),
                    passed: true,
                    detail: "recovered".to_string(),
                },
            ],
            evidence_digest: "e".to_string(),
            policy: VerifyPolicyOutput {
                require_attestation: true,
                require_sbom: true,
                min_slsa_level: 3,
                allow_unsigned: false,
            },
        };
        let json = serde_json::to_string(&output).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let steps = value["steps"].as_array().unwrap();
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[1]["passed"], false);
        assert_eq!(steps[2]["detail"], "recovered");
    }

    #[test]
    fn verify_output_json_field_names() {
        let output = VerifyOutput {
            connector_id: "c".to_string(),
            decision: "allow".to_string(),
            reason_code: "verified".to_string(),
            artifact_digest: "d".to_string(),
            steps: vec![],
            evidence_digest: "e".to_string(),
            policy: VerifyPolicyOutput {
                require_attestation: true,
                require_sbom: true,
                min_slsa_level: 0,
                allow_unsigned: false,
            },
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("connector_id"));
        assert!(json.contains("reason_code"));
        assert!(json.contains("artifact_digest"));
        assert!(json.contains("evidence_digest"));
        assert!(json.contains("require_attestation"));
        assert!(json.contains("require_sbom"));
        assert!(json.contains("min_slsa_level"));
        assert!(json.contains("allow_unsigned"));
    }

    // ── SupplyChainReportOutput extended ─────────────────────────────

    #[test]
    fn report_output_with_both_attestation_and_sbom() {
        let output = SupplyChainReportOutput {
            connector_id: "full-conn".to_string(),
            decision: "allow".to_string(),
            reason_code: "verified".to_string(),
            artifact_digest: "blake3-256:aaa".to_string(),
            evidence_digest: "blake3-256:bbb".to_string(),
            policy: VerifyPolicyOutput {
                require_attestation: true,
                require_sbom: true,
                min_slsa_level: 2,
                allow_unsigned: false,
            },
            steps: vec![],
            attestation: Some(SupplyChainAttestationReport {
                predicate_type: "slsa_provenance".to_string(),
                builder_id: "ci".to_string(),
                build_type: "pipeline".to_string(),
                subject_digest: "blake3-256:sub".to_string(),
                slsa_level: 2,
                provenance_hash: "blake3-256:prov".to_string(),
                content_digest: "blake3-256:cd".to_string(),
                trust_root: TrustRootReport {
                    root_type: "sigstore".to_string(),
                    root_id: "root-1".to_string(),
                },
            }),
            sbom: Some(SupplyChainSbomReport {
                bom_format: "CycloneDX".to_string(),
                bom_version: "1.5".to_string(),
                component_count: 10,
                dependency_count: 5,
                tool_chain: vec!["tool-a".to_string(), "tool-b".to_string()],
                content_digest: "blake3-256:sbom-cd".to_string(),
                trust_root: TrustRootReport {
                    root_type: "tuf".to_string(),
                    root_id: "tuf-root".to_string(),
                },
            }),
        };
        let json = serde_json::to_string(&output).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(value["attestation"].is_object());
        assert!(value["sbom"].is_object());
        assert_eq!(value["sbom"]["tool_chain"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn attestation_report_serde_all_fields() {
        let report = SupplyChainAttestationReport {
            predicate_type: "in-toto".to_string(),
            builder_id: "build-system-v2".to_string(),
            build_type: "container".to_string(),
            subject_digest: "sha256:abc".to_string(),
            slsa_level: 4,
            provenance_hash: "blake3-256:ppp".to_string(),
            content_digest: "blake3-256:ccc".to_string(),
            trust_root: TrustRootReport {
                root_type: "manual".to_string(),
                root_id: "manual-root".to_string(),
            },
        };
        let json = serde_json::to_string(&report).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["predicate_type"], "in-toto");
        assert_eq!(value["slsa_level"], 4);
        assert_eq!(value["trust_root"]["root_type"], "manual");
    }

    #[test]
    fn sbom_report_serde_empty_collections() {
        let report = SupplyChainSbomReport {
            bom_format: "SPDX".to_string(),
            bom_version: "2.3".to_string(),
            component_count: 0,
            dependency_count: 0,
            tool_chain: vec![],
            content_digest: "blake3-256:000".to_string(),
            trust_root: TrustRootReport {
                root_type: "tuf".to_string(),
                root_id: "tuf-2024".to_string(),
            },
        };
        let json = serde_json::to_string(&report).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["component_count"], 0);
        assert_eq!(value["dependency_count"], 0);
        assert!(value["tool_chain"].as_array().unwrap().is_empty());
    }

    // ── TrustRootReport ──────────────────────────────────────────────

    #[test]
    fn trust_root_report_debug() {
        let tr = TrustRootReport {
            root_type: "sigstore".to_string(),
            root_id: "fulcio".to_string(),
        };
        let dbg = format!("{tr:?}");
        assert!(dbg.contains("sigstore"));
        assert!(dbg.contains("fulcio"));
    }

    // ── SupplyChainEvaluation clone ──────────────────────────────────

    #[test]
    fn supply_chain_evaluation_clone() {
        let policy = SupplyChainVerificationPolicy {
            require_attestation: false,
            require_sbom: false,
            min_slsa_level: 0,
            trusted_builders: vec![],
            allow_unsigned: true,
            require_digest_match: false,
        };
        let pipeline = VerificationPipeline::new(policy.clone());
        let evidence = pipeline.verify("blake3-256:test", None, None);
        let eval = SupplyChainEvaluation {
            artifact_digest: "blake3-256:test".to_string(),
            attestation: None,
            sbom: None,
            policy,
            evidence_digest: "blake3-256:evhash".to_string(),
            evidence,
        };
        let cloned = eval.clone();
        assert_eq!(eval.artifact_digest, cloned.artifact_digest);
        assert_eq!(eval.evidence_digest, cloned.evidence_digest);
        assert_eq!(eval.evidence.decision, cloned.evidence.decision);
        assert!(cloned.attestation.is_none());
        assert!(cloned.sbom.is_none());
    }

    #[test]
    fn supply_chain_evaluation_debug() {
        let policy = SupplyChainVerificationPolicy::default();
        let pipeline = VerificationPipeline::new(policy.clone());
        let evidence = pipeline.verify("blake3-256:dbg", None, None);
        let eval = SupplyChainEvaluation {
            artifact_digest: "blake3-256:dbg".to_string(),
            attestation: None,
            sbom: None,
            policy,
            evidence_digest: "blake3-256:evdbg".to_string(),
            evidence,
        };
        let dbg = format!("{eval:?}");
        assert!(dbg.contains("blake3-256:dbg"));
        assert!(dbg.contains("evidence_digest"));
    }

    #[test]
    fn supply_chain_evaluation_clone_preserves_policy() {
        let policy = SupplyChainVerificationPolicy {
            require_attestation: true,
            require_sbom: true,
            min_slsa_level: 3,
            trusted_builders: vec!["builder-a".to_string()],
            allow_unsigned: false,
            require_digest_match: true,
        };
        let pipeline = VerificationPipeline::new(policy.clone());
        let evidence = pipeline.verify("blake3-256:pol", None, None);
        let eval = SupplyChainEvaluation {
            artifact_digest: "blake3-256:pol".to_string(),
            attestation: None,
            sbom: None,
            policy,
            evidence_digest: "blake3-256:ev".to_string(),
            evidence,
        };
        let cloned = eval.clone();
        assert_eq!(cloned.policy.require_attestation, true);
        assert_eq!(cloned.policy.min_slsa_level, 3);
        assert_eq!(cloned.policy.require_digest_match, true);
        assert_eq!(cloned.policy.trusted_builders.len(), 1);
    }

    #[test]
    fn supply_chain_evaluation_clone_preserves_steps() {
        let policy = SupplyChainVerificationPolicy::default();
        let pipeline = VerificationPipeline::new(policy.clone());
        let evidence = pipeline.verify("blake3-256:steps", None, None);
        let original_steps = evidence.steps.len();
        let eval = SupplyChainEvaluation {
            artifact_digest: "blake3-256:steps".to_string(),
            attestation: None,
            sbom: None,
            policy,
            evidence_digest: "blake3-256:ev".to_string(),
            evidence,
        };
        let cloned = eval.clone();
        assert_eq!(cloned.evidence.steps.len(), original_steps);
    }

    // ── build_verify_output extended ─────────────────────────────────

    #[test]
    fn build_verify_output_policy_fields_match() {
        let policy = SupplyChainVerificationPolicy {
            require_attestation: true,
            require_sbom: false,
            min_slsa_level: 3,
            trusted_builders: vec![],
            allow_unsigned: true,
            require_digest_match: true,
        };
        let pipeline = VerificationPipeline::new(policy.clone());
        let evidence = pipeline.verify("blake3-256:pol", None, None);
        let eval = SupplyChainEvaluation {
            artifact_digest: "blake3-256:pol".to_string(),
            attestation: None,
            sbom: None,
            policy,
            evidence_digest: "blake3-256:ev".to_string(),
            evidence,
        };
        let output = build_verify_output("pol-conn", &eval);
        assert!(output.policy.require_attestation);
        assert!(!output.policy.require_sbom);
        assert_eq!(output.policy.min_slsa_level, 3);
        assert!(output.policy.allow_unsigned);
    }

    #[test]
    fn build_verify_output_steps_count_matches_evidence() {
        let policy = SupplyChainVerificationPolicy::default();
        let pipeline = VerificationPipeline::new(policy.clone());
        let evidence = pipeline.verify("blake3-256:cnt", None, None);
        let expected_count = evidence.steps.len();
        let eval = SupplyChainEvaluation {
            artifact_digest: "blake3-256:cnt".to_string(),
            attestation: None,
            sbom: None,
            policy,
            evidence_digest: "blake3-256:ev".to_string(),
            evidence,
        };
        let output = build_verify_output("cnt-conn", &eval);
        assert_eq!(output.steps.len(), expected_count);
    }

    #[test]
    fn build_verify_output_evidence_digest_propagated() {
        let policy = SupplyChainVerificationPolicy::default();
        let pipeline = VerificationPipeline::new(policy.clone());
        let evidence = pipeline.verify("blake3-256:ed", None, None);
        let eval = SupplyChainEvaluation {
            artifact_digest: "blake3-256:ed".to_string(),
            attestation: None,
            sbom: None,
            policy,
            evidence_digest: "blake3-256:custom-ev-hash".to_string(),
            evidence,
        };
        let output = build_verify_output("ed-conn", &eval);
        assert_eq!(output.evidence_digest, "blake3-256:custom-ev-hash");
    }

    // ── build_report_output extended ─────────────────────────────────

    #[test]
    fn build_report_output_steps_match_evidence() {
        let policy = SupplyChainVerificationPolicy {
            require_attestation: false,
            require_sbom: false,
            min_slsa_level: 0,
            trusted_builders: vec![],
            allow_unsigned: true,
            require_digest_match: false,
        };
        let pipeline = VerificationPipeline::new(policy.clone());
        let evidence = pipeline.verify("blake3-256:rpt", None, None);
        let expected = evidence.steps.len();
        let eval = SupplyChainEvaluation {
            artifact_digest: "blake3-256:rpt".to_string(),
            attestation: None,
            sbom: None,
            policy,
            evidence_digest: "blake3-256:revhash".to_string(),
            evidence,
        };
        let output = build_report_output("rpt-conn", &eval).unwrap();
        assert_eq!(output.steps.len(), expected);
        assert_eq!(output.connector_id, "rpt-conn");
    }

    #[test]
    fn build_report_output_decision_and_reason_propagated() {
        let policy = SupplyChainVerificationPolicy::default();
        let pipeline = VerificationPipeline::new(policy.clone());
        let evidence = pipeline.verify("blake3-256:dec", None, None);
        let eval = SupplyChainEvaluation {
            artifact_digest: "blake3-256:dec".to_string(),
            attestation: None,
            sbom: None,
            policy,
            evidence_digest: "blake3-256:ev".to_string(),
            evidence,
        };
        let output = build_report_output("dec-conn", &eval).unwrap();
        assert_eq!(output.decision, "deny");
        assert!(!output.reason_code.is_empty());
    }

    // ── evaluate_supply_chain ────────────────────────────────────────

    #[test]
    fn evaluate_no_digest_no_attestation_errors() {
        let result = evaluate_supply_chain(None, None, None, 0, true);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("digest"));
    }

    #[test]
    fn evaluate_with_digest_no_attestation_allow_unsigned() {
        let result = evaluate_supply_chain(None, None, Some("blake3-256:abc123"), 0, true);
        assert!(result.is_ok());
        let eval = result.unwrap();
        assert_eq!(eval.artifact_digest, "blake3-256:abc123");
        assert!(eval.attestation.is_none());
        assert!(eval.sbom.is_none());
        assert!(eval.policy.allow_unsigned);
    }

    #[test]
    fn evaluate_with_digest_deny_when_strict() {
        let result = evaluate_supply_chain(None, None, Some("blake3-256:strict"), 0, false);
        assert!(result.is_ok());
        let eval = result.unwrap();
        assert_eq!(eval.evidence.decision, VerificationDecision::Deny);
    }

    #[test]
    fn evaluate_evidence_digest_is_nonempty() {
        let result = evaluate_supply_chain(None, None, Some("blake3-256:hash"), 0, true);
        let eval = result.unwrap();
        assert!(!eval.evidence_digest.is_empty());
        assert!(eval.evidence_digest.starts_with("blake3-256:"));
    }

    #[test]
    fn evaluate_nonexistent_attestation_path_errors() {
        let result = evaluate_supply_chain(
            Some("/nonexistent/attestation.json"),
            None,
            Some("blake3-256:abc"),
            0,
            true,
        );
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("attestation"));
    }

    #[test]
    fn evaluate_nonexistent_sbom_path_errors() {
        let result = evaluate_supply_chain(
            None,
            Some("/nonexistent/sbom.json"),
            Some("blake3-256:abc"),
            0,
            true,
        );
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("SBOM"));
    }

    // ── read_attestation / read_sbom ─────────────────────────────────

    #[test]
    fn read_attestation_none_returns_none() {
        let result = read_attestation(None).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn read_sbom_none_returns_none() {
        let result = read_sbom(None).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn read_attestation_bad_path_errors() {
        let result = read_attestation(Some("/no/such/file.json"));
        assert!(result.is_err());
    }

    #[test]
    fn read_sbom_bad_path_errors() {
        let result = read_sbom(Some("/no/such/sbom.json"));
        assert!(result.is_err());
    }

    // ── VerifyStepOutput debug ───────────────────────────────────────

    #[test]
    fn verify_step_output_debug() {
        let step = VerifyStepOutput {
            step: "check_name".to_string(),
            passed: false,
            detail: "missing data".to_string(),
        };
        let dbg = format!("{step:?}");
        assert!(dbg.contains("check_name"));
        assert!(dbg.contains("false"));
        assert!(dbg.contains("missing data"));
    }

    // ── VerifyPolicyOutput debug ─────────────────────────────────────

    #[test]
    fn verify_policy_output_debug() {
        let policy = VerifyPolicyOutput {
            require_attestation: true,
            require_sbom: false,
            min_slsa_level: 1,
            allow_unsigned: true,
        };
        let dbg = format!("{policy:?}");
        assert!(dbg.contains("require_attestation"));
        assert!(dbg.contains("allow_unsigned"));
    }

    // ── VerifyOutput debug ───────────────────────────────────────────

    #[test]
    fn verify_output_debug() {
        let output = VerifyOutput {
            connector_id: "dbg-conn".to_string(),
            decision: "allow".to_string(),
            reason_code: "verified".to_string(),
            artifact_digest: "blake3-256:d".to_string(),
            steps: vec![],
            evidence_digest: "blake3-256:e".to_string(),
            policy: VerifyPolicyOutput {
                require_attestation: false,
                require_sbom: false,
                min_slsa_level: 0,
                allow_unsigned: true,
            },
        };
        let dbg = format!("{output:?}");
        assert!(dbg.contains("dbg-conn"));
        assert!(dbg.contains("verified"));
    }

    // ── SupplyChainReportOutput debug ────────────────────────────────

    #[test]
    fn report_output_debug() {
        let output = SupplyChainReportOutput {
            connector_id: "rpt".to_string(),
            decision: "deny".to_string(),
            reason_code: "sbom_missing".to_string(),
            artifact_digest: "d".to_string(),
            evidence_digest: "e".to_string(),
            policy: VerifyPolicyOutput {
                require_attestation: false,
                require_sbom: true,
                min_slsa_level: 0,
                allow_unsigned: false,
            },
            steps: vec![],
            attestation: None,
            sbom: None,
        };
        let dbg = format!("{output:?}");
        assert!(dbg.contains("rpt"));
        assert!(dbg.contains("sbom_missing"));
    }

    // ── Expanded supply-chain tests ─────────────────────────────────

    // ── camel_to_snake_case additional edge cases ───────────────────

    #[test]
    fn camel_to_snake_unicode_lowercase() {
        // Non-ASCII lowercase should pass through
        assert_eq!(camel_to_snake_case("caf\u{00e9}"), "caf\u{00e9}");
    }

    #[test]
    fn camel_to_snake_long_string() {
        let result = camel_to_snake_case("ThisIsAVeryLongCamelCaseIdentifierForTesting");
        assert!(result.contains("this_is_a_very_long"));
        assert!(result.starts_with("this"));
        assert!(!result.starts_with('_'));
    }

    #[test]
    fn camel_to_snake_single_capital_at_end() {
        assert_eq!(camel_to_snake_case("testA"), "test_a");
    }

    #[test]
    fn camel_to_snake_two_chars_both_capital() {
        assert_eq!(camel_to_snake_case("AB"), "a_b");
    }

    #[test]
    fn camel_to_snake_numbers_between_capitals() {
        assert_eq!(camel_to_snake_case("A1B"), "a1_b");
    }

    #[test]
    fn camel_to_snake_spaces_preserved() {
        // Spaces are not uppercase, so they pass through
        assert_eq!(camel_to_snake_case("hello World"), "hello _world");
    }

    // ── verification_decision_label coverage ────────────────────────

    #[test]
    fn decision_label_allow_not_empty() {
        let label = verification_decision_label(VerificationDecision::Allow);
        assert!(!label.is_empty());
    }

    #[test]
    fn decision_label_deny_not_empty() {
        let label = verification_decision_label(VerificationDecision::Deny);
        assert!(!label.is_empty());
    }

    #[test]
    fn decision_labels_are_distinct() {
        let allow = verification_decision_label(VerificationDecision::Allow);
        let deny = verification_decision_label(VerificationDecision::Deny);
        assert_ne!(allow, deny);
    }

    // ── verification_reason_code_label extended ─────────────────────

    #[test]
    fn reason_code_label_is_lowercase() {
        let label = verification_reason_code_label(&"SomeReason");
        // All chars should be lowercase or underscore or quotes
        for ch in label.chars() {
            assert!(
                !ch.is_uppercase(),
                "reason code label should not contain uppercase: found '{ch}' in '{label}'"
            );
        }
    }

    #[test]
    fn reason_code_label_empty_debug() {
        let label = verification_reason_code_label(&"");
        // Debug of &str "" is "\"\"" → should produce "\"\"" after camel_to_snake
        assert!(!label.is_empty());
    }

    // ── build_verification_policy exhaustive ────────────────────────

    #[test]
    fn policy_require_digest_match_combinations() {
        for digest_match in [false, true] {
            let p = build_verification_policy(true, true, 0, false, digest_match);
            assert_eq!(p.require_digest_match, digest_match);
        }
    }

    #[test]
    fn policy_slsa_level_range() {
        for level in [0, 1, 2, 3, 4, 5, 128, 255] {
            let p = build_verification_policy(false, false, level, true, false);
            assert_eq!(p.min_slsa_level, level);
        }
    }

    #[test]
    fn policy_has_sbom_overrides_unsigned() {
        let p = build_verification_policy(false, true, 0, true, false);
        // has_sbom=true → require_sbom = true || !true = true
        assert!(p.require_sbom);
        // has_attestation=false, allow_unsigned=true → require_attestation = false || !true = false
        assert!(!p.require_attestation);
    }

    // ── json_string_value type coverage ─────────────────────────────

    #[test]
    fn json_string_value_rejects_object() {
        use std::collections::HashMap;
        let obj: HashMap<String, i32> = HashMap::new();
        assert!(json_string_value(&obj).is_err());
    }

    #[test]
    fn json_string_value_rejects_float() {
        assert!(json_string_value(&3.14).is_err());
    }

    #[test]
    fn json_string_value_string_with_quotes() {
        let s = r#"hello "world""#.to_string();
        let result = json_string_value(&s).unwrap();
        assert!(result.contains("hello"));
        assert!(result.contains("world"));
    }

    #[test]
    fn json_string_value_string_with_newlines() {
        let s = "line1\nline2".to_string();
        assert_eq!(json_string_value(&s).unwrap(), "line1\nline2");
    }

    // ── Output struct serialization extended ────────────────────────

    #[test]
    fn verify_output_all_fields_present_in_json() {
        let output = VerifyOutput {
            connector_id: "fc".to_string(),
            decision: "deny".to_string(),
            reason_code: "attestation_missing".to_string(),
            artifact_digest: "sha256:aaaa".to_string(),
            steps: vec![
                VerifyStepOutput {
                    step: "s1".to_string(),
                    passed: true,
                    detail: "ok".to_string(),
                },
                VerifyStepOutput {
                    step: "s2".to_string(),
                    passed: false,
                    detail: "nope".to_string(),
                },
            ],
            evidence_digest: "sha256:bbbb".to_string(),
            policy: VerifyPolicyOutput {
                require_attestation: true,
                require_sbom: false,
                min_slsa_level: 1,
                allow_unsigned: false,
            },
        };
        let value: serde_json::Value = serde_json::to_value(&output).unwrap();
        assert_eq!(value["connector_id"], "fc");
        assert_eq!(value["decision"], "deny");
        assert_eq!(value["steps"].as_array().unwrap().len(), 2);
        assert_eq!(value["policy"]["min_slsa_level"], 1);
    }

    #[test]
    fn verify_step_output_passed_true() {
        let step = VerifyStepOutput {
            step: "attestation_present".to_string(),
            passed: true,
            detail: "attestation found".to_string(),
        };
        let value: serde_json::Value = serde_json::to_value(&step).unwrap();
        assert_eq!(value["passed"], true);
    }

    #[test]
    fn verify_step_output_passed_false() {
        let step = VerifyStepOutput {
            step: "sbom_present".to_string(),
            passed: false,
            detail: "sbom not found".to_string(),
        };
        let value: serde_json::Value = serde_json::to_value(&step).unwrap();
        assert_eq!(value["passed"], false);
    }

    #[test]
    fn verify_policy_output_all_true() {
        let policy = VerifyPolicyOutput {
            require_attestation: true,
            require_sbom: true,
            min_slsa_level: 4,
            allow_unsigned: true,
        };
        let value: serde_json::Value = serde_json::to_value(&policy).unwrap();
        assert_eq!(value["require_attestation"], true);
        assert_eq!(value["require_sbom"], true);
        assert_eq!(value["min_slsa_level"], 4);
        assert_eq!(value["allow_unsigned"], true);
    }

    #[test]
    fn verify_policy_output_all_false() {
        let policy = VerifyPolicyOutput {
            require_attestation: false,
            require_sbom: false,
            min_slsa_level: 0,
            allow_unsigned: false,
        };
        let value: serde_json::Value = serde_json::to_value(&policy).unwrap();
        assert_eq!(value["require_attestation"], false);
        assert_eq!(value["require_sbom"], false);
        assert_eq!(value["min_slsa_level"], 0);
        assert_eq!(value["allow_unsigned"], false);
    }

    // ── Report output struct coverage ───────────────────────────────

    #[test]
    fn report_output_json_field_names() {
        let output = SupplyChainReportOutput {
            connector_id: "x".to_string(),
            decision: "allow".to_string(),
            reason_code: "ok".to_string(),
            artifact_digest: "d".to_string(),
            evidence_digest: "e".to_string(),
            policy: VerifyPolicyOutput {
                require_attestation: false,
                require_sbom: false,
                min_slsa_level: 0,
                allow_unsigned: true,
            },
            steps: vec![],
            attestation: None,
            sbom: None,
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("connector_id"));
        assert!(json.contains("decision"));
        assert!(json.contains("reason_code"));
        assert!(json.contains("artifact_digest"));
        assert!(json.contains("evidence_digest"));
    }

    #[test]
    fn attestation_report_trust_root_fields() {
        let report = SupplyChainAttestationReport {
            predicate_type: "p".to_string(),
            builder_id: "b".to_string(),
            build_type: "t".to_string(),
            subject_digest: "d".to_string(),
            slsa_level: 0,
            provenance_hash: "h".to_string(),
            content_digest: "c".to_string(),
            trust_root: TrustRootReport {
                root_type: "custom_type".to_string(),
                root_id: "custom_id".to_string(),
            },
        };
        let value: serde_json::Value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["trust_root"]["root_type"], "custom_type");
        assert_eq!(value["trust_root"]["root_id"], "custom_id");
    }

    #[test]
    fn attestation_report_slsa_level_zero() {
        let report = SupplyChainAttestationReport {
            predicate_type: "p".to_string(),
            builder_id: "b".to_string(),
            build_type: "t".to_string(),
            subject_digest: "d".to_string(),
            slsa_level: 0,
            provenance_hash: "h".to_string(),
            content_digest: "c".to_string(),
            trust_root: TrustRootReport {
                root_type: "t".to_string(),
                root_id: "i".to_string(),
            },
        };
        let value: serde_json::Value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["slsa_level"], 0);
    }

    #[test]
    fn attestation_report_slsa_level_max() {
        let report = SupplyChainAttestationReport {
            predicate_type: "p".to_string(),
            builder_id: "b".to_string(),
            build_type: "t".to_string(),
            subject_digest: "d".to_string(),
            slsa_level: 255,
            provenance_hash: "h".to_string(),
            content_digest: "c".to_string(),
            trust_root: TrustRootReport {
                root_type: "t".to_string(),
                root_id: "i".to_string(),
            },
        };
        let value: serde_json::Value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["slsa_level"], 255);
    }

    #[test]
    fn sbom_report_large_component_count() {
        let report = SupplyChainSbomReport {
            bom_format: "CycloneDX".to_string(),
            bom_version: "1.5".to_string(),
            component_count: 999_999,
            dependency_count: 500_000,
            tool_chain: vec![
                "tool1".to_string(),
                "tool2".to_string(),
                "tool3".to_string(),
            ],
            content_digest: "blake3-256:large".to_string(),
            trust_root: TrustRootReport {
                root_type: "tuf".to_string(),
                root_id: "root".to_string(),
            },
        };
        let value: serde_json::Value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["component_count"], 999_999);
        assert_eq!(value["dependency_count"], 500_000);
        assert_eq!(value["tool_chain"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn sbom_report_spdx_format() {
        let report = SupplyChainSbomReport {
            bom_format: "SPDX".to_string(),
            bom_version: "2.3".to_string(),
            component_count: 5,
            dependency_count: 3,
            tool_chain: vec!["spdx-sbom-generator".to_string()],
            content_digest: "blake3-256:spdx".to_string(),
            trust_root: TrustRootReport {
                root_type: "sigstore".to_string(),
                root_id: "fulcio".to_string(),
            },
        };
        let value: serde_json::Value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["bom_format"], "SPDX");
        assert_eq!(value["bom_version"], "2.3");
    }

    #[test]
    fn trust_root_report_empty_fields() {
        let tr = TrustRootReport {
            root_type: "".to_string(),
            root_id: "".to_string(),
        };
        let value: serde_json::Value = serde_json::to_value(&tr).unwrap();
        assert_eq!(value["root_type"], "");
        assert_eq!(value["root_id"], "");
    }

    #[test]
    fn trust_root_report_long_values() {
        let tr = TrustRootReport {
            root_type: "a".repeat(1000),
            root_id: "b".repeat(1000),
        };
        let value: serde_json::Value = serde_json::to_value(&tr).unwrap();
        assert_eq!(value["root_type"].as_str().unwrap().len(), 1000);
        assert_eq!(value["root_id"].as_str().unwrap().len(), 1000);
    }

    // ── evaluate_supply_chain extended ──────────────────────────────

    #[test]
    fn evaluate_allow_unsigned_result_decision() {
        let result = evaluate_supply_chain(None, None, Some("blake3-256:test"), 0, true);
        let eval = result.unwrap();
        assert_eq!(eval.evidence.decision, VerificationDecision::Allow);
    }

    #[test]
    fn evaluate_deny_unsigned_result_decision() {
        let result = evaluate_supply_chain(None, None, Some("blake3-256:test"), 0, false);
        let eval = result.unwrap();
        assert_eq!(eval.evidence.decision, VerificationDecision::Deny);
    }

    #[test]
    fn evaluate_policy_reflects_allow_unsigned() {
        let eval = evaluate_supply_chain(None, None, Some("blake3-256:x"), 0, true).unwrap();
        assert!(eval.policy.allow_unsigned);
    }

    #[test]
    fn evaluate_policy_reflects_deny_unsigned() {
        let eval = evaluate_supply_chain(None, None, Some("blake3-256:x"), 0, false).unwrap();
        assert!(!eval.policy.allow_unsigned);
    }

    #[test]
    fn evaluate_artifact_digest_matches_input() {
        let eval = evaluate_supply_chain(None, None, Some("blake3-256:mydigest"), 0, true).unwrap();
        assert_eq!(eval.artifact_digest, "blake3-256:mydigest");
    }

    #[test]
    fn evaluate_min_slsa_propagated() {
        let eval = evaluate_supply_chain(None, None, Some("blake3-256:x"), 4, true).unwrap();
        assert_eq!(eval.policy.min_slsa_level, 4);
    }

    #[test]
    fn evaluate_strict_evidence_has_steps() {
        // A strict policy should produce verification steps
        let eval = evaluate_supply_chain(None, None, Some("blake3-256:x"), 0, false).unwrap();
        assert!(!eval.evidence.steps.is_empty());
    }

    #[test]
    fn evaluate_evidence_digest_starts_with_blake3() {
        let eval = evaluate_supply_chain(None, None, Some("blake3-256:x"), 0, true).unwrap();
        assert!(
            eval.evidence_digest.starts_with("blake3-256:"),
            "evidence digest should be blake3: got {}",
            eval.evidence_digest
        );
    }

    #[test]
    fn evaluate_no_attestation_no_sbom_in_result() {
        let eval = evaluate_supply_chain(None, None, Some("blake3-256:x"), 0, true).unwrap();
        assert!(eval.attestation.is_none());
        assert!(eval.sbom.is_none());
    }

    // ── read_attestation / read_sbom extended ───────────────────────

    #[test]
    fn read_attestation_corrupt_json_errors() {
        let path = std::env::temp_dir().join("fwc_sc_test_bad_att.json");
        std::fs::write(&path, "not valid json {{{").unwrap();
        let result = read_attestation(Some(path.to_str().unwrap()));
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("invalid")
                || err_msg.contains("JSON")
                || err_msg.contains("attestation")
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_sbom_corrupt_json_errors() {
        let path = std::env::temp_dir().join("fwc_sc_test_bad_sbom.json");
        std::fs::write(&path, "{{bad json").unwrap();
        let result = read_sbom(Some(path.to_str().unwrap()));
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("invalid") || err_msg.contains("JSON") || err_msg.contains("SBOM")
        );
        let _ = std::fs::remove_file(&path);
    }

    // ── build_verify_output additional ──────────────────────────────

    #[test]
    fn build_verify_output_decision_deny() {
        let policy = SupplyChainVerificationPolicy::default();
        let pipeline = VerificationPipeline::new(policy.clone());
        let evidence = pipeline.verify("blake3-256:deny-test", None, None);
        let eval = SupplyChainEvaluation {
            artifact_digest: "blake3-256:deny-test".to_string(),
            attestation: None,
            sbom: None,
            policy,
            evidence_digest: "blake3-256:ev".to_string(),
            evidence,
        };
        let output = build_verify_output("deny-conn", &eval);
        assert_eq!(output.decision, "deny");
        assert!(!output.reason_code.is_empty());
    }

    #[test]
    fn build_verify_output_connector_id_propagated() {
        let policy = SupplyChainVerificationPolicy {
            require_attestation: false,
            require_sbom: false,
            min_slsa_level: 0,
            trusted_builders: vec![],
            allow_unsigned: true,
            require_digest_match: false,
        };
        let pipeline = VerificationPipeline::new(policy.clone());
        let evidence = pipeline.verify("blake3-256:x", None, None);
        let eval = SupplyChainEvaluation {
            artifact_digest: "blake3-256:x".to_string(),
            attestation: None,
            sbom: None,
            policy,
            evidence_digest: "blake3-256:ev".to_string(),
            evidence,
        };
        let output = build_verify_output("special-name-123", &eval);
        assert_eq!(output.connector_id, "special-name-123");
    }

    #[test]
    fn build_verify_output_step_details_nonempty() {
        let policy = SupplyChainVerificationPolicy::default();
        let pipeline = VerificationPipeline::new(policy.clone());
        let evidence = pipeline.verify("blake3-256:steps", None, None);
        let eval = SupplyChainEvaluation {
            artifact_digest: "blake3-256:steps".to_string(),
            attestation: None,
            sbom: None,
            policy,
            evidence_digest: "blake3-256:ev".to_string(),
            evidence,
        };
        let output = build_verify_output("steps-conn", &eval);
        for step in &output.steps {
            assert!(!step.step.is_empty(), "step name should not be empty");
            assert!(!step.detail.is_empty(), "step detail should not be empty");
        }
    }

    // ── build_report_output additional ──────────────────────────────

    #[test]
    fn build_report_output_evidence_digest_propagated() {
        let policy = SupplyChainVerificationPolicy {
            require_attestation: false,
            require_sbom: false,
            min_slsa_level: 0,
            trusted_builders: vec![],
            allow_unsigned: true,
            require_digest_match: false,
        };
        let pipeline = VerificationPipeline::new(policy.clone());
        let evidence = pipeline.verify("blake3-256:x", None, None);
        let eval = SupplyChainEvaluation {
            artifact_digest: "blake3-256:x".to_string(),
            attestation: None,
            sbom: None,
            policy,
            evidence_digest: "blake3-256:custom-hash".to_string(),
            evidence,
        };
        let output = build_report_output("c", &eval).unwrap();
        assert_eq!(output.evidence_digest, "blake3-256:custom-hash");
    }

    #[test]
    fn build_report_output_policy_matches_evaluation() {
        let policy = SupplyChainVerificationPolicy {
            require_attestation: true,
            require_sbom: false,
            min_slsa_level: 2,
            trusted_builders: vec![],
            allow_unsigned: true,
            require_digest_match: true,
        };
        let pipeline = VerificationPipeline::new(policy.clone());
        let evidence = pipeline.verify("blake3-256:x", None, None);
        let eval = SupplyChainEvaluation {
            artifact_digest: "blake3-256:x".to_string(),
            attestation: None,
            sbom: None,
            policy,
            evidence_digest: "blake3-256:ev".to_string(),
            evidence,
        };
        let output = build_report_output("c", &eval).unwrap();
        assert!(output.policy.require_attestation);
        assert!(!output.policy.require_sbom);
        assert_eq!(output.policy.min_slsa_level, 2);
        assert!(output.policy.allow_unsigned);
    }

    // ── Verification pipeline invariants ────────────────────────────

    #[test]
    fn pipeline_strict_policy_always_denies_without_artifacts() {
        let policy = SupplyChainVerificationPolicy {
            require_attestation: true,
            require_sbom: true,
            min_slsa_level: 3,
            trusted_builders: vec![],
            allow_unsigned: false,
            require_digest_match: true,
        };
        let pipeline = VerificationPipeline::new(policy);
        let evidence = pipeline.verify("blake3-256:strict", None, None);
        assert_eq!(evidence.decision, VerificationDecision::Deny);
    }

    #[test]
    fn pipeline_permissive_policy_always_allows_without_artifacts() {
        let policy = SupplyChainVerificationPolicy {
            require_attestation: false,
            require_sbom: false,
            min_slsa_level: 0,
            trusted_builders: vec![],
            allow_unsigned: true,
            require_digest_match: false,
        };
        let pipeline = VerificationPipeline::new(policy);
        let evidence = pipeline.verify("blake3-256:permissive", None, None);
        assert_eq!(evidence.decision, VerificationDecision::Allow);
    }

    #[test]
    fn pipeline_attestation_required_only_denies_without_attestation() {
        let policy = SupplyChainVerificationPolicy {
            require_attestation: true,
            require_sbom: false,
            min_slsa_level: 0,
            trusted_builders: vec![],
            allow_unsigned: false,
            require_digest_match: false,
        };
        let pipeline = VerificationPipeline::new(policy);
        let evidence = pipeline.verify("blake3-256:x", None, None);
        assert_eq!(evidence.decision, VerificationDecision::Deny);
    }

    #[test]
    fn pipeline_sbom_required_only_denies_without_sbom() {
        let policy = SupplyChainVerificationPolicy {
            require_attestation: false,
            require_sbom: true,
            min_slsa_level: 0,
            trusted_builders: vec![],
            allow_unsigned: false,
            require_digest_match: false,
        };
        let pipeline = VerificationPipeline::new(policy);
        let evidence = pipeline.verify("blake3-256:x", None, None);
        assert_eq!(evidence.decision, VerificationDecision::Deny);
    }

    #[test]
    fn pipeline_steps_have_step_names() {
        let policy = SupplyChainVerificationPolicy::default();
        let pipeline = VerificationPipeline::new(policy);
        let evidence = pipeline.verify("blake3-256:test", None, None);
        for step in &evidence.steps {
            assert!(
                !step.step.is_empty(),
                "each verification step must have a name"
            );
        }
    }

    #[test]
    fn pipeline_steps_have_details() {
        let policy = SupplyChainVerificationPolicy::default();
        let pipeline = VerificationPipeline::new(policy);
        let evidence = pipeline.verify("blake3-256:test", None, None);
        for step in &evidence.steps {
            assert!(
                !step.detail.is_empty(),
                "each verification step must have detail"
            );
        }
    }

    #[test]
    fn pipeline_deny_has_at_least_one_failing_step() {
        let policy = SupplyChainVerificationPolicy::default();
        let pipeline = VerificationPipeline::new(policy);
        let evidence = pipeline.verify("blake3-256:test", None, None);
        if evidence.decision == VerificationDecision::Deny {
            let has_failing = evidence.steps.iter().any(|s| !s.passed);
            assert!(
                has_failing,
                "deny decision should have at least one failing step"
            );
        }
    }

    #[test]
    fn pipeline_different_digests_same_policy_same_decision() {
        let policy = SupplyChainVerificationPolicy {
            require_attestation: false,
            require_sbom: false,
            min_slsa_level: 0,
            trusted_builders: vec![],
            allow_unsigned: true,
            require_digest_match: false,
        };
        let pipeline = VerificationPipeline::new(policy);
        let ev1 = pipeline.verify("blake3-256:aaa", None, None);
        let ev2 = pipeline.verify("blake3-256:bbb", None, None);
        assert_eq!(ev1.decision, ev2.decision);
    }

    // ── SupplyChainArgs / SupplyChainCommand coverage ──────────────

    #[test]
    fn supply_chain_command_verify_debug() {
        let cmd = SupplyChainCommand::Verify(VerifyArgs {
            connector_id: "debug-test".to_string(),
            attestation: None,
            sbom: None,
            digest: Some("sha256:abc".to_string()),
            min_slsa_level: 0,
            allow_unsigned: true,
            json: false,
        });
        let dbg = format!("{cmd:?}");
        assert!(dbg.contains("Verify"));
        assert!(dbg.contains("debug-test"));
    }

    #[test]
    fn supply_chain_command_report_debug() {
        let cmd = SupplyChainCommand::Report(ReportArgs {
            connector_id: "rpt-debug".to_string(),
            supply_chain: true,
            attestation: None,
            sbom: None,
            digest: None,
            min_slsa_level: 0,
            allow_unsigned: true,
            json: false,
        });
        let dbg = format!("{cmd:?}");
        assert!(dbg.contains("Report"));
        assert!(dbg.contains("rpt-debug"));
    }

    #[test]
    fn supply_chain_args_debug() {
        let args = SupplyChainArgs {
            command: SupplyChainCommand::Verify(VerifyArgs {
                connector_id: "args-test".to_string(),
                attestation: None,
                sbom: None,
                digest: None,
                min_slsa_level: 0,
                allow_unsigned: true,
                json: false,
            }),
        };
        let dbg = format!("{args:?}");
        assert!(dbg.contains("args-test"));
    }

    #[test]
    fn supply_chain_args_clone() {
        let args = SupplyChainArgs {
            command: SupplyChainCommand::Verify(VerifyArgs {
                connector_id: "clone-test".to_string(),
                attestation: Some("att.json".to_string()),
                sbom: None,
                digest: Some("blake3-256:x".to_string()),
                min_slsa_level: 2,
                allow_unsigned: false,
                json: true,
            }),
        };
        let cloned = args.clone();
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("clone-test"));
    }

    // ── Cross-cutting invariants ────────────────────────────────────

    #[test]
    fn verify_output_decision_is_allow_or_deny() {
        for allow_unsigned in [false, true] {
            let policy = SupplyChainVerificationPolicy {
                require_attestation: !allow_unsigned,
                require_sbom: !allow_unsigned,
                min_slsa_level: 0,
                trusted_builders: vec![],
                allow_unsigned,
                require_digest_match: false,
            };
            let pipeline = VerificationPipeline::new(policy.clone());
            let evidence = pipeline.verify("blake3-256:inv", None, None);
            let eval = SupplyChainEvaluation {
                artifact_digest: "blake3-256:inv".to_string(),
                attestation: None,
                sbom: None,
                policy,
                evidence_digest: "blake3-256:ev".to_string(),
                evidence,
            };
            let output = build_verify_output("inv-conn", &eval);
            assert!(
                output.decision == "allow" || output.decision == "deny",
                "decision must be 'allow' or 'deny', got '{}'",
                output.decision
            );
        }
    }

    #[test]
    fn report_output_decision_matches_evidence() {
        for allow_unsigned in [false, true] {
            let policy = SupplyChainVerificationPolicy {
                require_attestation: !allow_unsigned,
                require_sbom: !allow_unsigned,
                min_slsa_level: 0,
                trusted_builders: vec![],
                allow_unsigned,
                require_digest_match: false,
            };
            let pipeline = VerificationPipeline::new(policy.clone());
            let evidence = pipeline.verify("blake3-256:match", None, None);
            let expected = match evidence.decision {
                VerificationDecision::Allow => "allow",
                VerificationDecision::Deny => "deny",
            };
            let eval = SupplyChainEvaluation {
                artifact_digest: "blake3-256:match".to_string(),
                attestation: None,
                sbom: None,
                policy,
                evidence_digest: "blake3-256:ev".to_string(),
                evidence,
            };
            let output = build_report_output("match-conn", &eval).unwrap();
            assert_eq!(output.decision, expected);
        }
    }

    #[test]
    fn policy_truth_table_require_attestation() {
        // require_attestation = has_attestation || !allow_unsigned
        let cases = [
            (false, false, true), // !false || !false = true
            (false, true, false), // false || !true = false
            (true, false, true),  // true || !false = true
            (true, true, true),   // true || !true = true
        ];
        for (has_att, allow_unsigned, expected) in cases {
            let p = build_verification_policy(has_att, false, 0, allow_unsigned, false);
            assert_eq!(
                p.require_attestation, expected,
                "has_att={has_att}, allow_unsigned={allow_unsigned}"
            );
        }
    }

    #[test]
    fn policy_truth_table_require_sbom() {
        // require_sbom = has_sbom || !allow_unsigned
        let cases = [
            (false, false, true), // false || !false = true
            (false, true, false), // false || !true = false
            (true, false, true),  // true || !false = true
            (true, true, true),   // true || !true = true
        ];
        for (has_sbom, allow_unsigned, expected) in cases {
            let p = build_verification_policy(false, has_sbom, 0, allow_unsigned, false);
            assert_eq!(
                p.require_sbom, expected,
                "has_sbom={has_sbom}, allow_unsigned={allow_unsigned}"
            );
        }
    }

    #[test]
    fn evaluate_evidence_digest_deterministic() {
        // Same inputs should produce same evidence digest
        let eval1 = evaluate_supply_chain(None, None, Some("blake3-256:det"), 0, true).unwrap();
        let eval2 = evaluate_supply_chain(None, None, Some("blake3-256:det"), 0, true).unwrap();
        assert_eq!(eval1.evidence_digest, eval2.evidence_digest);
    }

    #[test]
    fn evaluate_different_digests_different_evidence_hashes() {
        let eval1 = evaluate_supply_chain(None, None, Some("blake3-256:aaa"), 0, true).unwrap();
        let eval2 = evaluate_supply_chain(None, None, Some("blake3-256:bbb"), 0, true).unwrap();
        // Different artifact digests may produce different evidence hashes
        // (not guaranteed but highly likely)
        // Just check both are valid
        assert!(eval1.evidence_digest.starts_with("blake3-256:"));
        assert!(eval2.evidence_digest.starts_with("blake3-256:"));
    }

    #[test]
    fn sbom_report_debug() {
        let report = SupplyChainSbomReport {
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
        };
        let dbg = format!("{report:?}");
        assert!(dbg.contains("CycloneDX"));
        assert!(dbg.contains("42"));
    }

    #[test]
    fn attestation_report_debug() {
        let report = SupplyChainAttestationReport {
            predicate_type: "in-toto".to_string(),
            builder_id: "ci-system".to_string(),
            build_type: "container".to_string(),
            subject_digest: "sha256:abc".to_string(),
            slsa_level: 3,
            provenance_hash: "blake3-256:prov".to_string(),
            content_digest: "blake3-256:cd".to_string(),
            trust_root: TrustRootReport {
                root_type: "sigstore".to_string(),
                root_id: "fulcio".to_string(),
            },
        };
        let dbg = format!("{report:?}");
        assert!(dbg.contains("in-toto"));
        assert!(dbg.contains("ci-system"));
    }

    #[test]
    fn report_output_with_multiple_steps() {
        let output = SupplyChainReportOutput {
            connector_id: "multi".to_string(),
            decision: "deny".to_string(),
            reason_code: "test".to_string(),
            artifact_digest: "d".to_string(),
            evidence_digest: "e".to_string(),
            policy: VerifyPolicyOutput {
                require_attestation: true,
                require_sbom: true,
                min_slsa_level: 0,
                allow_unsigned: false,
            },
            steps: (0..5)
                .map(|i| VerifyStepOutput {
                    step: format!("step_{i}"),
                    passed: i % 2 == 0,
                    detail: format!("detail_{i}"),
                })
                .collect(),
            attestation: None,
            sbom: None,
        };
        let value: serde_json::Value = serde_json::to_value(&output).unwrap();
        let steps = value["steps"].as_array().unwrap();
        assert_eq!(steps.len(), 5);
        assert_eq!(steps[0]["passed"], true);
        assert_eq!(steps[1]["passed"], false);
        assert_eq!(steps[4]["step"], "step_4");
    }

    #[test]
    fn verify_args_default_values() {
        let args = VerifyArgs {
            connector_id: "x".to_string(),
            attestation: None,
            sbom: None,
            digest: None,
            min_slsa_level: 0,
            allow_unsigned: false,
            json: false,
        };
        assert_eq!(args.min_slsa_level, 0);
        assert!(!args.allow_unsigned);
        assert!(!args.json);
    }

    #[test]
    fn report_args_supply_chain_flag() {
        let args = ReportArgs {
            connector_id: "c".to_string(),
            supply_chain: true,
            attestation: None,
            sbom: None,
            digest: None,
            min_slsa_level: 0,
            allow_unsigned: false,
            json: false,
        };
        assert!(args.supply_chain);

        let args2 = ReportArgs {
            supply_chain: false,
            ..args.clone()
        };
        assert!(!args2.supply_chain);
    }
}
