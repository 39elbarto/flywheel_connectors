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
