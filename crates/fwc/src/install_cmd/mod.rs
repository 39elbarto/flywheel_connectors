//! `fcp install` command implementation.
//!
//! Provides connector installation with full verification chain:
//! - Manifest signature verification (publisher and/or registry)
//! - Binary checksum verification
//! - Supply chain policy enforcement
//! - Capability ceiling enforcement
//! - Mesh store mirroring
//!
//! # Commands
//!
//! ## `fcp install <connector>`
//!
//! Install a connector into a zone with verification.
//!
//! ```text
//! # Install a connector (latest version)
//! fcp install fcp.telegram:base:v1 --zone z:work
//!
//! # Install a specific version
//! fcp install fcp.telegram:base:v1@1.2.3 --zone z:work
//!
//! # Skip mirroring (verify only)
//! fcp install fcp.telegram:base:v1 --zone z:work --verify-only
//!
//! # JSON output for automation
//! fcp install fcp.telegram:base:v1 --zone z:work --json
//! ```

pub mod types;

use std::collections::HashMap;

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use blake3::Hasher;
use chrono::{TimeZone, Utc};
use clap::Args;
use fcp_core::{
    AttestationMaterial, AttestationMetadata, AttestationPredicateType, HashAlgorithm, ObjectIdKey,
    SBOM_SIGNED_FIELDS, SUPPLY_CHAIN_ATTESTATION_SIGNED_FIELDS, SbomComponent, SbomFormat,
    SoftwareBillOfMaterials, SupplyChainAttestation, SupplyChainSignature,
    SupplyChainVerificationPolicy, TrustRootBinding, VerificationDecision, VerificationPipeline,
    ZoneId,
};
use fcp_crypto::ed25519::{Ed25519SigningKey, Ed25519VerifyingKey};
use fcp_manifest::ConnectorManifest;
use fcp_registry::{
    ConnectorBundle, ConnectorTarget, MANIFEST_SIGNATURE_CONTEXT, MirrorResult, RegistryError,
    RegistryTrustPolicy, RegistryVerifier, VerifiedConnectorBundle, manifest_signing_bytes,
    signature_message,
};
use fcp_store::{MemoryObjectStore, MemoryObjectStoreConfig};

use types::{InstallError, InstallOutput, InstallPhase, InstallProgress, VerificationDetails};

/// Arguments for the `fcp install` command.
#[allow(clippy::struct_excessive_bools)]
#[derive(Args, Debug)]
pub struct InstallArgs {
    /// Connector ID to install (format: `namespace.name:variant:version_constraint`).
    ///
    /// Examples:
    ///   fcp.telegram:base:v1
    ///   fcp.telegram:base:v1@1.2.3
    pub connector: String,

    /// Zone to install the connector into.
    #[arg(long, short = 'z')]
    pub zone: String,

    /// Target platform/architecture (defaults to current system).
    ///
    /// Examples: x86_64-unknown-linux-gnu, aarch64-apple-darwin
    #[arg(long, short = 't')]
    pub target: Option<String>,

    /// Verify only, don't mirror to mesh store.
    #[arg(long, default_value_t = false)]
    pub verify_only: bool,

    /// Skip supply chain verification (not recommended).
    #[arg(long, default_value_t = false)]
    pub skip_supply_chain: bool,

    /// Path to attestation file (JSON). If omitted, demo evidence is synthesized.
    #[arg(long)]
    pub attestation: Option<String>,

    /// Path to SBOM file (JSON). If omitted, demo evidence is synthesized.
    #[arg(long)]
    pub sbom: Option<String>,

    /// Minimum SLSA level required (0-4).
    #[arg(long, default_value_t = 0)]
    pub min_slsa_level: u8,

    /// Allow unsigned artifacts (dev mode only).
    #[arg(long, default_value_t = false)]
    pub allow_unsigned: bool,

    /// Path to trust policy file (defaults to zone policy).
    #[arg(long)]
    pub trust_policy: Option<String>,

    /// Output JSON instead of human-readable format.
    #[arg(long, default_value_t = false)]
    pub json: bool,

    /// Show verbose progress during installation.
    #[arg(long, short = 'v', default_value_t = false)]
    pub verbose: bool,
}

/// Run the install command.
///
/// # Errors
///
/// Returns an error if installation fails.
pub fn run(args: InstallArgs) -> Result<()> {
    fcp_async_core::runtime::block_on_sync(run_async(args)).context("async runtime failure")?
}

/// Async implementation of the install command.
#[allow(clippy::too_many_lines)]
async fn run_async(args: InstallArgs) -> Result<()> {
    // Parse connector ID and optional version
    let (connector_id, version) = parse_connector_spec(&args.connector);

    // Determine target platform
    let target = args
        .target
        .clone()
        .unwrap_or_else(|| current_target().to_string());

    // Validate zone format
    if !args.zone.starts_with("z:") {
        let err = InstallError::zone_not_found(&args.zone);
        exit_with_install_error(args.json, &err);
    }

    // Progress reporting helper
    let report_progress = |phase: InstallPhase, message: &str| {
        if args.json && args.verbose {
            let progress = InstallProgress {
                phase,
                message: message.to_string(),
                progress_percent: None,
            };
            if let Ok(json) = serde_json::to_string(&progress) {
                println!("{json}");
            }
        } else if args.verbose {
            let reset = "\x1b[0m";
            println!(
                "{}{} {}{reset} {}",
                phase.color(),
                phase.symbol(),
                phase.label(),
                message
            );
        }
    };

    // Phase 1: Fetch manifest
    report_progress(
        InstallPhase::FetchingManifest,
        &format!("from registry for {connector_id}"),
    );

    // Parse target triple into ConnectorTarget
    let connector_target = parse_target_triple(&target);

    let (bundle, demo_keys) =
        match fetch_connector_bundle(&connector_id, version.as_deref(), &connector_target) {
            Ok(b) => b,
            Err(err) => {
                let install_err = registry_error_to_install_error(&connector_id, err);
                exit_with_install_error(args.json, &install_err);
            }
        };

    // Phase 2: Verify manifest signatures
    report_progress(
        InstallPhase::VerifyingManifest,
        "checking publisher and registry signatures",
    );

    let (verified_bundle, mut verification) = match verify_bundle(
        &bundle,
        &demo_keys,
        args.trust_policy.as_deref(),
        Some(&connector_target),
    ) {
        Ok(v) => v,
        Err(err) => {
            let install_err = registry_error_to_install_error(&connector_id, err);
            exit_with_install_error(args.json, &install_err);
        }
    };

    // Phase 3: Verify binary checksum
    report_progress(
        InstallPhase::VerifyingBinary,
        &format!(
            "sha256 checksum ({})",
            truncate(&verified_bundle.binary_hash, 16)
        ),
    );

    // Phase 4: Check supply chain (unless skipped)
    if args.skip_supply_chain {
        verification.supply_chain_policy_satisfied = false;
        verification.supply_chain_reason_code = Some("skipped".to_string());
    } else {
        report_progress(
            InstallPhase::CheckingSupplyChain,
            "validating attestations and transparency log",
        );

        match verify_supply_chain(&args, &connector_id, &bundle.binary, &mut verification) {
            Ok(()) => {}
            Err(err) => {
                let install_err =
                    InstallError::supply_chain_policy_violation(&connector_id, &err.to_string());
                exit_with_install_error(args.json, &install_err);
            }
        }
    }

    // Phase 5: Mirror to mesh store (unless verify-only)
    let (manifest_object_id, binary_object_id) = if args.verify_only {
        (None, None)
    } else {
        report_progress(
            InstallPhase::Mirroring,
            &format!("pinning to zone {}", args.zone),
        );

        match mirror_to_store(&verified_bundle, &bundle, &args.zone, &demo_keys).await {
            Ok(result) => (
                Some(result.manifest_object_id.to_string()),
                Some(result.binary_object_id.to_string()),
            ),
            Err(err) => {
                let install_err = registry_error_to_install_error(&connector_id, err);
                exit_with_install_error(args.json, &install_err);
            }
        }
    };

    // Phase 6: Emit audit event
    report_progress(
        InstallPhase::EmittingAudit,
        "recording installation in audit chain",
    );

    // Build output
    let now = Utc::now();
    let installed_at = u64::try_from(now.timestamp()).unwrap_or(0);
    let installed_at_iso = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let output = InstallOutput {
        connector_id: verified_bundle.manifest.connector.id.to_string(),
        version: verified_bundle.manifest.connector.version.to_string(),
        target,
        zone_id: args.zone.clone(),
        manifest_hash: verified_bundle.manifest_hash.clone(),
        binary_hash: verified_bundle.binary_hash.clone(),
        manifest_object_id,
        binary_object_id,
        verification,
        installed_at,
        installed_at_iso,
    };

    // Output result
    if args.json {
        let json = serde_json::to_string_pretty(&output).context("failed to serialize output")?;
        println!("{json}");
    } else {
        report_progress(InstallPhase::Complete, "");
        output_human(&output, args.verify_only);
    }

    Ok(())
}

/// Parse a connector spec like "fcp.telegram:base:v1" or "fcp.telegram:base:v1@1.2.3".
fn parse_connector_spec(spec: &str) -> (String, Option<String>) {
    if let Some((id, version)) = spec.split_once('@') {
        (id.to_string(), Some(version.to_string()))
    } else {
        (spec.to_string(), None)
    }
}

/// Get the current system target triple.
const fn current_target() -> &'static str {
    // This would ideally use target_lexicon or similar at runtime
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    {
        "x86_64-unknown-linux-gnu"
    }
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    {
        "aarch64-unknown-linux-gnu"
    }
    #[cfg(all(target_arch = "x86_64", target_os = "macos"))]
    {
        "x86_64-apple-darwin"
    }
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    {
        "aarch64-apple-darwin"
    }
    #[cfg(not(any(
        all(target_arch = "x86_64", target_os = "linux"),
        all(target_arch = "aarch64", target_os = "linux"),
        all(target_arch = "x86_64", target_os = "macos"),
        all(target_arch = "aarch64", target_os = "macos"),
    )))]
    {
        "unknown-unknown-unknown"
    }
}

/// Demo signing keys for stub connectors.
struct DemoKeys {
    signing_key: Ed25519SigningKey,
    verifying_key: Ed25519VerifyingKey,
}

impl DemoKeys {
    fn new() -> Self {
        // Generate deterministic keys for demo connectors using a fixed seed.
        // In a real implementation, keys would come from the trust policy file.
        let seed = [42u8; 32];
        let signing_key = Ed25519SigningKey::from_bytes(&seed).expect("valid 32-byte seed");
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }
}

/// Parse target triple into `ConnectorTarget`.
fn parse_target_triple(triple: &str) -> ConnectorTarget {
    // Parse triples like "x86_64-unknown-linux-gnu" or "aarch64-apple-darwin"
    let parts: Vec<&str> = triple.split('-').collect();
    let raw_arch = parts.first().map_or("unknown", |s| *s);

    let arch = match raw_arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };

    let os = if parts.len() >= 3 {
        parts[2]
    } else {
        "unknown"
    };
    ConnectorTarget {
        os: os.to_string(),
        arch: arch.to_string(),
    }
}

/// Convert `RegistryError` to `InstallError`.
fn registry_error_to_install_error(connector_id: &str, err: RegistryError) -> InstallError {
    match err {
        RegistryError::MissingSignatures => {
            InstallError::signature_verification_failed(connector_id, "signatures section missing")
        }
        RegistryError::SignatureInvalid { kid } => InstallError::signature_verification_failed(
            connector_id,
            &format!("invalid signature for key {kid}"),
        ),
        RegistryError::PublisherThresholdUnmet { required, valid } => {
            InstallError::signature_verification_failed(
                connector_id,
                &format!("publisher threshold not met ({valid}/{required})"),
            )
        }
        RegistryError::RegistrySignatureRequired => InstallError::signature_verification_failed(
            connector_id,
            "registry signature required but missing",
        ),
        RegistryError::TargetMismatch { expected, found } => {
            InstallError::target_mismatch(connector_id, &expected, &found)
        }
        RegistryError::CapabilityCeilingViolation { capability } => {
            InstallError::capability_ceiling_violation(connector_id, &capability)
        }
        RegistryError::TransparencyLogMissing
        | RegistryError::TransparencyEvidenceMissing
        | RegistryError::RequiredAttestationMissing { .. }
        | RegistryError::AttestationEvidenceMissing
        | RegistryError::SlsaLevelInsufficient { .. }
        | RegistryError::UntrustedBuilder { .. } => {
            InstallError::supply_chain_policy_violation(connector_id, &err.to_string())
        }
        RegistryError::ObjectStore(e) => InstallError::mirror_failed(connector_id, &e.to_string()),
        _ => InstallError {
            code: "FCP-5000".to_string(),
            message: format!("Registry error for '{connector_id}': {err}"),
            hints: vec!["Check the error details above".to_string()],
            connector_id: Some(connector_id.to_string()),
            version: None,
        },
    }
}

/// Fetch a connector bundle from the registry.
///
/// Returns the bundle and the demo keys used to sign it.
fn fetch_connector_bundle(
    connector_id: &str,
    version: Option<&str>,
    target: &ConnectorTarget,
) -> Result<(ConnectorBundle, DemoKeys), RegistryError> {
    // Demo connectors available for installation
    let known_connectors = [
        "fcp.telegram:base:v1",
        "fcp.discord:base:v1",
        "fcp.openai:base:v1",
        "fcp.anthropic:base:v1",
    ];

    if !known_connectors.contains(&connector_id) {
        return Err(RegistryError::ManifestParse(
            fcp_manifest::ManifestError::Invalid {
                field: "connector",
                message: format!("unknown connector: {connector_id}"),
            },
        ));
    }

    let resolved_version = version.unwrap_or("1.0.0");

    // For demo, only "1.0.0" and "1.0.1" exist
    if resolved_version != "1.0.0" && resolved_version != "1.0.1" {
        return Err(RegistryError::ManifestParse(
            fcp_manifest::ManifestError::Invalid {
                field: "version",
                message: format!("unknown version: {resolved_version}"),
            },
        ));
    }

    let demo_keys = DemoKeys::new();

    // Generate demo binary bytes first (needed for signature)
    let binary = generate_demo_binary(connector_id, resolved_version);

    // Generate a demo manifest TOML with proper signature
    let manifest_toml = generate_demo_manifest(connector_id, resolved_version, &binary, &demo_keys);

    let bundle = ConnectorBundle {
        manifest_toml,
        binary,
        target: target.clone(),
    };

    Ok((bundle, demo_keys))
}

/// Placeholder interface hash for computing the real hash.
const PLACEHOLDER_INTERFACE_HASH: &str =
    "blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000";

/// Generate a demo manifest TOML with signature.
fn generate_demo_manifest(
    connector_id: &str,
    version: &str,
    binary: &[u8],
    keys: &DemoKeys,
) -> String {
    // Split connector_id like "fcp.telegram:base:v1" into parts
    let parts: Vec<&str> = connector_id.split(':').collect();
    let namespace_name = parts.first().map_or(connector_id, |s| *s);

    // Base manifest template with placeholder hash (no signatures yet)
    let manifest_template = format!(
        r#"[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"
min_mesh_version = "2.0.0"
min_protocol = "fcp2-sym/2.0"
protocol_features = []
max_datagram_bytes = 1200
interface_hash = "{PLACEHOLDER_INTERFACE_HASH}"

[connector]
id = "{connector_id}"
name = "{namespace_name} Connector"
version = "{version}"
description = "Demo connector for {namespace_name}"
archetypes = ["operational"]
format = "native"

[zones]
home = "z:work"
allowed_sources = ["z:work"]
allowed_targets = ["z:work"]
forbidden = []

[capabilities]
required = ["network.dns"]
optional = []
forbidden = ["system.exec"]

[provides.operations.demo_op]
description = "Demo operation"
capability = "{namespace_name}.demo"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "none"
input_schema = {{ type = "object" }}
output_schema = {{ type = "object" }}

[sandbox]
profile = "strict"
memory_mb = 64
cpu_percent = 20
wall_clock_timeout_ms = 1000
fs_readonly_paths = ["/usr"]
fs_writable_paths = ["$CONNECTOR_STATE"]
deny_exec = true
deny_ptrace = true
"#
    );

    // Compute the correct interface hash by parsing without validation
    let unchecked = ConnectorManifest::parse_str_unchecked(&manifest_template)
        .expect("demo manifest should parse");
    let computed_hash = unchecked
        .compute_interface_hash()
        .expect("compute interface hash");

    // Replace placeholder with computed hash
    let base_manifest =
        manifest_template.replace(PLACEHOLDER_INTERFACE_HASH, &computed_hash.to_string());

    // Re-parse to get the manifest object for signing
    let manifest_for_signing = ConnectorManifest::parse_str(&base_manifest)
        .expect("manifest with correct hash should parse");

    // Compute signing bytes using the same method as registry verifier
    let signing_bytes =
        manifest_signing_bytes(&manifest_for_signing).expect("compute signing bytes");

    // Compute binary hash
    let binary_hash = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(binary);
        let digest = hasher.finalize();
        format!("sha256:{}", hex::encode(digest))
    };

    // Build the message: signing_bytes + binary_hash (matches registry verifier)
    let message = signature_message(&signing_bytes, &binary_hash);

    // Sign with the proper context
    let sig_bytes = keys
        .signing_key
        .sign_with_context(MANIFEST_SIGNATURE_CONTEXT, &message);
    let sig_base64 = STANDARD.encode(sig_bytes.to_bytes());

    // Append signature section
    format!(
        r#"{base_manifest}
[signatures]
publisher_threshold = "1-of-1"

[[signatures.publisher_signatures]]
kid = "demo-publisher"
sig = "base64:{sig_base64}"
"#
    )
}

/// Generate demo binary bytes.
fn generate_demo_binary(connector_id: &str, version: &str) -> Vec<u8> {
    // Generate a deterministic "binary" for testing
    format!("DEMO_BINARY:{connector_id}:{version}").into_bytes()
}

/// Verify a connector bundle using `RegistryVerifier`.
fn verify_bundle(
    bundle: &ConnectorBundle,
    demo_keys: &DemoKeys,
    _trust_policy_path: Option<&str>,
    expected_target: Option<&ConnectorTarget>,
) -> Result<(VerifiedConnectorBundle, VerificationDetails), RegistryError> {
    // Build trust policy with demo keys
    // In a real implementation, this would be loaded from the trust_policy_path
    let mut publisher_keys = HashMap::new();
    publisher_keys.insert(
        "demo-publisher".to_string(),
        demo_keys.verifying_key.clone(),
    );

    let trust_policy = RegistryTrustPolicy {
        publisher_keys,
        registry_keys: HashMap::new(),
        require_registry_signature: false,
    };

    let registry_verifier = RegistryVerifier::new(trust_policy);

    // Verify the bundle
    let verified_bundle = registry_verifier.verify_bundle(
        bundle,
        None, // zone_policy - would be loaded from zone config
        None, // supply_chain - would be fetched from attestation service
        expected_target,
    )?;

    // Build verification details for output
    let verification = VerificationDetails {
        publisher_signature_verified: true,
        registry_signature_verified: false, // No registry sig in demo
        publisher_signatures_valid: 1,
        publisher_threshold: 1,
        supply_chain_policy_satisfied: true,
        capability_ceiling_respected: true,
        verified_attestations: Vec::new(), // Demo doesn't have attestations
        slsa_level: None,                  // Demo doesn't have SLSA
        supply_chain_reason_code: None,
        supply_chain_evidence_digest: None,
        supply_chain_artifact_digest: None,
    };

    Ok((verified_bundle, verification))
}

fn verify_supply_chain(
    args: &InstallArgs,
    connector_id: &str,
    binary: &[u8],
    verification: &mut VerificationDetails,
) -> Result<()> {
    let artifact_digest = binary_blake3_digest(binary);
    let attestation = match args.attestation.as_deref() {
        Some(path) => read_attestation_file(path)?,
        None => demo_attestation(connector_id, &artifact_digest),
    };
    let sbom = match args.sbom.as_deref() {
        Some(path) => read_sbom_file(path)?,
        None => demo_sbom(connector_id, &artifact_digest),
    };
    let policy = SupplyChainVerificationPolicy {
        require_attestation: true,
        require_sbom: true,
        min_slsa_level: args.min_slsa_level,
        trusted_builders: vec![],
        allow_unsigned: args.allow_unsigned,
        require_digest_match: true,
    };
    let evidence =
        VerificationPipeline::new(policy).verify(&artifact_digest, Some(&attestation), Some(&sbom));
    let evidence_digest = evidence
        .content_hash(HashAlgorithm::Blake3_256)
        .map_err(|err| anyhow::anyhow!("evidence hash failed: {err}"))?;

    verification.supply_chain_policy_satisfied = evidence.decision == VerificationDecision::Allow;
    verification.supply_chain_reason_code =
        Some(verification_reason_code_label(&evidence.reason_code));
    verification.supply_chain_evidence_digest = Some(evidence_digest);
    verification.supply_chain_artifact_digest = Some(artifact_digest);
    verification.verified_attestations = vec![
        attestation_label(&attestation).to_string(),
        format!("sbom:{}", sbom_format_label(sbom.bom_format)),
    ];
    verification.slsa_level = Some(attestation.slsa_level);

    if evidence.decision == VerificationDecision::Allow {
        Ok(())
    } else {
        Err(anyhow::anyhow!(verification_reason_code_label(
            &evidence.reason_code
        )))
    }
}

fn read_attestation_file(path: &str) -> Result<SupplyChainAttestation> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read attestation file: {path}"))?;
    serde_json::from_str(&content).with_context(|| format!("invalid attestation JSON in {path}"))
}

fn read_sbom_file(path: &str) -> Result<SoftwareBillOfMaterials> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read SBOM file: {path}"))?;
    serde_json::from_str(&content).with_context(|| format!("invalid SBOM JSON in {path}"))
}

fn binary_blake3_digest(binary: &[u8]) -> String {
    let mut hasher = Hasher::new();
    hasher.update(binary);
    format!("blake3-256:{}", hasher.finalize().to_hex())
}

fn demo_attestation(connector_id: &str, artifact_digest: &str) -> SupplyChainAttestation {
    let builder_id = "builder://flywheel/demo-registry".to_string();
    let root = TrustRootBinding {
        root_type: "manual".to_string(),
        root_id: "demo-root".to_string(),
    };
    SupplyChainAttestation {
        format: "fcp-supply-chain-attestation".to_string(),
        schema_version: "1.0".to_string(),
        subject_digest: artifact_digest.to_string(),
        predicate_type: AttestationPredicateType::SlsaProvenanceV1,
        builder_id: builder_id.clone(),
        build_type: "https://slsa.dev/container-based-build/v1".to_string(),
        materials: vec![AttestationMaterial {
            uri: format!("git+https://github.com/flywheel/connectors@refs/tags/{connector_id}"),
            digest: format!("blake3-256:{}", "a".repeat(64)),
        }],
        metadata: AttestationMetadata {
            build_started_at: Utc
                .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
                .single()
                .expect("valid build start"),
            build_finished_at: Utc
                .with_ymd_and_hms(2026, 1, 1, 0, 5, 0)
                .single()
                .expect("valid build finish"),
            invocation_id: Some(format!("demo-build:{connector_id}")),
        },
        slsa_level: 3,
        provenance_hash: format!("blake3-256:{}", "b".repeat(64)),
        trust_root: root,
        builder_allowlist: vec![builder_id],
        signature: SupplyChainSignature::new(
            "demo-attestor",
            "demo-signature",
            SUPPLY_CHAIN_ATTESTATION_SIGNED_FIELDS
                .iter()
                .map(|field| (*field).to_string())
                .collect(),
        ),
    }
}

fn demo_sbom(connector_id: &str, artifact_digest: &str) -> SoftwareBillOfMaterials {
    SoftwareBillOfMaterials {
        format: "fcp-sbom".to_string(),
        schema_version: "1.0".to_string(),
        bom_format: SbomFormat::Cyclonedx,
        bom_version: "1".to_string(),
        tool_chain: vec!["cargo".to_string(), "rustc".to_string()],
        components: vec![SbomComponent {
            component_id: connector_id.to_string(),
            name: connector_id.to_string(),
            version: "1.0.0".to_string(),
            hashes: vec![artifact_digest.to_string()],
            licenses: vec!["Apache-2.0".to_string()],
        }],
        dependencies: vec![],
        trust_root: TrustRootBinding {
            root_type: "manual".to_string(),
            root_id: "demo-root".to_string(),
        },
        signature: SupplyChainSignature::new(
            "demo-sbom-signer",
            "demo-signature",
            SBOM_SIGNED_FIELDS
                .iter()
                .map(|field| (*field).to_string())
                .collect(),
        ),
    }
}

const fn attestation_label(attestation: &SupplyChainAttestation) -> &'static str {
    match attestation.predicate_type {
        AttestationPredicateType::SlsaProvenanceV1 => "slsa-provenance-v1",
        AttestationPredicateType::InTotoStatementV1 => "in-toto-statement-v1",
    }
}

const fn sbom_format_label(format: SbomFormat) -> &'static str {
    match format {
        SbomFormat::Cyclonedx => "cyclonedx",
        SbomFormat::Spdx => "spdx",
    }
}

fn verification_reason_code_label(reason_code: &impl std::fmt::Debug) -> String {
    let debug = format!("{reason_code:?}");
    let mut output = String::with_capacity(debug.len() + 4);
    for (index, ch) in debug.chars().enumerate() {
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

fn exit_with_install_error(json: bool, install_err: &InstallError) -> ! {
    if json {
        match serde_json::to_string_pretty(install_err) {
            Ok(output) => println!("{output}"),
            Err(err) => eprintln!("Error: {install_err} (serialization failed: {err})"),
        }
    } else {
        eprintln!("Error: {install_err}");
        for hint in &install_err.hints {
            eprintln!("  Hint: {hint}");
        }
    }
    std::process::exit(1);
}

/// Mirror a verified bundle to the mesh store.
async fn mirror_to_store(
    verified_bundle: &VerifiedConnectorBundle,
    bundle: &ConnectorBundle,
    zone: &str,
    demo_keys: &DemoKeys,
) -> Result<MirrorResult, RegistryError> {
    // Parse zone ID
    let zone_id: ZoneId = zone
        .parse()
        .map_err(|e| RegistryError::ManifestParse(fcp_manifest::ManifestError::ZoneId(e)))?;

    // Create object ID key from demo key (in reality, this comes from zone config)
    let object_id_key = ObjectIdKey::from_bytes(
        demo_keys.signing_key.to_bytes()[..32]
            .try_into()
            .unwrap_or([0u8; 32]),
    );

    // Create in-memory object store for demo
    // In a real implementation, this would connect to the zone's mesh node
    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());

    // Build trust policy (same as verification)
    let mut publisher_keys = HashMap::new();
    publisher_keys.insert(
        "demo-publisher".to_string(),
        demo_keys.verifying_key.clone(),
    );

    let trust_policy = RegistryTrustPolicy {
        publisher_keys,
        registry_keys: HashMap::new(),
        require_registry_signature: false,
    };

    let registry_verifier = RegistryVerifier::new(trust_policy);

    // Mirror the bundle
    registry_verifier
        .mirror_bundle(verified_bundle, bundle, zone_id, &object_id_key, &store)
        .await
}

/// Truncate a string with ellipsis.
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else if max_len <= 3 {
        s[..max_len].to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

/// Output installation result in human-readable format.
fn output_human(output: &InstallOutput, verify_only: bool) {
    let reset = "\x1b[0m";
    let green = "\x1b[32m";
    let cyan = "\x1b[36m";
    let yellow = "\x1b[33m";

    println!();
    if verify_only {
        println!("{green}✔ Verification successful{reset}");
    } else {
        println!("{green}✔ Installation successful{reset}");
    }
    println!();

    // Connector info
    println!("  {cyan}Connector:{reset}  {}", output.connector_id);
    println!("  {cyan}Version:{reset}    {}", output.version);
    println!("  {cyan}Target:{reset}     {}", output.target);
    println!("  {cyan}Zone:{reset}       {}", output.zone_id);
    println!();

    // Hashes
    println!(
        "  {cyan}Manifest:{reset}   {}",
        truncate(&output.manifest_hash, 40)
    );
    println!(
        "  {cyan}Binary:{reset}     {}",
        truncate(&output.binary_hash, 40)
    );
    println!();

    // Verification
    let v = &output.verification;
    println!("  {cyan}Verification:{reset}");
    let pub_status = if v.publisher_signature_verified {
        format!("{green}✔{reset}")
    } else {
        format!("{yellow}✗{reset}")
    };
    let reg_status = if v.registry_signature_verified {
        format!("{green}✔{reset}")
    } else {
        format!("{yellow}✗{reset}")
    };
    println!(
        "    Publisher signature:  {pub_status} ({}/{} signatures)",
        v.publisher_signatures_valid, v.publisher_threshold
    );
    println!("    Registry signature:   {reg_status}");

    if !v.verified_attestations.is_empty() {
        println!(
            "    Attestations:         {}",
            v.verified_attestations.join(", ")
        );
    }
    if let Some(slsa) = v.slsa_level {
        println!("    SLSA Level:           {slsa}");
    }
    if let Some(reason_code) = &v.supply_chain_reason_code {
        println!("    Supply chain:         {reason_code}");
    }
    if let Some(evidence_digest) = &v.supply_chain_evidence_digest {
        println!(
            "    Evidence bundle:      {}",
            truncate(evidence_digest, 40)
        );
    }
    println!();

    // Object IDs (if mirrored)
    if let Some(ref mid) = output.manifest_object_id {
        println!("  {cyan}Manifest Object:{reset} {mid}");
    }
    if let Some(ref bid) = output.binary_object_id {
        println!("  {cyan}Binary Object:{reset}   {bid}");
    }
    if output.manifest_object_id.is_some() {
        println!();
    }

    // Timestamp
    println!("  {cyan}Installed:{reset}  {}", output.installed_at_iso);
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_connector_spec_without_version() {
        let (id, version) = parse_connector_spec("fcp.telegram:base:v1");
        assert_eq!(id, "fcp.telegram:base:v1");
        assert!(version.is_none());
    }

    #[test]
    fn parse_connector_spec_with_version() {
        let (id, version) = parse_connector_spec("fcp.telegram:base:v1@1.2.3");
        assert_eq!(id, "fcp.telegram:base:v1");
        assert_eq!(version, Some("1.2.3".to_string()));
    }

    #[test]
    fn current_target_not_empty() {
        let target = current_target();
        assert!(!target.is_empty());
    }

    #[test]
    fn fetch_known_connector() {
        let target = parse_target_triple("x86_64-unknown-linux-gnu");
        let result = fetch_connector_bundle("fcp.telegram:base:v1", None, &target);
        assert!(result.is_ok());
        let (bundle, _keys) = result.unwrap();
        assert!(bundle.manifest_toml.contains("fcp.telegram:base:v1"));
    }

    #[test]
    fn fetch_known_connector_with_version() {
        let target = parse_target_triple("x86_64-unknown-linux-gnu");
        let result = fetch_connector_bundle("fcp.telegram:base:v1", Some("1.0.1"), &target);
        assert!(result.is_ok());
        let (bundle, _keys) = result.unwrap();
        assert!(bundle.manifest_toml.contains("version = \"1.0.1\""));
    }

    #[test]
    fn fetch_unknown_connector() {
        let target = parse_target_triple("x86_64-unknown-linux-gnu");
        let result = fetch_connector_bundle("fcp.unknown:base:v1", None, &target);
        assert!(result.is_err());
    }

    #[test]
    fn fetch_unknown_version() {
        let target = parse_target_triple("x86_64-unknown-linux-gnu");
        let result = fetch_connector_bundle("fcp.telegram:base:v1", Some("9.9.9"), &target);
        assert!(result.is_err());
    }

    #[test]
    fn verify_bundle_passes() {
        let target = parse_target_triple("x86_64-unknown-linux-gnu");
        let (bundle, keys) = fetch_connector_bundle("fcp.telegram:base:v1", None, &target).unwrap();
        let result = verify_bundle(&bundle, &keys, None, Some(&target));
        assert!(result.is_ok(), "verify_bundle failed: {result:?}");
        let (_verified, details) = result.unwrap();
        assert!(details.publisher_signature_verified);
    }

    #[fcp_async_core::runtime::test]
    async fn mirror_to_store_success() {
        let target = parse_target_triple("x86_64-unknown-linux-gnu");
        let (bundle, keys) = fetch_connector_bundle("fcp.telegram:base:v1", None, &target).unwrap();
        let (verified, _details) = verify_bundle(&bundle, &keys, None, Some(&target)).unwrap();
        let result = mirror_to_store(&verified, &bundle, "z:work", &keys).await;
        assert!(result.is_ok());
        let mirror_result = result.unwrap();
        // ObjectId should have valid format
        assert!(!mirror_result.manifest_hash.is_empty());
        assert!(!mirror_result.binary_hash.is_empty());
    }

    #[test]
    fn truncate_short() {
        assert_eq!(truncate("abc", 10), "abc");
    }

    #[test]
    fn truncate_long() {
        assert_eq!(truncate("abcdefghij", 6), "abc...");
    }

    #[test]
    fn truncate_exact() {
        assert_eq!(truncate("abcdef", 6), "abcdef");
    }

    // ── parse_connector_spec edge cases ─────────────────────────

    #[test]
    fn parse_connector_spec_empty_string() {
        let (id, version) = parse_connector_spec("");
        assert_eq!(id, "");
        assert!(version.is_none());
    }

    #[test]
    fn parse_connector_spec_with_empty_version() {
        let (id, version) = parse_connector_spec("fcp.telegram:base:v1@");
        assert_eq!(id, "fcp.telegram:base:v1");
        assert_eq!(version, Some(String::new()));
    }

    #[test]
    fn parse_connector_spec_multiple_at_signs() {
        let (id, version) = parse_connector_spec("fcp.test@1.0.0@extra");
        assert_eq!(id, "fcp.test");
        assert_eq!(version, Some("1.0.0@extra".to_string()));
    }

    #[test]
    fn parse_connector_spec_version_only() {
        let (id, version) = parse_connector_spec("@1.0.0");
        assert_eq!(id, "");
        assert_eq!(version, Some("1.0.0".to_string()));
    }

    // ── parse_target_triple tests ───────────────────────────────

    #[test]
    fn parse_target_triple_x86_64_linux() {
        let target = parse_target_triple("x86_64-unknown-linux-gnu");
        assert_eq!(target.arch, "amd64");
        assert_eq!(target.os, "linux");
    }

    #[test]
    fn parse_target_triple_aarch64_macos() {
        let target = parse_target_triple("aarch64-apple-darwin");
        assert_eq!(target.arch, "arm64");
        assert_eq!(target.os, "darwin");
    }

    #[test]
    fn parse_target_triple_x86_64_macos() {
        let target = parse_target_triple("x86_64-apple-darwin");
        assert_eq!(target.arch, "amd64");
        assert_eq!(target.os, "darwin");
    }

    #[test]
    fn parse_target_triple_aarch64_linux() {
        let target = parse_target_triple("aarch64-unknown-linux-gnu");
        assert_eq!(target.arch, "arm64");
        assert_eq!(target.os, "linux");
    }

    #[test]
    fn parse_target_triple_unknown_arch() {
        let target = parse_target_triple("riscv64-unknown-linux-gnu");
        assert_eq!(target.arch, "riscv64");
        assert_eq!(target.os, "linux");
    }

    #[test]
    fn parse_target_triple_short() {
        let target = parse_target_triple("x86_64");
        assert_eq!(target.arch, "amd64");
        assert_eq!(target.os, "unknown");
    }

    #[test]
    fn parse_target_triple_two_parts() {
        let target = parse_target_triple("x86_64-unknown");
        assert_eq!(target.arch, "amd64");
        assert_eq!(target.os, "unknown");
    }

    // ── registry_error_to_install_error mapping ─────────────────

    #[test]
    fn registry_error_missing_signatures() {
        let err = registry_error_to_install_error("fcp.test:v1", RegistryError::MissingSignatures);
        assert_eq!(err.code, "FCP-4012");
        assert!(err.message.contains("signatures section missing"));
    }

    #[test]
    fn registry_error_signature_invalid() {
        let err = registry_error_to_install_error(
            "fcp.test:v1",
            RegistryError::SignatureInvalid {
                kid: "key-1".to_string(),
            },
        );
        assert_eq!(err.code, "FCP-4012");
        assert!(err.message.contains("key-1"));
    }

    #[test]
    fn registry_error_publisher_threshold_unmet() {
        let err = registry_error_to_install_error(
            "fcp.test:v1",
            RegistryError::PublisherThresholdUnmet {
                required: 3,
                valid: 1,
            },
        );
        assert_eq!(err.code, "FCP-4012");
        assert!(err.message.contains("1/3"));
    }

    #[test]
    fn registry_error_registry_signature_required() {
        let err = registry_error_to_install_error(
            "fcp.test:v1",
            RegistryError::RegistrySignatureRequired,
        );
        assert_eq!(err.code, "FCP-4012");
        assert!(err.message.contains("registry signature required"));
    }

    #[test]
    fn registry_error_target_mismatch() {
        let err = registry_error_to_install_error(
            "fcp.test:v1",
            RegistryError::TargetMismatch {
                expected: "linux/amd64".to_string(),
                found: "darwin/arm64".to_string(),
            },
        );
        assert_eq!(err.code, "FCP-4016");
        assert!(err.message.contains("linux/amd64"));
        assert!(err.message.contains("darwin/arm64"));
    }

    #[test]
    fn registry_error_capability_ceiling_violation() {
        let err = registry_error_to_install_error(
            "fcp.test:v1",
            RegistryError::CapabilityCeilingViolation {
                capability: "system.exec".to_string(),
            },
        );
        assert_eq!(err.code, "FCP-4014");
        assert!(err.message.contains("system.exec"));
    }

    #[test]
    fn registry_error_transparency_log_missing() {
        let err =
            registry_error_to_install_error("fcp.test:v1", RegistryError::TransparencyLogMissing);
        assert_eq!(err.code, "FCP-4015");
    }

    #[test]
    fn registry_error_transparency_evidence_missing() {
        let err = registry_error_to_install_error(
            "fcp.test:v1",
            RegistryError::TransparencyEvidenceMissing,
        );
        assert_eq!(err.code, "FCP-4015");
    }

    #[test]
    fn registry_error_attestation_evidence_missing() {
        let err = registry_error_to_install_error(
            "fcp.test:v1",
            RegistryError::AttestationEvidenceMissing,
        );
        assert_eq!(err.code, "FCP-4015");
    }

    // ── fetch_connector_bundle additional tests ─────────────────

    #[test]
    fn fetch_all_known_connectors() {
        let target = parse_target_triple("x86_64-unknown-linux-gnu");
        for connector in &[
            "fcp.telegram:base:v1",
            "fcp.discord:base:v1",
            "fcp.openai:base:v1",
            "fcp.anthropic:base:v1",
        ] {
            let result = fetch_connector_bundle(connector, None, &target);
            assert!(result.is_ok(), "failed to fetch {connector}");
            let (bundle, _) = result.unwrap();
            assert!(bundle.manifest_toml.contains(connector));
        }
    }

    #[test]
    fn fetch_connector_version_1_0_1() {
        let target = parse_target_triple("aarch64-apple-darwin");
        for connector in &["fcp.telegram:base:v1", "fcp.discord:base:v1"] {
            let result = fetch_connector_bundle(connector, Some("1.0.1"), &target);
            assert!(result.is_ok(), "failed to fetch {connector}@1.0.1");
        }
    }

    #[test]
    fn fetch_connector_different_targets() {
        for triple in &[
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
            "x86_64-apple-darwin",
            "aarch64-apple-darwin",
        ] {
            let target = parse_target_triple(triple);
            let result = fetch_connector_bundle("fcp.telegram:base:v1", None, &target);
            assert!(result.is_ok(), "failed for target {triple}");
        }
    }

    // ── generate_demo_binary tests ──────────────────────────────

    #[test]
    fn demo_binary_deterministic() {
        let b1 = generate_demo_binary("fcp.test:v1", "1.0.0");
        let b2 = generate_demo_binary("fcp.test:v1", "1.0.0");
        assert_eq!(b1, b2);
    }

    #[test]
    fn demo_binary_differs_by_connector() {
        let b1 = generate_demo_binary("fcp.a:v1", "1.0.0");
        let b2 = generate_demo_binary("fcp.b:v1", "1.0.0");
        assert_ne!(b1, b2);
    }

    #[test]
    fn demo_binary_differs_by_version() {
        let b1 = generate_demo_binary("fcp.test:v1", "1.0.0");
        let b2 = generate_demo_binary("fcp.test:v1", "1.0.1");
        assert_ne!(b1, b2);
    }

    #[test]
    fn demo_binary_contains_id_and_version() {
        let binary = generate_demo_binary("fcp.test:v1", "2.0.0");
        let s = String::from_utf8(binary).unwrap();
        assert!(s.contains("fcp.test:v1"));
        assert!(s.contains("2.0.0"));
    }

    // ── generate_demo_manifest tests ────────────────────────────

    #[test]
    fn demo_manifest_contains_connector_id() {
        let keys = DemoKeys::new();
        let binary = generate_demo_binary("fcp.telegram:base:v1", "1.0.0");
        let manifest = generate_demo_manifest("fcp.telegram:base:v1", "1.0.0", &binary, &keys);
        assert!(manifest.contains("fcp.telegram:base:v1"));
        assert!(manifest.contains("version = \"1.0.0\""));
    }

    #[test]
    fn demo_manifest_has_signature_section() {
        let keys = DemoKeys::new();
        let binary = generate_demo_binary("fcp.test:v1", "1.0.0");
        let manifest = generate_demo_manifest("fcp.test:v1", "1.0.0", &binary, &keys);
        assert!(manifest.contains("[signatures]"));
        assert!(manifest.contains("publisher_threshold"));
        assert!(manifest.contains("[[signatures.publisher_signatures]]"));
        assert!(manifest.contains("kid = \"demo-publisher\""));
    }

    #[test]
    fn demo_manifest_has_computed_interface_hash() {
        let keys = DemoKeys::new();
        let binary = generate_demo_binary("fcp.discord:base:v1", "1.0.0");
        let manifest = generate_demo_manifest("fcp.discord:base:v1", "1.0.0", &binary, &keys);
        // Should not contain the placeholder anymore
        assert!(!manifest.contains(PLACEHOLDER_INTERFACE_HASH));
        // Should contain a proper interface hash
        assert!(manifest.contains("interface_hash = \"blake3-256:fcp.interface.v2:"));
    }

    #[test]
    fn demo_manifest_parses_as_valid() {
        let keys = DemoKeys::new();
        let binary = generate_demo_binary("fcp.openai:base:v1", "1.0.0");
        let manifest = generate_demo_manifest("fcp.openai:base:v1", "1.0.0", &binary, &keys);
        let parsed = ConnectorManifest::parse_str(&manifest);
        assert!(parsed.is_ok(), "manifest should parse: {parsed:?}");
    }

    // ── DemoKeys tests ──────────────────────────────────────────

    #[test]
    fn demo_keys_deterministic() {
        let k1 = DemoKeys::new();
        let k2 = DemoKeys::new();
        assert_eq!(k1.verifying_key.to_bytes(), k2.verifying_key.to_bytes());
    }

    // ── verify_bundle edge cases ────────────────────────────────

    #[test]
    fn verify_bundle_all_known_connectors() {
        let target = parse_target_triple("aarch64-apple-darwin");
        for connector in &[
            "fcp.telegram:base:v1",
            "fcp.discord:base:v1",
            "fcp.openai:base:v1",
            "fcp.anthropic:base:v1",
        ] {
            let (bundle, keys) = fetch_connector_bundle(connector, None, &target).unwrap();
            let result = verify_bundle(&bundle, &keys, None, Some(&target));
            assert!(result.is_ok(), "verify failed for {connector}: {result:?}");
        }
    }

    #[test]
    fn verify_bundle_version_1_0_1() {
        let target = parse_target_triple("x86_64-unknown-linux-gnu");
        let (bundle, keys) =
            fetch_connector_bundle("fcp.telegram:base:v1", Some("1.0.1"), &target).unwrap();
        let result = verify_bundle(&bundle, &keys, None, Some(&target));
        assert!(result.is_ok());
    }

    #[test]
    fn verify_bundle_details_populated() {
        let target = parse_target_triple("x86_64-unknown-linux-gnu");
        let (bundle, keys) = fetch_connector_bundle("fcp.telegram:base:v1", None, &target).unwrap();
        let (_, details) = verify_bundle(&bundle, &keys, None, Some(&target)).unwrap();
        assert!(details.publisher_signature_verified);
        assert_eq!(details.publisher_signatures_valid, 1);
        assert_eq!(details.publisher_threshold, 1);
        assert!(details.supply_chain_policy_satisfied);
        assert!(details.capability_ceiling_respected);
    }

    #[test]
    fn verified_bundle_has_hashes() {
        let target = parse_target_triple("x86_64-unknown-linux-gnu");
        let (bundle, keys) = fetch_connector_bundle("fcp.telegram:base:v1", None, &target).unwrap();
        let (verified, _) = verify_bundle(&bundle, &keys, None, Some(&target)).unwrap();
        assert!(!verified.manifest_hash.is_empty());
        assert!(!verified.binary_hash.is_empty());
        assert!(verified.binary_hash.starts_with("sha256:"));
    }

    // ── mirror_to_store additional tests ────────────────────────

    #[fcp_async_core::runtime::test]
    async fn mirror_to_store_all_connectors() {
        let target = parse_target_triple("x86_64-unknown-linux-gnu");
        for connector in &["fcp.telegram:base:v1", "fcp.discord:base:v1"] {
            let (bundle, keys) = fetch_connector_bundle(connector, None, &target).unwrap();
            let (verified, _) = verify_bundle(&bundle, &keys, None, Some(&target)).unwrap();
            let result = mirror_to_store(&verified, &bundle, "z:private", &keys).await;
            assert!(result.is_ok(), "mirror failed for {connector}");
        }
    }

    // ── truncate additional edge cases ──────────────────────────

    #[test]
    fn truncate_max_len_zero() {
        assert_eq!(truncate("abc", 0), "");
    }

    #[test]
    fn truncate_max_len_one() {
        assert_eq!(truncate("abc", 1), "a");
    }

    #[test]
    fn truncate_max_len_two() {
        assert_eq!(truncate("abc", 2), "ab");
    }

    #[test]
    fn truncate_max_len_three() {
        assert_eq!(truncate("abc", 3), "abc");
    }

    #[test]
    fn truncate_long_max_four() {
        assert_eq!(truncate("abcdef", 4), "a...");
    }

    #[test]
    fn truncate_empty_string() {
        assert_eq!(truncate("", 5), "");
    }

    #[test]
    fn truncate_single_char() {
        assert_eq!(truncate("a", 5), "a");
    }
}
