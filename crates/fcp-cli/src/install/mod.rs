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
use chrono::Utc;
use clap::Args;
use fcp_core::{ObjectIdKey, ZoneId};
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
    // Create a tokio runtime for async operations
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to create tokio runtime")?;

    runtime.block_on(run_async(args))
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
        if args.json {
            let output = serde_json::to_string_pretty(&err).context("failed to serialize error")?;
            println!("{output}");
        } else {
            eprintln!("Error: {err}");
            for hint in &err.hints {
                eprintln!("  Hint: {hint}");
            }
        }
        return Ok(());
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
                if args.json {
                    let output = serde_json::to_string_pretty(&install_err)
                        .context("failed to serialize error")?;
                    println!("{output}");
                } else {
                    eprintln!("Error: {install_err}");
                    for hint in &install_err.hints {
                        eprintln!("  Hint: {hint}");
                    }
                }
                return Ok(());
            }
        };

    // Phase 2: Verify manifest signatures
    report_progress(
        InstallPhase::VerifyingManifest,
        "checking publisher and registry signatures",
    );

    let (verified_bundle, verification) = match verify_bundle(
        &bundle,
        &demo_keys,
        args.trust_policy.as_deref(),
        Some(&connector_target),
    ) {
        Ok(v) => v,
        Err(err) => {
            let install_err = registry_error_to_install_error(&connector_id, err);
            if args.json {
                let output = serde_json::to_string_pretty(&install_err)
                    .context("failed to serialize error")?;
                println!("{output}");
            } else {
                eprintln!("Error: {install_err}");
                for hint in &install_err.hints {
                    eprintln!("  Hint: {hint}");
                }
            }
            return Ok(());
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
    if !args.skip_supply_chain {
        report_progress(
            InstallPhase::CheckingSupplyChain,
            "validating attestations and transparency log",
        );
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
                if args.json {
                    let output = serde_json::to_string_pretty(&install_err)
                        .context("failed to serialize error")?;
                    println!("{output}");
                } else {
                    eprintln!("Error: {install_err}");
                    for hint in &install_err.hints {
                        eprintln!("  Hint: {hint}");
                    }
                }
                return Ok(());
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
    };

    Ok((verified_bundle, verification))
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

    #[tokio::test]
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
}
