//! Connector packaging workflow.
//!
//! This module implements the full connector packaging workflow:
//! 1. Build the connector with deterministic flags
//! 2. Embed manifest and compute interface hash
//! 3. Generate SBOM from cargo metadata
//! 4. Output package directory with binary, manifest, SBOM, and build metadata

pub mod types;

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

pub use types::*;

pub const PACKAGE_OUTPUT_FILENAME: &str = "package-output.json";

/// Run the package command.
pub fn run(args: &PackageArgs) -> Result<()> {
    let output = package_connector(args)?;

    match args.format {
        OutputFormat::Human => print_human_output(&output),
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
    }

    Ok(())
}

/// Build a connector package and return the generated package metadata.
pub fn package_connector(args: &PackageArgs) -> Result<PackageOutput> {
    let crate_path = args.path.canonicalize().context("invalid crate path")?;

    // Verify this is a valid connector crate
    let cargo_toml = crate_path.join("Cargo.toml");
    if !cargo_toml.exists() {
        bail!("No Cargo.toml found in {}", crate_path.display());
    }

    // Find the manifest.toml
    let manifest_path = find_manifest(&crate_path)?;
    tracing::info!("Found manifest at {}", manifest_path.display());

    // Determine output directory
    let output_dir = args
        .output
        .clone()
        .unwrap_or_else(|| crate_path.join("target").join("package"));
    fs::create_dir_all(&output_dir).context("failed to create output directory")?;

    // Build the connector
    tracing::info!("Building connector...");
    let binary_path = build_connector(&crate_path, args)?;
    tracing::info!("Built binary at {}", binary_path.display());

    // Copy binary to output
    let binary_name = binary_path
        .file_name()
        .context("binary has no filename")?
        .to_string_lossy();
    let output_binary = output_dir.join(binary_name.as_ref());
    fs::copy(&binary_path, &output_binary).context("failed to copy binary")?;

    // Compute binary hash
    let binary_sha256 = compute_sha256(&output_binary)?;
    tracing::info!("Binary SHA-256: {binary_sha256}");

    // Copy manifest
    let output_manifest = output_dir.join("manifest.toml");
    fs::copy(&manifest_path, &output_manifest).context("failed to copy manifest")?;

    // Parse manifest for metadata
    let manifest_content = fs::read_to_string(&manifest_path)?;
    let (connector_id, version) = extract_manifest_metadata(&manifest_content)?;

    // Generate build metadata
    let build_metadata = collect_build_metadata(args);
    let build_metadata_path = output_dir.join("build-metadata.json");
    let build_json = serde_json::to_string_pretty(&build_metadata)?;
    fs::write(&build_metadata_path, &build_json)?;

    // Generate SBOM if not skipped
    let sbom_path = if args.skip_sbom {
        None
    } else {
        tracing::info!("Generating SBOM...");
        let sbom = generate_sbom(&crate_path, &connector_id, &version)?;
        let sbom_file = output_dir.join("sbom.json");
        let sbom_json = serde_json::to_string_pretty(&sbom)?;
        fs::write(&sbom_file, &sbom_json)?;
        Some(sbom_file)
    };

    // Build output structure
    let output = PackageOutput {
        output_dir,
        binary_path: output_binary,
        manifest_path: output_manifest,
        sbom_path,
        build_metadata_path,
        binary_sha256,
        connector_id,
        version,
    };

    let package_metadata_path = output.output_dir.join(PACKAGE_OUTPUT_FILENAME);
    let output_json = serde_json::to_string_pretty(&output)?;
    fs::write(&package_metadata_path, format!("{output_json}\n"))
        .context("failed to write package metadata")?;

    Ok(output)
}

/// Find the manifest.toml file in the crate.
fn find_manifest(crate_path: &Path) -> Result<PathBuf> {
    // Check common locations
    let candidates = [
        crate_path.join("manifest.toml"),
        crate_path.join("fcp-manifest.toml"),
        crate_path.join("connector-manifest.toml"),
    ];

    for path in candidates {
        if path.exists() {
            return Ok(path);
        }
    }

    bail!(
        "No manifest.toml found in {}. Expected one of: manifest.toml, fcp-manifest.toml, connector-manifest.toml",
        crate_path.display()
    );
}

/// Build the connector with deterministic flags.
fn build_connector(crate_path: &Path, args: &PackageArgs) -> Result<PathBuf> {
    let mut cmd = Command::new("rch");
    cmd.arg("exec");
    cmd.arg("--");
    cmd.arg("cargo");
    cmd.arg("build");
    let target_root = crate_path.join("target");

    if args.release {
        cmd.arg("--release");
    }

    // Add deterministic build flags.
    // Use CARGO_ENCODED_RUSTFLAGS (0x1f-separated) to avoid shell expansion issues
    // with build hooks. Disable split-debuginfo to avoid requiring rust-objcopy
    // (which may not be installed if llvm-tools-preview is absent).
    cmd.env("CARGO_INCREMENTAL", "0");
    cmd.env(
        "CARGO_ENCODED_RUSTFLAGS",
        "-Cdebuginfo=0\x1f-Csplit-debuginfo=off",
    );
    cmd.env("CARGO_PROFILE_RELEASE_SPLIT_DEBUGINFO", "off");
    cmd.env("CARGO_PROFILE_RELEASE_STRIP", "none");
    cmd.env_remove("RUSTFLAGS");
    // Keep packaging builds isolated from parent-process target-dir settings.
    cmd.env("CARGO_TARGET_DIR", &target_root);

    // Add any extra cargo flags
    for flag in &args.cargo_flags {
        cmd.arg(flag);
    }

    cmd.current_dir(crate_path);

    let status = cmd
        .status()
        .context("failed to run `rch exec -- cargo build`")?;
    if !status.success() {
        bail!("`rch exec -- cargo build` failed with status: {status}");
    }

    // Find the built binary
    let profile = if args.release { "release" } else { "debug" };
    let target_dir = resolve_target_dir(crate_path, profile);

    // Get crate name from Cargo.toml
    let cargo_toml = fs::read_to_string(crate_path.join("Cargo.toml"))?;
    let cargo: toml::Value = toml::from_str(&cargo_toml)?;
    let crate_name = cargo
        .get("package")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .context("failed to extract crate name from Cargo.toml")?;

    // Handle binary name (might have hyphens converted to underscores)
    let binary_name = crate_name.replace('-', "_");
    let binary_path = target_dir.join(&binary_name);

    if binary_path.exists() {
        return Ok(binary_path);
    }

    // Try with original name
    let binary_path = target_dir.join(crate_name);
    if binary_path.exists() {
        return Ok(binary_path);
    }

    bail!(
        "Built binary not found at expected location: {}",
        target_dir.display()
    );
}

fn resolve_target_dir(crate_path: &Path, profile: &str) -> PathBuf {
    crate_path.join("target").join(profile)
}

/// Compute SHA-256 hash of a file.
fn compute_sha256(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    let hash = hasher.finalize();
    Ok(format!("{hash:x}"))
}

/// Extract connector ID and version from manifest.
fn extract_manifest_metadata(content: &str) -> Result<(String, String)> {
    let manifest: toml::Value = toml::from_str(content)?;

    let connector_id = manifest
        .get("connector")
        .and_then(|c| c.get("id"))
        .and_then(|id| id.as_str())
        .context("failed to extract connector.id from manifest")?;

    let version = manifest
        .get("connector")
        .and_then(|c| c.get("version"))
        .and_then(|v| v.as_str())
        .context("failed to extract connector.version from manifest")?;

    Ok((connector_id.to_string(), version.to_string()))
}

/// Collect build metadata for reproducibility verification.
fn collect_build_metadata(args: &PackageArgs) -> BuildMetadata {
    // Get Rust version
    let rust_version = Command::new("rustc").arg("--version").output().map_or_else(
        |_| "unknown".to_string(),
        |o| String::from_utf8_lossy(&o.stdout).trim().to_string(),
    );

    // Get Cargo version
    let cargo_version = Command::new("cargo").arg("--version").output().map_or_else(
        |_| "unknown".to_string(),
        |o| String::from_utf8_lossy(&o.stdout).trim().to_string(),
    );

    // Get target triple
    let target_triple = Command::new("rustc")
        .args(["--print", "host"])
        .output()
        .map_or_else(
            |_| "unknown".to_string(),
            |o| String::from_utf8_lossy(&o.stdout).trim().to_string(),
        );

    // Get git info
    let git_commit = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        });

    let git_dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .map(|o| !o.stdout.is_empty());

    // Collect relevant build environment
    let mut build_env = HashMap::new();
    for key in [
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_INCREMENTAL",
        "CC",
        "CXX",
        "TARGET",
    ] {
        if let Ok(value) = std::env::var(key) {
            build_env.insert(key.to_string(), value);
        }
    }

    BuildMetadata {
        rust_version,
        cargo_version,
        target_triple,
        build_timestamp: chrono::Utc::now().to_rfc3339(),
        profile: if args.release {
            "release".to_string()
        } else {
            "debug".to_string()
        },
        git_commit,
        git_dirty,
        features: vec![], // TODO: Extract from cargo metadata
        build_env,
        cargo_flags: args.cargo_flags.clone(),
    }
}

/// Generate SBOM from cargo metadata.
fn generate_sbom(crate_path: &Path, connector_id: &str, version: &str) -> Result<SimpleSbom> {
    // Get cargo metadata
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1"])
        .current_dir(crate_path)
        .output()
        .context("failed to run cargo metadata")?;

    if !output.status.success() {
        bail!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout)?;

    // Extract dependencies
    let packages = metadata
        .get("packages")
        .and_then(|p| p.as_array())
        .cloned()
        .unwrap_or_default();

    let dependencies: Vec<SbomDependency> = packages
        .iter()
        .filter_map(|pkg| {
            let name = pkg.get("name")?.as_str()?;
            let version = pkg.get("version")?.as_str()?;
            let source = pkg.get("source").and_then(|s| s.as_str()).unwrap_or("path");

            // Skip the main package
            if source == "path" {
                return None;
            }

            Some(SbomDependency {
                name: name.to_string(),
                version: version.to_string(),
                purl: format!("pkg:cargo/{name}@{version}"),
                source: source.to_string(),
            })
        })
        .collect();

    Ok(SimpleSbom {
        format_version: "1.0".to_string(),
        created: chrono::Utc::now().to_rfc3339(),
        tool: format!("fwc {}", env!("CARGO_PKG_VERSION")),
        component: SbomComponent {
            component_type: "application".to_string(),
            name: connector_id.to_string(),
            version: version.to_string(),
            purl: format!("pkg:fcp/{connector_id}@{version}"),
        },
        dependencies,
    })
}

/// Print human-readable output.
fn print_human_output(output: &PackageOutput) {
    println!("✓ Package created successfully");
    println!();
    println!("  Connector: {}", output.connector_id);
    println!("  Version:   {}", output.version);
    println!("  SHA-256:   {}", output.binary_sha256);
    println!();
    println!("  Output directory: {}", output.output_dir.display());
    println!("  Binary:           {}", output.binary_path.display());
    println!("  Manifest:         {}", output.manifest_path.display());
    if let Some(ref sbom) = output.sbom_path {
        println!("  SBOM:             {}", sbom.display());
    }
    println!(
        "  Build metadata:   {}",
        output.build_metadata_path.display()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn resolve_target_dir_release() {
        let crate_path = Path::new("/tmp/fcp-example");
        let resolved = resolve_target_dir(crate_path, "release");
        assert_eq!(resolved, Path::new("/tmp/fcp-example/target/release"));
    }

    #[test]
    fn resolve_target_dir_debug() {
        let crate_path = Path::new("/tmp/fcp-example");
        let resolved = resolve_target_dir(crate_path, "debug");
        assert_eq!(resolved, Path::new("/tmp/fcp-example/target/debug"));
    }

    #[test]
    fn extract_manifest_metadata_valid() {
        let toml = r#"
[connector]
id = "acme.storage:s3:1.2.0"
version = "1.2.0"
"#;
        let (id, version) = extract_manifest_metadata(toml).unwrap();
        assert_eq!(id, "acme.storage:s3:1.2.0");
        assert_eq!(version, "1.2.0");
    }

    #[test]
    fn extract_manifest_metadata_missing_id() {
        let toml = r#"
[connector]
version = "1.0.0"
"#;
        let result = extract_manifest_metadata(toml);
        assert!(result.is_err());
    }

    #[test]
    fn extract_manifest_metadata_missing_version() {
        let toml = r#"
[connector]
id = "acme:test:1.0.0"
"#;
        let result = extract_manifest_metadata(toml);
        assert!(result.is_err());
    }

    #[test]
    fn extract_manifest_metadata_missing_section() {
        let toml = r#"
[other]
foo = "bar"
"#;
        let result = extract_manifest_metadata(toml);
        assert!(result.is_err());
    }

    #[test]
    fn extract_manifest_metadata_empty() {
        let result = extract_manifest_metadata("");
        assert!(result.is_err());
    }

    #[test]
    fn extract_manifest_metadata_invalid_toml() {
        let result = extract_manifest_metadata("{{not valid}}");
        assert!(result.is_err());
    }

    #[test]
    fn find_manifest_nonexistent_dir() {
        let result = find_manifest(Path::new("/tmp/definitely-not-a-real-fcp-dir-12345"));
        assert!(result.is_err());
    }

    #[test]
    fn compute_sha256_nonexistent_file() {
        let result = compute_sha256(Path::new("/tmp/nonexistent-file-for-sha256-test"));
        assert!(result.is_err());
    }

    #[test]
    fn compute_sha256_known_value() {
        // Create a temp file with known content
        let dir = std::env::temp_dir().join("fcp-test-sha256");
        let _ = fs::create_dir_all(&dir);
        let file = dir.join("test.txt");
        fs::write(&file, b"hello").unwrap();
        let hash = compute_sha256(&file).unwrap();
        // SHA-256 of "hello" is 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn compute_sha256_empty_file() {
        let dir = std::env::temp_dir().join("fcp-test-sha256-empty");
        let _ = fs::create_dir_all(&dir);
        let file = dir.join("empty.txt");
        fs::write(&file, b"").unwrap();
        let hash = compute_sha256(&file).unwrap();
        // SHA-256 of empty is e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn compute_sha256_deterministic() {
        let dir = std::env::temp_dir().join("fcp-test-sha256-det");
        let _ = fs::create_dir_all(&dir);
        let file = dir.join("det.txt");
        fs::write(&file, b"deterministic content").unwrap();
        let hash1 = compute_sha256(&file).unwrap();
        let hash2 = compute_sha256(&file).unwrap();
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn compute_sha256_different_content_different_hash() {
        let dir = std::env::temp_dir().join("fcp-test-sha256-diff");
        let _ = fs::create_dir_all(&dir);
        let f1 = dir.join("a.txt");
        let f2 = dir.join("b.txt");
        fs::write(&f1, b"content A").unwrap();
        fs::write(&f2, b"content B").unwrap();
        let h1 = compute_sha256(&f1).unwrap();
        let h2 = compute_sha256(&f2).unwrap();
        assert_ne!(h1, h2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn compute_sha256_binary_content() {
        let dir = std::env::temp_dir().join("fcp-test-sha256-bin");
        let _ = fs::create_dir_all(&dir);
        let file = dir.join("bin.dat");
        fs::write(&file, [0u8, 1, 2, 255, 254, 253, 128, 0]).unwrap();
        let hash = compute_sha256(&file).unwrap();
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        let _ = fs::remove_dir_all(&dir);
    }

    // ── extract_manifest_metadata edge cases ──────────────────

    #[test]
    fn extract_manifest_metadata_extra_fields() {
        let toml = r#"
[connector]
id = "vendor.analytics:tracker:3.0.0"
version = "3.0.0"
description = "Analytics connector"
author = "vendor"
"#;
        let (id, version) = extract_manifest_metadata(toml).unwrap();
        assert_eq!(id, "vendor.analytics:tracker:3.0.0");
        assert_eq!(version, "3.0.0");
    }

    #[test]
    fn extract_manifest_metadata_with_other_sections() {
        let toml = r#"
[package]
name = "fcp-analytics"

[connector]
id = "analytics:core:1.0.0"
version = "1.0.0"

[capabilities]
read = true
"#;
        let (id, version) = extract_manifest_metadata(toml).unwrap();
        assert_eq!(id, "analytics:core:1.0.0");
        assert_eq!(version, "1.0.0");
    }

    #[test]
    fn extract_manifest_metadata_numeric_version_fails() {
        // Version must be a string
        let toml = r#"
[connector]
id = "test:c:1"
version = 1
"#;
        let result = extract_manifest_metadata(toml);
        assert!(result.is_err());
    }

    #[test]
    fn extract_manifest_metadata_semver_prerelease() {
        let toml = r#"
[connector]
id = "beta:conn:0.1.0-rc.1"
version = "0.1.0-rc.1"
"#;
        let (id, version) = extract_manifest_metadata(toml).unwrap();
        assert_eq!(id, "beta:conn:0.1.0-rc.1");
        assert_eq!(version, "0.1.0-rc.1");
    }

    // ── find_manifest tests ───────────────────────────────────

    #[test]
    fn find_manifest_with_manifest_toml() {
        let dir = std::env::temp_dir().join("fcp-test-find-manifest-1");
        let _ = fs::create_dir_all(&dir);
        fs::write(dir.join("manifest.toml"), "# manifest").unwrap();
        let result = find_manifest(&dir).unwrap();
        assert_eq!(result, dir.join("manifest.toml"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn find_manifest_with_fcp_manifest_toml() {
        let dir = std::env::temp_dir().join("fcp-test-find-manifest-2");
        let _ = fs::create_dir_all(&dir);
        fs::write(dir.join("fcp-manifest.toml"), "# manifest").unwrap();
        let result = find_manifest(&dir).unwrap();
        assert_eq!(result, dir.join("fcp-manifest.toml"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn find_manifest_with_connector_manifest_toml() {
        let dir = std::env::temp_dir().join("fcp-test-find-manifest-3");
        let _ = fs::create_dir_all(&dir);
        fs::write(dir.join("connector-manifest.toml"), "# manifest").unwrap();
        let result = find_manifest(&dir).unwrap();
        assert_eq!(result, dir.join("connector-manifest.toml"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn find_manifest_prefers_manifest_toml() {
        let dir = std::env::temp_dir().join("fcp-test-find-manifest-4");
        let _ = fs::create_dir_all(&dir);
        fs::write(dir.join("manifest.toml"), "# primary").unwrap();
        fs::write(dir.join("fcp-manifest.toml"), "# secondary").unwrap();
        let result = find_manifest(&dir).unwrap();
        assert_eq!(result, dir.join("manifest.toml"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn find_manifest_empty_dir_fails() {
        let dir = std::env::temp_dir().join("fcp-test-find-manifest-empty");
        let _ = fs::create_dir_all(&dir);
        // Ensure no manifest files exist
        let _ = fs::remove_file(dir.join("manifest.toml"));
        let _ = fs::remove_file(dir.join("fcp-manifest.toml"));
        let _ = fs::remove_file(dir.join("connector-manifest.toml"));
        let result = find_manifest(&dir);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("No manifest.toml found"));
        let _ = fs::remove_dir_all(&dir);
    }

    // ── resolve_target_dir tests ──────────────────────────────

    #[test]
    fn resolve_target_dir_custom_profile() {
        let resolved = resolve_target_dir(Path::new("/project"), "bench");
        assert_eq!(resolved, Path::new("/project/target/bench"));
    }

    #[test]
    fn resolve_target_dir_relative_path() {
        let resolved = resolve_target_dir(Path::new("my-connector"), "release");
        assert_eq!(resolved, Path::new("my-connector/target/release"));
    }

    // ── print_human_output tests ──────────────────────────────

    #[test]
    fn print_human_output_with_sbom() {
        let output = PackageOutput {
            output_dir: PathBuf::from("/tmp/pkg"),
            binary_path: PathBuf::from("/tmp/pkg/connector"),
            manifest_path: PathBuf::from("/tmp/pkg/manifest.toml"),
            sbom_path: Some(PathBuf::from("/tmp/pkg/sbom.json")),
            build_metadata_path: PathBuf::from("/tmp/pkg/build.json"),
            binary_sha256: "abcdef0123456789".to_string(),
            connector_id: "acme:storage:1.0.0".to_string(),
            version: "1.0.0".to_string(),
        };
        // Should not panic
        print_human_output(&output);
    }

    #[test]
    fn print_human_output_without_sbom() {
        let output = PackageOutput {
            output_dir: PathBuf::from("/out"),
            binary_path: PathBuf::from("/out/bin"),
            manifest_path: PathBuf::from("/out/manifest.toml"),
            sbom_path: None,
            build_metadata_path: PathBuf::from("/out/build.json"),
            binary_sha256: "deadbeef".to_string(),
            connector_id: "test:conn:0.1.0".to_string(),
            version: "0.1.0".to_string(),
        };
        print_human_output(&output);
    }

    // ── PackageOutput serde ───────────────────────────────────

    #[test]
    fn package_output_json_roundtrip() {
        let output = PackageOutput {
            output_dir: PathBuf::from("/build"),
            binary_path: PathBuf::from("/build/bin"),
            manifest_path: PathBuf::from("/build/m.toml"),
            sbom_path: Some(PathBuf::from("/build/sbom.json")),
            build_metadata_path: PathBuf::from("/build/meta.json"),
            binary_sha256: "abc123".to_string(),
            connector_id: "vendor:conn:1.0.0".to_string(),
            version: "1.0.0".to_string(),
        };
        let json = serde_json::to_string_pretty(&output).unwrap();
        let back: PackageOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(back.connector_id, output.connector_id);
        assert_eq!(back.version, output.version);
        assert_eq!(back.binary_sha256, output.binary_sha256);
    }

    #[test]
    fn package_output_no_sbom_skips_field() {
        let output = PackageOutput {
            output_dir: PathBuf::from("/out"),
            binary_path: PathBuf::from("/out/bin"),
            manifest_path: PathBuf::from("/out/m.toml"),
            sbom_path: None,
            build_metadata_path: PathBuf::from("/out/build.json"),
            binary_sha256: "abc".to_string(),
            connector_id: "c:t:1".to_string(),
            version: "1".to_string(),
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(!json.contains("sbom_path"));
    }
}
