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

/// Run the package command.
pub fn run(args: &PackageArgs) -> Result<()> {
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

    // Print output
    match args.format {
        OutputFormat::Human => print_human_output(&output),
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
    }

    Ok(())
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
    let mut cmd = Command::new("cargo");
    cmd.arg("build");
    let target_root = crate_path.join("target");

    if args.release {
        cmd.arg("--release");
    }

    // Add deterministic build flags
    cmd.env("CARGO_INCREMENTAL", "0");
    cmd.env("RUSTFLAGS", "-C debuginfo=0");
    // Keep packaging builds isolated from parent-process target-dir settings.
    cmd.env("CARGO_TARGET_DIR", &target_root);

    // Add any extra cargo flags
    for flag in &args.cargo_flags {
        cmd.arg(flag);
    }

    cmd.current_dir(crate_path);

    let status = cmd.status().context("failed to run cargo build")?;
    if !status.success() {
        bail!("cargo build failed with status: {status}");
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
    for key in ["RUSTFLAGS", "CARGO_INCREMENTAL", "CC", "CXX", "TARGET"] {
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
        tool: format!("fcp-cli {}", env!("CARGO_PKG_VERSION")),
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
    use super::resolve_target_dir;
    use std::path::Path;

    #[test]
    fn resolve_target_dir_defaults_to_crate_target() {
        let crate_path = Path::new("/tmp/fcp-example");
        let resolved = resolve_target_dir(crate_path, "release");
        assert_eq!(resolved, Path::new("/tmp/fcp-example/target/release"));
    }
}
