//! Types for connector packaging operations.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Arguments for the package subcommand.
#[derive(Debug, Clone, clap::Args)]
pub struct PackageArgs {
    /// Path to the connector crate directory.
    #[arg(short, long, default_value = ".")]
    pub path: PathBuf,

    /// Output directory for the package.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Skip SBOM generation.
    #[arg(long, default_value_t = false)]
    pub skip_sbom: bool,

    /// Skip signing (for development only).
    #[arg(long, default_value_t = false)]
    pub skip_sign: bool,

    /// Build in release mode.
    #[arg(long, default_value_t = true)]
    pub release: bool,

    /// Additional cargo build flags.
    #[arg(long)]
    pub cargo_flags: Vec<String>,

    /// Output format (json for machine-readable).
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,
}

/// Output format for package command.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum OutputFormat {
    /// Human-readable output.
    Human,
    /// JSON output for tooling integration.
    Json,
}

/// Package output metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageOutput {
    /// Path to the output directory.
    pub output_dir: PathBuf,

    /// Path to the packaged binary.
    pub binary_path: PathBuf,

    /// Path to the embedded manifest.
    pub manifest_path: PathBuf,

    /// Path to the SBOM file (if generated).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sbom_path: Option<PathBuf>,

    /// Path to the build metadata JSON.
    pub build_metadata_path: PathBuf,

    /// SHA-256 hash of the binary.
    pub binary_sha256: String,

    /// Connector ID from manifest.
    pub connector_id: String,

    /// Connector version.
    pub version: String,
}

/// Build metadata for reproducibility verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildMetadata {
    /// Rust toolchain version.
    pub rust_version: String,

    /// Cargo version.
    pub cargo_version: String,

    /// Target triple.
    pub target_triple: String,

    /// Build timestamp (ISO 8601).
    pub build_timestamp: String,

    /// Build profile (release/debug).
    pub profile: String,

    /// Git commit hash (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_commit: Option<String>,

    /// Git dirty status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_dirty: Option<bool>,

    /// Cargo features enabled.
    pub features: Vec<String>,

    /// Environment variables affecting build (filtered).
    pub build_env: std::collections::HashMap<String, String>,

    /// CARGO_* flags used.
    pub cargo_flags: Vec<String>,
}

/// SBOM (Software Bill of Materials) in a simplified format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleSbom {
    /// SBOM format version.
    pub format_version: String,

    /// Document creation timestamp.
    pub created: String,

    /// Tool that generated this SBOM.
    pub tool: String,

    /// Primary component (the connector).
    pub component: SbomComponent,

    /// Dependencies.
    pub dependencies: Vec<SbomDependency>,
}

/// Component in SBOM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomComponent {
    /// Component type (always "application" for connectors).
    pub component_type: String,

    /// Component name.
    pub name: String,

    /// Component version.
    pub version: String,

    /// PURL (Package URL).
    pub purl: String,
}

/// Dependency in SBOM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomDependency {
    /// Dependency name.
    pub name: String,

    /// Dependency version.
    pub version: String,

    /// PURL (Package URL).
    pub purl: String,

    /// Source (crates.io, git, path).
    pub source: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- PackageOutput serde ----

    #[test]
    fn package_output_serde_roundtrip() {
        let output = PackageOutput {
            output_dir: PathBuf::from("/tmp/pkg"),
            binary_path: PathBuf::from("/tmp/pkg/connector"),
            manifest_path: PathBuf::from("/tmp/pkg/manifest.toml"),
            sbom_path: Some(PathBuf::from("/tmp/pkg/sbom.json")),
            build_metadata_path: PathBuf::from("/tmp/pkg/build.json"),
            binary_sha256: "abcdef0123456789".to_string(),
            connector_id: "my-connector:storage:1.0.0".to_string(),
            version: "1.0.0".to_string(),
        };
        let json = serde_json::to_string(&output).unwrap();
        let back: PackageOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(back.connector_id, "my-connector:storage:1.0.0");
        assert_eq!(back.version, "1.0.0");
        assert!(back.sbom_path.is_some());
    }

    #[test]
    fn package_output_no_sbom() {
        let output = PackageOutput {
            output_dir: PathBuf::from("/tmp/pkg"),
            binary_path: PathBuf::from("/tmp/pkg/connector"),
            manifest_path: PathBuf::from("/tmp/pkg/manifest.toml"),
            sbom_path: None,
            build_metadata_path: PathBuf::from("/tmp/pkg/build.json"),
            binary_sha256: "abc".to_string(),
            connector_id: "conn:test:0.1.0".to_string(),
            version: "0.1.0".to_string(),
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(!json.contains("sbom_path"));
        let back: PackageOutput = serde_json::from_str(&json).unwrap();
        assert!(back.sbom_path.is_none());
    }

    // ---- BuildMetadata serde ----

    #[test]
    fn build_metadata_serde_roundtrip() {
        let meta = BuildMetadata {
            rust_version: "1.85.0".to_string(),
            cargo_version: "1.85.0".to_string(),
            target_triple: "x86_64-unknown-linux-gnu".to_string(),
            build_timestamp: "2026-03-03T12:00:00Z".to_string(),
            profile: "release".to_string(),
            git_commit: Some("abc123".to_string()),
            git_dirty: Some(false),
            features: vec!["default".to_string()],
            build_env: std::collections::HashMap::new(),
            cargo_flags: vec!["--release".to_string()],
        };
        let json = serde_json::to_string(&meta).unwrap();
        let back: BuildMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(back.rust_version, "1.85.0");
        assert_eq!(back.target_triple, "x86_64-unknown-linux-gnu");
        assert_eq!(back.profile, "release");
        assert_eq!(back.git_commit.as_deref(), Some("abc123"));
    }

    #[test]
    fn build_metadata_minimal() {
        let meta = BuildMetadata {
            rust_version: "1.85.0".to_string(),
            cargo_version: "1.85.0".to_string(),
            target_triple: "aarch64-apple-darwin".to_string(),
            build_timestamp: "2026-01-01T00:00:00Z".to_string(),
            profile: "debug".to_string(),
            git_commit: None,
            git_dirty: None,
            features: vec![],
            build_env: std::collections::HashMap::new(),
            cargo_flags: vec![],
        };
        let json = serde_json::to_string(&meta).unwrap();
        assert!(!json.contains("git_commit"));
        let back: BuildMetadata = serde_json::from_str(&json).unwrap();
        assert!(back.git_commit.is_none());
    }

    // ---- SimpleSbom serde ----

    #[test]
    fn simple_sbom_serde_roundtrip() {
        let sbom = SimpleSbom {
            format_version: "1.0".to_string(),
            created: "2026-03-03T12:00:00Z".to_string(),
            tool: "fcp-cli".to_string(),
            component: SbomComponent {
                component_type: "application".to_string(),
                name: "my-connector".to_string(),
                version: "1.0.0".to_string(),
                purl: "pkg:cargo/my-connector@1.0.0".to_string(),
            },
            dependencies: vec![SbomDependency {
                name: "serde".to_string(),
                version: "1.0.200".to_string(),
                purl: "pkg:cargo/serde@1.0.200".to_string(),
                source: "crates.io".to_string(),
            }],
        };
        let json = serde_json::to_string(&sbom).unwrap();
        let back: SimpleSbom = serde_json::from_str(&json).unwrap();
        assert_eq!(back.component.name, "my-connector");
        assert_eq!(back.dependencies.len(), 1);
        assert_eq!(back.dependencies[0].name, "serde");
    }

    #[test]
    fn simple_sbom_empty_deps() {
        let sbom = SimpleSbom {
            format_version: "1.0".to_string(),
            created: "2026-01-01T00:00:00Z".to_string(),
            tool: "fcp-cli".to_string(),
            component: SbomComponent {
                component_type: "application".to_string(),
                name: "test".to_string(),
                version: "0.1.0".to_string(),
                purl: "pkg:cargo/test@0.1.0".to_string(),
            },
            dependencies: vec![],
        };
        let json = serde_json::to_string(&sbom).unwrap();
        let back: SimpleSbom = serde_json::from_str(&json).unwrap();
        assert!(back.dependencies.is_empty());
    }

    // ---- Debug/Clone ----

    #[test]
    fn package_output_debug() {
        let output = PackageOutput {
            output_dir: PathBuf::from("/tmp"),
            binary_path: PathBuf::from("/tmp/bin"),
            manifest_path: PathBuf::from("/tmp/manifest.toml"),
            sbom_path: None,
            build_metadata_path: PathBuf::from("/tmp/build.json"),
            binary_sha256: "abc".to_string(),
            connector_id: "c:t:1".to_string(),
            version: "1.0.0".to_string(),
        };
        let dbg = format!("{output:?}");
        assert!(dbg.contains("PackageOutput"));
    }

    #[test]
    fn build_metadata_clone() {
        let meta = BuildMetadata {
            rust_version: "1.85.0".to_string(),
            cargo_version: "1.85.0".to_string(),
            target_triple: "x86_64".to_string(),
            build_timestamp: "now".to_string(),
            profile: "release".to_string(),
            git_commit: None,
            git_dirty: None,
            features: vec![],
            build_env: std::collections::HashMap::new(),
            cargo_flags: vec![],
        };
        let cloned = meta.clone();
        assert_eq!(cloned.rust_version, meta.rust_version);
    }
}
