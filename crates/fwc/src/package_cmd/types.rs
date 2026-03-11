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

    // ---- BuildMetadata git_commit/git_dirty combinations ----

    #[test]
    fn build_metadata_git_commit_only() {
        let meta = BuildMetadata {
            rust_version: "1.85.0".to_string(),
            cargo_version: "1.85.0".to_string(),
            target_triple: "x86_64-unknown-linux-gnu".to_string(),
            build_timestamp: "2026-03-04T00:00:00Z".to_string(),
            profile: "release".to_string(),
            git_commit: Some("deadbeef".to_string()),
            git_dirty: None,
            features: vec![],
            build_env: std::collections::HashMap::new(),
            cargo_flags: vec![],
        };
        let json = serde_json::to_string(&meta).unwrap();
        assert!(json.contains("git_commit"));
        assert!(!json.contains("git_dirty"));
        let back: BuildMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(back.git_commit.as_deref(), Some("deadbeef"));
        assert!(back.git_dirty.is_none());
    }

    #[test]
    fn build_metadata_git_dirty_only() {
        let meta = BuildMetadata {
            rust_version: "1.85.0".to_string(),
            cargo_version: "1.85.0".to_string(),
            target_triple: "x86_64-unknown-linux-gnu".to_string(),
            build_timestamp: "2026-03-04T00:00:00Z".to_string(),
            profile: "release".to_string(),
            git_commit: None,
            git_dirty: Some(true),
            features: vec![],
            build_env: std::collections::HashMap::new(),
            cargo_flags: vec![],
        };
        let json = serde_json::to_string(&meta).unwrap();
        assert!(!json.contains("git_commit"));
        assert!(json.contains("git_dirty"));
        let back: BuildMetadata = serde_json::from_str(&json).unwrap();
        assert!(back.git_commit.is_none());
        assert_eq!(back.git_dirty, Some(true));
    }

    #[test]
    fn build_metadata_git_both_present() {
        let meta = BuildMetadata {
            rust_version: "1.85.0".to_string(),
            cargo_version: "1.85.0".to_string(),
            target_triple: "x86_64-unknown-linux-gnu".to_string(),
            build_timestamp: "2026-03-04T00:00:00Z".to_string(),
            profile: "release".to_string(),
            git_commit: Some("abc123def456".to_string()),
            git_dirty: Some(false),
            features: vec!["default".to_string()],
            build_env: std::collections::HashMap::new(),
            cargo_flags: vec![],
        };
        let json = serde_json::to_string(&meta).unwrap();
        assert!(json.contains("git_commit"));
        assert!(json.contains("git_dirty"));
        let back: BuildMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(back.git_commit.as_deref(), Some("abc123def456"));
        assert_eq!(back.git_dirty, Some(false));
    }

    // ---- BuildMetadata build_env ----

    #[test]
    fn build_metadata_with_env_vars() {
        let mut env = std::collections::HashMap::new();
        env.insert("CARGO_CFG_TARGET_OS".to_string(), "linux".to_string());
        env.insert("RUSTFLAGS".to_string(), "-C opt-level=3".to_string());
        let meta = BuildMetadata {
            rust_version: "1.85.0".to_string(),
            cargo_version: "1.85.0".to_string(),
            target_triple: "x86_64-unknown-linux-gnu".to_string(),
            build_timestamp: "2026-03-04T00:00:00Z".to_string(),
            profile: "release".to_string(),
            git_commit: None,
            git_dirty: None,
            features: vec![],
            build_env: env,
            cargo_flags: vec![],
        };
        let json = serde_json::to_string(&meta).unwrap();
        let back: BuildMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(back.build_env.len(), 2);
        assert_eq!(back.build_env["RUSTFLAGS"], "-C opt-level=3");
    }

    // ---- BuildMetadata features ----

    #[test]
    fn build_metadata_multiple_features() {
        let meta = BuildMetadata {
            rust_version: "1.85.0".to_string(),
            cargo_version: "1.85.0".to_string(),
            target_triple: "aarch64-apple-darwin".to_string(),
            build_timestamp: "2026-03-04T00:00:00Z".to_string(),
            profile: "release".to_string(),
            git_commit: None,
            git_dirty: None,
            features: vec![
                "default".to_string(),
                "tls".to_string(),
                "compression".to_string(),
            ],
            build_env: std::collections::HashMap::new(),
            cargo_flags: vec!["--release".to_string(), "--locked".to_string()],
        };
        let json = serde_json::to_string(&meta).unwrap();
        let back: BuildMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(back.features.len(), 3);
        assert_eq!(back.cargo_flags.len(), 2);
        assert!(back.features.contains(&"tls".to_string()));
    }

    #[test]
    fn build_metadata_debug_format() {
        let meta = BuildMetadata {
            rust_version: "1.85.0".to_string(),
            cargo_version: "1.85.0".to_string(),
            target_triple: "x86_64".to_string(),
            build_timestamp: "now".to_string(),
            profile: "debug".to_string(),
            git_commit: None,
            git_dirty: None,
            features: vec![],
            build_env: std::collections::HashMap::new(),
            cargo_flags: vec![],
        };
        let dbg = format!("{meta:?}");
        assert!(dbg.contains("BuildMetadata"));
        assert!(dbg.contains("debug"));
    }

    // ---- PackageOutput field verification ----

    #[test]
    fn package_output_all_paths_preserved() {
        let output = PackageOutput {
            output_dir: PathBuf::from("/build/out"),
            binary_path: PathBuf::from("/build/out/my-connector.wasm"),
            manifest_path: PathBuf::from("/build/out/manifest.toml"),
            sbom_path: Some(PathBuf::from("/build/out/sbom.json")),
            build_metadata_path: PathBuf::from("/build/out/build-meta.json"),
            binary_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .to_string(),
            connector_id: "acme-storage:s3:2.1.0".to_string(),
            version: "2.1.0".to_string(),
        };
        let json = serde_json::to_string(&output).unwrap();
        let back: PackageOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(back.output_dir, PathBuf::from("/build/out"));
        assert_eq!(
            back.binary_path,
            PathBuf::from("/build/out/my-connector.wasm")
        );
        assert_eq!(
            back.manifest_path,
            PathBuf::from("/build/out/manifest.toml")
        );
        assert_eq!(back.sbom_path, Some(PathBuf::from("/build/out/sbom.json")));
        assert_eq!(
            back.build_metadata_path,
            PathBuf::from("/build/out/build-meta.json")
        );
        assert_eq!(back.binary_sha256.len(), 64);
    }

    #[test]
    fn package_output_clone() {
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
        let cloned = output.clone();
        assert_eq!(cloned.connector_id, output.connector_id);
        assert_eq!(cloned.binary_sha256, output.binary_sha256);
    }

    // ---- SbomComponent ----

    #[test]
    fn sbom_component_serde_roundtrip() {
        let comp = SbomComponent {
            component_type: "application".to_string(),
            name: "my-connector".to_string(),
            version: "1.2.3".to_string(),
            purl: "pkg:cargo/my-connector@1.2.3".to_string(),
        };
        let json = serde_json::to_string(&comp).unwrap();
        let back: SbomComponent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.component_type, "application");
        assert_eq!(back.name, "my-connector");
        assert_eq!(back.version, "1.2.3");
        assert!(back.purl.starts_with("pkg:cargo/"));
    }

    #[test]
    fn sbom_component_debug_clone() {
        let comp = SbomComponent {
            component_type: "library".to_string(),
            name: "lib-a".to_string(),
            version: "0.1.0".to_string(),
            purl: "pkg:cargo/lib-a@0.1.0".to_string(),
        };
        let dbg = format!("{comp:?}");
        assert!(dbg.contains("SbomComponent"));
        assert_eq!(comp.name, "lib-a");
    }

    // ---- SbomDependency ----

    #[test]
    fn sbom_dependency_serde_roundtrip() {
        let dep = SbomDependency {
            name: "tokio".to_string(),
            version: "1.40.0".to_string(),
            purl: "pkg:cargo/tokio@1.40.0".to_string(),
            source: "crates.io".to_string(),
        };
        let json = serde_json::to_string(&dep).unwrap();
        let back: SbomDependency = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "tokio");
        assert_eq!(back.source, "crates.io");
    }

    #[test]
    fn sbom_dependency_git_source() {
        let dep = SbomDependency {
            name: "custom-lib".to_string(),
            version: "0.5.0".to_string(),
            purl: "pkg:cargo/custom-lib@0.5.0".to_string(),
            source: "git+https://github.com/org/custom-lib".to_string(),
        };
        let json = serde_json::to_string(&dep).unwrap();
        let back: SbomDependency = serde_json::from_str(&json).unwrap();
        assert!(back.source.starts_with("git+"));
    }

    #[test]
    fn sbom_dependency_path_source() {
        let dep = SbomDependency {
            name: "local-lib".to_string(),
            version: "0.1.0".to_string(),
            purl: "pkg:cargo/local-lib@0.1.0".to_string(),
            source: "path+../local-lib".to_string(),
        };
        let json = serde_json::to_string(&dep).unwrap();
        let back: SbomDependency = serde_json::from_str(&json).unwrap();
        assert!(back.source.starts_with("path+"));
    }

    #[test]
    fn sbom_dependency_debug_clone() {
        let dep = SbomDependency {
            name: "serde".to_string(),
            version: "1.0.200".to_string(),
            purl: "pkg:cargo/serde@1.0.200".to_string(),
            source: "crates.io".to_string(),
        };
        let dbg = format!("{dep:?}");
        assert!(dbg.contains("SbomDependency"));
        assert_eq!(dep.version, "1.0.200");
    }

    // ---- SimpleSbom multiple deps ----

    #[test]
    fn simple_sbom_multiple_dependencies() {
        let sbom = SimpleSbom {
            format_version: "1.0".to_string(),
            created: "2026-03-04T00:00:00Z".to_string(),
            tool: "fcp-cli".to_string(),
            component: SbomComponent {
                component_type: "application".to_string(),
                name: "my-connector".to_string(),
                version: "2.0.0".to_string(),
                purl: "pkg:cargo/my-connector@2.0.0".to_string(),
            },
            dependencies: vec![
                SbomDependency {
                    name: "serde".to_string(),
                    version: "1.0.200".to_string(),
                    purl: "pkg:cargo/serde@1.0.200".to_string(),
                    source: "crates.io".to_string(),
                },
                SbomDependency {
                    name: "tokio".to_string(),
                    version: "1.40.0".to_string(),
                    purl: "pkg:cargo/tokio@1.40.0".to_string(),
                    source: "crates.io".to_string(),
                },
                SbomDependency {
                    name: "internal-utils".to_string(),
                    version: "0.3.0".to_string(),
                    purl: "pkg:cargo/internal-utils@0.3.0".to_string(),
                    source: "path+../internal-utils".to_string(),
                },
            ],
        };
        let json = serde_json::to_string(&sbom).unwrap();
        let back: SimpleSbom = serde_json::from_str(&json).unwrap();
        assert_eq!(back.dependencies.len(), 3);
        assert!(back.dependencies.iter().any(|d| d.name == "tokio"));
        assert!(
            back.dependencies
                .iter()
                .any(|d| d.source.starts_with("path+"))
        );
    }

    #[test]
    fn simple_sbom_debug_clone() {
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
        let dbg = format!("{sbom:?}");
        assert!(dbg.contains("SimpleSbom"));
        assert_eq!(sbom.format_version, "1.0");
    }

    // ---- OutputFormat ----

    #[test]
    fn output_format_debug() {
        let human = OutputFormat::Human;
        let json = OutputFormat::Json;
        assert!(format!("{human:?}").contains("Human"));
        assert!(format!("{json:?}").contains("Json"));
    }

    // ---- JSON deserialization with extra fields (forward compat) ----

    #[test]
    fn package_output_deserialize_missing_optional() {
        // Simulate JSON without sbom_path (skip_serializing_if = None)
        let json = r#"{
            "output_dir": "/tmp",
            "binary_path": "/tmp/bin",
            "manifest_path": "/tmp/m.toml",
            "build_metadata_path": "/tmp/b.json",
            "binary_sha256": "abc",
            "connector_id": "c:t:1",
            "version": "1.0.0"
        }"#;
        let output: PackageOutput = serde_json::from_str(json).unwrap();
        assert!(output.sbom_path.is_none());
    }

    #[test]
    fn build_metadata_deserialize_no_git_fields() {
        let json = r#"{
            "rust_version": "1.85.0",
            "cargo_version": "1.85.0",
            "target_triple": "x86_64",
            "build_timestamp": "now",
            "profile": "debug",
            "features": [],
            "build_env": {},
            "cargo_flags": []
        }"#;
        let meta: BuildMetadata = serde_json::from_str(json).unwrap();
        assert!(meta.git_commit.is_none());
        assert!(meta.git_dirty.is_none());
    }

    // ---- PackageArgs ----

    #[test]
    fn package_args_debug() {
        let args = PackageArgs {
            path: PathBuf::from("."),
            output: None,
            skip_sbom: false,
            release: true,
            cargo_flags: vec![],
            format: OutputFormat::Human,
        };
        let dbg = format!("{args:?}");
        assert!(dbg.contains("PackageArgs"));
        assert!(dbg.contains("release: true"));
    }

    #[test]
    fn package_args_clone() {
        let args = PackageArgs {
            path: PathBuf::from("/my/project"),
            output: Some(PathBuf::from("/out")),
            skip_sbom: true,
            release: false,
            cargo_flags: vec!["--locked".to_string()],
            format: OutputFormat::Json,
        };
        let cloned = args.clone();
        assert_eq!(args.path, PathBuf::from("/my/project"));
        assert_eq!(cloned.output, Some(PathBuf::from("/out")));
        assert!(cloned.skip_sbom);
        assert!(!cloned.release);
        assert_eq!(cloned.cargo_flags, vec!["--locked"]);
    }

    #[test]
    fn package_args_default_values() {
        let args = PackageArgs {
            path: PathBuf::from("."),
            output: None,
            skip_sbom: false,
            release: true,
            cargo_flags: vec![],
            format: OutputFormat::Human,
        };
        assert_eq!(args.path, PathBuf::from("."));
        assert!(args.output.is_none());
        assert!(!args.skip_sbom);
        assert!(args.release);
        assert!(args.cargo_flags.is_empty());
    }

    #[test]
    fn package_args_with_cargo_flags() {
        let args = PackageArgs {
            path: PathBuf::from("connectors/my-conn"),
            output: Some(PathBuf::from("/build/output")),
            skip_sbom: false,
            release: true,
            cargo_flags: vec![
                "--locked".to_string(),
                "--target".to_string(),
                "x86_64-unknown-linux-gnu".to_string(),
            ],
            format: OutputFormat::Json,
        };
        assert_eq!(args.cargo_flags.len(), 3);
    }

    // ---- OutputFormat ----

    #[test]
    fn output_format_clone() {
        let fmt = OutputFormat::Human;
        let cloned = fmt;
        assert!(matches!(cloned, OutputFormat::Human));
    }

    #[test]
    fn output_format_json_variant() {
        let fmt = OutputFormat::Json;
        let dbg = format!("{fmt:?}");
        assert!(dbg.contains("Json"));
    }

    // ---- PackageOutput JSON pretty ----

    #[test]
    fn package_output_json_pretty_contains_all_fields() {
        let output = PackageOutput {
            output_dir: PathBuf::from("/out"),
            binary_path: PathBuf::from("/out/bin"),
            manifest_path: PathBuf::from("/out/manifest.toml"),
            sbom_path: Some(PathBuf::from("/out/sbom.json")),
            build_metadata_path: PathBuf::from("/out/build.json"),
            binary_sha256: "abc123".to_string(),
            connector_id: "test:conn:1.0.0".to_string(),
            version: "1.0.0".to_string(),
        };
        let json = serde_json::to_string_pretty(&output).unwrap();
        assert!(json.contains("output_dir"));
        assert!(json.contains("binary_path"));
        assert!(json.contains("manifest_path"));
        assert!(json.contains("sbom_path"));
        assert!(json.contains("build_metadata_path"));
        assert!(json.contains("binary_sha256"));
        assert!(json.contains("connector_id"));
        assert!(json.contains("version"));
    }

    // ---- BuildMetadata with cargo_flags ----

    #[test]
    fn build_metadata_with_cargo_flags() {
        let meta = BuildMetadata {
            rust_version: "1.85.0".to_string(),
            cargo_version: "1.85.0".to_string(),
            target_triple: "x86_64-unknown-linux-gnu".to_string(),
            build_timestamp: "2026-03-08T00:00:00Z".to_string(),
            profile: "release".to_string(),
            git_commit: None,
            git_dirty: None,
            features: vec![],
            build_env: std::collections::HashMap::new(),
            cargo_flags: vec![
                "--release".to_string(),
                "--locked".to_string(),
                "--target=x86_64-unknown-linux-gnu".to_string(),
            ],
        };
        let json = serde_json::to_string(&meta).unwrap();
        let back: BuildMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(back.cargo_flags.len(), 3);
        assert!(back.cargo_flags.contains(&"--locked".to_string()));
    }

    // ---- SimpleSbom tool field ----

    #[test]
    fn simple_sbom_tool_field_preserved() {
        let sbom = SimpleSbom {
            format_version: "1.0".to_string(),
            created: "2026-03-08T00:00:00Z".to_string(),
            tool: "fcp-cli 0.5.0".to_string(),
            component: SbomComponent {
                component_type: "application".to_string(),
                name: "test-conn".to_string(),
                version: "1.0.0".to_string(),
                purl: "pkg:fcp/test-conn@1.0.0".to_string(),
            },
            dependencies: vec![],
        };
        let json = serde_json::to_string(&sbom).unwrap();
        let back: SimpleSbom = serde_json::from_str(&json).unwrap();
        assert_eq!(back.tool, "fcp-cli 0.5.0");
        assert_eq!(back.format_version, "1.0");
    }

    // ---- SbomComponent purl format ----

    #[test]
    fn sbom_component_purl_fcp_format() {
        let comp = SbomComponent {
            component_type: "application".to_string(),
            name: "weather-api".to_string(),
            version: "2.1.0".to_string(),
            purl: "pkg:fcp/weather-api@2.1.0".to_string(),
        };
        assert!(comp.purl.starts_with("pkg:fcp/"));
        assert!(comp.purl.contains("@2.1.0"));
    }

    // ---- SbomDependency clone ----

    #[test]
    fn sbom_dependency_clone() {
        let dep = SbomDependency {
            name: "anyhow".to_string(),
            version: "1.0.80".to_string(),
            purl: "pkg:cargo/anyhow@1.0.80".to_string(),
            source: "crates.io".to_string(),
        };
        let cloned = dep.clone();
        assert_eq!(cloned.name, dep.name);
        assert_eq!(cloned.version, dep.version);
        assert_eq!(cloned.purl, dep.purl);
        assert_eq!(cloned.source, dep.source);
    }

    // ---- SimpleSbom clone ----

    #[test]
    fn simple_sbom_clone() {
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
            dependencies: vec![SbomDependency {
                name: "serde".to_string(),
                version: "1.0.200".to_string(),
                purl: "pkg:cargo/serde@1.0.200".to_string(),
                source: "crates.io".to_string(),
            }],
        };
        let cloned = sbom.clone();
        assert_eq!(cloned.format_version, sbom.format_version);
        assert_eq!(cloned.component.name, sbom.component.name);
        assert_eq!(cloned.dependencies.len(), sbom.dependencies.len());
    }

    // ---- SbomComponent clone ----

    #[test]
    fn sbom_component_clone() {
        let comp = SbomComponent {
            component_type: "application".to_string(),
            name: "connector-x".to_string(),
            version: "3.0.0".to_string(),
            purl: "pkg:fcp/connector-x@3.0.0".to_string(),
        };
        let cloned = comp.clone();
        assert_eq!(cloned.name, comp.name);
        assert_eq!(cloned.component_type, comp.component_type);
    }
}
