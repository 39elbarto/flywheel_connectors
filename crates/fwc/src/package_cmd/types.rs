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
            tool: "fwc".to_string(),
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
            tool: "fwc".to_string(),
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
            tool: "fwc".to_string(),
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
            tool: "fwc".to_string(),
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
            tool: "fwc 0.5.0".to_string(),
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
        assert_eq!(back.tool, "fwc 0.5.0");
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
            tool: "fwc".to_string(),
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

    // ── PackageOutput JSON shape: field types ────────────────

    #[test]
    fn package_output_all_string_fields_are_json_strings() {
        let output = PackageOutput {
            output_dir: PathBuf::from("/a"),
            binary_path: PathBuf::from("/b"),
            manifest_path: PathBuf::from("/c"),
            sbom_path: Some(PathBuf::from("/d")),
            build_metadata_path: PathBuf::from("/e"),
            binary_sha256: "fff".to_string(),
            connector_id: "x:y:1".to_string(),
            version: "1".to_string(),
        };
        let v: serde_json::Value = serde_json::to_value(&output).unwrap();
        assert!(v["binary_sha256"].is_string());
        assert!(v["connector_id"].is_string());
        assert!(v["version"].is_string());
        assert!(v["sbom_path"].is_string());
    }

    #[test]
    fn package_output_deserialize_unknown_fields_ignored() {
        // serde default: unknown fields are ignored during deserialization
        let json = r#"{
            "output_dir": "/tmp",
            "binary_path": "/tmp/bin",
            "manifest_path": "/tmp/m.toml",
            "build_metadata_path": "/tmp/b.json",
            "binary_sha256": "abc",
            "connector_id": "c:t:1",
            "version": "1.0.0",
            "extra_field": "should be ignored",
            "another_extra": 42
        }"#;
        let output: PackageOutput = serde_json::from_str(json).unwrap();
        assert_eq!(output.connector_id, "c:t:1");
    }

    // ── BuildMetadata edge cases ─────────────────────────────

    #[test]
    fn build_metadata_all_optional_none_roundtrip() {
        let meta = BuildMetadata {
            rust_version: String::new(),
            cargo_version: String::new(),
            target_triple: String::new(),
            build_timestamp: String::new(),
            profile: String::new(),
            git_commit: None,
            git_dirty: None,
            features: vec![],
            build_env: std::collections::HashMap::new(),
            cargo_flags: vec![],
        };
        let json = serde_json::to_string(&meta).unwrap();
        let back: BuildMetadata = serde_json::from_str(&json).unwrap();
        assert!(back.rust_version.is_empty());
        assert!(back.git_commit.is_none());
        assert!(back.git_dirty.is_none());
    }

    #[test]
    fn build_metadata_many_env_vars() {
        let mut env = std::collections::HashMap::new();
        for i in 0..50 {
            env.insert(format!("VAR_{i}"), format!("value_{i}"));
        }
        let meta = BuildMetadata {
            rust_version: "1.85.0".to_string(),
            cargo_version: "1.85.0".to_string(),
            target_triple: "x86_64".to_string(),
            build_timestamp: "now".to_string(),
            profile: "release".to_string(),
            git_commit: None,
            git_dirty: None,
            features: vec![],
            build_env: env,
            cargo_flags: vec![],
        };
        let json = serde_json::to_string(&meta).unwrap();
        let back: BuildMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(back.build_env.len(), 50);
        assert_eq!(back.build_env["VAR_0"], "value_0");
        assert_eq!(back.build_env["VAR_49"], "value_49");
    }

    #[test]
    fn build_metadata_env_vars_with_special_chars() {
        let mut env = std::collections::HashMap::new();
        env.insert(
            "RUSTFLAGS".to_string(),
            "-C link-arg=-Wl,--no-as-needed -ldl".to_string(),
        );
        env.insert(
            "CARGO_ENCODED_RUSTFLAGS".to_string(),
            "-Cdebuginfo=0\x1f-Csplit-debuginfo=off".to_string(),
        );
        let meta = BuildMetadata {
            rust_version: "1.85.0".to_string(),
            cargo_version: "1.85.0".to_string(),
            target_triple: "x86_64".to_string(),
            build_timestamp: "now".to_string(),
            profile: "release".to_string(),
            git_commit: None,
            git_dirty: None,
            features: vec![],
            build_env: env,
            cargo_flags: vec![],
        };
        let json = serde_json::to_string(&meta).unwrap();
        let back: BuildMetadata = serde_json::from_str(&json).unwrap();
        assert!(back.build_env["RUSTFLAGS"].contains("--no-as-needed"));
    }

    #[test]
    fn build_metadata_many_features() {
        let features: Vec<String> = (0..20).map(|i| format!("feature_{i}")).collect();
        let meta = BuildMetadata {
            rust_version: "1.85.0".to_string(),
            cargo_version: "1.85.0".to_string(),
            target_triple: "x86_64".to_string(),
            build_timestamp: "now".to_string(),
            profile: "release".to_string(),
            git_commit: None,
            git_dirty: None,
            features,
            build_env: std::collections::HashMap::new(),
            cargo_flags: vec![],
        };
        let json = serde_json::to_string(&meta).unwrap();
        let back: BuildMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(back.features.len(), 20);
        assert_eq!(back.features[0], "feature_0");
        assert_eq!(back.features[19], "feature_19");
    }

    #[test]
    fn build_metadata_pretty_json_contains_all_keys() {
        let meta = BuildMetadata {
            rust_version: "1.85.0".to_string(),
            cargo_version: "1.85.0".to_string(),
            target_triple: "x86_64".to_string(),
            build_timestamp: "now".to_string(),
            profile: "release".to_string(),
            git_commit: Some("abc".to_string()),
            git_dirty: Some(true),
            features: vec![],
            build_env: std::collections::HashMap::new(),
            cargo_flags: vec![],
        };
        let json = serde_json::to_string_pretty(&meta).unwrap();
        assert!(json.contains("rust_version"));
        assert!(json.contains("cargo_version"));
        assert!(json.contains("target_triple"));
        assert!(json.contains("build_timestamp"));
        assert!(json.contains("profile"));
        assert!(json.contains("git_commit"));
        assert!(json.contains("git_dirty"));
        assert!(json.contains("features"));
        assert!(json.contains("build_env"));
        assert!(json.contains("cargo_flags"));
    }

    // ── SimpleSbom edge cases ────────────────────────────────

    #[test]
    fn simple_sbom_many_dependencies() {
        let deps: Vec<SbomDependency> = (0..100)
            .map(|i| SbomDependency {
                name: format!("crate-{i}"),
                version: format!("{i}.0.0"),
                purl: format!("pkg:cargo/crate-{i}@{i}.0.0"),
                source: "crates.io".to_string(),
            })
            .collect();
        let sbom = SimpleSbom {
            format_version: "1.0".to_string(),
            created: "2026-01-01T00:00:00Z".to_string(),
            tool: "fwc 1.0.0".to_string(),
            component: SbomComponent {
                component_type: "application".to_string(),
                name: "big-conn".to_string(),
                version: "1.0.0".to_string(),
                purl: "pkg:fcp/big-conn@1.0.0".to_string(),
            },
            dependencies: deps,
        };
        let json = serde_json::to_string(&sbom).unwrap();
        let back: SimpleSbom = serde_json::from_str(&json).unwrap();
        assert_eq!(back.dependencies.len(), 100);
        assert_eq!(back.dependencies[0].name, "crate-0");
        assert_eq!(back.dependencies[99].name, "crate-99");
    }

    #[test]
    fn simple_sbom_json_shape() {
        let sbom = SimpleSbom {
            format_version: "1.0".to_string(),
            created: "2026-01-01T00:00:00Z".to_string(),
            tool: "fwc".to_string(),
            component: SbomComponent {
                component_type: "application".to_string(),
                name: "test".to_string(),
                version: "1.0.0".to_string(),
                purl: "pkg:fcp/test@1.0.0".to_string(),
            },
            dependencies: vec![],
        };
        let v: serde_json::Value = serde_json::to_value(&sbom).unwrap();
        assert!(v["format_version"].is_string());
        assert!(v["created"].is_string());
        assert!(v["tool"].is_string());
        assert!(v["component"].is_object());
        assert!(v["dependencies"].is_array());
    }

    #[test]
    fn simple_sbom_component_is_nested_object() {
        let sbom = SimpleSbom {
            format_version: "1.0".to_string(),
            created: "2026-01-01T00:00:00Z".to_string(),
            tool: "fwc".to_string(),
            component: SbomComponent {
                component_type: "application".to_string(),
                name: "nested-test".to_string(),
                version: "2.0.0".to_string(),
                purl: "pkg:fcp/nested-test@2.0.0".to_string(),
            },
            dependencies: vec![],
        };
        let v: serde_json::Value = serde_json::to_value(&sbom).unwrap();
        let comp = v["component"].as_object().unwrap();
        assert_eq!(comp["component_type"].as_str().unwrap(), "application");
        assert_eq!(comp["name"].as_str().unwrap(), "nested-test");
        assert_eq!(comp["version"].as_str().unwrap(), "2.0.0");
        assert!(comp["purl"].as_str().unwrap().starts_with("pkg:fcp/"));
    }

    // ── SbomDependency edge cases ────────────────────────────

    #[test]
    fn sbom_dependency_empty_strings() {
        let dep = SbomDependency {
            name: String::new(),
            version: String::new(),
            purl: String::new(),
            source: String::new(),
        };
        let json = serde_json::to_string(&dep).unwrap();
        let back: SbomDependency = serde_json::from_str(&json).unwrap();
        assert!(back.name.is_empty());
        assert!(back.version.is_empty());
    }

    #[test]
    fn sbom_dependency_json_field_count() {
        let dep = SbomDependency {
            name: "serde".to_string(),
            version: "1.0.0".to_string(),
            purl: "pkg:cargo/serde@1.0.0".to_string(),
            source: "crates.io".to_string(),
        };
        let v: serde_json::Value = serde_json::to_value(&dep).unwrap();
        assert_eq!(v.as_object().unwrap().len(), 4);
    }

    #[test]
    fn sbom_dependency_registry_source() {
        let dep = SbomDependency {
            name: "my-lib".to_string(),
            version: "0.3.0".to_string(),
            purl: "pkg:cargo/my-lib@0.3.0".to_string(),
            source: "registry+https://github.com/rust-lang/crates.io-index".to_string(),
        };
        let json = serde_json::to_string(&dep).unwrap();
        let back: SbomDependency = serde_json::from_str(&json).unwrap();
        assert!(back.source.starts_with("registry+"));
    }

    // ── SbomComponent edge cases ─────────────────────────────

    #[test]
    fn sbom_component_json_field_count() {
        let comp = SbomComponent {
            component_type: "application".to_string(),
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            purl: "pkg:fcp/test@1.0.0".to_string(),
        };
        let v: serde_json::Value = serde_json::to_value(&comp).unwrap();
        assert_eq!(v.as_object().unwrap().len(), 4);
    }

    #[test]
    fn sbom_component_non_application_type() {
        let comp = SbomComponent {
            component_type: "library".to_string(),
            name: "shared-lib".to_string(),
            version: "0.5.0".to_string(),
            purl: "pkg:cargo/shared-lib@0.5.0".to_string(),
        };
        let json = serde_json::to_string(&comp).unwrap();
        let back: SbomComponent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.component_type, "library");
    }

    #[test]
    fn sbom_component_empty_fields_roundtrip() {
        let comp = SbomComponent {
            component_type: String::new(),
            name: String::new(),
            version: String::new(),
            purl: String::new(),
        };
        let json = serde_json::to_string(&comp).unwrap();
        let back: SbomComponent = serde_json::from_str(&json).unwrap();
        assert!(back.component_type.is_empty());
        assert!(back.name.is_empty());
    }

    // ── OutputFormat variant coverage ────────────────────────

    #[test]
    fn output_format_copy_semantics() {
        let a = OutputFormat::Human;
        let b = a; // Copy
        let _c = a; // Can still use `a` after copy
        assert!(matches!(b, OutputFormat::Human));
    }

    #[test]
    fn output_format_json_debug_stable() {
        let fmt = OutputFormat::Json;
        let d1 = format!("{fmt:?}");
        let d2 = format!("{fmt:?}");
        assert_eq!(d1, d2);
    }

    #[test]
    fn output_format_human_debug_stable() {
        let fmt = OutputFormat::Human;
        let d1 = format!("{fmt:?}");
        let d2 = format!("{fmt:?}");
        assert_eq!(d1, d2);
    }

    // ── PackageArgs edge cases ───────────────────────────────

    #[test]
    fn package_args_empty_cargo_flags() {
        let args = PackageArgs {
            path: PathBuf::from("."),
            output: None,
            skip_sbom: false,
            release: true,
            cargo_flags: vec![],
            format: OutputFormat::Human,
        };
        assert!(args.cargo_flags.is_empty());
    }

    #[test]
    fn package_args_many_cargo_flags() {
        let args = PackageArgs {
            path: PathBuf::from("."),
            output: None,
            skip_sbom: false,
            release: true,
            cargo_flags: vec![
                "--locked".to_string(),
                "--target".to_string(),
                "x86_64-unknown-linux-gnu".to_string(),
                "--features".to_string(),
                "tls,compression".to_string(),
                "--no-default-features".to_string(),
            ],
            format: OutputFormat::Json,
        };
        assert_eq!(args.cargo_flags.len(), 6);
    }

    #[test]
    fn package_args_skip_sbom_true() {
        let args = PackageArgs {
            path: PathBuf::from("/project"),
            output: Some(PathBuf::from("/out")),
            skip_sbom: true,
            release: true,
            cargo_flags: vec![],
            format: OutputFormat::Human,
        };
        assert!(args.skip_sbom);
        assert!(args.output.is_some());
    }

    #[test]
    fn package_args_debug_format_contains_all_fields() {
        let args = PackageArgs {
            path: PathBuf::from("/my/project"),
            output: Some(PathBuf::from("/my/output")),
            skip_sbom: true,
            release: false,
            cargo_flags: vec!["--locked".to_string()],
            format: OutputFormat::Json,
        };
        let dbg = format!("{args:?}");
        assert!(dbg.contains("skip_sbom"));
        assert!(dbg.contains("release"));
        assert!(dbg.contains("cargo_flags"));
        assert!(dbg.contains("format"));
    }

    #[test]
    fn package_args_clone_independence() {
        let args = PackageArgs {
            path: PathBuf::from("/p"),
            output: Some(PathBuf::from("/o")),
            skip_sbom: false,
            release: true,
            cargo_flags: vec!["--release".to_string()],
            format: OutputFormat::Json,
        };
        let mut cloned = args.clone();
        cloned.cargo_flags.push("--locked".to_string());
        // Original should be unaffected
        assert_eq!(args.cargo_flags.len(), 1);
        assert_eq!(cloned.cargo_flags.len(), 2);
    }

    // ── BuildMetadata deserialization with extra fields ──────

    #[test]
    fn build_metadata_deserialize_unknown_fields_ignored() {
        let json = r#"{
            "rust_version": "1.85.0",
            "cargo_version": "1.85.0",
            "target_triple": "x86_64",
            "build_timestamp": "now",
            "profile": "debug",
            "features": [],
            "build_env": {},
            "cargo_flags": [],
            "unknown_field": "should be ignored",
            "another_unknown": 123
        }"#;
        let meta: BuildMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(meta.rust_version, "1.85.0");
    }

    // ── PackageOutput: large hash and id values ──────────────

    #[test]
    fn package_output_long_connector_id() {
        let long_id = format!("org.{}:conn:1.0.0", "x".repeat(500));
        let output = PackageOutput {
            output_dir: PathBuf::from("/a"),
            binary_path: PathBuf::from("/b"),
            manifest_path: PathBuf::from("/c"),
            sbom_path: None,
            build_metadata_path: PathBuf::from("/d"),
            binary_sha256: "abc".to_string(),
            connector_id: long_id.clone(),
            version: "1.0.0".to_string(),
        };
        let json = serde_json::to_string(&output).unwrap();
        let back: PackageOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(back.connector_id, long_id);
    }

    #[test]
    fn package_output_version_zero() {
        let output = PackageOutput {
            output_dir: PathBuf::from("/a"),
            binary_path: PathBuf::from("/b"),
            manifest_path: PathBuf::from("/c"),
            sbom_path: None,
            build_metadata_path: PathBuf::from("/d"),
            binary_sha256: "abc".to_string(),
            connector_id: "c:t:0.0.0".to_string(),
            version: "0.0.0".to_string(),
        };
        let json = serde_json::to_string(&output).unwrap();
        let back: PackageOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(back.version, "0.0.0");
    }

    // ── SimpleSbom deserialization edge cases ─────────────────

    #[test]
    fn simple_sbom_deserialize_extra_fields_ignored() {
        let json = r#"{
            "format_version": "1.0",
            "created": "2026-01-01T00:00:00Z",
            "tool": "fwc",
            "component": {
                "component_type": "application",
                "name": "test",
                "version": "1.0.0",
                "purl": "pkg:fcp/test@1.0.0",
                "extra": "ignored"
            },
            "dependencies": [],
            "extra_top": true
        }"#;
        let sbom: SimpleSbom = serde_json::from_str(json).unwrap();
        assert_eq!(sbom.component.name, "test");
    }

    #[test]
    fn simple_sbom_dep_order_preserved() {
        let deps = vec![
            SbomDependency {
                name: "zzz".to_string(),
                version: "1.0.0".to_string(),
                purl: "pkg:cargo/zzz@1.0.0".to_string(),
                source: "crates.io".to_string(),
            },
            SbomDependency {
                name: "aaa".to_string(),
                version: "2.0.0".to_string(),
                purl: "pkg:cargo/aaa@2.0.0".to_string(),
                source: "crates.io".to_string(),
            },
        ];
        let sbom = SimpleSbom {
            format_version: "1.0".to_string(),
            created: "now".to_string(),
            tool: "fwc".to_string(),
            component: SbomComponent {
                component_type: "application".to_string(),
                name: "t".to_string(),
                version: "1".to_string(),
                purl: "pkg:fcp/t@1".to_string(),
            },
            dependencies: deps,
        };
        let json = serde_json::to_string(&sbom).unwrap();
        let back: SimpleSbom = serde_json::from_str(&json).unwrap();
        // Order is preserved
        assert_eq!(back.dependencies[0].name, "zzz");
        assert_eq!(back.dependencies[1].name, "aaa");
    }

    // ── Cross-type consistency ───────────────────────────────

    #[test]
    fn sbom_dependency_purl_format_consistency() {
        let dep = SbomDependency {
            name: "my-crate".to_string(),
            version: "3.2.1".to_string(),
            purl: format!("pkg:cargo/{}@{}", "my-crate", "3.2.1"),
            source: "crates.io".to_string(),
        };
        assert!(dep.purl.starts_with("pkg:cargo/"));
        assert!(dep.purl.contains('@'));
        assert!(dep.purl.contains(&dep.name));
        assert!(dep.purl.contains(&dep.version));
    }

    #[test]
    fn sbom_component_purl_format_consistency() {
        let comp = SbomComponent {
            component_type: "application".to_string(),
            name: "my-conn".to_string(),
            version: "1.0.0".to_string(),
            purl: format!("pkg:fcp/{}@{}", "my-conn", "1.0.0"),
        };
        assert!(comp.purl.starts_with("pkg:fcp/"));
        assert!(comp.purl.contains('@'));
        assert!(comp.purl.contains(&comp.name));
        assert!(comp.purl.contains(&comp.version));
    }
}
