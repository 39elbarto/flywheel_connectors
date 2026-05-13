use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use fcp_protocol::architecture::{
    CrateRef, INTEGRATION_GLUE_NARRATIVES, LAYER_COMPONENTS, LAYERS, Layer,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct CargoMetadata {
    packages: Vec<PackageMetadata>,
    workspace_members: Vec<String>,
    workspace_root: PathBuf,
}

#[derive(Debug, Deserialize)]
struct PackageMetadata {
    id: String,
    name: String,
    manifest_path: PathBuf,
    dependencies: Vec<DependencyMetadata>,
}

#[derive(Debug, Deserialize)]
struct DependencyMetadata {
    name: String,
    kind: Option<String>,
    source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PackageLayer {
    name: String,
    layer: Layer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UpwardDependencyViolation {
    from_crate: String,
    to_crate: String,
    from_layer: Layer,
    to_layer: Layer,
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("fcp-conformance lives under crates/")
        .to_path_buf()
}

fn cargo_metadata() -> CargoMetadata {
    let output = Command::new("cargo")
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .current_dir(workspace_root())
        .output()
        .expect("cargo metadata should run");

    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    serde_json::from_slice(&output.stdout).expect("cargo metadata JSON should parse")
}

fn relative_manifest_path(root: &Path, manifest_path: &Path) -> String {
    manifest_path
        .strip_prefix(root)
        .expect("manifest path should be under workspace root")
        .to_string_lossy()
        .replace('\\', "/")
}

fn workspace_packages(metadata: &CargoMetadata) -> Vec<&PackageMetadata> {
    let members: BTreeSet<&str> = metadata
        .workspace_members
        .iter()
        .map(String::as_str)
        .collect();
    metadata
        .packages
        .iter()
        .filter(|package| members.contains(package.id.as_str()))
        .collect()
}

fn layer_matches(package_name: &str, relative_manifest_path: &str) -> Vec<Layer> {
    LAYERS
        .iter()
        .filter_map(|(layer, crate_refs)| {
            crate_refs
                .iter()
                .any(|crate_ref| crate_ref.matches(package_name, relative_manifest_path))
                .then_some(*layer)
        })
        .collect()
}

fn package_layers(metadata: &CargoMetadata) -> BTreeMap<String, PackageLayer> {
    workspace_packages(metadata)
        .into_iter()
        .map(|package| {
            let relative_path =
                relative_manifest_path(&metadata.workspace_root, &package.manifest_path);
            let matches = layer_matches(&package.name, &relative_path);
            assert_eq!(
                matches.len(),
                1,
                "workspace crate `{}` at `{}` must match exactly one layer, got {:?}",
                package.name,
                relative_path,
                matches
            );
            (
                package.name.clone(),
                PackageLayer {
                    name: package.name.clone(),
                    layer: matches[0],
                },
            )
        })
        .collect()
}

fn find_upward_dependency_violations(
    packages: &[PackageMetadata],
    layer_by_crate: &BTreeMap<String, PackageLayer>,
) -> Vec<UpwardDependencyViolation> {
    let mut violations = Vec::new();

    for package in packages {
        let Some(from) = layer_by_crate.get(&package.name) else {
            continue;
        };

        for dependency in &package.dependencies {
            if dependency.kind.is_some() || dependency.source.is_some() {
                continue;
            }

            let Some(to) = layer_by_crate.get(&dependency.name) else {
                continue;
            };

            if to.layer.number() > from.layer.number() {
                violations.push(UpwardDependencyViolation {
                    from_crate: from.name.clone(),
                    to_crate: to.name.clone(),
                    from_layer: from.layer,
                    to_layer: to.layer,
                });
            }
        }
    }

    violations
}

#[test]
fn test_every_workspace_crate_assigned_to_layer() {
    let metadata = cargo_metadata();
    let layers = package_layers(&metadata);
    let workspace_count = workspace_packages(&metadata).len();

    assert_eq!(
        layers.len(),
        workspace_count,
        "every workspace package must have exactly one layer assignment"
    );
}

#[test]
fn test_no_upward_dependency() {
    let metadata = cargo_metadata();
    let layers = package_layers(&metadata);
    let workspace_ids: BTreeSet<&str> = metadata
        .workspace_members
        .iter()
        .map(String::as_str)
        .collect();
    let packages: Vec<PackageMetadata> = metadata
        .packages
        .into_iter()
        .filter(|package| workspace_ids.contains(package.id.as_str()))
        .collect();
    let violations = find_upward_dependency_violations(&packages, &layers);

    assert!(
        violations.is_empty(),
        "layer graph has upward dependencies: {violations:#?}"
    );
}

#[test]
fn test_layer_7_operator_surface() {
    let layer_7 = LAYERS
        .iter()
        .find(|(layer, _)| *layer == Layer::OperatorSurface)
        .expect("operator layer present")
        .1;

    assert!(
        layer_7.contains(&CrateRef::Named("fwc")),
        "fwc must remain in the operator surface layer"
    );
    assert!(LAYER_COMPONENTS.iter().any(|component| {
        component.layer == Layer::OperatorSurface && component.name == "LiveTruthResolver"
    }));
    assert!(LAYER_COMPONENTS.iter().any(|component| {
        component.layer == Layer::OperatorSurface && component.name == "ConformalScore"
    }));
}

#[test]
fn test_layer_1_crypto_hw() {
    let layer_1 = LAYERS
        .iter()
        .find(|(layer, _)| *layer == Layer::CryptoHardware)
        .expect("crypto layer present")
        .1;

    for expected in [
        CrateRef::Named("fcp-crypto"),
        CrateRef::Named("fcp-crypto-hw"),
        CrateRef::Named("fcp-crypto-pq"),
        CrateRef::Planned("fcp-hpke"),
    ] {
        assert!(
            layer_1.contains(&expected),
            "{expected:?} must remain in the crypto/hardware layer"
        );
    }
}

#[test]
fn test_integration_glue_narrative_consumers_documented() {
    let expected_items = [
        "HLC",
        "KZG/IPA vector commits",
        "BLS+FROST+VSS",
        "audit chain",
        "Datalog policy",
    ];

    for expected in expected_items {
        let narrative = INTEGRATION_GLUE_NARRATIVES
            .iter()
            .find(|narrative| narrative.item == expected)
            .unwrap_or_else(|| panic!("missing narrative item `{expected}`"));
        assert!(
            !narrative.consumers.is_empty(),
            "narrative item `{expected}` must document at least one consumer"
        );
    }
}

#[test]
fn test_synthetic_upward_dep_caught() {
    let mut layers = BTreeMap::new();
    layers.insert(
        "lower".to_string(),
        PackageLayer {
            name: "lower".to_string(),
            layer: Layer::StateCommit,
        },
    );
    layers.insert(
        "higher".to_string(),
        PackageLayer {
            name: "higher".to_string(),
            layer: Layer::OperatorSurface,
        },
    );

    let packages = vec![PackageMetadata {
        id: "lower".to_string(),
        name: "lower".to_string(),
        manifest_path: PathBuf::from("crates/lower/Cargo.toml"),
        dependencies: vec![DependencyMetadata {
            name: "higher".to_string(),
            kind: None,
            source: None,
        }],
    }];

    let violations = find_upward_dependency_violations(&packages, &layers);

    assert_eq!(
        violations,
        vec![UpwardDependencyViolation {
            from_crate: "lower".to_string(),
            to_crate: "higher".to_string(),
            from_layer: Layer::StateCommit,
            to_layer: Layer::OperatorSurface,
        }]
    );
}
