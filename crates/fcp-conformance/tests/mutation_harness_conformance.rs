//! Conformance ratchet for connector mutation-harness adoption.

use std::path::Path;

const MUTATION_HARNESS_REQUIRED: &[&str] = &["stripe"];

#[test]
fn required_connectors_ship_mutation_harness_tests() {
    let root = repo_root();

    for connector in MUTATION_HARNESS_REQUIRED {
        let test_path = root
            .join("connectors")
            .join(connector)
            .join("tests")
            .join("mutation.rs");
        assert!(
            test_path.exists(),
            "connector `{connector}` is in MUTATION_HARNESS_REQUIRED but lacks {}",
            test_path.display()
        );

        let source = std::fs::read_to_string(&test_path).unwrap_or_else(|err| {
            panic!(
                "failed to read mutation harness test {}: {err}",
                test_path.display()
            )
        });
        assert!(
            source.contains("MutationHarness"),
            "connector `{connector}` mutation test must wire fcp_testkit::MutationHarness"
        );
    }
}

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("fcp-conformance crate should live under crates/")
}
