use fcp_chaos::{ChaosScenario, DslError};

fn fixture(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scenarios/_fixtures")
        .join(name);
    std::fs::read_to_string(path).expect("read scenario fixture")
}

#[test]
fn test_valid_minimal_parses() {
    let scenario = ChaosScenario::from_toml_str(&fixture("valid_minimal.toml"))
        .expect("valid minimal scenario");
    assert_eq!(scenario.name, "valid_minimal");
    assert_eq!(scenario.blast_radius, 1);
    assert_eq!(scenario.recovery_objective_secs, 30);
    assert_eq!(scenario.rollback_steps.len(), 1);
}

#[test]
fn test_valid_full_parses_all_fields() {
    let scenario =
        ChaosScenario::from_toml_str(&fixture("valid_full.toml")).expect("valid full scenario");
    assert_eq!(scenario.name, "valid_full");
    assert_eq!(scenario.blast_radius, 3);
    assert_eq!(scenario.recovery_objective_secs, 120);
    assert_eq!(scenario.rollback_steps.len(), 2);
    assert_eq!(
        scenario.rollback_steps[0]
            .args
            .get("peer")
            .map(String::as_str),
        Some("mesh-a")
    );
}

#[test]
fn test_missing_blast_radius_fails() {
    let error = ChaosScenario::from_toml_str(&fixture("missing_blast.toml"))
        .expect_err("missing blast radius must fail");
    assert_eq!(error, DslError::MissingField("blast_radius"));
}

#[test]
fn test_missing_recovery_objective_fails() {
    let error = ChaosScenario::from_toml_str(&fixture("missing_recovery.toml"))
        .expect_err("missing recovery objective must fail");
    assert_eq!(error, DslError::MissingField("recovery_objective_secs"));
}

#[test]
fn test_negative_radius_rejected() {
    let error = ChaosScenario::from_toml_str(&fixture("negative_radius.toml"))
        .expect_err("negative radius must fail");
    assert!(matches!(
        error,
        DslError::InvalidValue {
            field: "blast_radius",
            ..
        }
    ));
}
