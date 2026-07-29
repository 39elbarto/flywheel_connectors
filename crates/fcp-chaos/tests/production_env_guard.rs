use fcp_chaos::{ChaosInjector, Env};

#[test]
#[should_panic(expected = "chaos injector blocked under production")]
fn test_init_panics_under_production_env() {
    let _ = ChaosInjector::from_deploy_mode("production");
}

#[test]
fn test_init_succeeds_under_staging() {
    let injector = ChaosInjector::from_deploy_mode("staging");
    assert_eq!(injector.run_scenario(&scenario()).env, Env::Staging);
}

fn scenario() -> fcp_chaos::ChaosScenario {
    fcp_chaos::ChaosScenario::from_toml_str(
        r#"
name = "production_guard"
blast_radius = 1
recovery_objective_secs = 30

[[rollback_steps]]
name = "restore"
action = "noop"
"#,
    )
    .expect("scenario")
}
