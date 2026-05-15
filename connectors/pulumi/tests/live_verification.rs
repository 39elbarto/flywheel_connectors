//! Gated sandbox live verification for the FCP Pulumi connector.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use std::{env, fs, path::PathBuf, process::Command};

use fcp_pulumi::connector::PulumiConnector;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const ACCESS_TOKEN_ENV: &str = "PULUMI_SANDBOX_ACCESS_TOKEN";
const ORGANIZATION_ENV: &str = "PULUMI_SANDBOX_ORG";
const PROJECT_ENV: &str = "PULUMI_SANDBOX_PROJECT";
const STACK_ENV: &str = "PULUMI_SANDBOX_STACK";
const RUN_NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const BASE_URL_ENV: &str = "PULUMI_SANDBOX_BASE_URL";
const CLI_ENV: &str = "PULUMI_SANDBOX_CLI";
const DEFAULT_BASE_URL: &str = "https://api.pulumi.com/api";
const LIVE_COMMAND: &str =
    "rch exec -- cargo test -p fcp-pulumi --test live_verification -- --nocapture";
const REQUIRED_ENV: [&str; 5] = [
    ACCESS_TOKEN_ENV,
    ORGANIZATION_ENV,
    PROJECT_ENV,
    STACK_ENV,
    RUN_NAMESPACE_ENV,
];
const CALL_CEILING: usize = 4;

fn env_value(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn live_gate_enabled() -> bool {
    env_value(LIVE_GATE_ENV).is_some_and(|value| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn emit_live_jsonl(
    status: &str,
    reason: &str,
    observed_count: usize,
    auth_denial_verified: bool,
    evidence: &Value,
) {
    eprintln!(
        "PULUMI_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "pulumi_live_sandbox_stack_read",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": [ACCESS_TOKEN_ENV],
            "required_env": [ORGANIZATION_ENV, PROJECT_ENV, STACK_ENV, RUN_NAMESPACE_ENV],
            "defaulted_env": BASE_URL_ENV,
            "command": LIVE_COMMAND,
            "git_revision": option_env!("FCP_LIVE_GIT_REVISION").unwrap_or("unknown"),
            "operation": [
                "auth-denial",
                "pulumi.stacks.get",
                "pulumi.deployments.list",
                "pulumi.preview"
            ],
            "status": status,
            "provider": "Pulumi Cloud sandbox",
            "environment": "sandbox",
            "resource_class": "sandbox_stack_metadata",
            "observed_count": observed_count,
            "call_ceiling": CALL_CEILING,
            "rate_limit_guidance": "Performs one invalid-token stack read, one sandbox stack metadata read, one update-history read, and one Pulumi CLI preview against the sandbox stack.",
            "mutation_expected": false,
            "cleanup_strategy": "preview_only_no_provider_mutation",
            "cleanup_result": "preview_only_no_cleanup_required",
            "request_category": [
                "auth-denial",
                "stack.metadata_read",
                "stack.update_history_read",
                "cli.preview"
            ],
            "auth_denial_verified": auth_denial_verified,
            "organization_logged": false,
            "project_logged": false,
            "stack_logged": false,
            "provider_resource_ids_logged": false,
            "secret_values_logged": false,
            "skip_reason": if status == "skipped" { Some(reason) } else { None },
            "fcp_error_mapping": if status == "failed" { Some(reason) } else { None },
            "evidence": evidence,
        })
    );
}

fn print_skip(reason: &str, missing_env: &[&str]) {
    emit_live_jsonl(
        "skipped",
        reason,
        0,
        false,
        &json!({
            "missing_env": missing_env,
            "live_gate_enabled": live_gate_enabled(),
        }),
    );
}

fn redacted_hash(value: &str) -> String {
    format!("sha256:{}", short_hash(value))
}

fn short_hash(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    let encoded = hex::encode(digest);
    encoded.chars().take(16).collect::<String>()
}

async fn configured_connector(access_token: &str, base_url: &str) -> PulumiConnector {
    let mut connector = PulumiConnector::new();
    connector
        .handle_configure(json!({
            "access_token": access_token,
            "base_url": base_url
        }))
        .await
        .expect("configure Pulumi live connector");
    connector
        .handle_handshake(json!({"session_id": "live-sandbox"}))
        .await
        .expect("handshake Pulumi live connector");
    connector
}

async fn invalid_token_is_denied(
    base_url: &str,
    organization: &str,
    project: &str,
    stack: &str,
) -> bool {
    let connector = configured_connector("pul-invalid-fcp-sandbox-token", base_url).await;
    connector
        .handle_invoke(json!({
            "operation_id": "pulumi.stacks.get",
            "input": {
                "organization": organization,
                "project": project,
                "stack": stack
            }
        }))
        .await
        .is_err()
}

fn preview_workdir(project: &str, stack: &str, run_namespace: &str) -> Result<PathBuf, String> {
    let dir = env::temp_dir().join(format!(
        "fcp-pulumi-live-preview-{}",
        short_hash(&format!("{project}:{stack}:{run_namespace}"))
    ));
    fs::create_dir_all(&dir)
        .map_err(|error| format!("failed to create Pulumi preview workdir: {error}"))?;
    let project_yaml = format!(
        "name: {project}\nruntime: yaml\ndescription: FCP Pulumi live sandbox preview fixture\nresources: {{}}\n"
    );
    fs::write(dir.join("Pulumi.yaml"), project_yaml)
        .map_err(|error| format!("failed to write Pulumi.yaml: {error}"))?;
    Ok(dir)
}

fn pulumi_cli_available(cli: &str) -> bool {
    Command::new(cli)
        .arg("version")
        .env("PULUMI_SKIP_UPDATE_CHECK", "true")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn run_pulumi_preview(
    cli: &str,
    access_token: &str,
    organization: &str,
    project: &str,
    stack: &str,
    run_namespace: &str,
) -> Result<Value, String> {
    let workdir = preview_workdir(project, stack, run_namespace)?;
    let stack_ref = format!("{organization}/{project}/{stack}");
    let output = Command::new(cli)
        .arg("preview")
        .arg("--stack")
        .arg(&stack_ref)
        .arg("--non-interactive")
        .arg("--refresh=false")
        .arg("--expect-no-changes")
        .arg("--suppress-outputs")
        .current_dir(&workdir)
        .env("PULUMI_ACCESS_TOKEN", access_token)
        .env("PULUMI_CI", "true")
        .env("PULUMI_CONFIG_PASSPHRASE", "")
        .env("PULUMI_SKIP_UPDATE_CHECK", "true")
        .output()
        .map_err(|error| format!("failed to execute pulumi preview: {error}"))?;

    if !output.status.success() {
        let stdout_hash = redacted_hash(&String::from_utf8_lossy(&output.stdout));
        let stderr_hash = redacted_hash(&String::from_utf8_lossy(&output.stderr));
        return Err(format!(
            "pulumi preview failed with status {:?}; stdout_hash={stdout_hash}; stderr_hash={stderr_hash}",
            output.status.code()
        ));
    }

    Ok(json!({
        "cli_path_hash": redacted_hash(cli),
        "workdir_hash": redacted_hash(&workdir.display().to_string()),
        "stack_ref_hash": redacted_hash(&stack_ref),
        "exit_code": output.status.code(),
        "stdout_hash": redacted_hash(&String::from_utf8_lossy(&output.stdout)),
        "stderr_hash": redacted_hash(&String::from_utf8_lossy(&output.stderr)),
        "preview_mode": "expect_no_changes_refresh_false",
    }))
}

#[fcp_async_core::runtime::test]
async fn gated_sandbox_stack_read_and_auth_denial() {
    if !live_gate_enabled() {
        print_skip("live gate disabled", &[LIVE_GATE_ENV]);
        return;
    }

    let missing_env = REQUIRED_ENV
        .iter()
        .copied()
        .filter(|name| env_value(name).is_none())
        .collect::<Vec<_>>();
    if !missing_env.is_empty() {
        print_skip("required sandbox environment missing", &missing_env);
        return;
    }

    let access_token = env_value(ACCESS_TOKEN_ENV).expect("checked access token env");
    let organization = env_value(ORGANIZATION_ENV).expect("checked organization env");
    let project = env_value(PROJECT_ENV).expect("checked project env");
    let stack = env_value(STACK_ENV).expect("checked stack env");
    let run_namespace = env_value(RUN_NAMESPACE_ENV).expect("checked namespace env");
    let base_url = env_value(BASE_URL_ENV).unwrap_or_else(|| DEFAULT_BASE_URL.to_string());
    let cli = env_value(CLI_ENV).unwrap_or_else(|| "pulumi".to_string());

    if !pulumi_cli_available(&cli) {
        emit_live_jsonl(
            "skipped",
            "pulumi_cli_not_available",
            0,
            false,
            &json!({
                "missing_prerequisite": "pulumi_cli",
                "cli_path_hash": redacted_hash(&cli),
                "live_gate_enabled": true,
            }),
        );
        return;
    }

    let auth_denial_verified =
        invalid_token_is_denied(&base_url, &organization, &project, &stack).await;
    assert!(
        auth_denial_verified,
        "Pulumi invalid-token stack read must be denied"
    );

    let connector = configured_connector(&access_token, &base_url).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "pulumi.stacks.get",
            "input": {
                "organization": &organization,
                "project": &project,
                "stack": &stack
            }
        }))
        .await
        .expect("read sandbox Pulumi stack metadata");

    let deployments = connector
        .handle_invoke(json!({
            "operation_id": "pulumi.deployments.list",
            "input": {
                "organization": &organization,
                "project": &project,
                "stack": &stack
            }
        }))
        .await
        .expect("read sandbox Pulumi stack update history");
    let observed_count = deployments
        .get("updates")
        .and_then(Value::as_array)
        .map_or(2, |updates| updates.len().saturating_add(2));
    let preview_evidence = run_pulumi_preview(
        &cli,
        &access_token,
        &organization,
        &project,
        &stack,
        &run_namespace,
    )
    .expect("run Pulumi sandbox preview without provider mutation");

    emit_live_jsonl(
        "passed",
        "",
        observed_count,
        auth_denial_verified,
        &json!({
            "organization_hash": redacted_hash(&organization),
            "project_hash": redacted_hash(&project),
            "stack_hash": redacted_hash(&stack),
            "namespace_hash": redacted_hash(&run_namespace),
            "base_url_hash": redacted_hash(&base_url),
            "base_url_env_present": env_value(BASE_URL_ENV).is_some(),
            "stack_metadata_shape": {
                "object": result.is_object(),
                "has_org_name": result.get("orgName").is_some(),
                "has_project_name": result.get("projectName").is_some(),
                "has_stack_name": result.get("stackName").is_some(),
            },
            "deployments_shape": {
                "object": deployments.is_object(),
                "updates_count": deployments.get("updates").and_then(Value::as_array).map(Vec::len),
            },
            "preview": preview_evidence,
        }),
    );
}
