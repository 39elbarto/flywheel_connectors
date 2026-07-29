//! Environment-gated live verification for the `Sentry` connector.

#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc
)]

use fcp_sentry::client::{SentryAuth, SentryClient};
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const AUTH_TOKEN_ENV: &str = "SENTRY_SANDBOX_AUTH_TOKEN";
const ORG_SLUG_ENV: &str = "SENTRY_SANDBOX_ORG";
const PROJECT_SLUG_ENV: &str = "SENTRY_SANDBOX_PROJECT";
const BASE_URL_ENV: &str = "SENTRY_SANDBOX_BASE_URL";
const NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const OP_LIST_PROJECTS: &str = "sentry.projects.list";
const OP_CREATE_RELEASE: &str = "sentry.release.create";
const OP_GET_RELEASE: &str = "sentry.get_release";
const OP_DELETE_RELEASE: &str = "sentry.release.delete";
const CALL_CEILING: usize = 5;
const LIVE_COMMAND: &str =
    "rch exec -- cargo test -p fcp-sentry --test live_verification -- --nocapture";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("sentry", "Sentry sandbox")
        .with_env_secret(
            "auth_token",
            AUTH_TOKEN_ENV,
            "Sentry API token scoped to read projects and create/delete releases in the sandbox organization",
        )
        .with_env_var(
            ORG_SLUG_ENV,
            "Sentry sandbox organization slug used for project listing and release lifecycle proof",
        )
        .with_env_var(
            PROJECT_SLUG_ENV,
            "Sentry sandbox project slug associated with the synthetic release",
        )
        .with_env_var(
            NAMESPACE_ENV,
            "Shared namespace recorded in evidence for any sandbox-side artifacts",
        )
        .with_env_var_default(BASE_URL_ENV, "https://sentry.io/api/0", "Sentry API endpoint")
        .with_account_setup(
            "Use a disposable Sentry organization or sanitized self-hosted instance. Token needs project:read and project:releases or equivalent release scopes for the sandbox project.",
        )
        .with_budget(0.02)
        .with_cleanup(CleanupStrategy::PrefixDelete)
        .with_rate_limits(1.0, true)
}

fn emit_live_jsonl(
    status: &str,
    reason: &str,
    observed_count: usize,
    cleanup_result: &str,
    auth_denial_verified: bool,
    evidence: &Value,
) {
    eprintln!(
        "SENTRY_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "sentry_live_sandbox_release_lifecycle",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": AUTH_TOKEN_ENV,
            "required_env": [ORG_SLUG_ENV, PROJECT_SLUG_ENV, NAMESPACE_ENV],
            "defaulted_env": BASE_URL_ENV,
            "command": LIVE_COMMAND,
            "git_revision": option_env!("FCP_LIVE_GIT_REVISION").unwrap_or("unknown"),
            "operation": [
                "auth-denial",
                OP_LIST_PROJECTS,
                OP_CREATE_RELEASE,
                OP_GET_RELEASE,
                OP_DELETE_RELEASE
            ],
            "status": status,
            "provider": "Sentry sandbox",
            "environment": "sandbox",
            "resource_class": "sandbox_release",
            "observed_count": observed_count,
            "call_ceiling": CALL_CEILING,
            "rate_limit_guidance": "Performs one invalid-token project listing, one sandbox project listing, one namespaced release create, one readback, and one cleanup delete.",
            "mutation_expected": true,
            "cleanup_strategy": "prefix_delete",
            "cleanup_result": cleanup_result,
            "request_category": [
                "auth-denial",
                "project.list",
                "release.create",
                "release.readback",
                "release.delete"
            ],
            "auth_denial_verified": auth_denial_verified,
            "provider_resource_ids_logged": false,
            "secret_values_logged": false,
            "base_url_logged": false,
            "org_slug_logged": false,
            "project_slug_logged": false,
            "release_version_logged": false,
            "skip_reason": if status == "skipped" { Some(reason) } else { None },
            "fcp_error_mapping": if status == "failed" { Some(reason) } else { None },
            "evidence": evidence,
        })
    );
}

fn skip_reason(gate: &LiveGate, env: &LiveEnvironment) -> String {
    if gate.is_enabled() {
        env.problems().join("; ")
    } else {
        gate.skip_reason()
    }
}

#[fcp_async_core::runtime::test]
async fn sentry_live_sandbox_project_listing_or_structured_skip_jsonl() {
    let gate = LiveGate::sandbox();
    let env = LiveEnvironment::from_manifest(manifest());
    if !gate.is_enabled() || !env.is_ready() {
        emit_live_jsonl(
            "skipped",
            &skip_reason(&gate, &env),
            0,
            "not_started",
            false,
            &env.evidence_summary(),
        );
        return;
    }

    let auth_denial_verified = invalid_token_is_denied(&env).await;
    assert!(
        auth_denial_verified,
        "Sentry invalid-token project listing must be denied"
    );

    let client = configured_client(&env);
    let org = env
        .env_vars
        .get(ORG_SLUG_ENV)
        .expect("organization slug env is ready");
    let project = env
        .env_vars
        .get(PROJECT_SLUG_ENV)
        .expect("project slug env is ready");
    let namespace = env
        .env_vars
        .get(NAMESPACE_ENV)
        .expect("namespace env is ready");
    let base_url = env
        .env_vars
        .get(BASE_URL_ENV)
        .expect("base URL env is ready");
    let release_version = format!(
        "fcp-live-{namespace}-{}",
        short_hash(&format!("{namespace}:{}", Uuid::new_v4()))
    );

    let projects = match client.list_projects(org, None).await {
        Ok(value) => value,
        Err(error) => {
            emit_live_jsonl(
                "failed",
                &error.to_string(),
                0,
                "not_started",
                auth_denial_verified,
                &env.evidence_summary(),
            );
            panic!("Sentry sandbox project listing failed: {error}");
        }
    };

    match client
        .create_release(
            org,
            &json!({
                "version": release_version,
                "projects": [project],
            }),
        )
        .await
    {
        Ok(_) => {}
        Err(error) => {
            emit_live_jsonl(
                "failed",
                &error.to_string(),
                1,
                "not_started",
                auth_denial_verified,
                &json!({
                    "environment": env.evidence_summary(),
                    "base_url_hash": redacted_hash(base_url),
                    "org_hash": redacted_hash(org),
                    "project_hash": redacted_hash(project),
                    "release_hash": redacted_hash(&release_version),
                    "project_count": projects.as_array().map_or(0, Vec::len),
                }),
            );
            panic!("Sentry sandbox release create failed: {error}");
        }
    }

    let release = match client.get_release(org, &release_version).await {
        Ok(value) => value,
        Err(error) => {
            emit_live_jsonl(
                "failed",
                &error.to_string(),
                2,
                "readback_failed",
                auth_denial_verified,
                &json!({
                    "environment": env.evidence_summary(),
                    "base_url_hash": redacted_hash(base_url),
                    "org_hash": redacted_hash(org),
                    "project_hash": redacted_hash(project),
                    "release_hash": redacted_hash(&release_version),
                }),
            );
            panic!("Sentry sandbox release readback failed: {error}");
        }
    };

    match client.delete_release(org, &release_version).await {
        Ok(delete) => {
            emit_live_jsonl(
                "passed",
                "",
                projects
                    .as_array()
                    .map_or(3, |items| items.len().saturating_add(3)),
                "delete_completed",
                auth_denial_verified,
                &json!({
                    "environment": env.evidence_summary(),
                    "base_url_hash": redacted_hash(base_url),
                    "org_hash": redacted_hash(org),
                    "project_hash": redacted_hash(project),
                    "release_hash": redacted_hash(&release_version),
                    "project_count": projects.as_array().map_or(0, Vec::len),
                    "readback_present": release.get("version").is_some(),
                    "delete_result": delete,
                }),
            );
        }
        Err(error) => {
            emit_live_jsonl(
                "failed",
                &error.to_string(),
                3,
                "delete_failed",
                auth_denial_verified,
                &json!({
                    "environment": env.evidence_summary(),
                    "base_url_hash": redacted_hash(base_url),
                    "org_hash": redacted_hash(org),
                    "project_hash": redacted_hash(project),
                    "release_hash": redacted_hash(&release_version),
                    "readback_present": release.get("version").is_some(),
                }),
            );
            panic!("Sentry sandbox release cleanup failed: {error}");
        }
    }
    client.shutdown();
}

async fn invalid_token_is_denied(env: &LiveEnvironment) -> bool {
    let client = configured_client_with_token(env, "fcp-invalid-sentry-live-token");
    let org = env
        .env_vars
        .get(ORG_SLUG_ENV)
        .expect("organization slug env is ready");
    let denied = client.list_projects(org, None).await.is_err();
    client.shutdown();
    denied
}

fn configured_client(env: &LiveEnvironment) -> SentryClient {
    configured_client_with_token(env, env.secrets.require("auth_token"))
}

fn configured_client_with_token(env: &LiveEnvironment, auth_token: &str) -> SentryClient {
    SentryClient::new(
        SentryAuth::BearerToken(auth_token.to_string()),
        Some(
            env.env_vars
                .get(BASE_URL_ENV)
                .expect("base URL env is ready"),
        ),
    )
    .expect("construct Sentry live client")
}

fn redacted_hash(value: &str) -> String {
    format!("sha256:{}", short_hash(value))
}

fn short_hash(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    hex::encode(digest).chars().take(16).collect()
}
