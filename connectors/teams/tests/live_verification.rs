//! Environment-gated live verification for the Teams connector.

#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc
)]

use std::time::Duration;

use fcp_teams::client::TeamsClient;
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const TENANT_ID_ENV: &str = "TEAMS_SANDBOX_TENANT_ID";
const CLIENT_ID_ENV: &str = "TEAMS_SANDBOX_CLIENT_ID";
const CLIENT_SECRET_ENV: &str = "TEAMS_SANDBOX_CLIENT_SECRET";
const TEAM_ID_ENV: &str = "TEAMS_SANDBOX_TEAM_ID";
const CHANNEL_ID_ENV: &str = "TEAMS_SANDBOX_CHANNEL_ID";
const BASE_URL_ENV: &str = "TEAMS_SANDBOX_GRAPH_BASE_URL";
const NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const OP_LIST_CHANNELS: &str = "teams.list_channels";
const OP_GET_CHANNEL: &str = "teams.get_channel";
const OP_SEND_CHANNEL_MESSAGE: &str = "teams.send_channel_message";
const OP_UPDATE_MESSAGE: &str = "teams.update_message";
const CALL_CEILING: usize = 5;
const LIVE_COMMAND: &str =
    "rch exec -- cargo test -p fcp-teams --test live_verification -- --nocapture";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("teams", "Microsoft Teams sandbox")
        .with_env_secret(
            "client_secret",
            CLIENT_SECRET_ENV,
            "Microsoft Graph client secret scoped to the sandbox tenant",
        )
        .with_env_var(
            TENANT_ID_ENV,
            "Microsoft Entra tenant id for the sandbox tenant",
        )
        .with_env_var(CLIENT_ID_ENV, "Microsoft Graph app client id")
        .with_env_var(
            TEAM_ID_ENV,
            "Dedicated sandbox team id used for channel message lifecycle proof",
        )
        .with_env_var(
            CHANNEL_ID_ENV,
            "Dedicated sandbox channel id used for channel message lifecycle proof",
        )
        .with_env_var(
            NAMESPACE_ENV,
            "Shared namespace recorded in evidence for any sandbox-side artifacts",
        )
        .with_env_var_default(
            BASE_URL_ENV,
            "https://graph.microsoft.com/v1.0",
            "Microsoft Graph API endpoint",
        )
        .with_account_setup(
            "Use a dedicated Microsoft 365 tenant and sandbox channel. The app must have Graph permissions to read the target channel, send one namespaced channel message, and update it to a cleanup tombstone.",
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
        "TEAMS_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "teams_live_sandbox_channel_message_lifecycle",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": CLIENT_SECRET_ENV,
            "required_env": [TENANT_ID_ENV, CLIENT_ID_ENV, TEAM_ID_ENV, CHANNEL_ID_ENV, NAMESPACE_ENV],
            "defaulted_env": BASE_URL_ENV,
            "command": LIVE_COMMAND,
            "git_revision": option_env!("FCP_LIVE_GIT_REVISION").unwrap_or("unknown"),
            "operation": [
                "auth-denial",
                OP_LIST_CHANNELS,
                OP_GET_CHANNEL,
                OP_SEND_CHANNEL_MESSAGE,
                OP_UPDATE_MESSAGE
            ],
            "status": status,
            "provider": "Microsoft Teams sandbox",
            "environment": "sandbox",
            "resource_class": "sandbox_channel_message",
            "observed_count": observed_count,
            "call_ceiling": CALL_CEILING,
            "rate_limit_guidance": "Performs one invalid-token channel listing, one sandbox channel listing, one channel readback, one namespaced channel send, and one tombstone update cleanup.",
            "mutation_expected": true,
            "cleanup_strategy": "tombstone_update",
            "cleanup_result": cleanup_result,
            "request_category": [
                "auth-denial",
                "channel.list",
                "channel.read",
                "message.send",
                "message.tombstone_update"
            ],
            "auth_denial_verified": auth_denial_verified,
            "provider_resource_ids_logged": false,
            "secret_values_logged": false,
            "tenant_id_logged": false,
            "client_id_logged": false,
            "team_id_logged": false,
            "channel_id_logged": false,
            "message_id_logged": false,
            "message_content_logged": false,
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
async fn teams_live_sandbox_team_listing_or_structured_skip_jsonl() {
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
        "Teams invalid-token channel listing must be denied"
    );

    let client = configured_client(&env).await;
    let tenant_id = env
        .env_vars
        .get(TENANT_ID_ENV)
        .expect("tenant id env is ready");
    let client_id = env
        .env_vars
        .get(CLIENT_ID_ENV)
        .expect("client id env is ready");
    let team_id = env.env_vars.get(TEAM_ID_ENV).expect("team id env is ready");
    let channel_id = env
        .env_vars
        .get(CHANNEL_ID_ENV)
        .expect("channel id env is ready");
    let namespace = env
        .env_vars
        .get(NAMESPACE_ENV)
        .expect("namespace env is ready");
    let message_key = short_hash(&format!("{namespace}:{}", Uuid::new_v4()));
    let content = format!("FCP Teams live verification {namespace} {message_key}");
    let tombstone = format!(
        "FCP Teams live verification cleanup {}",
        redacted_hash(&content)
    );

    let channels = match client.list_channels(team_id).await {
        Ok(channels) => channels,
        Err(error) => {
            emit_live_jsonl(
                "failed",
                &error.to_string(),
                0,
                "not_started",
                auth_denial_verified,
                &env.evidence_summary(),
            );
            panic!("Teams sandbox channel listing failed: {error}");
        }
    };

    match client.get_channel(team_id, channel_id).await {
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
                    "tenant_hash": redacted_hash(tenant_id),
                    "client_hash": redacted_hash(client_id),
                    "team_hash": redacted_hash(team_id),
                    "channel_hash": redacted_hash(channel_id),
                    "channel_count": channels.len(),
                }),
            );
            panic!("Teams sandbox channel readback failed: {error}");
        }
    }

    let sent = match client
        .send_channel_message(team_id, channel_id, &content, "text")
        .await
    {
        Ok(message) => message,
        Err(error) => {
            emit_live_jsonl(
                "failed",
                &error.to_string(),
                2,
                "not_started",
                auth_denial_verified,
                &json!({
                    "environment": env.evidence_summary(),
                    "tenant_hash": redacted_hash(tenant_id),
                    "client_hash": redacted_hash(client_id),
                    "team_hash": redacted_hash(team_id),
                    "channel_hash": redacted_hash(channel_id),
                    "content_hash": redacted_hash(&content),
                    "channel_count": channels.len(),
                }),
            );
            panic!("Teams sandbox channel message send failed: {error}");
        }
    };

    let message_id = sent
        .id
        .as_deref()
        .expect("Teams channel send response includes message id");
    match client
        .update_channel_message(
            team_id,
            channel_id,
            message_id,
            &json!({
                "body": {
                    "contentType": "text",
                    "content": tombstone
                }
            }),
        )
        .await
    {
        Ok(()) => {
            emit_live_jsonl(
                "passed",
                "",
                channels.len().saturating_add(3),
                "tombstone_update_completed",
                auth_denial_verified,
                &json!({
                    "environment": env.evidence_summary(),
                    "tenant_hash": redacted_hash(tenant_id),
                    "client_hash": redacted_hash(client_id),
                    "team_hash": redacted_hash(team_id),
                    "channel_hash": redacted_hash(channel_id),
                    "message_hash": redacted_hash(message_id),
                    "content_hash": redacted_hash(&content),
                    "channel_count": channels.len(),
                    "cleanup_artifact": "message_updated_to_redacted_tombstone",
                }),
            );
        }
        Err(error) => {
            emit_live_jsonl(
                "failed",
                &error.to_string(),
                3,
                "tombstone_update_failed",
                auth_denial_verified,
                &json!({
                    "environment": env.evidence_summary(),
                    "tenant_hash": redacted_hash(tenant_id),
                    "client_hash": redacted_hash(client_id),
                    "team_hash": redacted_hash(team_id),
                    "channel_hash": redacted_hash(channel_id),
                    "message_hash": redacted_hash(message_id),
                    "content_hash": redacted_hash(&content),
                    "cleanup_artifact": "message_left_namespaced_because_update_failed",
                }),
            );
            panic!("Teams sandbox channel message tombstone update failed: {error}");
        }
    }
}

async fn invalid_token_is_denied(env: &LiveEnvironment) -> bool {
    let team_id = env.env_vars.get(TEAM_ID_ENV).expect("team id env is ready");
    let client = TeamsClient::new(
        env.env_vars
            .get(BASE_URL_ENV)
            .expect("base URL env is ready"),
        "fcp-invalid-teams-live-token",
        Duration::from_secs(10),
    )
    .expect("construct Teams invalid-token client");
    client.list_channels(team_id).await.is_err()
}

async fn configured_client(env: &LiveEnvironment) -> TeamsClient {
    TeamsClient::from_client_credentials(
        env.env_vars
            .get(BASE_URL_ENV)
            .expect("base URL env is ready"),
        env.env_vars
            .get(CLIENT_ID_ENV)
            .expect("client id env is ready"),
        env.secrets.require("client_secret"),
        env.env_vars
            .get(TENANT_ID_ENV)
            .expect("tenant id env is ready"),
        Duration::from_secs(10),
    )
    .await
    .expect("construct Teams live client from client credentials")
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
