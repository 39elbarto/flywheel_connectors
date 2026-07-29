//! Environment-gated sandbox verification for the `Discord` connector.

#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc,
    clippy::panic,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_discord::DiscordConnector;
use fcp_prelude::{CapabilityConstraints, FcpError};
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const TOKEN_ENV: &str = "DISCORD_SANDBOX_BOT_TOKEN";
const GUILD_ID_ENV: &str = "DISCORD_SANDBOX_GUILD_ID";
const CHANNEL_ID_ENV: &str = "DISCORD_SANDBOX_CHANNEL_ID";
const RUN_NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const API_URL_ENV: &str = "DISCORD_SANDBOX_API_URL";
const CAP_READ: &str = "discord.read";
const CAP_SEND: &str = "discord.send";
const CAP_DELETE: &str = "discord.delete";
const OP_GET_CHANNEL: &str = "discord.get_channel";
const OP_SEND_MESSAGE: &str = "discord.send_message";
const OP_DELETE_MESSAGE: &str = "discord.delete_message";
const ALL_REQUIRED_INTENTS: u64 = (1 << 0) | (1 << 9) | (1 << 12) | (1 << 15);
const CALL_CEILING: usize = 4;
const LIVE_COMMAND: &str =
    "rch exec -- cargo test -p fcp-discord --test live_verification -- --nocapture";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("discord", "Discord sandbox")
        .with_env_secret(
            "bot_token",
            TOKEN_ENV,
            "Discord bot token scoped to a dedicated sandbox server",
        )
        .with_env_var(GUILD_ID_ENV, "Dedicated sandbox Discord guild/server ID")
        .with_env_var(
            CHANNEL_ID_ENV,
            "Dedicated sandbox text channel ID where synthetic messages may be sent",
        )
        .with_env_var(
            RUN_NAMESPACE_ENV,
            "Shared namespace embedded in synthetic sandbox message text for this run",
        )
        .with_env_var_default(
            API_URL_ENV,
            "https://discord.com/api/v10",
            "Discord REST API base URL",
        )
        .with_account_setup(
            "Use a dedicated Discord server and text channel. The bot must be installed there and allowed to read the channel, send messages, and delete its own sandbox messages.",
        )
        .with_budget(0.01)
        .with_cleanup(CleanupStrategy::PrefixDelete)
        .with_rate_limits(0.5, true)
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
        "DISCORD_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "discord_live_sandbox_message_lifecycle",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": [TOKEN_ENV],
            "required_env": [GUILD_ID_ENV, CHANNEL_ID_ENV, RUN_NAMESPACE_ENV],
            "defaulted_env": [API_URL_ENV],
            "command": LIVE_COMMAND,
            "git_revision": option_env!("FCP_LIVE_GIT_REVISION").unwrap_or("unknown"),
            "operation": [
                "auth-denial",
                OP_GET_CHANNEL,
                OP_SEND_MESSAGE,
                OP_DELETE_MESSAGE
            ],
            "status": status,
            "provider": "Discord sandbox",
            "environment": "sandbox",
            "resource_class": "sandbox_channel_message",
            "observed_count": observed_count,
            "call_ceiling": CALL_CEILING,
            "rate_limit_guidance": "Performs one invalid-token auth probe, one sandbox channel metadata read, one sandbox message send, and one cleanup delete.",
            "mutation_expected": true,
            "cleanup_strategy": "prefix_delete",
            "cleanup_result": cleanup_result,
            "request_category": [
                "auth-denial",
                "channel.metadata_read",
                "message.send",
                "message.delete"
            ],
            "auth_denial_verified": auth_denial_verified,
            "guild_id_logged": false,
            "channel_id_logged": false,
            "message_id_logged": false,
            "message_body_logged": false,
            "provider_resource_ids_logged": false,
            "secret_values_logged": false,
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

fn redacted_hash(value: &str) -> String {
    format!("sha256:{}", short_hash(value))
}

fn short_hash(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    hex::encode(digest).chars().take(16).collect()
}

async fn configured_connector(
    env: &LiveEnvironment,
    signing_key: &Ed25519SigningKey,
) -> DiscordConnector {
    let mut connector = DiscordConnector::new();
    connector
        .handle_configure(json!({
            "bot_credential": env.secrets.require("bot_token"),
            "api_url": env
                .env_vars
                .get(API_URL_ENV)
                .expect("API URL env is ready"),
            "gateway_url": "ws://127.0.0.1:1/",
            "intents": ALL_REQUIRED_INTENTS,
            "retry": {
                "max_attempts": 1,
                "initial_delay_ms": 250,
                "max_delay_ms": 1_000,
                "jitter": 0.0
            }
        }))
        .await
        .expect("configure live connector");
    connector
        .handle_handshake(json!({
            "protocol_version": "2.0.0",
            "zone": "z:work",
            "zone_dir": zone_dir("discord-live"),
            "host_public_key": signing_key.verifying_key().to_bytes(),
            "nonce": vec![23_u8; 32],
            "capabilities_requested": [CAP_READ, CAP_SEND, CAP_DELETE]
        }))
        .await
        .expect("handshake live connector");
    connector
}

fn zone_dir(label: &str) -> String {
    std::env::temp_dir()
        .join("fcp-discord-acceptance")
        .join(format!("{label}-{}", Uuid::new_v4()))
        .to_string_lossy()
        .into_owned()
}

fn capability_for_operation(operation: &'static str) -> &'static str {
    match operation {
        OP_GET_CHANNEL => CAP_READ,
        OP_SEND_MESSAGE => CAP_SEND,
        OP_DELETE_MESSAGE => CAP_DELETE,
        _ => panic!("unsupported Discord live operation {operation}"),
    }
}

fn capability_for(
    connector: &DiscordConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
) -> fcp_core::CapabilityToken {
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".to_string()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize constraints");
    let now = Utc::now();
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability_for_operation(operation))
        .zone_id("z:work")
        .principal("user:discord-live")
        .operations(&[operation])
        .issuer("node:live-verification")
        .validity(now, now + ChronoDuration::hours(1))
        .target_instance(connector.instance_id().as_ref())
        .try_constraints_cbor(&constraints_cbor)
        .expect("valid constraints cbor")
        .sign(signing_key)
        .expect("sign capability token");
    fcp_core::CapabilityToken::from_raw(cose)
}

async fn invoke(
    connector: &DiscordConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    input: Value,
) -> Result<Value, FcpError> {
    connector
        .handle_invoke(json!({
            "operation": operation,
            "input": input,
            "capability_token": capability_for(connector, signing_key, operation)
        }))
        .await
}

async fn invalid_token_is_denied(env: &LiveEnvironment) -> bool {
    let mut connector = DiscordConnector::new();
    connector
        .handle_configure(json!({
            "bot_credential": "fcp-invalid-discord-live-token",
            "api_url": env
                .env_vars
                .get(API_URL_ENV)
                .expect("API URL env is ready"),
            "gateway_url": "ws://127.0.0.1:1/",
            "intents": ALL_REQUIRED_INTENTS,
            "retry": {
                "max_attempts": 1,
                "initial_delay_ms": 250,
                "max_delay_ms": 1_000,
                "jitter": 0.0
            }
        }))
        .await
        .is_err()
}

async fn shutdown_connector(connector: &mut DiscordConnector) {
    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown live connector");
}

#[fcp_async_core::runtime::test]
async fn discord_live_sandbox_message_lifecycle_or_structured_skip_jsonl() {
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
        "Discord invalid-token configure probe must be denied"
    );

    let signing_key = Ed25519SigningKey::generate();
    let mut connector = configured_connector(&env, &signing_key).await;
    let guild_id = env.env_vars.get(GUILD_ID_ENV).expect("guild env is ready");
    let channel_id = env
        .env_vars
        .get(CHANNEL_ID_ENV)
        .expect("channel env is ready");
    let namespace = env
        .env_vars
        .get(RUN_NAMESPACE_ENV)
        .expect("namespace env is ready");
    let message_body = format!(
        "FCP Discord live verification {namespace} {}",
        Uuid::new_v4()
    );

    let channel = match invoke(
        &connector,
        &signing_key,
        OP_GET_CHANNEL,
        json!({ "channel_id": channel_id }),
    )
    .await
    {
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
            panic!("Discord sandbox channel read failed: {error}");
        }
    };

    let send = match invoke(
        &connector,
        &signing_key,
        OP_SEND_MESSAGE,
        json!({
            "channel_id": channel_id,
            "content": message_body,
        }),
    )
    .await
    {
        Ok(value) => value,
        Err(error) => {
            emit_live_jsonl(
                "failed",
                &error.to_string(),
                1,
                "not_started",
                auth_denial_verified,
                &json!({
                    "environment": env.evidence_summary(),
                    "guild_hash": redacted_hash(guild_id),
                    "channel_hash": redacted_hash(channel_id),
                    "channel_metadata_present": channel.get("id").is_some(),
                }),
            );
            panic!("Discord sandbox message send failed: {error}");
        }
    };

    let message_id = send["delivery"]["message_id"]
        .as_str()
        .or_else(|| send["id"].as_str())
        .expect("Discord send response includes message id");

    match invoke(
        &connector,
        &signing_key,
        OP_DELETE_MESSAGE,
        json!({
            "channel_id": channel_id,
            "message_id": message_id,
        }),
    )
    .await
    {
        Ok(delete) => {
            emit_live_jsonl(
                "passed",
                "",
                3,
                "delete_completed",
                auth_denial_verified,
                &json!({
                    "environment": env.evidence_summary(),
                    "guild_hash": redacted_hash(guild_id),
                    "channel_hash": redacted_hash(channel_id),
                    "message_hash": redacted_hash(message_id),
                    "message_body_hash": redacted_hash(&message_body),
                    "channel_metadata_present": channel.get("id").is_some(),
                    "send_status": send["delivery"]["status"].as_str().unwrap_or("unknown"),
                    "delete_result": delete,
                }),
            );
        }
        Err(error) => {
            emit_live_jsonl(
                "failed",
                &error.to_string(),
                2,
                "delete_failed",
                auth_denial_verified,
                &json!({
                    "environment": env.evidence_summary(),
                    "guild_hash": redacted_hash(guild_id),
                    "channel_hash": redacted_hash(channel_id),
                    "message_hash": redacted_hash(message_id),
                    "message_body_hash": redacted_hash(&message_body),
                    "channel_metadata_present": channel.get("id").is_some(),
                }),
            );
            panic!("Discord sandbox message cleanup failed: {error}");
        }
    }

    shutdown_connector(&mut connector).await;
}
