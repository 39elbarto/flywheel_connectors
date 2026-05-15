//! Environment-gated live verification for the `Discord` connector.

#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc,
    clippy::unwrap_used
)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_discord::DiscordConnector;
use fcp_prelude::CapabilityConstraints;
use serde_json::{Value, json};
use uuid::Uuid;

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const TOKEN_ENV: &str = "DISCORD_BOT_TOKEN";
const API_URL_ENV: &str = "DISCORD_API_URL";
const CHANNEL_ID_ENV: &str = "DISCORD_CHANNEL_ID";
const VERIFY_CHANNEL_ENV: &str = "DISCORD_VERIFY_CHANNEL";
const CAP_READ: &str = "discord.read";
const OP_GET_CHANNEL: &str = "discord.get_channel";
const ALL_REQUIRED_INTENTS: u64 = (1 << 0) | (1 << 9) | (1 << 12) | (1 << 15);

#[fcp_async_core::runtime::test]
async fn live_verification_validates_bot_token_when_enabled() {
    if !live_gate_enabled() {
        emit_live_jsonl("skipped", &format!("{LIVE_GATE_ENV} is not set to 1"), 0);
        return;
    }

    let Some(token) = env_nonempty(TOKEN_ENV) else {
        emit_live_jsonl("skipped", &format!("{TOKEN_ENV} is not set"), 0);
        return;
    };
    let api_url = env_nonempty(API_URL_ENV).unwrap_or_else(|| "https://discord.com/api/v10".into());

    let signing_key = Ed25519SigningKey::generate();
    let mut connector = configured_connector(&api_url, &token).await;
    let mut observed_count = 1;
    let reason = if std::env::var(VERIFY_CHANNEL_ENV).ok().as_deref() == Some("1") {
        let Some(channel_id) = env_nonempty(CHANNEL_ID_ENV) else {
            emit_live_jsonl(
                "skipped",
                &format!("{CHANNEL_ID_ENV} is not set"),
                observed_count,
            );
            return;
        };
        handshake_connector(&mut connector, &signing_key).await;
        let channel = invoke_get_channel(&connector, &signing_key, &channel_id)
            .await
            .expect("get live Discord channel");
        observed_count = usize::from(channel.get("id").is_some());
        "users.@me and get_channel completed"
    } else {
        "users.@me completed"
    };

    emit_live_jsonl("passed", reason, observed_count);
}

async fn configured_connector(api_url: &str, token: &str) -> DiscordConnector {
    let mut connector = DiscordConnector::new();
    connector
        .handle_configure(json!({
            "bot_credential": token,
            "api_url": api_url,
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
}

async fn handshake_connector(connector: &mut DiscordConnector, signing_key: &Ed25519SigningKey) {
    connector
        .handle_handshake(json!({
            "protocol_version": "2.0.0",
            "zone": "z:work",
            "zone_dir": zone_dir("discord-live"),
            "host_public_key": signing_key.verifying_key().to_bytes(),
            "nonce": vec![23_u8; 32],
            "capabilities_requested": [CAP_READ]
        }))
        .await
        .expect("handshake live connector");
}

fn zone_dir(label: &str) -> String {
    std::env::temp_dir()
        .join("fcp-discord-acceptance")
        .join(format!("{label}-{}", Uuid::new_v4()))
        .to_string_lossy()
        .into_owned()
}

fn capability_for(
    connector: &DiscordConnector,
    signing_key: &Ed25519SigningKey,
) -> fcp_core::CapabilityToken {
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".to_string()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize constraints");
    let now = Utc::now();
    let cose = CapabilityTokenBuilder::new()
        .capability_id(CAP_READ)
        .zone_id("z:work")
        .principal("user:discord-live")
        .operations(&[OP_GET_CHANNEL])
        .issuer("node:live-verification")
        .validity(now, now + ChronoDuration::hours(1))
        .target_instance(connector.instance_id().as_ref())
        .try_constraints_cbor(&constraints_cbor)
        .expect("valid constraints cbor")
        .sign(signing_key)
        .expect("sign capability token");
    fcp_core::CapabilityToken::from_raw(cose)
}

async fn invoke_get_channel(
    connector: &DiscordConnector,
    signing_key: &Ed25519SigningKey,
    channel_id: &str,
) -> Result<Value, fcp_prelude::FcpError> {
    connector
        .handle_invoke(json!({
            "operation": OP_GET_CHANNEL,
            "input": {"channel_id": channel_id},
            "capability_token": capability_for(connector, signing_key)
        }))
        .await
}

fn live_gate_enabled() -> bool {
    std::env::var(LIVE_GATE_ENV).ok().as_deref() == Some("1")
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn emit_live_jsonl(status: &str, reason: &str, observed_count: usize) {
    eprintln!(
        "DISCORD_LIVE_SANDBOX_JSONL {}",
        json!({
            "connector": "discord",
            "suite_class": "live",
            "gate_env_var": LIVE_GATE_ENV,
            "credential_env_vars": [TOKEN_ENV],
            "optional_env_vars": [API_URL_ENV, CHANNEL_ID_ENV, VERIFY_CHANNEL_ENV],
            "status": status,
            "reason": reason,
            "observed_count": observed_count,
            "credential_material_logged": false,
            "api_url_logged": false,
            "channel_id_logged": false
        })
    );
}
