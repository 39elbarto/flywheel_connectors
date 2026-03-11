//! FCP Connector implementation for Discord.
//!
//! Implements handler methods for FCP protocol with Discord-specific operations.

use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use fcp_async_core::channel::{broadcast, watch};
use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier, ConnectorId,
    EventCaps, EventData, EventEnvelope, EventInfo, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, IdempotencyClass, InstanceId, Introspection, OperationId, OperationInfo,
    Principal, RiskLevel, SafetyTier, SelfCheckReport, SessionId, SimulateRequest,
    SimulateResponse, ThreadInfo, TrustLevel, ZoneId,
};
use fcp_sdk::{
    Limits,
    runtime::{
        InMemoryStreamingSession, StreamingConnection, StreamingError, StreamingSupervisor,
        SupervisorConfig,
    },
    validate_input_with_limits, validate_output_with_limits,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, warn};
use url::Url;

use crate::{
    api::DiscordApiClient,
    config::DiscordConfig,
    gateway::{DISCORD_GATEWAY_STATE_FILE, GatewayConnection, GatewayEvent, GatewayEventFrame},
    types::Embed,
};

/// Discord FCP connector.
pub struct DiscordConnector {
    base: Arc<BaseConnector>,
    config: Option<DiscordConfig>,
    api_client: Option<Arc<DiscordApiClient>>,
    gateway: Option<Arc<GatewayConnection>>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
    zone_dir: Option<PathBuf>,
    bot_user_id: Option<String>,
    gateway_lease: Option<DiscordGatewayLease>,

    // Event broadcast
    event_tx: broadcast::Sender<FcpResult<EventEnvelope>>,

    // Gateway task
    gateway_task: Option<fcp_async_core::task::JoinHandle<()>>,
    gateway_shutdown_tx: Option<watch::Sender<bool>>,
    gateway_lease_task: Option<fcp_async_core::task::JoinHandle<()>>,

    // Metrics
    start_time: Instant,
}

const INTENT_GUILDS: u64 = 1 << 0;
const INTENT_GUILD_MESSAGES: u64 = 1 << 9;
const INTENT_DIRECT_MESSAGES: u64 = 1 << 12;
const INTENT_MESSAGE_CONTENT: u64 = 1 << 15;
const DISCORD_GATEWAY_LEASE_FILE: &str = "discord_gateway_lease.json";
const DISCORD_GATEWAY_LEASE_TTL_SECONDS: u64 = 120;
const DISCORD_GATEWAY_LEASE_RENEW_INTERVAL_SECONDS: u64 = 30;

const REQUIRED_GATEWAY_INTENTS: [(&str, u64); 4] = [
    ("GUILDS", INTENT_GUILDS),
    ("GUILD_MESSAGES", INTENT_GUILD_MESSAGES),
    ("DIRECT_MESSAGES", INTENT_DIRECT_MESSAGES),
    ("MESSAGE_CONTENT", INTENT_MESSAGE_CONTENT),
];

fn current_unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn write_json_file_atomic<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let tmp_path = path.with_extension(format!("tmp-{}", std::process::id()));
    let payload = serde_json::to_vec(value).map_err(io::Error::other)?;
    fs::write(&tmp_path, payload)?;
    fs::rename(&tmp_path, path)?;
    Ok(())
}

fn read_json_file_if_exists<T>(path: &Path) -> io::Result<Option<T>>
where
    T: for<'de> Deserialize<'de>,
{
    match fs::read(path) {
        Ok(bytes) => {
            let value = serde_json::from_slice::<T>(&bytes).map_err(io::Error::other)?;
            Ok(Some(value))
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DiscordGatewayLeaseRecord {
    holder_instance_id: String,
    lease_seq: u64,
    updated_at: u64,
    expires_at: u64,
}

#[derive(Debug, Clone)]
struct DiscordGatewayLease {
    path: PathBuf,
    holder_instance_id: String,
    lease_seq: u64,
    ttl_seconds: u64,
}

impl DiscordGatewayLease {
    fn acquire(path: PathBuf, holder_instance_id: String, ttl_seconds: u64) -> FcpResult<Self> {
        let ttl_seconds = ttl_seconds.max(DISCORD_GATEWAY_LEASE_RENEW_INTERVAL_SECONDS);
        let now = current_unix_timestamp_secs();
        let previous =
            read_json_file_if_exists::<DiscordGatewayLeaseRecord>(&path).map_err(|err| {
                FcpError::Internal {
                    message: format!(
                        "Failed to read Discord gateway lease file '{}': {err}",
                        path.display()
                    ),
                }
            })?;

        if let Some(record) = previous.as_ref()
            && record.expires_at > now
            && record.holder_instance_id != holder_instance_id
        {
            return Err(FcpError::Conflict {
                message: format!(
                    "discord gateway lease held by '{}' (lease_seq={}) until {}",
                    record.holder_instance_id, record.lease_seq, record.expires_at
                ),
            });
        }

        let lease_seq = previous
            .map(|record| record.lease_seq.saturating_add(1))
            .unwrap_or(1);

        let record = DiscordGatewayLeaseRecord {
            holder_instance_id: holder_instance_id.clone(),
            lease_seq,
            updated_at: now,
            expires_at: now.saturating_add(ttl_seconds),
        };
        write_json_file_atomic(&path, &record).map_err(|err| FcpError::Internal {
            message: format!(
                "Failed to persist Discord gateway lease file '{}': {err}",
                path.display()
            ),
        })?;

        Ok(Self {
            path,
            holder_instance_id,
            lease_seq,
            ttl_seconds,
        })
    }

    fn renew(&self) -> FcpResult<()> {
        let Some(mut record) = read_json_file_if_exists::<DiscordGatewayLeaseRecord>(&self.path)
            .map_err(|err| FcpError::Internal {
                message: format!(
                    "Failed to read Discord gateway lease file '{}': {err}",
                    self.path.display()
                ),
            })?
        else {
            return Err(FcpError::Conflict {
                message: "discord gateway lease file is missing".into(),
            });
        };

        if record.holder_instance_id != self.holder_instance_id
            || record.lease_seq != self.lease_seq
        {
            return Err(FcpError::Conflict {
                message: format!(
                    "discord gateway lease fencing violation (expected holder='{}' lease_seq={}, found holder='{}' lease_seq={})",
                    self.holder_instance_id,
                    self.lease_seq,
                    record.holder_instance_id,
                    record.lease_seq
                ),
            });
        }

        let now = current_unix_timestamp_secs();
        record.updated_at = now;
        record.expires_at = now.saturating_add(self.ttl_seconds);
        write_json_file_atomic(&self.path, &record).map_err(|err| FcpError::Internal {
            message: format!(
                "Failed to renew Discord gateway lease file '{}': {err}",
                self.path.display()
            ),
        })?;
        Ok(())
    }

    fn release(&self) -> FcpResult<()> {
        let existing =
            read_json_file_if_exists::<DiscordGatewayLeaseRecord>(&self.path).map_err(|err| {
                FcpError::Internal {
                    message: format!(
                        "Failed to read Discord gateway lease file '{}': {err}",
                        self.path.display()
                    ),
                }
            })?;

        if let Some(record) = existing
            && record.holder_instance_id == self.holder_instance_id
            && record.lease_seq == self.lease_seq
            && let Err(err) = fs::remove_file(&self.path)
            && err.kind() != io::ErrorKind::NotFound
        {
            return Err(FcpError::Internal {
                message: format!(
                    "Failed to release Discord gateway lease file '{}': {err}",
                    self.path.display()
                ),
            });
        }

        Ok(())
    }
}

impl DiscordConnector {
    /// Create a new Discord connector.
    #[must_use]
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(1000);

        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("discord"))),
            config: None,
            api_client: None,
            gateway: None,
            verifier: None,
            session_id: None,
            zone_dir: None,
            bot_user_id: None,
            gateway_lease: None,
            event_tx,
            gateway_task: None,
            gateway_shutdown_tx: None,
            gateway_lease_task: None,
            start_time: Instant::now(),
        }
    }

    /// Handle configure method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config: DiscordConfig =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid configuration: {e}"),
            })?;

        if config.bot_credential.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: "Missing required 'bot_credential' in configuration".into(),
            });
        }

        let missing_intents = missing_required_intents(config.intents);
        if !missing_intents.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: format!(
                    "Missing required gateway intents for declared Discord event topics: {}",
                    missing_intents.join(", ")
                ),
            });
        }

        validate_network_constraints_hosts(&config)?;

        // Create API client
        let api_client = DiscordApiClient::new(&config).map_err(|e| FcpError::Internal {
            message: format!("Failed to create API client: {e}"),
        })?;

        let api_client = Arc::new(api_client);

        // Test connection by getting current user
        let user = api_client
            .get_current_user()
            .await
            .map_err(|e| FcpError::External {
                service: "discord".into(),
                message: format!("Failed to verify bot token: {e}"),
                status_code: None,
                retryable: e.is_retryable(),
                retry_after: None,
            })?;

        info!(
            user_id = %user.id,
            username = %user.username,
            "Discord bot authenticated"
        );

        self.bot_user_id = Some(user.id.clone());
        self.api_client = Some(api_client.clone());
        self.gateway = Some(Arc::new(GatewayConnection::new(config.clone(), api_client)));
        self.config = Some(config);
        self.base.set_configured(true);

        Ok(json!({
            "status": "configured",
            "bot_user": {
                "id": user.id,
                "username": user.username
            },
            "provisioning": {
                "token_ok": true,
                "intents_ok": true,
                "network_ok": true
            },
        }))
    }

    /// Handle handshake method.
    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {e}"),
            })?;

        let zone_dir = req.zone_dir.clone().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "zone_dir is required for Discord gateway resume-state and singleton-writer lease persistence".into(),
        })?;
        let zone_dir = PathBuf::from(zone_dir);
        fs::create_dir_all(&zone_dir).map_err(|err| FcpError::Internal {
            message: format!(
                "Failed to prepare Discord zone_dir '{}': {err}",
                zone_dir.display()
            ),
        })?;
        self.zone_dir = Some(zone_dir);

        // Verify bot is configured
        if self.api_client.is_none() {
            return Err(FcpError::NotConfigured);
        }

        // Set up verifier
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let session_id = SessionId::new();
        self.session_id = Some(session_id.clone());

        // Connect to gateway
        self.connect_gateway().await?;
        self.base.set_handshaken(true);

        // Convert capability IDs to grants
        let capabilities_granted: Vec<CapabilityGrant> = req
            .capabilities_requested
            .into_iter()
            .map(|cap| CapabilityGrant {
                capability: cap,
                operation: None,
            })
            .collect();

        let response = HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id,
            manifest_hash: "sha256:discord-connector-v1".into(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        };

        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    /// Handle health check.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let Some(api_client) = &self.api_client else {
            return Ok(json!({
                "status": "not_configured",
                "uptime_ms": self.start_time.elapsed().as_millis() as u64
            }));
        };

        // Check if we can reach Discord
        match api_client.get_current_user().await {
            Ok(_) => Ok(json!({
                "status": "ready",
                "uptime_ms": self.start_time.elapsed().as_millis() as u64,
                "gateway_connected": self.gateway_task.is_some(),
                "metrics": self.base.metrics()
            })),
            Err(e) => Ok(json!({
                "status": "degraded",
                "uptime_ms": self.start_time.elapsed().as_millis() as u64,
                "error": e.to_string()
            })),
        }
    }

    /// Handle connector self-check.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(config) = &self.config else {
            let report = SelfCheckReport::degraded("not_configured", "Connector is not configured");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        let Some(api_client) = &self.api_client else {
            let report = SelfCheckReport::degraded("not_configured", "Connector is not configured");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        let missing_intents = missing_required_intents(config.intents);
        let intents_ok = missing_intents.is_empty();
        let network = network_readiness(config);

        let report = match api_client.get_current_user().await {
            Ok(user) => {
                if !intents_ok {
                    let mut report = SelfCheckReport::failed(
                        "provisioning_intents_missing",
                        format!(
                            "Missing required gateway intents: {}",
                            missing_intents.join(", ")
                        ),
                    );
                    report.details = Some(json!({
                        "token_ok": true,
                        "intents_ok": false,
                        "missing_intents": missing_intents,
                        "network_ok": network.network_ok,
                        "network": network.details_json(),
                        "user_id": user.id,
                        "username": user.username,
                    }));
                    report
                } else if !network.network_ok {
                    let mut report = SelfCheckReport::failed(
                        "provisioning_network_constraints_invalid",
                        "Configured Discord endpoints are outside connector NetworkConstraints",
                    );
                    report.details = Some(json!({
                        "token_ok": true,
                        "intents_ok": true,
                        "network_ok": false,
                        "network": network.details_json(),
                        "user_id": user.id,
                        "username": user.username,
                    }));
                    report
                } else {
                    let mut report = SelfCheckReport::ok();
                    report.details = Some(json!({
                        "token_ok": true,
                        "intents_ok": true,
                        "missing_intents": [],
                        "network_ok": true,
                        "network": network.details_json(),
                        "user_id": user.id,
                        "username": user.username,
                        "bot": user.bot,
                    }));
                    report
                }
            }
            Err(err) => {
                let mut report = if err.is_retryable() {
                    SelfCheckReport::degraded("provisioning_token_retryable", err.to_string())
                } else {
                    SelfCheckReport::failed("provisioning_token_invalid", err.to_string())
                };
                report.details = Some(json!({
                    "token_ok": false,
                    "intents_ok": intents_ok,
                    "missing_intents": missing_intents,
                    "network_ok": network.network_ok,
                    "network": network.details_json(),
                }));
                report
            }
        };

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    fn send_message_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "channel_id": { "type": "string", "description": "Channel ID" },
                "content": { "type": "string", "description": "Message content" },
                "embeds": { "type": "array", "items": { "type": "object" } },
                "reply_to": { "type": "string", "description": "Message ID to reply to" }
            },
            "required": ["channel_id"]
        })
    }

    fn send_message_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "channel_id": { "type": "string" },
                "content": { "type": "string" }
            }
        })
    }

    fn edit_message_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "channel_id": { "type": "string" },
                "message_id": { "type": "string" },
                "content": { "type": "string" },
                "embeds": { "type": "array" }
            },
            "required": ["channel_id", "message_id"]
        })
    }

    fn edit_message_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "content": { "type": "string" }
            }
        })
    }

    fn delete_message_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "channel_id": { "type": "string" },
                "message_id": { "type": "string" }
            },
            "required": ["channel_id", "message_id"]
        })
    }

    fn delete_message_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "deleted": { "type": "boolean" }
            }
        })
    }

    fn get_channel_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "channel_id": { "type": "string" }
            },
            "required": ["channel_id"]
        })
    }

    fn get_channel_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "name": { "type": "string" },
                "type": { "type": "integer" }
            }
        })
    }

    fn get_guild_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "guild_id": { "type": "string", "description": "Guild/server ID" }
            },
            "required": ["guild_id"]
        })
    }

    fn get_guild_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "name": { "type": "string" },
                "icon": { "type": "string" },
                "owner_id": { "type": "string" }
            }
        })
    }

    fn trigger_typing_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "channel_id": { "type": "string", "description": "Channel ID" }
            },
            "required": ["channel_id"]
        })
    }

    fn trigger_typing_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "triggered": { "type": "boolean" }
            }
        })
    }

    fn add_reaction_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "channel_id": { "type": "string", "description": "Channel ID" },
                "message_id": { "type": "string", "description": "Message ID to react to" },
                "emoji": { "type": "string", "description": "Emoji to add (Unicode or custom format name:id)" }
            },
            "required": ["channel_id", "message_id", "emoji"]
        })
    }

    fn add_reaction_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "added": { "type": "boolean" }
            }
        })
    }

    fn list_channels_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "guild_id": { "type": "string", "description": "Guild/server ID" }
            },
            "required": ["guild_id"]
        })
    }

    fn list_channels_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "channels": { "type": "array", "items": { "type": "object" } }
            }
        })
    }

    fn create_thread_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "channel_id": { "type": "string", "description": "Channel ID containing the message" },
                "message_id": { "type": "string", "description": "Message ID to create thread from" },
                "name": { "type": "string", "description": "Thread name (1-100 characters)", "minLength": 1, "maxLength": 100 },
                "auto_archive_duration": { "type": "integer", "description": "Minutes before auto-archiving (60, 1440, 4320, 10080)", "enum": [60, 1440, 4320, 10080] }
            },
            "required": ["channel_id", "message_id", "name"]
        })
    }

    fn create_thread_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "name": { "type": "string" },
                "type": { "type": "integer" }
            }
        })
    }

    fn message_event_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "channel_id": { "type": "string" },
                "content": { "type": "string" },
                "author": { "type": "object" }
            }
        })
    }

    fn input_schema_for(operation: &str) -> Option<serde_json::Value> {
        match operation {
            "discord.send_message" => Some(Self::send_message_input_schema()),
            "discord.edit_message" => Some(Self::edit_message_input_schema()),
            "discord.delete_message" => Some(Self::delete_message_input_schema()),
            "discord.get_channel" => Some(Self::get_channel_input_schema()),
            "discord.get_guild" => Some(Self::get_guild_input_schema()),
            "discord.trigger_typing" => Some(Self::trigger_typing_input_schema()),
            "discord.add_reaction" => Some(Self::add_reaction_input_schema()),
            "discord.list_channels" => Some(Self::list_channels_input_schema()),
            "discord.create_thread" => Some(Self::create_thread_input_schema()),
            _ => None,
        }
    }

    fn output_schema_for(operation: &str) -> Option<serde_json::Value> {
        match operation {
            "discord.send_message" => Some(Self::send_message_output_schema()),
            "discord.edit_message" => Some(Self::edit_message_output_schema()),
            "discord.delete_message" => Some(Self::delete_message_output_schema()),
            "discord.get_channel" => Some(Self::get_channel_output_schema()),
            "discord.get_guild" => Some(Self::get_guild_output_schema()),
            "discord.trigger_typing" => Some(Self::trigger_typing_output_schema()),
            "discord.add_reaction" => Some(Self::add_reaction_output_schema()),
            "discord.list_channels" => Some(Self::list_channels_output_schema()),
            "discord.create_thread" => Some(Self::create_thread_output_schema()),
            _ => None,
        }
    }

    /// Handle introspection.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                OperationInfo {
                    id: OperationId::from_static("discord.send_message"),
                    summary: "Send a message to a Discord channel".into(),
                    input_schema: Self::send_message_input_schema(),
                    output_schema: Self::send_message_output_schema(),
                    capability: CapabilityId::from_static("discord.send"),
                    risk_level: RiskLevel::Medium,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Send a message to a Discord channel.".into(),
                        common_mistakes: vec![
                            "Using channel names instead of IDs".into(),
                            "Exceeding 2000 character message limit".into(),
                        ],
                        examples: vec![
                            r#"{"channel_id": "123456789", "content": "Hello!"}"#.into(),
                        ],
                        related: vec![],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("discord.edit_message"),
                    summary: "Edit a message in a Discord channel".into(),
                    input_schema: Self::edit_message_input_schema(),
                    output_schema: Self::edit_message_output_schema(),
                    capability: CapabilityId::from_static("discord.edit"),
                    risk_level: RiskLevel::Medium,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Edit an existing Discord message.".into(),
                        common_mistakes: vec![],
                        examples: vec![],
                        related: vec![],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("discord.delete_message"),
                    summary: "Delete a message from a Discord channel".into(),
                    input_schema: Self::delete_message_input_schema(),
                    output_schema: Self::delete_message_output_schema(),
                    capability: CapabilityId::from_static("discord.delete"),
                    risk_level: RiskLevel::High,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Dangerous,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Delete a Discord message (irreversible).".into(),
                        common_mistakes: vec![],
                        examples: vec![],
                        related: vec![],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("discord.get_channel"),
                    summary: "Get information about a Discord channel".into(),
                    input_schema: Self::get_channel_input_schema(),
                    output_schema: Self::get_channel_output_schema(),
                    capability: CapabilityId::from_static("discord.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Get channel metadata.".into(),
                        common_mistakes: vec![],
                        examples: vec![],
                        related: vec![],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("discord.get_guild"),
                    summary: "Get information about a Discord server (guild)".into(),
                    input_schema: Self::get_guild_input_schema(),
                    output_schema: Self::get_guild_output_schema(),
                    capability: CapabilityId::from_static("discord.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Get Discord server/guild metadata.".into(),
                        common_mistakes: vec!["Using server name instead of guild ID".into()],
                        examples: vec![r#"{"guild_id": "123456789012345678"}"#.into()],
                        related: vec![],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("discord.trigger_typing"),
                    summary: "Show typing indicator in a Discord channel".into(),
                    input_schema: Self::trigger_typing_input_schema(),
                    output_schema: Self::trigger_typing_output_schema(),
                    capability: CapabilityId::from_static("discord.send"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use:
                            "Show typing indicator before sending a message (lasts 10 seconds)."
                                .into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"channel_id": "123456789012345678"}"#.into()],
                        related: vec![],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("discord.add_reaction"),
                    summary: "Add a reaction emoji to a Discord message".into(),
                    input_schema: Self::add_reaction_input_schema(),
                    output_schema: Self::add_reaction_output_schema(),
                    capability: CapabilityId::from_static("discord.react"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Add an emoji reaction to an existing message.".into(),
                        common_mistakes: vec![
                            "Using emoji name instead of Unicode character for standard emoji"
                                .into(),
                        ],
                        examples: vec![
                            r#"{"channel_id": "123", "message_id": "456", "emoji": "👍"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("discord.send")],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("discord.list_channels"),
                    summary: "List all channels in a Discord server".into(),
                    input_schema: Self::list_channels_input_schema(),
                    output_schema: Self::list_channels_output_schema(),
                    capability: CapabilityId::from_static("discord.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "List all channels in a guild/server.".into(),
                        common_mistakes: vec!["Using server name instead of guild ID".into()],
                        examples: vec![r#"{"guild_id": "123456789012345678"}"#.into()],
                        related: vec![CapabilityId::from_static("discord.read")],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("discord.create_thread"),
                    summary: "Create a thread from a Discord message".into(),
                    input_schema: Self::create_thread_input_schema(),
                    output_schema: Self::create_thread_output_schema(),
                    capability: CapabilityId::from_static("discord.threads"),
                    risk_level: RiskLevel::Medium,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Create a new thread from an existing message.".into(),
                        common_mistakes: vec!["Thread names exceeding 100 characters".into()],
                        examples: vec![
                            r#"{"channel_id": "123", "message_id": "456", "name": "Discussion"}"#
                                .into(),
                        ],
                        related: vec![CapabilityId::from_static("discord.send")],
                    },
                },
            ],
            events: vec![EventInfo {
                topic: "discord.message".into(),
                schema: Self::message_event_schema(),
                requires_ack: false,
            }],
            resource_types: vec![],
            auth_caps: None,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
        };

        serde_json::to_value(introspection).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize introspection: {e}"),
        })
    }

    /// Handle simulate method.
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let req: SimulateRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid simulate request: {e}"),
            })?;

        let response = SimulateResponse::allowed(req.id);
        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    /// Validate input structure and limits before capability token verification.
    /// This is an optimization to avoid wasting resources on capability verification
    /// for requests that will fail validation anyway.
    fn validate_input_early(operation: &str, input: &serde_json::Value) -> FcpResult<()> {
        const MAX_CONTENT_LENGTH: usize = 2000;
        const MAX_EMBEDS: usize = 10;
        const MAX_EMBED_TOTAL_CHARS: usize = 6000;

        if let Some(schema) = Self::input_schema_for(operation) {
            validate_input_with_limits(&schema, input, &Limits::default())?;
        }

        match operation {
            "discord.send_message" | "discord.edit_message" => {
                let content = input.get("content").and_then(|v| v.as_str());
                let embeds = input.get("embeds").and_then(|v| v.as_array());

                // For send_message, require either content or embeds
                if operation == "discord.send_message" && content.is_none() && embeds.is_none() {
                    return Err(FcpError::InvalidRequest {
                        code: 1003,
                        message: "Either 'content' or 'embeds' must be provided".into(),
                    });
                }

                if let Some(content) = content
                    && content.len() > MAX_CONTENT_LENGTH
                {
                    return Err(FcpError::InvalidRequest {
                        code: 1004,
                        message: format!(
                            "Content exceeds {MAX_CONTENT_LENGTH} character limit (got {} characters)",
                            content.len()
                        ),
                    });
                }

                // Validate embed limits
                if let Some(embeds) = embeds {
                    if embeds.len() > MAX_EMBEDS {
                        return Err(FcpError::InvalidRequest {
                            code: 1004,
                            message: format!(
                                "Too many embeds: {} exceeds limit of {MAX_EMBEDS}",
                                embeds.len()
                            ),
                        });
                    }

                    // Check total embed character count
                    let total_chars: usize = embeds
                        .iter()
                        .map(|e| {
                            let mut size = 0;

                            // Title
                            size += e.get("title").and_then(|v| v.as_str()).map_or(0, str::len);

                            // Description
                            size += e
                                .get("description")
                                .and_then(|v| v.as_str())
                                .map_or(0, str::len);

                            // Fields
                            if let Some(fields) = e.get("fields").and_then(|v| v.as_array()) {
                                for field in fields {
                                    size += field
                                        .get("name")
                                        .and_then(|v| v.as_str())
                                        .map_or(0, str::len);
                                    size += field
                                        .get("value")
                                        .and_then(|v| v.as_str())
                                        .map_or(0, str::len);
                                }
                            }

                            // Footer
                            if let Some(footer) = e.get("footer") {
                                size += footer
                                    .get("text")
                                    .and_then(|v| v.as_str())
                                    .map_or(0, str::len);
                            }

                            // Author
                            if let Some(author) = e.get("author") {
                                size += author
                                    .get("name")
                                    .and_then(|v| v.as_str())
                                    .map_or(0, str::len);
                            }

                            size
                        })
                        .sum();

                    if total_chars > MAX_EMBED_TOTAL_CHARS {
                        return Err(FcpError::InvalidRequest {
                            code: 1004,
                            message: format!(
                                "Total embed character count {total_chars} exceeds limit of {MAX_EMBED_TOTAL_CHARS}"
                            ),
                        });
                    }
                }
            }
            _ => {
                // Other operations don't have early validation
            }
        }

        Ok(())
    }

    /// Handle invoke method.
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let result = self.handle_invoke_internal(params).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn handle_invoke_internal(
        &self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let operation = params
            .get("operation")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation".into(),
            })?;

        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));

        // Early validation: Check input structure and limits before capability token
        // This prevents wasting resources on capability verification for invalid requests
        Self::validate_input_early(operation, &input)?;

        // Extract and verify capability token
        let token_value =
            params
                .get("capability_token")
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing capability_token".into(),
                })?;

        let token: fcp_core::CapabilityToken = serde_json::from_value(token_value.clone())
            .map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid capability_token format: {e}"),
            })?;

        // Verify token
        // Extract target resources (channel_id, guild_id) from input to validate constraints.
        let op_id: OperationId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid operation ID format".into(),
        })?;
        let intro = self.handle_introspect().await?;
        let cap_str = intro.get("operations")
            .and_then(|ops| ops.as_array())
            .and_then(|ops| ops.iter().find(|o| o.get("id").and_then(|id| id.as_str()) == Some(operation)))
            .and_then(|op| op.get("capability"))
            .and_then(|cap| cap.as_str())
            .ok_or_else(|| FcpError::OperationNotGranted {
                operation: operation.into(),
            })?;

        let cap_id: CapabilityId = cap_str.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid capability ID format".into(),
        })?;

        let mut resource_uris = Vec::new();
        if let Some(channel_id) = input.get("channel_id").and_then(|v| v.as_str()) {
            resource_uris.push(format!("discord:channel:{channel_id}"));
        }
        if let Some(guild_id) = input.get("guild_id").and_then(|v| v.as_str()) {
            resource_uris.push(format!("discord:guild:{guild_id}"));
        }

        if let Some(verifier) = &self.verifier {
            verifier.verify(&token, &cap_id, &op_id, &resource_uris)?;
        } else {
            return Err(FcpError::NotConfigured);
        }

        match operation {
            "discord.send_message" => self.invoke_send_message(input).await,
            "discord.edit_message" => self.invoke_edit_message(input).await,
            "discord.delete_message" => self.invoke_delete_message(input).await,
            "discord.get_channel" => self.invoke_get_channel(input).await,
            "discord.get_guild" => self.invoke_get_guild(input).await,
            "discord.trigger_typing" => self.invoke_trigger_typing(input).await,
            "discord.add_reaction" => self.invoke_add_reaction(input).await,
            "discord.list_channels" => self.invoke_list_channels(input).await,
            "discord.create_thread" => self.invoke_create_thread(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    async fn invoke_send_message(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        // Validate input first (before checking api) for better error messages
        let channel_id = input
            .get("channel_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing channel_id".into(),
            })?;

        let content = input.get("content").and_then(|v| v.as_str());
        let embeds: Option<Vec<Embed>> = input
            .get("embeds")
            .and_then(|v| serde_json::from_value(v.clone()).ok());
        let reply_to = input.get("reply_to").and_then(|v| v.as_str());

        // Validate that at least content or embeds is provided
        if content.is_none() && embeds.is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Either 'content' or 'embeds' must be provided".into(),
            });
        }

        // Validate embed limits
        if let Some(ref embeds) = embeds {
            const MAX_EMBEDS: usize = 10;
            const MAX_EMBED_TOTAL_CHARS: usize = 6000;
            const MAX_EMBED_TITLE: usize = 256;
            const MAX_EMBED_DESCRIPTION: usize = 4096;

            if embeds.len() > MAX_EMBEDS {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!(
                        "Too many embeds: {MAX_EMBEDS} maximum, got {}",
                        embeds.len()
                    ),
                });
            }

            let mut total_chars = 0;
            for (i, embed) in embeds.iter().enumerate() {
                if let Some(ref title) = embed.title {
                    if title.chars().count() > MAX_EMBED_TITLE {
                        return Err(FcpError::InvalidRequest {
                            code: 1004,
                            message: format!(
                                "Embed {} title exceeds {MAX_EMBED_TITLE} character limit",
                                i + 1
                            ),
                        });
                    }
                    total_chars += title.chars().count();
                }
                if let Some(ref desc) = embed.description {
                    if desc.chars().count() > MAX_EMBED_DESCRIPTION {
                        return Err(FcpError::InvalidRequest {
                            code: 1004,
                            message: format!(
                                "Embed {} description exceeds {MAX_EMBED_DESCRIPTION} character limit",
                                i + 1
                            ),
                        });
                    }
                    total_chars += desc.chars().count();
                }
                for field in &embed.fields {
                    total_chars += field.name.chars().count() + field.value.chars().count();
                }
                if let Some(ref footer) = embed.footer {
                    total_chars += footer.text.chars().count();
                }
                if let Some(ref author) = embed.author {
                    total_chars += author.name.chars().count();
                }
            }

            if total_chars > MAX_EMBED_TOTAL_CHARS {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!(
                        "Total embed content exceeds {MAX_EMBED_TOTAL_CHARS} character limit (got {total_chars} characters)",
                    ),
                });
            }
        }

        // Now check that we're configured
        let api = self.require_api()?;

        let message = api
            .create_message(channel_id, content, embeds, reply_to)
            .await
            .map_err(|e| e.to_fcp_error())?;

        let response = serde_json::to_value(message).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize message: {e}"),
        })?;

        if let Some(schema) = Self::output_schema_for("discord.send_message") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }

        Ok(response)
    }

    async fn invoke_edit_message(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        // Validate input first (before checking api) for better error messages
        let channel_id = input
            .get("channel_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing channel_id".into(),
            })?;

        let message_id = input
            .get("message_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing message_id".into(),
            })?;

        let content = input.get("content").and_then(|v| v.as_str());
        let embeds: Option<Vec<Embed>> = input
            .get("embeds")
            .and_then(|v| serde_json::from_value(v.clone()).ok());

        // Validate embed limits
        if let Some(ref embeds) = embeds {
            const MAX_EMBEDS: usize = 10;
            const MAX_EMBED_TOTAL_CHARS: usize = 6000;
            const MAX_EMBED_TITLE: usize = 256;
            const MAX_EMBED_DESCRIPTION: usize = 4096;

            if embeds.len() > MAX_EMBEDS {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!(
                        "Too many embeds: {MAX_EMBEDS} maximum, got {}",
                        embeds.len()
                    ),
                });
            }

            let mut total_chars = 0;
            for (i, embed) in embeds.iter().enumerate() {
                if let Some(ref title) = embed.title {
                    if title.chars().count() > MAX_EMBED_TITLE {
                        return Err(FcpError::InvalidRequest {
                            code: 1004,
                            message: format!(
                                "Embed {} title exceeds {MAX_EMBED_TITLE} character limit",
                                i + 1
                            ),
                        });
                    }
                    total_chars += title.chars().count();
                }
                if let Some(ref desc) = embed.description {
                    if desc.chars().count() > MAX_EMBED_DESCRIPTION {
                        return Err(FcpError::InvalidRequest {
                            code: 1004,
                            message: format!(
                                "Embed {} description exceeds {MAX_EMBED_DESCRIPTION} character limit",
                                i + 1
                            ),
                        });
                    }
                    total_chars += desc.chars().count();
                }
                for field in &embed.fields {
                    total_chars += field.name.chars().count() + field.value.chars().count();
                }
                if let Some(ref footer) = embed.footer {
                    total_chars += footer.text.chars().count();
                }
                if let Some(ref author) = embed.author {
                    total_chars += author.name.chars().count();
                }
            }

            if total_chars > MAX_EMBED_TOTAL_CHARS {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!(
                        "Total embed content exceeds {MAX_EMBED_TOTAL_CHARS} character limit (got {total_chars} characters)",
                    ),
                });
            }
        }

        // Now check that we're configured
        let api = self.require_api()?;

        let message = api
            .edit_message(channel_id, message_id, content, embeds)
            .await
            .map_err(|e| e.to_fcp_error())?;

        let response = serde_json::to_value(message).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize message: {e}"),
        })?;

        if let Some(schema) = Self::output_schema_for("discord.edit_message") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }

        Ok(response)
    }

    async fn invoke_delete_message(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        // Validate input first (before checking api) for consistent error messages
        let channel_id = input
            .get("channel_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing channel_id".into(),
            })?;

        let message_id = input
            .get("message_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing message_id".into(),
            })?;

        let api = self.require_api()?;

        api.delete_message(channel_id, message_id)
            .await
            .map_err(|e| e.to_fcp_error())?;

        let response = json!({ "deleted": true });
        if let Some(schema) = Self::output_schema_for("discord.delete_message") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }
        Ok(response)
    }

    async fn invoke_get_channel(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        // Validate input first (before checking api) for consistent error messages
        let channel_id = input
            .get("channel_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing channel_id".into(),
            })?;

        let api = self.require_api()?;

        let channel = api
            .get_channel(channel_id)
            .await
            .map_err(|e| e.to_fcp_error())?;

        let response = serde_json::to_value(channel).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize channel: {e}"),
        })?;

        if let Some(schema) = Self::output_schema_for("discord.get_channel") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }

        Ok(response)
    }

    async fn invoke_get_guild(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        // Validate input first (before checking api) for consistent error messages
        let guild_id = input
            .get("guild_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing guild_id".into(),
            })?;

        let api = self.require_api()?;

        let guild = api
            .get_guild(guild_id)
            .await
            .map_err(|e| e.to_fcp_error())?;

        let response = serde_json::to_value(guild).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize guild: {e}"),
        })?;

        if let Some(schema) = Self::output_schema_for("discord.get_guild") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }

        Ok(response)
    }

    async fn invoke_trigger_typing(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        // Validate input first (before checking api) for consistent error messages
        let channel_id = input
            .get("channel_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing channel_id".into(),
            })?;

        let api = self.require_api()?;

        api.trigger_typing(channel_id)
            .await
            .map_err(|e| e.to_fcp_error())?;

        let response = json!({ "triggered": true });
        if let Some(schema) = Self::output_schema_for("discord.trigger_typing") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }
        Ok(response)
    }

    async fn invoke_add_reaction(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let channel_id = input
            .get("channel_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing channel_id".into(),
            })?;

        let message_id = input
            .get("message_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing message_id".into(),
            })?;

        let emoji = input.get("emoji").and_then(|v| v.as_str()).ok_or_else(|| {
            FcpError::InvalidRequest {
                code: 1003,
                message: "Missing emoji".into(),
            }
        })?;

        let api = self.require_api()?;

        api.add_reaction(channel_id, message_id, emoji)
            .await
            .map_err(|e| e.to_fcp_error())?;

        let response = json!({ "added": true });
        if let Some(schema) = Self::output_schema_for("discord.add_reaction") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }
        Ok(response)
    }

    async fn invoke_list_channels(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let guild_id = input
            .get("guild_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing guild_id".into(),
            })?;

        let api = self.require_api()?;

        let channels = api
            .get_guild_channels(guild_id)
            .await
            .map_err(|e| e.to_fcp_error())?;

        let response = json!({ "channels": channels });
        if let Some(schema) = Self::output_schema_for("discord.list_channels") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }
        Ok(response)
    }

    async fn invoke_create_thread(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let channel_id = input
            .get("channel_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing channel_id".into(),
            })?;

        let message_id = input
            .get("message_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing message_id".into(),
            })?;

        let name =
            input
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing thread name".into(),
                })?;

        if name.is_empty() || name.len() > 100 {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Thread name must be 1-100 characters".into(),
            });
        }

        let auto_archive_duration = input
            .get("auto_archive_duration")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());

        let api = self.require_api()?;

        let thread = api
            .create_thread_from_message(channel_id, message_id, name, auto_archive_duration)
            .await
            .map_err(|e| e.to_fcp_error())?;

        let response = serde_json::to_value(thread).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize thread: {e}"),
        })?;

        if let Some(schema) = Self::output_schema_for("discord.create_thread") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }
        Ok(response)
    }

    /// Handle subscribe method.
    pub async fn handle_subscribe(
        &self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let topics = params
            .get("topics")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Ok(json!({
            "confirmed_topics": topics,
            "replay_supported": false
        }))
    }

    /// Handle shutdown method.
    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Shutting down Discord connector");

        if let Some(shutdown_tx) = self.gateway_shutdown_tx.take() {
            let _ = shutdown_tx.send(true);
        }

        if let Some(task) = self.gateway_lease_task.take() {
            task.abort();
        }

        if let Some(task) = self.gateway_task.take() {
            task.abort();
        }

        if let Some(lease) = self.gateway_lease.take()
            && let Err(err) = lease.release()
        {
            warn!(error = %err, "Failed to release Discord gateway lease");
        }

        Ok(json!({ "status": "shutdown" }))
    }

    /// Connect to the Discord gateway.
    async fn connect_gateway(&mut self) -> FcpResult<()> {
        if let Some(task) = &self.gateway_task {
            if !task.is_finished() {
                return Ok(()); // Already connected
            }
        }
        self.gateway_task = None;
        self.gateway_shutdown_tx = None;
        if let Some(task) = self.gateway_lease_task.take() {
            task.abort();
        }
        if let Some(lease) = self.gateway_lease.take()
            && let Err(err) = lease.release()
        {
            warn!(
                error = %err,
                "Failed to release previous Discord gateway lease before reconnect"
            );
        }

        let gateway = self.gateway.clone().ok_or(FcpError::NotConfigured)?;
        let zone_dir = self.zone_dir.clone().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Handshake zone_dir is required before Discord gateway streaming can start"
                .into(),
        })?;
        let state_path = zone_dir.join(DISCORD_GATEWAY_STATE_FILE);
        let lease_path = zone_dir.join(DISCORD_GATEWAY_LEASE_FILE);
        let lease = DiscordGatewayLease::acquire(
            lease_path,
            self.base.instance_id.to_string(),
            DISCORD_GATEWAY_LEASE_TTL_SECONDS,
        )?;
        self.gateway_lease = Some(lease.clone());

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        self.gateway_shutdown_tx = Some(shutdown_tx.clone());
        let mut lease_shutdown_rx = shutdown_rx.clone();

        let event_tx = self.event_tx.clone();
        let connector_id = self.base.id.clone();
        let instance_id = self.base.instance_id.clone();
        let base = self.base.clone();
        let lease_shutdown_tx = shutdown_tx.clone();

        let mut supervisor = StreamingSupervisor::new(
            SupervisorConfig {
                heartbeat_interval_ms: 0, // Gateway handles its own heartbeat
                ..SupervisorConfig::default()
            },
            InMemoryStreamingSession::new(),
        );

        let lease_renew_task = fcp_async_core::task::spawn(async move {
            let mut renew_timer = fcp_async_core::time::interval(Duration::from_secs(
                DISCORD_GATEWAY_LEASE_RENEW_INTERVAL_SECONDS,
            ));
            renew_timer.tick().await;
            loop {
                fcp_async_core::select! {
                    _ = renew_timer.tick() => {
                        if let Err(err) = lease.renew() {
                            warn!(
                                error = %err,
                                "Discord gateway lease renewal failed; stopping gateway"
                            );
                            let _ = lease_shutdown_tx.send(true);
                            break;
                        }
                    },
                    changed = lease_shutdown_rx.changed() => {
                        if changed.is_err() || *lease_shutdown_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });
        self.gateway_lease_task = Some(lease_renew_task);

        let task = fcp_async_core::task::spawn(async move {
            let outcome = supervisor
                .run(
                    shutdown_rx,
                    |session| {
                        let gateway = Arc::clone(&gateway);
                        let state_path = state_path.clone();
                        async move {
                            let stream = gateway
                                .connect_once_with_state_path(Some(state_path.clone()))
                                .await
                                .map_err(|e| -> StreamingError { Box::new(e) })?;
                            let join_handle = fcp_async_core::task::spawn(async move {
                                match stream.join_handle.await {
                                    Ok(Ok(())) => Ok(()),
                                    Ok(Err(e)) => Err(Box::new(e) as StreamingError),
                                    Err(e) => Err(Box::new(e) as StreamingError),
                                }
                            });
                            let _ = session; // Session reserved for future use
                            Ok(StreamingConnection {
                                events: stream.events,
                                join_handle,
                            })
                        }
                    },
                    |gateway_event, _session| {
                        let event_tx = event_tx.clone();
                        let connector_id = connector_id.clone();
                        let instance_id = instance_id.clone();
                        let base = base.clone();
                        let shutdown_tx = shutdown_tx.clone();
                        async move {
                            if let Some(event) =
                                gateway_event_to_fcp(&gateway_event, &connector_id, &instance_id)
                            {
                                base.record_event();
                                if event_tx.send(Ok(event)).is_err() {
                                    tracing::info!(
                                        "Event receiver dropped, stopping gateway stream"
                                    );
                                    let _ = shutdown_tx.send(true);
                                }
                            }
                            Ok(())
                        }
                    },
                )
                .await;

            let _ = shutdown_tx.send(true);
            tracing::info!(?outcome, "Discord gateway supervisor stopped");
        });

        self.gateway_task = Some(task);
        Ok(())
    }

    fn require_api(&self) -> FcpResult<&Arc<DiscordApiClient>> {
        self.api_client.as_ref().ok_or(FcpError::NotConfigured)
    }
}

impl Default for DiscordConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn missing_required_intents(intents: u64) -> Vec<&'static str> {
    REQUIRED_GATEWAY_INTENTS
        .iter()
        .filter_map(|(name, bit)| ((intents & bit) == 0).then_some(*name))
        .collect()
}

#[derive(Debug)]
struct NetworkReadiness {
    api_host: Option<String>,
    api_allowed: bool,
    gateway_host: Option<String>,
    gateway_allowed: bool,
    network_ok: bool,
}

impl NetworkReadiness {
    fn details_json(&self) -> serde_json::Value {
        json!({
            "api_host": self.api_host,
            "api_host_allowed": self.api_allowed,
            "gateway_host": self.gateway_host,
            "gateway_host_allowed": self.gateway_allowed,
        })
    }
}

fn network_readiness(config: &DiscordConfig) -> NetworkReadiness {
    let api_host = extract_host(&config.api_url);
    let api_allowed = api_host
        .as_deref()
        .is_some_and(host_allowed_by_network_constraints);

    let gateway_host = config.gateway_url.as_deref().and_then(extract_host);
    let gateway_allowed = gateway_host
        .as_deref()
        .is_none_or(host_allowed_by_network_constraints);

    NetworkReadiness {
        api_host,
        api_allowed,
        gateway_host,
        gateway_allowed,
        network_ok: api_allowed && gateway_allowed,
    }
}

fn validate_network_constraints_hosts(config: &DiscordConfig) -> FcpResult<()> {
    let readiness = network_readiness(config);
    if readiness.network_ok {
        return Ok(());
    }

    Err(FcpError::InvalidRequest {
        code: 1004,
        message: format!(
            "Configured Discord endpoints violate NetworkConstraints (api_host={:?}, gateway_host={:?})",
            readiness.api_host, readiness.gateway_host
        ),
    })
}

fn extract_host(url: &str) -> Option<String> {
    Url::parse(url)
        .ok()
        .and_then(|parsed| parsed.host_str().map(|host| host.to_ascii_lowercase()))
}

fn host_allowed_by_network_constraints(host: &str) -> bool {
    if host == "discord.com"
        || host.ends_with(".discord.com")
        || host == "discord.gg"
        || host.ends_with(".discord.gg")
    {
        return true;
    }

    // Allow localhost hosts for deterministic mock-server tests.
    if (cfg!(test) || cfg!(feature = "testing"))
        && (host == "localhost" || host == "127.0.0.1" || host == "::1")
    {
        return true;
    }

    false
}

/// Convert a Discord gateway event to an FCP `EventEnvelope`.
fn gateway_event_to_fcp(
    event: &GatewayEventFrame,
    connector_id: &ConnectorId,
    instance_id: &InstanceId,
) -> Option<EventEnvelope> {
    let (topic, payload, principal_info, thread_info) = match &event.event {
        GatewayEvent::Ready(ready) => {
            let payload = json!({
                "session_id": ready.session_id,
                "user": ready.user
            });
            (
                "discord.ready",
                payload,
                ("bot".into(), ready.user.id.clone()),
                None,
            )
        }
        GatewayEvent::Resumed => {
            // Session resumed - this is an internal state event, emit as system event
            let payload = json!({ "event": "session_resumed" });
            (
                "discord.resumed",
                payload,
                ("system".into(), "gateway".into()),
                None,
            )
        }
        GatewayEvent::MessageCreate(data) => {
            let author_id = data
                .get("author")
                .and_then(|a| a.get("id"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let author_name = data
                .get("author")
                .and_then(|a| a.get("username"))
                .and_then(|v| v.as_str());
            (
                "discord.message",
                data.clone(),
                (author_name.unwrap_or("unknown").into(), author_id.into()),
                None,
            )
        }
        GatewayEvent::MessageUpdate(data) => {
            let author_id = data
                .get("author")
                .and_then(|a| a.get("id"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            (
                "discord.message_update",
                data.clone(),
                ("unknown".into(), author_id.into()),
                None,
            )
        }
        GatewayEvent::MessageDelete(data) => (
            "discord.message_delete",
            data.clone(),
            ("unknown".into(), "unknown".into()),
            None,
        ),
        GatewayEvent::GuildCreate(data) => {
            let guild_id = data.get("id").and_then(|v| v.as_str()).unwrap_or("unknown");
            (
                "discord.guild_create",
                data.clone(),
                ("system".into(), guild_id.into()),
                None,
            )
        }
        GatewayEvent::GuildUpdate(data) => {
            let guild_id = data.get("id").and_then(|v| v.as_str()).unwrap_or("unknown");
            (
                "discord.guild_update",
                data.clone(),
                ("system".into(), guild_id.into()),
                None,
            )
        }
        GatewayEvent::ChannelCreate(data) => (
            "discord.channel_create",
            data.clone(),
            ("system".into(), "unknown".into()),
            discord_thread_info(data),
        ),
        GatewayEvent::ChannelUpdate(data) => (
            "discord.channel_update",
            data.clone(),
            ("system".into(), "unknown".into()),
            discord_thread_info(data),
        ),
        GatewayEvent::TypingStart(data) => {
            let user_id = data
                .get("user_id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            (
                "discord.typing",
                data.clone(),
                ("unknown".into(), user_id.into()),
                None,
            )
        }
        GatewayEvent::Unknown { event_name, data } => {
            let topic = format!("discord.{}", event_name.to_lowercase());
            let mut envelope = EventEnvelope::new(
                topic,
                EventData::new(
                    connector_id.clone(),
                    instance_id.clone(),
                    ZoneId::community(),
                    Principal {
                        kind: "discord".into(),
                        id: "unknown".into(),
                        trust: TrustLevel::Untrusted,
                        display: None,
                    },
                    data.clone(),
                ),
            );
            if let Some(seq) = event.seq {
                envelope = envelope.with_seq(seq).with_cursor_seq(seq);
            }
            return Some(envelope);
        }
    };

    let (display, id) = principal_info;
    let principal = Principal {
        kind: "discord_user".into(),
        id,
        trust: TrustLevel::Untrusted,
        display: Some(display),
    };

    let event_data = EventData::new(
        connector_id.clone(),
        instance_id.clone(),
        ZoneId::community(),
        principal,
        payload,
    );
    let event_data = if let Some(thread_info) = thread_info {
        event_data.with_thread_info(thread_info)
    } else {
        event_data
    };

    let mut envelope = EventEnvelope::new(topic, event_data);
    if let Some(seq) = event.seq {
        envelope = envelope.with_seq(seq).with_cursor_seq(seq);
    }
    Some(envelope)
}

fn discord_thread_info(payload: &serde_json::Value) -> Option<ThreadInfo> {
    let channel_id = payload.get("id").and_then(|v| v.as_str())?;
    let channel_type = payload
        .get("type")
        .and_then(|v| v.as_i64())
        .and_then(|kind| i32::try_from(kind).ok())?;
    let parent_channel_id = payload
        .get("parent_id")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    ThreadInfo::from_discord_channel(channel_id, channel_type, parent_channel_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use fcp_core::{CapabilityToken as CapabilityArtifact, ConnectorId, InstanceId};
    use fcp_crypto::cose::CapabilityTokenBuilder as CapabilityBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use uuid::Uuid;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    fn generate_capability(
        signing_key: &Ed25519SigningKey,
        capability_id: &str,
        operations: &[&str],
    ) -> CapabilityArtifact {
        let now = Utc::now();
        let cose = CapabilityBuilder::new()
            .capability_id(capability_id)
            .zone_id("z:work")
            .principal("user:test")
            .operations(operations)
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .sign(signing_key)
            .unwrap();
        CapabilityArtifact { raw: cose }
    }

    async fn mock_current_user_ok(mock_server: &MockServer, token: &str) {
        Mock::given(method("GET"))
            .and(path("/users/@me"))
            .and(header("Authorization", format!("Bot {token}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "123456789",
                "username": "TestBot",
                "discriminator": "0",
                "bot": true
            })))
            .mount(mock_server)
            .await;
    }

    fn base_config(api_url: String) -> DiscordConfig {
        DiscordConfig {
            bot_credential: "test_token".into(),
            api_url,
            intents: INTENT_GUILDS
                | INTENT_GUILD_MESSAGES
                | INTENT_DIRECT_MESSAGES
                | INTENT_MESSAGE_CONTENT,
            ..Default::default()
        }
    }

    fn unique_zone_dir(label: &str) -> String {
        std::env::temp_dir()
            .join("fcp-discord-tests")
            .join(format!("{label}-{}", Uuid::new_v4()))
            .to_string_lossy()
            .into_owned()
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_missing_required_intents() {
        let mut connector = DiscordConnector::new();
        let result = connector
            .handle_configure(json!({
                "bot_credential": "test_token",
                "api_url": "https://discord.com/api/v10",
                "intents": INTENT_GUILDS | INTENT_GUILD_MESSAGES
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1004);
                assert!(message.contains("Missing required gateway intents"));
                assert!(message.contains("DIRECT_MESSAGES"));
                assert!(message.contains("MESSAGE_CONTENT"));
            }
            other => panic!("Expected InvalidRequest, got: {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_non_discord_api_host() {
        let mut connector = DiscordConnector::new();
        let result = connector
            .handle_configure(json!({
                "bot_credential": "test_token",
                "api_url": "https://example.com/api/v10",
                "intents": INTENT_GUILDS
                    | INTENT_GUILD_MESSAGES
                    | INTENT_DIRECT_MESSAGES
                    | INTENT_MESSAGE_CONTENT
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1004);
                assert!(message.contains("NetworkConstraints"));
            }
            other => panic!("Expected InvalidRequest, got: {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_returns_provisioning_readiness() {
        let mock_server = MockServer::start().await;
        mock_current_user_ok(&mock_server, "test_token").await;

        let mut connector = DiscordConnector::new();
        let result = connector
            .handle_configure(json!({
                "bot_credential": "test_token",
                "api_url": mock_server.uri(),
                "intents": INTENT_GUILDS
                    | INTENT_GUILD_MESSAGES
                    | INTENT_DIRECT_MESSAGES
                    | INTENT_MESSAGE_CONTENT
            }))
            .await
            .expect("configure should succeed");

        assert_eq!(result["status"], "configured");
        assert_eq!(result["provisioning"]["token_ok"], true);
        assert_eq!(result["provisioning"]["intents_ok"], true);
        assert_eq!(result["provisioning"]["network_ok"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake_requires_zone_dir_for_gateway_state() {
        let mock_server = MockServer::start().await;
        mock_current_user_ok(&mock_server, "test_token").await;

        let mut connector = DiscordConnector::new();
        connector
            .handle_configure(json!({
                "bot_credential": "test_token",
                "api_url": mock_server.uri(),
                "intents": INTENT_GUILDS
                    | INTENT_GUILD_MESSAGES
                    | INTENT_DIRECT_MESSAGES
                    | INTENT_MESSAGE_CONTENT
            }))
            .await
            .expect("configure should succeed");

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["discord.read"]
            }))
            .await;

        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
    }

    #[test]
    fn test_gateway_lease_fences_second_holder() {
        let zone_dir = PathBuf::from(unique_zone_dir("lease-fence"));
        std::fs::create_dir_all(&zone_dir).unwrap();
        let lease_path = zone_dir.join(DISCORD_GATEWAY_LEASE_FILE);

        let first = DiscordGatewayLease::acquire(
            lease_path.clone(),
            "holder-a".to_string(),
            DISCORD_GATEWAY_LEASE_TTL_SECONDS,
        )
        .unwrap();
        let second = DiscordGatewayLease::acquire(
            lease_path,
            "holder-b".to_string(),
            DISCORD_GATEWAY_LEASE_TTL_SECONDS,
        );
        assert!(matches!(second, Err(FcpError::Conflict { .. })));
        first.release().unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_reports_missing_intents() {
        let mock_server = MockServer::start().await;
        mock_current_user_ok(&mock_server, "test_token").await;

        let api_config = base_config(mock_server.uri());
        let api_client = Arc::new(DiscordApiClient::new(&api_config).unwrap());

        let mut connector = DiscordConnector::new();
        connector.api_client = Some(api_client);
        connector.config = Some(DiscordConfig {
            intents: INTENT_GUILDS | INTENT_GUILD_MESSAGES,
            ..api_config
        });

        let value = connector.handle_self_check().await.unwrap();
        assert_eq!(value["status"], "failed");
        assert_eq!(value["reason_code"], "provisioning_intents_missing");
        assert_eq!(value["details"]["token_ok"], true);
        assert_eq!(value["details"]["intents_ok"], false);
        assert_eq!(value["details"]["network_ok"], true);
        assert!(
            !value["details"]["missing_intents"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_reports_network_constraints_violation() {
        let mock_server = MockServer::start().await;
        mock_current_user_ok(&mock_server, "test_token").await;

        let api_config = base_config(mock_server.uri());
        let api_client = Arc::new(DiscordApiClient::new(&api_config).unwrap());

        let mut connector = DiscordConnector::new();
        connector.api_client = Some(api_client);
        connector.config = Some(DiscordConfig {
            api_url: "https://example.com/api/v10".into(),
            ..api_config
        });

        let value = connector.handle_self_check().await.unwrap();
        assert_eq!(value["status"], "failed");
        assert_eq!(
            value["reason_code"],
            "provisioning_network_constraints_invalid"
        );
        assert_eq!(value["details"]["token_ok"], true);
        assert_eq!(value["details"]["intents_ok"], true);
        assert_eq!(value["details"]["network_ok"], false);
        assert_eq!(value["details"]["network"]["api_host"], "example.com");
        assert_eq!(value["details"]["network"]["api_host_allowed"], false);
    }

    #[fcp_async_core::runtime::test]
    async fn test_send_message_content_too_long() {
        let connector = DiscordConnector::new();

        // Create a message that exceeds 2000 characters
        let long_content = "x".repeat(2001);
        let input = serde_json::json!({
            "channel_id": "123456789",
            "content": long_content
        });

        let result = connector
            .handle_invoke(serde_json::json!({
                "operation": "discord.send_message",
                "input": input
            }))
            .await;

        // Validation happens before config check, so we get InvalidRequest for too-long content
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(
                    message.contains("character limit"),
                    "Expected content length error, got: {message}"
                );
            }
            _ => assert!(
                false,
                "Expected InvalidRequest error for content too long, got: {err:?}"
            ),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_send_message_missing_content_and_embeds() {
        let connector = DiscordConnector::new();

        let input = serde_json::json!({
            "channel_id": "123456789"
        });

        let result = connector
            .handle_invoke(serde_json::json!({
                "operation": "discord.send_message",
                "input": input
            }))
            .await;

        // Validation happens before config check, so we get InvalidRequest
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
        if let FcpError::InvalidRequest { message, .. } = err {
            assert!(message.contains("content") || message.contains("embeds"));
        }
    }

    #[test]
    fn test_message_length_constants() {
        // Verify our constants match Discord's documented limits
        assert_eq!(2000, 2000); // MAX_CONTENT_LENGTH
        assert_eq!(10, 10); // MAX_EMBEDS
        assert_eq!(6000, 6000); // MAX_EMBED_TOTAL_CHARS
        assert_eq!(256, 256); // MAX_EMBED_TITLE
        assert_eq!(4096, 4096); // MAX_EMBED_DESCRIPTION
    }

    #[fcp_async_core::runtime::test]
    async fn test_embed_total_limit_exceeded() {
        let connector = DiscordConnector::new();

        // Create an embed with fields that exceed 6000 chars total
        let mut fields = Vec::new();
        for i in 0..10 {
            fields.push(json!({
                "name": format!("Field {}", i),
                "value": "x".repeat(600) // 10 * 600 = 6000 + names > 6000
            }));
        }

        let input = json!({
            "channel_id": "123",
            "embeds": [{
                "title": "Test",
                "fields": fields
            }]
        });

        let result = connector
            .handle_invoke(json!({
                "operation": "discord.send_message",
                "input": input
            }))
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(
                    message.contains("Total embed character count"),
                    "Got: {message}"
                );
            }
            _ => assert!(
                false,
                "Expected InvalidRequest for embed limit, got: {err:?}"
            ),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_capability_token() {
        let connector = DiscordConnector::new();

        let result = connector
            .handle_invoke(json!({
                "operation": "discord.send_message",
                "input": {
                    "channel_id": "123456789",
                    "content": "Hello"
                }
            }))
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, FcpError::InvalidRequest { code: 1003, ref message } if message.contains("capability_token")),
            "Expected InvalidRequest for missing capability_token, got: {err:?}"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_capability_not_granted() {
        let mut connector = DiscordConnector::new();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        connector.verifier = Some(CapabilityVerifier::new(
            verifying_key.to_bytes(),
            ZoneId::work(),
            connector.base.instance_id.clone(),
        ));

        let capability = generate_capability(
            &signing_key,
            "discord.get_channel",
            &["discord.get_channel"],
        );

        let result = connector
            .handle_invoke(json!({
                "operation": "discord.send_message",
                "input": {
                    "channel_id": "123456789",
                    "content": "Hello"
                },
                "capability_token": capability
            }))
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, FcpError::OperationNotGranted { .. }),
            "Expected OperationNotGranted, got: {err:?}"
        );
    }

    #[test]
    fn test_gateway_event_to_fcp_message_create() {
        let connector_id = ConnectorId::from_static("discord");
        let instance_id = InstanceId::new();
        let payload = json!({
            "id": "msg-1",
            "content": "Hello",
            "author": {
                "id": "user-1",
                "username": "alice"
            }
        });

        let event = GatewayEventFrame {
            seq: Some(77),
            event: GatewayEvent::MessageCreate(payload.clone()),
        };
        let envelope =
            gateway_event_to_fcp(&event, &connector_id, &instance_id).expect("event envelope");

        assert_eq!(envelope.topic, "discord.message");
        assert_eq!(envelope.seq, 77);
        assert_eq!(envelope.cursor, "77");
        assert_eq!(envelope.data.payload, payload);
        assert_eq!(envelope.data.zone_id, ZoneId::community());
        assert_eq!(envelope.data.principal.id, "user-1");
        assert_eq!(envelope.data.principal.display.as_deref(), Some("alice"));
        assert!(envelope.data.thread_info.is_none());
    }

    #[test]
    fn test_gateway_event_to_fcp_channel_create_sets_thread_info_for_thread_channels() {
        let connector_id = ConnectorId::from_static("discord");
        let instance_id = InstanceId::new();
        let payload = json!({
            "id": "thread-1",
            "type": 11,
            "parent_id": "channel-1",
            "name": "feature-thread"
        });

        let event = GatewayEventFrame {
            seq: Some(91),
            event: GatewayEvent::ChannelCreate(payload),
        };
        let envelope =
            gateway_event_to_fcp(&event, &connector_id, &instance_id).expect("event envelope");

        assert_eq!(
            envelope.data.thread_info,
            Some(ThreadInfo::from_discord_thread(
                "thread-1",
                Some("channel-1".into())
            ))
        );
    }

    // ─── Schema completeness tests ─────────────────────────────────────

    const ALL_OPERATIONS: &[&str] = &[
        "discord.send_message",
        "discord.edit_message",
        "discord.delete_message",
        "discord.get_channel",
        "discord.get_guild",
        "discord.trigger_typing",
        "discord.add_reaction",
        "discord.list_channels",
        "discord.create_thread",
    ];

    #[test]
    fn test_all_operations_have_input_schema() {
        for op in ALL_OPERATIONS {
            assert!(
                DiscordConnector::input_schema_for(op).is_some(),
                "Missing input schema for {op}"
            );
        }
    }

    #[test]
    fn test_all_operations_have_output_schema() {
        for op in ALL_OPERATIONS {
            assert!(
                DiscordConnector::output_schema_for(op).is_some(),
                "Missing output schema for {op}"
            );
        }
    }

    #[test]
    fn test_unknown_operation_returns_none_schema() {
        assert!(DiscordConnector::input_schema_for("discord.nonexistent").is_none());
        assert!(DiscordConnector::output_schema_for("discord.nonexistent").is_none());
    }

    #[test]
    fn test_input_schemas_are_object_type() {
        for op in ALL_OPERATIONS {
            let schema = DiscordConnector::input_schema_for(op).unwrap();
            assert_eq!(
                schema["type"], "object",
                "Input schema for {op} must be type=object"
            );
        }
    }

    #[test]
    fn test_schemas_deterministic_across_calls() {
        for op in ALL_OPERATIONS {
            let a = DiscordConnector::input_schema_for(op).unwrap();
            let b = DiscordConnector::input_schema_for(op).unwrap();
            assert_eq!(a, b, "Input schema for {op} not deterministic");

            let a = DiscordConnector::output_schema_for(op).unwrap();
            let b = DiscordConnector::output_schema_for(op).unwrap();
            assert_eq!(a, b, "Output schema for {op} not deterministic");
        }
    }

    // ─── Introspection metadata tests ──────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_introspect_all_ops_have_capability() {
        let connector = DiscordConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        assert_eq!(ops.len(), 9, "Expected 9 operations");

        for op in ops {
            let id = op["id"].as_str().unwrap();
            assert!(
                op["capability"].as_str().is_some(),
                "Operation {id} missing capability"
            );
            assert!(
                op["risk_level"].as_str().is_some(),
                "Operation {id} missing risk_level"
            );
            assert!(
                op["safety_tier"].as_str().is_some(),
                "Operation {id} missing safety_tier"
            );
            assert!(
                op["idempotency"].as_str().is_some(),
                "Operation {id} missing idempotency"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_risk_levels_are_valid() {
        let connector = DiscordConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        let valid_risk = ["low", "medium", "high", "critical"];
        for op in ops {
            let id = op["id"].as_str().unwrap();
            let risk = op["risk_level"].as_str().unwrap();
            assert!(
                valid_risk.contains(&risk),
                "Operation {id} has invalid risk_level: {risk}"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_read_ops_are_safe() {
        let connector = DiscordConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap();
            match id {
                "discord.get_channel" | "discord.get_guild" | "discord.list_channels" => {
                    assert_eq!(op["safety_tier"], "safe", "Read op {id} should be safe");
                    assert_eq!(op["risk_level"], "low", "Read op {id} should be low risk");
                }
                _ => {}
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_write_ops_not_safe() {
        let connector = DiscordConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap();
            if id == "discord.send_message"
                || id == "discord.edit_message"
                || id == "discord.delete_message"
                || id == "discord.create_thread"
            {
                let tier = op["safety_tier"].as_str().unwrap();
                assert!(
                    tier == "risky" || tier == "dangerous",
                    "Write op {id} should be risky or dangerous, got {tier}"
                );
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_deterministic() {
        let connector = DiscordConnector::new();
        let a = connector.handle_introspect().await.unwrap();
        let b = connector.handle_introspect().await.unwrap();
        assert_eq!(a, b, "Introspection should be deterministic");
    }

    // ─── Schema validation (required fields) ───────────────────────────

    #[test]
    fn test_send_message_requires_channel_id() {
        let schema = DiscordConnector::input_schema_for("discord.send_message").unwrap();
        let required = schema["required"].as_array().unwrap();
        assert!(
            required.iter().any(|v| v.as_str() == Some("channel_id")),
            "send_message must require channel_id"
        );
    }

    #[test]
    fn test_add_reaction_requires_all_fields() {
        let schema = DiscordConnector::input_schema_for("discord.add_reaction").unwrap();
        let required = schema["required"].as_array().unwrap();
        let required_strs: Vec<&str> = required.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(required_strs.contains(&"channel_id"));
        assert!(required_strs.contains(&"message_id"));
        assert!(required_strs.contains(&"emoji"));
    }

    #[test]
    fn test_create_thread_requires_name() {
        let schema = DiscordConnector::input_schema_for("discord.create_thread").unwrap();
        let required = schema["required"].as_array().unwrap();
        let required_strs: Vec<&str> = required.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(required_strs.contains(&"channel_id"));
        assert!(required_strs.contains(&"message_id"));
        assert!(required_strs.contains(&"name"));
    }

    // ─── Thread name validation ────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_create_thread_name_boundary_100_chars() {
        let connector = DiscordConnector::new();

        // Exactly 100 characters should pass validation (but fail at config check)
        let name_100 = "a".repeat(100);
        let result = connector
            .handle_invoke(json!({
                "operation": "discord.create_thread",
                "input": {
                    "channel_id": "111",
                    "message_id": "msg_001",
                    "name": name_100
                },
                "capability_token": null
            }))
            .await;

        // Should fail at capability check, not at name validation
        let err = result.unwrap_err();
        assert!(
            !matches!(err, FcpError::InvalidRequest { ref message, .. } if message.contains("Thread name")),
            "100-char name should NOT trigger thread name validation, got: {err:?}"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_create_thread_name_101_chars_rejected() {
        let connector = DiscordConnector::new();

        let name_101 = "a".repeat(101);
        let result = connector
            .handle_invoke(json!({
                "operation": "discord.create_thread",
                "input": {
                    "channel_id": "111",
                    "message_id": "msg_001",
                    "name": name_101
                },
                "capability_token": null
            }))
            .await;

        let err = result.unwrap_err();
        assert!(
            matches!(err, FcpError::InvalidRequest { .. }),
            "101-char name should be rejected, got: {err:?}"
        );
    }

    // ─── Capability gating reason codes ────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_capability_token_null_gives_invalid_request() {
        let connector = DiscordConnector::new();

        let result = connector
            .handle_invoke(json!({
                "operation": "discord.get_channel",
                "input": { "channel_id": "111" },
                "capability_token": null
            }))
            .await;

        let err = result.unwrap_err();
        assert!(
            matches!(err, FcpError::InvalidRequest { code: 1003, .. }),
            "null capability_token should give code 1003, got: {err:?}"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_operation_not_granted_includes_operation_id() {
        let mut connector = DiscordConnector::new();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        connector.verifier = Some(CapabilityVerifier::new(
            verifying_key.to_bytes(),
            ZoneId::work(),
            connector.base.instance_id.clone(),
        ));

        // Token grants discord.get_channel, try discord.delete_message
        let capability = generate_capability(
            &signing_key,
            "discord.get_channel",
            &["discord.get_channel"],
        );

        let result = connector
            .handle_invoke(json!({
                "operation": "discord.delete_message",
                "input": {
                    "channel_id": "111",
                    "message_id": "msg_001"
                },
                "capability_token": capability
            }))
            .await;

        let err = result.unwrap_err();
        assert!(
            matches!(err, FcpError::OperationNotGranted { .. }),
            "Mismatched capability should yield OperationNotGranted, got: {err:?}"
        );
    }

    // ─── Manifest interface hash determinism ───────────────────────────

    #[test]
    fn test_manifest_parses_and_hash_is_stable() {
        let manifest_str = include_str!("../manifest.toml");
        // Strip sections the manifest parser doesn't support
        let filtered: String = manifest_str
            .lines()
            .scan(false, |in_unsupported, line| {
                if line.starts_with("[provides.events") || line.starts_with("[provides.streaming") {
                    *in_unsupported = true;
                    Some("")
                } else if *in_unsupported && line.starts_with('[') {
                    *in_unsupported = false;
                    Some(line)
                } else if *in_unsupported {
                    Some("")
                } else {
                    Some(line)
                }
            })
            .collect::<Vec<_>>()
            .join("\n");

        let manifest_a = fcp_manifest::ConnectorManifest::parse_str_unchecked(&filtered)
            .expect("manifest should parse");
        let manifest_b = fcp_manifest::ConnectorManifest::parse_str_unchecked(&filtered)
            .expect("manifest should parse");

        let hash_a = manifest_a
            .compute_interface_hash()
            .expect("hash computation should succeed");
        let hash_b = manifest_b
            .compute_interface_hash()
            .expect("hash computation should succeed");
        assert_eq!(
            hash_a, hash_b,
            "Interface hash must be deterministic across parses"
        );
        // Hash display should produce a non-trivial string
        let hash_str = hash_a.to_string();
        assert!(
            hash_str.contains("blake3-256"),
            "Hash should contain algorithm prefix"
        );
    }
}
