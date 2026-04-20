//! FCP Connector implementation for Telegram.
//!
//! Implements the FcpConnector trait with Telegram-specific operations.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fcp_async_core::channel::{broadcast, watch};
use fcp_async_core::sync::RwLock;
use fcp_core::*;
use fcp_sdk::{
    ErrorClass, FormatMode, Formatter, Limits, classify_error_message,
    runtime::{PollResult, PollingCursor, PollingSupervisor, SupervisorConfig},
    validate_input_with_limits, validate_output_with_limits,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::client::TelegramClient;
use crate::error::TelegramError;
use crate::limits::{MEDIA_CAPTION_MAX_CHARS, MESSAGE_TEXT_MAX_CHARS};
use crate::types::*;

const TELEGRAM_POLL_CURSOR_FILE: &str = "telegram_poll_cursor.json";
const TELEGRAM_POLL_LEASE_FILE: &str = "telegram_poll_lease.json";
const MANIFEST_TOML: &str = include_str!("../manifest.toml");

fn current_unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn write_json_file_atomic<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let tmp_path = path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
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

#[derive(Debug, Default)]
struct TelegramPollingCursor {
    offset: Option<i64>,
    last_poll_at: Option<Instant>,
    last_poll_count: usize,
    state_path: Option<PathBuf>,
}

impl TelegramPollingCursor {
    fn new(state_path: Option<PathBuf>) -> Self {
        Self {
            state_path,
            ..Self::default()
        }
    }
}

impl PollingCursor for TelegramPollingCursor {
    fn offset(&self) -> Option<i64> {
        self.offset
    }

    fn set_offset(&mut self, offset: i64) {
        self.offset = Some(offset);
    }

    fn clear_offset(&mut self) {
        self.offset = None;
    }

    fn last_poll_at(&self) -> Option<Instant> {
        self.last_poll_at
    }

    fn record_poll(&mut self, at: Instant, updates_received: usize) {
        self.last_poll_at = Some(at);
        self.last_poll_count = updates_received;
    }

    fn last_poll_count(&self) -> usize {
        self.last_poll_count
    }

    fn persist(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(path) = &self.state_path {
            let state = TelegramPollingCursorState {
                offset: self.offset,
                last_poll_count: self.last_poll_count,
                updated_at: current_unix_timestamp_secs(),
            };
            write_json_file_atomic(path, &state)?;
        }
        Ok(())
    }

    fn restore(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(path) = &self.state_path
            && let Some(state) = read_json_file_if_exists::<TelegramPollingCursorState>(path)?
        {
            self.offset = state.offset;
            self.last_poll_count = state.last_poll_count;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct TelegramPollLease {
    path: PathBuf,
    holder_instance_id: String,
    lease_seq: u64,
    ttl_secs: u64,
}

impl TelegramPollLease {
    fn acquire(path: PathBuf, holder_instance_id: String, ttl_secs: u64) -> FcpResult<Self> {
        let ttl_secs = ttl_secs.max(MIN_POLL_LEASE_TTL_SECS);
        let now = current_unix_timestamp_secs();
        let previous =
            read_json_file_if_exists::<TelegramPollLeaseRecord>(&path).map_err(|err| {
                FcpError::Internal {
                    message: format!(
                        "Failed to read polling lease file '{}': {err}",
                        path.display()
                    ),
                }
            })?;

        if let Some(record) = &previous
            && record.expires_at > now
            && record.holder_instance_id != holder_instance_id
        {
            return Err(FcpError::Conflict {
                message: format!(
                    "telegram polling lease held by '{}' (lease_seq={}) until {}",
                    record.holder_instance_id, record.lease_seq, record.expires_at
                ),
            });
        }

        let lease_seq = previous
            .map(|record| record.lease_seq.saturating_add(1))
            .unwrap_or(1);

        let record = TelegramPollLeaseRecord {
            holder_instance_id: holder_instance_id.clone(),
            lease_seq,
            updated_at: now,
            expires_at: now.saturating_add(ttl_secs),
        };

        write_json_file_atomic(&path, &record).map_err(|err| FcpError::Internal {
            message: format!(
                "Failed to persist polling lease file '{}': {err}",
                path.display()
            ),
        })?;

        Ok(Self {
            path,
            holder_instance_id,
            lease_seq,
            ttl_secs,
        })
    }

    fn renew(&self) -> FcpResult<()> {
        let Some(mut record) = read_json_file_if_exists::<TelegramPollLeaseRecord>(&self.path)
            .map_err(|err| FcpError::Internal {
                message: format!(
                    "Failed to read polling lease file '{}': {err}",
                    self.path.display()
                ),
            })?
        else {
            return Err(FcpError::Conflict {
                message: "telegram polling lease file is missing".into(),
            });
        };

        if record.holder_instance_id != self.holder_instance_id
            || record.lease_seq != self.lease_seq
        {
            return Err(FcpError::Conflict {
                message: format!(
                    "telegram polling lease fencing violation (expected holder='{}' lease_seq={}, found holder='{}' lease_seq={})",
                    self.holder_instance_id,
                    self.lease_seq,
                    record.holder_instance_id,
                    record.lease_seq
                ),
            });
        }

        let now = current_unix_timestamp_secs();
        record.updated_at = now;
        record.expires_at = now.saturating_add(self.ttl_secs);
        write_json_file_atomic(&self.path, &record).map_err(|err| FcpError::Internal {
            message: format!(
                "Failed to renew polling lease file '{}': {err}",
                self.path.display()
            ),
        })?;
        Ok(())
    }

    fn release(&self) -> FcpResult<()> {
        let record =
            read_json_file_if_exists::<TelegramPollLeaseRecord>(&self.path).map_err(|err| {
                FcpError::Internal {
                    message: format!(
                        "Failed to read polling lease file '{}': {err}",
                        self.path.display()
                    ),
                }
            })?;

        if let Some(record) = record
            && record.holder_instance_id == self.holder_instance_id
            && record.lease_seq == self.lease_seq
            && let Err(err) = fs::remove_file(&self.path)
            && err.kind() != io::ErrorKind::NotFound
        {
            return Err(FcpError::Internal {
                message: format!(
                    "Failed to release polling lease file '{}': {err}",
                    self.path.display()
                ),
            });
        }

        Ok(())
    }
}

/// Telegram FCP connector.
pub struct TelegramConnector {
    base: Arc<BaseConnector>,
    config: Option<TelegramConfig>,
    client: Option<TelegramClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
    zone_dir: Option<PathBuf>,
    // instance_id: InstanceId, // Remove

    // Polling state
    poll_running: Arc<RwLock<bool>>,
    poll_task: Option<fcp_async_core::task::JoinHandle<()>>,
    poll_shutdown_tx: Option<watch::Sender<bool>>,

    // Event broadcast
    event_tx: broadcast::Sender<FcpResult<EventEnvelope>>,

    // Metrics
    start_time: Instant,
}

fn validate_bot_token_syntax(token: &str) -> FcpResult<()> {
    let (bot_id, secret) = token.split_once(':').ok_or(FcpError::InvalidRequest {
        code: 1004,
        message: "Telegram bot token must be in '<bot_id>:<secret>' format".into(),
    })?;

    if bot_id.len() < 6 || !bot_id.chars().all(|c| c.is_ascii_digit()) {
        return Err(FcpError::InvalidRequest {
            code: 1004,
            message: "Telegram bot token has invalid bot_id prefix".into(),
        });
    }
    if secret.len() < 20
        || !secret
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
    {
        return Err(FcpError::InvalidRequest {
            code: 1004,
            message: "Telegram bot token has invalid secret segment".into(),
        });
    }

    Ok(())
}

fn is_telegram_or_local_base_url(base_url: &str) -> bool {
    let Ok(url) = Url::parse(base_url) else {
        return false;
    };
    let Some(host) = url.host_str() else {
        return false;
    };

    host.eq_ignore_ascii_case("api.telegram.org")
        || host.eq_ignore_ascii_case("localhost")
        || host.ends_with(".localhost")
        || host == "127.0.0.1"
        || host == "::1"
}

impl TelegramConnector {
    /// Create a new Telegram connector.
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(1000);

        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("fcp.telegram"))),
            config: None,
            client: None,
            verifier: None,
            session_id: None,
            zone_dir: None,
            // instance_id: InstanceId::new(), // Remove
            poll_running: Arc::new(RwLock::new(false)),
            poll_task: None,
            poll_shutdown_tx: None,
            event_tx,
            start_time: Instant::now(),
        }
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    /// Handle configure method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let mut config: TelegramConfig =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid configuration: {e}"),
            })?;

        config.validate_runtime_settings()?;
        let auth_mode = config.resolve_auth_mode()?;
        let normalized_base_url = config.normalize_base_url()?;
        config.base_url = Some(normalized_base_url.clone());

        let mut status = "configured";
        let mut details = json!({});
        match auth_mode {
            TelegramAuthConfig::BotToken => {
                let bot_credential = config
                    .credential
                    .as_deref()
                    .map(str::trim)
                    .ok_or(FcpError::InvalidRequest {
                        code: 1004,
                        message: "Missing required credential in configuration".into(),
                    })?
                    .to_string();

                validate_bot_token_syntax(&bot_credential)?;
                config.credential = Some(bot_credential.clone());
                config.credential_id = None;

                let mut client =
                    TelegramClient::new(&bot_credential).map_err(|e| FcpError::Internal {
                        message: format!("Failed to create HTTP client: {e}"),
                    })?;
                client = client.with_base_url(&normalized_base_url);

                let bot_info =
                    client
                        .get_me()
                        .await
                        .map_err(|e: TelegramError| FcpError::External {
                            service: "telegram".into(),
                            message: format!("Credential validation failed: {e}"),
                            status_code: None,
                            retryable: e.is_retryable(),
                            retry_after: None,
                        })?;

                details = json!({
                    "bot_id": bot_info.id,
                    "username": bot_info.username,
                    "base_url": normalized_base_url,
                });

                self.client = Some(client);
            }
            TelegramAuthConfig::CredentialId(id) => {
                config.credential = None;
                config.credential_id = Some(id);
                self.client = None;
                status = "configured_pending_token_materialization";
                details = json!({
                    "credential_id": id.to_string(),
                    "base_url": normalized_base_url,
                    "note": "credential_id configured; direct getMe validation requires token materialization in current runtime",
                });
            }
        }

        self.config = Some(config);
        self.base.set_configured(true);

        info!(auth_mode = ?auth_mode, "Telegram connector configured");
        Ok(json!({
            "status": status,
            "auth_mode": self.config.as_ref().map_or("unknown", TelegramConfig::auth_label),
            "details": details
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
            message: "zone_dir is required for Telegram polling cursor + singleton-writer lease persistence".into(),
        })?;

        // Verify bot is reachable
        let client = self.client.as_ref().ok_or_else(|| {
            if self
                .config
                .as_ref()
                .and_then(|cfg| cfg.credential_id)
                .is_some()
            {
                FcpError::InvalidRequest {
                    code: 1004,
                    message: "Connector is configured with credential_id but no materialized bot token is available for handshake validation".into(),
                }
            } else {
                FcpError::NotConfigured
            }
        })?;
        let zone_dir = PathBuf::from(zone_dir);
        fs::create_dir_all(&zone_dir).map_err(|err| FcpError::Internal {
            message: format!(
                "Failed to prepare Telegram zone_dir '{}': {err}",
                zone_dir.display()
            ),
        })?;
        self.zone_dir = Some(zone_dir.clone());
        let bot_info = client
            .get_me()
            .await
            .map_err(|e: TelegramError| FcpError::External {
                service: "telegram".into(),
                message: format!("Failed to verify bot: {e}"),
                status_code: None,
                retryable: e.is_retryable(),
                retry_after: None,
            })?;

        info!(
            bot_username = ?bot_info.username,
            bot_id = bot_info.id,
            zone_dir = %zone_dir.display(),
            "Telegram bot verified"
        );

        // Set up verifier
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(), // Use base.instance_id
        ));

        let session_id = SessionId::new();
        self.session_id = Some(session_id.clone());

        // Start polling if not already running
        self.start_polling().await?;
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
            manifest_hash: Self::manifest_hash(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: 1000,
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
        let Some(config) = &self.config else {
            return Ok(json!({
                "status": "not_configured",
                "uptime_ms": self.start_time.elapsed().as_millis() as u64
            }));
        };

        if config.credential_id.is_some() && self.client.is_none() {
            return Ok(json!({
                "status": "degraded",
                "uptime_ms": self.start_time.elapsed().as_millis() as u64,
                "auth_mode": "credential_id",
                "error": "credential_id configured; direct runtime token validation unavailable"
            }));
        }

        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        // Check if we can reach Telegram
        let result: Result<_, TelegramError> = client.get_me().await;
        match result {
            Ok(_) => Ok(json!({
                "status": "ready",
                "uptime_ms": self.start_time.elapsed().as_millis() as u64,
                "auth_mode": config.auth_label(),
                "polling": *self.poll_running.read().await,
                "metrics": self.base.metrics()
            })),
            Err(e) => Ok(json!({
                "status": "degraded",
                "uptime_ms": self.start_time.elapsed().as_millis() as u64,
                "auth_mode": config.auth_label(),
                "error": e.to_string()
            })),
        }
    }

    /// Handle doctor checks.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let result = self.build_doctor_result().await;
        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize doctor result: {e}"),
        })
    }

    async fn build_doctor_result(&self) -> DoctorResult {
        let mut checks = Vec::new();

        let configured = self.config.is_some();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: configured,
            message: Some(if configured {
                "Configuration loaded".into()
            } else {
                "Not configured - run configure first".into()
            }),
            critical: true,
        });

        let Some(config) = &self.config else {
            return DoctorResult::from_checks(checks);
        };

        checks.push(DoctorCheck {
            name: "auth_mode".into(),
            passed: true,
            message: Some(format!("Auth mode: {}", config.auth_label())),
            critical: true,
        });

        checks.push(DoctorCheck {
            name: "poll_timeout".into(),
            passed: (MIN_POLL_TIMEOUT_SECS..=MAX_POLL_TIMEOUT_SECS).contains(&config.poll_timeout),
            message: Some(format!(
                "poll_timeout={}s (expected {}..={}s)",
                config.poll_timeout, MIN_POLL_TIMEOUT_SECS, MAX_POLL_TIMEOUT_SECS
            )),
            critical: true,
        });

        checks.push(DoctorCheck {
            name: "allowed_updates".into(),
            passed: true,
            message: Some(if config.allowed_updates.is_empty() {
                "allowed_updates not set (Telegram defaults will apply)".into()
            } else {
                format!(
                    "allowed_updates configured: {}",
                    config.allowed_updates.join(", ")
                )
            }),
            critical: false,
        });

        let base_url = config
            .base_url
            .as_deref()
            .unwrap_or(DEFAULT_TELEGRAM_BASE_URL);
        let network_ok = is_telegram_or_local_base_url(base_url);
        checks.push(DoctorCheck {
            name: "network_constraints".into(),
            passed: network_ok,
            message: Some(if network_ok {
                format!("Base URL host is allowed for Telegram checks: {base_url}")
            } else {
                format!(
                    "Base URL host does not match api.telegram.org or local test host: {base_url}"
                )
            }),
            critical: false,
        });

        if let Some(token) = config.credential.as_deref().map(str::trim) {
            checks.push(DoctorCheck {
                name: "token_syntax".into(),
                passed: validate_bot_token_syntax(token).is_ok(),
                message: Some("Bot token syntax check completed".into()),
                critical: true,
            });
        } else {
            checks.push(DoctorCheck {
                name: "token_syntax".into(),
                passed: true,
                message: Some("credential_id mode (no inline token syntax check)".into()),
                critical: false,
            });
        }

        match (&self.client, config.credential_id) {
            (Some(client), _) => match client.get_me().await {
                Ok(bot) => checks.push(DoctorCheck {
                    name: "token_validation".into(),
                    passed: true,
                    message: Some(format!(
                        "Read-only getMe check passed (bot_id={}, username={:?})",
                        bot.id, bot.username
                    )),
                    critical: true,
                }),
                Err(err) => checks.push(DoctorCheck {
                    name: "token_validation".into(),
                    passed: false,
                    message: Some(format!("Read-only getMe check failed: {err}")),
                    critical: true,
                }),
            },
            (None, Some(id)) => checks.push(DoctorCheck {
                name: "token_validation".into(),
                passed: false,
                message: Some(format!(
                    "credential_id {id} configured; direct getMe validation unavailable without token materialization"
                )),
                critical: false,
            }),
            (None, None) => checks.push(DoctorCheck {
                name: "token_validation".into(),
                passed: false,
                message: Some("No Telegram client initialized".into()),
                critical: true,
            }),
        }

        DoctorResult::from_checks(checks)
    }

    /// Handle connector self-check.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        if self
            .config
            .as_ref()
            .and_then(|cfg| cfg.credential_id)
            .is_some()
            && self.client.is_none()
        {
            let report = SelfCheckReport::degraded(
                "credential_injection_required",
                "Configured with credential_id; materialized bot token is required for direct self-checks",
            );
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        }

        let Some(client) = &self.client else {
            let report = SelfCheckReport::degraded("not_configured", "Connector is not configured");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        let report = match client.get_me().await {
            Ok(bot) => {
                let mut report = SelfCheckReport::ok();
                report.details = Some(json!({
                    "bot_id": bot.id,
                    "username": bot.username,
                    "is_bot": bot.is_bot,
                }));
                report
            }
            Err(err) => {
                if err.is_retryable() {
                    SelfCheckReport::degraded("self_check_retryable", err.to_string())
                } else {
                    SelfCheckReport::failed("self_check_failed", err.to_string())
                }
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
                "chat_id": { "type": ["string", "integer"], "description": "Chat ID or @username" },
                "text": { "type": "string", "description": "Message text" },
                "parse_mode": { "type": "string", "enum": ["HTML", "MarkdownV2"] },
                "reply_to_message_id": { "type": "integer" }
            },
            "required": ["chat_id", "text"]
        })
    }

    fn send_message_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "message_id": { "type": "integer" },
                "chat_id": { "type": "integer" }
            }
        })
    }

    fn send_media_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "chat_id": { "type": ["string", "integer"], "description": "Chat ID or @username" },
                "media_type": { "type": "string", "enum": ["photo", "document", "audio", "video", "voice"], "description": "Type of media to send" },
                "media": { "type": "string", "description": "File ID (from a previous message) or HTTPS URL" },
                "caption": { "type": "string", "description": "Media caption (up to 1024 characters)" },
                "parse_mode": { "type": "string", "enum": ["HTML", "MarkdownV2"] },
                "reply_to_message_id": { "type": "integer" }
            },
            "required": ["chat_id", "media_type", "media"]
        })
    }

    fn send_media_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "message_id": { "type": "integer" },
                "chat_id": { "type": "integer" }
            }
        })
    }

    fn get_file_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "file_id": { "type": "string", "description": "File ID from a message" }
            },
            "required": ["file_id"]
        })
    }

    fn get_file_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "file_id": { "type": "string" },
                "file_path": { "type": "string" },
                "file_size": { "type": "integer" }
            }
        })
    }

    fn answer_callback_query_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "callback_query_id": { "type": "string", "description": "Unique identifier for the query to be answered" },
                "text": { "type": "string", "description": "Text of the notification. If not specified, nothing will be shown to the user" }
            },
            "required": ["callback_query_id"]
        })
    }

    fn answer_callback_query_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "success": { "type": "boolean" }
            }
        })
    }

    fn message_event_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "message_id": { "type": "integer" },
                "from": { "type": "object" },
                "chat": { "type": "object" },
                "text": { "type": "string" }
            }
        })
    }

    fn callback_query_event_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "from": { "type": "object" },
                "data": { "type": "string" },
                "chat_instance": { "type": "string" }
            }
        })
    }

    fn input_schema_for(operation: &str) -> Option<serde_json::Value> {
        match operation {
            "telegram.send_message" => Some(Self::send_message_input_schema()),
            "telegram.send_media" => Some(Self::send_media_input_schema()),
            "telegram.get_file" => Some(Self::get_file_input_schema()),
            "telegram.answer_callback_query" => Some(Self::answer_callback_query_input_schema()),
            _ => None,
        }
    }

    fn output_schema_for(operation: &str) -> Option<serde_json::Value> {
        match operation {
            "telegram.send_message" => Some(Self::send_message_output_schema()),
            "telegram.send_media" => Some(Self::send_media_output_schema()),
            "telegram.get_file" => Some(Self::get_file_output_schema()),
            "telegram.answer_callback_query" => Some(Self::answer_callback_query_output_schema()),
            _ => None,
        }
    }

    /// Handle introspection.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                OperationInfo {
                    id: OperationId::from_static("telegram.send_message"),
                    summary: "Send a text message to a Telegram chat".into(),
                    description: Some("Sends a text message to a specified Telegram chat, user, or group.".into()),
                    input_schema: Self::send_message_input_schema(),
                    output_schema: Self::send_message_output_schema(),
                    capability: CapabilityId::from_static("telegram.send"),
                    risk_level: RiskLevel::Medium,
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Send a message to a Telegram user or group.".into(),
                        common_mistakes: vec![
                            "Using invite links instead of chat IDs".into(),
                            "Forgetting the @ prefix for usernames".into(),
                        ],
                        examples: vec![
                            r#"{"chat_id": "@username", "text": "Hello!"}"#.into(),
                            r#"{"chat_id": "-100123456789", "text": "Group message"}"#.into(),
                        ],
                        related: vec![],
                    },
                    rate_limit: None,
                    requires_approval: None,
                },
                OperationInfo {
                    id: OperationId::from_static("telegram.send_media"),
                    summary: "Send a media file (photo, document, audio, video, voice) to a Telegram chat".into(),
                    description: Some("Sends media by file_id or HTTPS URL to a specified Telegram chat.".into()),
                    input_schema: Self::send_media_input_schema(),
                    output_schema: Self::send_media_output_schema(),
                    capability: CapabilityId::from_static("telegram.send"),
                    risk_level: RiskLevel::Medium,
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Send a photo, document, audio, video, or voice message to a Telegram chat.".into(),
                        common_mistakes: vec![
                            "Providing a local file path instead of a file_id or HTTPS URL".into(),
                        ],
                        examples: vec![
                            r#"{"chat_id": "@username", "media_type": "photo", "media": "AgACAgIAAxk..."}"#.into(),
                            r#"{"chat_id": "123456", "media_type": "document", "media": "https://example.com/file.pdf", "caption": "Report"}"#.into(),
                        ],
                        related: vec![],
                    },
                    rate_limit: None,
                    requires_approval: None,
                },
                OperationInfo {
                    id: OperationId::from_static("telegram.get_file"),
                    summary: "Get file information for downloading".into(),
                    description: Some("Retrieves file information including download path for files attached to messages.".into()),
                    input_schema: Self::get_file_input_schema(),
                    output_schema: Self::get_file_output_schema(),
                    capability: CapabilityId::from_static("telegram.read"),
                    risk_level: RiskLevel::Low,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Get download URL for files attached to messages.".into(),
                        common_mistakes: vec![],
                        examples: vec![],
                        related: vec![],
                    },
                    rate_limit: None,
                    requires_approval: None,
                },
                OperationInfo {
                    id: OperationId::from_static("telegram.answer_callback_query"),
                    summary: "Answer a callback query (button press)".into(),
                    description: Some("Notify Telegram that a callback query has been received. Stops the loading animation.".into()),
                    input_schema: Self::answer_callback_query_input_schema(),
                    output_schema: Self::answer_callback_query_output_schema(),
                    capability: CapabilityId::from_static("telegram.send"),
                    risk_level: RiskLevel::Low,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Respond to a button press (callback query).".into(),
                        common_mistakes: vec![
                            "Forgetting to call this after processing a button press".into(),
                        ],
                        examples: vec![
                            r#"{"callback_query_id": "12345", "text": "Done!"}"#.into(),
                        ],
                        related: vec![],
                    },
                    rate_limit: None,
                    requires_approval: None,
                },
            ],
            events: vec![
                EventInfo {
                    topic: "telegram.message.new".into(),
                    schema: Self::message_event_schema(),
                    requires_ack: false,
                },
                EventInfo {
                    topic: "telegram.message.edited".into(),
                    schema: Self::message_event_schema(),
                    requires_ack: false,
                },
                EventInfo {
                    topic: "telegram.channel_post.new".into(),
                    schema: Self::message_event_schema(),
                    requires_ack: false,
                },
                EventInfo {
                    topic: "telegram.channel_post.edited".into(),
                    schema: Self::message_event_schema(),
                    requires_ack: false,
                },
                EventInfo {
                    topic: "telegram.callback_query".into(),
                    schema: Self::callback_query_event_schema(),
                    requires_ack: false,
                },
            ],
            resource_types: vec![],
            auth_caps: None,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: 1000,
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

    /// Handle invoke method.
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let result = self.handle_invoke_internal(params).await;
        self.base.record_request(result.is_ok());
        result
    }

    /// Validate input structure and limits before capability token verification.
    fn validate_input_early(operation: &str, input: &serde_json::Value) -> FcpResult<()> {
        if let Some(schema) = Self::input_schema_for(operation) {
            validate_input_with_limits(&schema, input, &Limits::default())?;
        }

        match operation {
            "telegram.send_message" => {
                let text = input.get("text").and_then(|v| v.as_str());
                if let Some(text) = text {
                    // Telegram limit is character-based, not byte-based.
                    // Using chars().count() correctly handles multi-byte characters (e.g. emojis).
                    if text.chars().count() > MESSAGE_TEXT_MAX_CHARS {
                        return Err(FcpError::InvalidRequest {
                            code: 1004,
                            message: format!(
                                "Message text exceeds {MESSAGE_TEXT_MAX_CHARS} character limit (got {} characters)",
                                text.chars().count()
                            ),
                        });
                    }
                }
            }
            "telegram.send_media" => {
                if let Some(caption) = input.get("caption").and_then(|v| v.as_str()) {
                    if caption.chars().count() > MEDIA_CAPTION_MAX_CHARS {
                        return Err(FcpError::InvalidRequest {
                            code: 1004,
                            message: format!(
                                "Caption exceeds {MEDIA_CAPTION_MAX_CHARS} character limit (got {} characters)",
                                caption.chars().count()
                            ),
                        });
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    async fn handle_invoke_internal(
        &self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let operation =
            params
                .get("operation")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing operation".into(),
                })?;

        let input = params.get("input").cloned().unwrap_or(json!({}));

        // Early validation
        Self::validate_input_early(operation, &input)?;

        // Extract and verify capability token
        let token_value = params
            .get("capability_token")
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing capability_token".into(),
            })?;

        let token: fcp_core::CapabilityToken = serde_json::from_value(token_value.clone())
            .map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid capability_token format: {e}"),
            })?;

        // Verify token
        let op_id: OperationId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid operation ID format".into(),
        })?;
        let intro = self.handle_introspect().await?;
        let cap_str = intro
            .get("operations")
            .and_then(|ops| ops.as_array())
            .and_then(|ops| {
                ops.iter()
                    .find(|o| o.get("id").and_then(|id| id.as_str()) == Some(operation))
            })
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

        // Extract chat_id (can be string or integer)
        if let Some(val) = input.get("chat_id") {
            if let Some(s) = val.as_str() {
                resource_uris.push(format!("telegram:chat:{s}"));
            } else if let Some(i) = val.as_i64() {
                resource_uris.push(format!("telegram:chat:{i}"));
            }
        }

        if let Some(file_id) = input.get("file_id").and_then(|v| v.as_str()) {
            resource_uris.push(format!("telegram:file:{file_id}"));
        }

        if let Some(cb_id) = input.get("callback_query_id").and_then(|v| v.as_str()) {
            resource_uris.push(format!("telegram:callback:{cb_id}"));
        }

        if let Some(verifier) = &self.verifier {
            verifier.verify(token, &cap_id, &op_id, &resource_uris)?;
        } else {
            return Err(FcpError::NotConfigured);
        }

        match operation {
            "telegram.send_message" => self.invoke_send_message(input).await,
            "telegram.send_media" => self.invoke_send_media(input).await,
            "telegram.get_file" => self.invoke_get_file(input).await,
            "telegram.answer_callback_query" => self.invoke_answer_callback_query(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    async fn invoke_send_message(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        // Input validation is now done in validate_input_early, but we still need to extract fields
        let chat_id = match input.get("chat_id") {
            Some(serde_json::Value::String(value)) => value.clone(),
            Some(serde_json::Value::Number(value)) => value
                .as_i64()
                .map(|value| value.to_string())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "chat_id must be an integer or string".into(),
                })?,
            Some(_) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "chat_id must be an integer or string".into(),
                });
            }
            None => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing chat_id".into(),
                });
            }
        };

        let text = input
            .get("text")
            .and_then(|v| v.as_str())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing text".into(),
            })?;

        // Now check that we're configured
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let requested_mode = match input.get("parse_mode").and_then(|v| v.as_str()) {
            Some("HTML") => FormatMode::Html,
            Some("MarkdownV2") => FormatMode::MarkdownV2,
            None => FormatMode::Plain,
            Some(_) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Unsupported parse_mode".into(),
                });
            }
        };

        let render = Formatter::render_with_fallback(text, requested_mode);

        let mut options = SendMessageOptions::default();
        options.parse_mode = render
            .parse_mode_used
            .and_then(|mode| mode.as_parse_mode().map(|value| value.to_string()));
        if let Some(reply_to) = input.get("reply_to_message_id").and_then(|v| v.as_i64()) {
            options.reply_to_message_id = Some(reply_to);
        }

        let map_external = |e: TelegramError| FcpError::External {
            service: "telegram".into(),
            message: e.to_string(),
            status_code: match &e {
                TelegramError::Api { code, .. } => u16::try_from(*code).ok(),
                _ => None,
            },
            retryable: e.is_retryable(),
            retry_after: None,
        };

        let message = match client
            .send_message(chat_id.clone(), render.rendered, options.clone())
            .await
        {
            Ok(message) => message,
            Err(err) => {
                if options.parse_mode.is_some() {
                    if let TelegramError::Api { description, .. } = &err {
                        if classify_error_message(description) == ErrorClass::ParseError {
                            warn!(
                                parse_mode = ?requested_mode,
                                "Telegram parse error, retrying with plaintext fallback"
                            );
                            let fallback =
                                Formatter::render_plaintext_fallback(text, requested_mode);
                            let mut fallback_options = options.clone();
                            fallback_options.parse_mode = None;
                            return client
                                .send_message(chat_id, fallback.rendered, fallback_options)
                                .await
                                .map(|msg| {
                                    json!({
                                        "message_id": msg.message_id,
                                        "chat_id": msg.chat.id
                                    })
                                })
                                .map_err(map_external);
                        }
                    }
                }

                return Err(map_external(err));
            }
        };

        let response = json!({
            "message_id": message.message_id,
            "chat_id": message.chat.id
        });

        if let Some(schema) = Self::output_schema_for("telegram.send_message") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }

        Ok(response)
    }

    async fn invoke_send_media(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let chat_id = match input.get("chat_id") {
            Some(serde_json::Value::String(value)) => value.clone(),
            Some(serde_json::Value::Number(value)) => value
                .as_i64()
                .map(|value| value.to_string())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "chat_id must be an integer or string".into(),
                })?,
            Some(_) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "chat_id must be an integer or string".into(),
                });
            }
            None => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing chat_id".into(),
                });
            }
        };

        let media_type =
            input
                .get("media_type")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing media_type".into(),
                })?;

        let media =
            input
                .get("media")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing media (file_id or URL)".into(),
                })?;

        let mut options = SendMediaOptions::default();
        if let Some(caption) = input.get("caption").and_then(|v| v.as_str()) {
            options.caption = Some(caption.to_string());
        }
        if let Some(parse_mode) = input.get("parse_mode").and_then(|v| v.as_str()) {
            options.parse_mode = Some(parse_mode.to_string());
        }
        if let Some(reply_to) = input.get("reply_to_message_id").and_then(|v| v.as_i64()) {
            options.reply_to_message_id = Some(reply_to);
        }

        let map_external = |e: TelegramError| FcpError::External {
            service: "telegram".into(),
            message: e.to_string(),
            status_code: match &e {
                TelegramError::Api { code, .. } => u16::try_from(*code).ok(),
                _ => None,
            },
            retryable: e.is_retryable(),
            retry_after: None,
        };

        let message: Message = match media_type {
            "photo" => client
                .send_photo(chat_id, media, options)
                .await
                .map_err(map_external)?,
            "document" => client
                .send_document(chat_id, media, options)
                .await
                .map_err(map_external)?,
            "audio" => client
                .send_audio(chat_id, media, options)
                .await
                .map_err(map_external)?,
            "video" => client
                .send_video(chat_id, media, options)
                .await
                .map_err(map_external)?,
            "voice" => client
                .send_voice(chat_id, media, options)
                .await
                .map_err(map_external)?,
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!(
                        "Unsupported media_type: {media_type}. Must be one of: photo, document, audio, video, voice"
                    ),
                });
            }
        };

        let response = json!({
            "message_id": message.message_id,
            "chat_id": message.chat.id
        });

        if let Some(schema) = Self::output_schema_for("telegram.send_media") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }

        Ok(response)
    }

    async fn invoke_get_file(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let file_id =
            input
                .get("file_id")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing file_id".into(),
                })?;

        let file =
            client
                .get_file(file_id)
                .await
                .map_err(|e: TelegramError| FcpError::External {
                    service: "telegram".into(),
                    message: e.to_string(),
                    status_code: match &e {
                        TelegramError::Api { code, .. } => u16::try_from(*code).ok(),
                        _ => None,
                    },
                    retryable: e.is_retryable(),
                    retry_after: None,
                })?;

        let download_url = file
            .file_path
            .as_ref()
            .map(|p| client.file_download_url(p))
            .transpose()
            .map_err(TelegramError::to_fcp_error)?;

        let response = json!({
            "file_id": file.file_id,
            "file_unique_id": file.file_unique_id,
            "file_size": file.file_size,
            "file_path": file.file_path,
            "download_url": download_url
        });

        if let Some(schema) = Self::output_schema_for("telegram.get_file") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }

        Ok(response)
    }

    async fn invoke_answer_callback_query(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let callback_query_id = input
            .get("callback_query_id")
            .and_then(|v| v.as_str())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing callback_query_id".into(),
            })?;

        let text = input.get("text").and_then(|v| v.as_str());

        let success = client
            .answer_callback_query(callback_query_id, text)
            .await
            .map_err(|e: TelegramError| FcpError::External {
                service: "telegram".into(),
                message: e.to_string(),
                status_code: match &e {
                    TelegramError::Api { code, .. } => u16::try_from(*code).ok(),
                    _ => None,
                },
                retryable: e.is_retryable(),
                retry_after: None,
            })?;

        let response = json!({ "success": success });

        if let Some(schema) = Self::output_schema_for("telegram.answer_callback_query") {
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
        info!("Shutting down Telegram connector");

        // Stop polling
        if let Some(shutdown_tx) = self.poll_shutdown_tx.take() {
            let _ = shutdown_tx.send(true);
        }
        *self.poll_running.write().await = false;

        if let Some(mut task) = self.poll_task.take() {
            if fcp_async_core::time::timeout(Duration::from_secs(2), &mut task)
                .await
                .is_err()
            {
                warn!("Polling task did not stop within timeout, aborting");
                task.abort();
            }
        }

        if let Some(client) = &self.client {
            client.shutdown();
        }

        self.client = None;
        self.config = None;
        self.verifier = None;
        self.session_id = None;
        self.zone_dir = None;
        self.base.set_handshaken(false);
        self.base.set_configured(false);

        Ok(json!({ "status": "shutdown" }))
    }

    /// Start the polling loop.
    async fn start_polling(&mut self) -> FcpResult<()> {
        if *self.poll_running.read().await {
            return Ok(()); // Already running
        }

        let client = self.client.clone().ok_or(FcpError::NotConfigured)?;
        let config = self.config.clone().ok_or(FcpError::NotConfigured)?;
        let event_tx = self.event_tx.clone();
        let poll_running = self.poll_running.clone();
        let instance_id = self.base.instance_id.clone(); // Use base.instance_id
        let connector_id = self.base.id.clone();
        let base = self.base.clone();
        let zone_dir = self.zone_dir.clone().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Handshake zone_dir is required before polling can start".into(),
        })?;
        let cursor_path = zone_dir.join(TELEGRAM_POLL_CURSOR_FILE);
        let lease_path = zone_dir.join(TELEGRAM_POLL_LEASE_FILE);
        let poll_timeout_secs =
            u64::try_from(config.poll_timeout.max(MIN_POLL_TIMEOUT_SECS)).unwrap_or(30);
        let poll_lease = TelegramPollLease::acquire(
            lease_path,
            instance_id.to_string(),
            poll_timeout_secs.saturating_mul(3),
        )?;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        self.poll_shutdown_tx = Some(shutdown_tx.clone());

        *poll_running.write().await = true;

        let task = fcp_async_core::task::spawn(async move {
            info!("Starting Telegram polling loop");

            let mut supervisor = PollingSupervisor::new(
                SupervisorConfig::default(),
                TelegramPollingCursor::new(Some(cursor_path)),
            );

            let outcome = supervisor
                .run(
                    shutdown_rx,
                    0,
                    |offset| {
                        let client = client.clone();
                        let config = config.clone();
                        let poll_lease = poll_lease.clone();
                        async move {
                            if let Err(err) = poll_lease.renew() {
                                return PollResult::fatal(format!(
                                    "singleton-writer lease renewal failed: {err}"
                                ));
                            }

                            let request = GetUpdatesRequest {
                                offset,
                                limit: Some(100),
                                timeout: Some(config.poll_timeout),
                                allowed_updates: if config.allowed_updates.is_empty() {
                                    None
                                } else {
                                    Some(config.allowed_updates.clone())
                                },
                            };

                            match client.get_updates(request).await {
                                Ok(updates) => PollResult::success(updates),
                                Err(err) if err.is_retryable() => {
                                    PollResult::recoverable(err.to_string())
                                }
                                Err(err) => PollResult::fatal(err.to_string()),
                            }
                        }
                    },
                    |updates, cursor| {
                        for update in updates {
                            cursor.advance_if_newer(update.update_id);

                            if let Some(event) =
                                update_to_event(&update, &connector_id, &instance_id)
                            {
                                base.record_event();
                                if event_tx.send(Ok(event)).is_err() {
                                    info!("Event receiver dropped, closing polling loop");
                                    let _ = shutdown_tx.send(true);
                                    break;
                                }
                            }
                        }
                        Ok(())
                    },
                )
                .await;

            info!(?outcome, "Telegram polling supervisor stopped");
            if let Err(err) = poll_lease.release() {
                warn!(error = %err, "Failed to release Telegram polling lease");
            }

            info!("Telegram polling loop stopped");
            *poll_running.write().await = false;
        });

        self.poll_task = Some(task);
        Ok(())
    }
}

/// Convert a Telegram Update to an FCP EventEnvelope.
fn update_to_event(
    update: &Update,
    connector_id: &ConnectorId,
    instance_id: &InstanceId,
) -> Option<EventEnvelope> {
    let (topic, payload, thread_info) = match &update.kind {
        UpdateKind::Message(msg) => (
            "telegram.message.new",
            message_to_json(msg),
            message_thread_info(msg),
        ),
        UpdateKind::EditedMessage(msg) => (
            "telegram.message.edited",
            message_to_json(msg),
            message_thread_info(msg),
        ),
        UpdateKind::ChannelPost(msg) => (
            "telegram.channel_post.new",
            message_to_json(msg),
            message_thread_info(msg),
        ),
        UpdateKind::EditedChannelPost(msg) => (
            "telegram.channel_post.edited",
            message_to_json(msg),
            message_thread_info(msg),
        ),
        UpdateKind::CallbackQuery(cb) => (
            "telegram.callback_query",
            json!({
                "id": cb.id,
                "from": cb.from,
                "data": cb.data,
                "chat_instance": cb.chat_instance
            }),
            None,
        ),
        UpdateKind::Unknown => return None,
    };

    let principal = Principal {
        kind: "telegram_user".into(),
        id: payload
            .get("from")
            .and_then(|f| f.get("id"))
            .and_then(|id| id.as_i64())
            .map(|id| id.to_string())
            .unwrap_or_else(|| "unknown".into()),
        trust: TrustLevel::Untrusted,
        display: payload
            .get("from")
            .and_then(|f| f.get("username"))
            .and_then(|u| u.as_str())
            .map(String::from),
    };

    let event_data = EventData {
        connector_id: connector_id.clone(),
        instance_id: instance_id.clone(),
        zone_id: ZoneId::community(),
        principal,
        payload,
        correlation_id: None,
        resource_uris: vec![],
        thread_info,
    };

    // update_id is always positive per Telegram API, but use saturating conversion for safety
    let seq = u64::try_from(update.update_id).unwrap_or(0);
    Some(EventEnvelope::new(topic, event_data).with_seq(seq))
}

fn message_thread_info(msg: &Message) -> Option<ThreadInfo> {
    msg.message_thread_id.map(|thread_id| {
        ThreadInfo::from_telegram_message_thread(thread_id, msg.chat.id.to_string())
    })
}

/// Convert a Message to JSON.
fn message_to_json(msg: &Message) -> serde_json::Value {
    json!({
        "message_id": msg.message_id,
        "from": msg.from,
        "chat": msg.chat,
        "date": msg.date,
        "text": msg.text,
        "caption": msg.caption,
        "has_photo": msg.photo.is_some(),
        "has_document": msg.document.is_some(),
        "has_audio": msg.audio.is_some(),
        "has_video": msg.video.is_some(),
        "has_voice": msg.voice.is_some(),
        "reply_to_message_id": msg.reply_to_message.as_ref().map(|m| m.message_id),
        "message_thread_id": msg.message_thread_id
    })
}

impl Default for TelegramConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration as StdDuration;

    use super::*;
    use crate::types::{Chat, User};
    use serde_json::json;

    #[test]
    fn test_validate_input_early_unicode_length() {
        // Create a string that is below the message limit in characters but above it in bytes.
        // '€' is 3 bytes. 2000 chars * 3 = 6000 bytes.
        let text = "€".repeat(2000);
        assert!(text.len() > MESSAGE_TEXT_MAX_CHARS);
        assert!(text.chars().count() < MESSAGE_TEXT_MAX_CHARS);

        let input = json!({
            "chat_id": "123",
            "text": text
        });

        let result = TelegramConnector::validate_input_early("telegram.send_message", &input);
        assert!(
            result.is_ok(),
            "Validation failed for valid Unicode string: {:?}",
            result.err()
        );

        // Test actual overflow
        let long_text = "a".repeat(MESSAGE_TEXT_MAX_CHARS + 1);
        let input_long = json!({
            "chat_id": "123",
            "text": long_text
        });
        let result_long =
            TelegramConnector::validate_input_early("telegram.send_message", &input_long);
        assert!(
            result_long.is_err(),
            "Validation should fail for > {MESSAGE_TEXT_MAX_CHARS} chars"
        );
    }

    use chrono::{Duration, Utc};
    use fcp_core::CapabilityConstraints;
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_testkit::LogCapture;
    use uuid::Uuid;

    fn generate_valid_token(
        signing_key: &Ed25519SigningKey,
        op: &str,
    ) -> fcp_core::CapabilityToken {
        let cap = match op {
            "telegram.send_message" | "telegram.send_media" | "telegram.answer_callback_query" => {
                "telegram.send"
            }
            _ => "telegram.read",
        };
        let now = Utc::now();
        // C3.4: tokens MUST include constraints (default-deny)
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
        let cose = CapabilityTokenBuilder::new()
            .capability_id(cap)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[op])
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .constraints_cbor(&cbor)
            .sign(signing_key)
            .unwrap();
        fcp_core::CapabilityToken::from_raw(cose)
    }

    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TEST_BOT_TOKEN: &str = "123456:ABCDEFGHIJKLMNOPQRSTUVWXyz012345";

    fn token_path(method: &str) -> String {
        format!("/bot{TEST_BOT_TOKEN}/{method}")
    }

    fn unique_zone_dir(label: &str) -> String {
        let dir = std::env::temp_dir()
            .join("fcp-telegram-tests")
            .join(format!("{label}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("failed to create unique zone dir");
        dir.to_string_lossy().into_owned()
    }

    fn uncreated_zone_dir(label: &str) -> String {
        std::env::temp_dir()
            .join("fcp-telegram-tests")
            .join(format!("{label}-{}", Uuid::new_v4()))
            .to_string_lossy()
            .into_owned()
    }

    async fn setup_connector_with_token(
        cap: &str,
    ) -> (TelegramConnector, fcp_core::CapabilityToken, MockServer) {
        let mock_server = MockServer::start().await;

        // Mock getMe for handshake
        Mock::given(method("GET"))
            .and(path(token_path("getMe")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "result": {
                    "id": 123456789,
                    "is_bot": true,
                    "first_name": "Test Bot",
                    "username": "test_bot"
                }
            })))
            .mount(&mock_server)
            .await;

        // Mock getUpdates for polling
        Mock::given(method("POST"))
            .and(path(token_path("getUpdates")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "result": []
            })))
            .mount(&mock_server)
            .await;

        let mut connector = TelegramConnector::new();

        // Configure with dummy credential and mock base URL
        connector
            .handle_configure(serde_json::json!({
                "credential": TEST_BOT_TOKEN,
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let zone_dir = unique_zone_dir("setup-connector");

        connector
            .handle_handshake(serde_json::json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "zone_dir": zone_dir,
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": [cap]
            }))
            .await
            .unwrap();

        let capability = generate_valid_token(&signing_key, cap);
        (connector, capability, mock_server)
    }

    #[test]
    fn test_validate_bot_token_syntax_rules() {
        assert!(validate_bot_token_syntax(TEST_BOT_TOKEN).is_ok());
        assert!(validate_bot_token_syntax("bad-token").is_err());
        assert!(validate_bot_token_syntax("123:too_short").is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_ambiguous_auth_mode() {
        let mut connector = TelegramConnector::new();
        let result = connector
            .handle_configure(json!({
                "credential": TEST_BOT_TOKEN,
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
            }))
            .await;

        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_invalid_token_syntax() {
        let mut connector = TelegramConnector::new();
        let result = connector
            .handle_configure(json!({
                "credential": "not-a-token"
            }))
            .await;

        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_credential_id_mode_is_degraded() {
        let mut connector = TelegramConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
            }))
            .await
            .expect("configure");

        let doctor: DoctorResult = serde_json::from_value(
            connector
                .handle_doctor()
                .await
                .expect("doctor response should serialize"),
        )
        .expect("doctor response parse");

        assert_eq!(doctor.status, DoctorStatus::Degraded);
        let validation = doctor
            .checks
            .iter()
            .find(|check| check.name == "token_validation")
            .expect("token_validation check present");
        assert!(!validation.passed);
    }

    #[test]
    fn test_polling_cursor_advances_and_persists() {
        let cursor_path = std::path::PathBuf::from(unique_zone_dir("cursor-state"))
            .join(TELEGRAM_POLL_CURSOR_FILE);
        let mut cursor = TelegramPollingCursor::new(Some(cursor_path.clone()));
        assert_eq!(cursor.offset(), None);

        cursor.advance_if_newer(100);
        assert_eq!(cursor.offset(), Some(101));

        cursor.advance_if_newer(50);
        assert_eq!(cursor.offset(), Some(101));

        cursor.advance_if_newer(101);
        assert_eq!(cursor.offset(), Some(102));

        assert!(cursor.persist().is_ok());
        let mut restored = TelegramPollingCursor::new(Some(cursor_path));
        assert!(restored.restore().is_ok());
        assert_eq!(restored.offset(), Some(102));
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake_requires_zone_dir_for_polling_state() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(token_path("getMe")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "result": {
                    "id": 123456789,
                    "is_bot": true,
                    "first_name": "Test Bot",
                    "username": "test_bot"
                }
            })))
            .mount(&mock_server)
            .await;

        let mut connector = TelegramConnector::new();
        connector
            .handle_configure(serde_json::json!({
                "credential": TEST_BOT_TOKEN,
                "base_url": mock_server.uri()
            }))
            .await
            .expect("configure should succeed");

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let result = connector
            .handle_handshake(serde_json::json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["telegram.read"]
            }))
            .await;

        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake_before_configure_does_not_create_zone_dir() {
        let mut connector = TelegramConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let zone_dir = uncreated_zone_dir("handshake-before-configure");

        let result = connector
            .handle_handshake(serde_json::json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "zone_dir": zone_dir,
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["telegram.read"]
            }))
            .await;

        assert!(matches!(result, Err(FcpError::NotConfigured)));
        assert!(connector.zone_dir.is_none());
        assert!(!Path::new(&zone_dir).exists());
    }

    #[test]
    fn connector_base_id_matches_manifest() {
        let connector = TelegramConnector::new();
        assert_eq!(connector.base.id.as_ref(), "fcp.telegram");
    }

    #[fcp_async_core::runtime::test]
    async fn test_polling_lease_fences_second_instance() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path(token_path("getMe")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "result": {
                    "id": 123456789,
                    "is_bot": true,
                    "first_name": "Test Bot",
                    "username": "test_bot"
                }
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path(token_path("getUpdates")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "result": []
            })))
            .mount(&mock_server)
            .await;

        let zone_dir = unique_zone_dir("lease-fence");

        let mut connector_a = TelegramConnector::new();
        connector_a
            .handle_configure(serde_json::json!({
                "credential": TEST_BOT_TOKEN,
                "base_url": mock_server.uri(),
                "poll_timeout": 1
            }))
            .await
            .expect("configure A should succeed");
        let signing_key_a = Ed25519SigningKey::generate();
        let verifying_key_a = signing_key_a.verifying_key();
        connector_a
            .handle_handshake(serde_json::json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "zone_dir": zone_dir,
                "host_public_key": verifying_key_a.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["telegram.read"]
            }))
            .await
            .expect("first handshake should succeed");

        let mut connector_b = TelegramConnector::new();
        connector_b
            .handle_configure(serde_json::json!({
                "credential": TEST_BOT_TOKEN,
                "base_url": mock_server.uri(),
                "poll_timeout": 1
            }))
            .await
            .expect("configure B should succeed");
        let signing_key_b = Ed25519SigningKey::generate();
        let verifying_key_b = signing_key_b.verifying_key();
        let second = connector_b
            .handle_handshake(serde_json::json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "zone_dir": zone_dir,
                "host_public_key": verifying_key_b.to_bytes(),
                "nonce": vec![1u8; 32],
                "capabilities_requested": ["telegram.read"]
            }))
            .await;

        assert!(matches!(second, Err(FcpError::Conflict { .. })));

        connector_a
            .handle_shutdown(json!({}))
            .await
            .expect("shutdown should succeed");
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake_manifest_hash_and_shutdown_clear_state() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path(token_path("getMe")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "result": {
                    "id": 123456789,
                    "is_bot": true,
                    "first_name": "Test Bot",
                    "username": "test_bot"
                }
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path(token_path("getUpdates")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "result": []
            })))
            .mount(&mock_server)
            .await;

        let mut connector = TelegramConnector::new();
        connector
            .handle_configure(serde_json::json!({
                "credential": TEST_BOT_TOKEN,
                "base_url": mock_server.uri(),
                "poll_timeout": 1
            }))
            .await
            .expect("configure should succeed");

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let zone_dir = unique_zone_dir("shutdown-state");
        let handshake = connector
            .handle_handshake(serde_json::json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "zone_dir": zone_dir,
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["telegram.read"]
            }))
            .await
            .expect("handshake should succeed");

        assert_eq!(
            handshake["manifest_hash"],
            TelegramConnector::manifest_hash()
        );

        connector
            .handle_shutdown(json!({}))
            .await
            .expect("shutdown should succeed");

        assert!(connector.client.is_none());
        assert!(connector.config.is_none());
        assert!(connector.verifier.is_none());
        assert!(connector.session_id.is_none());
        assert!(connector.zone_dir.is_none());
        assert!(!*connector.poll_running.read().await);

        let health = connector.handle_health().await.expect("health");
        assert_eq!(health["status"], "not_configured");
    }

    #[test]
    fn test_update_to_event_sets_untrusted_principal() {
        let update = Update {
            update_id: 42,
            kind: UpdateKind::Message(Message {
                message_id: 1,
                from: Some(User {
                    id: 7,
                    is_bot: false,
                    first_name: "Test".into(),
                    last_name: None,
                    username: Some("tester".into()),
                    language_code: None,
                }),
                chat: Chat {
                    id: 99,
                    chat_type: "private".into(),
                    title: None,
                    username: Some("tester".into()),
                    first_name: Some("Test".into()),
                    last_name: None,
                },
                date: 1234567890,
                text: Some("hello".into()),
                caption: None,
                photo: None,
                document: None,
                audio: None,
                video: None,
                voice: None,
                reply_to_message: None,
                message_thread_id: None,
            }),
        };

        let event = update_to_event(
            &update,
            &ConnectorId::from_static("fcp.telegram"),
            &InstanceId::new(),
        )
        .expect("event");

        assert_eq!(event.topic, "telegram.message.new");
        assert_eq!(event.seq, 42);
        assert_eq!(event.data.zone_id, ZoneId::community());
        assert_eq!(event.data.principal.kind, "telegram_user");
        assert_eq!(event.data.principal.id, "7");
        assert_eq!(event.data.principal.trust, TrustLevel::Untrusted);
        assert_eq!(
            event.data.payload.get("text").and_then(|v| v.as_str()),
            Some("hello")
        );
    }

    #[test]
    fn test_update_to_event_maps_topics_by_update_variant() {
        let msg = Message {
            message_id: 1,
            from: Some(User {
                id: 7,
                is_bot: false,
                first_name: "Test".into(),
                last_name: None,
                username: Some("tester".into()),
                language_code: None,
            }),
            chat: Chat {
                id: 99,
                chat_type: "private".into(),
                title: None,
                username: Some("tester".into()),
                first_name: Some("Test".into()),
                last_name: None,
            },
            date: 1234567890,
            text: Some("hello".into()),
            caption: None,
            photo: None,
            document: None,
            audio: None,
            video: None,
            voice: None,
            reply_to_message: None,
            message_thread_id: None,
        };

        let connector_id = ConnectorId::from_static("fcp.telegram");
        let instance_id = InstanceId::new();

        let edited = Update {
            update_id: 43,
            kind: UpdateKind::EditedMessage(msg.clone()),
        };
        let channel_post = Update {
            update_id: 44,
            kind: UpdateKind::ChannelPost(msg.clone()),
        };
        let edited_channel_post = Update {
            update_id: 45,
            kind: UpdateKind::EditedChannelPost(msg),
        };
        let callback = Update {
            update_id: 46,
            kind: UpdateKind::CallbackQuery(crate::types::CallbackQuery {
                id: "cb-1".into(),
                from: User {
                    id: 8,
                    is_bot: false,
                    first_name: "Button".into(),
                    last_name: None,
                    username: Some("button_user".into()),
                    language_code: None,
                },
                message: None,
                chat_instance: "chat-instance".into(),
                data: Some("tap".into()),
            }),
        };

        assert_eq!(
            update_to_event(&edited, &connector_id, &instance_id)
                .expect("edited event")
                .topic,
            "telegram.message.edited"
        );
        assert_eq!(
            update_to_event(&channel_post, &connector_id, &instance_id)
                .expect("channel post event")
                .topic,
            "telegram.channel_post.new"
        );
        assert_eq!(
            update_to_event(&edited_channel_post, &connector_id, &instance_id)
                .expect("edited channel post event")
                .topic,
            "telegram.channel_post.edited"
        );
        assert_eq!(
            update_to_event(&callback, &connector_id, &instance_id)
                .expect("callback event")
                .topic,
            "telegram.callback_query"
        );
    }

    #[test]
    fn test_update_to_event_sets_thread_info_for_forum_topics() {
        let update = Update {
            update_id: 52,
            kind: UpdateKind::Message(Message {
                message_id: 7,
                from: Some(User {
                    id: 10,
                    is_bot: false,
                    first_name: "Forum".into(),
                    last_name: None,
                    username: Some("forum_user".into()),
                    language_code: None,
                }),
                chat: Chat {
                    id: -100123,
                    chat_type: "supergroup".into(),
                    title: Some("Forum".into()),
                    username: None,
                    first_name: None,
                    last_name: None,
                },
                date: 1_700_000_000,
                text: Some("topic message".into()),
                caption: None,
                photo: None,
                document: None,
                audio: None,
                video: None,
                voice: None,
                reply_to_message: None,
                message_thread_id: Some(77),
            }),
        };

        let event = update_to_event(
            &update,
            &ConnectorId::from_static("fcp.telegram"),
            &InstanceId::new(),
        )
        .expect("event");

        assert_eq!(
            event.data.thread_info,
            Some(ThreadInfo::from_telegram_message_thread(77, "-100123"))
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_polling_emits_event_envelope_from_get_updates() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path(token_path("getMe")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "result": {
                    "id": 123456789,
                    "is_bot": true,
                    "first_name": "Test Bot",
                    "username": "test_bot"
                }
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path(token_path("getUpdates")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "result": [{
                    "update_id": 1000,
                    "message": {
                        "message_id": 55,
                        "from": {
                            "id": 7,
                            "is_bot": false,
                            "first_name": "Test",
                            "username": "tester"
                        },
                        "chat": {
                            "id": 99,
                            "type": "private",
                            "first_name": "Test",
                            "username": "tester"
                        },
                        "date": 1700000000,
                        "text": "hello poll"
                    }
                }]
            })))
            .mount(&mock_server)
            .await;

        let mut connector = TelegramConnector::new();
        let mut event_rx = connector.event_tx.subscribe();

        connector
            .handle_configure(json!({
                "credential": TEST_BOT_TOKEN,
                "base_url": mock_server.uri(),
                "poll_timeout": 1
            }))
            .await
            .expect("configure should succeed");

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let zone_dir = unique_zone_dir("polling-event");
        connector
            .handle_handshake(serde_json::json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "zone_dir": zone_dir,
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["telegram.read"]
            }))
            .await
            .expect("handshake should succeed");

        let event = fcp_async_core::time::timeout(StdDuration::from_secs(3), event_rx.recv())
            .await
            .expect("timed out waiting for polling event")
            .expect("broadcast receive should succeed")
            .expect("event payload should be ok");

        assert_eq!(event.topic, "telegram.message.new");
        assert_eq!(event.seq, 1000);
        assert_eq!(event.data.principal.trust, TrustLevel::Untrusted);
        assert_eq!(
            event.data.payload.get("text").and_then(|v| v.as_str()),
            Some("hello poll")
        );

        connector
            .handle_shutdown(json!({}))
            .await
            .expect("shutdown should succeed");
    }

    #[fcp_async_core::runtime::test]
    async fn test_capability_mismatch_denied() {
        let (connector, token, _server) = setup_connector_with_token("telegram.get_file").await;

        let input = serde_json::json!({
            "chat_id": "123456789",
            "text": "Hello"
        });

        let result = connector
            .handle_invoke(serde_json::json!({
                "operation": "telegram.send_message",
                "input": input,
                "capability_token": token
            }))
            .await;

        let err = match result {
            Err(err) => err,
            Ok(_) => {
                assert!(false, "expected OperationNotGranted");
                return;
            }
        };

        if let FcpError::OperationNotGranted { operation } = err {
            assert_eq!(operation, "telegram.send_message");
        } else {
            assert!(false, "unexpected error: {err:?}");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_file_rejects_traversal_download_path() {
        let (connector, token, server) = setup_connector_with_token("telegram.get_file").await;

        Mock::given(method("GET"))
            .and(path(token_path("getFile")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "result": {
                    "file_id": "AgACAgIAAxkBAAI",
                    "file_unique_id": "unique",
                    "file_path": "../../../etc/passwd"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let result = connector
            .handle_invoke(serde_json::json!({
                "operation": "telegram.get_file",
                "input": { "file_id": "AgACAgIAAxkBAAI" },
                "capability_token": token
            }))
            .await;

        match result {
            Err(FcpError::InvalidRequest { code, message }) => {
                assert_eq!(code, 1003);
                assert!(message.contains("Invalid file path"));
            }
            other => panic!("expected InvalidRequest for traversal file path, got {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_logs_redact_token_and_message_text() {
        let capture = LogCapture::new();
        let _guard = capture.install_json_with_filter("debug");
        tracing::debug!("log_capture_ready");
        let (connector, token, server) = setup_connector_with_token("telegram.send_message").await;

        Mock::given(method("POST"))
            .and(path(token_path("sendMessage")))
            .and(body_json(serde_json::json!({
                "chat_id": "123456789",
                "text": "<b>secret message</b>",
                "parse_mode": "HTML"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": false,
                "error_code": 400,
                "description": "Bad Request: can't parse entities"
            })))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path(token_path("sendMessage")))
            .and(body_json(serde_json::json!({
                "chat_id": "123456789",
                "text": "secret message"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "result": {
                    "message_id": 77,
                    "chat": { "id": 123456789, "type": "private", "first_name": "Test" },
                    "date": 1234567890,
                    "text": "secret message"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let input = serde_json::json!({
            "chat_id": "123456789",
            "text": "<b>secret message</b>",
            "parse_mode": "HTML"
        });

        let result = connector
            .handle_invoke(serde_json::json!({
                "operation": "telegram.send_message",
                "input": input,
                "capability_token": token
            }))
            .await;

        assert!(result.is_ok());

        let logs = capture.jsonl();
        assert!(
            logs.contains("log_capture_ready"),
            "expected debug logs to be captured"
        );
        assert!(
            !logs.contains(TEST_BOT_TOKEN),
            "bot token should not appear in logs"
        );
        assert!(
            !logs.contains("secret message"),
            "message text should not appear in logs"
        );
        for line in logs.lines().filter(|line| !line.trim().is_empty()) {
            let parsed: serde_json::Value =
                serde_json::from_str(line).expect("log lines should be JSON");
            assert!(parsed.get("timestamp").is_some() || parsed.get("message").is_some());
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_send_message_text_too_long() {
        let (connector, token, _server) = setup_connector_with_token("telegram.send_message").await;

        let long_text = "x".repeat(MESSAGE_TEXT_MAX_CHARS + 1);
        let input = serde_json::json!({
            "chat_id": "123456789",
            "text": long_text
        });

        let result = connector
            .handle_invoke(serde_json::json!({
                "operation": "telegram.send_message",
                "input": input,
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
        if let FcpError::InvalidRequest { code, message } = err {
            assert_eq!(code, 1004);
            assert!(message.contains(&MESSAGE_TEXT_MAX_CHARS.to_string()));
            assert!(message.contains("character limit"));
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_send_message_text_at_limit() {
        let (connector, token, _server) = setup_connector_with_token("telegram.send_message").await;

        // Create a message exactly at the platform limit - should pass validation
        // but fail on NotConfigured -> Wait, we configured it with a mock!
        // But invoke_send_message calls client.send_message.
        // We haven't mocked sendMessage!
        // So it will fail with 404 from mock server (because no mock matches).
        // BUT the test expects NotConfigured? No, the original test expected NotConfigured because it wasn't configured.
        // Now it IS configured.
        // We should mock sendMessage to return success or error as needed.
        // But this test specifically wants to test boundary condition.
        // If validation passes (<= 4096), it proceeds to call API.
        // If we want to test that validation passed, we can check that it didn't fail with InvalidRequest.
        // If the mock returns 404, that means it TRIED to send, so validation passed.

        let exact_text = "x".repeat(MESSAGE_TEXT_MAX_CHARS);
        let input = serde_json::json!({
            "chat_id": "123456789",
            "text": exact_text
        });

        let result = connector
            .handle_invoke(serde_json::json!({
                "operation": "telegram.send_message",
                "input": input,
                "capability_token": token
            }))
            .await;

        // It should NOT be InvalidRequest.
        // It will be External error (404 from mock) or Success if we mock it.
        // Let's assert it is NOT InvalidRequest(1004).

        match result {
            Ok(_) => {}                          // Success is fine (if we mocked it)
            Err(FcpError::External { .. }) => {} // External error means it tried to send -> validation passed
            Err(e) => assert!(matches!(e, FcpError::External { .. })),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_send_message_parse_error_falls_back() {
        let (connector, token, server) = setup_connector_with_token("telegram.send_message").await;

        Mock::given(method("POST"))
            .and(path(token_path("sendMessage")))
            .and(body_json(serde_json::json!({
                "chat_id": "123456789",
                "text": "<b>Hello</b>",
                "parse_mode": "HTML"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": false,
                "error_code": 400,
                "description": "Bad Request: can't parse entities"
            })))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path(token_path("sendMessage")))
            .and(body_json(serde_json::json!({
                "chat_id": "123456789",
                "text": "Hello"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "result": {
                    "message_id": 55,
                    "chat": { "id": 123456789, "type": "private", "first_name": "Test" },
                    "date": 1234567890,
                    "text": "Hello"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let input = serde_json::json!({
            "chat_id": "123456789",
            "text": "<b>Hello</b>",
            "parse_mode": "HTML"
        });

        let result = connector
            .handle_invoke(serde_json::json!({
                "operation": "telegram.send_message",
                "input": input,
                "capability_token": token
            }))
            .await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(
            response.get("message_id").and_then(|v| v.as_i64()),
            Some(55)
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_send_message_missing_text() {
        let (connector, token, _server) = setup_connector_with_token("telegram.send_message").await;

        let input = serde_json::json!({
            "chat_id": "123456789"
        });

        let result = connector
            .handle_invoke(serde_json::json!({
                "operation": "telegram.send_message",
                "input": input,
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
        if let FcpError::InvalidRequest { message, .. } = err {
            assert!(message.contains("text"));
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_send_message_missing_chat_id() {
        let (connector, token, _server) = setup_connector_with_token("telegram.send_message").await;

        let input = serde_json::json!({
            "text": "Hello"
        });

        let result = connector
            .handle_invoke(serde_json::json!({
                "operation": "telegram.send_message",
                "input": input,
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
        if let FcpError::InvalidRequest { message, .. } = err {
            assert!(message.contains("chat_id"));
        }
    }

    #[test]
    fn test_telegram_message_length_constant() {
        // Verify our constant matches Telegram's documented limit
        assert_eq!(MESSAGE_TEXT_MAX_CHARS, 4096);
        assert_eq!(MEDIA_CAPTION_MAX_CHARS, 1024);
    }

    #[test]
    fn test_send_media_caption_too_long() {
        let caption = "x".repeat(MEDIA_CAPTION_MAX_CHARS + 1);
        let input = json!({
            "chat_id": "123",
            "media_type": "photo",
            "media": "AgACAgIAAxk",
            "caption": caption
        });
        let result = TelegramConnector::validate_input_early("telegram.send_media", &input);
        assert!(result.is_err());
        if let Err(FcpError::InvalidRequest { message, .. }) = result {
            assert!(message.contains(&MEDIA_CAPTION_MAX_CHARS.to_string()));
        }
    }

    #[test]
    fn test_send_media_caption_at_limit() {
        let caption = "x".repeat(MEDIA_CAPTION_MAX_CHARS);
        let input = json!({
            "chat_id": "123",
            "media_type": "photo",
            "media": "AgACAgIAAxk",
            "caption": caption
        });
        let result = TelegramConnector::validate_input_early("telegram.send_media", &input);
        assert!(result.is_ok());
    }

    #[test]
    fn test_send_media_invalid_type_rejected() {
        let input = json!({
            "chat_id": "123",
            "media_type": "gif",
            "media": "AgACAgIAAxk"
        });
        // The input_schema validation should reject "gif" since it's not in the enum
        let result = TelegramConnector::validate_input_early("telegram.send_media", &input);
        assert!(result.is_err());
    }

    #[test]
    fn test_introspect_has_four_operations() {
        let rt = fcp_async_core::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let connector = TelegramConnector::new();
            let result = connector.handle_introspect().await.unwrap();
            let ops = result["operations"].as_array().unwrap();
            assert_eq!(ops.len(), 4, "expected 4 operations, got {}", ops.len());
            let op_ids: Vec<&str> = ops.iter().filter_map(|o| o["id"].as_str()).collect();
            assert!(op_ids.contains(&"telegram.send_message"));
            assert!(op_ids.contains(&"telegram.send_media"));
            assert!(op_ids.contains(&"telegram.get_file"));
            assert!(op_ids.contains(&"telegram.answer_callback_query"));
        });
    }

    // ─── Schema completeness tests ─────────────────────────────────────

    const ALL_OPERATIONS: &[&str] = &[
        "telegram.send_message",
        "telegram.send_media",
        "telegram.get_file",
        "telegram.answer_callback_query",
    ];

    #[test]
    fn test_all_operations_have_input_schema() {
        for op in ALL_OPERATIONS {
            assert!(
                TelegramConnector::input_schema_for(op).is_some(),
                "Missing input schema for {op}"
            );
        }
    }

    #[test]
    fn test_all_operations_have_output_schema() {
        for op in ALL_OPERATIONS {
            assert!(
                TelegramConnector::output_schema_for(op).is_some(),
                "Missing output schema for {op}"
            );
        }
    }

    #[test]
    fn test_unknown_operation_returns_none_schema() {
        assert!(TelegramConnector::input_schema_for("telegram.nonexistent").is_none());
        assert!(TelegramConnector::output_schema_for("telegram.nonexistent").is_none());
    }

    #[test]
    fn test_input_schemas_are_object_type() {
        for op in ALL_OPERATIONS {
            let schema = TelegramConnector::input_schema_for(op).unwrap();
            assert_eq!(
                schema["type"], "object",
                "Input schema for {op} must be type=object"
            );
        }
    }

    #[test]
    fn test_schemas_deterministic_across_calls() {
        for op in ALL_OPERATIONS {
            let a = TelegramConnector::input_schema_for(op).unwrap();
            let b = TelegramConnector::input_schema_for(op).unwrap();
            assert_eq!(a, b, "Input schema for {op} not deterministic");

            let a = TelegramConnector::output_schema_for(op).unwrap();
            let b = TelegramConnector::output_schema_for(op).unwrap();
            assert_eq!(a, b, "Output schema for {op} not deterministic");
        }
    }

    // ─── Introspection metadata tests ──────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_introspect_all_ops_have_required_metadata() {
        let connector = TelegramConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap();
            assert!(
                op["capability"].as_str().is_some(),
                "Op {id} missing capability"
            );
            assert!(
                op["risk_level"].as_str().is_some(),
                "Op {id} missing risk_level"
            );
            assert!(
                op["safety_tier"].as_str().is_some(),
                "Op {id} missing safety_tier"
            );
            assert!(
                op["idempotency"].as_str().is_some(),
                "Op {id} missing idempotency"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_risk_levels_valid() {
        let connector = TelegramConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        let valid_risk = ["low", "medium", "high", "critical"];
        for op in ops {
            let id = op["id"].as_str().unwrap();
            let risk = op["risk_level"].as_str().unwrap();
            assert!(
                valid_risk.contains(&risk),
                "Op {id} has invalid risk_level: {risk}"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_read_ops_are_safe() {
        let connector = TelegramConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap();
            if id == "telegram.get_file" {
                assert_eq!(op["safety_tier"], "safe", "Read op {id} should be safe");
                assert_eq!(op["risk_level"], "low", "Read op {id} should be low risk");
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_deterministic() {
        let connector = TelegramConnector::new();
        let a = connector.handle_introspect().await.unwrap();
        let b = connector.handle_introspect().await.unwrap();
        assert_eq!(a, b, "Introspection should be deterministic");
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_events_present() {
        let connector = TelegramConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let events = result["events"].as_array().unwrap();

        assert_eq!(events.len(), 5, "Expected 5 events");
        let topics: Vec<&str> = events.iter().filter_map(|e| e["topic"].as_str()).collect();
        assert!(topics.contains(&"telegram.message.new"));
        assert!(topics.contains(&"telegram.message.edited"));
        assert!(topics.contains(&"telegram.callback_query"));
    }

    // ─── Schema validation (required fields) ───────────────────────────

    #[test]
    fn test_send_message_requires_chat_id_and_text() {
        let schema = TelegramConnector::input_schema_for("telegram.send_message").unwrap();
        let required = schema["required"].as_array().unwrap();
        let required_strs: Vec<&str> = required.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(required_strs.contains(&"chat_id"));
        assert!(required_strs.contains(&"text"));
    }

    #[test]
    fn test_get_file_requires_file_id() {
        let schema = TelegramConnector::input_schema_for("telegram.get_file").unwrap();
        let required = schema["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str().unwrap() == "file_id"));
    }

    #[test]
    fn test_answer_callback_query_requires_id() {
        let schema = TelegramConnector::input_schema_for("telegram.answer_callback_query").unwrap();
        let required = schema["required"].as_array().unwrap();
        assert!(
            required
                .iter()
                .any(|v| v.as_str().unwrap() == "callback_query_id")
        );
    }

    // ─── Manifest interface hash determinism ───────────────────────────

    // ─── TelegramConfig serde and validation tests ────────────────

    #[test]
    fn test_telegram_config_default_values() {
        let config: TelegramConfig = serde_json::from_value(json!({})).unwrap();
        assert!(config.credential.is_none());
        assert!(config.credential_id.is_none());
        assert!(config.base_url.is_none());
        assert_eq!(config.poll_timeout, 30); // default_poll_timeout()
        assert!(config.allowed_updates.is_empty());
    }

    #[test]
    fn test_telegram_config_serde_roundtrip() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "credential": "123456:ABCtest",
            "base_url": "https://custom.api.tg",
            "poll_timeout": 15,
            "allowed_updates": ["message", "callback_query"]
        }))
        .unwrap();
        assert_eq!(config.credential.as_deref(), Some("123456:ABCtest"));
        assert_eq!(config.base_url.as_deref(), Some("https://custom.api.tg"));
        assert_eq!(config.poll_timeout, 15);
        assert_eq!(config.allowed_updates.len(), 2);
    }

    #[test]
    fn test_telegram_config_resolve_auth_mode_token() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "credential": "123456:ABCtest"
        }))
        .unwrap();
        let mode = config.resolve_auth_mode().unwrap();
        assert_eq!(mode, TelegramAuthConfig::BotToken);
    }

    #[test]
    fn test_telegram_config_resolve_auth_mode_credential_id() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
        }))
        .unwrap();
        let mode = config.resolve_auth_mode().unwrap();
        assert!(matches!(mode, TelegramAuthConfig::CredentialId(_)));
    }

    #[test]
    fn test_telegram_config_resolve_auth_mode_both_fails() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "credential": "123456:ABCtest",
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
        }))
        .unwrap();
        let err = config.resolve_auth_mode().unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn test_telegram_config_resolve_auth_mode_neither_fails() {
        let config: TelegramConfig = serde_json::from_value(json!({})).unwrap();
        let err = config.resolve_auth_mode().unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn test_telegram_config_resolve_auth_mode_empty_credential_fails() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "credential": ""
        }))
        .unwrap();
        let err = config.resolve_auth_mode().unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn test_telegram_config_resolve_auth_mode_whitespace_credential_fails() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "credential": "   "
        }))
        .unwrap();
        let err = config.resolve_auth_mode().unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn test_normalize_base_url_default() {
        let config: TelegramConfig = serde_json::from_value(json!({})).unwrap();
        let url = config.normalize_base_url().unwrap();
        assert_eq!(url, DEFAULT_TELEGRAM_BASE_URL);
    }

    #[test]
    fn test_normalize_base_url_custom() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "base_url": "http://localhost:8080/"
        }))
        .unwrap();
        let url = config.normalize_base_url().unwrap();
        assert_eq!(url, "http://localhost:8080"); // trailing slash stripped
    }

    #[test]
    fn test_normalize_base_url_empty_fails() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "base_url": ""
        }))
        .unwrap();
        let err = config.normalize_base_url().unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn test_normalize_base_url_rejects_non_telegram_remote_host() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "base_url": "https://evil.example.com"
        }))
        .unwrap();
        let err = config.normalize_base_url().unwrap_err();
        if let FcpError::InvalidRequest { message, .. } = err {
            assert!(message.contains("api.telegram.org"));
        }
    }

    #[test]
    fn test_normalize_base_url_rejects_remote_http_host() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "base_url": "http://api.telegram.org"
        }))
        .unwrap();
        let err = config.normalize_base_url().unwrap_err();
        if let FcpError::InvalidRequest { message, .. } = err {
            assert!(message.contains("must use https"));
        }
    }

    #[test]
    fn test_normalize_base_url_invalid_scheme_fails() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "base_url": "ftp://example.com"
        }))
        .unwrap();
        let err = config.normalize_base_url().unwrap_err();
        if let FcpError::InvalidRequest { message, .. } = err {
            assert!(message.contains("http or https"));
        }
    }

    #[test]
    fn test_normalize_base_url_not_a_url_fails() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "base_url": "not a url"
        }))
        .unwrap();
        assert!(config.normalize_base_url().is_err());
    }

    #[test]
    fn test_validate_runtime_settings_default_ok() {
        let config: TelegramConfig = serde_json::from_value(json!({})).unwrap();
        assert!(config.validate_runtime_settings().is_ok());
    }

    #[test]
    fn test_validate_runtime_settings_min_timeout() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "poll_timeout": 1
        }))
        .unwrap();
        assert!(config.validate_runtime_settings().is_ok());
    }

    #[test]
    fn test_validate_runtime_settings_max_timeout() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "poll_timeout": 50
        }))
        .unwrap();
        assert!(config.validate_runtime_settings().is_ok());
    }

    #[test]
    fn test_validate_runtime_settings_timeout_too_low() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "poll_timeout": 0
        }))
        .unwrap();
        let err = config.validate_runtime_settings().unwrap_err();
        if let FcpError::InvalidRequest { message, .. } = err {
            assert!(message.contains("poll_timeout"));
        }
    }

    #[test]
    fn test_validate_runtime_settings_timeout_too_high() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "poll_timeout": 51
        }))
        .unwrap();
        let err = config.validate_runtime_settings().unwrap_err();
        if let FcpError::InvalidRequest { message, .. } = err {
            assert!(message.contains("poll_timeout"));
        }
    }

    #[test]
    fn test_validate_runtime_settings_allowed_updates_valid() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "allowed_updates": ["message", "callback_query", "channel_post"]
        }))
        .unwrap();
        assert!(config.validate_runtime_settings().is_ok());
    }

    #[test]
    fn test_validate_runtime_settings_allowed_updates_empty_entry() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "allowed_updates": ["message", ""]
        }))
        .unwrap();
        let err = config.validate_runtime_settings().unwrap_err();
        if let FcpError::InvalidRequest { message, .. } = err {
            assert!(message.contains("empty"));
        }
    }

    #[test]
    fn test_validate_runtime_settings_allowed_updates_duplicate() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "allowed_updates": ["message", "message"]
        }))
        .unwrap();
        let err = config.validate_runtime_settings().unwrap_err();
        if let FcpError::InvalidRequest { message, .. } = err {
            assert!(message.contains("duplicate"));
        }
    }

    #[test]
    fn test_validate_runtime_settings_allowed_updates_unsupported() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "allowed_updates": ["message", "nonexistent_type"]
        }))
        .unwrap();
        let err = config.validate_runtime_settings().unwrap_err();
        if let FcpError::InvalidRequest { message, .. } = err {
            assert!(message.contains("unsupported"));
        }
    }

    #[test]
    fn test_config_auth_label_token() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "credential": "123456:ABCtest"
        }))
        .unwrap();
        assert_eq!(config.auth_label(), "bot_token");
    }

    #[test]
    fn test_config_auth_label_credential_id() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
        }))
        .unwrap();
        assert_eq!(config.auth_label(), "credential_id");
    }

    // ─── DoctorResult / DoctorStatus / DoctorCheck serde tests ──────

    #[test]
    fn test_doctor_status_serde_roundtrip() {
        let statuses = [
            (DoctorStatus::Healthy, "\"healthy\""),
            (DoctorStatus::Degraded, "\"degraded\""),
            (DoctorStatus::Unhealthy, "\"unhealthy\""),
        ];
        for (status, expected_json) in statuses {
            let serialized = serde_json::to_string(&status).unwrap();
            assert_eq!(serialized, expected_json);
            let back: DoctorStatus = serde_json::from_str(&serialized).unwrap();
            assert_eq!(back, status);
        }
    }

    #[test]
    fn test_doctor_check_serde_roundtrip() {
        let check = DoctorCheck {
            name: "test_check".into(),
            passed: true,
            message: Some("All good".into()),
            critical: false,
        };
        let json_str = serde_json::to_string(&check).unwrap();
        let back: DoctorCheck = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.name, "test_check");
        assert!(back.passed);
        assert_eq!(back.message.as_deref(), Some("All good"));
        assert!(!back.critical);
    }

    #[test]
    fn test_doctor_check_skip_serializing_none_message() {
        let check = DoctorCheck {
            name: "no_msg".into(),
            passed: false,
            message: None,
            critical: true,
        };
        let json_str = serde_json::to_string(&check).unwrap();
        assert!(!json_str.contains("message"));
    }

    #[test]
    fn test_doctor_result_from_checks_healthy() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: true,
                message: None,
                critical: false,
            },
        ];
        let result = DoctorResult::from_checks(checks);
        assert_eq!(result.status, DoctorStatus::Healthy);
    }

    #[test]
    fn test_doctor_result_from_checks_degraded() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: None,
                critical: false,
            },
        ];
        let result = DoctorResult::from_checks(checks);
        assert_eq!(result.status, DoctorStatus::Degraded);
    }

    #[test]
    fn test_doctor_result_from_checks_unhealthy() {
        let checks = vec![DoctorCheck {
            name: "a".into(),
            passed: false,
            message: None,
            critical: true,
        }];
        let result = DoctorResult::from_checks(checks);
        assert_eq!(result.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn test_doctor_result_serde_roundtrip() {
        let result = DoctorResult {
            status: DoctorStatus::Degraded,
            checks: vec![
                DoctorCheck {
                    name: "c1".into(),
                    passed: true,
                    message: None,
                    critical: true,
                },
                DoctorCheck {
                    name: "c2".into(),
                    passed: false,
                    message: Some("warn".into()),
                    critical: false,
                },
            ],
        };
        let json_str = serde_json::to_string(&result).unwrap();
        let back: DoctorResult = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.status, DoctorStatus::Degraded);
        assert_eq!(back.checks.len(), 2);
    }

    // ─── TelegramPollingCursorState serde tests ────────────────────

    #[test]
    fn test_polling_cursor_state_serde_roundtrip() {
        let state = TelegramPollingCursorState {
            offset: Some(42),
            last_poll_count: 5,
            updated_at: 1700000000,
        };
        let json_str = serde_json::to_string(&state).unwrap();
        let back: TelegramPollingCursorState = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.offset, Some(42));
        assert_eq!(back.last_poll_count, 5);
        assert_eq!(back.updated_at, 1700000000);
    }

    #[test]
    fn test_polling_cursor_state_none_offset() {
        let state = TelegramPollingCursorState {
            offset: None,
            last_poll_count: 0,
            updated_at: 0,
        };
        let json_str = serde_json::to_string(&state).unwrap();
        assert!(json_str.contains("null"));
        let back: TelegramPollingCursorState = serde_json::from_str(&json_str).unwrap();
        assert!(back.offset.is_none());
    }

    // ─── TelegramPollingCursor unit tests ──────────────────────────

    #[test]
    fn test_polling_cursor_new_without_path() {
        let cursor = TelegramPollingCursor::new(None);
        assert!(cursor.offset().is_none());
        assert!(cursor.state_path.is_none());
    }

    #[test]
    fn test_polling_cursor_advance_monotonic() {
        let mut cursor = TelegramPollingCursor::new(None);
        cursor.advance_if_newer(10);
        assert_eq!(cursor.offset(), Some(11));
        cursor.advance_if_newer(5); // should not regress
        assert_eq!(cursor.offset(), Some(11));
        cursor.advance_if_newer(11);
        assert_eq!(cursor.offset(), Some(12));
    }

    // ─── is_telegram_or_local_base_url edge cases ──────────────────

    #[test]
    fn test_is_telegram_or_local_url_telegram() {
        assert!(is_telegram_or_local_base_url("https://api.telegram.org"));
    }

    #[test]
    fn test_is_telegram_or_local_url_localhost() {
        assert!(is_telegram_or_local_base_url("http://localhost:8080"));
    }

    #[test]
    fn test_is_telegram_or_local_url_127_0_0_1() {
        assert!(is_telegram_or_local_base_url("http://127.0.0.1:9090"));
    }

    #[test]
    fn test_is_telegram_or_local_url_custom_domain_rejected() {
        assert!(!is_telegram_or_local_base_url("https://evil.example.com"));
    }

    #[test]
    fn test_is_telegram_or_local_url_empty() {
        assert!(!is_telegram_or_local_base_url(""));
    }

    #[test]
    fn test_is_telegram_or_local_url_not_a_url() {
        assert!(!is_telegram_or_local_base_url("not a url"));
    }

    // ─── validate_bot_token_syntax additional tests ─────────────────

    #[test]
    fn test_validate_bot_token_too_short_suffix() {
        assert!(validate_bot_token_syntax("123:abc").is_err());
    }

    #[test]
    fn test_validate_bot_token_no_colon() {
        assert!(validate_bot_token_syntax("123456ABCDEFGHIJKLMNOPQRSTUVWXyz012345").is_err());
    }

    #[test]
    fn test_validate_bot_token_empty() {
        assert!(validate_bot_token_syntax("").is_err());
    }

    // ─── KNOWN_ALLOWED_UPDATES constant test ────────────────────────

    #[test]
    fn test_known_allowed_updates_count() {
        // Telegram documents exactly these update types
        assert_eq!(KNOWN_ALLOWED_UPDATES.len(), 14);
    }

    #[test]
    fn test_known_allowed_updates_contains_expected() {
        assert!(KNOWN_ALLOWED_UPDATES.contains(&"message"));
        assert!(KNOWN_ALLOWED_UPDATES.contains(&"edited_message"));
        assert!(KNOWN_ALLOWED_UPDATES.contains(&"callback_query"));
        assert!(KNOWN_ALLOWED_UPDATES.contains(&"channel_post"));
        assert!(KNOWN_ALLOWED_UPDATES.contains(&"poll"));
    }

    // ─── TelegramConnector default / new tests ──────────────────────

    #[test]
    fn test_connector_default_equals_new() {
        let a = TelegramConnector::new();
        let b = TelegramConnector::default();
        // Both should have no config and no client
        assert!(a.config.is_none());
        assert!(b.config.is_none());
    }

    // ─── Constants tests ────────────────────────────────────────────

    #[test]
    fn test_poll_timeout_bounds_constants() {
        assert_eq!(MIN_POLL_TIMEOUT_SECS, 1);
        assert_eq!(MAX_POLL_TIMEOUT_SECS, 50);
    }

    #[test]
    fn test_default_poll_timeout_value() {
        assert_eq!(default_poll_timeout(), 30);
    }

    #[test]
    fn test_manifest_parses_as_valid_toml_and_is_deterministic() {
        let manifest_str = include_str!("../manifest.toml");
        // Parse as generic TOML twice and verify determinism
        let val_a: toml::Value =
            toml::from_str(manifest_str).expect("manifest should be valid TOML");
        let val_b: toml::Value =
            toml::from_str(manifest_str).expect("manifest should be valid TOML");
        assert_eq!(val_a, val_b, "TOML parse must be deterministic");

        // Verify key structural sections exist
        let table = val_a.as_table().unwrap();
        assert!(table.contains_key("manifest"), "missing [manifest] section");
        assert!(
            table.contains_key("connector"),
            "missing [connector] section"
        );
        assert!(table.contains_key("provides"), "missing [provides] section");

        // Verify operations exist
        let ops = table["provides"]["operations"].as_table().unwrap();
        assert!(ops.contains_key("telegram.send_message"));
        assert!(ops.contains_key("telegram.send_media"));
        assert!(ops.contains_key("telegram.get_file"));
        assert!(ops.contains_key("telegram.answer_callback_query"));

        // Verify interface_hash field exists with expected prefix
        let hash = table["manifest"]["interface_hash"].as_str().unwrap();
        assert!(
            hash.starts_with("blake3-256:"),
            "interface_hash should have blake3-256 prefix"
        );

        // Verify serialization is deterministic
        let ser_a = toml::to_string(&val_a).unwrap();
        let ser_b = toml::to_string(&val_b).unwrap();
        assert_eq!(ser_a, ser_b, "TOML serialization must be deterministic");
    }
}
