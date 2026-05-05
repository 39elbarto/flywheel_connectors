//! `BlueBubbles` API types.
//!
//! Covers the `BlueBubbles` REST API types for `iMessage` bridging.

use std::collections::{BTreeMap, BTreeSet};

use fcp_prelude::FcpError;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// `BlueBubbles` connector configuration.
#[derive(Clone, Deserialize)]
pub struct BlueBubblesConfig {
    /// Base URL for the `BlueBubbles` server (e.g. `http://localhost:1234`).
    #[serde(default = "default_server_url")]
    pub server_url: String,

    /// Server passcode for API authentication.
    #[serde(rename = "password")]
    pub server_passcode: String,

    /// Polling interval in milliseconds for new messages.
    #[serde(default = "default_poll_interval_ms")]
    pub poll_interval_ms: u64,

    /// Directory for storing downloaded attachments.
    #[serde(default)]
    pub attachment_dir: Option<String>,

    /// HTTP retry configuration.
    #[serde(default)]
    pub retry: fcp_sdk::migration::HttpRetryConfig,

    /// Request timeout in milliseconds.
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,

    /// Host/interface used when constructing the local webhook callback URL.
    #[serde(default = "default_webhook_host")]
    pub webhook_host: String,

    /// Port used when constructing the local webhook callback URL.
    #[serde(default = "default_webhook_port")]
    pub webhook_port: u16,

    /// Path used when constructing the local webhook callback URL.
    #[serde(default = "default_webhook_path")]
    pub webhook_path: String,

    /// Account namespace used for inbound webhook dedupe keys.
    #[serde(default = "default_webhook_account_id")]
    pub webhook_account_id: String,

    /// Inbound webhook authorization and replay-dedupe posture.
    #[serde(default)]
    pub webhook_inbound: BlueBubblesWebhookInboundConfig,

    /// Optional DM split-send coalescing posture for accepted inbound webhooks.
    #[serde(default)]
    pub webhook_coalescing: BlueBubblesWebhookCoalescingConfig,

    /// Optional API fallback for resolving missing inbound reply context.
    #[serde(default)]
    pub reply_context_api_fallback: BlueBubblesReplyContextApiFallbackConfig,

    /// Optional Contacts-backed enrichment for accepted inbound group participants.
    #[serde(
        default,
        alias = "enrichGroupParticipantsFromContacts",
        deserialize_with = "deserialize_contacts_enrichment_config"
    )]
    pub contacts_enrichment: BlueBubblesContactsEnrichmentConfig,
}

/// Policy and persistence config for accepted inbound `BlueBubbles` webhook events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlueBubblesWebhookInboundConfig {
    /// Local-account echo messages can be accepted without sender allowlist checks.
    #[serde(default = "default_allow_from_me")]
    pub allow_from_me: bool,

    /// External DM sender handles that may produce accepted inbound events.
    #[serde(default)]
    pub allowed_sender_ids: Vec<String>,

    /// Chat GUIDs or identifiers explicitly bound to this connector instance.
    #[serde(default)]
    pub allowed_chat_guids: Vec<String>,

    /// Whether group conversations may be accepted at all.
    #[serde(default)]
    pub allow_group_chats: bool,

    /// Whether DMs require an explicit configured conversation binding.
    #[serde(default = "default_require_conversation_binding")]
    pub require_conversation_binding: bool,

    /// Optional JSON file used for replay dedupe across connector restart.
    #[serde(default)]
    pub dedupe_state_path: Option<String>,

    /// How long replay dedupe claims remain active.
    #[serde(default = "default_webhook_dedupe_ttl_seconds")]
    pub dedupe_ttl_seconds: u64,
}

impl Default for BlueBubblesWebhookInboundConfig {
    fn default() -> Self {
        Self {
            allow_from_me: default_allow_from_me(),
            allowed_sender_ids: Vec::new(),
            allowed_chat_guids: Vec::new(),
            allow_group_chats: false,
            require_conversation_binding: default_require_conversation_binding(),
            dedupe_state_path: None,
            dedupe_ttl_seconds: default_webhook_dedupe_ttl_seconds(),
        }
    }
}

impl BlueBubblesWebhookInboundConfig {
    fn validate(mut self) -> Result<Self, FcpError> {
        self.allowed_sender_ids = normalize_policy_list(self.allowed_sender_ids);
        self.allowed_chat_guids = normalize_policy_list(self.allowed_chat_guids);
        self.dedupe_state_path = self
            .dedupe_state_path
            .as_deref()
            .map(str::trim)
            .filter(|path| !path.is_empty())
            .map(str::to_owned);

        if self.dedupe_ttl_seconds == 0 {
            return Err(invalid_config(
                "webhook_inbound.dedupe_ttl_seconds must be greater than zero",
            ));
        }

        Ok(self)
    }

    /// Return a PII-safe summary suitable for doctor/introspection surfaces.
    #[must_use]
    pub fn summary(&self) -> BlueBubblesWebhookInboundSummary {
        BlueBubblesWebhookInboundSummary {
            allow_from_me: self.allow_from_me,
            allowed_sender_count: self.allowed_sender_ids.len(),
            allowed_chat_count: self.allowed_chat_guids.len(),
            allow_group_chats: self.allow_group_chats,
            require_conversation_binding: self.require_conversation_binding,
            persistent_dedupe: self.dedupe_state_path.is_some(),
            dedupe_ttl_seconds: self.dedupe_ttl_seconds,
        }
    }

    /// Decide whether a normalized webhook event may cross the inbound boundary.
    #[must_use]
    pub fn evaluate(
        &self,
        event: &NormalizedBlueBubblesWebhookMessage,
    ) -> BlueBubblesInboundDecision {
        let conversation_bound = event.conversation_keys().iter().any(|candidate| {
            self.allowed_chat_guids
                .iter()
                .any(|bound| bound == candidate)
        });

        if event.is_group {
            if !self.allow_group_chats {
                return BlueBubblesInboundDecision::rejected("group_not_allowed");
            }
            if !conversation_bound {
                return BlueBubblesInboundDecision::rejected("conversation_not_bound");
            }
            return BlueBubblesInboundDecision::accepted("group_conversation_bound");
        }

        if self.require_conversation_binding && !conversation_bound {
            return BlueBubblesInboundDecision::rejected("conversation_not_bound");
        }

        if event.is_from_me && self.allow_from_me {
            return BlueBubblesInboundDecision::accepted("from_me_allowed");
        }

        let Some(sender_id) = event.sender_id.as_deref() else {
            return BlueBubblesInboundDecision::rejected("sender_missing");
        };

        if self
            .allowed_sender_ids
            .iter()
            .any(|allowed| allowed == sender_id)
        {
            return BlueBubblesInboundDecision::accepted("sender_allowed");
        }

        BlueBubblesInboundDecision::rejected("sender_not_allowed")
    }
}

/// PII-safe inbound policy summary.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize)]
pub struct BlueBubblesWebhookInboundSummary {
    pub allow_from_me: bool,
    pub allowed_sender_count: usize,
    pub allowed_chat_count: usize,
    pub allow_group_chats: bool,
    pub require_conversation_binding: bool,
    pub persistent_dedupe: bool,
    pub dedupe_ttl_seconds: u64,
}

/// Policy and bounds for accepted DM split-send coalescing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlueBubblesWebhookCoalescingConfig {
    /// Whether accepted DM events may be buffered and merged before emission.
    #[serde(default)]
    pub enabled: bool,

    /// Default debounce window for same-sender DM split sends.
    #[serde(default = "default_webhook_coalescing_debounce_ms")]
    pub debounce_ms: u64,

    /// Maximum supported debounce window; protects against hidden long sleeps.
    #[serde(default = "default_webhook_coalescing_max_debounce_ms")]
    pub max_debounce_ms: u64,

    /// Text prefixes that force immediate emission instead of buffering.
    #[serde(default)]
    pub immediate_command_prefixes: Vec<String>,

    /// Maximum merged text characters before truncation metadata is emitted.
    #[serde(default = "default_webhook_coalescing_max_text_chars")]
    pub max_text_chars: usize,

    /// Maximum attachments included in the merged event payload.
    #[serde(default = "default_webhook_coalescing_max_attachments")]
    pub max_attachments: usize,

    /// Maximum source entries folded into text/attachment merge work.
    #[serde(default = "default_webhook_coalescing_max_source_messages")]
    pub max_source_messages: usize,

    /// Maximum pending DM buffers retained before new buffers are rejected.
    #[serde(default = "default_webhook_coalescing_max_pending_buffers")]
    pub max_pending_buffers: usize,
}

impl Default for BlueBubblesWebhookCoalescingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            debounce_ms: default_webhook_coalescing_debounce_ms(),
            max_debounce_ms: default_webhook_coalescing_max_debounce_ms(),
            immediate_command_prefixes: Vec::new(),
            max_text_chars: default_webhook_coalescing_max_text_chars(),
            max_attachments: default_webhook_coalescing_max_attachments(),
            max_source_messages: default_webhook_coalescing_max_source_messages(),
            max_pending_buffers: default_webhook_coalescing_max_pending_buffers(),
        }
    }
}

impl BlueBubblesWebhookCoalescingConfig {
    fn validate(mut self) -> Result<Self, FcpError> {
        self.immediate_command_prefixes = normalize_policy_list(self.immediate_command_prefixes);

        if self.debounce_ms == 0 {
            return Err(invalid_config(
                "webhook_coalescing.debounce_ms must be greater than zero",
            ));
        }
        if self.max_debounce_ms == 0 {
            return Err(invalid_config(
                "webhook_coalescing.max_debounce_ms must be greater than zero",
            ));
        }
        if self.debounce_ms > self.max_debounce_ms {
            return Err(invalid_config(
                "webhook_coalescing.debounce_ms must not exceed max_debounce_ms",
            ));
        }
        if self.max_text_chars == 0 {
            return Err(invalid_config(
                "webhook_coalescing.max_text_chars must be greater than zero",
            ));
        }
        if self.max_attachments == 0 {
            return Err(invalid_config(
                "webhook_coalescing.max_attachments must be greater than zero",
            ));
        }
        if self.max_source_messages == 0 {
            return Err(invalid_config(
                "webhook_coalescing.max_source_messages must be greater than zero",
            ));
        }
        if self.max_pending_buffers == 0 {
            return Err(invalid_config(
                "webhook_coalescing.max_pending_buffers must be greater than zero",
            ));
        }

        Ok(self)
    }

    /// Return a PII-safe summary suitable for doctor/introspection surfaces.
    #[must_use]
    pub fn summary(&self) -> BlueBubblesWebhookCoalescingSummary {
        BlueBubblesWebhookCoalescingSummary {
            enabled: self.enabled,
            debounce_ms: self.debounce_ms,
            max_debounce_ms: self.max_debounce_ms,
            immediate_command_prefix_count: self.immediate_command_prefixes.len(),
            max_text_chars: self.max_text_chars,
            max_attachments: self.max_attachments,
            max_source_messages: self.max_source_messages,
            max_pending_buffers: self.max_pending_buffers,
        }
    }
}

/// PII-safe coalescing summary.
#[derive(Debug, Clone, Serialize)]
pub struct BlueBubblesWebhookCoalescingSummary {
    pub enabled: bool,
    pub debounce_ms: u64,
    pub max_debounce_ms: u64,
    pub immediate_command_prefix_count: usize,
    pub max_text_chars: usize,
    pub max_attachments: usize,
    pub max_source_messages: usize,
    pub max_pending_buffers: usize,
}

/// Per-account or per-chat override for reply-context fallback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlueBubblesReplyContextFallbackOverride {
    /// Account namespace this override applies to.
    #[serde(default)]
    pub account_id: Option<String>,

    /// Chat GUID or identifier this override applies to.
    #[serde(default)]
    pub chat_guid: Option<String>,

    /// Override value. Chat-scoped overrides take precedence over account-scoped overrides.
    pub enabled: bool,
}

/// Config for best-effort reply context fetches on accepted inbound webhooks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlueBubblesReplyContextApiFallbackConfig {
    /// Global default. Defaults to false for privacy and network minimization.
    #[serde(default)]
    pub enabled: bool,

    /// Account/chat-specific overrides. Chat-scoped matches win over account matches.
    #[serde(default)]
    pub overrides: Vec<BlueBubblesReplyContextFallbackOverride>,

    /// Maximum sanitized reply ID length accepted before path construction.
    #[serde(default = "default_reply_context_max_reply_id_chars")]
    pub max_reply_id_chars: usize,

    /// Maximum bytes read from the `BlueBubbles` message lookup response.
    #[serde(default = "default_reply_context_max_response_bytes")]
    pub max_response_bytes: usize,
}

impl Default for BlueBubblesReplyContextApiFallbackConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            overrides: Vec::new(),
            max_reply_id_chars: default_reply_context_max_reply_id_chars(),
            max_response_bytes: default_reply_context_max_response_bytes(),
        }
    }
}

impl BlueBubblesReplyContextApiFallbackConfig {
    fn validate(mut self) -> Result<Self, FcpError> {
        for override_config in &mut self.overrides {
            override_config.account_id = override_config
                .account_id
                .as_deref()
                .and_then(nonempty_string);
            override_config.chat_guid = override_config
                .chat_guid
                .as_deref()
                .and_then(nonempty_string);
        }
        self.overrides.retain(|override_config| {
            override_config.account_id.is_some() || override_config.chat_guid.is_some()
        });

        if self.max_reply_id_chars == 0 {
            return Err(invalid_config(
                "reply_context_api_fallback.max_reply_id_chars must be greater than zero",
            ));
        }
        if self.max_reply_id_chars > MAX_WEBHOOK_GUID_CHARS {
            return Err(invalid_config(format!(
                "reply_context_api_fallback.max_reply_id_chars must not exceed {MAX_WEBHOOK_GUID_CHARS}"
            )));
        }
        if self.max_response_bytes == 0 {
            return Err(invalid_config(
                "reply_context_api_fallback.max_response_bytes must be greater than zero",
            ));
        }

        Ok(self)
    }

    /// Return a PII-safe summary suitable for doctor/introspection surfaces.
    #[must_use]
    pub fn summary(&self) -> BlueBubblesReplyContextApiFallbackSummary {
        BlueBubblesReplyContextApiFallbackSummary {
            enabled: self.enabled,
            account_override_count: self
                .overrides
                .iter()
                .filter(|override_config| {
                    override_config.account_id.is_some() && override_config.chat_guid.is_none()
                })
                .count(),
            chat_override_count: self
                .overrides
                .iter()
                .filter(|override_config| override_config.chat_guid.is_some())
                .count(),
            max_reply_id_chars: self.max_reply_id_chars,
            max_response_bytes: self.max_response_bytes,
        }
    }

    /// Resolve fallback enablement for one accepted inbound event.
    #[must_use]
    pub fn enabled_for(&self, account_id: &str, chat_keys: &[String]) -> bool {
        for chat_key in chat_keys {
            if let Some(override_config) = self.overrides.iter().find(|override_config| {
                override_config.chat_guid.as_deref() == Some(chat_key.as_str())
                    && override_config
                        .account_id
                        .as_deref()
                        .is_none_or(|configured| configured == account_id)
            }) {
                return override_config.enabled;
            }
        }

        if let Some(override_config) = self.overrides.iter().find(|override_config| {
            override_config.chat_guid.is_none()
                && override_config.account_id.as_deref() == Some(account_id)
        }) {
            return override_config.enabled;
        }

        self.enabled
    }
}

/// PII-safe reply-context fallback summary.
#[derive(Debug, Clone, Serialize)]
pub struct BlueBubblesReplyContextApiFallbackSummary {
    pub enabled: bool,
    pub account_override_count: usize,
    pub chat_override_count: usize,
    pub max_reply_id_chars: usize,
    pub max_response_bytes: usize,
}

/// Per-account or per-chat override for Contacts-backed participant enrichment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlueBubblesContactsEnrichmentOverride {
    /// Account namespace this override applies to.
    #[serde(default)]
    pub account_id: Option<String>,

    /// Chat GUID or identifier this override applies to.
    #[serde(default)]
    pub chat_guid: Option<String>,

    /// Override value. Chat-scoped overrides take precedence over account-scoped overrides.
    pub enabled: bool,
}

/// Config for opt-in Contacts-backed group participant enrichment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlueBubblesContactsEnrichmentConfig {
    /// Global default. Defaults to false because local Contacts access can expose private data.
    #[serde(default)]
    pub enabled: bool,

    /// Account/chat-specific overrides. Chat-scoped matches win over account matches.
    #[serde(default)]
    pub overrides: Vec<BlueBubblesContactsEnrichmentOverride>,

    /// Explicit `AddressBook` `SQLite` database paths. Empty means discover the macOS default.
    #[serde(default)]
    pub database_paths: Vec<String>,

    /// Optional home directory used for macOS `AddressBook` discovery.
    #[serde(default)]
    pub home_dir: Option<String>,

    /// Deterministic phone-to-name source for tests or operator-provided fixtures.
    #[serde(default)]
    pub test_contacts: BTreeMap<String, String>,

    /// TTL for positive contact-name cache entries.
    #[serde(default = "default_contacts_positive_cache_ttl_seconds")]
    pub positive_cache_ttl_seconds: u64,

    /// TTL for negative contact-name cache entries.
    #[serde(default = "default_contacts_negative_cache_ttl_seconds")]
    pub negative_cache_ttl_seconds: u64,

    /// Maximum normalized phone keys retained in the enrichment cache.
    #[serde(default = "default_contacts_max_cache_entries")]
    pub max_cache_entries: usize,
}

impl Default for BlueBubblesContactsEnrichmentConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            overrides: Vec::new(),
            database_paths: Vec::new(),
            home_dir: None,
            test_contacts: BTreeMap::new(),
            positive_cache_ttl_seconds: default_contacts_positive_cache_ttl_seconds(),
            negative_cache_ttl_seconds: default_contacts_negative_cache_ttl_seconds(),
            max_cache_entries: default_contacts_max_cache_entries(),
        }
    }
}

impl BlueBubblesContactsEnrichmentConfig {
    fn validate(mut self) -> Result<Self, FcpError> {
        for override_config in &mut self.overrides {
            override_config.account_id = override_config
                .account_id
                .as_deref()
                .and_then(nonempty_string);
            override_config.chat_guid = override_config
                .chat_guid
                .as_deref()
                .and_then(nonempty_string);
        }
        self.overrides.retain(|override_config| {
            override_config.account_id.is_some() || override_config.chat_guid.is_some()
        });
        self.database_paths = normalize_policy_list(self.database_paths);
        self.home_dir = self
            .home_dir
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);

        self.test_contacts = std::mem::take(&mut self.test_contacts)
            .into_iter()
            .filter_map(|(phone, name)| {
                let phone = normalize_bluebubbles_contact_phone_key(&phone)?;
                nonempty_string(&name).map(|name| (phone, name))
            })
            .collect();

        if self.positive_cache_ttl_seconds == 0 {
            return Err(invalid_config(
                "contacts_enrichment.positive_cache_ttl_seconds must be greater than zero",
            ));
        }
        if self.negative_cache_ttl_seconds == 0 {
            return Err(invalid_config(
                "contacts_enrichment.negative_cache_ttl_seconds must be greater than zero",
            ));
        }
        if self.max_cache_entries == 0 {
            return Err(invalid_config(
                "contacts_enrichment.max_cache_entries must be greater than zero",
            ));
        }

        Ok(self)
    }

    /// Return a PII-safe summary suitable for doctor/introspection surfaces.
    #[must_use]
    pub fn summary(&self) -> BlueBubblesContactsEnrichmentSummary {
        BlueBubblesContactsEnrichmentSummary {
            enabled: self.enabled,
            default_enabled: false,
            account_override_count: self
                .overrides
                .iter()
                .filter(|override_config| {
                    override_config.account_id.is_some() && override_config.chat_guid.is_none()
                })
                .count(),
            chat_override_count: self
                .overrides
                .iter()
                .filter(|override_config| override_config.chat_guid.is_some())
                .count(),
            explicit_database_count: self.database_paths.len(),
            home_dir_configured: self.home_dir.is_some(),
            test_contact_count: self.test_contacts.len(),
            positive_cache_ttl_seconds: self.positive_cache_ttl_seconds,
            negative_cache_ttl_seconds: self.negative_cache_ttl_seconds,
            max_cache_entries: self.max_cache_entries,
        }
    }

    /// Resolve enrichment enablement for one accepted inbound event.
    #[must_use]
    pub fn enabled_for(&self, account_id: &str, chat_keys: &[String]) -> bool {
        for chat_key in chat_keys {
            if let Some(override_config) = self.overrides.iter().find(|override_config| {
                override_config.chat_guid.as_deref() == Some(chat_key.as_str())
                    && override_config
                        .account_id
                        .as_deref()
                        .is_none_or(|configured| configured == account_id)
            }) {
                return override_config.enabled;
            }
        }

        if let Some(override_config) = self.overrides.iter().find(|override_config| {
            override_config.chat_guid.is_none()
                && override_config.account_id.as_deref() == Some(account_id)
        }) {
            return override_config.enabled;
        }

        self.enabled
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum BlueBubblesContactsEnrichmentConfigInput {
    Enabled(bool),
    Config(BlueBubblesContactsEnrichmentConfig),
}

fn deserialize_contacts_enrichment_config<'de, D>(
    deserializer: D,
) -> Result<BlueBubblesContactsEnrichmentConfig, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match BlueBubblesContactsEnrichmentConfigInput::deserialize(deserializer)? {
        BlueBubblesContactsEnrichmentConfigInput::Enabled(enabled) => {
            Ok(BlueBubblesContactsEnrichmentConfig {
                enabled,
                ..BlueBubblesContactsEnrichmentConfig::default()
            })
        }
        BlueBubblesContactsEnrichmentConfigInput::Config(config) => Ok(config),
    }
}

/// PII-safe Contacts enrichment summary.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize)]
pub struct BlueBubblesContactsEnrichmentSummary {
    pub enabled: bool,
    pub default_enabled: bool,
    pub account_override_count: usize,
    pub chat_override_count: usize,
    pub explicit_database_count: usize,
    pub home_dir_configured: bool,
    pub test_contact_count: usize,
    pub positive_cache_ttl_seconds: u64,
    pub negative_cache_ttl_seconds: u64,
    pub max_cache_entries: usize,
}

/// Result of applying inbound sender/conversation policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BlueBubblesInboundDecision {
    pub accepted: bool,
    pub reason: &'static str,
}

impl BlueBubblesInboundDecision {
    const fn accepted(reason: &'static str) -> Self {
        Self {
            accepted: true,
            reason,
        }
    }

    const fn rejected(reason: &'static str) -> Self {
        Self {
            accepted: false,
            reason,
        }
    }
}

impl BlueBubblesConfig {
    /// Parse and validate connector configuration from FCP configure payloads.
    ///
    /// # Errors
    ///
    /// Returns an `InvalidRequest` error when required fields are missing or malformed.
    pub fn from_value(value: serde_json::Value) -> Result<Self, FcpError> {
        let config: Self =
            serde_json::from_value(value).map_err(|error| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid BlueBubbles config: {error}"),
            })?;
        config.validate()
    }

    /// Validate and normalize the configuration.
    ///
    /// # Errors
    ///
    /// Returns an `InvalidRequest` error when the config is unusable.
    pub fn validate(mut self) -> Result<Self, FcpError> {
        self.server_url = self.server_url.trim().trim_end_matches('/').to_string();
        self.server_passcode = self.server_passcode.trim().to_string();
        self.attachment_dir = self
            .attachment_dir
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        self.webhook_host = self.webhook_host.trim().to_string();
        self.webhook_path = normalize_webhook_path(&self.webhook_path);
        self.webhook_account_id = self.webhook_account_id.trim().to_string();
        self.webhook_inbound = self.webhook_inbound.validate()?;
        self.webhook_coalescing = self.webhook_coalescing.validate()?;
        self.reply_context_api_fallback = self.reply_context_api_fallback.validate()?;
        self.contacts_enrichment = self.contacts_enrichment.validate()?;

        if self.server_passcode.is_empty() {
            return Err(invalid_config("password must not be empty"));
        }

        if self.poll_interval_ms == 0 {
            return Err(invalid_config("poll_interval_ms must be greater than zero"));
        }

        if self.request_timeout_ms == 0 {
            return Err(invalid_config(
                "request_timeout_ms must be greater than zero",
            ));
        }

        if self.webhook_host.is_empty() {
            return Err(invalid_config("webhook_host must not be empty"));
        }

        if self.webhook_port == 0 {
            return Err(invalid_config("webhook_port must be greater than zero"));
        }

        if self.webhook_path == "/" {
            return Err(invalid_config("webhook_path must not be the root path"));
        }

        if self.webhook_account_id.is_empty() {
            return Err(invalid_config("webhook_account_id must not be empty"));
        }

        let parsed_url = Url::parse(&self.server_url).map_err(|error| {
            invalid_config(format!("server_url must be a valid absolute URL: {error}"))
        })?;

        if !matches!(parsed_url.scheme(), "http" | "https") {
            return Err(invalid_config("server_url must use http or https"));
        }

        if parsed_url.host_str().is_none() {
            return Err(invalid_config("server_url must include a host"));
        }

        Ok(self)
    }

    /// Extract the configured host for diagnostics.
    #[must_use]
    pub fn server_host(&self) -> Option<String> {
        Url::parse(&self.server_url)
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
    }

    /// Build the URL registered with `BlueBubbles` for inbound webhook callbacks.
    ///
    /// The `BlueBubbles` registration API cannot attach custom headers, so the
    /// bridge password is embedded as a query parameter for inbound auth.
    ///
    /// # Errors
    ///
    /// Returns `InvalidRequest` if the configured host/path cannot form a URL.
    pub fn webhook_registration_url(&self) -> Result<String, FcpError> {
        let host = match self.webhook_host.as_str() {
            "0.0.0.0" | "127.0.0.1" | "localhost" | "::" => "localhost",
            other => other,
        };
        let mut url = Url::parse(&format!(
            "http://{}:{}{}",
            host, self.webhook_port, self.webhook_path
        ))
        .map_err(|error| invalid_config(format!("invalid webhook callback URL: {error}")))?;
        url.query_pairs_mut()
            .append_pair("password", &self.server_passcode);
        Ok(url.to_string())
    }
}

impl std::fmt::Debug for BlueBubblesConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlueBubblesConfig")
            .field("server_url", &self.server_url)
            .field("server_passcode", &"[REDACTED]")
            .field("poll_interval_ms", &self.poll_interval_ms)
            .field("attachment_dir", &self.attachment_dir)
            .field("retry", &self.retry)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .field("webhook_host", &self.webhook_host)
            .field("webhook_port", &self.webhook_port)
            .field("webhook_path", &self.webhook_path)
            .field("webhook_account_id", &self.webhook_account_id)
            .field("webhook_inbound", &self.webhook_inbound.summary())
            .field("webhook_coalescing", &self.webhook_coalescing.summary())
            .field(
                "reply_context_api_fallback",
                &self.reply_context_api_fallback.summary(),
            )
            .field("contacts_enrichment", &self.contacts_enrichment.summary())
            .finish()
    }
}

fn default_server_url() -> String {
    "http://localhost:1234".to_string()
}

const fn default_poll_interval_ms() -> u64 {
    5000
}

const fn default_request_timeout_ms() -> u64 {
    30_000
}

fn default_webhook_host() -> String {
    "127.0.0.1".to_string()
}

const fn default_webhook_port() -> u16 {
    8645
}

fn default_webhook_path() -> String {
    "/bluebubbles-webhook".to_string()
}

fn default_webhook_account_id() -> String {
    "default".to_string()
}

const fn default_allow_from_me() -> bool {
    true
}

const fn default_require_conversation_binding() -> bool {
    true
}

const fn default_webhook_dedupe_ttl_seconds() -> u64 {
    7 * 24 * 60 * 60
}

const fn default_webhook_coalescing_debounce_ms() -> u64 {
    2_500
}

const fn default_webhook_coalescing_max_debounce_ms() -> u64 {
    2_500
}

const fn default_webhook_coalescing_max_text_chars() -> usize {
    4_000
}

const fn default_webhook_coalescing_max_attachments() -> usize {
    20
}

const fn default_webhook_coalescing_max_source_messages() -> usize {
    10
}

const fn default_webhook_coalescing_max_pending_buffers() -> usize {
    256
}

const fn default_reply_context_max_reply_id_chars() -> usize {
    MAX_WEBHOOK_GUID_CHARS
}

const fn default_reply_context_max_response_bytes() -> usize {
    256 * 1024
}

const fn default_contacts_positive_cache_ttl_seconds() -> u64 {
    60 * 60
}

const fn default_contacts_negative_cache_ttl_seconds() -> u64 {
    5 * 60
}

const fn default_contacts_max_cache_entries() -> usize {
    2048
}

fn normalize_webhook_path(path: &str) -> String {
    let path = path.trim();
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

fn normalize_policy_list(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .filter_map(|value| nonempty_string(&value))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn invalid_config(message: impl Into<String>) -> FcpError {
    FcpError::InvalidRequest {
        code: 1001,
        message: format!("Invalid BlueBubbles config: {}", message.into()),
    }
}

/// Normalize a phone number into the Contacts lookup key used by `BlueBubbles`.
#[must_use]
pub fn normalize_bluebubbles_contact_phone_key(value: &str) -> Option<String> {
    let digits = value
        .chars()
        .filter(char::is_ascii_digit)
        .collect::<String>();
    if digits.is_empty() {
        return None;
    }
    let normalized = match (digits.len(), digits.strip_prefix('1')) {
        (11, Some(rest)) => rest.to_string(),
        _ => digits,
    };
    (normalized.len() >= 7).then_some(normalized)
}

// ---------------------------------------------------------------------------
// Chat types
// ---------------------------------------------------------------------------

/// A `BlueBubbles` chat (individual or group conversation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chat {
    /// Unique chat identifier (e.g. "iMessage;-;+15551234567").
    pub guid: String,

    /// Human-readable display name for the chat.
    #[serde(default)]
    pub display_name: Option<String>,

    /// Participants in this chat.
    #[serde(default)]
    pub participants: Vec<ChatParticipant>,

    /// Group identifier (for group chats).
    #[serde(default)]
    pub group_id: Option<String>,

    /// Whether this is a group chat.
    #[serde(default)]
    pub is_group: bool,

    /// The last message in this chat.
    #[serde(default)]
    pub last_message: Option<Message>,
}

/// A participant in a chat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatParticipant {
    /// Address (phone number or email).
    pub address: String,

    /// Human-readable display name.
    #[serde(default)]
    pub display_name: Option<String>,

    /// Whether this participant is the local user.
    #[serde(default)]
    pub is_me: bool,
}

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

/// A `BlueBubbles` message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Unique message identifier.
    pub guid: String,

    /// Message text content.
    #[serde(default)]
    pub text: Option<String>,

    /// Timestamp when the message was created (epoch ms).
    #[serde(default)]
    pub date_created: Option<i64>,

    /// Timestamp when the message was delivered (epoch ms).
    #[serde(default)]
    pub date_delivered: Option<i64>,

    /// Timestamp when the message was read (epoch ms).
    #[serde(default)]
    pub date_read: Option<i64>,

    /// Whether this message was sent by the local user.
    #[serde(default)]
    pub is_from_me: bool,

    /// Handle (sender) info.
    #[serde(default)]
    pub handle: Option<MessageHandle>,

    /// Chat GUID included by single-message lookup responses when available.
    #[serde(
        default,
        rename = "chatGuid",
        alias = "chat_guid",
        skip_serializing_if = "Option::is_none"
    )]
    pub chat_guid: Option<String>,

    /// Chat identifier included by single-message lookup responses when available.
    #[serde(
        default,
        rename = "chatIdentifier",
        alias = "chat_identifier",
        skip_serializing_if = "Option::is_none"
    )]
    pub chat_identifier: Option<String>,

    /// Embedded chat metadata included by some `BlueBubbles` responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chat: Option<MessageChatReference>,

    /// Embedded chat list included by webhook-like or expanded responses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chats: Vec<MessageChatReference>,

    /// Attachments on this message.
    #[serde(default)]
    pub attachments: Vec<Attachment>,

    /// GUID of the thread originator message (for threaded replies).
    #[serde(default)]
    pub thread_originator_guid: Option<String>,

    /// Associated message type (tapback reactions, etc.).
    #[serde(default)]
    pub associated_message_type: Option<i32>,

    /// Group action type (member added/removed, name change, etc.).
    #[serde(default)]
    pub group_action_type: Option<i32>,
}

impl Message {
    /// Return non-empty chat identifiers exposed by this message without leaking participant data.
    #[must_use]
    pub fn conversation_keys(&self) -> Vec<String> {
        let mut keys = Vec::new();
        push_optional_key(&mut keys, self.chat_guid.as_deref());
        push_optional_key(&mut keys, self.chat_identifier.as_deref());
        if let Some(chat) = &self.chat {
            chat.push_conversation_keys(&mut keys);
        }
        for chat in &self.chats {
            chat.push_conversation_keys(&mut keys);
        }
        keys
    }
}

/// Lightweight chat reference embedded in message lookup responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageChatReference {
    /// `BlueBubbles` chat GUID, when exposed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guid: Option<String>,

    /// Alternate chat GUID spelling used by some response shapes.
    #[serde(
        default,
        rename = "chatGuid",
        alias = "chat_guid",
        skip_serializing_if = "Option::is_none"
    )]
    pub chat_guid: Option<String>,

    /// Alternate chat identifier spelling used by some response shapes.
    #[serde(
        default,
        rename = "chatIdentifier",
        alias = "chat_identifier",
        skip_serializing_if = "Option::is_none"
    )]
    pub chat_identifier: Option<String>,
}

impl MessageChatReference {
    fn push_conversation_keys(&self, keys: &mut Vec<String>) {
        push_optional_key(keys, self.guid.as_deref());
        push_optional_key(keys, self.chat_guid.as_deref());
        push_optional_key(keys, self.chat_identifier.as_deref());
    }
}

/// Handle (sender) information for a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageHandle {
    /// Address (phone number or email).
    pub address: String,

    /// Human-readable display name.
    #[serde(default)]
    pub display_name: Option<String>,
}

/// An attachment on a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    /// Unique attachment identifier.
    pub guid: String,

    /// MIME type of the attachment.
    #[serde(default)]
    pub mime_type: Option<String>,

    /// Original filename.
    #[serde(default)]
    pub filename: Option<String>,

    /// Total size in bytes.
    #[serde(default)]
    pub total_bytes: Option<u64>,

    /// Transfer name (server-side filename).
    #[serde(default)]
    pub transfer_name: Option<String>,
}

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

/// Request to send a message via `BlueBubbles`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendMessageRequest {
    /// Target chat GUID.
    #[serde(rename = "chatGuid")]
    pub chat_guid: String,

    /// Message text.
    pub message: String,

    /// Temporary GUID for de-duplication.
    #[serde(rename = "tempGuid", default)]
    pub temp_guid: Option<String>,

    /// Sending method ("apple-script" or "private-api").
    #[serde(default = "default_send_method")]
    pub method: String,
}

/// `BlueBubbles` `AppleScript` send mode.
pub const SEND_METHOD_APPLE_SCRIPT: &str = "apple-script";

/// `BlueBubbles` Private API send mode.
pub const SEND_METHOD_PRIVATE_API: &str = "private-api";

fn default_send_method() -> String {
    SEND_METHOD_APPLE_SCRIPT.to_string()
}

/// Response from sending a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendMessageResponse {
    /// Status code from the server.
    pub status: i32,

    /// Status message.
    #[serde(default)]
    pub message: Option<String>,

    /// Sent message data.
    #[serde(default)]
    pub data: Option<Message>,
}

/// Server information from the `BlueBubbles` instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    /// macOS version running `BlueBubbles`.
    #[serde(default)]
    pub os_version: Option<String>,

    /// `BlueBubbles` server version.
    #[serde(default)]
    pub server_version: Option<String>,

    /// Whether the Private API is enabled.
    #[serde(default)]
    pub private_api: bool,

    /// Proxy service in use (e.g. "ngrok", "cloudflare").
    #[serde(default)]
    pub proxy_service: Option<String>,
}

/// Query parameters for paginated endpoints.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QueryParams {
    /// Offset for pagination.
    #[serde(default)]
    pub offset: Option<u64>,

    /// Maximum number of results to return.
    #[serde(default)]
    pub limit: Option<u64>,

    /// Only return results after this timestamp (epoch ms).
    #[serde(default)]
    pub after: Option<i64>,

    /// Only return results before this timestamp (epoch ms).
    #[serde(default)]
    pub before: Option<i64>,

    /// Sort order ("ASC" or "DESC").
    #[serde(default)]
    pub sort: Option<String>,

    /// Related objects to include (e.g. `["chat", "handle"]`).
    #[serde(default)]
    pub with: Vec<String>,
}

/// Paginated response wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    /// Total number of results available.
    #[serde(default)]
    pub total: Option<u64>,

    /// Current offset.
    #[serde(default)]
    pub offset: u64,

    /// Page size limit.
    #[serde(default)]
    pub limit: u64,

    /// Response data.
    pub data: Vec<T>,
}

/// API error response from `BlueBubbles`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorResponse {
    /// Error message from the server.
    #[serde(default)]
    pub error: Option<String>,

    /// Status code from the server.
    #[serde(default)]
    pub status: Option<i32>,

    /// Human-readable message.
    #[serde(default)]
    pub message: Option<String>,
}

// ---------------------------------------------------------------------------
// Webhook registration and ingress types
// ---------------------------------------------------------------------------

/// Default `BlueBubbles` webhook events that carry message activity.
#[must_use]
pub fn default_webhook_events() -> Vec<String> {
    vec!["new-message".to_string(), "updated-message".to_string()]
}

/// Request body for registering a `BlueBubbles` webhook callback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookRegistrationRequest {
    /// Callback URL to register with the `BlueBubbles` server.
    pub url: String,

    /// Event names the server should POST to the callback URL.
    #[serde(default = "default_webhook_events")]
    pub events: Vec<String>,
}

/// One registered `BlueBubbles` webhook callback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookRegistration {
    /// Server-assigned webhook ID. Some server versions use numeric IDs.
    #[serde(default, deserialize_with = "deserialize_optional_id")]
    pub id: Option<String>,

    /// Registered callback URL.
    #[serde(default)]
    pub url: Option<String>,

    /// Registered event names.
    #[serde(default)]
    pub events: Vec<String>,
}

/// Attachment metadata normalized from inbound webhook payloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedWebhookAttachment {
    /// Attachment GUID.
    pub guid: String,

    /// MIME type, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,

    /// Apple UTI, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uti: Option<String>,

    /// Original transfer name, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transfer_name: Option<String>,

    /// Reported byte size, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_bytes: Option<u64>,
}

/// Participant metadata normalized from inbound group webhook payloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlueBubblesWebhookParticipant {
    /// Phone number, email, or bridge handle identifying the participant.
    pub address: String,

    /// Human-readable display name when exposed or safely enriched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    /// Whether this participant represents the local account.
    pub is_me: bool,

    /// Whether `display_name` came from opt-in Contacts enrichment.
    #[serde(default, skip_serializing_if = "is_false")]
    pub contact_name_enriched: bool,
}

/// Normalized message-shaped event from a `BlueBubbles` webhook payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedBlueBubblesWebhookMessage {
    /// Original webhook event type, such as `new-message` or `updated-message`.
    pub event_type: String,

    /// FCP event topic derived from the message metadata.
    pub topic: String,

    /// Message GUID used as the primary webhook event ID.
    pub event_id: String,

    /// Chat GUID, when the payload exposes one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chat_guid: Option<String>,

    /// Chat identifier fallback, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chat_identifier: Option<String>,

    /// Sender address/handle, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_id: Option<String>,

    /// Sender display name, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_name: Option<String>,

    /// Text body, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,

    /// Whether the message originated from the local `BlueBubbles` account.
    pub is_from_me: bool,

    /// Whether the chat is a group conversation.
    pub is_group: bool,

    /// Attachments on the inbound message.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<NormalizedWebhookAttachment>,

    /// Participant metadata for group conversations, when exposed by `BlueBubbles`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub participants: Vec<BlueBubblesWebhookParticipant>,

    /// Thread/reply originator GUID, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to_message_guid: Option<String>,

    /// Best-effort reply context resolved from cache or the `BlueBubbles` API.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_context: Option<BlueBubblesReplyContext>,

    /// Associated message GUID used by tapbacks, replies, stickers, and previews.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub associated_message_guid: Option<String>,

    /// Associated message type used by tapback add/remove events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub associated_message_type: Option<i32>,

    /// Balloon bundle ID used by stickers/previews that can coalesce with text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balloon_bundle_id: Option<String>,

    /// Whether this payload represents a tapback-style associated message.
    pub is_tapback: bool,

    /// Additional source `BlueBubbles` message IDs represented by this event.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_message_ids: Vec<String>,

    /// Source message timestamp in epoch milliseconds, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_created_ms: Option<i64>,

    /// Number of raw source webhook messages folded into this normalized event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coalesced_source_count: Option<usize>,

    /// Bounded fields truncated while constructing a coalesced event.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub coalescing_truncated_fields: Vec<String>,
}

impl NormalizedBlueBubblesWebhookMessage {
    /// Return non-empty chat identifiers that scope caches and policy.
    #[must_use]
    pub fn conversation_keys(&self) -> Vec<String> {
        [&self.chat_guid, &self.chat_identifier]
            .into_iter()
            .filter_map(|value| value.as_deref().and_then(nonempty_string))
            .collect()
    }
}

/// Reply context intentionally omits reply text and sender names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlueBubblesReplyContext {
    /// Canonical message GUID fetched from `BlueBubbles`.
    pub message_guid: String,

    /// Whether the reply body exists; body text is not serialized.
    pub text_present: bool,

    /// Whether this reply was sent by the local account.
    pub is_from_me: bool,

    /// Number of attachments on the referenced reply.
    pub attachment_count: usize,

    /// Reply creation timestamp in epoch milliseconds, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_created_ms: Option<i64>,
}

const MAX_WEBHOOK_GUID_CHARS: usize = 512;

fn deserialize_optional_id<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<Value>::deserialize(deserializer)?;
    Ok(value.and_then(|value| match value {
        Value::String(value) => nonempty_string(&value),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }))
}

fn nonempty_string(value: &str) -> Option<String> {
    let value = value.trim().to_string();
    (!value.is_empty()).then_some(value)
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_false(value: &bool) -> bool {
    !*value
}

fn read_string(record: Option<&Map<String, Value>>, keys: &[&str]) -> Option<String> {
    let record = record?;
    keys.iter().find_map(|key| {
        record
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    })
}

fn read_bool(record: Option<&Map<String, Value>>, keys: &[&str]) -> Option<bool> {
    let record = record?;
    keys.iter()
        .find_map(|key| record.get(*key).and_then(Value::as_bool))
}

fn read_i64(record: Option<&Map<String, Value>>, keys: &[&str]) -> Option<i64> {
    let record = record?;
    keys.iter().find_map(|key| {
        record.get(*key).and_then(|value| {
            value
                .as_i64()
                .or_else(|| value.as_u64().and_then(|number| i64::try_from(number).ok()))
        })
    })
}

fn read_u64(record: Option<&Map<String, Value>>, keys: &[&str]) -> Option<u64> {
    let record = record?;
    keys.iter().find_map(|key| {
        record.get(*key).and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_i64().and_then(|number| u64::try_from(number).ok()))
        })
    })
}

fn read_string_array(record: Option<&Map<String, Value>>, keys: &[&str]) -> Vec<String> {
    let Some(record) = record else {
        return Vec::new();
    };

    keys.iter()
        .find_map(|key| record.get(*key))
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(|value| match value {
                    Value::String(value) => nonempty_string(value),
                    Value::Number(value) => Some(value.to_string()),
                    _ => None,
                })
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        })
        .unwrap_or_default()
}

fn push_optional_key(keys: &mut Vec<String>, value: Option<&str>) {
    let Some(value) = value.and_then(nonempty_string) else {
        return;
    };
    if !keys.iter().any(|existing| existing == &value) {
        keys.push(value);
    }
}

fn read_record<'a>(
    record: Option<&'a Map<String, Value>>,
    keys: &[&str],
) -> Option<&'a Map<String, Value>> {
    let record = record?;
    keys.iter().find_map(|key| record.get(*key)?.as_object())
}

fn first_record_in_array<'a>(
    record: Option<&'a Map<String, Value>>,
    keys: &[&str],
) -> Option<&'a Map<String, Value>> {
    let record = record?;
    keys.iter().find_map(|key| {
        record
            .get(*key)?
            .as_array()?
            .iter()
            .find_map(Value::as_object)
    })
}

fn payload_record(payload: &Value) -> Result<&Map<String, Value>, FcpError> {
    let root = payload
        .as_object()
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: "BlueBubbles webhook payload must be a JSON object".into(),
        })?;

    if let Some(data) = root.get("data") {
        if let Some(record) = data.as_object() {
            return Ok(record);
        }
        if let Some(record) = data
            .as_array()
            .and_then(|items| items.iter().find_map(Value::as_object))
        {
            return Ok(record);
        }
    }

    if let Some(record) = root.get("message").and_then(Value::as_object) {
        return Ok(record);
    }

    Ok(root)
}

fn payload_root(payload: &Value) -> Option<&Map<String, Value>> {
    payload.as_object()
}

fn normalize_attachment(value: &Value) -> Option<NormalizedWebhookAttachment> {
    let record = value.as_object()?;
    let guid = read_string(Some(record), &["guid", "attachmentGuid", "attachment_guid"])?;
    Some(NormalizedWebhookAttachment {
        guid,
        mime_type: read_string(Some(record), &["mimeType", "mime_type"]),
        uti: read_string(Some(record), &["uti"]),
        transfer_name: read_string(Some(record), &["transferName", "transfer_name", "filename"]),
        total_bytes: read_u64(Some(record), &["totalBytes", "total_bytes", "size"]),
    })
}

fn normalize_attachments(record: &Map<String, Value>) -> Vec<NormalizedWebhookAttachment> {
    record
        .get("attachments")
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(normalize_attachment).collect())
        .unwrap_or_default()
}

fn read_participant_string(record: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    read_string(Some(record), keys).or_else(|| {
        ["handle", "sender", "contact"]
            .into_iter()
            .find_map(|nested_key| read_string(read_record(Some(record), &[nested_key]), keys))
    })
}

fn read_participant_bool(record: &Map<String, Value>, keys: &[&str]) -> Option<bool> {
    read_bool(Some(record), keys).or_else(|| {
        ["handle", "sender", "contact"]
            .into_iter()
            .find_map(|nested_key| read_bool(read_record(Some(record), &[nested_key]), keys))
    })
}

fn normalize_webhook_participant(value: &Value) -> Option<BlueBubblesWebhookParticipant> {
    match value {
        Value::String(value) => {
            nonempty_string(value).map(|address| BlueBubblesWebhookParticipant {
                address,
                display_name: None,
                is_me: false,
                contact_name_enriched: false,
            })
        }
        Value::Number(value) => Some(BlueBubblesWebhookParticipant {
            address: value.to_string(),
            display_name: None,
            is_me: false,
            contact_name_enriched: false,
        }),
        Value::Object(record) => {
            let address = read_participant_string(
                record,
                &[
                    "address",
                    "handle",
                    "id",
                    "phoneNumber",
                    "phone_number",
                    "email",
                ],
            )?;
            let display_name = read_participant_string(
                record,
                &["displayName", "display_name", "name", "fullName", "title"],
            );
            let is_me = read_participant_bool(record, &["isMe", "is_me", "me"]).unwrap_or(false);

            Some(BlueBubblesWebhookParticipant {
                address,
                display_name,
                is_me,
                contact_name_enriched: false,
            })
        }
        _ => None,
    }
}

fn push_participants_from_record(
    participants: &mut Vec<BlueBubblesWebhookParticipant>,
    seen: &mut BTreeSet<String>,
    record: Option<&Map<String, Value>>,
) {
    let Some(record) = record else {
        return;
    };

    for key in ["participants", "handles", "participantHandles"] {
        let Some(values) = record.get(key).and_then(Value::as_array) else {
            continue;
        };
        for value in values {
            let Some(participant) = normalize_webhook_participant(value) else {
                continue;
            };
            let dedupe_key = participant.address.to_ascii_lowercase();
            if seen.insert(dedupe_key) {
                participants.push(participant);
            }
        }
    }
}

fn normalize_webhook_participants(
    record: &Map<String, Value>,
    chat_record: Option<&Map<String, Value>>,
    chat_from_list: Option<&Map<String, Value>>,
) -> Vec<BlueBubblesWebhookParticipant> {
    let mut participants = Vec::new();
    let mut seen = BTreeSet::new();
    push_participants_from_record(&mut participants, &mut seen, Some(record));
    push_participants_from_record(&mut participants, &mut seen, chat_record);
    push_participants_from_record(&mut participants, &mut seen, chat_from_list);
    participants
}

fn is_tapback_type(associated_type: Option<i32>) -> bool {
    associated_type.is_some_and(|value| (2000..4000).contains(&value))
}

fn webhook_topic(event_type: &str, is_from_me: bool, associated_type: Option<i32>) -> &'static str {
    if is_tapback_type(associated_type) {
        "imessage.message.tapback"
    } else if event_type == "updated-message" {
        "imessage.message.updated"
    } else if is_from_me {
        "imessage.message.outbound"
    } else {
        "imessage.message.inbound"
    }
}

/// Normalize a raw `BlueBubbles` webhook payload into FCP event-shaped data.
///
/// # Errors
///
/// Returns `InvalidRequest` when the payload lacks a message GUID or has an
/// invalid shape.
#[allow(clippy::too_many_lines)]
pub fn normalize_bluebubbles_webhook_payload(
    payload: &Value,
    event_type_override: Option<&str>,
) -> Result<NormalizedBlueBubblesWebhookMessage, FcpError> {
    let root = payload_root(payload);
    let record = payload_record(payload)?;
    let chat_record = read_record(Some(record), &["chat", "conversation"]);
    let chat_from_list = first_record_in_array(Some(record), &["chats"]);
    let handle_record = read_record(Some(record), &["handle", "sender"]);

    let event_type = event_type_override
        .and_then(nonempty_string)
        .or_else(|| read_string(root, &["type", "event"]))
        .unwrap_or_else(|| "message".to_string());

    let event_id = read_string(Some(record), &["guid", "messageGuid", "message_id", "id"])
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: "BlueBubbles webhook payload is missing a message GUID".into(),
        })?;

    if event_id.len() > MAX_WEBHOOK_GUID_CHARS {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: "BlueBubbles webhook message GUID is too long".into(),
        });
    }

    let associated_message_type = read_i64(
        Some(record),
        &["associatedMessageType", "associated_message_type"],
    )
    .and_then(|value| i32::try_from(value).ok());
    let is_from_me =
        read_bool(Some(record), &["isFromMe", "fromMe", "is_from_me"]).unwrap_or(false);
    let chat_guid = read_string(Some(record), &["chatGuid", "chat_guid"])
        .or_else(|| read_string(chat_record, &["chatGuid", "chat_guid", "guid"]))
        .or_else(|| read_string(chat_from_list, &["chatGuid", "chat_guid", "guid"]))
        .or_else(|| read_string(root, &["chatGuid", "chat_guid"]));
    let chat_identifier = read_string(Some(record), &["chatIdentifier", "chat_identifier"])
        .or_else(|| {
            read_string(
                chat_record,
                &["chatIdentifier", "chat_identifier", "identifier"],
            )
        })
        .or_else(|| {
            read_string(
                chat_from_list,
                &["chatIdentifier", "chat_identifier", "identifier"],
            )
        });
    let sender_id = read_string(handle_record, &["address", "handle", "id"])
        .or_else(|| read_string(Some(record), &["senderId", "sender", "from", "address"]));
    let sender_name = read_string(handle_record, &["displayName", "display_name", "name"])
        .or_else(|| read_string(Some(record), &["senderName", "sender_name"]));
    let text = read_string(Some(record), &["text", "message", "body"]);
    let associated_message_guid = read_string(
        Some(record),
        &[
            "associatedMessageGuid",
            "associated_message_guid",
            "associatedMessageId",
        ],
    );
    let reply_to_message_guid = read_string(
        Some(record),
        &[
            "threadOriginatorGuid",
            "replyToMessageGuid",
            "replyToGuid",
            "selectedMessageGuid",
        ],
    )
    .or_else(|| {
        if is_tapback_type(associated_message_type) {
            None
        } else {
            associated_message_guid.clone()
        }
    });
    let balloon_bundle_id = read_string(Some(record), &["balloonBundleId", "balloon_bundle_id"]);
    let source_message_ids = read_string_array(
        Some(record),
        &[
            "sourceMessageIds",
            "source_message_ids",
            "coalescedMessageIds",
            "coalesced_message_ids",
        ],
    );
    let date_created_ms = read_i64(
        Some(record),
        &[
            "dateCreated",
            "date_created",
            "dateCreatedMs",
            "date_created_ms",
            "timestamp",
        ],
    );
    let group_from_guid = chat_guid.as_deref().and_then(|guid| {
        if guid.contains(";+;") {
            Some(true)
        } else if guid.contains(";-;") {
            Some(false)
        } else {
            None
        }
    });
    let participants = normalize_webhook_participants(record, chat_record, chat_from_list);
    let is_group = group_from_guid
        .or_else(|| read_bool(Some(record), &["isGroup", "is_group", "group"]))
        .or_else(|| (participants.len() > 2).then_some(true))
        .unwrap_or(false);

    Ok(NormalizedBlueBubblesWebhookMessage {
        topic: webhook_topic(&event_type, is_from_me, associated_message_type).to_string(),
        event_type,
        event_id,
        chat_guid,
        chat_identifier,
        sender_id,
        sender_name,
        text,
        is_from_me,
        is_group,
        attachments: normalize_attachments(record),
        participants,
        reply_to_message_guid,
        reply_context: None,
        associated_message_guid,
        associated_message_type,
        balloon_bundle_id,
        is_tapback: is_tapback_type(associated_message_type),
        source_message_ids,
        date_created_ms,
        coalesced_source_count: None,
        coalescing_truncated_fields: Vec::new(),
    })
}

/// Build an account-scoped atomic dedupe key for a normalized webhook message.
#[must_use]
pub fn bluebubbles_webhook_dedupe_id(
    account_id: &str,
    message: &NormalizedBlueBubblesWebhookMessage,
) -> String {
    let account_id = normalized_webhook_account_id(account_id);
    let base = if message.balloon_bundle_id.is_some() {
        message
            .associated_message_guid
            .as_deref()
            .unwrap_or(message.event_id.as_str())
    } else {
        message.event_id.as_str()
    };
    let suffix = if message.event_type == "updated-message" {
        ":updated"
    } else {
        ""
    };
    format!("{account_id}:{base}{suffix}")
}

/// Build every account-scoped source ID that must be claimed for this event.
#[must_use]
pub fn bluebubbles_webhook_source_dedupe_ids(
    account_id: &str,
    message: &NormalizedBlueBubblesWebhookMessage,
) -> Vec<String> {
    let primary = bluebubbles_webhook_dedupe_id(account_id, message);
    let suffix = if message.event_type == "updated-message" {
        ":updated"
    } else {
        ""
    };
    let account_id = normalized_webhook_account_id(account_id);
    let mut ids = vec![primary];
    let mut add_id = |raw_id: &str| {
        let Some(raw_id) = nonempty_string(raw_id) else {
            return;
        };
        let dedupe_id = format!("{account_id}:{raw_id}{suffix}");
        if !ids.iter().any(|existing| existing == &dedupe_id) {
            ids.push(dedupe_id);
        }
    };
    add_id(&message.event_id);
    for source_id in &message.source_message_ids {
        add_id(source_id);
    }
    ids
}

fn normalized_webhook_account_id(account_id: &str) -> &str {
    let account_id = account_id.trim();
    if account_id.is_empty() {
        "default"
    } else {
        account_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults() {
        let config: BlueBubblesConfig = serde_json::from_str(r#"{"password":"test123"}"#).unwrap();
        assert_eq!(config.server_url, "http://localhost:1234");
        assert_eq!(config.poll_interval_ms, 5000);
        assert_eq!(config.request_timeout_ms, 30_000);
        assert_eq!(config.webhook_host, "127.0.0.1");
        assert_eq!(config.webhook_port, 8645);
        assert_eq!(config.webhook_path, "/bluebubbles-webhook");
        assert_eq!(config.webhook_account_id, "default");
        assert!(config.webhook_inbound.allow_from_me);
        assert!(config.webhook_inbound.allowed_sender_ids.is_empty());
        assert!(config.webhook_inbound.allowed_chat_guids.is_empty());
        assert!(!config.webhook_inbound.allow_group_chats);
        assert!(config.webhook_inbound.require_conversation_binding);
        assert!(config.webhook_inbound.dedupe_state_path.is_none());
        assert_eq!(config.webhook_inbound.dedupe_ttl_seconds, 604_800);
        assert!(!config.webhook_coalescing.enabled);
        assert_eq!(config.webhook_coalescing.debounce_ms, 2_500);
        assert_eq!(config.webhook_coalescing.max_debounce_ms, 2_500);
        assert!(
            config
                .webhook_coalescing
                .immediate_command_prefixes
                .is_empty()
        );
        assert_eq!(config.webhook_coalescing.max_text_chars, 4_000);
        assert_eq!(config.webhook_coalescing.max_attachments, 20);
        assert_eq!(config.webhook_coalescing.max_source_messages, 10);
        assert_eq!(config.webhook_coalescing.max_pending_buffers, 256);
        assert!(!config.reply_context_api_fallback.enabled);
        assert!(config.reply_context_api_fallback.overrides.is_empty());
        assert_eq!(config.reply_context_api_fallback.max_reply_id_chars, 512);
        assert_eq!(
            config.reply_context_api_fallback.max_response_bytes,
            256 * 1024
        );
        assert!(!config.contacts_enrichment.enabled);
        assert!(config.contacts_enrichment.overrides.is_empty());
        assert!(config.contacts_enrichment.database_paths.is_empty());
        assert!(config.contacts_enrichment.home_dir.is_none());
        assert!(config.contacts_enrichment.test_contacts.is_empty());
        assert_eq!(config.contacts_enrichment.positive_cache_ttl_seconds, 3600);
        assert_eq!(config.contacts_enrichment.negative_cache_ttl_seconds, 300);
        assert_eq!(config.contacts_enrichment.max_cache_entries, 2048);
        assert!(config.attachment_dir.is_none());
    }

    #[test]
    fn config_custom_values() {
        let config: BlueBubblesConfig = serde_json::from_str(
            r#"{"server_url":"http://myhost:5555","password":"abc","poll_interval_ms":1000}"#,
        )
        .unwrap();
        assert_eq!(config.server_url, "http://myhost:5555");
        assert_eq!(config.server_passcode, "abc");
        assert_eq!(config.poll_interval_ms, 1000);
    }

    #[test]
    fn config_from_value_trims_and_normalizes() {
        let config = BlueBubblesConfig::from_value(serde_json::json!({
            "server_url": " https://example.com/bridge/ ",
            "password": " secret ",
            "poll_interval_ms": 2500,
            "request_timeout_ms": 45000,
            "attachment_dir": "   "
        }))
        .unwrap();

        assert_eq!(config.server_url, "https://example.com/bridge");
        assert_eq!(config.server_passcode, "secret");
        assert_eq!(config.server_host().as_deref(), Some("example.com"));
        assert!(config.attachment_dir.is_none());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn config_from_value_normalizes_webhook_inbound_policy() {
        let config = BlueBubblesConfig::from_value(serde_json::json!({
            "password": "secret",
            "webhook_inbound": {
                "allowed_sender_ids": [" +15551234567 ", "", "+15551234567", "alice@example.com"],
                "allowed_chat_guids": [" iMessage;-;+15551234567 ", "iMessage;-;+15551234567"],
                "allow_group_chats": true,
                "require_conversation_binding": false,
                "dedupe_state_path": " /tmp/fcp-imessage-dedupe.json ",
                "dedupe_ttl_seconds": 42
            },
            "webhook_coalescing": {
                "enabled": true,
                "debounce_ms": 500,
                "max_debounce_ms": 2500,
                "immediate_command_prefixes": [" / ", "", " / ", "!"],
                "max_text_chars": 123,
                "max_attachments": 4,
                "max_source_messages": 3,
                "max_pending_buffers": 8
            },
            "reply_context_api_fallback": {
                "enabled": false,
                "max_reply_id_chars": 128,
                "max_response_bytes": 4096,
                "overrides": [
                    { "account_id": " acct-a ", "enabled": false },
                    { "chat_guid": " iMessage;-;+15551234567 ", "enabled": true },
                    { "account_id": " ", "chat_guid": " ", "enabled": true }
                ]
            },
            "contacts_enrichment": {
                "enabled": false,
                "database_paths": [" /tmp/addressbook-1.abcddb ", "", "/tmp/addressbook-1.abcddb"],
                "home_dir": " /Users/example ",
                "test_contacts": {
                    "+1 (555) 123-4567": " Alice Example ",
                    "not-a-phone": "Ignored",
                    "+15557654321": " "
                },
                "positive_cache_ttl_seconds": 60,
                "negative_cache_ttl_seconds": 30,
                "max_cache_entries": 8,
                "overrides": [
                    { "account_id": " acct-a ", "enabled": false },
                    { "chat_guid": " iMessage;+;family ", "enabled": true },
                    { "account_id": " ", "chat_guid": " ", "enabled": true }
                ]
            }
        }))
        .unwrap();

        assert_eq!(
            config.webhook_inbound.allowed_sender_ids,
            vec!["+15551234567", "alice@example.com"]
        );
        assert_eq!(
            config.webhook_inbound.allowed_chat_guids,
            vec!["iMessage;-;+15551234567"]
        );
        assert!(config.webhook_inbound.allow_group_chats);
        assert!(!config.webhook_inbound.require_conversation_binding);
        assert_eq!(
            config.webhook_inbound.dedupe_state_path.as_deref(),
            Some("/tmp/fcp-imessage-dedupe.json")
        );
        assert_eq!(config.webhook_inbound.dedupe_ttl_seconds, 42);
        assert!(config.webhook_coalescing.enabled);
        assert_eq!(config.webhook_coalescing.debounce_ms, 500);
        assert_eq!(config.webhook_coalescing.max_debounce_ms, 2500);
        assert_eq!(
            config.webhook_coalescing.immediate_command_prefixes,
            vec!["!", "/"]
        );
        assert_eq!(config.webhook_coalescing.max_text_chars, 123);
        assert_eq!(config.webhook_coalescing.max_attachments, 4);
        assert_eq!(config.webhook_coalescing.max_source_messages, 3);
        assert_eq!(config.webhook_coalescing.max_pending_buffers, 8);
        assert!(!config.reply_context_api_fallback.enabled);
        assert_eq!(config.reply_context_api_fallback.max_reply_id_chars, 128);
        assert_eq!(config.reply_context_api_fallback.max_response_bytes, 4096);
        assert_eq!(config.reply_context_api_fallback.overrides.len(), 2);
        assert!(!config.reply_context_api_fallback.enabled_for("acct-a", &[]));
        assert!(
            config
                .reply_context_api_fallback
                .enabled_for("acct-a", &["iMessage;-;+15551234567".to_string()])
        );
        assert!(!config.contacts_enrichment.enabled);
        assert_eq!(
            config.contacts_enrichment.database_paths,
            vec!["/tmp/addressbook-1.abcddb"]
        );
        assert_eq!(
            config.contacts_enrichment.home_dir.as_deref(),
            Some("/Users/example")
        );
        assert_eq!(
            config
                .contacts_enrichment
                .test_contacts
                .get("5551234567")
                .map(String::as_str),
            Some("Alice Example")
        );
        assert_eq!(config.contacts_enrichment.test_contacts.len(), 1);
        assert_eq!(config.contacts_enrichment.positive_cache_ttl_seconds, 60);
        assert_eq!(config.contacts_enrichment.negative_cache_ttl_seconds, 30);
        assert_eq!(config.contacts_enrichment.max_cache_entries, 8);
        assert_eq!(config.contacts_enrichment.overrides.len(), 2);
        assert!(!config.contacts_enrichment.enabled_for("acct-a", &[]));
        assert!(
            config
                .contacts_enrichment
                .enabled_for("acct-a", &["iMessage;+;family".to_string()])
        );
    }

    #[test]
    fn config_accepts_legacy_contacts_enrichment_boolean_alias() {
        let config = BlueBubblesConfig::from_value(serde_json::json!({
            "password": "secret",
            "enrichGroupParticipantsFromContacts": true
        }))
        .unwrap();

        assert!(config.contacts_enrichment.enabled);
    }

    #[test]
    fn contact_phone_lookup_key_matches_bluebubbles_contacts_rules() {
        assert_eq!(
            normalize_bluebubbles_contact_phone_key("+1 (555) 123-4567").as_deref(),
            Some("5551234567")
        );
        assert_eq!(
            normalize_bluebubbles_contact_phone_key("555.123.4567").as_deref(),
            Some("5551234567")
        );
        assert!(normalize_bluebubbles_contact_phone_key("abc@example.com").is_none());
        assert!(normalize_bluebubbles_contact_phone_key("123456").is_none());
    }

    #[test]
    fn config_from_value_rejects_blank_password() {
        let result = BlueBubblesConfig::from_value(serde_json::json!({
            "password": "   "
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_from_value_rejects_zero_poll_interval() {
        let result = BlueBubblesConfig::from_value(serde_json::json!({
            "password": "secret",
            "poll_interval_ms": 0
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_from_value_rejects_zero_request_timeout() {
        let result = BlueBubblesConfig::from_value(serde_json::json!({
            "password": "secret",
            "request_timeout_ms": 0
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_from_value_rejects_invalid_server_url() {
        let result = BlueBubblesConfig::from_value(serde_json::json!({
            "server_url": "not-a-url",
            "password": "secret"
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_from_value_rejects_invalid_webhook_callback_config() {
        let cases = [
            serde_json::json!({
                "password": "secret",
                "webhook_host": "   "
            }),
            serde_json::json!({
                "password": "secret",
                "webhook_port": 0
            }),
            serde_json::json!({
                "password": "secret",
                "webhook_path": "/"
            }),
            serde_json::json!({
                "password": "secret",
                "webhook_account_id": "   "
            }),
            serde_json::json!({
                "password": "secret",
                "webhook_inbound": { "dedupe_ttl_seconds": 0 }
            }),
            serde_json::json!({
                "password": "secret",
                "webhook_coalescing": { "debounce_ms": 0 }
            }),
            serde_json::json!({
                "password": "secret",
                "webhook_coalescing": { "debounce_ms": 2501, "max_debounce_ms": 2500 }
            }),
            serde_json::json!({
                "password": "secret",
                "webhook_coalescing": { "max_text_chars": 0 }
            }),
            serde_json::json!({
                "password": "secret",
                "webhook_coalescing": { "max_attachments": 0 }
            }),
            serde_json::json!({
                "password": "secret",
                "webhook_coalescing": { "max_source_messages": 0 }
            }),
            serde_json::json!({
                "password": "secret",
                "webhook_coalescing": { "max_pending_buffers": 0 }
            }),
            serde_json::json!({
                "password": "secret",
                "reply_context_api_fallback": { "max_reply_id_chars": 0 }
            }),
            serde_json::json!({
                "password": "secret",
                "reply_context_api_fallback": { "max_reply_id_chars": 513 }
            }),
            serde_json::json!({
                "password": "secret",
                "reply_context_api_fallback": { "max_response_bytes": 0 }
            }),
            serde_json::json!({
                "password": "secret",
                "contacts_enrichment": { "positive_cache_ttl_seconds": 0 }
            }),
            serde_json::json!({
                "password": "secret",
                "contacts_enrichment": { "negative_cache_ttl_seconds": 0 }
            }),
            serde_json::json!({
                "password": "secret",
                "contacts_enrichment": { "max_cache_entries": 0 }
            }),
        ];

        for case in cases {
            assert!(BlueBubblesConfig::from_value(case).is_err());
        }
    }

    #[test]
    fn chat_deserialize() {
        let json = serde_json::json!({
            "guid": "iMessage;-;+15551234567",
            "display_name": "John",
            "participants": [],
            "is_group": false
        });
        let chat: Chat = serde_json::from_value(json).unwrap();
        assert_eq!(chat.guid, "iMessage;-;+15551234567");
        assert_eq!(chat.display_name.as_deref(), Some("John"));
        assert!(!chat.is_group);
    }

    #[test]
    fn chat_group_deserialize() {
        let json = serde_json::json!({
            "guid": "iMessage;+;chat123",
            "display_name": "Family Chat",
            "participants": [
                { "address": "+15551111111", "display_name": "Mom", "is_me": false },
                { "address": "+15552222222", "is_me": true }
            ],
            "is_group": true,
            "group_id": "chat123"
        });
        let chat: Chat = serde_json::from_value(json).unwrap();
        assert!(chat.is_group);
        assert_eq!(chat.participants.len(), 2);
        assert!(chat.participants[1].is_me);
    }

    #[test]
    fn message_deserialize() {
        let json = serde_json::json!({
            "guid": "msg-001",
            "text": "Hello!",
            "date_created": 1_700_000_000_000_i64,
            "is_from_me": false,
            "handle": {
                "address": "+15551234567",
                "display_name": "Alice"
            },
            "attachments": []
        });
        let msg: Message = serde_json::from_value(json).unwrap();
        assert_eq!(msg.guid, "msg-001");
        assert_eq!(msg.text.as_deref(), Some("Hello!"));
        assert!(!msg.is_from_me);
        assert_eq!(msg.handle.as_ref().unwrap().address, "+15551234567");
    }

    #[test]
    fn message_with_attachment() {
        let json = serde_json::json!({
            "guid": "msg-002",
            "text": null,
            "is_from_me": true,
            "attachments": [
                {
                    "guid": "att-001",
                    "mime_type": "image/png",
                    "filename": "photo.png",
                    "total_bytes": 12345,
                    "transfer_name": "photo.png"
                }
            ]
        });
        let msg: Message = serde_json::from_value(json).unwrap();
        assert_eq!(msg.attachments.len(), 1);
        assert_eq!(msg.attachments[0].mime_type.as_deref(), Some("image/png"));
        assert_eq!(msg.attachments[0].total_bytes, Some(12345));
    }

    #[test]
    fn send_message_request_serialize() {
        let req = SendMessageRequest {
            chat_guid: "iMessage;-;+15551234567".to_string(),
            message: "Hello!".to_string(),
            temp_guid: Some("tmp-001".to_string()),
            method: "apple-script".to_string(),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["chatGuid"], "iMessage;-;+15551234567");
        assert_eq!(json["message"], "Hello!");
        assert_eq!(json["tempGuid"], "tmp-001");
        assert_eq!(json["method"], SEND_METHOD_APPLE_SCRIPT);
    }

    #[test]
    fn send_message_response_deserialize() {
        let json = serde_json::json!({
            "status": 200,
            "message": "Message sent!",
            "data": {
                "guid": "msg-003",
                "text": "Hello!",
                "is_from_me": true,
                "attachments": []
            }
        });
        let resp: SendMessageResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.status, 200);
        assert!(resp.data.is_some());
        assert_eq!(resp.data.unwrap().guid, "msg-003");
    }

    #[test]
    fn server_info_deserialize() {
        let json = serde_json::json!({
            "os_version": "14.2",
            "server_version": "1.9.0",
            "private_api": true,
            "proxy_service": "cloudflare"
        });
        let info: ServerInfo = serde_json::from_value(json).unwrap();
        assert_eq!(info.os_version.as_deref(), Some("14.2"));
        assert!(info.private_api);
        assert_eq!(info.proxy_service.as_deref(), Some("cloudflare"));
    }

    #[test]
    fn paginated_response_deserialize() {
        let json = serde_json::json!({
            "total": 100,
            "offset": 0,
            "limit": 25,
            "data": [
                {
                    "guid": "iMessage;-;+15551234567",
                    "is_group": false,
                    "participants": []
                }
            ]
        });
        let resp: PaginatedResponse<Chat> = serde_json::from_value(json).unwrap();
        assert_eq!(resp.total, Some(100));
        assert_eq!(resp.limit, 25);
        assert_eq!(resp.data.len(), 1);
    }

    #[test]
    fn query_params_default() {
        let params = QueryParams::default();
        assert!(params.offset.is_none());
        assert!(params.limit.is_none());
        assert!(params.after.is_none());
        assert!(params.with.is_empty());
    }

    #[test]
    fn api_error_response_deserialize() {
        let json = serde_json::json!({
            "error": "Not Found",
            "status": 404,
            "message": "Chat not found"
        });
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.error.as_deref(), Some("Not Found"));
        assert_eq!(err.status, Some(404));
    }

    #[test]
    fn webhook_registration_url_normalizes_localhost_and_encodes_password() {
        let config = BlueBubblesConfig::from_value(serde_json::json!({
            "password": "W9fTC&L5JL*@",
            "webhook_host": "0.0.0.0",
            "webhook_port": 9999,
            "webhook_path": "custom-hook",
            "webhook_account_id": "personal"
        }))
        .unwrap();

        assert_eq!(config.webhook_path, "/custom-hook");
        let url = config.webhook_registration_url().unwrap();
        assert!(url.starts_with("http://localhost:9999/custom-hook?"));
        assert!(url.contains("%26"));
        assert!(url.contains("%40"));
        let parsed = reqwest::Url::parse(&url).unwrap();
        assert!(
            parsed
                .query_pairs()
                .any(|(key, value)| { key == "password" && value == "W9fTC&L5JL*@" })
        );
    }

    #[test]
    fn webhook_registration_deserializes_numeric_ids() {
        let registration: WebhookRegistration = serde_json::from_value(serde_json::json!({
            "id": 42,
            "url": "http://localhost:8645/bluebubbles-webhook",
            "events": ["new-message"]
        }))
        .unwrap();

        assert_eq!(registration.id.as_deref(), Some("42"));
        assert_eq!(registration.events, vec!["new-message"]);
    }

    #[test]
    fn normalize_webhook_payload_extracts_nested_chat_and_attachments() {
        let payload = serde_json::json!({
            "type": "new-message",
            "data": {
                "guid": "msg-001",
                "text": "hello",
                "isFromMe": false,
                "handle": { "address": "+15551234567", "displayName": "Alice" },
                "dateCreated": 1_700_000_000_123_i64,
                "chats": [{
                    "guid": "iMessage;+;chat123",
                    "chatIdentifier": "Family",
                    "participants": [
                        { "address": "+1 (555) 123-4567" },
                        { "address": "self@example.com", "displayName": "Me", "isMe": true },
                        { "address": "+15557654321", "displayName": "Bob" }
                    ]
                }],
                "attachments": [{
                    "guid": "att-1",
                    "mimeType": "image/png",
                    "uti": "public.png",
                    "transferName": "photo.png",
                    "totalBytes": 123
                }],
                "threadOriginatorGuid": "root-1",
                "associatedMessageGuid": "assoc-1",
                "associatedMessageType": 0,
                "balloonBundleId": "com.example.MessagesPlugin",
                "coalescedMessageIds": ["msg-002", "msg-003", "msg-002"]
            }
        });

        let normalized = normalize_bluebubbles_webhook_payload(&payload, None).unwrap();
        assert_eq!(normalized.event_type, "new-message");
        assert_eq!(normalized.event_id, "msg-001");
        assert_eq!(normalized.topic, "imessage.message.inbound");
        assert_eq!(normalized.chat_guid.as_deref(), Some("iMessage;+;chat123"));
        assert_eq!(normalized.chat_identifier.as_deref(), Some("Family"));
        assert_eq!(normalized.sender_id.as_deref(), Some("+15551234567"));
        assert_eq!(normalized.sender_name.as_deref(), Some("Alice"));
        assert_eq!(normalized.text.as_deref(), Some("hello"));
        assert_eq!(normalized.date_created_ms, Some(1_700_000_000_123_i64));
        assert!(!normalized.is_from_me);
        assert!(normalized.is_group);
        assert_eq!(normalized.attachments.len(), 1);
        assert_eq!(normalized.attachments[0].guid, "att-1");
        assert_eq!(
            normalized.attachments[0].mime_type.as_deref(),
            Some("image/png")
        );
        assert_eq!(normalized.attachments[0].uti.as_deref(), Some("public.png"));
        assert_eq!(
            normalized.attachments[0].transfer_name.as_deref(),
            Some("photo.png")
        );
        assert_eq!(normalized.attachments[0].total_bytes, Some(123));
        assert_eq!(normalized.participants.len(), 3);
        assert_eq!(normalized.participants[0].address, "+1 (555) 123-4567");
        assert!(normalized.participants[1].is_me);
        assert_eq!(
            normalized.participants[2].display_name.as_deref(),
            Some("Bob")
        );
        assert_eq!(normalized.reply_to_message_guid.as_deref(), Some("root-1"));
        assert_eq!(
            normalized.associated_message_guid.as_deref(),
            Some("assoc-1")
        );
        assert_eq!(normalized.associated_message_type, Some(0));
        assert_eq!(
            normalized.balloon_bundle_id.as_deref(),
            Some("com.example.MessagesPlugin")
        );
        assert!(!normalized.is_tapback);
        assert_eq!(normalized.source_message_ids, vec!["msg-002", "msg-003"]);
    }

    #[test]
    fn normalize_webhook_payload_extracts_participants_and_infers_group() {
        let payload = serde_json::json!({
            "type": "new-message",
            "data": {
                "guid": "participant-msg",
                "handle": { "address": "+15551234567" },
                "participants": [
                    "+15551234567",
                    { "phoneNumber": "+1 (555) 765-4321", "displayName": "Alice" },
                    { "email": "me@example.com", "isMe": true },
                    { "handle": { "address": "+15551234567" } }
                ],
                "isFromMe": false
            }
        });

        let normalized = normalize_bluebubbles_webhook_payload(&payload, None).unwrap();
        assert!(normalized.is_group);
        assert_eq!(normalized.participants.len(), 3);
        assert_eq!(normalized.participants[0].address, "+15551234567");
        assert_eq!(
            normalized.participants[1].display_name.as_deref(),
            Some("Alice")
        );
        assert!(normalized.participants[2].is_me);
    }

    #[test]
    fn normalize_webhook_payload_rejects_malformed_and_accepts_data_arrays() {
        let malformed = serde_json::json!({
            "type": "new-message",
            "data": { "text": "missing guid" }
        });
        assert!(normalize_bluebubbles_webhook_payload(&malformed, None).is_err());

        let payload = serde_json::json!({
            "type": "new-message",
            "data": [{
                "guid": "array-msg",
                "chat": {
                    "guid": "iMessage;-;+15551234567",
                    "identifier": "+15551234567"
                },
                "sender": {
                    "id": "+15551234567",
                    "name": "Alice"
                },
                "fromMe": true
            }]
        });
        let normalized = normalize_bluebubbles_webhook_payload(&payload, None).unwrap();
        assert_eq!(normalized.event_id, "array-msg");
        assert_eq!(
            normalized.chat_guid.as_deref(),
            Some("iMessage;-;+15551234567")
        );
        assert_eq!(normalized.chat_identifier.as_deref(), Some("+15551234567"));
        assert_eq!(normalized.sender_id.as_deref(), Some("+15551234567"));
        assert_eq!(normalized.sender_name.as_deref(), Some("Alice"));
        assert!(normalized.is_from_me);
        assert_eq!(normalized.topic, "imessage.message.outbound");
    }

    #[test]
    fn normalize_webhook_payload_marks_tapbacks_and_updated_dedupe() {
        let payload = serde_json::json!({
            "event": "updated-message",
            "message": {
                "guid": "balloon-1",
                "text": "Loved \"hello\"",
                "associatedMessageGuid": "msg-root",
                "associatedMessageType": 2000,
                "balloonBundleId": "com.apple.messages.URLBalloonProvider",
                "isFromMe": false
            }
        });

        let normalized = normalize_bluebubbles_webhook_payload(&payload, None).unwrap();
        assert!(normalized.is_tapback);
        assert_eq!(normalized.topic, "imessage.message.tapback");
        assert_eq!(
            bluebubbles_webhook_dedupe_id("acct-a", &normalized),
            "acct-a:msg-root:updated"
        );
        assert_eq!(
            bluebubbles_webhook_source_dedupe_ids("acct-a", &normalized),
            vec!["acct-a:msg-root:updated", "acct-a:balloon-1:updated"]
        );
    }

    #[test]
    fn webhook_inbound_policy_requires_sender_and_conversation_for_external_dm() {
        let payload = serde_json::json!({
            "type": "new-message",
            "data": {
                "guid": "msg-1",
                "handle": { "address": "+15551234567" },
                "chats": [{ "guid": "iMessage;-;+15551234567" }],
                "isFromMe": false
            }
        });
        let event = normalize_bluebubbles_webhook_payload(&payload, None).unwrap();
        let default_policy = BlueBubblesWebhookInboundConfig::default();

        assert_eq!(
            default_policy.evaluate(&event),
            BlueBubblesInboundDecision::rejected("conversation_not_bound")
        );

        let policy = BlueBubblesWebhookInboundConfig {
            allowed_sender_ids: vec!["+15551234567".to_string()],
            allowed_chat_guids: vec!["iMessage;-;+15551234567".to_string()],
            ..BlueBubblesWebhookInboundConfig::default()
        }
        .validate()
        .unwrap();

        assert_eq!(
            policy.evaluate(&event),
            BlueBubblesInboundDecision::accepted("sender_allowed")
        );
    }

    #[test]
    fn webhook_inbound_policy_keeps_groups_conservative() {
        let payload = serde_json::json!({
            "type": "new-message",
            "data": {
                "guid": "group-msg-1",
                "handle": { "address": "+15551234567" },
                "chats": [{ "guid": "iMessage;+;group-chat" }],
                "isFromMe": false
            }
        });
        let event = normalize_bluebubbles_webhook_payload(&payload, None).unwrap();
        let bound_but_dm_only = BlueBubblesWebhookInboundConfig {
            allowed_chat_guids: vec!["iMessage;+;group-chat".to_string()],
            ..BlueBubblesWebhookInboundConfig::default()
        };

        assert_eq!(
            bound_but_dm_only.evaluate(&event),
            BlueBubblesInboundDecision::rejected("group_not_allowed")
        );

        let group_policy = BlueBubblesWebhookInboundConfig {
            allowed_chat_guids: vec!["iMessage;+;group-chat".to_string()],
            allow_group_chats: true,
            ..BlueBubblesWebhookInboundConfig::default()
        };

        assert_eq!(
            group_policy.evaluate(&event),
            BlueBubblesInboundDecision::accepted("group_conversation_bound")
        );
    }
}
