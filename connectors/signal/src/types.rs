//! Signal messenger API types for the signal-cli REST daemon.
//!
//! Covers daemon-mode message structures, request/response payloads, and
//! connector configuration.

use fcp_sdk::prelude::{FcpError, FcpResult};
use reqwest::Url;
use serde::{Deserialize, Deserializer, Serialize, de::Error as DeError};

const SSE_FIELD_EVENT: &str = "event";
const SSE_FIELD_ID: &str = "id";
const SSE_FIELD_DATA: &str = "data";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Signal connector configuration.
#[derive(Clone, Deserialize)]
pub struct SignalConfig {
    /// Base URL for the signal-cli REST daemon.
    #[serde(default = "default_daemon_url")]
    pub daemon_url: String,

    /// Registered phone number in E.164 format (e.g. +15551234567).
    pub phone_number: String,

    /// Trust mode for identity keys.
    #[serde(default = "default_trust_mode")]
    pub trust_mode: TrustMode,

    /// Optional signal-cli data directory hint for operators.
    #[serde(default)]
    pub data_dir: Option<String>,

    /// Receive polling timeout in milliseconds.
    #[serde(default = "default_receive_timeout_ms")]
    pub receive_timeout_ms: u64,

    /// Receive-loop polling cadence in milliseconds.
    #[serde(default = "default_poll_interval_ms")]
    pub poll_interval_ms: u64,

    /// Maximum reconnection backoff in milliseconds after daemon failures.
    #[serde(default = "default_max_reconnect_delay_ms")]
    pub max_reconnect_delay_ms: u64,

    /// Background health-check cadence in milliseconds while connected.
    #[serde(default = "default_health_check_interval_ms")]
    pub health_check_interval_ms: u64,

    /// Directory for storing downloaded attachments.
    #[serde(default)]
    pub attachment_dir: Option<String>,

    /// Maximum attachment size accepted by the bridge in bytes.
    #[serde(default = "default_max_attachment_bytes")]
    pub max_attachment_bytes: u64,

    /// HTTP retry configuration.
    #[serde(default)]
    pub retry: fcp_sdk::migration::HttpRetryConfig,

    /// Request timeout in milliseconds.
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,

    /// signal-cli SSE streaming behavior.
    #[serde(default)]
    pub streaming: SignalStreamingConfig,

    /// Connector-owned inbound authorization policy applied before events are emitted.
    #[serde(default)]
    pub inbound_policy: SignalInboundPolicy,
}

impl std::fmt::Debug for SignalConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redacted_phone = if self.phone_number.len() >= 4 {
            format!("****{}", &self.phone_number[self.phone_number.len() - 4..])
        } else {
            "****".to_string()
        };
        f.debug_struct("SignalConfig")
            .field("daemon_url", &self.daemon_url)
            .field("phone_number", &redacted_phone)
            .field("trust_mode", &self.trust_mode)
            .field("data_dir", &self.data_dir)
            .field("receive_timeout_ms", &self.receive_timeout_ms)
            .field("poll_interval_ms", &self.poll_interval_ms)
            .field("max_reconnect_delay_ms", &self.max_reconnect_delay_ms)
            .field("health_check_interval_ms", &self.health_check_interval_ms)
            .field("attachment_dir", &self.attachment_dir)
            .field("max_attachment_bytes", &self.max_attachment_bytes)
            .field("retry", &self.retry)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .field("streaming", &self.streaming)
            .field("inbound_policy", &self.inbound_policy)
            .finish()
    }
}

/// Trust mode for Signal identity keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustMode {
    /// Only trust identities that are explicitly verified.
    OnFirstUse,
    /// Trust all identities automatically.
    Always,
    /// Never trust unverified identities.
    Never,
}

/// signal-cli SSE streaming behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SignalStreamingConfig {
    /// Whether `subscribe` may enable the signal-cli `/api/v1/events` SSE path.
    pub enabled: bool,

    /// Milliseconds without SSE activity before health monitoring treats the stream as stale.
    pub stale_after_ms: u64,

    /// Minimum supervised reconnect delay.
    pub reconnect_initial_ms: u64,

    /// Maximum supervised reconnect delay.
    pub reconnect_max_ms: u64,

    /// Minimum event buffer advertised in handshake and introspection.
    pub min_buffer_events: u32,
}

impl Default for SignalStreamingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            stale_after_ms: 120_000,
            reconnect_initial_ms: 1_000,
            reconnect_max_ms: 60_000,
            min_buffer_events: 100,
        }
    }
}

impl SignalStreamingConfig {
    /// Validate streaming configuration invariants.
    ///
    /// # Errors
    ///
    /// Returns `FcpError::InvalidRequest` when any enabled streaming interval or
    /// buffer size is zero.
    pub fn validate(&self) -> FcpResult<()> {
        if !self.enabled {
            return Ok(());
        }
        if self.stale_after_ms == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "streaming.stale_after_ms must be greater than zero".into(),
            });
        }
        if self.reconnect_initial_ms == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "streaming.reconnect_initial_ms must be greater than zero".into(),
            });
        }
        if self.reconnect_max_ms < self.reconnect_initial_ms {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "streaming.reconnect_max_ms must be >= reconnect_initial_ms".into(),
            });
        }
        if self.min_buffer_events == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "streaming.min_buffer_events must be greater than zero".into(),
            });
        }
        Ok(())
    }
}

/// Direct-message authorization mode for inbound Signal events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalDmPolicy {
    /// Allow any direct sender.
    Open,
    /// Allow only senders listed in `allow_from`.
    Allowlist,
    /// Do not emit the event; caller should initiate a pairing challenge.
    Pairing,
    /// Drop all direct-message events.
    Disabled,
}

/// Group authorization mode for inbound Signal events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalGroupPolicy {
    /// Allow any group.
    Open,
    /// Allow only groups or senders listed in `group_allow_from`.
    Allowlist,
    /// Drop all group events.
    Disabled,
}

/// Quote-context visibility for group events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalQuoteContextVisibility {
    /// Include quote context after the inbound event itself is authorized.
    All,
    /// Include group quote context only when the quoted author is allowlisted.
    AllowedOnly,
    /// Never include quote text or quote author context.
    None,
}

/// Connector-owned inbound authorization policy for Signal events.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SignalInboundPolicy {
    /// Direct-message access mode.
    pub dm_policy: SignalDmPolicy,

    /// Direct-message sender allowlist. Entries use strict canonical equality;
    /// `*` opens the list explicitly.
    pub allow_from: Vec<String>,

    /// Group access mode. Defaults to allowlist, which denies groups unless a
    /// group ID is explicitly configured.
    pub group_policy: SignalGroupPolicy,

    /// Group or group-sender allowlist. Accepts raw group IDs, `group:<id>`,
    /// `signal:group:<id>`, raw sender IDs, and `signal:<sender>`.
    pub group_allow_from: Vec<String>,

    /// Require a configured mention pattern or account mention in group text.
    pub require_group_mention: bool,

    /// Plain substring mention patterns used when Signal mention metadata does
    /// not reference the configured account directly.
    pub mention_patterns: Vec<String>,

    /// Whether quote context is exposed after the event is authorized.
    pub quote_context_visibility: SignalQuoteContextVisibility,

    /// Drop events from the configured account to prevent echo loops.
    pub suppress_self_echo: bool,

    /// Emit authorized reaction-only events.
    pub emit_reactions: bool,

    /// Emit receipt events when signal-cli surfaces them.
    pub emit_read_receipts: bool,

    /// Emit typing events when signal-cli surfaces them.
    pub emit_typing: bool,
}

impl Default for SignalInboundPolicy {
    fn default() -> Self {
        Self {
            dm_policy: SignalDmPolicy::Open,
            allow_from: Vec::new(),
            group_policy: SignalGroupPolicy::Allowlist,
            group_allow_from: Vec::new(),
            require_group_mention: false,
            mention_patterns: Vec::new(),
            quote_context_visibility: SignalQuoteContextVisibility::AllowedOnly,
            suppress_self_echo: true,
            emit_reactions: true,
            emit_read_receipts: true,
            emit_typing: true,
        }
    }
}

impl SignalInboundPolicy {
    /// Validate inbound policy configuration.
    ///
    /// # Errors
    ///
    /// Returns `FcpError::InvalidRequest` when a configured allowlist or mention
    /// pattern contains a blank entry.
    pub fn validate(&self) -> FcpResult<()> {
        if self.allow_from.iter().any(|value| value.trim().is_empty()) {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "inbound_policy.allow_from must not contain empty entries".into(),
            });
        }
        if self
            .group_allow_from
            .iter()
            .any(|value| value.trim().is_empty())
        {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "inbound_policy.group_allow_from must not contain empty entries".into(),
            });
        }
        if self
            .mention_patterns
            .iter()
            .any(|value| value.trim().is_empty())
        {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "inbound_policy.mention_patterns must not contain empty entries".into(),
            });
        }
        Ok(())
    }

    /// Apply inbound policy to a Signal envelope and return the event to emit
    /// or the structured reason for dropping it.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn evaluate_envelope(
        &self,
        envelope: &SignalEnvelope,
        account: &str,
    ) -> SignalInboundPolicyOutcome {
        let Some(sender) = envelope.sender_identifier() else {
            return SignalInboundPolicyOutcome::Drop(SignalInboundDrop::new(
                SignalInboundDropReason::NoSender,
                None,
                None,
                None,
            ));
        };

        if self.suppress_self_echo && identifiers_match(sender, account) {
            return SignalInboundPolicyOutcome::Drop(SignalInboundDrop::new(
                SignalInboundDropReason::SelfEcho,
                Some(sender),
                None,
                None,
            ));
        }

        if envelope.sync_message.is_some() {
            return SignalInboundPolicyOutcome::Drop(SignalInboundDrop::new(
                SignalInboundDropReason::SyncMessage,
                Some(sender),
                None,
                None,
            ));
        }

        let data_message = envelope.primary_data_message();
        let reaction = envelope
            .reaction_message
            .as_ref()
            .or_else(|| data_message.and_then(|message| message.reaction.as_ref()));
        let group = data_message
            .and_then(|message| message.group_info.as_ref())
            .or_else(|| reaction.and_then(|message| message.group_info.as_ref()));
        let group_id = group.map(|info| info.id.as_str());
        let is_group = group_id.is_some();

        if let Some(reason) = self.access_denial_reason(sender, group_id, is_group) {
            return SignalInboundPolicyOutcome::Drop(SignalInboundDrop::new(
                reason,
                Some(sender),
                group_id,
                classify_envelope_kind(envelope),
            ));
        }

        if let Some(receipt) = envelope.receipt_message.as_ref() {
            if !self.emit_read_receipts {
                return SignalInboundPolicyOutcome::Drop(SignalInboundDrop::new(
                    SignalInboundDropReason::EventKindDisabled,
                    Some(sender),
                    group_id,
                    Some(SignalInboundEventKind::ReadReceipt),
                ));
            }
            return SignalInboundPolicyOutcome::Emit(Box::new(SignalInboundEvent::from_receipt(
                envelope,
                sender,
                group,
                receipt.clone(),
            )));
        }

        if let Some(typing) = envelope.typing_message.as_ref() {
            if !self.emit_typing {
                return SignalInboundPolicyOutcome::Drop(SignalInboundDrop::new(
                    SignalInboundDropReason::EventKindDisabled,
                    Some(sender),
                    group_id,
                    Some(SignalInboundEventKind::Typing),
                ));
            }
            return SignalInboundPolicyOutcome::Emit(Box::new(SignalInboundEvent::from_typing(
                envelope,
                sender,
                group,
                typing.clone(),
            )));
        }

        let visible_quote = data_message.and_then(|message| self.visible_quote(message, is_group));
        let has_body_content = data_message.is_some_and(|message| {
            message
                .message
                .as_deref()
                .is_some_and(|text| !text.trim().is_empty())
                || !message.attachments.is_empty()
                || visible_quote
                    .as_ref()
                    .is_some_and(|quote| !quote.text.trim().is_empty())
        });

        if let Some(reaction) = reaction {
            if !has_body_content {
                if !self.emit_reactions {
                    return SignalInboundPolicyOutcome::Drop(SignalInboundDrop::new(
                        SignalInboundDropReason::EventKindDisabled,
                        Some(sender),
                        group_id,
                        Some(SignalInboundEventKind::Reaction),
                    ));
                }
                return SignalInboundPolicyOutcome::Emit(Box::new(
                    SignalInboundEvent::from_reaction(envelope, sender, group, reaction.clone()),
                ));
            }
        }

        let Some(data_message) = data_message else {
            return SignalInboundPolicyOutcome::Drop(SignalInboundDrop::new(
                SignalInboundDropReason::NoContent,
                Some(sender),
                group_id,
                classify_envelope_kind(envelope),
            ));
        };

        if is_group
            && self.require_group_mention
            && !self.group_message_mentions_account(data_message, account)
        {
            return SignalInboundPolicyOutcome::Drop(SignalInboundDrop::new(
                SignalInboundDropReason::GroupMentionRequired,
                Some(sender),
                group_id,
                Some(SignalInboundEventKind::Message),
            ));
        }

        let rendered_body = data_message
            .message
            .as_deref()
            .map(|message| render_signal_mentions(message, &data_message.mentions));
        let body_has_text = rendered_body
            .as_deref()
            .is_some_and(|message| !message.trim().is_empty());
        if !body_has_text && data_message.attachments.is_empty() && visible_quote.is_none() {
            return SignalInboundPolicyOutcome::Drop(SignalInboundDrop::new(
                SignalInboundDropReason::NoContent,
                Some(sender),
                group_id,
                Some(SignalInboundEventKind::Message),
            ));
        }

        SignalInboundPolicyOutcome::Emit(Box::new(SignalInboundEvent::from_message(
            envelope,
            sender,
            group,
            rendered_body,
            visible_quote,
        )))
    }

    fn access_denial_reason(
        &self,
        sender: &str,
        group_id: Option<&str>,
        is_group: bool,
    ) -> Option<SignalInboundDropReason> {
        if is_group {
            return match self.group_policy {
                SignalGroupPolicy::Open => None,
                SignalGroupPolicy::Disabled => Some(SignalInboundDropReason::GroupDisabled),
                SignalGroupPolicy::Allowlist => {
                    if group_id.is_some_and(|id| {
                        entry_matches_group(id, &self.group_allow_from)
                            || entry_matches_sender(sender, &self.group_allow_from)
                    }) {
                        None
                    } else {
                        Some(SignalInboundDropReason::GroupNotAllowed)
                    }
                }
            };
        }

        match self.dm_policy {
            SignalDmPolicy::Open => None,
            SignalDmPolicy::Disabled => Some(SignalInboundDropReason::DmDisabled),
            SignalDmPolicy::Pairing => Some(SignalInboundDropReason::DmPairingRequired),
            SignalDmPolicy::Allowlist => {
                if entry_matches_sender(sender, &self.allow_from) {
                    None
                } else {
                    Some(SignalInboundDropReason::DmNotAllowed)
                }
            }
        }
    }

    fn group_message_mentions_account(&self, message: &DataMessage, account: &str) -> bool {
        let account = account.trim();
        if !account.is_empty()
            && message.mentions.iter().any(|mention| {
                mention
                    .number
                    .as_deref()
                    .is_some_and(|value| identifiers_match(value, account))
                    || mention
                        .uuid
                        .as_deref()
                        .is_some_and(|value| identifiers_match(value, account))
            })
        {
            return true;
        }

        let Some(text) = message.message.as_deref() else {
            return false;
        };
        let rendered = render_signal_mentions(text, &message.mentions);
        self.mention_patterns
            .iter()
            .any(|pattern| rendered.contains(pattern.trim()))
    }

    fn visible_quote(&self, message: &DataMessage, is_group: bool) -> Option<VisibleSignalQuote> {
        let quote = message.quote.as_ref()?;
        let text = quote.text.as_deref()?.trim();
        if text.is_empty() {
            return None;
        }

        match self.quote_context_visibility {
            SignalQuoteContextVisibility::All => {}
            SignalQuoteContextVisibility::None => return None,
            SignalQuoteContextVisibility::AllowedOnly => {
                if is_group
                    && !self.group_allow_from.is_empty()
                    && !quote_author_allowed(quote, &self.group_allow_from)
                {
                    return None;
                }
            }
        }

        Some(VisibleSignalQuote {
            text: text.to_string(),
            author: quote
                .author_uuid
                .clone()
                .filter(|value| !value.trim().is_empty())
                .or_else(|| Some(quote.author.clone()).filter(|value| !value.trim().is_empty())),
        })
    }
}

/// Inbound event kind emitted by the Signal connector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalInboundEventKind {
    /// Message or attachment event.
    Message,
    /// Reaction-only event.
    Reaction,
    /// Read/delivery receipt event.
    ReadReceipt,
    /// Typing indicator event.
    Typing,
}

impl SignalInboundEventKind {
    /// Return the FCP event topic for this kind.
    #[must_use]
    pub const fn topic(self) -> &'static str {
        match self {
            Self::Message => "signal.message.received",
            Self::Reaction => "signal.reaction.received",
            Self::ReadReceipt => "signal.receipt.read",
            Self::Typing => "signal.typing.received",
        }
    }
}

/// Outcome of applying inbound policy to a Signal envelope.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalInboundPolicyOutcome {
    /// Emit this authorized event.
    Emit(Box<SignalInboundEvent>),
    /// Drop the event and log/audit the structured reason.
    Drop(SignalInboundDrop),
}

/// Structured drop reason for unauthorized or unsupported inbound events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalInboundDropReason {
    /// Envelope had no sender identity.
    NoSender,
    /// Event came from the configured account and self-echo suppression is enabled.
    SelfEcho,
    /// Sync events are not emitted into the inbound message stream.
    SyncMessage,
    /// Direct-message policy is disabled.
    DmDisabled,
    /// Direct sender is not allowlisted.
    DmNotAllowed,
    /// Direct sender must complete pairing first.
    DmPairingRequired,
    /// Group policy is disabled.
    GroupDisabled,
    /// Group or group sender is not allowlisted.
    GroupNotAllowed,
    /// Group event did not mention the configured account or a mention pattern.
    GroupMentionRequired,
    /// The event kind is disabled in configuration.
    EventKindDisabled,
    /// Envelope carried no user-visible content.
    NoContent,
}

/// Structured description of an inbound event dropped by policy.
#[derive(Debug, Clone, Serialize)]
pub struct SignalInboundDrop {
    /// Why the event was dropped.
    pub reason: SignalInboundDropReason,
    /// Sender identifier, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender: Option<String>,
    /// Group identifier, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    /// Event kind, if it could be classified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<SignalInboundEventKind>,
}

impl SignalInboundDrop {
    fn new(
        reason: SignalInboundDropReason,
        sender: Option<&str>,
        group_id: Option<&str>,
        kind: Option<SignalInboundEventKind>,
    ) -> Self {
        Self {
            reason,
            sender: sender.map(str::to_string),
            group_id: group_id.map(str::to_string),
            kind,
        }
    }
}

/// Authorized normalized Signal inbound event.
#[derive(Debug, Clone, Serialize)]
pub struct SignalInboundEvent {
    /// Event kind.
    pub kind: SignalInboundEventKind,
    /// FCP topic.
    pub topic: String,
    /// Sender identifier.
    pub sender: String,
    /// Sender display name, if signal-cli supplied one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_name: Option<String>,
    /// Event timestamp in Signal epoch milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>,
    /// Signal group identifier for group events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    /// Signal group name for group events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_name: Option<String>,
    /// Rendered text body with Signal mention placeholders replaced.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// Visible quote text after quote-context policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quote_text: Option<String>,
    /// Visible quote author after quote-context policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quote_author: Option<String>,
    /// Reaction payload for reaction events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reaction: Option<SignalReactionMessage>,
    /// Raw receipt payload for receipt events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<serde_json::Value>,
    /// Raw typing payload for typing events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typing: Option<serde_json::Value>,
}

impl SignalInboundEvent {
    fn base(
        kind: SignalInboundEventKind,
        envelope: &SignalEnvelope,
        sender: &str,
        group: Option<&GroupInfo>,
    ) -> Self {
        Self {
            kind,
            topic: kind.topic().to_string(),
            sender: sender.to_string(),
            sender_name: envelope
                .source_name
                .clone()
                .filter(|name| !name.trim().is_empty()),
            timestamp: envelope.timestamp,
            group_id: group.map(|info| info.id.clone()),
            group_name: group.and_then(|info| info.name.clone()),
            body: None,
            quote_text: None,
            quote_author: None,
            reaction: None,
            receipt: None,
            typing: None,
        }
    }

    fn from_message(
        envelope: &SignalEnvelope,
        sender: &str,
        group: Option<&GroupInfo>,
        body: Option<String>,
        quote: Option<VisibleSignalQuote>,
    ) -> Self {
        let mut event = Self::base(SignalInboundEventKind::Message, envelope, sender, group);
        event.body = body.filter(|text| !text.trim().is_empty());
        if let Some(quote) = quote {
            event.quote_text = Some(quote.text);
            event.quote_author = quote.author;
        }
        event
    }

    fn from_reaction(
        envelope: &SignalEnvelope,
        sender: &str,
        group: Option<&GroupInfo>,
        reaction: SignalReactionMessage,
    ) -> Self {
        let mut event = Self::base(SignalInboundEventKind::Reaction, envelope, sender, group);
        event.reaction = Some(reaction);
        event
    }

    fn from_receipt(
        envelope: &SignalEnvelope,
        sender: &str,
        group: Option<&GroupInfo>,
        receipt: serde_json::Value,
    ) -> Self {
        let mut event = Self::base(SignalInboundEventKind::ReadReceipt, envelope, sender, group);
        event.receipt = Some(receipt);
        event
    }

    fn from_typing(
        envelope: &SignalEnvelope,
        sender: &str,
        group: Option<&GroupInfo>,
        typing: serde_json::Value,
    ) -> Self {
        let mut event = Self::base(SignalInboundEventKind::Typing, envelope, sender, group);
        event.typing = Some(typing);
        event
    }
}

#[derive(Debug, Clone)]
struct VisibleSignalQuote {
    text: String,
    author: Option<String>,
}

fn default_daemon_url() -> String {
    "http://localhost:8080".into()
}

const fn default_trust_mode() -> TrustMode {
    TrustMode::OnFirstUse
}

const fn default_receive_timeout_ms() -> u64 {
    10_000
}

const fn default_poll_interval_ms() -> u64 {
    5_000
}

const fn default_max_reconnect_delay_ms() -> u64 {
    60_000
}

const fn default_health_check_interval_ms() -> u64 {
    30_000
}

const fn default_max_attachment_bytes() -> u64 {
    100 * 1024 * 1024
}

const fn default_request_timeout_ms() -> u64 {
    30_000
}

impl SignalConfig {
    /// Parse and validate connector configuration from JSON.
    ///
    /// # Errors
    ///
    /// Returns `FcpError::InvalidRequest` when the JSON shape is invalid or any
    /// configuration invariant fails validation.
    pub fn from_value(value: serde_json::Value) -> FcpResult<Self> {
        let config: Self =
            serde_json::from_value(value).map_err(|error| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid Signal config: {error}"),
            })?;
        config.validate()?;
        Ok(config)
    }

    /// Validate configuration invariants.
    ///
    /// # Errors
    ///
    /// Returns `FcpError::InvalidRequest` when the daemon URL, phone number, or
    /// timeout/path settings are invalid.
    pub fn validate(&self) -> FcpResult<()> {
        let parsed =
            Url::parse(self.daemon_url.trim()).map_err(|error| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid daemon_url: {error}"),
            })?;

        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "daemon_url must use http or https".into(),
            });
        }

        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "daemon_url must not contain a query string or fragment".into(),
            });
        }

        validate_e164_number("phone_number", &self.phone_number)?;

        if self.receive_timeout_ms == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "receive_timeout_ms must be greater than zero".into(),
            });
        }

        if self.request_timeout_ms == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "request_timeout_ms must be greater than zero".into(),
            });
        }

        if self.poll_interval_ms == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "poll_interval_ms must be greater than zero".into(),
            });
        }

        if self.max_reconnect_delay_ms == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "max_reconnect_delay_ms must be greater than zero".into(),
            });
        }

        if self.health_check_interval_ms == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "health_check_interval_ms must be greater than zero".into(),
            });
        }

        if self.max_attachment_bytes == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "max_attachment_bytes must be greater than zero".into(),
            });
        }

        validate_optional_non_empty("data_dir", self.data_dir.as_deref())?;
        validate_optional_non_empty("attachment_dir", self.attachment_dir.as_deref())?;
        self.streaming.validate()?;
        self.inbound_policy.validate()?;

        Ok(())
    }

    /// Return the normalized daemon URL without a trailing slash.
    #[must_use]
    pub fn normalized_daemon_url(&self) -> String {
        self.daemon_url.trim().trim_end_matches('/').to_string()
    }

    /// Return the configured phone number trimmed for runtime use.
    #[must_use]
    pub fn normalized_phone_number(&self) -> String {
        self.phone_number.trim().to_string()
    }

    /// Return the daemon host, if it can be parsed.
    #[must_use]
    pub fn daemon_host(&self) -> Option<String> {
        Url::parse(&self.normalized_daemon_url())
            .ok()
            .and_then(|parsed| parsed.host_str().map(str::to_owned))
    }

    /// Whether the daemon host is a local loopback endpoint.
    #[must_use]
    pub fn daemon_host_is_loopback(&self) -> bool {
        self.daemon_host().as_deref().is_some_and(is_loopback_host)
    }

    /// Return the configured receive timeout rounded up to whole seconds.
    #[must_use]
    pub const fn default_receive_timeout_seconds(&self) -> u64 {
        self.receive_timeout_ms.saturating_add(999) / 1000
    }
}

fn validate_optional_non_empty(field: &str, value: Option<&str>) -> FcpResult<()> {
    if let Some(value) = value {
        validate_non_empty(field, value)?;
    }
    Ok(())
}

fn validate_non_empty(field: &str, value: &str) -> FcpResult<()> {
    if value.trim().is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: format!("{field} must not be empty"),
        });
    }
    Ok(())
}

fn validate_e164_number(field: &str, value: &str) -> FcpResult<()> {
    let value = value.trim();
    if !value.starts_with('+')
        || value.len() < 8
        || value[1..]
            .chars()
            .any(|character| !character.is_ascii_digit())
    {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: format!("{field} must be a valid E.164 phone number"),
        });
    }
    Ok(())
}

#[must_use]
pub fn is_loopback_host(host: &str) -> bool {
    let normalized = host.trim().trim_start_matches('[').trim_end_matches(']');
    normalized.eq_ignore_ascii_case("localhost") || normalized == "127.0.0.1" || normalized == "::1"
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// An incoming Signal message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalMessage {
    /// Sender phone number (E.164).
    pub sender: String,

    /// Message timestamp (Signal epoch ms).
    pub timestamp: u64,

    /// Text body of the message.
    #[serde(default)]
    pub body: Option<String>,

    /// Attached files.
    #[serde(default)]
    pub attachments: Vec<SignalAttachment>,

    /// Group context, if this is a group message.
    #[serde(default)]
    pub group_info: Option<GroupInfo>,

    /// Quote (reply) reference.
    #[serde(default)]
    pub quote: Option<SignalQuote>,
}

/// A quoted (reply-to) message reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalQuote {
    /// Timestamp of the quoted message.
    pub id: u64,
    /// Author of the quoted message.
    #[serde(default)]
    pub author: String,
    /// UUID author identifier, when the daemon supplies one instead of a number.
    #[serde(default, rename = "authorUuid")]
    pub author_uuid: Option<String>,
    /// Text of the quoted message.
    #[serde(default)]
    pub text: Option<String>,
}

/// A Signal file attachment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalAttachment {
    /// Attachment identifier.
    #[serde(default)]
    pub id: Option<String>,

    /// MIME content type.
    #[serde(default, alias = "contentType")]
    pub content_type: Option<String>,

    /// Original filename.
    #[serde(default)]
    pub filename: Option<String>,

    /// File size in bytes.
    #[serde(default)]
    pub size: Option<u64>,
}

/// Signal group info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalGroup {
    /// Group identifier (base64-encoded group ID).
    pub id: String,

    /// Display name of the group.
    #[serde(default)]
    pub name: Option<String>,

    /// Phone numbers of group members.
    #[serde(default)]
    pub members: Vec<String>,
}

/// Signal delivery receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalReceipt {
    /// Timestamp of the original message.
    pub timestamp: u64,

    /// Sender of the receipt.
    pub sender: String,

    /// Receipt type (delivery, read, viewed).
    pub receipt_type: ReceiptType,
}

/// Receipt type enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptType {
    Delivery,
    Read,
    Viewed,
}

/// Sync message from a linked device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalSyncMessage {
    /// The message that was sent (from another linked device).
    #[serde(default)]
    pub sent_message: Option<SentMessage>,

    /// Read receipts synced from another device.
    #[serde(default)]
    pub read_messages: Vec<ReadMessage>,
}

/// A message sent from a linked device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentMessage {
    /// Destination phone number.
    pub destination: String,
    /// Timestamp of the message.
    pub timestamp: u64,
    /// Text body.
    #[serde(default)]
    pub body: Option<String>,
}

/// A read receipt from a linked device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadMessage {
    /// Sender of the message that was read.
    pub sender: String,
    /// Timestamp of the message.
    pub timestamp: u64,
}

// ---------------------------------------------------------------------------
// Requests / Responses (signal-cli REST API)
// ---------------------------------------------------------------------------

/// Request to send a message via signal-cli REST API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendMessageRequest {
    /// Recipient phone numbers (E.164).
    pub recipients: Vec<String>,

    /// Text message body.
    pub message: String,

    /// Base64-encoded attachments.
    #[serde(default)]
    pub attachments: Vec<String>,

    /// Timestamp of the message to quote (reply to).
    #[serde(default)]
    pub quote_timestamp: Option<u64>,
}

impl SendMessageRequest {
    /// Validate send-message request invariants.
    ///
    /// # Errors
    ///
    /// Returns `FcpError::InvalidRequest` when recipients or attachments contain
    /// empty values, or when `quote_timestamp` is zero.
    pub fn validate(&self) -> FcpResult<()> {
        if self.recipients.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: "recipients must not be empty".into(),
            });
        }

        if self
            .recipients
            .iter()
            .any(|recipient| recipient.trim().is_empty())
        {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: "recipients must not contain empty values".into(),
            });
        }

        if self
            .attachments
            .iter()
            .any(|attachment| attachment.trim().is_empty())
        {
            return Err(FcpError::InvalidRequest {
                code: 1006,
                message: "attachments must not contain empty values".into(),
            });
        }

        if self.quote_timestamp == Some(0) {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: "quote_timestamp must be greater than zero".into(),
            });
        }

        Ok(())
    }
}

/// Request to receive messages from the REST daemon.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReceiveMessagesRequest {
    /// Optional override for the receive long-poll timeout.
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
}

impl ReceiveMessagesRequest {
    /// Validate receive-message request invariants.
    ///
    /// # Errors
    ///
    /// Returns `FcpError::InvalidRequest` when `timeout_seconds` is zero.
    pub fn validate(&self) -> FcpResult<()> {
        if self.timeout_seconds == Some(0) {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: "timeout_seconds must be greater than zero".into(),
            });
        }
        Ok(())
    }
}

/// Request to look up a Signal group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupLookupRequest {
    /// Base64-encoded group identifier.
    pub group_id: String,
}

impl GroupLookupRequest {
    /// Validate group lookup request invariants.
    ///
    /// # Errors
    ///
    /// Returns `FcpError::InvalidRequest` when `group_id` is blank.
    pub fn validate(&self) -> FcpResult<()> {
        validate_non_empty("group_id", &self.group_id)
    }
}

/// Request to look up a Signal identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityRequest {
    /// Phone number in E.164 format.
    pub number: String,
}

impl IdentityRequest {
    /// Validate identity request invariants.
    ///
    /// # Errors
    ///
    /// Returns `FcpError::InvalidRequest` when `number` is not a valid E.164
    /// phone number.
    pub fn validate(&self) -> FcpResult<()> {
        validate_e164_number("number", &self.number)
    }
}

/// Request to trust a Signal identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustIdentityRequest {
    /// Phone number in E.164 format.
    pub number: String,

    /// Safety number to trust explicitly.
    #[serde(default)]
    pub verified_safety_number: Option<String>,

    /// Trust every known key for the recipient.
    #[serde(default)]
    pub trust_all_known_keys: bool,
}

impl TrustIdentityRequest {
    /// Validate identity trust request invariants.
    ///
    /// # Errors
    ///
    /// Returns `FcpError::InvalidRequest` when `number` is invalid or when the
    /// request does not specify exactly one trust mode.
    pub fn validate(&self) -> FcpResult<()> {
        validate_e164_number("number", &self.number)?;

        let has_verified_safety_number = self
            .verified_safety_number
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());

        if !has_verified_safety_number && !self.trust_all_known_keys {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: "provide verified_safety_number or set trust_all_known_keys=true".into(),
            });
        }

        if has_verified_safety_number && self.trust_all_known_keys {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message:
                    "verified_safety_number and trust_all_known_keys=true are mutually exclusive"
                        .into(),
            });
        }

        Ok(())
    }
}

/// Response from signal-cli REST API after sending a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendMessageResponse {
    /// Timestamp assigned by Signal server.
    #[serde(deserialize_with = "deserialize_u64_from_string_or_number")]
    pub timestamp: u64,
}

/// Extended group info (from `list_groups` / `get_group`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInfo {
    /// Group identifier (base64-encoded).
    #[serde(alias = "groupId")]
    pub id: String,

    /// Display name of the group.
    #[serde(default, alias = "groupName")]
    pub name: Option<String>,

    /// Phone numbers of group members.
    #[serde(default)]
    pub members: Vec<String>,

    /// Phone numbers of group admins.
    #[serde(default)]
    pub admins: Vec<String>,
}

/// Signal identity / trust info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalIdentity {
    /// Phone number (E.164).
    pub number: String,

    /// UUID of the identity.
    #[serde(default)]
    pub uuid: Option<String>,

    /// Trust level (`TRUSTED_UNVERIFIED`, `TRUSTED_VERIFIED`, `UNTRUSTED`).
    #[serde(default)]
    pub trust_level: Option<String>,
}

/// Cursor for receive pagination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiveCursor {
    /// Timestamp of the last received message.
    pub last_timestamp: u64,
}

/// signal-cli REST API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    /// Error message from signal-cli.
    #[serde(default)]
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// signal-cli REST API envelope (receive)
// ---------------------------------------------------------------------------

/// Envelope received from the signal-cli REST daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalEnvelope {
    /// Sender number (E.164).
    #[serde(default, alias = "sourceNumber")]
    pub source: Option<String>,

    /// Sender UUID, when signal-cli emits UUID identity instead of a number.
    #[serde(default, rename = "sourceUuid")]
    pub source_uuid: Option<String>,

    /// Sender display name supplied by signal-cli.
    #[serde(default, rename = "sourceName")]
    pub source_name: Option<String>,

    /// Sender device ID.
    #[serde(default, rename = "sourceDevice")]
    pub source_device: Option<u32>,

    /// Envelope timestamp.
    #[serde(default)]
    pub timestamp: Option<u64>,

    /// Data message content.
    #[serde(default, rename = "dataMessage")]
    pub data_message: Option<DataMessage>,

    /// Edited data message content.
    #[serde(default, rename = "editMessage")]
    pub edit_message: Option<SignalEditMessage>,

    /// Reaction-only message content.
    #[serde(default, rename = "reactionMessage")]
    pub reaction_message: Option<SignalReactionMessage>,

    /// Receipt message.
    #[serde(default, rename = "receiptMessage")]
    pub receipt_message: Option<serde_json::Value>,

    /// Typing indicator message.
    #[serde(default, rename = "typingMessage")]
    pub typing_message: Option<serde_json::Value>,

    /// Sync message.
    #[serde(default, rename = "syncMessage")]
    pub sync_message: Option<serde_json::Value>,
}

impl SignalEnvelope {
    /// Return the data message carried by this envelope, including edit events.
    #[must_use]
    pub fn primary_data_message(&self) -> Option<&DataMessage> {
        self.data_message.as_ref().or_else(|| {
            self.edit_message
                .as_ref()
                .and_then(|edit| edit.data_message.as_ref())
        })
    }

    /// Return the best available sender identifier from the envelope.
    #[must_use]
    pub fn sender_identifier(&self) -> Option<&str> {
        self.source.as_deref().or(self.source_uuid.as_deref())
    }
}

/// Edited message wrapper from signal-cli receive events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalEditMessage {
    /// Edited data message content.
    #[serde(default, rename = "dataMessage")]
    pub data_message: Option<DataMessage>,
}

/// Data message from signal-cli.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataMessage {
    /// Message timestamp.
    #[serde(default)]
    pub timestamp: Option<u64>,

    /// Text body.
    #[serde(default)]
    pub message: Option<String>,

    /// Group context.
    #[serde(default, rename = "groupInfo")]
    pub group_info: Option<GroupInfo>,

    /// Attachments.
    #[serde(default)]
    pub attachments: Vec<SignalAttachment>,

    /// Quote (reply).
    #[serde(default)]
    pub quote: Option<SignalQuote>,

    /// Signal mention metadata for object-replacement placeholders.
    #[serde(default)]
    pub mentions: Vec<SignalMention>,

    /// Reaction payload nested in a data message.
    #[serde(default)]
    pub reaction: Option<SignalReactionMessage>,
}

/// Signal mention metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalMention {
    /// Display name for the mentioned sender.
    #[serde(default)]
    pub name: Option<String>,

    /// E.164 phone number for the mentioned sender.
    #[serde(default)]
    pub number: Option<String>,

    /// UUID for the mentioned sender.
    #[serde(default)]
    pub uuid: Option<String>,

    /// Start offset in the message text.
    #[serde(default)]
    pub start: Option<u64>,

    /// Length of the mention placeholder span.
    #[serde(default)]
    pub length: Option<u64>,
}

/// Signal reaction message payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalReactionMessage {
    /// Reaction emoji.
    #[serde(default)]
    pub emoji: Option<String>,

    /// Target author number.
    #[serde(default, rename = "targetAuthor")]
    pub target_author: Option<String>,

    /// Target author UUID.
    #[serde(default, rename = "targetAuthorUuid")]
    pub target_author_uuid: Option<String>,

    /// Target message timestamp.
    #[serde(default, rename = "targetSentTimestamp")]
    pub target_sent_timestamp: Option<u64>,

    /// Whether this reaction removes a previous reaction.
    #[serde(default, rename = "isRemove")]
    pub is_remove: bool,

    /// Group context for group reactions.
    #[serde(default, rename = "groupInfo")]
    pub group_info: Option<GroupInfo>,
}

/// Exception payload from signal-cli receive events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalReceiveException {
    /// Daemon-provided exception message.
    #[serde(default)]
    pub message: Option<String>,
}

/// Payload carried by signal-cli SSE `receive` events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalReceivePayload {
    /// Signal envelope, if the event carried one.
    #[serde(default)]
    pub envelope: Option<SignalEnvelope>,

    /// Receive exception, if the daemon emitted an error event.
    #[serde(default)]
    pub exception: Option<SignalReceiveException>,
}

/// Parsed signal-cli SSE event.
#[derive(Debug, Clone)]
pub struct SignalSseEvent {
    /// SSE event type, for example `receive`.
    pub event: Option<String>,

    /// SSE event ID.
    pub id: Option<String>,

    /// Parsed receive payload.
    pub payload: SignalReceivePayload,
}

/// Parse a complete signal-cli SSE event block.
///
/// Comments and empty keepalive blocks return `Ok(None)`. The parser accepts
/// both the wrapped `{"envelope": ...}` shape used by current signal-cli event
/// streams and raw envelope JSON used by older clients.
///
/// # Errors
///
/// Returns the underlying JSON parse error when the `data:` payload is present
/// but malformed.
pub fn parse_signal_sse_event(block: &str) -> serde_json::Result<Option<SignalSseEvent>> {
    let mut event = None;
    let mut id = None;
    let mut data = None::<String>;

    for raw_line in block.lines() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.is_empty() || line.starts_with(':') {
            continue;
        }

        let Some((raw_field, raw_value)) = line.split_once(':') else {
            continue;
        };
        let value = raw_value.strip_prefix(' ').unwrap_or(raw_value);

        match raw_field.trim() {
            SSE_FIELD_EVENT => event = Some(value.to_string()),
            SSE_FIELD_ID => id = Some(value.to_string()),
            SSE_FIELD_DATA => {
                if value.is_empty() {
                    continue;
                }
                match &mut data {
                    Some(existing) => {
                        existing.push('\n');
                        existing.push_str(value);
                    }
                    None => data = Some(value.to_string()),
                }
            }
            _ => {}
        }
    }

    let Some(data) = data else {
        return Ok(None);
    };
    if data.trim().is_empty() {
        return Ok(None);
    }

    let payload = parse_signal_receive_payload(&data)?;
    Ok(Some(SignalSseEvent { event, id, payload }))
}

/// Parse an already-framed SSE data payload into a Signal receive event.
///
/// This is used by streaming clients that parse the SSE framing separately but
/// still need signal-cli's wrapped/raw envelope compatibility.
///
/// # Errors
///
/// Returns the underlying JSON parse error when `data` is malformed.
pub fn parse_signal_sse_data(
    event: Option<String>,
    id: Option<String>,
    data: &str,
) -> serde_json::Result<Option<SignalSseEvent>> {
    if data.trim().is_empty() {
        return Ok(None);
    }

    let payload = parse_signal_receive_payload(data)?;
    Ok(Some(SignalSseEvent { event, id, payload }))
}

fn parse_signal_receive_payload(data: &str) -> serde_json::Result<SignalReceivePayload> {
    let value = serde_json::from_str::<serde_json::Value>(data)?;
    let wrapped = serde_json::from_value::<SignalReceivePayload>(value.clone())?;
    if wrapped.envelope.is_some() || wrapped.exception.is_some() {
        return Ok(wrapped);
    }

    let envelope = serde_json::from_value::<SignalEnvelope>(value)?;
    Ok(SignalReceivePayload {
        envelope: Some(envelope),
        exception: None,
    })
}

/// Render Signal mention placeholders (`\u{fffc}`) as readable `@identifier`
/// tokens using the out-of-band mention metadata.
#[must_use]
pub fn render_signal_mentions(message: &str, mentions: &[SignalMention]) -> String {
    const OBJECT_REPLACEMENT: char = '\u{fffc}';

    if message.is_empty() || mentions.is_empty() || !message.contains(OBJECT_REPLACEMENT) {
        return message.to_string();
    }

    let mut chars = message.chars().collect::<Vec<_>>();
    let mut candidates = mentions
        .iter()
        .filter_map(|mention| {
            let start = usize::try_from(mention.start?).ok()?;
            let length = usize::try_from(mention.length?).ok()?;
            if length == 0 {
                return None;
            }
            let identifier = mention
                .name
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .or_else(|| {
                    mention
                        .number
                        .as_deref()
                        .filter(|value| !value.trim().is_empty())
                })
                .or_else(|| {
                    mention
                        .uuid
                        .as_deref()
                        .filter(|value| !value.trim().is_empty())
                })?;
            Some((start, length, identifier))
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.0));

    for (start, length, identifier) in candidates {
        let end = start.saturating_add(length).min(chars.len());
        if start >= end || !chars[start..end].contains(&OBJECT_REPLACEMENT) {
            continue;
        }
        chars.splice(start..end, format!("@{identifier}").chars());
    }

    chars.iter().collect()
}

fn classify_envelope_kind(envelope: &SignalEnvelope) -> Option<SignalInboundEventKind> {
    if envelope.receipt_message.is_some() {
        return Some(SignalInboundEventKind::ReadReceipt);
    }
    if envelope.typing_message.is_some() {
        return Some(SignalInboundEventKind::Typing);
    }
    if envelope.reaction_message.is_some()
        || envelope
            .primary_data_message()
            .and_then(|message| message.reaction.as_ref())
            .is_some()
    {
        return Some(SignalInboundEventKind::Reaction);
    }
    if envelope.primary_data_message().is_some() {
        return Some(SignalInboundEventKind::Message);
    }
    None
}

fn identifiers_match(left: &str, right: &str) -> bool {
    let left = left.trim();
    let right = right.trim();
    !left.is_empty() && !right.is_empty() && left.eq_ignore_ascii_case(right)
}

fn entry_matches_sender(sender: &str, entries: &[String]) -> bool {
    let candidates = [
        sender.to_string(),
        format!("signal:{sender}"),
        format!("phone:{sender}"),
    ];
    entries.iter().any(|entry| {
        let entry = entry.trim();
        entry == "*"
            || candidates
                .iter()
                .any(|candidate| identifiers_match(entry, candidate))
    })
}

fn entry_matches_group(group_id: &str, entries: &[String]) -> bool {
    let candidates = [
        group_id.to_string(),
        format!("group:{group_id}"),
        format!("signal:group:{group_id}"),
    ];
    entries.iter().any(|entry| {
        let entry = entry.trim();
        entry == "*"
            || candidates
                .iter()
                .any(|candidate| identifiers_match(entry, candidate))
    })
}

fn quote_author_allowed(quote: &SignalQuote, entries: &[String]) -> bool {
    quote
        .author
        .split(',')
        .chain(quote.author_uuid.as_deref())
        .any(|author| entry_matches_sender(author.trim(), entries))
}

fn deserialize_u64_from_string_or_number<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    match serde_json::Value::deserialize(deserializer)? {
        serde_json::Value::Number(number) => number
            .as_u64()
            .ok_or_else(|| D::Error::custom("timestamp must be an unsigned integer")),
        serde_json::Value::String(value) => value
            .parse::<u64>()
            .map_err(|error| D::Error::custom(format!("invalid timestamp: {error}"))),
        other => Err(D::Error::custom(format!(
            "timestamp must be a string or integer, got {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expect_emit(outcome: SignalInboundPolicyOutcome) -> Box<SignalInboundEvent> {
        match outcome {
            SignalInboundPolicyOutcome::Emit(event) => Some(event),
            SignalInboundPolicyOutcome::Drop(_) => None,
        }
        .expect("expected inbound policy to emit an event")
    }

    fn expect_drop(outcome: SignalInboundPolicyOutcome) -> SignalInboundDrop {
        match outcome {
            SignalInboundPolicyOutcome::Emit(_) => None,
            SignalInboundPolicyOutcome::Drop(dropped) => Some(dropped),
        }
        .expect("expected inbound policy to drop the event")
    }

    #[test]
    fn deserialize_signal_config_defaults() {
        let json = serde_json::json!({
            "phone_number": "+15551234567"
        });
        let config = SignalConfig::from_value(json).unwrap();
        assert_eq!(config.phone_number, "+15551234567");
        assert_eq!(config.daemon_url, "http://localhost:8080");
        assert_eq!(config.trust_mode, TrustMode::OnFirstUse);
        assert_eq!(config.receive_timeout_ms, 10_000);
        assert_eq!(config.poll_interval_ms, 5_000);
        assert_eq!(config.max_reconnect_delay_ms, 60_000);
        assert_eq!(config.health_check_interval_ms, 30_000);
        assert_eq!(config.max_attachment_bytes, 100 * 1024 * 1024);
        assert_eq!(config.request_timeout_ms, 30_000);
        assert!(config.data_dir.is_none());
        assert!(config.attachment_dir.is_none());
    }

    #[test]
    fn deserialize_signal_config_overrides() {
        let json = serde_json::json!({
            "daemon_url": "https://signal.example.com:9090",
            "phone_number": "+491701234567",
            "trust_mode": "always",
            "data_dir": "/var/lib/signal-cli",
            "receive_timeout_ms": 30000,
            "poll_interval_ms": 7000,
            "max_reconnect_delay_ms": 45000,
            "health_check_interval_ms": 12000,
            "attachment_dir": "/tmp/signal-attachments",
            "max_attachment_bytes": 4096,
            "request_timeout_ms": 60000
        });
        let config = SignalConfig::from_value(json).unwrap();
        assert_eq!(config.daemon_url, "https://signal.example.com:9090");
        assert_eq!(config.trust_mode, TrustMode::Always);
        assert_eq!(config.data_dir, Some("/var/lib/signal-cli".into()));
        assert_eq!(config.receive_timeout_ms, 30000);
        assert_eq!(config.poll_interval_ms, 7000);
        assert_eq!(config.max_reconnect_delay_ms, 45000);
        assert_eq!(config.health_check_interval_ms, 12000);
        assert_eq!(
            config.attachment_dir,
            Some("/tmp/signal-attachments".into())
        );
        assert_eq!(config.max_attachment_bytes, 4096);
    }

    #[test]
    fn normalize_runtime_strings_for_signal_config() {
        let config = SignalConfig::from_value(serde_json::json!({
            "daemon_url": "  https://signal.example.com:9090/  ",
            "phone_number": "  +491701234567  ",
        }))
        .unwrap();

        assert_eq!(
            config.normalized_daemon_url(),
            "https://signal.example.com:9090"
        );
        assert_eq!(config.normalized_phone_number(), "+491701234567");
    }

    #[test]
    fn daemon_host_helpers_support_ipv6_loopback() {
        let config = SignalConfig::from_value(serde_json::json!({
            "daemon_url": "http://[::1]:8080/",
            "phone_number": "+15551234567",
        }))
        .unwrap();

        assert_eq!(config.daemon_host().as_deref(), Some("[::1]"));
        assert!(config.daemon_host_is_loopback());
    }

    #[test]
    fn reject_invalid_signal_config_phone_number() {
        let error = SignalConfig::from_value(serde_json::json!({
            "phone_number": "alice"
        }))
        .unwrap_err();

        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn round_up_receive_timeout_to_seconds() {
        let config = SignalConfig::from_value(serde_json::json!({
            "phone_number": "+15551234567",
            "receive_timeout_ms": 10_001
        }))
        .unwrap();

        assert_eq!(config.default_receive_timeout_seconds(), 11);
    }

    #[test]
    fn deserialize_signal_message_full() {
        let json = serde_json::json!({
            "sender": "+15551234567",
            "timestamp": 1_700_000_000_000_u64,
            "body": "Hello, Signal!",
            "attachments": [
                {
                    "id": "att_001",
                    "content_type": "image/png",
                    "filename": "photo.png",
                    "size": 12345
                }
            ],
            "group_info": {
                "id": "Z3JvdXBfaWQ=",
                "name": "Test Group",
                "members": ["+15551111111", "+15552222222"],
                "admins": ["+15551111111"]
            },
            "quote": {
                "id": 1_699_999_999_000_u64,
                "author": "+15559999999",
                "text": "Original message"
            }
        });
        let msg: SignalMessage = serde_json::from_value(json).unwrap();
        assert_eq!(msg.sender, "+15551234567");
        assert_eq!(msg.timestamp, 1_700_000_000_000);
        assert_eq!(msg.body, Some("Hello, Signal!".into()));
        assert_eq!(msg.attachments.len(), 1);
        assert_eq!(msg.attachments[0].filename, Some("photo.png".into()));
        assert!(msg.group_info.is_some());
        let group = msg.group_info.unwrap();
        assert_eq!(group.name, Some("Test Group".into()));
        assert_eq!(group.members.len(), 2);
        assert!(msg.quote.is_some());
        assert_eq!(msg.quote.unwrap().author, "+15559999999");
    }

    #[test]
    fn deserialize_signal_message_minimal() {
        let json = serde_json::json!({
            "sender": "+15551234567",
            "timestamp": 1_700_000_000_000_u64
        });
        let msg: SignalMessage = serde_json::from_value(json).unwrap();
        assert!(msg.body.is_none());
        assert!(msg.attachments.is_empty());
        assert!(msg.group_info.is_none());
        assert!(msg.quote.is_none());
    }

    #[test]
    fn serialize_send_message_request() {
        let req = SendMessageRequest {
            recipients: vec!["+15551234567".into(), "+15559876543".into()],
            message: "Hello from FCP".into(),
            attachments: Vec::new(),
            quote_timestamp: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["recipients"].as_array().unwrap().len(), 2);
        assert_eq!(json["message"], "Hello from FCP");
    }

    #[test]
    fn deserialize_send_message_response() {
        let json = serde_json::json!({
            "timestamp": "1700000001000"
        });
        let resp: SendMessageResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.timestamp, 1_700_000_001_000);
    }

    #[test]
    fn trust_identity_request_requires_exactly_one_trust_mode() {
        let error = TrustIdentityRequest {
            number: "+15551234567".into(),
            verified_safety_number: None,
            trust_all_known_keys: false,
        }
        .validate()
        .unwrap_err();

        assert!(matches!(error, FcpError::InvalidRequest { .. }));

        let error = TrustIdentityRequest {
            number: "+15551234567".into(),
            verified_safety_number: Some("12345".into()),
            trust_all_known_keys: true,
        }
        .validate()
        .unwrap_err();

        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn deserialize_signal_identity() {
        let json = serde_json::json!({
            "number": "+15551234567",
            "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "trust_level": "TRUSTED_VERIFIED"
        });
        let identity: SignalIdentity = serde_json::from_value(json).unwrap();
        assert_eq!(identity.number, "+15551234567");
        assert_eq!(identity.trust_level, Some("TRUSTED_VERIFIED".into()));
    }

    #[test]
    fn receive_cursor_roundtrip() {
        let cursor = ReceiveCursor {
            last_timestamp: 1_700_000_000_000,
        };
        let json = serde_json::to_value(&cursor).unwrap();
        let deserialized: ReceiveCursor = serde_json::from_value(json).unwrap();
        assert_eq!(deserialized.last_timestamp, 1_700_000_000_000);
    }

    #[test]
    fn trust_mode_serialization() {
        assert_eq!(
            serde_json::to_value(TrustMode::OnFirstUse).unwrap(),
            serde_json::json!("on_first_use")
        );
        assert_eq!(
            serde_json::to_value(TrustMode::Always).unwrap(),
            serde_json::json!("always")
        );
        assert_eq!(
            serde_json::to_value(TrustMode::Never).unwrap(),
            serde_json::json!("never")
        );
    }

    #[test]
    fn receipt_type_deserialization() {
        let json = serde_json::json!({
            "timestamp": 1_700_000_000_000_u64,
            "sender": "+15551234567",
            "receipt_type": "read"
        });
        let receipt: SignalReceipt = serde_json::from_value(json).unwrap();
        assert_eq!(receipt.receipt_type, ReceiptType::Read);
    }

    #[test]
    fn deserialize_sync_message() {
        let json = serde_json::json!({
            "sent_message": {
                "destination": "+15559876543",
                "timestamp": 1_700_000_002_000_u64,
                "body": "Synced text"
            },
            "read_messages": [
                { "sender": "+15551111111", "timestamp": 1_700_000_003_000_u64 }
            ]
        });
        let sync: SignalSyncMessage = serde_json::from_value(json).unwrap();
        assert!(sync.sent_message.is_some());
        assert_eq!(sync.sent_message.unwrap().destination, "+15559876543");
        assert_eq!(sync.read_messages.len(), 1);
    }

    #[test]
    fn deserialize_signal_envelope() {
        let json = serde_json::json!({
            "source": "+15551234567",
            "sourceDevice": 1,
            "timestamp": 1_700_000_000_000_u64,
            "dataMessage": {
                "timestamp": 1_700_000_000_000_u64,
                "message": "Hello from envelope"
            }
        });
        let env: SignalEnvelope = serde_json::from_value(json).unwrap();
        assert_eq!(env.source, Some("+15551234567".into()));
        assert_eq!(env.source_device, Some(1));
        let dm = env.data_message.unwrap();
        assert_eq!(dm.message, Some("Hello from envelope".into()));
    }

    #[test]
    fn deserialize_signal_envelope_accepts_sse_aliases() {
        let json = serde_json::json!({
            "sourceNumber": "+15551234567",
            "sourceUuid": "6f1a0d8c-0000-4000-8000-000000000001",
            "sourceName": "Alice",
            "dataMessage": {
                "timestamp": 1_700_000_000_000_u64,
                "message": "Hello from group",
                "mentions": [
                    {
                        "number": "+15559876543",
                        "start": 0,
                        "length": 1
                    }
                ],
                "groupInfo": {
                    "groupId": "Z3JvdXBfaWQ=",
                    "groupName": "Engineers"
                },
                "attachments": [
                    {
                        "id": "att-1",
                        "contentType": "image/png"
                    }
                ],
                "reaction": {
                    "emoji": "+1",
                    "targetAuthor": "+15551234567",
                    "targetSentTimestamp": 1_700_000_000_000_u64,
                    "groupInfo": {
                        "groupId": "Z3JvdXBfaWQ=",
                        "groupName": "Engineers"
                    }
                }
            }
        });

        let envelope: SignalEnvelope = serde_json::from_value(json).unwrap();
        assert_eq!(envelope.source.as_deref(), Some("+15551234567"));
        assert_eq!(envelope.source_name.as_deref(), Some("Alice"));
        assert_eq!(envelope.sender_identifier(), Some("+15551234567"));

        let data = envelope.primary_data_message().unwrap();
        assert_eq!(data.mentions.len(), 1);
        assert_eq!(
            data.attachments[0].content_type.as_deref(),
            Some("image/png")
        );
        assert_eq!(
            data.group_info.as_ref().unwrap().name.as_deref(),
            Some("Engineers")
        );
        let reaction = data.reaction.as_ref().unwrap();
        assert_eq!(reaction.emoji.as_deref(), Some("+1"));
        assert_eq!(reaction.group_info.as_ref().unwrap().id, "Z3JvdXBfaWQ=");
    }

    #[test]
    fn parse_signal_sse_receive_event_payload() {
        let block = r#"id: 42
event: receive
data: {"envelope":{"sourceNumber":"+15551234567","timestamp":1700000000000,"dataMessage":{"timestamp":1700000000000,"message":"hello"}}}
"#;

        let event = parse_signal_sse_event(block).unwrap().unwrap();
        assert_eq!(event.id.as_deref(), Some("42"));
        assert_eq!(event.event.as_deref(), Some("receive"));

        let envelope = event.payload.envelope.unwrap();
        assert_eq!(envelope.source.as_deref(), Some("+15551234567"));
        assert_eq!(
            envelope.primary_data_message().unwrap().message.as_deref(),
            Some("hello")
        );
    }

    #[test]
    fn parse_signal_sse_keepalive_returns_none() {
        assert!(parse_signal_sse_event(": keepalive\n\n").unwrap().is_none());
    }

    #[test]
    fn parse_signal_sse_accepts_raw_envelope_payload() {
        let block = r#"event: receive
data: {"sourceNumber":"+15551234567","dataMessage":{"message":"legacy"}}
"#;

        let event = parse_signal_sse_event(block).unwrap().unwrap();
        let envelope = event.payload.envelope.unwrap();
        assert_eq!(
            envelope.primary_data_message().unwrap().message.as_deref(),
            Some("legacy")
        );
    }

    #[test]
    fn parse_signal_sse_rejects_malformed_data() {
        let error = parse_signal_sse_event("event: receive\ndata: {bad json}\n").unwrap_err();
        assert!(error.is_syntax());
    }

    #[test]
    fn render_signal_mentions_replaces_object_placeholder() {
        let rendered = render_signal_mentions(
            "hi \u{fffc}",
            &[SignalMention {
                name: None,
                number: Some("+15559876543".into()),
                uuid: None,
                start: Some(3),
                length: Some(1),
            }],
        );

        assert_eq!(rendered, "hi @+15559876543");
    }

    #[test]
    fn inbound_policy_defaults_allow_dm_and_deny_unlisted_group() {
        let policy = SignalInboundPolicy::default();
        let dm: SignalEnvelope = serde_json::from_value(serde_json::json!({
            "sourceNumber": "+15559876543",
            "timestamp": 1_700_000_000_000_u64,
            "dataMessage": { "message": "hello" }
        }))
        .unwrap();
        let group: SignalEnvelope = serde_json::from_value(serde_json::json!({
            "sourceNumber": "+15559876543",
            "dataMessage": {
                "message": "hello",
                "groupInfo": { "groupId": "group-1", "groupName": "Ops" }
            }
        }))
        .unwrap();

        let event = expect_emit(policy.evaluate_envelope(&dm, "+15551234567"));
        assert_eq!(event.kind, SignalInboundEventKind::Message);
        assert_eq!(event.body.as_deref(), Some("hello"));

        let dropped = expect_drop(policy.evaluate_envelope(&group, "+15551234567"));
        assert_eq!(dropped.reason, SignalInboundDropReason::GroupNotAllowed);
        assert_eq!(dropped.group_id.as_deref(), Some("group-1"));
    }

    #[test]
    fn inbound_policy_supports_dm_allowlist_and_pairing_modes() {
        let envelope: SignalEnvelope = serde_json::from_value(serde_json::json!({
            "sourceNumber": "+15559876543",
            "dataMessage": { "message": "hello" }
        }))
        .unwrap();
        let allowed = SignalInboundPolicy {
            dm_policy: SignalDmPolicy::Allowlist,
            allow_from: vec!["signal:+15559876543".into()],
            ..SignalInboundPolicy::default()
        };
        let pairing = SignalInboundPolicy {
            dm_policy: SignalDmPolicy::Pairing,
            ..SignalInboundPolicy::default()
        };

        assert!(matches!(
            allowed.evaluate_envelope(&envelope, "+15551234567"),
            SignalInboundPolicyOutcome::Emit(_)
        ));
        let dropped = expect_drop(pairing.evaluate_envelope(&envelope, "+15551234567"));
        assert_eq!(dropped.reason, SignalInboundDropReason::DmPairingRequired);
    }

    #[test]
    fn inbound_policy_requires_group_mention_when_configured() {
        let policy = SignalInboundPolicy {
            group_allow_from: vec!["group:group-1".into()],
            require_group_mention: true,
            mention_patterns: vec!["@bot".into()],
            ..SignalInboundPolicy::default()
        };
        let missing_mention: SignalEnvelope = serde_json::from_value(serde_json::json!({
            "sourceNumber": "+15559876543",
            "dataMessage": {
                "message": "hello",
                "groupInfo": { "groupId": "group-1" }
            }
        }))
        .unwrap();
        let with_mention: SignalEnvelope = serde_json::from_value(serde_json::json!({
            "sourceNumber": "+15559876543",
            "dataMessage": {
                "message": "@bot hello",
                "groupInfo": { "groupId": "group-1" }
            }
        }))
        .unwrap();

        let dropped = expect_drop(policy.evaluate_envelope(&missing_mention, "+15551234567"));
        assert_eq!(
            dropped.reason,
            SignalInboundDropReason::GroupMentionRequired
        );
        assert!(matches!(
            policy.evaluate_envelope(&with_mention, "+15551234567"),
            SignalInboundPolicyOutcome::Emit(_)
        ));
    }

    #[test]
    fn inbound_policy_hides_group_quote_context_from_unallowed_author() {
        let envelope: SignalEnvelope = serde_json::from_value(serde_json::json!({
            "sourceNumber": "+15559876543",
            "dataMessage": {
                "message": "replying",
                "groupInfo": { "groupId": "group-1" },
                "quote": {
                    "id": 1_700_000_000_000_u64,
                    "author": "+15550000000",
                    "text": "private context"
                }
            }
        }))
        .unwrap();
        let policy = SignalInboundPolicy {
            group_allow_from: vec!["group:group-1".into()],
            ..SignalInboundPolicy::default()
        };

        let event = expect_emit(policy.evaluate_envelope(&envelope, "+15551234567"));
        assert_eq!(event.body.as_deref(), Some("replying"));
        assert!(event.quote_text.is_none());
    }

    #[test]
    fn inbound_policy_drops_self_echo() {
        let envelope: SignalEnvelope = serde_json::from_value(serde_json::json!({
            "sourceNumber": "+15551234567",
            "dataMessage": { "message": "echo" }
        }))
        .unwrap();

        let dropped = expect_drop(
            SignalInboundPolicy::default().evaluate_envelope(&envelope, "+15551234567"),
        );
        assert_eq!(dropped.reason, SignalInboundDropReason::SelfEcho);
    }

    #[test]
    fn inbound_policy_authorizes_reaction_only_events_after_sender_policy() {
        let envelope: SignalEnvelope = serde_json::from_value(serde_json::json!({
            "sourceNumber": "+15559876543",
            "reactionMessage": {
                "emoji": "+1",
                "targetAuthor": "+15551234567",
                "targetSentTimestamp": 1_700_000_000_000_u64,
                "groupInfo": { "groupId": "group-1" }
            }
        }))
        .unwrap();
        let denied = SignalInboundPolicy::default();
        let allowed = SignalInboundPolicy {
            group_allow_from: vec!["group:group-1".into()],
            ..SignalInboundPolicy::default()
        };

        let dropped = expect_drop(denied.evaluate_envelope(&envelope, "+15551234567"));
        assert_eq!(dropped.reason, SignalInboundDropReason::GroupNotAllowed);
        assert_eq!(dropped.kind, Some(SignalInboundEventKind::Reaction));

        let event = expect_emit(allowed.evaluate_envelope(&envelope, "+15551234567"));
        assert_eq!(event.kind, SignalInboundEventKind::Reaction);
        assert_eq!(
            event
                .reaction
                .as_ref()
                .and_then(|reaction| reaction.emoji.as_deref()),
            Some("+1")
        );
    }

    #[test]
    fn inbound_policy_emits_receipts_and_typing_events() {
        let receipt: SignalEnvelope = serde_json::from_value(serde_json::json!({
            "sourceNumber": "+15559876543",
            "receiptMessage": { "type": "READ", "timestamps": [1_700_000_000_000_u64] }
        }))
        .unwrap();
        let typing: SignalEnvelope = serde_json::from_value(serde_json::json!({
            "sourceNumber": "+15559876543",
            "typingMessage": { "action": "STARTED" }
        }))
        .unwrap();
        let policy = SignalInboundPolicy::default();

        let event = expect_emit(policy.evaluate_envelope(&receipt, "+15551234567"));
        assert_eq!(event.kind, SignalInboundEventKind::ReadReceipt);
        assert!(event.receipt.is_some());

        let event = expect_emit(policy.evaluate_envelope(&typing, "+15551234567"));
        assert_eq!(event.kind, SignalInboundEventKind::Typing);
        assert!(event.typing.is_some());
    }

    #[test]
    fn deserialize_group_info() {
        let json = serde_json::json!({
            "id": "Z3JvdXBfaWQ=",
            "name": "Engineers",
            "members": ["+15551111111", "+15552222222"],
            "admins": ["+15551111111"]
        });
        let group: GroupInfo = serde_json::from_value(json).unwrap();
        assert_eq!(group.id, "Z3JvdXBfaWQ=");
        assert_eq!(group.name, Some("Engineers".into()));
        assert_eq!(group.members.len(), 2);
        assert_eq!(group.admins.len(), 1);
    }

    #[test]
    fn api_error_response_deserialization() {
        let json = serde_json::json!({
            "error": "User is not registered"
        });
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.error, Some("User is not registered".into()));
    }
}
