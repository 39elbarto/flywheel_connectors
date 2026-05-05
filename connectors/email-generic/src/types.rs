//! Configuration types for the generic email connector.

use fcp_prelude::{FcpError, FcpResult};
use std::collections::{BTreeSet, VecDeque};

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Serialize, Deserialize)]
pub struct ImapConfig {
    pub host: String,
    #[serde(default = "default_imap_port")]
    pub port: u16,
    pub username: String,
    pub password: String,
    #[serde(default = "default_true")]
    pub tls: bool,
}

impl std::fmt::Debug for ImapConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImapConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("tls", &self.tls)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SmtpConfig {
    pub host: String,
    #[serde(default = "default_smtp_port")]
    pub port: u16,
    pub username: String,
    pub password: String,
    pub from_address: String,
    #[serde(default)]
    pub from_name: Option<String>,
    #[serde(default = "default_true")]
    pub starttls: bool,
}

impl std::fmt::Debug for SmtpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("from_address", &self.from_address)
            .field("from_name", &self.from_name)
            .field("starttls", &self.starttls)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EmailInboundPolicyDecision {
    Accept,
    DropAutomated,
    DropSenderNotAllowed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EmailAttachmentClass {
    Image,
    Document,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmailAttachmentCandidate {
    pub filename: String,
    pub media_type: String,
    pub size_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmailAttachmentSummary {
    pub filename: String,
    pub media_type: String,
    pub size_bytes: usize,
    pub class: EmailAttachmentClass,
    pub exposed: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmailBoundedBody {
    pub text: String,
    pub original_chars: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmailThreadMetadata {
    pub subject: String,
    pub message_id: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Option<String>,
    pub reply_subject: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmailInboundMessage {
    pub uid: String,
    pub sender: String,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    pub subject: String,
    pub body: String,
    pub message_id: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Option<String>,
    #[serde(default)]
    pub attachments: Vec<EmailAttachmentCandidate>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmailInboundPreview {
    pub decision: EmailInboundPolicyDecision,
    pub text: Option<EmailBoundedBody>,
    pub attachments: Vec<EmailAttachmentSummary>,
    pub thread: Option<EmailThreadMetadata>,
    pub tainted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailSeenUidCache {
    cap: usize,
    seen: BTreeSet<String>,
    order: VecDeque<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmailMonitorPolicy {
    #[serde(default, deserialize_with = "deserialize_sender_list")]
    pub allowed_senders: Vec<String>,
    #[serde(default = "default_true")]
    pub require_allowed_sender: bool,
    #[serde(default = "default_true")]
    pub drop_automated: bool,
    #[serde(default)]
    pub allow_attachments: bool,
    #[serde(default = "default_monitor_poll_interval_secs")]
    pub poll_interval_secs: u64,
    #[serde(default = "default_max_body_chars")]
    pub max_body_chars: usize,
    #[serde(default = "default_seen_uid_cap")]
    pub seen_uid_cap: usize,
}

impl Default for EmailMonitorPolicy {
    fn default() -> Self {
        Self {
            allowed_senders: Vec::new(),
            require_allowed_sender: true,
            drop_automated: true,
            allow_attachments: false,
            poll_interval_secs: default_monitor_poll_interval_secs(),
            max_body_chars: default_max_body_chars(),
            seen_uid_cap: default_seen_uid_cap(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailGenericConfig {
    pub imap: ImapConfig,
    pub smtp: SmtpConfig,
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
    #[serde(default)]
    pub monitor_policy: EmailMonitorPolicy,
}

const MAX_ALLOWED_SENDERS: usize = 512;
const MAX_POLL_INTERVAL_SECS: u64 = 3_600;
const MAX_BODY_CHARS_LIMIT: usize = 1_000_000;
const MAX_SEEN_UID_CAP_LIMIT: usize = 100_000;

const fn default_true() -> bool {
    true
}

const fn default_imap_port() -> u16 {
    993
}

const fn default_smtp_port() -> u16 {
    587
}

const fn default_request_timeout_ms() -> u64 {
    15_000
}

const fn default_monitor_poll_interval_secs() -> u64 {
    15
}

const fn default_max_body_chars() -> usize {
    50_000
}

const fn default_seen_uid_cap() -> usize {
    2_000
}

fn deserialize_sender_list<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    match value {
        Value::Null => Ok(Vec::new()),
        Value::String(value) => Ok(split_sender_list(&value)),
        Value::Array(values) => values
            .into_iter()
            .map(|value| match value {
                Value::String(sender) => Ok(sender),
                other => Err(serde::de::Error::custom(format!(
                    "allowed_senders entries must be strings, got {other}"
                ))),
            })
            .collect(),
        other => Err(serde::de::Error::custom(format!(
            "allowed_senders must be an array or comma-separated string, got {other}"
        ))),
    }
}

fn split_sender_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|sender| !sender.is_empty())
        .map(str::to_owned)
        .collect()
}

pub fn normalize_sender_address(address: &str) -> Option<String> {
    let trimmed = address.trim();
    let candidate = trimmed
        .rsplit_once('<')
        .map_or(trimmed, |(_, after_open)| {
            after_open
                .split_once('>')
                .map_or(after_open, |(sender, _)| sender)
        })
        .trim()
        .trim_matches('"')
        .trim_matches('\'');

    if candidate.is_empty()
        || !candidate.contains('@')
        || candidate.chars().any(char::is_whitespace)
        || candidate.starts_with('@')
        || candidate.ends_with('@')
    {
        return None;
    }
    Some(candidate.to_ascii_lowercase())
}

pub fn is_automated_sender(address: &str, headers: &[(&str, &str)]) -> bool {
    const NOREPLY_PATTERNS: &[&str] = &[
        "noreply",
        "no-reply",
        "no_reply",
        "donotreply",
        "do-not-reply",
        "mailer-daemon",
        "postmaster",
        "bounce",
        "notifications@",
        "automated@",
        "auto-confirm",
        "auto-reply",
        "automailer",
    ];

    let normalized =
        normalize_sender_address(address).unwrap_or_else(|| address.trim().to_ascii_lowercase());
    if NOREPLY_PATTERNS
        .iter()
        .any(|pattern| normalized.contains(pattern))
    {
        return true;
    }

    headers.iter().any(|(name, value)| {
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if value.is_empty() {
            return false;
        }
        match name.as_str() {
            "auto-submitted" => !value.eq_ignore_ascii_case("no"),
            "precedence" => matches!(
                value.to_ascii_lowercase().as_str(),
                "bulk" | "list" | "junk"
            ),
            "x-auto-response-suppress" | "list-unsubscribe" => true,
            _ => false,
        }
    })
}

#[must_use]
pub fn classify_email_attachment(filename: &str, media_type: &str) -> EmailAttachmentClass {
    const IMAGE_EXTS: &[&str] = &["jpg", "jpeg", "png", "gif", "webp"];

    let media_type = media_type.trim().to_ascii_lowercase();
    if media_type.starts_with("image/") {
        return EmailAttachmentClass::Image;
    }
    let ext = filename
        .rsplit_once('.')
        .map(|(_, ext)| ext.trim().to_ascii_lowercase());
    if ext.as_deref().is_some_and(|ext| IMAGE_EXTS.contains(&ext)) {
        return EmailAttachmentClass::Image;
    }
    EmailAttachmentClass::Document
}

impl EmailSeenUidCache {
    pub fn new(cap: usize) -> FcpResult<Self> {
        if cap == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "seen UID cache cap must be greater than zero".into(),
            });
        }
        Ok(Self {
            cap,
            seen: BTreeSet::new(),
            order: VecDeque::new(),
        })
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    #[must_use]
    pub fn contains(&self, uid: &str) -> bool {
        self.seen.contains(uid)
    }

    pub fn observe(&mut self, uid: impl Into<String>) -> bool {
        let uid = uid.into();
        if self.seen.contains(&uid) {
            return false;
        }
        self.seen.insert(uid.clone());
        self.order.push_back(uid);
        if self.seen.len() > self.cap {
            self.trim_to_recent_half();
        }
        true
    }

    fn trim_to_recent_half(&mut self) {
        let keep = (self.cap / 2).max(1);
        let parsed = self
            .seen
            .iter()
            .map(|uid| uid.parse::<u128>().ok().map(|number| (number, uid.clone())))
            .collect::<Option<Vec<_>>>();

        if let Some(mut parsed) = parsed {
            parsed.sort_by_key(|(number, _)| *number);
            let keep_start = parsed.len().saturating_sub(keep);
            self.seen = parsed
                .into_iter()
                .skip(keep_start)
                .map(|(_, uid)| uid)
                .collect();
            self.order.retain(|uid| self.seen.contains(uid));
            return;
        }

        while self.seen.len() > keep {
            if let Some(uid) = self.order.pop_front() {
                self.seen.remove(&uid);
            } else {
                break;
            }
        }
    }
}

impl EmailMonitorPolicy {
    pub fn validate(&self) -> FcpResult<()> {
        let senders = self.normalized_allowed_senders()?;
        if self.allowed_senders.len() > MAX_ALLOWED_SENDERS {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("allowed_senders must have at most {MAX_ALLOWED_SENDERS} entries"),
            });
        }
        if senders.len() != self.allowed_senders.len() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "allowed_senders must not contain duplicates after normalization".into(),
            });
        }
        if self.poll_interval_secs == 0 || self.poll_interval_secs > MAX_POLL_INTERVAL_SECS {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "monitor_policy.poll_interval_secs must be between 1 and {MAX_POLL_INTERVAL_SECS}"
                ),
            });
        }
        if self.max_body_chars == 0 || self.max_body_chars > MAX_BODY_CHARS_LIMIT {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "monitor_policy.max_body_chars must be between 1 and {MAX_BODY_CHARS_LIMIT}"
                ),
            });
        }
        if self.seen_uid_cap == 0 || self.seen_uid_cap > MAX_SEEN_UID_CAP_LIMIT {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "monitor_policy.seen_uid_cap must be between 1 and {MAX_SEEN_UID_CAP_LIMIT}"
                ),
            });
        }
        Ok(())
    }

    pub fn normalized_allowed_senders(&self) -> FcpResult<BTreeSet<String>> {
        self.allowed_senders
            .iter()
            .map(|sender| {
                normalize_sender_address(sender).ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid allowed sender address: {sender}"),
                })
            })
            .collect()
    }

    pub fn allows_sender(&self, address: &str) -> bool {
        if !self.require_allowed_sender && self.allowed_senders.is_empty() {
            return true;
        }
        let Some(sender) = normalize_sender_address(address) else {
            return false;
        };
        self.normalized_allowed_senders()
            .is_ok_and(|allowed| allowed.contains(&sender))
    }

    pub fn evaluate_sender(
        &self,
        address: &str,
        headers: &[(&str, &str)],
    ) -> EmailInboundPolicyDecision {
        if self.drop_automated && is_automated_sender(address, headers) {
            return EmailInboundPolicyDecision::DropAutomated;
        }
        if !self.allows_sender(address) {
            return EmailInboundPolicyDecision::DropSenderNotAllowed;
        }
        EmailInboundPolicyDecision::Accept
    }

    pub fn redacted_state(&self) -> Value {
        json!({
            "allowed_senders_configured": !self.allowed_senders.is_empty(),
            "allowed_senders_count": self.allowed_senders.len(),
            "require_allowed_sender": self.require_allowed_sender,
            "drop_automated": self.drop_automated,
            "allow_attachments": self.allow_attachments,
            "poll_interval_secs": self.poll_interval_secs,
            "max_body_chars": self.max_body_chars,
            "seen_uid_cap": self.seen_uid_cap,
        })
    }

    #[must_use]
    pub fn bound_body(&self, body: &str) -> EmailBoundedBody {
        let original_chars = body.chars().count();
        if original_chars <= self.max_body_chars {
            return EmailBoundedBody {
                text: body.to_owned(),
                original_chars,
                truncated: false,
            };
        }
        EmailBoundedBody {
            text: body.chars().take(self.max_body_chars).collect(),
            original_chars,
            truncated: true,
        }
    }

    #[must_use]
    pub fn event_text(&self, subject: &str, body: &str) -> EmailBoundedBody {
        let subject = subject.trim();
        let body = body.trim();
        let text = if subject.is_empty() || subject.to_ascii_lowercase().starts_with("re:") {
            body.to_owned()
        } else {
            format!("[Subject: {subject}]\n\n{body}")
        };
        self.bound_body(&text)
    }

    #[must_use]
    pub fn evaluate_attachment(
        &self,
        attachment: &EmailAttachmentCandidate,
    ) -> EmailAttachmentSummary {
        let class = classify_email_attachment(&attachment.filename, &attachment.media_type);
        let exposed = self.allow_attachments;
        EmailAttachmentSummary {
            filename: attachment.filename.clone(),
            media_type: attachment.media_type.clone(),
            size_bytes: attachment.size_bytes,
            class,
            exposed,
            reason: (!exposed).then(|| "attachments_disabled".to_owned()),
        }
    }

    #[must_use]
    pub fn prepare_inbound_message(&self, message: &EmailInboundMessage) -> EmailInboundPreview {
        let headers = message
            .headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect::<Vec<_>>();
        let decision = self.evaluate_sender(&message.sender, &headers);
        if decision != EmailInboundPolicyDecision::Accept {
            return EmailInboundPreview {
                decision,
                text: None,
                attachments: Vec::new(),
                thread: None,
                tainted: true,
            };
        }

        EmailInboundPreview {
            decision,
            text: Some(self.event_text(&message.subject, &message.body)),
            attachments: message
                .attachments
                .iter()
                .map(|attachment| self.evaluate_attachment(attachment))
                .collect(),
            thread: Some(EmailThreadMetadata::from_inbound(message)),
            tainted: true,
        }
    }
}

impl EmailThreadMetadata {
    #[must_use]
    pub fn from_inbound(message: &EmailInboundMessage) -> Self {
        let subject = message.subject.trim();
        let reply_subject = if subject.is_empty() {
            "Re: (no subject)".to_owned()
        } else if subject.to_ascii_lowercase().starts_with("re:") {
            subject.to_owned()
        } else {
            format!("Re: {subject}")
        };
        Self {
            subject: subject.to_owned(),
            message_id: message.message_id.clone(),
            in_reply_to: message.in_reply_to.clone(),
            references: message.references.clone(),
            reply_subject,
        }
    }
}

impl EmailGenericConfig {
    pub fn from_value(value: Value) -> FcpResult<Self> {
        let config: Self =
            serde_json::from_value(value).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid generic email config: {error}"),
            })?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> FcpResult<()> {
        if self.imap.host.trim().is_empty() || self.smtp.host.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "imap.host and smtp.host must not be empty".into(),
            });
        }
        if self.imap.username.trim().is_empty()
            || self.imap.password.trim().is_empty()
            || self.smtp.username.trim().is_empty()
            || self.smtp.password.trim().is_empty()
            || self.smtp.from_address.trim().is_empty()
        {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "email credentials and from_address must not be empty".into(),
            });
        }
        if self.request_timeout_ms == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "request_timeout_ms must be greater than zero".into(),
            });
        }
        self.monitor_policy.validate()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config_json() -> Value {
        serde_json::json!({
            "imap": {
                "host": "imap.example.com",
                "username": "user@example.com",
                "password": "secret"
            },
            "smtp": {
                "host": "smtp.example.com",
                "username": "user@example.com",
                "password": "secret",
                "from_address": "user@example.com"
            }
        })
    }

    fn inbound_message() -> EmailInboundMessage {
        EmailInboundMessage {
            uid: "42".into(),
            sender: "Allowed@Example.com".into(),
            headers: Vec::new(),
            subject: "Deploy status".into(),
            body: "green".into(),
            message_id: Some("<msg-42@example.com>".into()),
            in_reply_to: Some("<parent@example.com>".into()),
            references: Some("<root@example.com> <parent@example.com>".into()),
            attachments: vec![EmailAttachmentCandidate {
                filename: "report.pdf".into(),
                media_type: "application/pdf".into(),
                size_bytes: 256,
            }],
        }
    }

    #[test]
    fn config_parses_successfully() {
        let config =
            EmailGenericConfig::from_value(valid_config_json()).expect("config should parse");
        assert_eq!(config.imap.port, 993);
        assert_eq!(config.smtp.port, 587);
    }

    #[test]
    fn config_defaults_imap_port_to_993() {
        let config = EmailGenericConfig::from_value(valid_config_json()).unwrap();
        assert_eq!(config.imap.port, 993);
    }

    #[test]
    fn config_defaults_smtp_port_to_587() {
        let config = EmailGenericConfig::from_value(valid_config_json()).unwrap();
        assert_eq!(config.smtp.port, 587);
    }

    #[test]
    fn config_defaults_tls_to_true() {
        let config = EmailGenericConfig::from_value(valid_config_json()).unwrap();
        assert!(config.imap.tls);
    }

    #[test]
    fn config_defaults_starttls_to_true() {
        let config = EmailGenericConfig::from_value(valid_config_json()).unwrap();
        assert!(config.smtp.starttls);
    }

    #[test]
    fn config_defaults_timeout_to_15000() {
        let config = EmailGenericConfig::from_value(valid_config_json()).unwrap();
        assert_eq!(config.request_timeout_ms, 15_000);
    }

    #[test]
    fn config_defaults_monitor_policy_to_closed_inbound_gate() {
        let config = EmailGenericConfig::from_value(valid_config_json()).unwrap();
        assert!(config.monitor_policy.require_allowed_sender);
        assert!(config.monitor_policy.drop_automated);
        assert!(!config.monitor_policy.allow_attachments);
        assert_eq!(config.monitor_policy.poll_interval_secs, 15);
        assert_eq!(config.monitor_policy.max_body_chars, 50_000);
        assert_eq!(config.monitor_policy.seen_uid_cap, 2_000);
        assert_eq!(
            config
                .monitor_policy
                .evaluate_sender("person@example.com", &[]),
            EmailInboundPolicyDecision::DropSenderNotAllowed
        );
    }

    #[test]
    fn config_accepts_custom_ports() {
        let config = EmailGenericConfig::from_value(serde_json::json!({
            "imap": { "host": "h", "port": 143, "username": "u", "password": "p" },
            "smtp": { "host": "h", "port": 25, "username": "u", "password": "p", "from_address": "a@b.com" }
        })).unwrap();
        assert_eq!(config.imap.port, 143);
        assert_eq!(config.smtp.port, 25);
    }

    #[test]
    fn config_rejects_empty_imap_host() {
        let result = EmailGenericConfig::from_value(serde_json::json!({
            "imap": { "host": "  ", "username": "u", "password": "p" },
            "smtp": { "host": "h", "username": "u", "password": "p", "from_address": "a@b.com" }
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_smtp_host() {
        let result = EmailGenericConfig::from_value(serde_json::json!({
            "imap": { "host": "h", "username": "u", "password": "p" },
            "smtp": { "host": "  ", "username": "u", "password": "p", "from_address": "a@b.com" }
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_imap_username() {
        let result = EmailGenericConfig::from_value(serde_json::json!({
            "imap": { "host": "h", "username": "  ", "password": "p" },
            "smtp": { "host": "h", "username": "u", "password": "p", "from_address": "a@b.com" }
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_imap_password() {
        let result = EmailGenericConfig::from_value(serde_json::json!({
            "imap": { "host": "h", "username": "u", "password": "  " },
            "smtp": { "host": "h", "username": "u", "password": "p", "from_address": "a@b.com" }
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_smtp_from_address() {
        let result = EmailGenericConfig::from_value(serde_json::json!({
            "imap": { "host": "h", "username": "u", "password": "p" },
            "smtp": { "host": "h", "username": "u", "password": "p", "from_address": "  " }
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_zero_timeout() {
        let result = EmailGenericConfig::from_value(serde_json::json!({
            "imap": { "host": "h", "username": "u", "password": "p" },
            "smtp": { "host": "h", "username": "u", "password": "p", "from_address": "a@b.com" },
            "request_timeout_ms": 0
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_missing_imap() {
        let result = EmailGenericConfig::from_value(serde_json::json!({
            "smtp": { "host": "h", "username": "u", "password": "p", "from_address": "a@b.com" }
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_missing_smtp() {
        let result = EmailGenericConfig::from_value(serde_json::json!({
            "imap": { "host": "h", "username": "u", "password": "p" }
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_accepts_optional_from_name() {
        let config = EmailGenericConfig::from_value(serde_json::json!({
            "imap": { "host": "h", "username": "u", "password": "p" },
            "smtp": { "host": "h", "username": "u", "password": "p", "from_address": "a@b.com", "from_name": "Test User" }
        })).unwrap();
        assert_eq!(config.smtp.from_name.as_deref(), Some("Test User"));
    }

    #[test]
    fn config_from_name_defaults_to_none() {
        let config = EmailGenericConfig::from_value(valid_config_json()).unwrap();
        assert!(config.smtp.from_name.is_none());
    }

    #[test]
    fn monitor_policy_accepts_comma_separated_allowed_senders() {
        let config = EmailGenericConfig::from_value(serde_json::json!({
            "imap": { "host": "h", "username": "u", "password": "p" },
            "smtp": { "host": "h", "username": "u", "password": "p", "from_address": "a@b.com" },
            "monitor_policy": {
                "allowed_senders": "User@Example.com, Other@example.com"
            }
        }))
        .unwrap();
        assert_eq!(
            config
                .monitor_policy
                .evaluate_sender("user@example.com", &[]),
            EmailInboundPolicyDecision::Accept
        );
        assert_eq!(
            config
                .monitor_policy
                .evaluate_sender("other@example.com", &[]),
            EmailInboundPolicyDecision::Accept
        );
    }

    #[test]
    fn monitor_policy_allows_display_name_addresses() {
        let policy = EmailMonitorPolicy {
            allowed_senders: vec!["Alice <Alice@Example.com>".into()],
            ..EmailMonitorPolicy::default()
        };
        assert_eq!(
            policy.evaluate_sender("alice@example.com", &[]),
            EmailInboundPolicyDecision::Accept
        );
    }

    #[test]
    fn monitor_policy_can_allow_all_non_automated_when_explicitly_configured() {
        let policy = EmailMonitorPolicy {
            require_allowed_sender: false,
            ..EmailMonitorPolicy::default()
        };
        assert_eq!(
            policy.evaluate_sender("person@example.com", &[]),
            EmailInboundPolicyDecision::Accept
        );
    }

    #[test]
    fn monitor_policy_drops_noreply_pattern_before_allowlist() {
        let policy = EmailMonitorPolicy {
            allowed_senders: vec!["notifications@example.com".into()],
            ..EmailMonitorPolicy::default()
        };
        assert_eq!(
            policy.evaluate_sender("notifications@example.com", &[]),
            EmailInboundPolicyDecision::DropAutomated
        );
    }

    #[test]
    fn monitor_policy_drops_automated_headers() {
        let policy = EmailMonitorPolicy {
            allowed_senders: vec!["person@example.com".into()],
            ..EmailMonitorPolicy::default()
        };
        assert_eq!(
            policy.evaluate_sender(
                "person@example.com",
                &[("Auto-Submitted", "auto-generated")]
            ),
            EmailInboundPolicyDecision::DropAutomated
        );
        assert_eq!(
            policy.evaluate_sender("person@example.com", &[("Precedence", "bulk")]),
            EmailInboundPolicyDecision::DropAutomated
        );
        assert_eq!(
            policy.evaluate_sender("person@example.com", &[("Auto-Submitted", "no")]),
            EmailInboundPolicyDecision::Accept
        );
    }

    #[test]
    fn monitor_policy_redacted_state_hides_sender_values() {
        let policy = EmailMonitorPolicy {
            allowed_senders: vec!["secret@example.com".into()],
            allow_attachments: true,
            ..EmailMonitorPolicy::default()
        };
        let state = policy.redacted_state();
        assert_eq!(state["allowed_senders_count"], 1);
        assert_eq!(state["allowed_senders_configured"], true);
        assert_eq!(state["allow_attachments"], true);
        assert!(!state.to_string().contains("secret@example.com"));
    }

    #[test]
    fn monitor_policy_rejects_invalid_sender() {
        let result = EmailGenericConfig::from_value(serde_json::json!({
            "imap": { "host": "h", "username": "u", "password": "p" },
            "smtp": { "host": "h", "username": "u", "password": "p", "from_address": "a@b.com" },
            "monitor_policy": { "allowed_senders": ["not an address"] }
        }));
        assert!(result.is_err());
    }

    #[test]
    fn monitor_policy_rejects_duplicate_sender_after_normalization() {
        let result = EmailGenericConfig::from_value(serde_json::json!({
            "imap": { "host": "h", "username": "u", "password": "p" },
            "smtp": { "host": "h", "username": "u", "password": "p", "from_address": "a@b.com" },
            "monitor_policy": { "allowed_senders": ["USER@example.com", "user@example.com"] }
        }));
        assert!(result.is_err());
    }

    #[test]
    fn monitor_policy_rejects_zero_bounds() {
        for policy in [
            serde_json::json!({ "poll_interval_secs": 0 }),
            serde_json::json!({ "max_body_chars": 0 }),
            serde_json::json!({ "seen_uid_cap": 0 }),
        ] {
            let result = EmailGenericConfig::from_value(serde_json::json!({
                "imap": { "host": "h", "username": "u", "password": "p" },
                "smtp": { "host": "h", "username": "u", "password": "p", "from_address": "a@b.com" },
                "monitor_policy": policy
            }));
            assert!(result.is_err());
        }
    }

    #[test]
    fn classify_email_attachment_detects_images_from_type_or_extension() {
        assert_eq!(
            classify_email_attachment("photo.bin", "image/png"),
            EmailAttachmentClass::Image
        );
        assert_eq!(
            classify_email_attachment("photo.WEBP", "application/octet-stream"),
            EmailAttachmentClass::Image
        );
        assert_eq!(
            classify_email_attachment("report.pdf", "application/pdf"),
            EmailAttachmentClass::Document
        );
    }

    #[test]
    fn monitor_policy_denies_attachment_exposure_by_default() {
        let policy = EmailMonitorPolicy::default();
        let summary = policy.evaluate_attachment(&EmailAttachmentCandidate {
            filename: "photo.png".into(),
            media_type: "image/png".into(),
            size_bytes: 1024,
        });
        assert_eq!(summary.class, EmailAttachmentClass::Image);
        assert!(!summary.exposed);
        assert_eq!(summary.reason.as_deref(), Some("attachments_disabled"));
    }

    #[test]
    fn monitor_policy_allows_attachment_exposure_when_configured() {
        let policy = EmailMonitorPolicy {
            allow_attachments: true,
            ..EmailMonitorPolicy::default()
        };
        let summary = policy.evaluate_attachment(&EmailAttachmentCandidate {
            filename: "report.pdf".into(),
            media_type: "application/pdf".into(),
            size_bytes: 2048,
        });
        assert_eq!(summary.class, EmailAttachmentClass::Document);
        assert!(summary.exposed);
        assert_eq!(summary.reason, None);
    }

    #[test]
    fn monitor_policy_bounds_event_text_after_subject_context() {
        let policy = EmailMonitorPolicy {
            max_body_chars: 12,
            ..EmailMonitorPolicy::default()
        };
        let body = policy.event_text("Deploy", "abcdefghijkl");
        assert!(body.truncated);
        assert_eq!(body.original_chars, 31);
        assert_eq!(body.text, "[Subject: De");
    }

    #[test]
    fn monitor_policy_does_not_prefix_reply_subjects() {
        let policy = EmailMonitorPolicy {
            max_body_chars: 100,
            ..EmailMonitorPolicy::default()
        };
        let body = policy.event_text("Re: Deploy", "body");
        assert_eq!(body.text, "body");
        assert!(!body.truncated);
    }

    #[test]
    fn prepare_inbound_message_drops_disallowed_before_body_or_thread_context() {
        let policy = EmailMonitorPolicy {
            allowed_senders: vec!["other@example.com".into()],
            ..EmailMonitorPolicy::default()
        };
        let preview = policy.prepare_inbound_message(&inbound_message());
        assert_eq!(
            preview.decision,
            EmailInboundPolicyDecision::DropSenderNotAllowed
        );
        assert_eq!(preview.text, None);
        assert!(preview.attachments.is_empty());
        assert_eq!(preview.thread, None);
        assert!(preview.tainted);
    }

    #[test]
    fn prepare_inbound_message_shapes_allowed_content_without_exposing_attachments() {
        let policy = EmailMonitorPolicy {
            allowed_senders: vec!["allowed@example.com".into()],
            max_body_chars: 1000,
            ..EmailMonitorPolicy::default()
        };
        let preview = policy.prepare_inbound_message(&inbound_message());
        assert_eq!(preview.decision, EmailInboundPolicyDecision::Accept);
        assert_eq!(
            preview.text.expect("accepted text").text,
            "[Subject: Deploy status]\n\ngreen"
        );
        assert_eq!(preview.attachments.len(), 1);
        assert!(!preview.attachments[0].exposed);
        let thread = preview.thread.expect("thread metadata");
        assert_eq!(thread.reply_subject, "Re: Deploy status");
        assert_eq!(thread.message_id.as_deref(), Some("<msg-42@example.com>"));
    }

    #[test]
    fn prepare_inbound_message_drops_automated_before_allowlisted_content() {
        let policy = EmailMonitorPolicy {
            allowed_senders: vec!["allowed@example.com".into()],
            ..EmailMonitorPolicy::default()
        };
        let mut message = inbound_message();
        message
            .headers
            .push(("Auto-Submitted".into(), "auto-generated".into()));
        let preview = policy.prepare_inbound_message(&message);
        assert_eq!(preview.decision, EmailInboundPolicyDecision::DropAutomated);
        assert_eq!(preview.text, None);
        assert_eq!(preview.thread, None);
    }

    #[test]
    fn seen_uid_cache_rejects_duplicates_and_trims_numeric_uids() {
        let mut cache = EmailSeenUidCache::new(4).expect("cache");
        for uid in ["1", "2", "3", "4"] {
            assert!(cache.observe(uid));
        }
        assert_eq!(cache.len(), 4);
        assert!(!cache.observe("3"));
        assert!(cache.observe("5"));
        assert_eq!(cache.len(), 2);
        assert!(!cache.contains("1"));
        assert!(!cache.contains("3"));
        assert!(cache.contains("4"));
        assert!(cache.contains("5"));
    }

    #[test]
    fn seen_uid_cache_trims_nonnumeric_uids_by_insertion_order() {
        let mut cache = EmailSeenUidCache::new(4).expect("cache");
        for uid in ["a", "b", "c", "d", "e"] {
            assert!(cache.observe(uid));
        }
        assert_eq!(cache.len(), 2);
        assert!(!cache.contains("a"));
        assert!(!cache.contains("c"));
        assert!(cache.contains("d"));
        assert!(cache.contains("e"));
    }

    #[test]
    fn seen_uid_cache_rejects_zero_cap() {
        assert!(EmailSeenUidCache::new(0).is_err());
    }
}
