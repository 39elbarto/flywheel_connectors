//! Configuration types for the generic email connector.

use fcp_prelude::{FcpError, FcpResult};
use std::collections::BTreeSet;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailInboundPolicyDecision {
    Accept,
    DropAutomated,
    DropSenderNotAllowed,
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
        .rfind('<')
        .map_or(trimmed, |start| {
            trimmed[start + 1..]
                .find('>')
                .map_or(&trimmed[start + 1..], |end| {
                    &trimmed[start + 1..start + 1 + end]
                })
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
}
