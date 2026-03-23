//! `WeCom` API and configuration types.

use fcp_core::{FcpError, FcpResult};
use reqwest::Url;
use serde::Deserialize;
use serde_json::Value;

pub const DEFAULT_BASE_URL: &str = "https://qyapi.weixin.qq.com";
pub const DEFAULT_TIMEOUT_MS: u64 = 30_000;
pub const TOKEN_REFRESH_SAFETY_MARGIN_SECS: u64 = 60;

pub const OP_SEND_TEXT: &str = "wecom.messages.send_text";
pub const OP_SEND_MARKDOWN: &str = "wecom.messages.send_markdown";
pub const OP_UPLOAD_MEDIA: &str = "wecom.media.upload";
pub const OP_GET_USER: &str = "wecom.users.get";
pub const OP_LIST_DEPARTMENTS: &str = "wecom.departments.list";
pub const OP_HEALTH: &str = "wecom.health";

pub const CAP_MESSAGES_WRITE: &str = "wecom.messages.write";
pub const CAP_MEDIA_WRITE: &str = "wecom.media.write";
pub const CAP_USERS_READ: &str = "wecom.users.read";
pub const CAP_DEPARTMENTS_READ: &str = "wecom.departments.read";
pub const CAP_HEALTH_READ: &str = "wecom.health.read";

#[derive(Clone, Deserialize)]
pub struct WeComConfig {
    #[serde(default = "default_base_url")]
    pub base_url: String,
    pub corp_id: String,
    pub agent_id: u64,
    pub agent_secret: String,
    #[serde(default = "default_timeout_ms")]
    pub request_timeout_ms: u64,
}

// Redact agent_secret in Debug output
impl std::fmt::Debug for WeComConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WeComConfig")
            .field("base_url", &self.base_url)
            .field("corp_id", &self.corp_id)
            .field("agent_id", &self.agent_id)
            .field("agent_secret", &"[REDACTED]")
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

fn default_base_url() -> String {
    DEFAULT_BASE_URL.to_string()
}

const fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}

impl WeComConfig {
    /// Validate the configuration for required fields and allowed hosts.
    ///
    /// # Errors
    ///
    /// Returns an error if required fields are empty, `agent_id` is zero,
    /// `request_timeout_ms` is zero, or the `base_url` host is not allowed.
    pub fn validate(&self) -> FcpResult<()> {
        if self.corp_id.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "corp_id must not be empty".into(),
            });
        }
        if self.agent_secret.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "agent_secret must not be empty".into(),
            });
        }
        if self.agent_id == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "agent_id must be greater than zero".into(),
            });
        }
        if self.request_timeout_ms == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "request_timeout_ms must be greater than zero".into(),
            });
        }

        let base_url =
            Url::parse(self.base_url.trim()).map_err(|error| FcpError::InvalidRequest {
                code: 1001,
                message: format!("invalid base_url: {error}"),
            })?;
        if !matches!(base_url.scheme(), "http" | "https") {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "base_url must use http or https".into(),
            });
        }
        let host = base_url
            .host_str()
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1001,
                message: "base_url must include a host".into(),
            })?;
        if !matches!(host, "qyapi.weixin.qq.com" | "localhost" | "127.0.0.1") {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: format!(
                    "base_url host `{host}` is not allowed; use qyapi.weixin.qq.com or localhost for tests"
                ),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct AccessTokenResponse {
    #[serde(default)]
    pub access_token: String,
    #[serde(default)]
    pub expires_in: u64,
}

/// Parsed message targets for `WeCom` message routing.
#[derive(Debug)]
pub struct MessageTargets<'a> {
    pub touser: &'a str,
    pub toparty: &'a str,
    pub totag: &'a str,
}

/// Extract message targets from invoke input.
///
/// # Errors
///
/// Returns an error if none of `touser`, `toparty`, or `totag` are provided.
pub fn extract_targets(input: &Value) -> FcpResult<MessageTargets<'_>> {
    let touser = input.get("touser").and_then(Value::as_str).unwrap_or("");
    let toparty = input.get("toparty").and_then(Value::as_str).unwrap_or("");
    let totag = input.get("totag").and_then(Value::as_str).unwrap_or("");
    if touser.is_empty() && toparty.is_empty() && totag.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: "at least one target must be provided via touser, toparty, or totag".into(),
        });
    }
    Ok(MessageTargets {
        touser,
        toparty,
        totag,
    })
}

/// Extract a required non-empty string field from a JSON value.
///
/// # Errors
///
/// Returns an error if the field is missing or empty.
pub fn required_string<'a>(value: &'a Value, field: &str) -> FcpResult<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} is required"),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn config_deserializes_defaults() {
        let json = r#"{
            "corp_id": "test_corp",
            "agent_id": 1000002,
            "agent_secret": "test_secret"
        }"#;
        let config: WeComConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
        assert_eq!(config.request_timeout_ms, DEFAULT_TIMEOUT_MS);
        assert_eq!(config.corp_id, "test_corp");
        assert_eq!(config.agent_id, 1_000_002);
        assert_eq!(config.agent_secret, "test_secret");
    }

    #[test]
    fn config_debug_redacts_secret() {
        let json = r#"{
            "corp_id": "mycorp",
            "agent_id": 1000002,
            "agent_secret": "super_secret_value"
        }"#;
        let config: WeComConfig = serde_json::from_str(json).unwrap();
        let debug = format!("{config:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super_secret_value"));
        assert!(debug.contains("mycorp"));
    }

    #[test]
    fn config_rejects_empty_corp_id() {
        let config = WeComConfig {
            base_url: DEFAULT_BASE_URL.to_string(),
            corp_id: String::new(),
            agent_id: 1_000_002,
            agent_secret: "secret".into(),
            request_timeout_ms: DEFAULT_TIMEOUT_MS,
        };
        assert!(matches!(config.validate(), Err(FcpError::InvalidRequest { .. })));
    }

    #[test]
    fn config_rejects_empty_agent_secret() {
        let config = WeComConfig {
            base_url: DEFAULT_BASE_URL.to_string(),
            corp_id: "corp".into(),
            agent_id: 1_000_002,
            agent_secret: String::new(),
            request_timeout_ms: DEFAULT_TIMEOUT_MS,
        };
        assert!(matches!(config.validate(), Err(FcpError::InvalidRequest { .. })));
    }

    #[test]
    fn config_rejects_zero_agent_id() {
        let config = WeComConfig {
            base_url: DEFAULT_BASE_URL.to_string(),
            corp_id: "corp".into(),
            agent_id: 0,
            agent_secret: "secret".into(),
            request_timeout_ms: DEFAULT_TIMEOUT_MS,
        };
        assert!(matches!(config.validate(), Err(FcpError::InvalidRequest { .. })));
    }

    #[test]
    fn config_rejects_disallowed_host() {
        let config = WeComConfig {
            base_url: "https://evil.example.com".into(),
            corp_id: "corp".into(),
            agent_id: 1_000_002,
            agent_secret: "secret".into(),
            request_timeout_ms: DEFAULT_TIMEOUT_MS,
        };
        assert!(matches!(config.validate(), Err(FcpError::InvalidRequest { .. })));
    }

    #[test]
    fn access_token_response_deserializes() {
        let json = r#"{"access_token": "tok_abc", "expires_in": 7200}"#;
        let resp: AccessTokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.access_token, "tok_abc");
        assert_eq!(resp.expires_in, 7200);
    }

    #[test]
    fn extract_targets_requires_at_least_one() {
        let input = json!({});
        assert!(extract_targets(&input).is_err());
    }

    #[test]
    fn extract_targets_accepts_touser() {
        let input = json!({"touser": "zhangsan"});
        let targets = extract_targets(&input).unwrap();
        assert_eq!(targets.touser, "zhangsan");
        assert!(targets.toparty.is_empty());
    }

    #[test]
    fn required_string_returns_value() {
        let input = json!({"content": "hello"});
        assert_eq!(required_string(&input, "content").unwrap(), "hello");
    }

    #[test]
    fn required_string_rejects_missing() {
        let input = json!({});
        assert!(required_string(&input, "content").is_err());
    }

    #[test]
    fn required_string_rejects_empty() {
        let input = json!({"content": "  "});
        assert!(required_string(&input, "content").is_err());
    }
}
