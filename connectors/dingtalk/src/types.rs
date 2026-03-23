//! `DingTalk` API and configuration types.

use serde::Deserialize;

pub const DEFAULT_BASE_URL: &str = "https://api.dingtalk.com";
pub const DEFAULT_MEDIA_BASE_URL: &str = "https://oapi.dingtalk.com";
pub const DEFAULT_TIMEOUT_MS: u64 = 30_000;
pub const TOKEN_REFRESH_SAFETY_MARGIN_SECS: u64 = 60;

#[derive(Clone, Deserialize)]
pub struct DingTalkConfig {
    #[serde(default = "default_base_url")]
    pub base_url: String,
    #[serde(default = "default_media_base_url")]
    pub media_base_url: String,
    pub client_id: String,
    pub client_secret: String,
    #[serde(default = "default_timeout_ms")]
    pub request_timeout_ms: u64,
}

// Redact client_secret in Debug output
impl std::fmt::Debug for DingTalkConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DingTalkConfig")
            .field("base_url", &self.base_url)
            .field("media_base_url", &self.media_base_url)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

fn default_base_url() -> String {
    DEFAULT_BASE_URL.to_string()
}

fn default_media_base_url() -> String {
    DEFAULT_MEDIA_BASE_URL.to_string()
}

const fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessTokenResponse {
    #[serde(default)]
    pub access_token: String,
    #[serde(default)]
    pub expire_in: u64,
}

/// Parsed target for `DingTalk` message routing.
#[derive(Debug, Clone, Copy)]
pub struct ParsedTarget<'a> {
    pub id: &'a str,
    pub is_group: bool,
}

impl<'a> ParsedTarget<'a> {
    #[allow(clippy::option_if_let_else)]
    #[must_use]
    pub fn parse(raw: &'a str) -> Self {
        if let Some(id) = raw.strip_prefix("chat:") {
            Self { id, is_group: true }
        } else if let Some(id) = raw.strip_prefix("user:") {
            Self {
                id,
                is_group: false,
            }
        } else {
            Self {
                id: raw,
                is_group: false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_deserializes_defaults() {
        let json = r#"{
            "client_id": "test_id",
            "client_secret": "test_secret"
        }"#;
        let config: DingTalkConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
        assert_eq!(config.media_base_url, DEFAULT_MEDIA_BASE_URL);
        assert_eq!(config.request_timeout_ms, DEFAULT_TIMEOUT_MS);
        assert_eq!(config.client_id, "test_id");
        assert_eq!(config.client_secret, "test_secret");
    }

    #[test]
    fn config_debug_redacts_secret() {
        let json = r#"{
            "client_id": "myid",
            "client_secret": "super_secret_value"
        }"#;
        let config: DingTalkConfig = serde_json::from_str(json).unwrap();
        let debug = format!("{config:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super_secret_value"));
        assert!(debug.contains("myid"));
    }

    #[test]
    fn parsed_target_chat_prefix() {
        let target = ParsedTarget::parse("chat:group123");
        assert_eq!(target.id, "group123");
        assert!(target.is_group);
    }

    #[test]
    fn parsed_target_user_prefix() {
        let target = ParsedTarget::parse("user:user456");
        assert_eq!(target.id, "user456");
        assert!(!target.is_group);
    }

    #[test]
    fn parsed_target_bare_id() {
        let target = ParsedTarget::parse("some_bare_id");
        assert_eq!(target.id, "some_bare_id");
        assert!(!target.is_group);
    }

    #[test]
    fn access_token_response_deserializes() {
        let json = r#"{"accessToken": "tok_abc", "expireIn": 7200}"#;
        let resp: AccessTokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.access_token, "tok_abc");
        assert_eq!(resp.expire_in, 7200);
    }
}
