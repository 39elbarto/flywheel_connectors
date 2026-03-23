//! QQ API configuration and response types.

use serde::Deserialize;

pub const DEFAULT_BASE_URL: &str = "https://api.sgroup.qq.com";
pub const DEFAULT_TOKEN_BASE_URL: &str = "https://bots.qq.com";
pub const DEFAULT_TIMEOUT_MS: u64 = 30_000;
pub const TOKEN_REFRESH_SAFETY_MARGIN_SECS: u64 = 60;

pub const OP_SEND_CHANNEL: &str = "qq.messages.send_channel";
pub const OP_SEND_GROUP: &str = "qq.messages.send_group";
pub const OP_SEND_C2C: &str = "qq.messages.send_c2c";
pub const OP_GET_GATEWAY: &str = "qq.gateway.get";
pub const OP_HEALTH: &str = "qq.health";

pub const CAP_MESSAGES_WRITE: &str = "qq.messages.write";
pub const CAP_GATEWAY_READ: &str = "qq.gateway.read";
pub const CAP_HEALTH_READ: &str = "qq.health.read";

#[derive(Clone, Deserialize)]
pub struct QqConfig {
    #[serde(default = "default_base_url")]
    pub base_url: String,
    #[serde(default = "default_token_base_url")]
    pub token_base_url: String,
    pub app_id: String,
    pub client_secret: String,
    #[serde(default = "default_timeout_ms")]
    pub request_timeout_ms: u64,
}

// Redact client_secret in Debug output
impl std::fmt::Debug for QqConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QqConfig")
            .field("base_url", &self.base_url)
            .field("token_base_url", &self.token_base_url)
            .field("app_id", &self.app_id)
            .field("client_secret", &"[REDACTED]")
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

fn default_base_url() -> String {
    DEFAULT_BASE_URL.to_string()
}

fn default_token_base_url() -> String {
    DEFAULT_TOKEN_BASE_URL.to_string()
}

const fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}

#[derive(Deserialize)]
pub struct AccessTokenResponse {
    #[serde(default)]
    pub access_token: String,
    #[serde(default)]
    pub expires_in: u64,
}

impl std::fmt::Debug for AccessTokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessTokenResponse")
            .field("access_token", &"[REDACTED]")
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_deserializes_defaults() {
        let json = r#"{
            "app_id": "test_id",
            "client_secret": "test_secret"
        }"#;
        let config: QqConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
        assert_eq!(config.token_base_url, DEFAULT_TOKEN_BASE_URL);
        assert_eq!(config.request_timeout_ms, DEFAULT_TIMEOUT_MS);
        assert_eq!(config.app_id, "test_id");
        assert_eq!(config.client_secret, "test_secret");
    }

    #[test]
    fn config_debug_redacts_secret() {
        let json = r#"{
            "app_id": "myid",
            "client_secret": "super_secret_value"
        }"#;
        let config: QqConfig = serde_json::from_str(json).unwrap();
        let debug = format!("{config:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super_secret_value"));
        assert!(debug.contains("myid"));
    }

    #[test]
    fn config_with_custom_urls() {
        let json = r#"{
            "base_url": "http://localhost:8080",
            "token_base_url": "http://localhost:8081",
            "app_id": "app1",
            "client_secret": "sec1",
            "request_timeout_ms": 5000
        }"#;
        let config: QqConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.base_url, "http://localhost:8080");
        assert_eq!(config.token_base_url, "http://localhost:8081");
        assert_eq!(config.request_timeout_ms, 5000);
    }

    #[test]
    fn access_token_response_deserializes() {
        let json = r#"{"access_token": "tok_abc", "expires_in": 7200}"#;
        let resp: AccessTokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.access_token, "tok_abc");
        assert_eq!(resp.expires_in, 7200);
    }

    #[test]
    fn access_token_response_defaults() {
        let json = r"{}";
        let resp: AccessTokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.access_token, "");
        assert_eq!(resp.expires_in, 0);
    }

    #[test]
    fn access_token_response_debug_redacts_token() {
        let resp = AccessTokenResponse {
            access_token: "super_secret_token_value".into(),
            expires_in: 7200,
        };
        let debug = format!("{resp:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super_secret_token_value"));
        assert!(debug.contains("7200"));
    }

    #[test]
    fn constants_are_correct() {
        assert_eq!(OP_SEND_CHANNEL, "qq.messages.send_channel");
        assert_eq!(OP_SEND_GROUP, "qq.messages.send_group");
        assert_eq!(OP_SEND_C2C, "qq.messages.send_c2c");
        assert_eq!(OP_GET_GATEWAY, "qq.gateway.get");
        assert_eq!(OP_HEALTH, "qq.health");
        assert_eq!(CAP_MESSAGES_WRITE, "qq.messages.write");
        assert_eq!(CAP_GATEWAY_READ, "qq.gateway.read");
        assert_eq!(CAP_HEALTH_READ, "qq.health.read");
    }
}
