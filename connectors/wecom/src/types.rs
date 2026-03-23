//! Typed configuration and request models for the `WeCom` connector.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use fcp_core::{FcpError, FcpResult};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const DEFAULT_BASE_URL: &str = "https://qyapi.weixin.qq.com";
pub const DEFAULT_TIMEOUT_MS: u64 = 30_000;
pub const TOKEN_REFRESH_SAFETY_MARGIN_SECS: u64 = 60;

#[derive(Clone, Deserialize)]
pub struct WeComConfig {
    #[serde(default = "default_base_url")]
    base_url: String,
    corp_id: String,
    agent_id: u64,
    agent_secret: String,
    #[serde(default = "default_timeout_ms")]
    request_timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WeComStateModel {
    pub base_url: String,
    pub agent_id: u64,
    pub token_cached: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WeComMessageKind {
    Text,
    Markdown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeComMessageTargets {
    touser: String,
    toparty: String,
    totag: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeComMessageRequest {
    targets: WeComMessageTargets,
    content: String,
    safe: bool,
    kind: WeComMessageKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeComMediaUploadRequest {
    media_type: String,
    file_name: String,
    mime_type: String,
    content_base64: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeComUserLookupRequest {
    userid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeComDepartmentListRequest {
    id: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct AccessTokenResponse {
    #[serde(default)]
    pub access_token: String,
    #[serde(default)]
    pub expires_in: u64,
}

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
    pub fn from_value(value: Value) -> FcpResult<Self> {
        let mut config: Self =
            serde_json::from_value(value).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("invalid WeCom configuration: {error}"),
            })?;
        config.normalize();
        config.validate()?;
        Ok(config)
    }

    fn normalize(&mut self) {
        self.base_url = self.base_url.trim().trim_end_matches('/').to_string();
        self.corp_id = self.corp_id.trim().to_string();
        self.agent_secret = self.agent_secret.trim().to_string();
    }

    pub fn validate(&self) -> FcpResult<()> {
        if self.corp_id.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "corp_id must not be empty".into(),
            });
        }
        if self.agent_secret.is_empty() {
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

        let base_url = Url::parse(&self.base_url).map_err(|error| FcpError::InvalidRequest {
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

    #[must_use]
    pub fn state_model(&self, token_cached: bool) -> WeComStateModel {
        WeComStateModel {
            base_url: self.base_url.clone(),
            agent_id: self.agent_id,
            token_cached,
        }
    }

    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    #[must_use]
    pub fn corp_id(&self) -> &str {
        &self.corp_id
    }

    #[must_use]
    pub const fn agent_id(&self) -> u64 {
        self.agent_id
    }

    #[must_use]
    pub fn agent_secret(&self) -> &str {
        &self.agent_secret
    }

    #[must_use]
    pub const fn request_timeout_ms(&self) -> u64 {
        self.request_timeout_ms
    }
}

impl WeComMessageTargets {
    pub fn from_value(input: &Value) -> FcpResult<Self> {
        let touser = optional_trimmed_string(input, "touser");
        let toparty = optional_trimmed_string(input, "toparty");
        let totag = optional_trimmed_string(input, "totag");
        if touser.is_empty() && toparty.is_empty() && totag.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: "at least one target must be provided via touser, toparty, or totag"
                    .into(),
            });
        }
        Ok(Self {
            touser,
            toparty,
            totag,
        })
    }

    #[must_use]
    pub fn touser(&self) -> &str {
        &self.touser
    }

    #[must_use]
    pub fn toparty(&self) -> &str {
        &self.toparty
    }

    #[must_use]
    pub fn totag(&self) -> &str {
        &self.totag
    }
}

impl WeComMessageRequest {
    pub fn from_value(input: &Value, kind: WeComMessageKind) -> FcpResult<Self> {
        Ok(Self {
            targets: WeComMessageTargets::from_value(input)?,
            content: required_string(input, "content")?.to_string(),
            safe: input.get("safe").and_then(Value::as_bool).unwrap_or(false),
            kind,
        })
    }

    #[must_use]
    pub fn to_body(&self, agent_id: u64) -> Value {
        match self.kind {
            WeComMessageKind::Text => json!({
                "touser": self.targets.touser(),
                "toparty": self.targets.toparty(),
                "totag": self.targets.totag(),
                "msgtype": "text",
                "agentid": agent_id,
                "text": { "content": self.content },
                "safe": i32::from(self.safe),
            }),
            WeComMessageKind::Markdown => json!({
                "touser": self.targets.touser(),
                "toparty": self.targets.toparty(),
                "totag": self.targets.totag(),
                "msgtype": "markdown",
                "agentid": agent_id,
                "markdown": { "content": self.content },
            }),
        }
    }
}

impl WeComMediaUploadRequest {
    pub fn from_value(input: &Value) -> FcpResult<Self> {
        let media_type = required_string(input, "media_type")?.to_string();
        if !matches!(media_type.as_str(), "image" | "voice" | "video" | "file") {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: "media_type must be one of image, voice, video, or file".into(),
            });
        }
        Ok(Self {
            media_type,
            file_name: required_string(input, "file_name")?.to_string(),
            mime_type: optional_trimmed_string(input, "mime_type"),
            content_base64: required_string(input, "content_base64")?.to_string(),
        })
    }

    pub fn decode_content(&self) -> Result<Vec<u8>, String> {
        BASE64
            .decode(self.content_base64.trim())
            .map_err(|error| format!("content_base64 must be valid base64: {error}"))
    }

    #[must_use]
    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    #[must_use]
    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    #[must_use]
    pub fn mime_type(&self) -> &str {
        if self.mime_type.is_empty() {
            "application/octet-stream"
        } else {
            &self.mime_type
        }
    }
}

impl WeComUserLookupRequest {
    pub fn from_value(input: &Value) -> FcpResult<Self> {
        Ok(Self {
            userid: required_string(input, "userid")?.to_string(),
        })
    }

    #[must_use]
    pub fn userid(&self) -> &str {
        &self.userid
    }
}

impl WeComDepartmentListRequest {
    pub fn from_value(input: &Value) -> FcpResult<Self> {
        let id = match input.get("id") {
            Some(value) => Some(value.as_i64().ok_or_else(|| FcpError::InvalidRequest {
                code: 1005,
                message: "id must be an integer".into(),
            })?),
            None => None,
        };
        Ok(Self { id })
    }

    #[must_use]
    pub const fn id(&self) -> Option<i64> {
        self.id
    }
}

fn optional_trimmed_string(input: &Value, field: &str) -> String {
    input
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .unwrap_or_default()
}

fn required_string<'a>(value: &'a Value, field: &str) -> FcpResult<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} is required"),
        })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn config_rejects_empty_corp_id() {
        let error = WeComConfig::from_value(json!({
            "corp_id": "",
            "agent_id": 1_000_002_u64,
            "agent_secret": "secret",
        }))
        .expect_err("corp_id must be required");
        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn message_request_requires_at_least_one_target() {
        let error = WeComMessageRequest::from_value(
            &json!({
                "content": "hello",
            }),
            WeComMessageKind::Text,
        )
        .expect_err("one target is required");
        assert!(matches!(error, FcpError::InvalidRequest { code: 1005, .. }));
    }

    #[test]
    fn media_upload_request_rejects_invalid_base64() {
        let request = WeComMediaUploadRequest::from_value(&json!({
            "media_type": "image",
            "file_name": "a.png",
            "content_base64": "%%%not-base64%%%",
        }))
        .expect("request should parse");
        assert!(request.decode_content().is_err());
    }
}
