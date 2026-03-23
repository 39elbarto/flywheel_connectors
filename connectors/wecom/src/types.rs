//! Typed configuration and request models for the `WeCom` connector.

use std::collections::BTreeMap;

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
    #[serde(default)]
    callback_token: String,
    #[serde(default)]
    callback_encoding_aes_key: String,
    #[serde(default)]
    callback_receive_id: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WeComStateModel {
    pub base_url: String,
    pub agent_id: u64,
    pub token_cached: bool,
    pub callback_configured: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WeComMessageKind {
    Text,
    Markdown,
    Image,
    File,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum WeComMessagePayload {
    Text { content: String },
    Markdown { content: String },
    Image { media_id: String },
    File { media_id: String },
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
    safe: bool,
    enable_duplicate_check: bool,
    duplicate_check_interval: Option<u32>,
    payload: WeComMessagePayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeComMediaUploadRequest {
    media_type: String,
    file_name: String,
    mime_type: String,
    content_base64: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeComMediaDownloadRequest {
    media_id: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WeComMediaDownload {
    pub media_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    pub content_length: usize,
    pub content_base64: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeComUserLookupRequest {
    userid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeComDepartmentListRequest {
    id: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeComCallbackVerifyRequest {
    msg_signature: String,
    timestamp: String,
    nonce: String,
    echostr: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeComCallbackIngestRequest {
    msg_signature: String,
    timestamp: String,
    nonce: String,
    body: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WeComCallbackEnvelope {
    pub receive_id: String,
    pub wrapper: BTreeMap<String, String>,
    pub message: BTreeMap<String, String>,
    pub plaintext_xml: String,
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

impl std::fmt::Debug for WeComConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WeComConfig")
            .field("base_url", &self.base_url)
            .field("corp_id", &self.corp_id)
            .field("agent_id", &self.agent_id)
            .field("agent_secret", &redacted_secret(&self.agent_secret))
            .field("request_timeout_ms", &self.request_timeout_ms)
            .field("callback_token", &redacted_secret(&self.callback_token))
            .field(
                "callback_encoding_aes_key",
                &redacted_secret(&self.callback_encoding_aes_key),
            )
            .field("callback_receive_id", &self.callback_receive_id())
            .finish()
    }
}

fn redacted_secret(value: &str) -> Option<&'static str> {
    if value.is_empty() {
        None
    } else {
        Some("[REDACTED]")
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
        self.callback_token = self.callback_token.trim().to_string();
        self.callback_encoding_aes_key = self.callback_encoding_aes_key.trim().to_string();
        self.callback_receive_id = self.callback_receive_id.trim().to_string();
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

        let has_callback_token = !self.callback_token.is_empty();
        let has_callback_key = !self.callback_encoding_aes_key.is_empty();
        if has_callback_token != has_callback_key {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "callback_token and callback_encoding_aes_key must either both be set or both be omitted".into(),
            });
        }
        if has_callback_key {
            let _key = self
                .callback_aes_key()
                .map_err(|message| FcpError::InvalidRequest {
                    code: 1001,
                    message,
                })?;
        }

        Ok(())
    }

    #[must_use]
    pub fn state_model(&self, token_cached: bool) -> WeComStateModel {
        WeComStateModel {
            base_url: self.base_url.clone(),
            agent_id: self.agent_id,
            token_cached,
            callback_configured: self.callback_configured(),
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

    #[must_use]
    pub fn callback_configured(&self) -> bool {
        !self.callback_token.is_empty() && !self.callback_encoding_aes_key.is_empty()
    }

    #[must_use]
    pub fn callback_token(&self) -> Option<&str> {
        (!self.callback_token.is_empty()).then_some(self.callback_token.as_str())
    }

    #[must_use]
    pub fn callback_receive_id(&self) -> &str {
        if self.callback_receive_id.is_empty() {
            &self.corp_id
        } else {
            &self.callback_receive_id
        }
    }

    pub fn callback_aes_key(&self) -> Result<[u8; 32], String> {
        decode_callback_aes_key(&self.callback_encoding_aes_key)
    }
}

pub fn decode_callback_aes_key(raw: &str) -> Result<[u8; 32], String> {
    if raw.trim().is_empty() {
        return Err("callback_encoding_aes_key must not be empty".into());
    }

    let mut normalized = raw.trim().to_string();
    while normalized.len() % 4 != 0 {
        normalized.push('=');
    }

    let decoded = BASE64
        .decode(normalized)
        .map_err(|error| format!("callback_encoding_aes_key must be valid base64: {error}"))?;
    let decoded_len = decoded.len();
    let key: [u8; 32] = decoded.try_into().map_err(|_| {
        format!(
            "callback_encoding_aes_key must decode to exactly 32 bytes, got {}",
            decoded_len
        )
    })?;
    Ok(key)
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
        let payload = match kind {
            WeComMessageKind::Text => WeComMessagePayload::Text {
                content: required_string(input, "content")?.to_string(),
            },
            WeComMessageKind::Markdown => WeComMessagePayload::Markdown {
                content: required_string(input, "content")?.to_string(),
            },
            WeComMessageKind::Image => WeComMessagePayload::Image {
                media_id: required_string(input, "media_id")?.to_string(),
            },
            WeComMessageKind::File => WeComMessagePayload::File {
                media_id: required_string(input, "media_id")?.to_string(),
            },
        };

        Ok(Self {
            targets: WeComMessageTargets::from_value(input)?,
            safe: optional_bool_like(input, "safe")?.unwrap_or(false),
            enable_duplicate_check: optional_bool_like(input, "enable_duplicate_check")?
                .unwrap_or(false),
            duplicate_check_interval: optional_u32(input, "duplicate_check_interval")?,
            payload,
        })
    }

    #[must_use]
    pub fn to_body(&self, agent_id: u64) -> Value {
        let mut body = json!({
            "touser": self.targets.touser(),
            "toparty": self.targets.toparty(),
            "totag": self.targets.totag(),
            "agentid": agent_id,
            "enable_duplicate_check": i32::from(self.enable_duplicate_check),
        });

        if let Some(interval) = self.duplicate_check_interval {
            body["duplicate_check_interval"] = json!(interval);
        }

        match &self.payload {
            WeComMessagePayload::Text { content } => {
                body["msgtype"] = json!("text");
                body["text"] = json!({ "content": content });
                body["safe"] = json!(i32::from(self.safe));
            }
            WeComMessagePayload::Markdown { content } => {
                body["msgtype"] = json!("markdown");
                body["markdown"] = json!({ "content": content });
            }
            WeComMessagePayload::Image { media_id } => {
                body["msgtype"] = json!("image");
                body["image"] = json!({ "media_id": media_id });
                body["safe"] = json!(i32::from(self.safe));
            }
            WeComMessagePayload::File { media_id } => {
                body["msgtype"] = json!("file");
                body["file"] = json!({ "media_id": media_id });
                body["safe"] = json!(i32::from(self.safe));
            }
        }

        body
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

impl WeComMediaDownloadRequest {
    pub fn from_value(input: &Value) -> FcpResult<Self> {
        Ok(Self {
            media_id: required_string(input, "media_id")?.to_string(),
        })
    }

    #[must_use]
    pub fn media_id(&self) -> &str {
        &self.media_id
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

impl WeComCallbackVerifyRequest {
    pub fn from_value(input: &Value) -> FcpResult<Self> {
        Ok(Self {
            msg_signature: required_string(input, "msg_signature")?.to_string(),
            timestamp: required_string(input, "timestamp")?.to_string(),
            nonce: required_string(input, "nonce")?.to_string(),
            echostr: required_string(input, "echostr")?.to_string(),
        })
    }

    #[must_use]
    pub fn msg_signature(&self) -> &str {
        &self.msg_signature
    }

    #[must_use]
    pub fn timestamp(&self) -> &str {
        &self.timestamp
    }

    #[must_use]
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    #[must_use]
    pub fn echostr(&self) -> &str {
        &self.echostr
    }
}

impl WeComCallbackIngestRequest {
    pub fn from_value(input: &Value) -> FcpResult<Self> {
        Ok(Self {
            msg_signature: required_string(input, "msg_signature")?.to_string(),
            timestamp: required_string(input, "timestamp")?.to_string(),
            nonce: required_string(input, "nonce")?.to_string(),
            body: required_string_alias(input, &["body", "body_xml"])?.to_string(),
        })
    }

    #[must_use]
    pub fn msg_signature(&self) -> &str {
        &self.msg_signature
    }

    #[must_use]
    pub fn timestamp(&self) -> &str {
        &self.timestamp
    }

    #[must_use]
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    #[must_use]
    pub fn body(&self) -> &str {
        &self.body
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

fn optional_bool_like(input: &Value, field: &str) -> FcpResult<Option<bool>> {
    let Some(value) = input.get(field) else {
        return Ok(None);
    };

    if let Some(boolean) = value.as_bool() {
        return Ok(Some(boolean));
    }
    if let Some(integer) = value.as_i64() {
        return match integer {
            0 => Ok(Some(false)),
            1 => Ok(Some(true)),
            _ => Err(FcpError::InvalidRequest {
                code: 1005,
                message: format!("{field} must be a boolean or 0/1"),
            }),
        };
    }

    Err(FcpError::InvalidRequest {
        code: 1005,
        message: format!("{field} must be a boolean or 0/1"),
    })
}

fn optional_u32(input: &Value, field: &str) -> FcpResult<Option<u32>> {
    let Some(value) = input.get(field) else {
        return Ok(None);
    };

    let integer = value.as_u64().ok_or_else(|| FcpError::InvalidRequest {
        code: 1005,
        message: format!("{field} must be a non-negative integer"),
    })?;
    let integer = u32::try_from(integer).map_err(|_| FcpError::InvalidRequest {
        code: 1005,
        message: format!("{field} must fit into a 32-bit integer"),
    })?;
    Ok(Some(integer))
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

fn required_string_alias<'a>(value: &'a Value, fields: &[&str]) -> FcpResult<&'a str> {
    for field in fields {
        if let Some(candidate) = value
            .get(*field)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|candidate| !candidate.is_empty())
        {
            return Ok(candidate);
        }
    }

    Err(FcpError::InvalidRequest {
        code: 1005,
        message: format!("{} is required", fields.join(" or ")),
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn sample_callback_key() -> String {
        BASE64.encode([7_u8; 32]).trim_end_matches('=').to_string()
    }

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
    fn config_rejects_partial_callback_configuration() {
        let error = WeComConfig::from_value(json!({
            "corp_id": "corp",
            "agent_id": 1_000_002_u64,
            "agent_secret": "secret",
            "callback_token": "token-only",
        }))
        .expect_err("partial callback config must fail");
        assert!(matches!(error, FcpError::InvalidRequest { code: 1001, .. }));
    }

    #[test]
    fn config_state_model_reports_callback_configuration() {
        let config = WeComConfig::from_value(json!({
            "corp_id": "corp",
            "agent_id": 1_000_002_u64,
            "agent_secret": "secret",
            "callback_token": "token",
            "callback_encoding_aes_key": sample_callback_key(),
        }))
        .expect("config should parse");

        let model = config.state_model(true);
        assert!(model.token_cached);
        assert!(model.callback_configured);
        assert_eq!(config.callback_receive_id(), "corp");
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
    fn text_message_request_includes_duplicate_check_fields() {
        let request = WeComMessageRequest::from_value(
            &json!({
                "touser": "zhangsan",
                "content": "hello",
                "safe": 1,
                "enable_duplicate_check": true,
                "duplicate_check_interval": 300,
            }),
            WeComMessageKind::Text,
        )
        .expect("text request should parse");

        let body = request.to_body(1_000_002_u64);
        assert_eq!(body["msgtype"], "text");
        assert_eq!(body["safe"], 1);
        assert_eq!(body["enable_duplicate_check"], 1);
        assert_eq!(body["duplicate_check_interval"], 300);
        assert_eq!(body["text"]["content"], "hello");
    }

    #[test]
    fn image_message_request_requires_media_id() {
        let error = WeComMessageRequest::from_value(
            &json!({
                "touser": "zhangsan",
            }),
            WeComMessageKind::Image,
        )
        .expect_err("image request must require media_id");
        assert!(matches!(error, FcpError::InvalidRequest { code: 1005, .. }));
    }

    #[test]
    fn file_message_request_builds_media_payload() {
        let request = WeComMessageRequest::from_value(
            &json!({
                "touser": "zhangsan",
                "media_id": "MEDIA123",
                "safe": false,
                "enable_duplicate_check": 1,
            }),
            WeComMessageKind::File,
        )
        .expect("file request should parse");

        let body = request.to_body(1_000_002_u64);
        assert_eq!(body["msgtype"], "file");
        assert_eq!(body["file"]["media_id"], "MEDIA123");
        assert_eq!(body["safe"], 0);
        assert_eq!(body["enable_duplicate_check"], 1);
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

    #[test]
    fn callback_verify_request_requires_fields() {
        let error = WeComCallbackVerifyRequest::from_value(&json!({
            "timestamp": "1",
            "nonce": "2",
            "echostr": "3",
        }))
        .expect_err("missing signature must fail");
        assert!(matches!(error, FcpError::InvalidRequest { code: 1005, .. }));
    }

    #[test]
    fn access_token_response_debug_redacts_token() {
        let response = AccessTokenResponse {
            access_token: "super_secret_token_12345".into(),
            expires_in: 7200,
        };
        let debug = format!("{response:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super_secret_token_12345"));
        assert!(debug.contains("7200"));
    }
}
