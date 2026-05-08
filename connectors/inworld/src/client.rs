//! Inworld client helpers for Realtime, TTS WebSocket, and Router REST calls.

use std::time::Duration;

use fcp_streaming::{StreamError, WsClient, WsConfig, WsConnection, WsMessage};
use reqwest::{StatusCode, header};
use serde_json::{Value, json};
use url::Url;

use crate::error::{InworldError, InworldResult};
use crate::types::{
    AudioTurnInput, EventSummary, RouterChatCompletionInput, TextTurnInput,
    TtsContextRoundtripInput, audio_events, optional_hash, realtime_session_update_event,
    response_create_event, router_request_body, stable_hash, text_item_event,
    tts_close_context_event, tts_create_context_event, tts_send_text_event,
};

pub const DEFAULT_REALTIME_WS_URL: &str = "wss://api.inworld.ai/api/v1/realtime/session";
pub const DEFAULT_TTS_WS_URL: &str = "wss://api.inworld.ai/tts/v1/voice:streamBidirectional";
pub const DEFAULT_ROUTER_BASE_URL: &str = "https://api.inworld.ai";
const DEFAULT_TIMEOUT_MS: u64 = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InworldAuth {
    BasicApiKey(String),
    BearerToken(String),
    CredentialId(String),
}

impl InworldAuth {
    pub fn from_config(
        api_key: Option<String>,
        bearer_token: Option<String>,
        credential_id: Option<String>,
    ) -> InworldResult<Self> {
        let supplied_count = [
            api_key.as_ref().map(|_| "api_key"),
            bearer_token.as_ref().map(|_| "bearer_token"),
            credential_id.as_ref().map(|_| "credential_id"),
        ]
        .into_iter()
        .flatten()
        .count();
        if supplied_count != 1 {
            return Err(InworldError::InvalidInput(
                "provide exactly one of api_key, bearer_token, or credential_id".into(),
            ));
        }
        if let Some(value) = api_key {
            validate_secret("api_key", &value)?;
            Ok(Self::BasicApiKey(value))
        } else if let Some(value) = bearer_token {
            validate_secret("bearer_token", &value)?;
            Ok(Self::BearerToken(value))
        } else if let Some(value) = credential_id {
            validate_secret("credential_id", &value)?;
            Ok(Self::CredentialId(value))
        } else {
            Err(InworldError::InvalidInput(
                "provide exactly one of api_key, bearer_token, or credential_id".into(),
            ))
        }
    }

    pub fn header_value(&self) -> InworldResult<String> {
        match self {
            Self::BasicApiKey(value) => Ok(format!("Basic {value}")),
            Self::BearerToken(value) => Ok(format!("Bearer {value}")),
            Self::CredentialId(_) => Err(InworldError::CredentialInjectionRequired),
        }
    }

    #[must_use]
    pub const fn redacted_label(&self) -> &'static str {
        match self {
            Self::BasicApiKey(_) => "basic_api_key",
            Self::BearerToken(_) => "bearer_jwt",
            Self::CredentialId(_) => "credential_id",
        }
    }
}

#[derive(Debug, Clone)]
pub struct InworldClient {
    auth: InworldAuth,
    realtime_ws_url: String,
    tts_ws_url: String,
    router_base_url: String,
    timeout: Duration,
    http: reqwest::Client,
}

impl InworldClient {
    pub fn new(
        auth: InworldAuth,
        realtime_ws_url: Option<&str>,
        tts_ws_url: Option<&str>,
        router_base_url: Option<&str>,
        timeout_ms: Option<u64>,
    ) -> InworldResult<Self> {
        let timeout =
            Duration::from_millis(timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS).clamp(100, 120_000));
        let realtime_ws_url = normalize_ws_url(
            realtime_ws_url.unwrap_or(DEFAULT_REALTIME_WS_URL),
            "/api/v1/realtime/session",
        )?;
        let tts_ws_url = normalize_ws_url(
            tts_ws_url.unwrap_or(DEFAULT_TTS_WS_URL),
            "/tts/v1/voice:streamBidirectional",
        )?;
        let router_base_url =
            normalize_https_base_url(router_base_url.unwrap_or(DEFAULT_ROUTER_BASE_URL))?;
        Ok(Self {
            auth,
            realtime_ws_url,
            tts_ws_url,
            router_base_url,
            timeout,
            http: reqwest::Client::builder().timeout(timeout).build()?,
        })
    }

    #[must_use]
    pub const fn auth_label(&self) -> &'static str {
        self.auth.redacted_label()
    }

    #[must_use]
    pub fn realtime_ws_url(&self) -> &str {
        &self.realtime_ws_url
    }

    #[must_use]
    pub fn tts_ws_url(&self) -> &str {
        &self.tts_ws_url
    }

    #[must_use]
    pub fn router_base_url(&self) -> &str {
        &self.router_base_url
    }

    pub async fn realtime_text_turn(&self, input: TextTurnInput) -> InworldResult<Value> {
        input.validate().map_err(fcp_error_to_invalid)?;
        let mut connection = self
            .connect_ws(self.realtime_url_for_session(&input.session.session_id)?)
            .await?;
        let started = std::time::Instant::now();
        let mut summary = EventSummary::default();

        let created = next_json_message(&mut connection).await?;
        summary.observe(&created).map_err(fcp_error_to_invalid)?;
        connection
            .send_json(
                &realtime_session_update_event(&input.session).map_err(fcp_error_to_invalid)?,
            )
            .await
            .map_err(stream_error)?;
        connection
            .send_json(&text_item_event(&input.text).map_err(fcp_error_to_invalid)?)
            .await
            .map_err(stream_error)?;
        if input.create_response.unwrap_or(true) {
            connection
                .send_json(&response_create_event())
                .await
                .map_err(stream_error)?;
        }
        collect_realtime_events(&mut connection, &mut summary, input.session.max_events()).await?;
        let _ = connection.close().await;

        Ok(json!({
            "mode": "realtime_websocket",
            "operation_result": "ok",
            "session_id_hash": stable_hash(&input.session.session_id),
            "character_id_hash": optional_hash(input.session.character_id.as_deref()),
            "profile_id_hash": optional_hash(input.session.profile_id.as_deref()),
            "event_history_id_hash": optional_hash(input.session.event_history_id.as_deref()),
            "conversation_state_id_hash": optional_hash(input.session.conversation_state_id.as_deref()),
            "model_id": input.session.model.as_deref().unwrap_or(crate::types::DEFAULT_REALTIME_MODEL),
            "voice_id": input.session.voice_id.as_deref().unwrap_or(crate::types::DEFAULT_VOICE),
            "input_text_bytes": input.text.len(),
            "input_audio_bytes": 0,
            "events": summary.to_value(),
            "latency_ms": elapsed_ms(started),
            "cleanup_result": "websocket_closed"
        }))
    }

    pub async fn realtime_audio_turn(&self, input: AudioTurnInput) -> InworldResult<Value> {
        let (events, input_audio_bytes) = audio_events(&input).map_err(fcp_error_to_invalid)?;
        let mut connection = self
            .connect_ws(self.realtime_url_for_session(&input.session.session_id)?)
            .await?;
        let started = std::time::Instant::now();
        let mut summary = EventSummary::default();

        let created = next_json_message(&mut connection).await?;
        summary.observe(&created).map_err(fcp_error_to_invalid)?;
        connection
            .send_json(
                &realtime_session_update_event(&input.session).map_err(fcp_error_to_invalid)?,
            )
            .await
            .map_err(stream_error)?;
        for event in events {
            connection.send_json(&event).await.map_err(stream_error)?;
        }
        if input.create_response.unwrap_or(true) {
            connection
                .send_json(&response_create_event())
                .await
                .map_err(stream_error)?;
        }
        collect_realtime_events(&mut connection, &mut summary, input.session.max_events()).await?;
        let _ = connection.close().await;

        Ok(json!({
            "mode": "realtime_websocket",
            "operation_result": "ok",
            "session_id_hash": stable_hash(&input.session.session_id),
            "character_id_hash": optional_hash(input.session.character_id.as_deref()),
            "profile_id_hash": optional_hash(input.session.profile_id.as_deref()),
            "model_id": input.session.model.as_deref().unwrap_or(crate::types::DEFAULT_REALTIME_MODEL),
            "voice_id": input.session.voice_id.as_deref().unwrap_or(crate::types::DEFAULT_VOICE),
            "input_text_bytes": 0,
            "input_audio_bytes": input_audio_bytes,
            "events": summary.to_value(),
            "latency_ms": elapsed_ms(started),
            "cleanup_result": "websocket_closed"
        }))
    }

    pub async fn tts_context_roundtrip(
        &self,
        input: TtsContextRoundtripInput,
    ) -> InworldResult<Value> {
        input.validate().map_err(fcp_error_to_invalid)?;
        let context_id = input.context_id();
        let started = std::time::Instant::now();
        let mut connection = self.connect_ws(self.tts_ws_url.clone()).await?;
        let mut summary = EventSummary::default();

        connection
            .send_json(&tts_create_context_event(&input).map_err(fcp_error_to_invalid)?)
            .await
            .map_err(stream_error)?;
        connection
            .send_json(&tts_send_text_event(&input).map_err(fcp_error_to_invalid)?)
            .await
            .map_err(stream_error)?;
        if input.close.unwrap_or(true) {
            connection
                .send_json(&tts_close_context_event(&context_id))
                .await
                .map_err(stream_error)?;
        }
        collect_tts_events(&mut connection, &mut summary, input.max_events()).await?;
        let _ = connection.close().await;

        Ok(json!({
            "mode": "tts_websocket",
            "operation_result": "ok",
            "context_id_hash": stable_hash(&context_id),
            "voice_id": input.voice_id.as_deref().unwrap_or(crate::types::DEFAULT_VOICE),
            "model_id": input.model_id.as_deref().unwrap_or("inworld-tts-2"),
            "input_text_bytes": input.text.len(),
            "events": summary.to_value(),
            "latency_ms": elapsed_ms(started),
            "cleanup_result": "websocket_closed"
        }))
    }

    pub async fn router_chat_completion(
        &self,
        input: RouterChatCompletionInput,
    ) -> InworldResult<Value> {
        input.validate().map_err(fcp_error_to_invalid)?;
        let prompt_bytes = input.prompt_bytes();
        let url = format!(
            "{}/v1/chat/completions",
            self.router_base_url.trim_end_matches('/')
        );
        let response = self
            .http
            .post(url)
            .header(header::AUTHORIZATION, self.auth.header_value()?)
            .header(header::CONTENT_TYPE, "application/json")
            .json(&router_request_body(&input).map_err(fcp_error_to_invalid)?)
            .send()
            .await?;
        let status = response.status();
        let body = response.text().await?;
        if !status.is_success() {
            return Err(http_error(status, &body));
        }
        let value: Value = serde_json::from_str(&body)?;
        Ok(json!({
            "mode": "router_chat_completion",
            "operation_result": "ok",
            "id_hash": value.get("id").and_then(Value::as_str).map(stable_hash),
            "model_id": value.get("model").and_then(Value::as_str).unwrap_or(&input.model),
            "choice_count": value.get("choices").and_then(Value::as_array).map_or(0, Vec::len),
            "prompt_bytes": prompt_bytes,
            "output_text_bytes": router_output_text_bytes(&value),
            "usage": value.get("usage").cloned().unwrap_or(Value::Null),
            "metadata_attempt_count": value
                .get("metadata")
                .and_then(|metadata| metadata.get("attempts"))
                .and_then(Value::as_array)
                .map_or(0, Vec::len),
            "cleanup_result": "http_response_consumed"
        }))
    }

    async fn connect_ws(&self, url: String) -> InworldResult<WsConnection> {
        let config = WsConfig::new()
            .with_connect_timeout(self.timeout)
            .with_ping_interval(None)
            .with_auto_reconnect(false)
            .with_header("Authorization", self.auth.header_value()?);
        WsClient::with_config(url, config)
            .connect()
            .await
            .map_err(stream_error)
    }

    fn realtime_url_for_session(&self, session_id: &str) -> InworldResult<String> {
        let mut url = Url::parse(&self.realtime_ws_url)?;
        url.query_pairs_mut()
            .clear()
            .append_pair("key", session_id)
            .append_pair("protocol", "realtime");
        Ok(url.to_string())
    }
}

pub fn normalize_ws_url(raw: &str, expected_path: &str) -> InworldResult<String> {
    let mut url = Url::parse(raw)?;
    match url.scheme() {
        "wss" => {
            if url.host_str() != Some("api.inworld.ai") {
                return Err(InworldError::InvalidInput(
                    "production Inworld websocket host must be api.inworld.ai".into(),
                ));
            }
        }
        "ws" => {
            if !is_loopback_host(url.host_str()) {
                return Err(InworldError::InvalidInput(
                    "plain ws is only allowed for loopback fixtures".into(),
                ));
            }
        }
        _ => {
            return Err(InworldError::InvalidInput(
                "Inworld websocket URL must use ws or wss".into(),
            ));
        }
    }
    if url.path().is_empty() || url.path() == "/" {
        url.set_path(expected_path);
    }
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.to_string())
}

pub fn normalize_https_base_url(raw: &str) -> InworldResult<String> {
    let mut url = Url::parse(raw)?;
    match url.scheme() {
        "https" => {
            if url.host_str() != Some("api.inworld.ai") {
                return Err(InworldError::InvalidInput(
                    "production Inworld HTTP host must be api.inworld.ai".into(),
                ));
            }
        }
        "http" => {
            if !is_loopback_host(url.host_str()) {
                return Err(InworldError::InvalidInput(
                    "plain http is only allowed for loopback fixtures".into(),
                ));
            }
        }
        _ => {
            return Err(InworldError::InvalidInput(
                "Inworld HTTP URL must use http or https".into(),
            ));
        }
    }
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.to_string().trim_end_matches('/').to_string())
}

async fn collect_realtime_events(
    connection: &mut WsConnection,
    summary: &mut EventSummary,
    max_events: usize,
) -> InworldResult<()> {
    for _ in 0..max_events {
        let event = next_json_message(connection).await?;
        if summary.observe(&event).map_err(fcp_error_to_invalid)? {
            if summary.error_code.is_some() {
                return Err(InworldError::WebSocket {
                    message: format!(
                        "Inworld error event: {}",
                        summary.error_code.as_deref().unwrap_or("unknown")
                    ),
                    retryable: false,
                });
            }
            return Ok(());
        }
    }
    Err(InworldError::WebSocket {
        message: "Inworld realtime stream ended before response.done".into(),
        retryable: true,
    })
}

async fn collect_tts_events(
    connection: &mut WsConnection,
    summary: &mut EventSummary,
    max_events: usize,
) -> InworldResult<()> {
    for _ in 0..max_events {
        let event = next_json_message(connection).await?;
        if summary.observe_tts(&event).map_err(fcp_error_to_invalid)? {
            return Ok(());
        }
    }
    Err(InworldError::WebSocket {
        message: "Inworld TTS stream ended before completion".into(),
        retryable: true,
    })
}

async fn next_json_message(connection: &mut WsConnection) -> InworldResult<Value> {
    loop {
        let frame = connection.recv().await.map_err(stream_error)?;
        match frame {
            Some(WsMessage::Text(text)) => return Ok(serde_json::from_str(&text)?),
            Some(WsMessage::Binary(bytes)) => return Ok(serde_json::from_slice(bytes.as_ref())?),
            Some(WsMessage::Ping(bytes)) => {
                connection
                    .send(WsMessage::Pong(bytes))
                    .await
                    .map_err(stream_error)?;
            }
            Some(WsMessage::Pong(_)) => {}
            Some(WsMessage::Close(frame)) => {
                let message = frame.map_or_else(
                    || "websocket closed".to_string(),
                    |frame| format!("websocket closed: {} ({})", frame.reason, frame.code),
                );
                return Err(InworldError::WebSocket {
                    message,
                    retryable: true,
                });
            }
            None => {
                return Err(InworldError::WebSocket {
                    message: "websocket closed".into(),
                    retryable: true,
                });
            }
        }
    }
}

fn router_output_text_bytes(value: &Value) -> usize {
    value
        .get("choices")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|choice| choice.get("message"))
        .filter_map(|message| message.get("content"))
        .map(router_content_text_bytes)
        .sum()
}

fn router_content_text_bytes(content: &Value) -> usize {
    match content {
        Value::String(text) => text.len(),
        Value::Array(parts) => parts
            .iter()
            .filter_map(|part| {
                part.get("text")
                    .and_then(Value::as_str)
                    .or_else(|| part.get("content").and_then(Value::as_str))
            })
            .map(str::len)
            .sum(),
        _ => 0,
    }
}

fn elapsed_ms(started: std::time::Instant) -> u64 {
    duration_ms(started.elapsed())
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn http_error(status: StatusCode, body: &str) -> InworldError {
    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        return InworldError::Unauthorized;
    }
    if status == StatusCode::TOO_MANY_REQUESTS {
        return InworldError::RateLimited {
            retry_after_ms: None,
        };
    }
    let message = serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("error")
                .and_then(|error| error.get("message"))
                .or_else(|| value.get("message"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| format!("provider returned HTTP {}", status.as_u16()));
    InworldError::Api {
        status_code: status.as_u16(),
        message,
        retry_after_ms: None,
    }
}

fn stream_error(error: StreamError) -> InworldError {
    match error {
        StreamError::Timeout(timeout) => InworldError::WebSocket {
            message: format!("websocket timeout after {timeout:?}"),
            retryable: true,
        },
        StreamError::HttpError {
            status,
            message,
            retry_after,
        } => InworldError::Api {
            status_code: status,
            message,
            retry_after_ms: retry_after.map(duration_ms),
        },
        other => InworldError::WebSocket {
            message: other.to_string(),
            retryable: true,
        },
    }
}

#[allow(clippy::needless_pass_by_value)]
fn fcp_error_to_invalid(error: fcp_prelude::FcpError) -> InworldError {
    InworldError::InvalidInput(error.to_string())
}

fn validate_secret(field: &str, value: &str) -> InworldResult<()> {
    if value.trim().is_empty() {
        Err(InworldError::InvalidInput(format!(
            "{field} must not be empty"
        )))
    } else {
        Ok(())
    }
}

fn is_loopback_host(host: Option<&str>) -> bool {
    matches!(host, Some("127.0.0.1" | "::1" | "localhost"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_requires_exactly_one_source() {
        assert!(InworldAuth::from_config(None, None, None).is_err());
        assert!(InworldAuth::from_config(Some("a".into()), Some("b".into()), None).is_err());
        assert_eq!(
            InworldAuth::from_config(Some("encoded".into()), None, None)
                .unwrap()
                .redacted_label(),
            "basic_api_key"
        );
    }

    #[test]
    fn production_urls_are_host_specific() {
        assert!(normalize_ws_url(DEFAULT_REALTIME_WS_URL, "/api/v1/realtime/session").is_ok());
        assert!(normalize_https_base_url(DEFAULT_ROUTER_BASE_URL).is_ok());
        assert!(normalize_ws_url("wss://evil.example/ws", "/api/v1/realtime/session").is_err());
        assert!(normalize_https_base_url("https://evil.example").is_err());
    }

    #[test]
    fn loopback_urls_are_allowed_for_fixtures() {
        assert!(
            normalize_ws_url("ws://127.0.0.1:9000", "/api/v1/realtime/session")
                .unwrap()
                .contains("/api/v1/realtime/session")
        );
        assert_eq!(
            normalize_https_base_url("http://localhost:8080/").unwrap(),
            "http://localhost:8080"
        );
    }

    #[test]
    fn router_output_byte_count_does_not_keep_json_rendered_text() {
        let payload = json!({
            "choices": [
                { "message": { "content": "provider secret" } },
                { "message": { "content": [{ "type": "text", "text": "more" }] } }
            ]
        });
        assert_eq!(
            router_output_text_bytes(&payload),
            "provider secret".len() + 4
        );
    }
}
