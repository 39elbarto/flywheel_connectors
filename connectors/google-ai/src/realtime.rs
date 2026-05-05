//! Google Live realtime WebSocket runner.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::Utc;
use fcp_streaming::{WsClient, WsConfig, WsMessage};
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};

use crate::error::{GoogleAiError, GoogleAiResult};
use crate::types::{
    GOOGLE_LIVE_INPUT_SAMPLE_RATE_HZ, GOOGLE_LIVE_MAX_PENDING_AUDIO_CHUNKS,
    build_google_live_tool_response, convert_google_live_mulaw8k_to_pcm16k,
    is_google_live_mulaw_silence, is_google_live_pcm16_silence,
};

const DEFAULT_SILENCE_STREAM_END_MS: u64 = 500;
const DEFAULT_TOTAL_TIMEOUT: Duration = Duration::from_secs(5);
const SCRIPT_NAME: &str = "google_ai_live_realtime_loopback";

/// Input audio encoding accepted by the Google Live realtime runner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoogleLiveRealtimeAudioEncoding {
    /// Little-endian PCM16.
    Pcm16,
    /// G.711 mu-law.
    G711Ulaw,
}

/// One realtime audio chunk queued before Google Live setup completes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleLiveRealtimeAudioChunk {
    pub encoding: GoogleLiveRealtimeAudioEncoding,
    pub sample_rate_hz: u32,
    pub bytes: Vec<u8>,
}

impl GoogleLiveRealtimeAudioChunk {
    /// Create a PCM16 audio chunk.
    #[must_use]
    pub fn pcm16(sample_rate_hz: u32, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            encoding: GoogleLiveRealtimeAudioEncoding::Pcm16,
            sample_rate_hz,
            bytes: bytes.into(),
        }
    }

    /// Create a G.711 mu-law audio chunk.
    #[must_use]
    pub fn g711_ulaw(sample_rate_hz: u32, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            encoding: GoogleLiveRealtimeAudioEncoding::G711Ulaw,
            sample_rate_hz,
            bytes: bytes.into(),
        }
    }

    fn is_silence(&self) -> bool {
        match self.encoding {
            GoogleLiveRealtimeAudioEncoding::Pcm16 => is_google_live_pcm16_silence(&self.bytes),
            GoogleLiveRealtimeAudioEncoding::G711Ulaw => is_google_live_mulaw_silence(&self.bytes),
        }
    }

    fn duration_ms(&self) -> u64 {
        let bytes_per_sample = match self.encoding {
            GoogleLiveRealtimeAudioEncoding::Pcm16 => 2,
            GoogleLiveRealtimeAudioEncoding::G711Ulaw => 1,
        };
        if self.sample_rate_hz == 0 || bytes_per_sample == 0 {
            return 0;
        }
        let samples = self.bytes.len() / bytes_per_sample;
        let numerator = u128::try_from(samples).unwrap_or(u128::MAX) * 1000;
        u64::try_from(numerator / u128::from(self.sample_rate_hz)).unwrap_or(u64::MAX)
    }

    fn to_google_pcm16_16k(&self) -> GoogleAiResult<Vec<u8>> {
        match (self.encoding, self.sample_rate_hz) {
            (GoogleLiveRealtimeAudioEncoding::G711Ulaw, 8_000) => {
                Ok(convert_google_live_mulaw8k_to_pcm16k(&self.bytes))
            }
            (GoogleLiveRealtimeAudioEncoding::Pcm16, GOOGLE_LIVE_INPUT_SAMPLE_RATE_HZ) => {
                Ok(self.bytes.clone())
            }
            _ => Err(GoogleAiError::InvalidConfig(format!(
                "unsupported Google Live realtime input format: {:?} at {} Hz",
                self.encoding, self.sample_rate_hz
            ))),
        }
    }
}

/// Configuration for one Google Live realtime WebSocket run.
#[derive(Debug, Clone)]
pub struct GoogleLiveRealtimeSessionConfig {
    pub websocket_url: String,
    pub client_secret: String,
    pub initial_message: JsonValue,
    pub audio_chunks: Vec<GoogleLiveRealtimeAudioChunk>,
    pub user_messages: Vec<String>,
    pub silence_stream_end_ms: u64,
    pub max_pending_audio_chunks: usize,
    pub total_timeout: Duration,
    pub correlation_id: String,
}

impl GoogleLiveRealtimeSessionConfig {
    /// Build a realtime session config.
    #[must_use]
    pub fn new(
        websocket_url: impl Into<String>,
        client_secret: impl Into<String>,
        initial_message: JsonValue,
    ) -> Self {
        Self {
            websocket_url: websocket_url.into(),
            client_secret: client_secret.into(),
            initial_message,
            audio_chunks: Vec::new(),
            user_messages: Vec::new(),
            silence_stream_end_ms: DEFAULT_SILENCE_STREAM_END_MS,
            max_pending_audio_chunks: GOOGLE_LIVE_MAX_PENDING_AUDIO_CHUNKS,
            total_timeout: DEFAULT_TOTAL_TIMEOUT,
            correlation_id: format!(
                "google-live-{}",
                Utc::now().timestamp_nanos_opt().unwrap_or(0)
            ),
        }
    }

    /// Queue audio that will be drained after `setupComplete`.
    #[must_use]
    pub fn with_audio_chunks(mut self, audio_chunks: Vec<GoogleLiveRealtimeAudioChunk>) -> Self {
        self.audio_chunks = audio_chunks;
        self
    }

    /// Add text turns to send after setup completes.
    #[must_use]
    pub fn with_user_messages(mut self, messages: Vec<String>) -> Self {
        self.user_messages = messages;
        self
    }

    /// Override the silence threshold for sending `audioStreamEnd`.
    #[must_use]
    pub const fn with_silence_stream_end_ms(mut self, silence_stream_end_ms: u64) -> Self {
        self.silence_stream_end_ms = silence_stream_end_ms;
        self
    }

    /// Override the total bounded runtime timeout.
    #[must_use]
    pub const fn with_total_timeout(mut self, total_timeout: Duration) -> Self {
        self.total_timeout = total_timeout;
        self
    }

    fn validate(&self) -> GoogleAiResult<()> {
        if self.websocket_url.trim().is_empty() {
            return Err(GoogleAiError::InvalidConfig(
                "websocket_url must not be empty".into(),
            ));
        }
        if self.client_secret.trim().is_empty() {
            return Err(GoogleAiError::InvalidConfig(
                "client_secret must not be empty".into(),
            ));
        }
        if self.initial_message.get("setup").is_none() {
            return Err(GoogleAiError::InvalidConfig(
                "initial_message must contain setup".into(),
            ));
        }
        Ok(())
    }
}

/// One redacted JSONL evidence row for a Google Live realtime run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleLiveRealtimeLogEntry {
    pub timestamp: String,
    pub log_version: String,
    pub script: String,
    pub step: String,
    pub step_number: usize,
    pub correlation_id: String,
    pub duration_ms: u64,
    pub result: String,
    pub details: JsonValue,
}

/// Redacted report returned by a realtime run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleLiveRealtimeRunReport {
    pub outcome: String,
    pub ready: bool,
    pub pending_audio_queued: usize,
    pub pending_audio_drained: usize,
    pub audio_frames_sent: usize,
    pub audio_stream_end_sent: bool,
    pub tool_calls: Vec<String>,
    pub cancelled_tool_calls: Vec<String>,
    pub resumption_handle: Option<String>,
    pub go_away_time_left: Option<String>,
    pub close_reason: Option<String>,
    pub events: Vec<GoogleLiveRealtimeLogEntry>,
}

impl GoogleLiveRealtimeRunReport {
    fn new() -> Self {
        Self {
            outcome: "running".into(),
            ready: false,
            pending_audio_queued: 0,
            pending_audio_drained: 0,
            audio_frames_sent: 0,
            audio_stream_end_sent: false,
            tool_calls: Vec::new(),
            cancelled_tool_calls: Vec::new(),
            resumption_handle: None,
            go_away_time_left: None,
            close_reason: None,
            events: Vec::new(),
        }
    }

    fn push_log(
        &mut self,
        config: &GoogleLiveRealtimeSessionConfig,
        started_at: Instant,
        step: impl Into<String>,
        result: &'static str,
        details: JsonValue,
    ) {
        let duration_ms = u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.events.push(GoogleLiveRealtimeLogEntry {
            timestamp: Utc::now().to_rfc3339(),
            log_version: "v1".into(),
            script: SCRIPT_NAME.into(),
            step: step.into(),
            step_number: self.events.len(),
            correlation_id: config.correlation_id.clone(),
            duration_ms,
            result: result.into(),
            details,
        });
    }

    /// Serialize the redacted report events as stable JSONL.
    #[must_use]
    pub fn to_jsonl(&self) -> String {
        let mut output = String::new();
        for event in &self.events {
            if let Ok(line) = serde_json::to_string(event) {
                output.push_str(&line);
                output.push('\n');
            }
        }
        output
    }
}

/// Run one bounded Google Live realtime WebSocket session.
///
/// The token is sent as an `Authorization: Token ...` header and is never
/// copied into the returned report or JSONL.
pub async fn run_google_live_realtime_session(
    config: GoogleLiveRealtimeSessionConfig,
) -> GoogleAiResult<GoogleLiveRealtimeRunReport> {
    config.validate()?;
    let started_at = Instant::now();
    let mut report = GoogleLiveRealtimeRunReport::new();
    let run = Box::pin(run_google_live_realtime_session_inner(
        &config,
        started_at,
        &mut report,
    ));

    match Box::pin(fcp_async_core::time::timeout(config.total_timeout, run)).await {
        Ok(Ok(())) => {
            if report.outcome == "running" {
                report.outcome = "completed".into();
            }
            Ok(report)
        }
        Ok(Err(err)) => Err(err),
        Err(_) => {
            report.outcome = "timeout".into();
            report.push_log(
                &config,
                started_at,
                "bounded_shutdown",
                "fail",
                json!({ "reason": "timeout" }),
            );
            Ok(report)
        }
    }
}

async fn run_google_live_realtime_session_inner(
    config: &GoogleLiveRealtimeSessionConfig,
    started_at: Instant,
    report: &mut GoogleLiveRealtimeRunReport,
) -> GoogleAiResult<()> {
    if config.audio_chunks.len() > config.max_pending_audio_chunks {
        report.outcome = "pending_audio_bound_exceeded".into();
        report.push_log(
            config,
            started_at,
            "pending_audio_bound",
            "fail",
            json!({
                "queued": config.audio_chunks.len(),
                "max": config.max_pending_audio_chunks,
            }),
        );
        return Ok(());
    }

    report.pending_audio_queued = config.audio_chunks.len();
    report.push_log(
        config,
        started_at,
        "pending_audio_queued",
        "pass",
        json!({ "chunks": report.pending_audio_queued }),
    );

    let mut ws_config = WsConfig::default()
        .with_connect_timeout(config.total_timeout)
        .with_ping_interval(None)
        .with_auto_reconnect(false);
    ws_config.headers.insert(
        "Authorization".into(),
        format!("Token {}", config.client_secret),
    );

    report.push_log(config, started_at, "connect_start", "pass", json!({}));
    let mut connection = WsClient::with_config(config.websocket_url.clone(), ws_config)
        .connect()
        .await
        .map_err(|err| GoogleAiError::Api {
            message: format!("Google Live websocket connect failed: {err}"),
            status_code: None,
            error_type: Some("websocket_connect".into()),
        })?;

    connection
        .send_json(&config.initial_message)
        .await
        .map_err(|err| GoogleAiError::Api {
            message: format!("Google Live setup send failed: {err}"),
            status_code: None,
            error_type: Some("websocket_send".into()),
        })?;
    report.push_log(config, started_at, "setup_sent", "pass", json!({}));

    let mut pending_audio: VecDeque<_> = config.audio_chunks.iter().cloned().collect();
    let mut pending_functions = HashMap::<String, String>::new();
    let mut consecutive_silence_ms = 0_u64;
    let mut stream_ended = false;

    while let Some(message) = connection.recv().await.map_err(|err| GoogleAiError::Api {
        message: format!("Google Live websocket receive failed: {err}"),
        status_code: None,
        error_type: Some("websocket_recv".into()),
    })? {
        let value = match decode_message(&message) {
            Ok(value) => value,
            Err(message) => {
                report.outcome = "malformed_frame".into();
                report.push_log(
                    config,
                    started_at,
                    "malformed_frame",
                    "fail",
                    json!({ "error": message }),
                );
                let _ = connection.close().await;
                return Ok(());
            }
        };

        if handle_error_frame(config, started_at, report, &value, &mut connection).await? {
            return Ok(());
        }
        if value.get("setupComplete").is_some() {
            report.ready = true;
            report.push_log(config, started_at, "setup_complete", "pass", json!({}));
            while let Some(chunk) = pending_audio.pop_front() {
                send_audio_chunk(
                    &mut connection,
                    config,
                    started_at,
                    report,
                    &chunk,
                    &mut consecutive_silence_ms,
                    &mut stream_ended,
                )
                .await?;
                report.pending_audio_drained += 1;
            }
            report.push_log(
                config,
                started_at,
                "pending_audio_drained",
                "pass",
                json!({ "chunks": report.pending_audio_drained }),
            );
            send_user_messages(&mut connection, config, started_at, report).await?;
        }
        handle_session_lifecycle(config, started_at, report, &value);
        handle_server_content(config, started_at, report, &value);
        handle_tool_call(
            &mut connection,
            config,
            started_at,
            report,
            &value,
            &mut pending_functions,
        )
        .await?;
        handle_tool_cancellation(config, started_at, report, &value);
    }

    report.close_reason = Some("server_closed".into());
    report.push_log(
        config,
        started_at,
        "bounded_shutdown",
        "pass",
        json!({ "reason": "server_closed" }),
    );
    Ok(())
}

fn decode_message(message: &WsMessage) -> Result<JsonValue, String> {
    match message {
        WsMessage::Text(text) => serde_json::from_str(text).map_err(|err| err.to_string()),
        WsMessage::Binary(bytes) => serde_json::from_slice(bytes).map_err(|err| err.to_string()),
        WsMessage::Close(_) => Ok(json!({ "close": true })),
        WsMessage::Ping(_) | WsMessage::Pong(_) => Ok(json!({ "control": true })),
    }
}

async fn handle_error_frame(
    config: &GoogleLiveRealtimeSessionConfig,
    started_at: Instant,
    report: &mut GoogleLiveRealtimeRunReport,
    value: &JsonValue,
    connection: &mut fcp_streaming::WsConnection,
) -> GoogleAiResult<bool> {
    let Some(error) = value.get("error") else {
        return Ok(false);
    };
    let code = error
        .get("code")
        .and_then(JsonValue::as_i64)
        .and_then(|code| u16::try_from(code).ok());
    let step = if matches!(code, Some(401 | 403)) {
        report.outcome = "auth_failure".into();
        "auth_failure"
    } else {
        report.outcome = "server_error".into();
        "server_error"
    };
    let message_chars = error
        .get("message")
        .and_then(JsonValue::as_str)
        .map(str::chars)
        .map_or(0, Iterator::count);
    report.push_log(
        config,
        started_at,
        step,
        "fail",
        json!({
            "code": code,
            "message_chars": message_chars,
        }),
    );
    let _ = connection.close().await;
    Ok(true)
}

async fn send_audio_chunk(
    connection: &mut fcp_streaming::WsConnection,
    config: &GoogleLiveRealtimeSessionConfig,
    started_at: Instant,
    report: &mut GoogleLiveRealtimeRunReport,
    chunk: &GoogleLiveRealtimeAudioChunk,
    consecutive_silence_ms: &mut u64,
    stream_ended: &mut bool,
) -> GoogleAiResult<()> {
    let silent = chunk.is_silence();
    if silent && *stream_ended {
        report.push_log(
            config,
            started_at,
            "silence_skipped_after_stream_end",
            "pass",
            json!({}),
        );
        return Ok(());
    }
    if !silent {
        *consecutive_silence_ms = 0;
        *stream_ended = false;
    }

    let pcm = chunk.to_google_pcm16_16k()?;
    let frame = json!({
        "realtimeInput": {
            "audio": {
                "data": BASE64_STANDARD.encode(pcm),
                "mimeType": format!("audio/pcm;rate={GOOGLE_LIVE_INPUT_SAMPLE_RATE_HZ}"),
            },
        },
    });
    connection
        .send_json(&frame)
        .await
        .map_err(|err| GoogleAiError::Api {
            message: format!("Google Live audio send failed: {err}"),
            status_code: None,
            error_type: Some("websocket_send".into()),
        })?;
    report.audio_frames_sent += 1;
    report.push_log(
        config,
        started_at,
        "audio_sent",
        "pass",
        json!({
            "encoding": format!("{:?}", chunk.encoding),
            "input_sample_rate_hz": chunk.sample_rate_hz,
            "google_sample_rate_hz": GOOGLE_LIVE_INPUT_SAMPLE_RATE_HZ,
            "silent": silent,
        }),
    );

    if !silent {
        return Ok(());
    }
    *consecutive_silence_ms = consecutive_silence_ms.saturating_add(chunk.duration_ms());
    if !*stream_ended && *consecutive_silence_ms >= config.silence_stream_end_ms {
        connection
            .send_json(&json!({ "realtimeInput": { "audioStreamEnd": true } }))
            .await
            .map_err(|err| GoogleAiError::Api {
                message: format!("Google Live audioStreamEnd send failed: {err}"),
                status_code: None,
                error_type: Some("websocket_send".into()),
            })?;
        *stream_ended = true;
        report.audio_stream_end_sent = true;
        report.push_log(
            config,
            started_at,
            "audio_stream_end_sent",
            "pass",
            json!({ "consecutive_silence_ms": *consecutive_silence_ms }),
        );
    }
    Ok(())
}

async fn send_user_messages(
    connection: &mut fcp_streaming::WsConnection,
    config: &GoogleLiveRealtimeSessionConfig,
    started_at: Instant,
    report: &mut GoogleLiveRealtimeRunReport,
) -> GoogleAiResult<()> {
    for message in &config.user_messages {
        let normalized = message.trim();
        if normalized.is_empty() {
            continue;
        }
        connection
            .send_json(&json!({
                "clientContent": {
                    "turns": [{
                        "role": "user",
                        "parts": [{ "text": normalized }],
                    }],
                    "turnComplete": true,
                },
            }))
            .await
            .map_err(|err| GoogleAiError::Api {
                message: format!("Google Live clientContent send failed: {err}"),
                status_code: None,
                error_type: Some("websocket_send".into()),
            })?;
        report.push_log(
            config,
            started_at,
            "client_content_sent",
            "pass",
            json!({ "chars": normalized.len() }),
        );
    }
    Ok(())
}

fn handle_session_lifecycle(
    config: &GoogleLiveRealtimeSessionConfig,
    started_at: Instant,
    report: &mut GoogleLiveRealtimeRunReport,
    value: &JsonValue,
) {
    if let Some(update) = value.get("sessionResumptionUpdate") {
        if update
            .get("resumable")
            .and_then(JsonValue::as_bool)
            .unwrap_or(false)
        {
            if let Some(handle) = update.get("newHandle").and_then(JsonValue::as_str) {
                report.resumption_handle = Some(handle.to_string());
                report.push_log(
                    config,
                    started_at,
                    "session_resumption_update",
                    "pass",
                    json!({ "resumable": true, "handle_present": true }),
                );
            }
        }
    }
    if let Some(go_away) = value.get("goAway") {
        let time_left = go_away
            .get("timeLeft")
            .and_then(JsonValue::as_str)
            .unwrap_or("unspecified");
        report.go_away_time_left = Some(time_left.to_string());
        report.push_log(
            config,
            started_at,
            "go_away",
            "pass",
            json!({ "time_left": time_left }),
        );
    }
}

fn handle_server_content(
    config: &GoogleLiveRealtimeSessionConfig,
    started_at: Instant,
    report: &mut GoogleLiveRealtimeRunReport,
    value: &JsonValue,
) {
    let Some(content) = value.get("serverContent") else {
        return;
    };
    if content
        .get("interrupted")
        .and_then(JsonValue::as_bool)
        .unwrap_or(false)
    {
        report.push_log(config, started_at, "playback_cleared", "pass", json!({}));
    }
    for (role, key) in [
        ("user", "inputTranscription"),
        ("assistant", "outputTranscription"),
    ] {
        if let Some(text) = content
            .get(key)
            .and_then(|value| value.get("text"))
            .and_then(JsonValue::as_str)
            .filter(|text| !text.trim().is_empty())
        {
            report.push_log(
                config,
                started_at,
                "transcript",
                "pass",
                json!({
                    "role": role,
                    "chars": text.chars().count(),
                    "finished": content
                        .get(key)
                        .and_then(|value| value.get("finished"))
                        .and_then(JsonValue::as_bool)
                        .unwrap_or(false),
                }),
            );
        }
    }
    if let Some(parts) = content
        .get("modelTurn")
        .and_then(|turn| turn.get("parts"))
        .and_then(JsonValue::as_array)
    {
        for part in parts {
            if part
                .get("inlineData")
                .and_then(|data| data.get("data"))
                .and_then(JsonValue::as_str)
                .is_some()
            {
                report.push_log(config, started_at, "server_audio", "pass", json!({}));
            }
            if part.get("thought").and_then(JsonValue::as_bool) == Some(true) {
                continue;
            }
            if let Some(text) = part
                .get("text")
                .and_then(JsonValue::as_str)
                .filter(|text| !text.trim().is_empty())
            {
                report.push_log(
                    config,
                    started_at,
                    "assistant_text",
                    "pass",
                    json!({ "chars": text.chars().count() }),
                );
            }
        }
    }
    if content
        .get("turnComplete")
        .and_then(JsonValue::as_bool)
        .unwrap_or(false)
    {
        report.push_log(config, started_at, "turn_complete", "pass", json!({}));
    }
}

async fn handle_tool_call(
    connection: &mut fcp_streaming::WsConnection,
    config: &GoogleLiveRealtimeSessionConfig,
    started_at: Instant,
    report: &mut GoogleLiveRealtimeRunReport,
    value: &JsonValue,
    pending_functions: &mut HashMap<String, String>,
) -> GoogleAiResult<()> {
    let Some(calls) = value
        .get("toolCall")
        .and_then(|tool_call| tool_call.get("functionCalls"))
        .and_then(JsonValue::as_array)
    else {
        return Ok(());
    };
    for call in calls {
        let Some(name) = call
            .get("name")
            .and_then(JsonValue::as_str)
            .map(str::trim)
            .filter(|name| !name.is_empty())
        else {
            continue;
        };
        let call_id = call
            .get("id")
            .and_then(JsonValue::as_str)
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .unwrap_or("google-live-call");
        pending_functions.insert(call_id.to_string(), name.to_string());
        report.tool_calls.push(call_id.to_string());
        report.push_log(
            config,
            started_at,
            "tool_call",
            "pass",
            json!({
                "call_id": call_id,
                "name": name,
                "args_present": call.get("args").is_some(),
            }),
        );
        let response = build_google_live_tool_response(call_id, name, json!({ "ok": true }), false)
            .map_err(GoogleAiError::InvalidConfig)?;
        connection
            .send_json(&json!({ "toolResponse": response }))
            .await
            .map_err(|err| GoogleAiError::Api {
                message: format!("Google Live tool response send failed: {err}"),
                status_code: None,
                error_type: Some("websocket_send".into()),
            })?;
        pending_functions.remove(call_id);
        report.push_log(
            config,
            started_at,
            "tool_response_sent",
            "pass",
            json!({ "call_id": call_id, "name": name }),
        );
    }
    Ok(())
}

fn handle_tool_cancellation(
    config: &GoogleLiveRealtimeSessionConfig,
    started_at: Instant,
    report: &mut GoogleLiveRealtimeRunReport,
    value: &JsonValue,
) {
    let Some(ids) = value
        .get("toolCallCancellation")
        .and_then(|cancellation| cancellation.get("ids"))
        .and_then(JsonValue::as_array)
    else {
        return;
    };
    for id in ids.iter().filter_map(JsonValue::as_str) {
        report.cancelled_tool_calls.push(id.to_string());
    }
    report.push_log(
        config,
        started_at,
        "tool_call_cancellation",
        "pass",
        json!({ "count": ids.len() }),
    );
}
