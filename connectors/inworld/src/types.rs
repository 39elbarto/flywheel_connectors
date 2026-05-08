//! Typed Inworld request, event, and redaction helpers.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use fcp_prelude::{FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const DEFAULT_REALTIME_MODEL: &str = "google-ai-studio/gemini-2.5-flash";
pub const DEFAULT_TTS_MODEL: &str = "inworld-tts-1.5-mini";
pub const DEFAULT_VOICE: &str = "Dennis";
pub const MAX_TEXT_CHARS: usize = 4_000;
pub const MAX_TTS_TEXT_CHARS: usize = 1_000;
pub const MAX_AUDIO_CHUNKS: usize = 64;
pub const MAX_AUDIO_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_MAX_EVENTS: usize = 32;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealtimeSessionInput {
    pub session_id: String,
    pub model: Option<String>,
    pub voice_id: Option<String>,
    pub tts_model_id: Option<String>,
    pub stt_model_id: Option<String>,
    pub character_id: Option<String>,
    pub profile_id: Option<String>,
    pub event_history_id: Option<String>,
    pub conversation_state_id: Option<String>,
    pub output_modalities: Option<Vec<String>>,
    pub instructions: Option<String>,
    pub max_output_tokens: Option<Value>,
    pub temperature: Option<f32>,
    pub timeout_ms: Option<u64>,
    pub max_events: Option<usize>,
    #[serde(default)]
    pub session_extra: Value,
}

impl RealtimeSessionInput {
    pub fn validate(&self) -> FcpResult<()> {
        validate_non_empty("session_id", &self.session_id)?;
        validate_optional_id("character_id", self.character_id.as_deref())?;
        validate_optional_id("profile_id", self.profile_id.as_deref())?;
        validate_optional_id("event_history_id", self.event_history_id.as_deref())?;
        validate_optional_id(
            "conversation_state_id",
            self.conversation_state_id.as_deref(),
        )?;
        if let Some(instructions) = &self.instructions
            && instructions.chars().count() > MAX_TEXT_CHARS
        {
            return invalid("instructions exceeds maximum length");
        }
        if let Some(modalities) = &self.output_modalities {
            if modalities.is_empty() {
                return invalid("output_modalities must not be empty when supplied");
            }
            for modality in modalities {
                validate_enum("output_modalities[]", modality, &["audio", "text"])?;
            }
        }
        if let Some(temperature) = self.temperature
            && !(0.0..=2.0).contains(&temperature)
        {
            return invalid("temperature must be between 0 and 2");
        }
        Ok(())
    }

    #[must_use]
    pub fn max_events(&self) -> usize {
        self.max_events
            .unwrap_or(DEFAULT_MAX_EVENTS)
            .clamp(1, DEFAULT_MAX_EVENTS)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TextTurnInput {
    #[serde(flatten)]
    pub session: RealtimeSessionInput,
    pub text: String,
    pub create_response: Option<bool>,
}

impl TextTurnInput {
    pub fn validate(&self) -> FcpResult<()> {
        self.session.validate()?;
        validate_non_empty("text", &self.text)?;
        if self.text.chars().count() > MAX_TEXT_CHARS {
            return invalid("text exceeds maximum length");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AudioTurnInput {
    #[serde(flatten)]
    pub session: RealtimeSessionInput,
    pub audio_chunks_base64: Vec<String>,
    pub clear_before_append: Option<bool>,
    pub commit: Option<bool>,
    pub create_response: Option<bool>,
}

impl AudioTurnInput {
    pub fn validate(&self) -> FcpResult<usize> {
        self.session.validate()?;
        if self.audio_chunks_base64.is_empty() {
            return invalid("audio_chunks_base64 must not be empty");
        }
        if self.audio_chunks_base64.len() > MAX_AUDIO_CHUNKS {
            return invalid("too many audio chunks");
        }
        let mut total = 0usize;
        for chunk in &self.audio_chunks_base64 {
            let decoded = BASE64
                .decode(chunk)
                .map_err(|err| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("invalid base64 audio chunk: {err}"),
                })?;
            total = total.saturating_add(decoded.len());
        }
        if total > MAX_AUDIO_BYTES {
            return invalid("decoded audio exceeds maximum byte limit");
        }
        Ok(total)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TtsContextRoundtripInput {
    pub context_id: Option<String>,
    pub voice_id: Option<String>,
    pub model_id: Option<String>,
    pub text: String,
    pub flush: Option<bool>,
    pub close: Option<bool>,
    pub timeout_ms: Option<u64>,
    pub max_events: Option<usize>,
}

impl TtsContextRoundtripInput {
    pub fn validate(&self) -> FcpResult<()> {
        validate_non_empty("text", &self.text)?;
        if self.text.chars().count() > MAX_TTS_TEXT_CHARS {
            return invalid("text exceeds Inworld TTS websocket per-message limit");
        }
        validate_optional_id("context_id", self.context_id.as_deref())?;
        Ok(())
    }

    #[must_use]
    pub fn context_id(&self) -> String {
        self.context_id
            .clone()
            .unwrap_or_else(|| "ctx-fcp-inworld".to_string())
    }

    #[must_use]
    pub fn max_events(&self) -> usize {
        self.max_events
            .unwrap_or(DEFAULT_MAX_EVENTS)
            .clamp(1, DEFAULT_MAX_EVENTS)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouterMessage {
    pub role: String,
    pub content: Value,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterChatCompletionInput {
    pub model: String,
    pub messages: Vec<RouterMessage>,
    pub stream: Option<bool>,
    pub temperature: Option<f32>,
    pub top_p: Option<f32>,
    pub max_tokens: Option<u32>,
    pub max_completion_tokens: Option<u32>,
    #[serde(default)]
    pub extra_body: Value,
}

impl RouterChatCompletionInput {
    pub fn validate(&self) -> FcpResult<()> {
        validate_non_empty("model", &self.model)?;
        if self.messages.is_empty() {
            return invalid("messages must not be empty");
        }
        if self.stream.unwrap_or(false) {
            return invalid(
                "router streaming is intentionally not exposed in this connector slice",
            );
        }
        for message in &self.messages {
            validate_enum(
                "messages[].role",
                &message.role,
                &["system", "user", "assistant"],
            )?;
        }
        if let Some(temperature) = self.temperature
            && !(0.0..=2.0).contains(&temperature)
        {
            return invalid("temperature must be between 0 and 2");
        }
        if let Some(top_p) = self.top_p
            && !(0.0 < top_p && top_p <= 1.0)
        {
            return invalid("top_p must be greater than 0 and less than or equal to 1");
        }
        Ok(())
    }

    #[must_use]
    pub fn prompt_bytes(&self) -> usize {
        self.messages
            .iter()
            .map(|message| message.content.to_string().len())
            .sum()
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct EventSummary {
    pub event_types: Vec<String>,
    pub text_output_bytes: usize,
    pub audio_output_bytes: usize,
    pub stream_chunk_count: usize,
    pub item_ids_hashed: Vec<String>,
    pub error_code: Option<String>,
}

impl EventSummary {
    pub fn observe(&mut self, value: &Value) -> FcpResult<bool> {
        let event_type =
            value
                .get("type")
                .and_then(Value::as_str)
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "Inworld event missing type".into(),
                })?;
        self.event_types.push(event_type.to_string());
        match event_type {
            "response.output_text.delta" | "response.output_audio_transcript.delta" => {
                self.text_output_bytes = self.text_output_bytes.saturating_add(
                    value
                        .get("delta")
                        .and_then(Value::as_str)
                        .map(str::len)
                        .unwrap_or_default(),
                );
                self.stream_chunk_count = self.stream_chunk_count.saturating_add(1);
            }
            "response.output_audio.delta" => {
                self.audio_output_bytes = self.audio_output_bytes.saturating_add(
                    value
                        .get("delta")
                        .and_then(Value::as_str)
                        .map(encoded_audio_len)
                        .transpose()?
                        .unwrap_or_default(),
                );
                self.stream_chunk_count = self.stream_chunk_count.saturating_add(1);
            }
            "conversation.item.added" | "conversation.item.done" => {
                if let Some(id) = value
                    .get("item")
                    .and_then(|item| item.get("id"))
                    .and_then(Value::as_str)
                {
                    push_unique_hash(&mut self.item_ids_hashed, id);
                }
            }
            "error" => {
                self.error_code = value
                    .get("error")
                    .and_then(|error| error.get("code"))
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
                    .or_else(|| Some("inworld_error_event".to_string()));
                return Ok(true);
            }
            _ => {}
        }
        Ok(matches!(event_type, "response.done" | "session.closed"))
    }

    pub fn observe_tts(&mut self, value: &Value) -> FcpResult<bool> {
        let event_name = tts_event_name(value).ok_or_else(|| FcpError::InvalidRequest {
            code: 1003,
            message: "Inworld TTS event missing recognized result key".into(),
        })?;
        self.event_types.push(event_name.to_string());
        if let Some(audio) = value
            .get("result")
            .and_then(|result| result.get("audioChunk"))
            .and_then(|chunk| chunk.get("audioContent"))
            .and_then(Value::as_str)
        {
            self.audio_output_bytes = self
                .audio_output_bytes
                .saturating_add(encoded_audio_len(audio)?);
            self.stream_chunk_count = self.stream_chunk_count.saturating_add(1);
        }
        Ok(matches!(event_name, "contextClosed" | "flushCompleted"))
    }

    #[must_use]
    pub fn to_value(&self) -> Value {
        json!(self)
    }
}

pub fn realtime_session_update_event(input: &RealtimeSessionInput) -> FcpResult<Value> {
    input.validate()?;
    let mut session = serde_json::Map::new();
    session.insert("type".to_string(), json!("realtime"));
    session.insert(
        "model".to_string(),
        json!(input.model.as_deref().unwrap_or(DEFAULT_REALTIME_MODEL)),
    );
    session.insert(
        "output_modalities".to_string(),
        json!(
            input
                .output_modalities
                .clone()
                .unwrap_or_else(|| vec!["text".to_string(), "audio".to_string()])
        ),
    );
    if let Some(instructions) = &input.instructions {
        session.insert("instructions".to_string(), json!(instructions));
    }
    if let Some(max_output_tokens) = &input.max_output_tokens {
        session.insert("max_output_tokens".to_string(), max_output_tokens.clone());
    }
    if let Some(temperature) = input.temperature {
        session.insert("temperature".to_string(), json!(temperature));
    }
    if input.voice_id.is_some() || input.tts_model_id.is_some() || input.stt_model_id.is_some() {
        let mut audio = serde_json::Map::new();
        if let Some(stt_model_id) = &input.stt_model_id {
            audio.insert(
                "input".to_string(),
                json!({ "transcription": { "model": stt_model_id } }),
            );
        }
        let mut output = serde_json::Map::new();
        output.insert(
            "voice".to_string(),
            json!(input.voice_id.as_deref().unwrap_or(DEFAULT_VOICE)),
        );
        output.insert(
            "model".to_string(),
            json!(input.tts_model_id.as_deref().unwrap_or(DEFAULT_TTS_MODEL)),
        );
        audio.insert("output".to_string(), Value::Object(output));
        session.insert("audio".to_string(), Value::Object(audio));
    }
    insert_runtime_metadata(&mut session, input);
    merge_object(&mut session, &input.session_extra)?;
    Ok(json!({ "type": "session.update", "session": Value::Object(session) }))
}

pub fn text_item_event(text: &str) -> FcpResult<Value> {
    validate_non_empty("text", text)?;
    if text.chars().count() > MAX_TEXT_CHARS {
        return invalid("text exceeds maximum length");
    }
    Ok(json!({
        "type": "conversation.item.create",
        "item": {
            "type": "message",
            "role": "user",
            "content": [{ "type": "input_text", "text": text }]
        }
    }))
}

pub fn audio_events(input: &AudioTurnInput) -> FcpResult<(Vec<Value>, usize)> {
    let total_audio_bytes = input.validate()?;
    let mut events = Vec::new();
    if input.clear_before_append.unwrap_or(false) {
        events.push(json!({ "type": "input_audio_buffer.clear" }));
    }
    for chunk in &input.audio_chunks_base64 {
        events.push(json!({ "type": "input_audio_buffer.append", "audio": chunk }));
    }
    if input.commit.unwrap_or(true) {
        events.push(json!({ "type": "input_audio_buffer.commit" }));
    }
    Ok((events, total_audio_bytes))
}

#[must_use]
pub fn response_create_event() -> Value {
    json!({
        "type": "response.create",
        "response": {
            "output_modalities": ["text", "audio"]
        }
    })
}

pub fn tts_create_context_event(input: &TtsContextRoundtripInput) -> FcpResult<Value> {
    input.validate()?;
    Ok(json!({
        "create": {
            "voiceId": input.voice_id.as_deref().unwrap_or(DEFAULT_VOICE),
            "modelId": input.model_id.as_deref().unwrap_or("inworld-tts-2"),
            "autoMode": true,
            "timestampType": "WORD",
            "timestampTransportStrategy": "ASYNC"
        },
        "contextId": input.context_id()
    }))
}

pub fn tts_send_text_event(input: &TtsContextRoundtripInput) -> FcpResult<Value> {
    input.validate()?;
    let mut send_text = serde_json::Map::new();
    send_text.insert("text".to_string(), json!(input.text));
    if input.flush.unwrap_or(true) {
        send_text.insert("flush_context".to_string(), json!({}));
    }
    Ok(json!({
        "send_text": Value::Object(send_text),
        "contextId": input.context_id()
    }))
}

#[must_use]
pub fn tts_close_context_event(context_id: &str) -> Value {
    json!({ "close_context": {}, "contextId": context_id })
}

pub fn router_request_body(input: &RouterChatCompletionInput) -> FcpResult<Value> {
    input.validate()?;
    let mut body = serde_json::Map::new();
    body.insert("model".to_string(), json!(input.model));
    body.insert("messages".to_string(), json!(input.messages));
    if let Some(temperature) = input.temperature {
        body.insert("temperature".to_string(), json!(temperature));
    }
    if let Some(top_p) = input.top_p {
        body.insert("top_p".to_string(), json!(top_p));
    }
    if let Some(max_tokens) = input.max_tokens {
        body.insert("max_tokens".to_string(), json!(max_tokens));
    }
    if let Some(max_completion_tokens) = input.max_completion_tokens {
        body.insert(
            "max_completion_tokens".to_string(),
            json!(max_completion_tokens),
        );
    }
    if input.extra_body != Value::Null {
        body.insert("extra_body".to_string(), input.extra_body.clone());
    }
    Ok(Value::Object(body))
}

#[must_use]
pub fn stable_hash(value: &str) -> String {
    blake3::hash(value.as_bytes())
        .to_hex()
        .chars()
        .take(16)
        .collect()
}

#[must_use]
pub fn optional_hash(value: Option<&str>) -> Value {
    value.map(stable_hash).map_or(Value::Null, Value::String)
}

fn insert_runtime_metadata(
    session: &mut serde_json::Map<String, Value>,
    input: &RealtimeSessionInput,
) {
    let mut metadata = serde_json::Map::new();
    if let Some(character_id) = &input.character_id {
        metadata.insert("character_id".to_string(), json!(character_id));
    }
    if let Some(profile_id) = &input.profile_id {
        metadata.insert("profile_id".to_string(), json!(profile_id));
    }
    if let Some(event_history_id) = &input.event_history_id {
        metadata.insert("event_history_id".to_string(), json!(event_history_id));
    }
    if let Some(conversation_state_id) = &input.conversation_state_id {
        metadata.insert(
            "conversation_state_id".to_string(),
            json!(conversation_state_id),
        );
    }
    if !metadata.is_empty() {
        session.insert("metadata".to_string(), Value::Object(metadata));
    }
}

fn merge_object(target: &mut serde_json::Map<String, Value>, value: &Value) -> FcpResult<()> {
    match value {
        Value::Null => Ok(()),
        Value::Object(map) => {
            target.extend(map.iter().map(|(key, value)| (key.clone(), value.clone())));
            Ok(())
        }
        _ => invalid("session_extra must be an object when supplied"),
    }
}

fn tts_event_name(value: &Value) -> Option<&'static str> {
    let result = value.get("result")?;
    if result.get("contextCreated").is_some() {
        Some("contextCreated")
    } else if result.get("audioChunk").is_some() {
        Some("audioChunk")
    } else if result.get("contextClosed").is_some() {
        Some("contextClosed")
    } else if result.get("flushCompleted").is_some() {
        Some("flushCompleted")
    } else {
        None
    }
}

fn encoded_audio_len(value: &str) -> FcpResult<usize> {
    BASE64
        .decode(value)
        .map(|bytes| bytes.len())
        .map_err(|err| FcpError::InvalidRequest {
            code: 1003,
            message: format!("invalid base64 audio in Inworld event: {err}"),
        })
}

fn push_unique_hash(unique_hashes: &mut Vec<String>, value: &str) {
    let hashed = stable_hash(value);
    if !unique_hashes.contains(&hashed) {
        unique_hashes.push(hashed);
    }
}

fn validate_optional_id(field: &str, value: Option<&str>) -> FcpResult<()> {
    if let Some(value) = value {
        validate_non_empty(field, value)?;
        if value.chars().count() > 256 {
            return invalid(&format!("{field} exceeds maximum length"));
        }
    }
    Ok(())
}

fn validate_non_empty(field: &str, value: &str) -> FcpResult<()> {
    if value.trim().is_empty() {
        invalid(&format!("{field} must not be empty"))
    } else {
        Ok(())
    }
}

fn validate_enum(field: &str, value: &str, allowed: &[&str]) -> FcpResult<()> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        invalid(&format!("{field} must be one of {}", allowed.join(", ")))
    }
}

fn invalid<T>(message: &str) -> FcpResult<T> {
    Err(FcpError::InvalidRequest {
        code: 1003,
        message: message.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_event_rejects_empty_input() {
        assert!(text_item_event(" ").is_err());
    }

    #[test]
    fn audio_events_count_decoded_bytes_and_commit() {
        let input = AudioTurnInput {
            session: RealtimeSessionInput {
                session_id: "session-1".into(),
                model: None,
                voice_id: None,
                tts_model_id: None,
                stt_model_id: None,
                character_id: None,
                profile_id: None,
                event_history_id: None,
                conversation_state_id: None,
                output_modalities: None,
                instructions: None,
                max_output_tokens: None,
                temperature: None,
                timeout_ms: None,
                max_events: None,
                session_extra: Value::Null,
            },
            audio_chunks_base64: vec![BASE64.encode([1_u8, 2, 3])],
            clear_before_append: Some(true),
            commit: Some(true),
            create_response: Some(true),
        };
        let (events, bytes) = audio_events(&input).expect("audio events");
        assert_eq!(bytes, 3);
        assert_eq!(events[0]["type"], "input_audio_buffer.clear");
        assert_eq!(events[1]["type"], "input_audio_buffer.append");
        assert_eq!(events[2]["type"], "input_audio_buffer.commit");
    }

    #[test]
    fn event_summary_counts_without_preserving_text() {
        let mut summary = EventSummary::default();
        assert!(
            !summary
                .observe(&json!({"type": "response.output_text.delta", "delta": "secret text"}))
                .expect("observe delta")
        );
        assert!(
            summary
                .observe(&json!({"type": "response.done"}))
                .expect("observe done")
        );
        let value = summary.to_value().to_string();
        assert_eq!(summary.text_output_bytes, "secret text".len());
        assert!(!value.contains("secret text"));
    }

    #[test]
    fn event_summary_accepts_current_realtime_event_family() {
        let mut summary = EventSummary::default();
        for event in [
            json!({"type": "session.created"}),
            json!({"type": "session.updated"}),
            json!({"type": "conversation.item.added", "item": { "id": "secret-item-id" }}),
            json!({"type": "response.output_audio.delta", "delta": BASE64.encode([1_u8, 2])}),
            json!({"type": "rate_limits.updated"}),
        ] {
            assert!(!summary.observe(&event).expect("observe event"));
        }
        assert!(summary.event_types.contains(&"session.created".to_string()));
        assert!(summary.event_types.contains(&"session.updated".to_string()));
        assert!(
            summary
                .event_types
                .contains(&"rate_limits.updated".to_string())
        );
        assert_eq!(summary.audio_output_bytes, 2);
        let serialized = summary.to_value().to_string();
        assert!(!serialized.contains("secret-item-id"));
    }

    #[test]
    fn error_events_finish_summary_with_code_only() {
        let mut summary = EventSummary::default();
        assert!(
            summary
                .observe(&json!({
                    "type": "error",
                    "error": {
                        "code": "rate_limit_exceeded",
                        "message": "provider secret"
                    }
                }))
                .expect("observe error")
        );
        assert_eq!(summary.error_code.as_deref(), Some("rate_limit_exceeded"));
        assert!(!summary.to_value().to_string().contains("provider secret"));
    }

    #[test]
    fn tts_close_frame_matches_current_websocket_docs() {
        assert_eq!(
            tts_close_context_event("ctx-1"),
            json!({ "close_context": {}, "contextId": "ctx-1" })
        );
    }
}
