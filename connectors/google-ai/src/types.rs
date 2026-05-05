//! Google AI (Gemini) API types.

use std::fmt;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// A content message with role and parts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Content {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    pub parts: Vec<Part>,
}

/// A content part (text, inline data, function call, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Part {
    /// Text content.
    Text { text: String },
    /// Function call from the model.
    FunctionCall {
        #[serde(rename = "functionCall")]
        function_call: FunctionCallData,
    },
    /// Function response to the model.
    FunctionResponse {
        #[serde(rename = "functionResponse")]
        function_response: FunctionResponseData,
    },
}

/// Function call data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCallData {
    pub name: String,
    pub args: serde_json::Value,
}

/// Function response data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionResponseData {
    pub name: String,
    pub response: serde_json::Value,
}

/// Response from generateContent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateContentResponse {
    #[serde(default)]
    pub candidates: Vec<Candidate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_metadata: Option<UsageMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_version: Option<String>,
}

/// A generation candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Candidate {
    pub content: Option<Content>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finish_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safety_ratings: Option<Vec<SafetyRating>>,
}

/// Safety rating for a candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyRating {
    pub category: String,
    pub probability: String,
}

/// Token usage metadata.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct UsageMetadata {
    #[serde(default)]
    pub prompt_token_count: u64,
    #[serde(default)]
    pub candidates_token_count: u64,
    #[serde(default)]
    pub total_token_count: u64,
}

/// Response from embedContent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbedContentResponse {
    pub embedding: Embedding,
}

/// An embedding vector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Embedding {
    pub values: Vec<f64>,
}

/// Response from batchEmbedContents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchEmbedContentsResponse {
    pub embeddings: Vec<Embedding>,
}

/// Response from countTokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CountTokensResponse {
    pub total_tokens: u64,
}

/// Model information.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelInfo {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default)]
    pub supported_generation_methods: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_token_limit: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_token_limit: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_k: Option<u32>,
}

/// Response from list models.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListModelsResponse {
    pub models: Vec<ModelInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,
}

/// Request to create a tuned model.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTunedModelRequest {
    #[serde(alias = "tuned_model_id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tuned_model_id: Option<String>,
    #[serde(alias = "display_name")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(alias = "source_model")]
    pub source_model: String,
    #[serde(alias = "tuning_task")]
    pub tuning_task: TuningTaskConfig,
}

impl CreateTunedModelRequest {
    /// Validate the request before sending it to the API.
    pub fn validate(&self) -> Result<(), String> {
        if self.source_model.trim().is_empty() {
            return Err("source_model must not be empty".into());
        }
        self.tuning_task.validate()
    }
}

/// User-supplied tuning task configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TuningTaskConfig {
    #[serde(alias = "training_data")]
    pub training_data: TuningDataset,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hyperparameters: Option<Hyperparameters>,
}

impl TuningTaskConfig {
    /// Validate the tuning task config.
    pub fn validate(&self) -> Result<(), String> {
        self.training_data.validate()
    }
}

/// Training dataset for a tuned model job.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TuningDataset {
    pub examples: Vec<TuningExample>,
}

impl TuningDataset {
    /// Validate that the dataset contains usable examples.
    pub fn validate(&self) -> Result<(), String> {
        if self.examples.is_empty() {
            return Err("training_data.examples must include at least one example".into());
        }
        for (idx, example) in self.examples.iter().enumerate() {
            if example.text_input.trim().is_empty() {
                return Err(format!(
                    "training_data.examples[{idx}].text_input must not be empty"
                ));
            }
            if example.output.trim().is_empty() {
                return Err(format!(
                    "training_data.examples[{idx}].output must not be empty"
                ));
            }
        }
        Ok(())
    }
}

/// One supervised tuning example.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TuningExample {
    #[serde(alias = "text_input")]
    pub text_input: String,
    pub output: String,
}

/// Hyperparameters for a tuning job.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Hyperparameters {
    #[serde(alias = "epoch_count")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch_count: Option<u32>,
    #[serde(alias = "batch_size")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_size: Option<u32>,
    #[serde(alias = "learning_rate")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub learning_rate: Option<f64>,
}

/// Request to list tuned models.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ListTunedModelsRequest {
    #[serde(alias = "page_size")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_size: Option<u32>,
    #[serde(alias = "page_token")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_token: Option<String>,
}

impl ListTunedModelsRequest {
    /// Validate the listing options.
    pub fn validate(&self) -> Result<(), String> {
        if self.page_size == Some(0) {
            return Err("page_size must be greater than zero".into());
        }
        Ok(())
    }
}

/// Request to fetch one tuned model.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetTunedModelRequest {
    #[serde(alias = "tuned_model")]
    pub tuned_model: String,
}

impl GetTunedModelRequest {
    /// Validate the resource selector.
    pub fn validate(&self) -> Result<(), String> {
        if self.tuned_model.trim().is_empty() {
            return Err("tuned_model must not be empty".into());
        }
        Ok(())
    }
}

/// Request to fetch a long-running tuning operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetTuningOperationRequest {
    pub operation: String,
}

impl GetTuningOperationRequest {
    /// Validate the operation selector.
    pub fn validate(&self) -> Result<(), String> {
        if self.operation.trim().is_empty() {
            return Err("operation must not be empty".into());
        }
        if !self.operation.contains("/operations/") {
            return Err("operation must be a full tuned model operation resource".into());
        }
        Ok(())
    }
}

/// Request to cancel a long-running tuning operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelTuningOperationRequest {
    pub operation: String,
}

impl CancelTuningOperationRequest {
    /// Validate the cancel request.
    pub fn validate(&self) -> Result<(), String> {
        GetTuningOperationRequest {
            operation: self.operation.clone(),
        }
        .validate()
    }
}

/// Response from list tuned models.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListTunedModelsResponse {
    #[serde(default)]
    pub tuned_models: Vec<TunedModel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,
}

/// Tuned model metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TunedModel {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub create_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_time: Option<String>,
    #[serde(default)]
    pub supported_generation_methods: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_token_limit: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_token_limit: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tuning_task: Option<TuningTask>,
}

/// Tuning task status embedded in a tuned model.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TuningTask {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub complete_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hyperparameters: Option<Hyperparameters>,
    #[serde(default)]
    pub snapshots: Vec<TuningSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub training_data: Option<TuningDataset>,
}

/// One progress snapshot from a tuning task.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TuningSnapshot {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mean_loss: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compute_time: Option<String>,
}

/// Long-running operation returned by tuned model create jobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TuningOperation {
    pub name: String,
    #[serde(default)]
    pub done: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<OperationError>,
}

/// Structured long-running operation error details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// Google AI API error response body.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    pub error: Option<ApiErrorDetail>,
}

/// Detail of an API error.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorDetail {
    pub message: Option<String>,
    pub status: Option<String>,
    pub code: Option<u16>,
}

/// Local usage counters tracked by the connector.
#[derive(Debug, Clone, Default)]
pub struct UsageCounters {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub requests_total: u64,
    pub requests_error: u64,
}

/// Default Google Live model mirrored from OpenClaw's Google realtime provider.
pub const GOOGLE_LIVE_DEFAULT_MODEL: &str = "gemini-2.5-flash-native-audio-preview-12-2025";
/// Default prebuilt Google Live voice mirrored from OpenClaw.
pub const GOOGLE_LIVE_DEFAULT_VOICE: &str = "Kore";
/// Google ephemeral Live tokens are currently constrained to the v1alpha API.
pub const GOOGLE_LIVE_BROWSER_API_VERSION: &str = "v1alpha";
/// Browser WebSocket path for constrained Google Live sessions.
pub const GOOGLE_LIVE_BROWSER_WEBSOCKET_URL: &str = "wss://generativelanguage.googleapis.com/ws/google.ai.generativelanguage.v1alpha.GenerativeService.BidiGenerateContentConstrained";
/// Gemini Live expects realtime audio input as 16 kHz PCM.
pub const GOOGLE_LIVE_INPUT_SAMPLE_RATE_HZ: u32 = 16_000;
/// Gemini Live emits audio as 24 kHz PCM by default.
pub const GOOGLE_LIVE_OUTPUT_SAMPLE_RATE_HZ: u32 = 24_000;
/// Default token lifetime for established Live sessions.
pub const GOOGLE_LIVE_BROWSER_SESSION_TTL_SECS: i64 = 30 * 60;
/// Default time window for opening a new Live session from an ephemeral token.
pub const GOOGLE_LIVE_BROWSER_NEW_SESSION_TTL_SECS: i64 = 60;
/// Bound copied from OpenClaw's pending-audio queue.
pub const GOOGLE_LIVE_MAX_PENDING_AUDIO_CHUNKS: usize = 320;
/// Name of the non-blocking consult tool used by OpenClaw's voice bridge.
pub const GOOGLE_LIVE_AGENT_CONSULT_TOOL_NAME: &str = "openclaw_agent_consult";

/// Request to create a constrained browser-session token for Google Live.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GoogleLiveBrowserSessionRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub voice: Option<String>,
    #[serde(alias = "api_version", skip_serializing_if = "Option::is_none")]
    pub api_version: Option<String>,
    #[serde(alias = "system_instruction", skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
    #[serde(default)]
    pub tools: Vec<GoogleLiveToolDeclaration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    #[serde(alias = "prefix_padding_ms", skip_serializing_if = "Option::is_none")]
    pub prefix_padding_ms: Option<i64>,
    #[serde(alias = "silence_duration_ms", skip_serializing_if = "Option::is_none")]
    pub silence_duration_ms: Option<i64>,
    #[serde(alias = "start_sensitivity", skip_serializing_if = "Option::is_none")]
    pub start_sensitivity: Option<String>,
    #[serde(alias = "end_sensitivity", skip_serializing_if = "Option::is_none")]
    pub end_sensitivity: Option<String>,
    #[serde(alias = "activity_handling", skip_serializing_if = "Option::is_none")]
    pub activity_handling: Option<String>,
    #[serde(alias = "turn_coverage", skip_serializing_if = "Option::is_none")]
    pub turn_coverage: Option<String>,
    #[serde(
        alias = "automatic_activity_detection_disabled",
        skip_serializing_if = "Option::is_none"
    )]
    pub automatic_activity_detection_disabled: Option<bool>,
    #[serde(
        alias = "enable_affective_dialog",
        skip_serializing_if = "Option::is_none"
    )]
    pub enable_affective_dialog: Option<bool>,
    #[serde(alias = "session_resumption", skip_serializing_if = "Option::is_none")]
    pub session_resumption: Option<bool>,
    #[serde(
        alias = "context_window_compression",
        skip_serializing_if = "Option::is_none"
    )]
    pub context_window_compression: Option<bool>,
    #[serde(alias = "thinking_level", skip_serializing_if = "Option::is_none")]
    pub thinking_level: Option<String>,
    #[serde(alias = "thinking_budget", skip_serializing_if = "Option::is_none")]
    pub thinking_budget: Option<i64>,
    #[serde(alias = "expire_time", skip_serializing_if = "Option::is_none")]
    pub expire_time: Option<String>,
    #[serde(
        alias = "new_session_expire_time",
        skip_serializing_if = "Option::is_none"
    )]
    pub new_session_expire_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uses: Option<u32>,
}

impl GoogleLiveBrowserSessionRequest {
    /// Validate the Live browser-session request before network IO.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(model) = trimmed_opt(self.model.as_deref()) {
            if model.is_empty() {
                return Err("model must not be empty".into());
            }
        }
        if let Some(voice) = trimmed_opt(self.voice.as_deref()) {
            if voice.is_empty() {
                return Err("voice must not be empty".into());
            }
        }
        if self.normalized_api_version() != GOOGLE_LIVE_BROWSER_API_VERSION {
            return Err("Google Live browser sessions require api_version v1alpha".into());
        }
        if self.uses == Some(0) {
            return Err("uses must be greater than zero".into());
        }
        if let Some(temperature) = self.temperature {
            if !temperature.is_finite() {
                return Err("temperature must be finite".into());
            }
        }
        if let Some(expire_time) = &self.expire_time {
            parse_rfc3339_epoch(expire_time)
                .map_err(|_| "expire_time must be an RFC3339 timestamp".to_string())?;
        }
        if let Some(new_session_expire_time) = &self.new_session_expire_time {
            parse_rfc3339_epoch(new_session_expire_time)
                .map_err(|_| "new_session_expire_time must be an RFC3339 timestamp".to_string())?;
        }
        Ok(())
    }

    /// API version to use for ephemeral token creation.
    #[must_use]
    pub fn normalized_api_version(&self) -> String {
        trimmed_opt(self.api_version.as_deref())
            .unwrap_or(GOOGLE_LIVE_BROWSER_API_VERSION)
            .to_string()
    }

    /// Model ID, without the `models/` resource prefix.
    #[must_use]
    pub fn normalized_model(&self) -> String {
        trimmed_opt(self.model.as_deref())
            .unwrap_or(GOOGLE_LIVE_DEFAULT_MODEL)
            .trim_start_matches("models/")
            .to_string()
    }

    /// Full Google model resource name.
    #[must_use]
    pub fn model_resource(&self) -> String {
        format!("models/{}", self.normalized_model())
    }

    /// Voice name to lock into the browser token.
    #[must_use]
    pub fn normalized_voice(&self) -> String {
        trimmed_opt(self.voice.as_deref())
            .unwrap_or(GOOGLE_LIVE_DEFAULT_VOICE)
            .to_string()
    }

    /// Build the body for `AuthTokenService.CreateToken`.
    #[must_use]
    pub fn auth_token_body(&self, now: DateTime<Utc>) -> serde_json::Value {
        json!({
            "uses": self.uses.unwrap_or(1),
            "expireTime": self.expire_time.clone().unwrap_or_else(|| {
                (now + Duration::seconds(GOOGLE_LIVE_BROWSER_SESSION_TTL_SECS)).to_rfc3339()
            }),
            "newSessionExpireTime": self.new_session_expire_time.clone().unwrap_or_else(|| {
                (now + Duration::seconds(GOOGLE_LIVE_BROWSER_NEW_SESSION_TTL_SECS)).to_rfc3339()
            }),
            "bidiGenerateContentSetup": self.bidi_generate_content_setup(),
        })
    }

    /// Setup locked into the ephemeral token.
    #[must_use]
    pub fn bidi_generate_content_setup(&self) -> serde_json::Value {
        let mut generation_config = json!({
            "responseModalities": ["AUDIO"],
            "speechConfig": {
                "voiceConfig": {
                    "prebuiltVoiceConfig": {
                        "voiceName": self.normalized_voice(),
                    },
                },
            },
        });

        if let Some(temperature) = self.temperature.filter(|value| *value > 0.0) {
            generation_config["temperature"] = json!(temperature);
        }
        if let Some(enable_affective_dialog) = self.enable_affective_dialog {
            generation_config["enableAffectiveDialog"] = json!(enable_affective_dialog);
        }
        if let Some(thinking_config) = self.thinking_config() {
            generation_config["thinkingConfig"] = thinking_config;
        }

        let mut setup = json!({
            "model": self.model_resource(),
            "generationConfig": generation_config,
            "inputAudioTranscription": {},
            "outputAudioTranscription": {},
        });

        if let Some(instructions) = trimmed_opt(self.instructions.as_deref()) {
            setup["systemInstruction"] = json!({
                "parts": [{ "text": instructions }],
            });
        }
        if !self.tools.is_empty() {
            setup["tools"] = json!([{
                "functionDeclarations": self.tools
                    .iter()
                    .map(GoogleLiveToolDeclaration::function_declaration)
                    .collect::<Vec<_>>(),
            }]);
        }
        if let Some(realtime_input_config) = self.realtime_input_config() {
            setup["realtimeInputConfig"] = realtime_input_config;
        }
        if self.session_resumption.unwrap_or(true) {
            setup["sessionResumption"] = json!({});
        }
        if self.context_window_compression.unwrap_or(true) {
            setup["contextWindowCompression"] = json!({ "slidingWindow": {} });
        }

        setup
    }

    /// Initial browser message for the constrained `BidiGenerateContentConstrained` socket.
    #[must_use]
    pub fn browser_initial_message(&self) -> serde_json::Value {
        json!({
            "setup": {
                "model": self.model_resource(),
                "generationConfig": {
                    "responseModalities": ["AUDIO"],
                },
                "inputAudioTranscription": {},
                "outputAudioTranscription": {},
            },
        })
    }

    /// Convert a Google token response into the FCP browser-session payload.
    #[must_use]
    pub fn browser_session_response(
        &self,
        client_secret: String,
        now: DateTime<Utc>,
    ) -> GoogleLiveBrowserSessionResponse {
        let expires_at = self
            .expire_time
            .as_deref()
            .and_then(|value| parse_rfc3339_epoch(value).ok())
            .unwrap_or_else(|| {
                (now + Duration::seconds(GOOGLE_LIVE_BROWSER_SESSION_TTL_SECS)).timestamp()
            });
        let new_session_expires_at = self
            .new_session_expire_time
            .as_deref()
            .and_then(|value| parse_rfc3339_epoch(value).ok())
            .unwrap_or_else(|| {
                (now + Duration::seconds(GOOGLE_LIVE_BROWSER_NEW_SESSION_TTL_SECS)).timestamp()
            });

        GoogleLiveBrowserSessionResponse {
            provider: "google".into(),
            transport: "json-pcm-websocket".into(),
            protocol: "google-live-bidi".into(),
            client_secret,
            websocket_url: GOOGLE_LIVE_BROWSER_WEBSOCKET_URL.into(),
            audio: GoogleLiveBrowserSessionAudio {
                input_encoding: "pcm16".into(),
                input_sample_rate_hz: GOOGLE_LIVE_INPUT_SAMPLE_RATE_HZ,
                output_encoding: "pcm16".into(),
                output_sample_rate_hz: GOOGLE_LIVE_OUTPUT_SAMPLE_RATE_HZ,
            },
            initial_message: self.browser_initial_message(),
            model: self.normalized_model(),
            voice: self.normalized_voice(),
            expires_at,
            new_session_expires_at,
        }
    }

    fn thinking_config(&self) -> Option<serde_json::Value> {
        if let Some(level) = normalize_thinking_level(self.thinking_level.as_deref()) {
            return Some(json!({ "thinkingLevel": level }));
        }
        self.thinking_budget
            .map(|budget| json!({ "thinkingBudget": budget }))
    }

    fn realtime_input_config(&self) -> Option<serde_json::Value> {
        let mut automatic_activity_detection = serde_json::Map::new();
        if let Some(disabled) = self.automatic_activity_detection_disabled {
            automatic_activity_detection.insert("disabled".into(), json!(disabled));
        }
        if let Some(start) = normalize_start_sensitivity(self.start_sensitivity.as_deref()) {
            automatic_activity_detection.insert("startOfSpeechSensitivity".into(), json!(start));
        }
        if let Some(end) = normalize_end_sensitivity(self.end_sensitivity.as_deref()) {
            automatic_activity_detection.insert("endOfSpeechSensitivity".into(), json!(end));
        }
        if let Some(prefix_padding_ms) = self.prefix_padding_ms {
            automatic_activity_detection
                .insert("prefixPaddingMs".into(), json!(prefix_padding_ms.max(0)));
        }
        if let Some(silence_duration_ms) = self.silence_duration_ms {
            automatic_activity_detection.insert(
                "silenceDurationMs".into(),
                json!(silence_duration_ms.max(0)),
            );
        }

        let mut config = serde_json::Map::new();
        if !automatic_activity_detection.is_empty() {
            config.insert(
                "automaticActivityDetection".into(),
                serde_json::Value::Object(automatic_activity_detection),
            );
        }
        if let Some(activity_handling) =
            normalize_activity_handling(self.activity_handling.as_deref())
        {
            config.insert("activityHandling".into(), json!(activity_handling));
        }
        if let Some(turn_coverage) = normalize_turn_coverage(self.turn_coverage.as_deref()) {
            config.insert("turnCoverage".into(), json!(turn_coverage));
        }

        if config.is_empty() {
            None
        } else {
            Some(serde_json::Value::Object(config))
        }
    }
}

/// Tool declaration accepted by the Google Live browser-session contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleLiveToolDeclaration {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(alias = "parameters", skip_serializing_if = "Option::is_none")]
    pub parameters_json_schema: Option<serde_json::Value>,
    #[serde(alias = "non_blocking", default)]
    pub non_blocking: bool,
}

impl GoogleLiveToolDeclaration {
    fn function_declaration(&self) -> serde_json::Value {
        let mut declaration = serde_json::Map::new();
        declaration.insert("name".into(), json!(self.name));
        if let Some(description) = trimmed_opt(self.description.as_deref()) {
            declaration.insert("description".into(), json!(description));
        }
        if let Some(parameters) = &self.parameters_json_schema {
            declaration.insert("parametersJsonSchema".into(), parameters.clone());
        }
        if self.non_blocking || self.name == GOOGLE_LIVE_AGENT_CONSULT_TOOL_NAME {
            declaration.insert("behavior".into(), json!("NON_BLOCKING"));
        }
        serde_json::Value::Object(declaration)
    }
}

/// Response returned by `google-ai.live.create_browser_session`.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleLiveBrowserSessionResponse {
    pub provider: String,
    pub transport: String,
    pub protocol: String,
    pub client_secret: String,
    pub websocket_url: String,
    pub audio: GoogleLiveBrowserSessionAudio,
    pub initial_message: serde_json::Value,
    pub model: String,
    pub voice: String,
    pub expires_at: i64,
    pub new_session_expires_at: i64,
}

impl fmt::Debug for GoogleLiveBrowserSessionResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GoogleLiveBrowserSessionResponse")
            .field("provider", &self.provider)
            .field("transport", &self.transport)
            .field("protocol", &self.protocol)
            .field("client_secret", &"<redacted>")
            .field("websocket_url", &self.websocket_url)
            .field("audio", &self.audio)
            .field("initial_message", &self.initial_message)
            .field("model", &self.model)
            .field("voice", &self.voice)
            .field("expires_at", &self.expires_at)
            .field("new_session_expires_at", &self.new_session_expires_at)
            .finish()
    }
}

/// Audio parameters for a Google Live browser session.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleLiveBrowserSessionAudio {
    pub input_encoding: String,
    pub input_sample_rate_hz: u32,
    pub output_encoding: String,
    pub output_sample_rate_hz: u32,
}

/// Minimal token response from Google `AuthTokenService.CreateToken`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleLiveAuthTokenResponse {
    pub name: String,
}

/// Convert a G.711 μ-law 8 kHz frame to 16 kHz little-endian PCM16.
#[must_use]
pub fn convert_google_live_mulaw8k_to_pcm16k(mu_law: &[u8]) -> Vec<u8> {
    if mu_law.is_empty() {
        return Vec::new();
    }
    let mut pcm = Vec::with_capacity(mu_law.len() * 4);
    for (index, sample) in mu_law.iter().enumerate() {
        let current = decode_mulaw_sample(*sample);
        let next = mu_law
            .get(index + 1)
            .copied()
            .map_or(current, decode_mulaw_sample);
        pcm.extend_from_slice(&current.to_le_bytes());
        pcm.extend_from_slice(
            &i16::try_from((i32::from(current) + i32::from(next)) / 2)
                .unwrap_or(if current.is_negative() {
                    i16::MIN
                } else {
                    i16::MAX
                })
                .to_le_bytes(),
        );
    }
    pcm
}

/// Whether a G.711 μ-law frame is silence.
#[must_use]
pub fn is_google_live_mulaw_silence(audio: &[u8]) -> bool {
    !audio.is_empty() && audio.iter().all(|sample| *sample == 0xff)
}

/// Whether a little-endian PCM16 frame is silence.
#[must_use]
pub fn is_google_live_pcm16_silence(audio: &[u8]) -> bool {
    if audio.len() < 2 {
        return false;
    }
    audio
        .chunks_exact(2)
        .all(|sample| i16::from_le_bytes([sample[0], sample[1]]) == 0)
}

/// Whether the pending audio queue can accept one more chunk.
#[must_use]
pub const fn google_live_pending_audio_accepts(current_chunks: usize) -> bool {
    current_chunks < GOOGLE_LIVE_MAX_PENDING_AUDIO_CHUNKS
}

/// Build a Google Live tool response while enforcing continuation policy.
pub fn build_google_live_tool_response(
    call_id: &str,
    name: &str,
    result: serde_json::Value,
    will_continue: bool,
) -> Result<serde_json::Value, String> {
    let normalized_name = name.trim();
    if normalized_name.is_empty() {
        return Err("tool response name must not be empty".into());
    }
    if will_continue && normalized_name != GOOGLE_LIVE_AGENT_CONSULT_TOOL_NAME {
        return Err(format!(
            "Google Live continuation is only supported for {GOOGLE_LIVE_AGENT_CONSULT_TOOL_NAME}"
        ));
    }

    let response = if result.is_object() && !result.is_array() {
        result
    } else {
        json!({ "output": result })
    };
    let mut function_response = json!({
        "id": call_id,
        "name": normalized_name,
        "response": response,
    });
    if normalized_name == GOOGLE_LIVE_AGENT_CONSULT_TOOL_NAME {
        function_response["scheduling"] = json!("WHEN_IDLE");
        if will_continue {
            function_response["willContinue"] = json!(true);
        }
    }

    Ok(json!({
        "functionResponses": [function_response],
    }))
}

fn trimmed_opt(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn normalize_choice<'a>(value: Option<&str>, aliases: &[(&[&str], &'a str)]) -> Option<&'a str> {
    let normalized = value?.trim().to_ascii_lowercase().replace('_', "-");
    aliases
        .iter()
        .find_map(|(keys, output)| keys.contains(&normalized.as_str()).then_some(*output))
}

fn normalize_start_sensitivity(value: Option<&str>) -> Option<&'static str> {
    normalize_choice(
        value,
        &[
            (&["high"], "START_SENSITIVITY_HIGH"),
            (&["low"], "START_SENSITIVITY_LOW"),
        ],
    )
}

fn normalize_end_sensitivity(value: Option<&str>) -> Option<&'static str> {
    normalize_choice(
        value,
        &[
            (&["high"], "END_SENSITIVITY_HIGH"),
            (&["low"], "END_SENSITIVITY_LOW"),
        ],
    )
}

fn normalize_activity_handling(value: Option<&str>) -> Option<&'static str> {
    normalize_choice(
        value,
        &[
            (
                &[
                    "start-of-activity-interrupts",
                    "start-of-activity-interrupt",
                    "interrupt",
                    "interrupts",
                ],
                "START_OF_ACTIVITY_INTERRUPTS",
            ),
            (
                &["no-interruption", "no-interruptions", "none"],
                "NO_INTERRUPTION",
            ),
        ],
    )
}

fn normalize_turn_coverage(value: Option<&str>) -> Option<&'static str> {
    normalize_choice(
        value,
        &[
            (
                &["only-activity", "turn-includes-only-activity"],
                "TURN_INCLUDES_ONLY_ACTIVITY",
            ),
            (
                &["all-input", "turn-includes-all-input"],
                "TURN_INCLUDES_ALL_INPUT",
            ),
            (
                &[
                    "audio-activity-and-all-video",
                    "turn-includes-audio-activity-and-all-video",
                ],
                "TURN_INCLUDES_AUDIO_ACTIVITY_AND_ALL_VIDEO",
            ),
        ],
    )
}

fn normalize_thinking_level(value: Option<&str>) -> Option<&'static str> {
    normalize_choice(
        value,
        &[
            (&["minimal"], "MINIMAL"),
            (&["low"], "LOW"),
            (&["medium"], "MEDIUM"),
            (&["high"], "HIGH"),
        ],
    )
}

fn parse_rfc3339_epoch(value: &str) -> Result<i64, chrono::ParseError> {
    DateTime::parse_from_rfc3339(value).map(|parsed| parsed.timestamp())
}

fn decode_mulaw_sample(value: u8) -> i16 {
    let mu_law = !value;
    let sign = mu_law & 0x80;
    let exponent = (mu_law >> 4) & 0x07;
    let mantissa = mu_law & 0x0f;
    let mut sample = i32::from((mantissa << 3) + 132) << exponent;
    sample -= 132;
    let signed = if sign == 0 { sample } else { -sample };
    i16::try_from(signed).unwrap_or(if signed.is_negative() {
        i16::MIN
    } else {
        i16::MAX
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ════════════════════════════════════════════════════════════════════
    // Google Live browser-session contract
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn live_browser_session_defaults_match_openclaw_google_provider() {
        let request = GoogleLiveBrowserSessionRequest::default();
        assert_eq!(request.normalized_model(), GOOGLE_LIVE_DEFAULT_MODEL);
        assert_eq!(request.normalized_voice(), GOOGLE_LIVE_DEFAULT_VOICE);
        assert_eq!(
            request.normalized_api_version(),
            GOOGLE_LIVE_BROWSER_API_VERSION
        );

        let setup = request.bidi_generate_content_setup();
        assert_eq!(
            setup["model"],
            format!("models/{GOOGLE_LIVE_DEFAULT_MODEL}")
        );
        assert_eq!(
            setup["generationConfig"]["speechConfig"]["voiceConfig"]["prebuiltVoiceConfig"]["voiceName"],
            GOOGLE_LIVE_DEFAULT_VOICE
        );
        assert_eq!(
            setup["generationConfig"]["responseModalities"],
            json!(["AUDIO"])
        );
        assert_eq!(setup["inputAudioTranscription"], json!({}));
        assert_eq!(setup["outputAudioTranscription"], json!({}));
        assert_eq!(setup["sessionResumption"], json!({}));
        assert_eq!(
            setup["contextWindowCompression"],
            json!({"slidingWindow": {}})
        );
    }

    #[test]
    fn live_browser_session_normalizes_activity_turn_and_thinking_config() {
        let request: GoogleLiveBrowserSessionRequest = serde_json::from_value(json!({
            "model": "models/gemini-live-test",
            "voice": "Puck",
            "temperature": 0.4,
            "start_sensitivity": "low",
            "endSensitivity": "high",
            "activity_handling": "no_interruption",
            "turnCoverage": "turn_includes_only_activity",
            "automatic_activity_detection_disabled": true,
            "prefix_padding_ms": -4,
            "silenceDurationMs": 700,
            "thinkingLevel": "minimal",
            "enableAffectiveDialog": true,
            "instructions": "Speak briefly."
        }))
        .unwrap();

        request.validate().unwrap();
        let setup = request.bidi_generate_content_setup();
        assert_eq!(setup["model"], "models/gemini-live-test");
        assert_eq!(setup["generationConfig"]["temperature"], 0.4);
        assert_eq!(
            setup["generationConfig"]["thinkingConfig"],
            json!({"thinkingLevel": "MINIMAL"})
        );
        assert_eq!(setup["generationConfig"]["enableAffectiveDialog"], true);
        assert_eq!(
            setup["systemInstruction"],
            json!({"parts": [{"text": "Speak briefly."}]})
        );
        assert_eq!(
            setup["realtimeInputConfig"],
            json!({
                "automaticActivityDetection": {
                    "disabled": true,
                    "startOfSpeechSensitivity": "START_SENSITIVITY_LOW",
                    "endOfSpeechSensitivity": "END_SENSITIVITY_HIGH",
                    "prefixPaddingMs": 0,
                    "silenceDurationMs": 700,
                },
                "activityHandling": "NO_INTERRUPTION",
                "turnCoverage": "TURN_INCLUDES_ONLY_ACTIVITY",
            })
        );
    }

    #[test]
    fn live_browser_session_can_disable_resumption_and_compression() {
        let request = GoogleLiveBrowserSessionRequest {
            session_resumption: Some(false),
            context_window_compression: Some(false),
            thinking_budget: Some(128),
            temperature: Some(0.0),
            ..Default::default()
        };

        let setup = request.bidi_generate_content_setup();
        assert!(setup.get("sessionResumption").is_none());
        assert!(setup.get("contextWindowCompression").is_none());
        assert!(setup["generationConfig"].get("temperature").is_none());
        assert_eq!(
            setup["generationConfig"]["thinkingConfig"],
            json!({"thinkingBudget": 128})
        );
    }

    #[test]
    fn live_browser_session_rejects_non_v1alpha_api_version() {
        let request = GoogleLiveBrowserSessionRequest {
            api_version: Some("v1beta".into()),
            ..Default::default()
        };
        let err = request.validate().unwrap_err();
        assert!(err.contains("v1alpha"));
    }

    #[test]
    fn live_browser_session_auth_token_body_uses_explicit_ttls_and_constraints() {
        let now = DateTime::parse_from_rfc3339("2026-05-05T20:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let request = GoogleLiveBrowserSessionRequest {
            expire_time: Some("2026-05-05T20:30:00Z".into()),
            new_session_expire_time: Some("2026-05-05T20:01:00Z".into()),
            uses: Some(1),
            ..Default::default()
        };

        let body = request.auth_token_body(now);
        assert_eq!(body["uses"], 1);
        assert_eq!(body["expireTime"], "2026-05-05T20:30:00Z");
        assert_eq!(body["newSessionExpireTime"], "2026-05-05T20:01:00Z");
        assert_eq!(
            body["bidiGenerateContentSetup"]["generationConfig"]["responseModalities"],
            json!(["AUDIO"])
        );
    }

    #[test]
    fn live_browser_session_response_debug_redacts_client_secret() {
        let request = GoogleLiveBrowserSessionRequest::default();
        let now = DateTime::parse_from_rfc3339("2026-05-05T20:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let response = request.browser_session_response("auth_tokens/secret".into(), now);

        assert_eq!(response.client_secret, "auth_tokens/secret");
        assert_eq!(response.websocket_url, GOOGLE_LIVE_BROWSER_WEBSOCKET_URL);
        assert_eq!(response.expires_at, 1_778_013_000);
        let debug = format!("{response:?}");
        assert!(!debug.contains("auth_tokens/secret"));
        assert!(debug.contains("redacted"));
    }

    #[test]
    fn live_tool_declarations_apply_non_blocking_policy() {
        let request = GoogleLiveBrowserSessionRequest {
            tools: vec![
                GoogleLiveToolDeclaration {
                    name: "lookup".into(),
                    description: Some("Look up a value".into()),
                    parameters_json_schema: Some(json!({"type": "object"})),
                    non_blocking: false,
                },
                GoogleLiveToolDeclaration {
                    name: GOOGLE_LIVE_AGENT_CONSULT_TOOL_NAME.into(),
                    description: None,
                    parameters_json_schema: None,
                    non_blocking: false,
                },
            ],
            ..Default::default()
        };

        let tools = &request.bidi_generate_content_setup()["tools"][0]["functionDeclarations"];
        assert_eq!(tools[0]["name"], "lookup");
        assert!(tools[0].get("behavior").is_none());
        assert_eq!(tools[1]["name"], GOOGLE_LIVE_AGENT_CONSULT_TOOL_NAME);
        assert_eq!(tools[1]["behavior"], "NON_BLOCKING");
    }

    #[test]
    fn live_audio_helpers_cover_silence_bounds_and_mulaw_conversion() {
        assert!(is_google_live_mulaw_silence(&[0xff, 0xff]));
        assert!(!is_google_live_mulaw_silence(&[]));
        assert!(is_google_live_pcm16_silence(&[0, 0, 0, 0]));
        assert!(!is_google_live_pcm16_silence(&[1, 0]));
        assert!(google_live_pending_audio_accepts(
            GOOGLE_LIVE_MAX_PENDING_AUDIO_CHUNKS - 1
        ));
        assert!(!google_live_pending_audio_accepts(
            GOOGLE_LIVE_MAX_PENDING_AUDIO_CHUNKS
        ));

        let pcm = convert_google_live_mulaw8k_to_pcm16k(&[0xff, 0x00]);
        let samples: Vec<i16> = pcm
            .chunks_exact(2)
            .map(|chunk| i16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        assert_eq!(samples, vec![0, -16_062, -32_124, -32_124]);
    }

    #[test]
    fn live_tool_response_policy_rejects_invalid_continuation() {
        let err =
            build_google_live_tool_response("call-1", "lookup", json!("ok"), true).unwrap_err();
        assert!(err.contains(GOOGLE_LIVE_AGENT_CONSULT_TOOL_NAME));

        let response = build_google_live_tool_response(
            "call-2",
            GOOGLE_LIVE_AGENT_CONSULT_TOOL_NAME,
            json!("continue"),
            true,
        )
        .unwrap();
        assert_eq!(response["functionResponses"][0]["scheduling"], "WHEN_IDLE");
        assert_eq!(response["functionResponses"][0]["willContinue"], true);
        assert_eq!(
            response["functionResponses"][0]["response"],
            json!({"output": "continue"})
        );
    }

    // ════════════════════════════════════════════════════════════════════
    // Content + Part
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn content_text_roundtrip() {
        let content = Content {
            role: Some("user".to_string()),
            parts: vec![Part::Text {
                text: "Hello!".to_string(),
            }],
        };
        let json = serde_json::to_string(&content).unwrap();
        let back: Content = serde_json::from_str(&json).unwrap();
        assert_eq!(back.role.as_deref(), Some("user"));
        assert_eq!(back.parts.len(), 1);
        match &back.parts[0] {
            Part::Text { text } => assert_eq!(text, "Hello!"),
            other => panic!("expected Text, got {other:?}"),
        }
    }

    #[test]
    fn content_role_none_skipped_in_serialization() {
        let content = Content {
            role: None,
            parts: vec![Part::Text {
                text: "hi".to_string(),
            }],
        };
        let json_str = serde_json::to_string(&content).unwrap();
        assert!(!json_str.contains("role"));
    }

    #[test]
    fn content_role_some_included_in_serialization() {
        let content = Content {
            role: Some("model".to_string()),
            parts: vec![Part::Text {
                text: "hi".to_string(),
            }],
        };
        let json_str = serde_json::to_string(&content).unwrap();
        assert!(json_str.contains("\"role\":\"model\""));
    }

    #[test]
    fn content_missing_role_field_deserializes_as_none() {
        let json = json!({"parts": [{"text": "hi"}]});
        let content: Content = serde_json::from_value(json).unwrap();
        assert!(content.role.is_none());
        assert_eq!(content.parts.len(), 1);
    }

    #[test]
    fn content_empty_parts() {
        let content = Content {
            role: Some("user".into()),
            parts: vec![],
        };
        let json_str = serde_json::to_string(&content).unwrap();
        let back: Content = serde_json::from_str(&json_str).unwrap();
        assert!(back.parts.is_empty());
    }

    #[test]
    fn content_multiple_parts() {
        let content = Content {
            role: Some("user".into()),
            parts: vec![
                Part::Text {
                    text: "part1".into(),
                },
                Part::Text {
                    text: "part2".into(),
                },
            ],
        };
        let json_str = serde_json::to_string(&content).unwrap();
        let back: Content = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.parts.len(), 2);
    }

    #[test]
    fn content_clone() {
        let content = Content {
            role: Some("user".into()),
            parts: vec![Part::Text {
                text: "hello".into(),
            }],
        };
        let cloned = content.clone();
        assert_eq!(cloned.role, content.role);
        assert_eq!(cloned.parts.len(), content.parts.len());
    }

    #[test]
    fn content_debug() {
        let content = Content {
            role: Some("user".into()),
            parts: vec![],
        };
        let debug = format!("{content:?}");
        assert!(debug.contains("Content"));
        assert!(debug.contains("user"));
    }

    // ── Part variants ─────────────────────────────────────────────────

    #[test]
    fn part_text_roundtrip() {
        let part = Part::Text {
            text: "Hello world".into(),
        };
        let json_str = serde_json::to_string(&part).unwrap();
        let back: Part = serde_json::from_str(&json_str).unwrap();
        match back {
            Part::Text { text } => assert_eq!(text, "Hello world"),
            other => panic!("expected Text, got {other:?}"),
        }
    }

    #[test]
    fn part_text_empty_string() {
        let part = Part::Text {
            text: String::new(),
        };
        let json_str = serde_json::to_string(&part).unwrap();
        let back: Part = serde_json::from_str(&json_str).unwrap();
        match back {
            Part::Text { text } => assert!(text.is_empty()),
            other => panic!("expected Text, got {other:?}"),
        }
    }

    #[test]
    fn part_function_call_roundtrip() {
        let part = Part::FunctionCall {
            function_call: FunctionCallData {
                name: "get_weather".to_string(),
                args: json!({"city": "London"}),
            },
        };
        let json_str = serde_json::to_string(&part).unwrap();
        assert!(json_str.contains("functionCall"));
        assert!(!json_str.contains("function_call"));
        let back: Part = serde_json::from_str(&json_str).unwrap();
        match back {
            Part::FunctionCall { function_call } => {
                assert_eq!(function_call.name, "get_weather");
                assert_eq!(function_call.args["city"], "London");
            }
            other => panic!("expected FunctionCall, got {other:?}"),
        }
    }

    #[test]
    fn part_function_call_empty_args() {
        let part = Part::FunctionCall {
            function_call: FunctionCallData {
                name: "no_args_fn".into(),
                args: json!({}),
            },
        };
        let json_str = serde_json::to_string(&part).unwrap();
        let back: Part = serde_json::from_str(&json_str).unwrap();
        match back {
            Part::FunctionCall { function_call } => {
                assert_eq!(function_call.name, "no_args_fn");
                assert!(function_call.args.as_object().unwrap().is_empty());
            }
            other => panic!("expected FunctionCall, got {other:?}"),
        }
    }

    #[test]
    fn part_function_response_roundtrip() {
        let part = Part::FunctionResponse {
            function_response: FunctionResponseData {
                name: "get_weather".to_string(),
                response: json!({"temp": 20, "unit": "celsius"}),
            },
        };
        let json_str = serde_json::to_string(&part).unwrap();
        assert!(json_str.contains("functionResponse"));
        let back: Part = serde_json::from_str(&json_str).unwrap();
        match back {
            Part::FunctionResponse { function_response } => {
                assert_eq!(function_response.name, "get_weather");
                assert_eq!(function_response.response["temp"], 20);
            }
            other => panic!("expected FunctionResponse, got {other:?}"),
        }
    }

    #[test]
    fn part_function_response_null_response() {
        let part = Part::FunctionResponse {
            function_response: FunctionResponseData {
                name: "void_fn".into(),
                response: json!(null),
            },
        };
        let json_str = serde_json::to_string(&part).unwrap();
        let back: Part = serde_json::from_str(&json_str).unwrap();
        match back {
            Part::FunctionResponse { function_response } => {
                assert!(function_response.response.is_null());
            }
            other => panic!("expected FunctionResponse, got {other:?}"),
        }
    }

    #[test]
    fn part_clone() {
        let part = Part::Text {
            text: "test".into(),
        };
        let cloned = part.clone();
        let json_orig = serde_json::to_string(&part).unwrap();
        let json_clone = serde_json::to_string(&cloned).unwrap();
        assert_eq!(json_orig, json_clone);
    }

    #[test]
    fn part_debug() {
        let part = Part::Text {
            text: "hello".into(),
        };
        let debug = format!("{part:?}");
        assert!(debug.contains("Text"));
        assert!(debug.contains("hello"));
    }

    // ── FunctionCallData ──────────────────────────────────────────────

    #[test]
    fn function_call_data_roundtrip() {
        let data = FunctionCallData {
            name: "search".into(),
            args: json!({"query": "test", "limit": 10}),
        };
        let json_str = serde_json::to_string(&data).unwrap();
        let back: FunctionCallData = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.name, "search");
        assert_eq!(back.args["limit"], 10);
    }

    #[test]
    fn function_call_data_clone_debug() {
        let data = FunctionCallData {
            name: "fn1".into(),
            args: json!(null),
        };
        let cloned = data.clone();
        assert_eq!(cloned.name, "fn1");
        let debug = format!("{data:?}");
        assert!(debug.contains("FunctionCallData"));
    }

    // ── FunctionResponseData ──────────────────────────────────────────

    #[test]
    fn function_response_data_roundtrip() {
        let data = FunctionResponseData {
            name: "search".into(),
            response: json!({"results": [1, 2, 3]}),
        };
        let json_str = serde_json::to_string(&data).unwrap();
        let back: FunctionResponseData = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.name, "search");
        assert_eq!(back.response["results"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn function_response_data_clone_debug() {
        let data = FunctionResponseData {
            name: "fn1".into(),
            response: json!("ok"),
        };
        let cloned = data.clone();
        assert_eq!(cloned.name, "fn1");
        let debug = format!("{data:?}");
        assert!(debug.contains("FunctionResponseData"));
    }

    // ════════════════════════════════════════════════════════════════════
    // GenerateContentResponse
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn generate_content_response_full_roundtrip() {
        let json = json!({
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": "Hi!"}]},
                "finishReason": "STOP",
                "index": 0,
                "safetyRatings": [{"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "probability": "NEGLIGIBLE"}]
            }],
            "usageMetadata": {
                "promptTokenCount": 10,
                "candidatesTokenCount": 5,
                "totalTokenCount": 15
            },
            "modelVersion": "gemini-2.0-flash-001"
        });
        let resp: GenerateContentResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.candidates.len(), 1);
        assert_eq!(resp.candidates[0].finish_reason.as_deref(), Some("STOP"));
        assert_eq!(resp.candidates[0].index, Some(0));
        let usage = resp.usage_metadata.as_ref().unwrap();
        assert_eq!(usage.prompt_token_count, 10);
        assert_eq!(usage.candidates_token_count, 5);
        assert_eq!(usage.total_token_count, 15);
        assert_eq!(resp.model_version.as_deref(), Some("gemini-2.0-flash-001"));

        // Re-serialize and verify camelCase
        let re_json = serde_json::to_string(&resp).unwrap();
        assert!(re_json.contains("finishReason"));
        assert!(re_json.contains("promptTokenCount"));
        assert!(re_json.contains("modelVersion"));
    }

    #[test]
    fn generate_content_response_empty_object() {
        let json = json!({});
        let resp: GenerateContentResponse = serde_json::from_value(json).unwrap();
        assert!(resp.candidates.is_empty());
        assert!(resp.usage_metadata.is_none());
        assert!(resp.model_version.is_none());
    }

    #[test]
    fn generate_content_response_no_usage_metadata() {
        let json = json!({
            "candidates": [{
                "content": {"parts": [{"text": "response"}]},
                "finishReason": "STOP"
            }]
        });
        let resp: GenerateContentResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.candidates.len(), 1);
        assert!(resp.usage_metadata.is_none());
    }

    #[test]
    fn generate_content_response_multiple_candidates() {
        let json = json!({
            "candidates": [
                {"content": {"parts": [{"text": "A"}]}, "index": 0},
                {"content": {"parts": [{"text": "B"}]}, "index": 1}
            ]
        });
        let resp: GenerateContentResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.candidates.len(), 2);
        assert_eq!(resp.candidates[0].index, Some(0));
        assert_eq!(resp.candidates[1].index, Some(1));
    }

    #[test]
    fn generate_content_response_skip_serializing_none_fields() {
        let resp = GenerateContentResponse {
            candidates: vec![],
            usage_metadata: None,
            model_version: None,
        };
        let json_str = serde_json::to_string(&resp).unwrap();
        assert!(!json_str.contains("usageMetadata"));
        assert!(!json_str.contains("modelVersion"));
    }

    #[test]
    fn generate_content_response_clone_debug() {
        let resp = GenerateContentResponse {
            candidates: vec![],
            usage_metadata: None,
            model_version: Some("v1".into()),
        };
        let cloned = resp.clone();
        assert_eq!(cloned.model_version, resp.model_version);
        let debug = format!("{resp:?}");
        assert!(debug.contains("GenerateContentResponse"));
    }

    // ════════════════════════════════════════════════════════════════════
    // Candidate
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn candidate_full_roundtrip() {
        let json = json!({
            "content": {"role": "model", "parts": [{"text": "test"}]},
            "finishReason": "MAX_TOKENS",
            "index": 2,
            "safetyRatings": [
                {"category": "HARM_CATEGORY_HARASSMENT", "probability": "LOW"},
                {"category": "HARM_CATEGORY_HATE_SPEECH", "probability": "NEGLIGIBLE"}
            ]
        });
        let candidate: Candidate = serde_json::from_value(json).unwrap();
        assert!(candidate.content.is_some());
        assert_eq!(candidate.finish_reason.as_deref(), Some("MAX_TOKENS"));
        assert_eq!(candidate.index, Some(2));
        assert_eq!(candidate.safety_ratings.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn candidate_minimal() {
        let json = json!({});
        let candidate: Candidate = serde_json::from_value(json).unwrap();
        assert!(candidate.content.is_none());
        assert!(candidate.finish_reason.is_none());
        assert!(candidate.index.is_none());
        assert!(candidate.safety_ratings.is_none());
    }

    #[test]
    fn candidate_no_content() {
        // Some safety-blocked responses have no content
        let json = json!({
            "finishReason": "SAFETY",
            "safetyRatings": [{"category": "HARM_CATEGORY_DANGEROUS", "probability": "HIGH"}]
        });
        let candidate: Candidate = serde_json::from_value(json).unwrap();
        assert!(candidate.content.is_none());
        assert_eq!(candidate.finish_reason.as_deref(), Some("SAFETY"));
    }

    #[test]
    fn candidate_skip_serializing_none_fields() {
        let candidate = Candidate {
            content: None,
            finish_reason: None,
            index: None,
            safety_ratings: None,
        };
        let json_str = serde_json::to_string(&candidate).unwrap();
        assert!(!json_str.contains("finishReason"));
        assert!(!json_str.contains("index"));
        assert!(!json_str.contains("safetyRatings"));
        // content is not skip_serializing_if, so it will appear as null
        assert!(json_str.contains("content"));
    }

    #[test]
    fn candidate_clone_debug() {
        let candidate = Candidate {
            content: Some(Content {
                role: Some("model".into()),
                parts: vec![],
            }),
            finish_reason: Some("STOP".into()),
            index: Some(0),
            safety_ratings: None,
        };
        let cloned = candidate.clone();
        assert_eq!(cloned.finish_reason, candidate.finish_reason);
        let debug = format!("{candidate:?}");
        assert!(debug.contains("Candidate"));
    }

    // ════════════════════════════════════════════════════════════════════
    // SafetyRating
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn safety_rating_roundtrip() {
        let rating = SafetyRating {
            category: "HARM_CATEGORY_SEXUALLY_EXPLICIT".into(),
            probability: "NEGLIGIBLE".into(),
        };
        let json_str = serde_json::to_string(&rating).unwrap();
        let back: SafetyRating = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.category, "HARM_CATEGORY_SEXUALLY_EXPLICIT");
        assert_eq!(back.probability, "NEGLIGIBLE");
    }

    #[test]
    fn safety_rating_clone_debug() {
        let rating = SafetyRating {
            category: "TEST".into(),
            probability: "HIGH".into(),
        };
        let cloned = rating.clone();
        assert_eq!(cloned.category, "TEST");
        let debug = format!("{rating:?}");
        assert!(debug.contains("SafetyRating"));
    }

    // ════════════════════════════════════════════════════════════════════
    // UsageMetadata
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn usage_metadata_default() {
        let usage = UsageMetadata::default();
        assert_eq!(usage.prompt_token_count, 0);
        assert_eq!(usage.candidates_token_count, 0);
        assert_eq!(usage.total_token_count, 0);
    }

    #[test]
    fn usage_metadata_roundtrip() {
        let json = json!({
            "promptTokenCount": 100,
            "candidatesTokenCount": 200,
            "totalTokenCount": 300
        });
        let usage: UsageMetadata = serde_json::from_value(json).unwrap();
        assert_eq!(usage.prompt_token_count, 100);
        assert_eq!(usage.candidates_token_count, 200);
        assert_eq!(usage.total_token_count, 300);

        // Re-serialize
        let re_json = serde_json::to_value(&usage).unwrap();
        assert_eq!(re_json["promptTokenCount"], 100);
    }

    #[test]
    fn usage_metadata_missing_fields_default_to_zero() {
        let json = json!({});
        let usage: UsageMetadata = serde_json::from_value(json).unwrap();
        assert_eq!(usage.prompt_token_count, 0);
        assert_eq!(usage.candidates_token_count, 0);
        assert_eq!(usage.total_token_count, 0);
    }

    #[test]
    fn usage_metadata_partial_fields() {
        let json = json!({"promptTokenCount": 42});
        let usage: UsageMetadata = serde_json::from_value(json).unwrap();
        assert_eq!(usage.prompt_token_count, 42);
        assert_eq!(usage.candidates_token_count, 0);
        assert_eq!(usage.total_token_count, 0);
    }

    #[test]
    fn usage_metadata_clone_debug() {
        let usage = UsageMetadata {
            prompt_token_count: 10,
            candidates_token_count: 20,
            total_token_count: 30,
        };
        let cloned = usage.clone();
        assert_eq!(cloned.total_token_count, 30);
        let debug = format!("{usage:?}");
        assert!(debug.contains("UsageMetadata"));
        assert!(debug.contains("30"));
    }

    // ════════════════════════════════════════════════════════════════════
    // EmbedContentResponse
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn embed_content_response_roundtrip() {
        let json = json!({"embedding": {"values": [0.1, 0.2, 0.3]}});
        let resp: EmbedContentResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.embedding.values.len(), 3);
        assert!((resp.embedding.values[0] - 0.1).abs() < f64::EPSILON);

        let re_json = serde_json::to_value(&resp).unwrap();
        assert_eq!(re_json["embedding"]["values"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn embed_content_response_empty_values() {
        let json = json!({"embedding": {"values": []}});
        let resp: EmbedContentResponse = serde_json::from_value(json).unwrap();
        assert!(resp.embedding.values.is_empty());
    }

    #[test]
    fn embed_content_response_clone_debug() {
        let resp = EmbedContentResponse {
            embedding: Embedding {
                values: vec![1.0, 2.0],
            },
        };
        let cloned = resp.clone();
        assert_eq!(cloned.embedding.values.len(), 2);
        let debug = format!("{resp:?}");
        assert!(debug.contains("EmbedContentResponse"));
    }

    // ════════════════════════════════════════════════════════════════════
    // Embedding
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn embedding_roundtrip() {
        let emb = Embedding {
            values: vec![-0.5, 0.0, 0.5],
        };
        let json_str = serde_json::to_string(&emb).unwrap();
        let back: Embedding = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.values.len(), 3);
        assert!((back.values[0] - (-0.5)).abs() < f64::EPSILON);
    }

    #[test]
    fn embedding_clone_debug() {
        let emb = Embedding { values: vec![1.0] };
        let cloned = emb.clone();
        assert_eq!(cloned.values, emb.values);
        let debug = format!("{emb:?}");
        assert!(debug.contains("Embedding"));
    }

    // ════════════════════════════════════════════════════════════════════
    // BatchEmbedContentsResponse
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn batch_embed_response_roundtrip() {
        let json = json!({"embeddings": [{"values": [0.1]}, {"values": [0.2]}]});
        let resp: BatchEmbedContentsResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.embeddings.len(), 2);

        let re_json = serde_json::to_value(&resp).unwrap();
        assert_eq!(re_json["embeddings"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn batch_embed_response_empty() {
        let json = json!({"embeddings": []});
        let resp: BatchEmbedContentsResponse = serde_json::from_value(json).unwrap();
        assert!(resp.embeddings.is_empty());
    }

    #[test]
    fn batch_embed_response_clone_debug() {
        let resp = BatchEmbedContentsResponse {
            embeddings: vec![
                Embedding { values: vec![0.1] },
                Embedding { values: vec![0.2] },
            ],
        };
        let cloned = resp.clone();
        assert_eq!(cloned.embeddings.len(), 2);
        let debug = format!("{resp:?}");
        assert!(debug.contains("BatchEmbedContentsResponse"));
    }

    // ════════════════════════════════════════════════════════════════════
    // CountTokensResponse
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn count_tokens_response_roundtrip() {
        let json = json!({"totalTokens": 42});
        let resp: CountTokensResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.total_tokens, 42);

        let re_json = serde_json::to_value(&resp).unwrap();
        assert_eq!(re_json["totalTokens"], 42);
    }

    #[test]
    fn count_tokens_response_zero() {
        let json = json!({"totalTokens": 0});
        let resp: CountTokensResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.total_tokens, 0);
    }

    #[test]
    fn count_tokens_response_large_value() {
        let json = json!({"totalTokens": 1_000_000});
        let resp: CountTokensResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.total_tokens, 1_000_000);
    }

    #[test]
    fn count_tokens_response_clone_debug() {
        let resp = CountTokensResponse { total_tokens: 99 };
        let cloned = resp.clone();
        assert_eq!(cloned.total_tokens, 99);
        let debug = format!("{resp:?}");
        assert!(debug.contains("CountTokensResponse"));
        assert!(debug.contains("99"));
    }

    // ════════════════════════════════════════════════════════════════════
    // ModelInfo
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn model_info_full_roundtrip() {
        let json = json!({
            "name": "models/gemini-1.5-flash",
            "displayName": "Gemini 1.5 Flash",
            "description": "Fast model",
            "version": "001",
            "supportedGenerationMethods": ["generateContent", "countTokens"],
            "inputTokenLimit": 1000000,
            "outputTokenLimit": 8192,
            "temperature": 0.7,
            "topP": 0.95,
            "topK": 40
        });
        let info: ModelInfo = serde_json::from_value(json).unwrap();
        assert_eq!(info.name, "models/gemini-1.5-flash");
        assert_eq!(info.display_name.as_deref(), Some("Gemini 1.5 Flash"));
        assert_eq!(info.description.as_deref(), Some("Fast model"));
        assert_eq!(info.version.as_deref(), Some("001"));
        assert_eq!(info.supported_generation_methods.len(), 2);
        assert_eq!(info.input_token_limit, Some(1_000_000));
        assert_eq!(info.output_token_limit, Some(8192));
        assert!((info.temperature.unwrap() - 0.7).abs() < f64::EPSILON);
        assert!((info.top_p.unwrap() - 0.95).abs() < f64::EPSILON);
        assert_eq!(info.top_k, Some(40));

        // Re-serialize and check camelCase
        let re_json = serde_json::to_string(&info).unwrap();
        assert!(re_json.contains("displayName"));
        assert!(re_json.contains("inputTokenLimit"));
        assert!(re_json.contains("topP"));
        assert!(re_json.contains("topK"));
    }

    #[test]
    fn model_info_minimal() {
        let json = json!({"name": "models/test"});
        let info: ModelInfo = serde_json::from_value(json).unwrap();
        assert_eq!(info.name, "models/test");
        assert!(info.display_name.is_none());
        assert!(info.description.is_none());
        assert!(info.version.is_none());
        assert!(info.supported_generation_methods.is_empty());
        assert!(info.input_token_limit.is_none());
        assert!(info.output_token_limit.is_none());
        assert!(info.temperature.is_none());
        assert!(info.top_p.is_none());
        assert!(info.top_k.is_none());
    }

    #[test]
    fn model_info_skip_serializing_none_fields() {
        let info = ModelInfo {
            name: "models/test".into(),
            display_name: None,
            description: None,
            version: None,
            supported_generation_methods: vec![],
            input_token_limit: None,
            output_token_limit: None,
            temperature: None,
            top_p: None,
            top_k: None,
        };
        let json_str = serde_json::to_string(&info).unwrap();
        assert!(!json_str.contains("displayName"));
        assert!(!json_str.contains("description"));
        assert!(!json_str.contains("version"));
        assert!(!json_str.contains("inputTokenLimit"));
        assert!(!json_str.contains("outputTokenLimit"));
        assert!(!json_str.contains("temperature"));
        assert!(!json_str.contains("topP"));
        assert!(!json_str.contains("topK"));
        // name and supportedGenerationMethods are always serialized
        assert!(json_str.contains("name"));
        assert!(json_str.contains("supportedGenerationMethods"));
    }

    #[test]
    fn model_info_only_some_optional_fields() {
        let json = json!({
            "name": "models/gemini-2.0-flash",
            "inputTokenLimit": 2048
        });
        let info: ModelInfo = serde_json::from_value(json).unwrap();
        assert_eq!(info.input_token_limit, Some(2048));
        assert!(info.output_token_limit.is_none());
        assert!(info.display_name.is_none());
    }

    #[test]
    fn model_info_clone_debug() {
        let info = ModelInfo {
            name: "models/test".into(),
            display_name: Some("Test".into()),
            description: None,
            version: None,
            supported_generation_methods: vec!["generateContent".into()],
            input_token_limit: None,
            output_token_limit: None,
            temperature: None,
            top_p: None,
            top_k: None,
        };
        let cloned = info.clone();
        assert_eq!(cloned.name, "models/test");
        assert_eq!(cloned.display_name.as_deref(), Some("Test"));
        let debug = format!("{info:?}");
        assert!(debug.contains("ModelInfo"));
        assert!(debug.contains("models/test"));
    }

    // ════════════════════════════════════════════════════════════════════
    // ListModelsResponse
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn list_models_response_roundtrip() {
        let json = json!({
            "models": [{"name": "models/gemini-1.5-flash"}],
            "nextPageToken": "abc"
        });
        let resp: ListModelsResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.models.len(), 1);
        assert_eq!(resp.next_page_token.as_deref(), Some("abc"));

        let re_json = serde_json::to_value(&resp).unwrap();
        assert_eq!(re_json["nextPageToken"], "abc");
    }

    #[test]
    fn list_models_response_no_next_page() {
        let json = json!({
            "models": [{"name": "models/a"}, {"name": "models/b"}]
        });
        let resp: ListModelsResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.models.len(), 2);
        assert!(resp.next_page_token.is_none());
    }

    #[test]
    fn list_models_response_empty_models() {
        let json = json!({"models": []});
        let resp: ListModelsResponse = serde_json::from_value(json).unwrap();
        assert!(resp.models.is_empty());
        assert!(resp.next_page_token.is_none());
    }

    #[test]
    fn list_models_response_skip_serializing_none_page_token() {
        let resp = ListModelsResponse {
            models: vec![],
            next_page_token: None,
        };
        let json_str = serde_json::to_string(&resp).unwrap();
        assert!(!json_str.contains("nextPageToken"));
    }

    #[test]
    fn list_models_response_clone_debug() {
        let resp = ListModelsResponse {
            models: vec![ModelInfo {
                name: "models/test".into(),
                display_name: None,
                description: None,
                version: None,
                supported_generation_methods: vec![],
                input_token_limit: None,
                output_token_limit: None,
                temperature: None,
                top_p: None,
                top_k: None,
            }],
            next_page_token: Some("token123".into()),
        };
        let cloned = resp.clone();
        assert_eq!(cloned.models.len(), 1);
        assert_eq!(cloned.next_page_token.as_deref(), Some("token123"));
        let debug = format!("{resp:?}");
        assert!(debug.contains("ListModelsResponse"));
    }

    // ════════════════════════════════════════════════════════════════════
    // Tuned model requests + responses
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn create_tuned_model_request_roundtrip() {
        let request = CreateTunedModelRequest {
            tuned_model_id: Some("support-bot".into()),
            display_name: Some("Support Bot".into()),
            description: Some("Customer support tuned model".into()),
            source_model: "models/gemini-1.5-flash-001".into(),
            tuning_task: TuningTaskConfig {
                training_data: TuningDataset {
                    examples: vec![TuningExample {
                        text_input: "Classify this ticket".into(),
                        output: "billing".into(),
                    }],
                },
                hyperparameters: Some(Hyperparameters {
                    epoch_count: Some(3),
                    batch_size: Some(4),
                    learning_rate: Some(0.001),
                }),
            },
        };
        request.validate().unwrap();

        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["tunedModelId"], "support-bot");
        assert_eq!(json["sourceModel"], "models/gemini-1.5-flash-001");
        assert_eq!(
            json["tuningTask"]["trainingData"]["examples"][0]["textInput"],
            "Classify this ticket"
        );
    }

    #[test]
    fn create_tuned_model_request_rejects_empty_examples() {
        let request = CreateTunedModelRequest {
            tuned_model_id: None,
            display_name: None,
            description: None,
            source_model: "models/gemini-1.5-flash-001".into(),
            tuning_task: TuningTaskConfig {
                training_data: TuningDataset { examples: vec![] },
                hyperparameters: None,
            },
        };
        let error = request.validate().unwrap_err();
        assert!(error.contains("at least one example"));
    }

    #[test]
    fn list_tuned_models_response_roundtrip() {
        let json = json!({
            "tunedModels": [
                {
                    "name": "tunedModels/support-bot",
                    "displayName": "Support Bot",
                    "state": "ACTIVE",
                    "sourceModel": "models/gemini-1.5-flash-001",
                    "supportedGenerationMethods": ["generateContent"]
                }
            ],
            "nextPageToken": "next-token"
        });
        let response: ListTunedModelsResponse = serde_json::from_value(json).unwrap();
        assert_eq!(response.tuned_models.len(), 1);
        assert_eq!(response.tuned_models[0].name, "tunedModels/support-bot");
        assert_eq!(response.next_page_token.as_deref(), Some("next-token"));
    }

    #[test]
    fn tuned_model_roundtrip_with_task_metadata() {
        let json = json!({
            "name": "tunedModels/support-bot",
            "displayName": "Support Bot",
            "tuningTask": {
                "startTime": "2026-03-10T12:00:00Z",
                "snapshots": [
                    {"epoch": 1, "meanLoss": 1.2, "computeTime": "5s"}
                ]
            }
        });
        let model: TunedModel = serde_json::from_value(json).unwrap();
        assert_eq!(model.name, "tunedModels/support-bot");
        assert_eq!(model.display_name.as_deref(), Some("Support Bot"));
        assert_eq!(model.tuning_task.as_ref().unwrap().snapshots.len(), 1);
    }

    #[test]
    fn get_tuning_operation_request_requires_full_operation_resource() {
        let request = GetTuningOperationRequest {
            operation: "support-bot-op".into(),
        };
        let error = request.validate().unwrap_err();
        assert!(error.contains("full tuned model operation resource"));
    }

    #[test]
    fn tuning_operation_roundtrip() {
        let json = json!({
            "name": "tunedModels/support-bot/operations/op-123",
            "done": false,
            "metadata": {
                "state": "RUNNING"
            }
        });
        let operation: TuningOperation = serde_json::from_value(json).unwrap();
        assert_eq!(operation.name, "tunedModels/support-bot/operations/op-123");
        assert!(!operation.done);
        assert_eq!(operation.metadata.unwrap()["state"], "RUNNING");
    }

    // ════════════════════════════════════════════════════════════════════
    // ApiErrorResponse + ApiErrorDetail
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn api_error_response_full() {
        let json = json!({"error": {"message": "Not found", "status": "NOT_FOUND", "code": 404}});
        let resp: ApiErrorResponse = serde_json::from_value(json).unwrap();
        let detail = resp.error.unwrap();
        assert_eq!(detail.code, Some(404));
        assert_eq!(detail.status.as_deref(), Some("NOT_FOUND"));
        assert_eq!(detail.message.as_deref(), Some("Not found"));
    }

    #[test]
    fn api_error_response_null_error() {
        let json = json!({"error": null});
        let resp: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert!(resp.error.is_none());
    }

    #[test]
    fn api_error_response_missing_error_field() {
        let json = json!({});
        let resp: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert!(resp.error.is_none());
    }

    #[test]
    fn api_error_detail_partial_fields() {
        let json = json!({"error": {"message": "Something happened"}});
        let resp: ApiErrorResponse = serde_json::from_value(json).unwrap();
        let detail = resp.error.unwrap();
        assert_eq!(detail.message.as_deref(), Some("Something happened"));
        assert!(detail.status.is_none());
        assert!(detail.code.is_none());
    }

    #[test]
    fn api_error_detail_only_code() {
        let json = json!({"error": {"code": 500}});
        let resp: ApiErrorResponse = serde_json::from_value(json).unwrap();
        let detail = resp.error.unwrap();
        assert_eq!(detail.code, Some(500));
        assert!(detail.message.is_none());
        assert!(detail.status.is_none());
    }

    #[test]
    fn api_error_detail_empty_object() {
        let json = json!({"error": {}});
        let resp: ApiErrorResponse = serde_json::from_value(json).unwrap();
        let detail = resp.error.unwrap();
        assert!(detail.message.is_none());
        assert!(detail.status.is_none());
        assert!(detail.code.is_none());
    }

    #[test]
    fn api_error_response_clone_debug() {
        let resp = ApiErrorResponse {
            error: Some(ApiErrorDetail {
                message: Some("test".into()),
                status: Some("INTERNAL".into()),
                code: Some(500),
            }),
        };
        let cloned = resp.clone();
        assert_eq!(
            cloned.error.as_ref().unwrap().code,
            resp.error.as_ref().unwrap().code
        );
        let debug = format!("{resp:?}");
        assert!(debug.contains("ApiErrorResponse"));
    }

    #[test]
    fn api_error_detail_clone_debug() {
        let detail = ApiErrorDetail {
            message: Some("err".into()),
            status: None,
            code: Some(400),
        };
        let cloned = detail.clone();
        assert_eq!(cloned.code, Some(400));
        let debug = format!("{detail:?}");
        assert!(debug.contains("ApiErrorDetail"));
    }

    // ════════════════════════════════════════════════════════════════════
    // UsageCounters
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn usage_counters_default() {
        let counters = UsageCounters::default();
        assert_eq!(counters.input_tokens, 0);
        assert_eq!(counters.output_tokens, 0);
        assert_eq!(counters.requests_total, 0);
        assert_eq!(counters.requests_error, 0);
    }

    #[test]
    fn usage_counters_manual_construction() {
        let counters = UsageCounters {
            input_tokens: 100,
            output_tokens: 200,
            requests_total: 10,
            requests_error: 2,
        };
        assert_eq!(counters.input_tokens, 100);
        assert_eq!(counters.output_tokens, 200);
        assert_eq!(counters.requests_total, 10);
        assert_eq!(counters.requests_error, 2);
    }

    #[test]
    fn usage_counters_clone() {
        let counters = UsageCounters {
            input_tokens: 50,
            output_tokens: 75,
            requests_total: 5,
            requests_error: 1,
        };
        let cloned = counters.clone();
        assert_eq!(cloned.input_tokens, 50);
        assert_eq!(cloned.output_tokens, 75);
        assert_eq!(cloned.requests_total, 5);
        assert_eq!(cloned.requests_error, 1);
        assert_eq!(counters.input_tokens, 50);
    }

    #[test]
    fn usage_counters_debug() {
        let counters = UsageCounters::default();
        let debug = format!("{counters:?}");
        assert!(debug.contains("UsageCounters"));
    }

    // ════════════════════════════════════════════════════════════════════
    // Deserialization error cases
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn count_tokens_missing_required_field_fails() {
        let json = json!({});
        let result = serde_json::from_value::<CountTokensResponse>(json);
        assert!(result.is_err());
    }

    #[test]
    fn embedding_missing_values_fails() {
        let json = json!({});
        let result = serde_json::from_value::<Embedding>(json);
        assert!(result.is_err());
    }

    #[test]
    fn embed_content_response_missing_embedding_fails() {
        let json = json!({});
        let result = serde_json::from_value::<EmbedContentResponse>(json);
        assert!(result.is_err());
    }

    #[test]
    fn batch_embed_missing_embeddings_fails() {
        let json = json!({});
        let result = serde_json::from_value::<BatchEmbedContentsResponse>(json);
        assert!(result.is_err());
    }

    #[test]
    fn model_info_missing_name_fails() {
        let json = json!({"displayName": "test"});
        let result = serde_json::from_value::<ModelInfo>(json);
        assert!(result.is_err());
    }

    #[test]
    fn list_models_missing_models_fails() {
        let json = json!({});
        let result = serde_json::from_value::<ListModelsResponse>(json);
        assert!(result.is_err());
    }

    #[test]
    fn safety_rating_missing_fields_fails() {
        let json = json!({"category": "TEST"});
        let result = serde_json::from_value::<SafetyRating>(json);
        assert!(result.is_err());
    }

    #[test]
    fn function_call_data_missing_name_fails() {
        let json = json!({"args": {}});
        let result = serde_json::from_value::<FunctionCallData>(json);
        assert!(result.is_err());
    }

    #[test]
    fn function_response_data_missing_response_fails() {
        let json = json!({"name": "fn1"});
        let result = serde_json::from_value::<FunctionResponseData>(json);
        assert!(result.is_err());
    }

    // ════════════════════════════════════════════════════════════════════
    // JSON from_str (string input) roundtrips
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn generate_content_response_json_string_roundtrip() {
        let original = GenerateContentResponse {
            candidates: vec![Candidate {
                content: Some(Content {
                    role: Some("model".into()),
                    parts: vec![Part::Text {
                        text: "response text".into(),
                    }],
                }),
                finish_reason: Some("STOP".into()),
                index: Some(0),
                safety_ratings: Some(vec![SafetyRating {
                    category: "HARM_CATEGORY_HARASSMENT".into(),
                    probability: "NEGLIGIBLE".into(),
                }]),
            }],
            usage_metadata: Some(UsageMetadata {
                prompt_token_count: 10,
                candidates_token_count: 20,
                total_token_count: 30,
            }),
            model_version: Some("v1".into()),
        };
        let json_str = serde_json::to_string(&original).unwrap();
        let back: GenerateContentResponse = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.candidates.len(), 1);
        assert_eq!(back.usage_metadata.as_ref().unwrap().total_token_count, 30);
        assert_eq!(back.model_version.as_deref(), Some("v1"));
    }

    #[test]
    fn model_info_json_string_roundtrip() {
        let original = ModelInfo {
            name: "models/gemini-2.0-flash".into(),
            display_name: Some("Gemini 2.0 Flash".into()),
            description: Some("A fast model".into()),
            version: Some("001".into()),
            supported_generation_methods: vec!["generateContent".into(), "embedContent".into()],
            input_token_limit: Some(1_048_576),
            output_token_limit: Some(8192),
            temperature: Some(1.0),
            top_p: Some(0.95),
            top_k: Some(64),
        };
        let json_str = serde_json::to_string(&original).unwrap();
        let back: ModelInfo = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.name, "models/gemini-2.0-flash");
        assert_eq!(back.supported_generation_methods.len(), 2);
        assert_eq!(back.top_k, Some(64));
    }

    // ════════════════════════════════════════════════════════════════════
    // Unicode and special characters
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn content_unicode_text() {
        let content = Content {
            role: Some("user".into()),
            parts: vec![Part::Text {
                text: "Hello \u{1F600} \u{4E16}\u{754C}".into(),
            }],
        };
        let json_str = serde_json::to_string(&content).unwrap();
        let back: Content = serde_json::from_str(&json_str).unwrap();
        match &back.parts[0] {
            Part::Text { text } => assert!(text.contains('\u{1F600}')),
            other => panic!("expected Text, got {other:?}"),
        }
    }

    #[test]
    fn model_info_special_chars_in_description() {
        let json = json!({
            "name": "models/test",
            "description": "A model with \"quotes\" and <brackets> & ampersands"
        });
        let info: ModelInfo = serde_json::from_value(json).unwrap();
        assert!(info.description.as_ref().unwrap().contains("\"quotes\""));
    }

    // ── Additional type coverage tests ────────────────────────────

    #[test]
    fn content_with_no_role() {
        let content = Content {
            role: None,
            parts: vec![Part::Text {
                text: "hello".into(),
            }],
        };
        let json_str = serde_json::to_string(&content).unwrap();
        let back: Content = serde_json::from_str(&json_str).unwrap();
        assert!(back.role.is_none());
        assert_eq!(back.parts.len(), 1);
    }

    #[test]
    fn content_multiple_parts_roundtrip() {
        let content = Content {
            role: Some("user".into()),
            parts: vec![
                Part::Text {
                    text: "part one".into(),
                },
                Part::Text {
                    text: "part two".into(),
                },
            ],
        };
        let v = serde_json::to_value(&content).unwrap();
        assert_eq!(v["parts"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn usage_metadata_large_values() {
        let usage = UsageMetadata {
            prompt_token_count: 1_000_000,
            candidates_token_count: 500_000,
            total_token_count: 1_500_000,
        };
        let v = serde_json::to_value(&usage).unwrap();
        assert_eq!(v["promptTokenCount"], 1_000_000);
        assert_eq!(v["totalTokenCount"], 1_500_000);
    }

    #[test]
    fn embedding_large_vector() {
        let values: Vec<f64> = (0..768).map(|i| f64::from(i) * 0.001).collect();
        let emb = Embedding { values };
        let json_str = serde_json::to_string(&emb).unwrap();
        let back: Embedding = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.values.len(), 768);
        assert!((back.values[0]).abs() < f64::EPSILON);
    }

    #[test]
    fn candidate_finish_reason_other_values() {
        for reason in &["STOP", "MAX_TOKENS", "SAFETY", "RECITATION", "OTHER"] {
            let json = json!({"finishReason": reason});
            let c: Candidate = serde_json::from_value(json).unwrap();
            assert_eq!(c.finish_reason.as_deref(), Some(*reason));
        }
    }

    #[test]
    fn safety_rating_various_probabilities() {
        for prob in &["NEGLIGIBLE", "LOW", "MEDIUM", "HIGH"] {
            let rating = SafetyRating {
                category: "HARM_CATEGORY_HARASSMENT".into(),
                probability: prob.to_string(),
            };
            let json_str = serde_json::to_string(&rating).unwrap();
            let back: SafetyRating = serde_json::from_str(&json_str).unwrap();
            assert_eq!(back.probability, *prob);
        }
    }

    #[test]
    fn api_error_detail_all_fields() {
        let detail = ApiErrorDetail {
            message: Some("error msg".into()),
            status: Some("INVALID_ARGUMENT".into()),
            code: Some(400),
        };
        assert_eq!(detail.message.as_deref(), Some("error msg"));
        assert_eq!(detail.status.as_deref(), Some("INVALID_ARGUMENT"));
        assert_eq!(detail.code, Some(400));
    }

    #[test]
    fn usage_counters_accumulation() {
        let mut counters = UsageCounters::default();
        counters.input_tokens += 100;
        counters.output_tokens += 200;
        counters.requests_total += 3;
        counters.requests_error += 1;
        assert_eq!(counters.input_tokens, 100);
        assert_eq!(counters.output_tokens, 200);
        assert_eq!(counters.requests_total, 3);
        assert_eq!(counters.requests_error, 1);
    }

    #[test]
    fn function_call_data_complex_args() {
        let data = FunctionCallData {
            name: "complex_fn".into(),
            args: json!({"nested": {"key": [1, 2, 3]}, "flag": true}),
        };
        let json_str = serde_json::to_string(&data).unwrap();
        let back: FunctionCallData = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.args["nested"]["key"].as_array().unwrap().len(), 3);
    }
}
