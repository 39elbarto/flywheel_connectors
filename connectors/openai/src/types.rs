//! OpenAI API types.

use serde::{Deserialize, Serialize};

/// Available OpenAI models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Model {
    /// GPT-4o - Most capable multimodal model
    #[serde(rename = "gpt-4o")]
    Gpt4o,
    /// GPT-4o mini - Smaller, faster GPT-4o
    #[serde(rename = "gpt-4o-mini")]
    Gpt4oMini,
    /// GPT-4 Turbo - Previous generation
    #[serde(rename = "gpt-4-turbo")]
    Gpt4Turbo,
    /// GPT-4 - Original GPT-4
    #[serde(rename = "gpt-4")]
    Gpt4,
    /// GPT-3.5 Turbo - Fast and cost-effective
    #[serde(rename = "gpt-3.5-turbo")]
    Gpt35Turbo,
}

impl Model {
    /// Get the model string for API requests.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Gpt4o => "gpt-4o",
            Self::Gpt4oMini => "gpt-4o-mini",
            Self::Gpt4Turbo => "gpt-4-turbo",
            Self::Gpt4 => "gpt-4",
            Self::Gpt35Turbo => "gpt-3.5-turbo",
        }
    }

    /// Get input price per million tokens.
    #[must_use]
    pub const fn input_price_per_million(&self) -> f64 {
        match self {
            Self::Gpt4o => 2.50,
            Self::Gpt4oMini => 0.15,
            Self::Gpt4Turbo => 10.0,
            Self::Gpt4 => 30.0,
            Self::Gpt35Turbo => 0.50,
        }
    }

    /// Get output price per million tokens.
    #[must_use]
    pub const fn output_price_per_million(&self) -> f64 {
        match self {
            Self::Gpt4o => 10.0,
            Self::Gpt4oMini => 0.60,
            Self::Gpt4Turbo => 30.0,
            Self::Gpt4 => 60.0,
            Self::Gpt35Turbo => 1.50,
        }
    }
}

impl Default for Model {
    fn default() -> Self {
        Self::Gpt4o
    }
}

/// A message in a conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Role of the message sender.
    pub role: Role,
    /// Content of the message.
    pub content: MessageContent,
    /// Optional name for the participant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Tool calls made by the assistant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCall>>,
    /// ID of the tool call this message is responding to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

impl Message {
    /// Create a user message.
    #[must_use]
    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: Role::User,
            content: MessageContent::Text(content.into()),
            name: None,
            tool_calls: None,
            tool_call_id: None,
        }
    }

    /// Create an assistant message.
    #[must_use]
    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: Role::Assistant,
            content: MessageContent::Text(content.into()),
            name: None,
            tool_calls: None,
            tool_call_id: None,
        }
    }

    /// Create a system message.
    #[must_use]
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: Role::System,
            content: MessageContent::Text(content.into()),
            name: None,
            tool_calls: None,
            tool_call_id: None,
        }
    }
}

/// Role in a conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// System message
    System,
    /// User message
    User,
    /// Assistant message
    Assistant,
    /// Tool message (function result)
    Tool,
}

/// Content of a message (can be text or multimodal).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MessageContent {
    /// Simple text content
    Text(String),
    /// Complex content with multiple parts (for vision)
    Parts(Vec<ContentPart>),
}

impl From<&str> for MessageContent {
    fn from(s: &str) -> Self {
        Self::Text(s.to_string())
    }
}

impl From<String> for MessageContent {
    fn from(s: String) -> Self {
        Self::Text(s)
    }
}

/// A content part for multimodal messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentPart {
    /// Text content
    Text { text: String },
    /// Image URL
    ImageUrl { image_url: ImageUrl },
}

/// Image URL for vision requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageUrl {
    /// URL of the image (can be data: URL for base64)
    pub url: String,
    /// Detail level for the image
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<ImageDetail>,
}

/// Detail level for image processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ImageDetail {
    /// Automatic detail level
    Auto,
    /// Low detail (faster, cheaper)
    Low,
    /// High detail (more accurate)
    High,
}

/// Request to the Chat Completions API.
#[derive(Debug, Clone, Serialize)]
pub struct ChatCompletionRequest {
    /// Model to use
    pub model: String,
    /// Messages in the conversation
    pub messages: Vec<Message>,
    /// Maximum tokens to generate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    /// Temperature for sampling
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    /// Top-p sampling
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f64>,
    /// Number of completions to generate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<u32>,
    /// Whether to stream the response
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    /// Stop sequences
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop: Option<Vec<String>>,
    /// Presence penalty (-2.0 to 2.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presence_penalty: Option<f64>,
    /// Frequency penalty (-2.0 to 2.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frequency_penalty: Option<f64>,
    /// User identifier for abuse detection
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Tools available to the model
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<Tool>>,
    /// How to choose which tool to use
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<ToolChoice>,
    /// Response format (for JSON mode)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_format: Option<ResponseFormat>,
    /// Seed for deterministic outputs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed: Option<i64>,
}

/// A tool definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tool {
    /// Type of tool (always "function" for now)
    #[serde(rename = "type")]
    pub tool_type: String,
    /// Function definition
    pub function: FunctionDefinition,
}

/// Function definition for a tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDefinition {
    /// Function name
    pub name: String,
    /// Function description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Parameters schema (JSON Schema)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<serde_json::Value>,
}

/// How to choose which tool to use.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ToolChoice {
    /// String choice: "none", "auto", or "required"
    String(String),
    /// Specific tool choice
    Specific {
        #[serde(rename = "type")]
        choice_type: String,
        function: ToolChoiceFunction,
    },
}

/// Function choice for specific tool selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolChoiceFunction {
    /// Name of the function to call
    pub name: String,
}

/// Response format specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseFormat {
    /// Type of response format
    #[serde(rename = "type")]
    pub format_type: String,
}

/// A tool call made by the assistant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    /// Unique ID for this tool call
    pub id: String,
    /// Type of tool (always "function")
    #[serde(rename = "type")]
    pub tool_type: String,
    /// Function call details
    pub function: FunctionCall,
}

/// Function call details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCall {
    /// Name of the function to call
    pub name: String,
    /// Arguments as a JSON string
    pub arguments: String,
}

/// Response from the Chat Completions API.
#[derive(Debug, Clone, Deserialize)]
pub struct ChatCompletionResponse {
    /// Response ID
    pub id: String,
    /// Object type (always "chat.completion")
    pub object: String,
    /// Unix timestamp of creation
    pub created: i64,
    /// Model used
    pub model: String,
    /// Choices (completions)
    pub choices: Vec<Choice>,
    /// Usage statistics
    pub usage: Option<Usage>,
    /// System fingerprint
    pub system_fingerprint: Option<String>,
}

/// A completion choice.
#[derive(Debug, Clone, Deserialize)]
pub struct Choice {
    /// Index of this choice
    pub index: u32,
    /// The message
    pub message: ResponseMessage,
    /// Finish reason
    pub finish_reason: Option<FinishReason>,
}

/// Message in a response.
#[derive(Debug, Clone, Deserialize)]
pub struct ResponseMessage {
    /// Role (always "assistant")
    pub role: Role,
    /// Text content
    pub content: Option<String>,
    /// Tool calls made by the assistant
    pub tool_calls: Option<Vec<ToolCall>>,
}

/// Reason the model stopped generating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinishReason {
    /// Natural end of message
    Stop,
    /// Hit max tokens
    Length,
    /// Model wants to use a tool
    ToolCalls,
    /// Content was filtered
    ContentFilter,
}

/// Token usage statistics.
#[derive(Debug, Clone, Copy, Deserialize, Default)]
pub struct Usage {
    /// Prompt tokens used
    pub prompt_tokens: u32,
    /// Completion tokens used
    pub completion_tokens: u32,
    /// Total tokens used
    pub total_tokens: u32,
    /// Detailed breakdown of prompt tokens
    #[serde(default)]
    pub prompt_tokens_details: Option<PromptTokensDetails>,
}

/// Detailed breakdown of prompt tokens.
#[derive(Debug, Clone, Copy, Deserialize, Default)]
pub struct PromptTokensDetails {
    /// Number of tokens retrieved from the cache
    pub cached_tokens: u32,
}

impl Usage {
    /// Calculate cost for this usage with a given model.
    #[must_use]
    pub fn calculate_cost(&self, model: Model) -> f64 {
        let base_input_price = model.input_price_per_million();
        let output_price = model.output_price_per_million();

        let cached_tokens = self
            .prompt_tokens_details
            .map(|d| d.cached_tokens)
            .unwrap_or(0);

        // OpenAI pricing: Cached input tokens are 50% discounted
        let uncached_input = self.prompt_tokens.saturating_sub(cached_tokens);

        let input_cost = (f64::from(uncached_input) / 1_000_000.0) * base_input_price
            + (f64::from(cached_tokens) / 1_000_000.0) * (base_input_price * 0.5);

        let output_cost = (f64::from(self.completion_tokens) / 1_000_000.0) * output_price;

        input_cost + output_cost
    }
}

/// Streaming chunk from the Chat Completions API.
#[derive(Debug, Clone, Deserialize)]
pub struct ChatCompletionChunk {
    /// Chunk ID
    pub id: String,
    /// Object type (always "chat.completion.chunk")
    pub object: String,
    /// Unix timestamp of creation
    pub created: i64,
    /// Model used
    pub model: String,
    /// Choices (partial completions)
    pub choices: Vec<ChunkChoice>,
    /// System fingerprint
    pub system_fingerprint: Option<String>,
    /// Usage (only in final chunk if requested)
    pub usage: Option<Usage>,
}

/// A choice in a streaming chunk.
#[derive(Debug, Clone, Deserialize)]
pub struct ChunkChoice {
    /// Index of this choice
    pub index: u32,
    /// Delta (incremental content)
    pub delta: ChunkDelta,
    /// Finish reason (only in final chunk)
    pub finish_reason: Option<FinishReason>,
}

/// Delta content in a streaming chunk.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ChunkDelta {
    /// Role (only in first chunk)
    pub role: Option<Role>,
    /// Content delta
    pub content: Option<String>,
    /// Tool calls delta
    pub tool_calls: Option<Vec<ToolCallDelta>>,
}

/// Tool call delta in streaming.
#[derive(Debug, Clone, Deserialize)]
pub struct ToolCallDelta {
    /// Index of the tool call
    pub index: u32,
    /// ID (only in first chunk for this tool call)
    pub id: Option<String>,
    /// Type (only in first chunk)
    #[serde(rename = "type")]
    pub tool_type: Option<String>,
    /// Function delta
    pub function: Option<FunctionCallDelta>,
}

/// Function call delta in streaming.
#[derive(Debug, Clone, Deserialize)]
pub struct FunctionCallDelta {
    /// Name (only in first chunk)
    pub name: Option<String>,
    /// Arguments delta (incremental JSON string)
    pub arguments: Option<String>,
}

// ─────────────────────── Embeddings ───────────────────────

/// Available embedding models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EmbeddingModel {
    /// text-embedding-3-small
    #[serde(rename = "text-embedding-3-small")]
    TextEmbedding3Small,
    /// text-embedding-3-large
    #[serde(rename = "text-embedding-3-large")]
    TextEmbedding3Large,
    /// text-embedding-ada-002 (legacy)
    #[serde(rename = "text-embedding-ada-002")]
    TextEmbeddingAda002,
}

impl EmbeddingModel {
    /// Get the model string for API requests.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::TextEmbedding3Small => "text-embedding-3-small",
            Self::TextEmbedding3Large => "text-embedding-3-large",
            Self::TextEmbeddingAda002 => "text-embedding-ada-002",
        }
    }

    /// Get the default output dimensions.
    #[must_use]
    pub const fn default_dimensions(&self) -> u32 {
        match self {
            Self::TextEmbedding3Large => 3072,
            Self::TextEmbedding3Small | Self::TextEmbeddingAda002 => 1536,
        }
    }

    /// Get price per million tokens.
    #[must_use]
    pub const fn price_per_million(&self) -> f64 {
        match self {
            Self::TextEmbedding3Small => 0.02,
            Self::TextEmbedding3Large => 0.13,
            Self::TextEmbeddingAda002 => 0.10,
        }
    }

    /// Maximum input tokens.
    #[must_use]
    pub const fn max_input_tokens(&self) -> u32 {
        8191
    }
}

impl Default for EmbeddingModel {
    fn default() -> Self {
        Self::TextEmbedding3Small
    }
}

/// Request to the Embeddings API.
#[derive(Debug, Clone, Serialize)]
pub struct EmbeddingRequest {
    /// Model to use.
    pub model: String,
    /// Input text(s) to embed.
    pub input: EmbeddingInput,
    /// Output encoding format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding_format: Option<String>,
    /// Output dimensions (text-embedding-3 only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dimensions: Option<u32>,
}

/// Embedding input: single string or array of strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EmbeddingInput {
    /// Single text input.
    Single(String),
    /// Batch of text inputs.
    Batch(Vec<String>),
}

/// Response from the Embeddings API.
#[derive(Debug, Clone, Deserialize)]
pub struct EmbeddingResponse {
    /// Object type (always "list").
    pub object: String,
    /// Embedding data entries.
    pub data: Vec<EmbeddingData>,
    /// Model used.
    pub model: String,
    /// Usage statistics.
    pub usage: EmbeddingUsage,
}

/// A single embedding vector.
#[derive(Debug, Clone, Deserialize)]
pub struct EmbeddingData {
    /// Object type (always "embedding").
    pub object: String,
    /// Index of this embedding.
    pub index: u32,
    /// The embedding vector.
    pub embedding: Vec<f64>,
}

/// Usage statistics for embeddings.
#[derive(Debug, Clone, Copy, Deserialize, Default)]
pub struct EmbeddingUsage {
    /// Prompt tokens used.
    pub prompt_tokens: u32,
    /// Total tokens used.
    pub total_tokens: u32,
}

impl EmbeddingUsage {
    /// Calculate cost for this usage with a given embedding model.
    #[must_use]
    pub fn calculate_cost(&self, model: EmbeddingModel) -> f64 {
        (f64::from(self.total_tokens) / 1_000_000.0) * model.price_per_million()
    }
}

// ─────────────────────── Images ───────────────────────

/// Image generation models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImageModel {
    /// DALL-E 3
    #[serde(rename = "dall-e-3")]
    DallE3,
    /// DALL-E 2
    #[serde(rename = "dall-e-2")]
    DallE2,
}

impl ImageModel {
    /// Get the model string for API requests.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::DallE3 => "dall-e-3",
            Self::DallE2 => "dall-e-2",
        }
    }
}

impl Default for ImageModel {
    fn default() -> Self {
        Self::DallE3
    }
}

/// Image size options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImageSize {
    /// 256x256 (DALL-E 2 only)
    #[serde(rename = "256x256")]
    Size256,
    /// 512x512 (DALL-E 2 only)
    #[serde(rename = "512x512")]
    Size512,
    /// 1024x1024
    #[serde(rename = "1024x1024")]
    Size1024,
    /// 1792x1024 (DALL-E 3 only)
    #[serde(rename = "1792x1024")]
    SizeLandscape,
    /// 1024x1792 (DALL-E 3 only)
    #[serde(rename = "1024x1792")]
    SizePortrait,
}

impl Default for ImageSize {
    fn default() -> Self {
        Self::Size1024
    }
}

/// Image quality options (DALL-E 3 only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ImageQuality {
    /// Standard quality.
    Standard,
    /// HD quality.
    Hd,
}

impl Default for ImageQuality {
    fn default() -> Self {
        Self::Standard
    }
}

/// Request to the Images API.
#[derive(Debug, Clone, Serialize)]
pub struct ImageGenerationRequest {
    /// Model to use.
    pub model: String,
    /// Text prompt.
    pub prompt: String,
    /// Number of images to generate (1-10, DALL-E 2; always 1 for DALL-E 3).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<u32>,
    /// Image size.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<ImageSize>,
    /// Image quality (DALL-E 3 only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quality: Option<ImageQuality>,
    /// Response format.
    pub response_format: String,
}

/// Response from the Images API.
#[derive(Debug, Clone, Deserialize)]
pub struct ImageGenerationResponse {
    /// Unix timestamp of creation.
    pub created: i64,
    /// Generated image data.
    pub data: Vec<ImageData>,
}

/// A single generated image.
#[derive(Debug, Clone, Deserialize)]
pub struct ImageData {
    /// Base64-encoded image data (when `response_format` is `b64_json`).
    #[serde(default)]
    pub b64_json: Option<String>,
    /// URL of generated image (when `response_format` is `url`).
    #[serde(default)]
    pub url: Option<String>,
    /// Revised prompt (DALL-E 3 only).
    #[serde(default)]
    pub revised_prompt: Option<String>,
}

// ─────────────────────── Audio ───────────────────────

/// Whisper transcription models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WhisperModel {
    /// whisper-1
    #[serde(rename = "whisper-1")]
    Whisper1,
}

impl WhisperModel {
    /// Get the model string for API requests.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Whisper1 => "whisper-1",
        }
    }

    /// Price per minute of audio.
    #[must_use]
    pub const fn price_per_minute(&self) -> f64 {
        match self {
            Self::Whisper1 => 0.006,
        }
    }
}

impl Default for WhisperModel {
    fn default() -> Self {
        Self::Whisper1
    }
}

/// Text-to-speech models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TtsModel {
    /// tts-1 (standard quality, lower latency)
    #[serde(rename = "tts-1")]
    Tts1,
    /// tts-1-hd (higher quality)
    #[serde(rename = "tts-1-hd")]
    Tts1Hd,
}

impl TtsModel {
    /// Get the model string for API requests.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Tts1 => "tts-1",
            Self::Tts1Hd => "tts-1-hd",
        }
    }

    /// Price per 1M characters.
    #[must_use]
    pub const fn price_per_million_chars(&self) -> f64 {
        match self {
            Self::Tts1 => 15.0,
            Self::Tts1Hd => 30.0,
        }
    }
}

impl Default for TtsModel {
    fn default() -> Self {
        Self::Tts1
    }
}

/// TTS voice options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TtsVoice {
    /// Alloy voice.
    Alloy,
    /// Echo voice.
    Echo,
    /// Fable voice.
    Fable,
    /// Onyx voice.
    Onyx,
    /// Nova voice.
    Nova,
    /// Shimmer voice.
    Shimmer,
}

impl TtsVoice {
    /// Get the voice string for API requests.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Alloy => "alloy",
            Self::Echo => "echo",
            Self::Fable => "fable",
            Self::Onyx => "onyx",
            Self::Nova => "nova",
            Self::Shimmer => "shimmer",
        }
    }
}

impl Default for TtsVoice {
    fn default() -> Self {
        Self::Alloy
    }
}

/// TTS output audio formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TtsResponseFormat {
    /// MP3 audio.
    Mp3,
    /// Opus audio.
    Opus,
    /// AAC audio.
    Aac,
    /// FLAC audio.
    Flac,
}

impl TtsResponseFormat {
    /// Get the format string for API requests.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Mp3 => "mp3",
            Self::Opus => "opus",
            Self::Aac => "aac",
            Self::Flac => "flac",
        }
    }

    /// Get the MIME type for this format.
    #[must_use]
    pub const fn mime_type(&self) -> &'static str {
        match self {
            Self::Mp3 => "audio/mpeg",
            Self::Opus => "audio/opus",
            Self::Aac => "audio/aac",
            Self::Flac => "audio/flac",
        }
    }
}

impl Default for TtsResponseFormat {
    fn default() -> Self {
        Self::Mp3
    }
}

/// Request to the TTS API.
#[derive(Debug, Clone, Serialize)]
pub struct TtsRequest {
    /// Model to use.
    pub model: String,
    /// Text to convert to speech (max 4096 chars).
    pub input: String,
    /// Voice to use.
    pub voice: String,
    /// Output audio format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_format: Option<String>,
    /// Playback speed (0.25 to 4.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub speed: Option<f64>,
}

/// Response from the Transcriptions API.
#[derive(Debug, Clone, Deserialize)]
pub struct TranscriptionResponse {
    /// Transcribed text.
    pub text: String,
}

// ─────────────────────── Fine-tuning ───────────────────────

/// Fine-tuning job status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FineTuneStatus {
    /// Job is validating files.
    ValidatingFiles,
    /// Job is queued.
    Queued,
    /// Job is actively running.
    Running,
    /// Job completed successfully.
    Succeeded,
    /// Job failed.
    Failed,
    /// Job was cancelled.
    Cancelled,
}

/// Hyperparameters for fine-tuning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FineTuneHyperparameters {
    /// Number of epochs (or "auto").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n_epochs: Option<serde_json::Value>,
    /// Batch size (or "auto").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_size: Option<serde_json::Value>,
    /// Learning rate multiplier (or "auto").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub learning_rate_multiplier: Option<serde_json::Value>,
}

/// Request to create a fine-tuning job.
#[derive(Debug, Clone, Serialize)]
pub struct CreateFineTuneRequest {
    /// Training file ID.
    pub training_file: String,
    /// Model to fine-tune.
    pub model: String,
    /// Optional validation file ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_file: Option<String>,
    /// Hyperparameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hyperparameters: Option<FineTuneHyperparameters>,
    /// Suffix for the fine-tuned model name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suffix: Option<String>,
}

/// Fine-tuning job object.
#[derive(Debug, Clone, Deserialize)]
pub struct FineTuneJob {
    /// Job ID.
    pub id: String,
    /// Object type (always "fine_tuning.job").
    pub object: String,
    /// Base model being fine-tuned.
    pub model: String,
    /// Job status.
    pub status: FineTuneStatus,
    /// Training file ID.
    pub training_file: String,
    /// Validation file ID.
    pub validation_file: Option<String>,
    /// Fine-tuned model name (available after success).
    pub fine_tuned_model: Option<String>,
    /// Unix timestamp of creation.
    pub created_at: i64,
    /// Unix timestamp of completion.
    pub finished_at: Option<i64>,
    /// Hyperparameters used.
    pub hyperparameters: Option<FineTuneHyperparameters>,
    /// Trained token count.
    pub trained_tokens: Option<u64>,
    /// Error information if failed.
    pub error: Option<FineTuneError>,
}

/// Error details for a failed fine-tuning job.
#[derive(Debug, Clone, Deserialize)]
pub struct FineTuneError {
    /// Error code.
    pub code: Option<String>,
    /// Error message.
    pub message: Option<String>,
}

/// Response from listing fine-tuning jobs.
#[derive(Debug, Clone, Deserialize)]
pub struct FineTuneListResponse {
    /// List of fine-tuning jobs.
    pub data: Vec<FineTuneJob>,
    /// Whether there are more results.
    pub has_more: bool,
}

/// A fine-tuning event.
#[derive(Debug, Clone, Deserialize)]
pub struct FineTuneEvent {
    /// Event ID.
    pub id: String,
    /// Object type (always "fine_tuning.job.event").
    pub object: String,
    /// Unix timestamp.
    pub created_at: i64,
    /// Event level (info, warn, error).
    pub level: String,
    /// Event message.
    pub message: String,
}

/// Response from listing fine-tuning events.
#[derive(Debug, Clone, Deserialize)]
pub struct FineTuneEventListResponse {
    /// List of events.
    pub data: Vec<FineTuneEvent>,
    /// Whether there are more results.
    pub has_more: bool,
}

// ─────────────────────── Assistants ───────────────────────

/// Tool definition for assistants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssistantTool {
    /// Tool type: "code_interpreter", "file_search", or "function".
    #[serde(rename = "type")]
    pub tool_type: String,
    /// Function definition (only for "function" type).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<serde_json::Value>,
}

/// Request to create an assistant.
#[derive(Debug, Clone, Serialize)]
pub struct CreateAssistantRequest {
    /// Model to use.
    pub model: String,
    /// Name of the assistant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// System instructions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
    /// Tools the assistant can use.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<AssistantTool>>,
    /// Metadata key-value pairs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// An assistant object.
#[derive(Debug, Clone, Deserialize)]
pub struct Assistant {
    /// Assistant ID.
    pub id: String,
    /// Object type.
    pub object: String,
    /// Unix timestamp of creation.
    pub created_at: i64,
    /// Name of the assistant.
    pub name: Option<String>,
    /// Model used.
    pub model: String,
    /// System instructions.
    pub instructions: Option<String>,
    /// Tools the assistant can use.
    pub tools: Vec<AssistantTool>,
    /// Metadata.
    pub metadata: Option<serde_json::Value>,
}

/// Response from listing assistants.
#[derive(Debug, Clone, Deserialize)]
pub struct AssistantListResponse {
    /// List of assistants.
    pub data: Vec<Assistant>,
    /// Whether there are more results.
    pub has_more: bool,
}

// ─────────────────────── Threads ───────────────────────

/// A thread object.
#[derive(Debug, Clone, Deserialize)]
pub struct Thread {
    /// Thread ID.
    pub id: String,
    /// Object type.
    pub object: String,
    /// Unix timestamp of creation.
    pub created_at: i64,
    /// Metadata.
    pub metadata: Option<serde_json::Value>,
}

/// Content part of a thread message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadMessageContentPart {
    /// Content type: "text" or "image_file".
    #[serde(rename = "type")]
    pub content_type: String,
    /// Text content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<MessageText>,
}

/// Text content with optional annotations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageText {
    /// The text value.
    pub value: String,
    /// Annotations (citations, file references).
    #[serde(default)]
    pub annotations: Vec<serde_json::Value>,
}

/// A message in a thread.
#[derive(Debug, Clone, Deserialize)]
pub struct ThreadMessage {
    /// Message ID.
    pub id: String,
    /// Object type.
    pub object: String,
    /// Unix timestamp of creation.
    pub created_at: i64,
    /// Thread this message belongs to.
    pub thread_id: String,
    /// Role: "user" or "assistant".
    pub role: String,
    /// Content parts.
    pub content: Vec<ThreadMessageContentPart>,
    /// Assistant ID (if role is "assistant").
    pub assistant_id: Option<String>,
    /// Run ID that generated this message.
    pub run_id: Option<String>,
    /// Metadata.
    pub metadata: Option<serde_json::Value>,
}

/// Response from listing thread messages.
#[derive(Debug, Clone, Deserialize)]
pub struct ThreadMessageListResponse {
    /// List of messages.
    pub data: Vec<ThreadMessage>,
    /// Whether there are more results.
    pub has_more: bool,
}

// ─────────────────────── Runs ───────────────────────

/// Run status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    /// Run is queued for processing.
    Queued,
    /// Run is in progress.
    InProgress,
    /// Run requires action (tool outputs).
    RequiresAction,
    /// Run is cancelling.
    Cancelling,
    /// Run was cancelled.
    Cancelled,
    /// Run failed.
    Failed,
    /// Run completed successfully.
    Completed,
    /// Run is incomplete.
    Incomplete,
    /// Run expired.
    Expired,
}

/// A run on a thread.
#[derive(Debug, Clone, Deserialize)]
pub struct Run {
    /// Run ID.
    pub id: String,
    /// Object type.
    pub object: String,
    /// Unix timestamp of creation.
    pub created_at: i64,
    /// Thread ID.
    pub thread_id: String,
    /// Assistant ID.
    pub assistant_id: String,
    /// Run status.
    pub status: RunStatus,
    /// Model used.
    pub model: String,
    /// Instructions override.
    pub instructions: Option<String>,
    /// Tools used.
    pub tools: Vec<AssistantTool>,
    /// Unix timestamp of start.
    pub started_at: Option<i64>,
    /// Unix timestamp of completion.
    pub completed_at: Option<i64>,
    /// Unix timestamp of failure.
    pub failed_at: Option<i64>,
    /// Unix timestamp of cancellation.
    pub cancelled_at: Option<i64>,
    /// Last error.
    pub last_error: Option<RunError>,
    /// Usage statistics.
    pub usage: Option<RunUsage>,
    /// Metadata.
    pub metadata: Option<serde_json::Value>,
}

/// Run error details.
#[derive(Debug, Clone, Deserialize)]
pub struct RunError {
    /// Error code.
    pub code: String,
    /// Error message.
    pub message: String,
}

/// Usage statistics for a run.
#[derive(Debug, Clone, Deserialize)]
pub struct RunUsage {
    /// Prompt tokens used.
    pub prompt_tokens: u64,
    /// Completion tokens used.
    pub completion_tokens: u64,
    /// Total tokens used.
    pub total_tokens: u64,
}

/// Response from listing runs.
#[derive(Debug, Clone, Deserialize)]
pub struct RunListResponse {
    /// List of runs.
    pub data: Vec<Run>,
    /// Whether there are more results.
    pub has_more: bool,
}

/// API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiError {
    /// Error details
    pub error: ApiErrorDetails,
}

/// API error details.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorDetails {
    /// Error message
    pub message: String,
    /// Error type
    #[serde(rename = "type")]
    pub error_type: String,
    /// Parameter that caused the error
    pub param: Option<String>,
    /// Error code
    pub code: Option<String>,
}
