//! Whisper connector types.

use serde::{Deserialize, Serialize};

/// Request to transcribe audio.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscribeRequest {
    /// Base64-encoded audio data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audio_base64: Option<String>,
    /// URL to audio file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audio_url: Option<String>,
    /// Model to use for transcription (default: whisper-1).
    #[serde(default = "default_model")]
    pub model: String,
    /// Language of the audio (ISO 639-1 code).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    /// Response format: json, text, srt, vtt, or verbose json.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_format: Option<String>,
    /// Sampling temperature (0.0 to 1.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
}

impl Default for TranscribeRequest {
    fn default() -> Self {
        Self {
            audio_base64: None,
            audio_url: None,
            model: default_model(),
            language: None,
            response_format: None,
            temperature: None,
        }
    }
}

/// Transcription result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptionResult {
    /// The transcribed text.
    pub text: String,
    /// Detected language.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    /// Duration of the audio in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_seconds: Option<f64>,
    /// Transcription segments.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub segments: Vec<TranscriptionSegment>,
}

/// A segment of a transcription.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptionSegment {
    /// Segment index.
    pub id: u32,
    /// Start time in seconds.
    pub start: f64,
    /// End time in seconds.
    pub end: f64,
    /// Segment text.
    pub text: String,
    /// Token IDs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tokens: Vec<u32>,
    /// Temperature used for this segment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    /// Average log probability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avg_logprob: Option<f64>,
    /// No speech probability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_speech_prob: Option<f64>,
}

/// Word-level timestamp.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WordTimestamp {
    /// The word.
    pub word: String,
    /// Start time in seconds.
    pub start: f64,
    /// End time in seconds.
    pub end: f64,
}

/// Verbose transcription with word-level detail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerboseTranscription {
    /// The full transcribed text.
    pub text: String,
    /// Detected language.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    /// Duration of the audio in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<f64>,
    /// Transcription segments.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub segments: Vec<TranscriptionSegment>,
    /// Word-level timestamps.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub words: Vec<WordTimestamp>,
}

/// Request to translate audio to English.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranslateRequest {
    /// Base64-encoded audio data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audio_base64: Option<String>,
    /// URL to audio file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audio_url: Option<String>,
    /// Model to use (default: whisper-1).
    #[serde(default = "default_model")]
    pub model: String,
    /// Sampling temperature (0.0 to 1.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
}

impl Default for TranslateRequest {
    fn default() -> Self {
        Self {
            audio_base64: None,
            audio_url: None,
            model: default_model(),
            temperature: None,
        }
    }
}

/// Translation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranslationResult {
    /// The translated text (in English).
    pub text: String,
    /// Detected source language.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_language: Option<String>,
    /// Duration of the audio in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_seconds: Option<f64>,
}

/// Whisper model information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhisperModel {
    /// Model identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Description of the model.
    pub description: String,
    /// Maximum file size in megabytes.
    pub max_file_size_mb: u32,
    /// Number of supported languages.
    pub supported_languages: u32,
}

/// Supported audio format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudioFormat {
    /// File extension.
    pub extension: String,
    /// MIME type.
    pub mime_type: String,
    /// Human-readable description.
    pub description: String,
}

/// API error response envelope.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    /// The error object.
    pub error: Option<ApiErrorDetail>,
}

/// API error detail.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorDetail {
    /// Error message.
    pub message: Option<String>,
    /// Error type.
    #[serde(rename = "type")]
    pub error_type: Option<String>,
    /// Error code.
    pub code: Option<String>,
}

fn default_model() -> String {
    "whisper-1".to_string()
}
