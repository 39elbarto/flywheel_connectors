//! Google AI (Gemini) API types.

use serde::{Deserialize, Serialize};

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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---- Content + Part ----

    #[test]
    fn content_text_serde() {
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
    }

    #[test]
    fn part_function_call_serde() {
        let part = Part::FunctionCall {
            function_call: FunctionCallData {
                name: "get_weather".to_string(),
                args: json!({"city": "London"}),
            },
        };
        let json = serde_json::to_string(&part).unwrap();
        assert!(json.contains("functionCall"));
        let back: Part = serde_json::from_str(&json).unwrap();
        match back {
            Part::FunctionCall { function_call } => assert_eq!(function_call.name, "get_weather"),
            _ => panic!("expected FunctionCall"),
        }
    }

    #[test]
    fn part_function_response_serde() {
        let part = Part::FunctionResponse {
            function_response: FunctionResponseData {
                name: "get_weather".to_string(),
                response: json!({"temp": 20}),
            },
        };
        let json = serde_json::to_string(&part).unwrap();
        assert!(json.contains("functionResponse"));
    }

    // ---- GenerateContentResponse ----

    #[test]
    fn generate_content_response_serde() {
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
            }
        });
        let resp: GenerateContentResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.candidates.len(), 1);
        assert_eq!(resp.candidates[0].finish_reason.as_deref(), Some("STOP"));
        let usage = resp.usage_metadata.unwrap();
        assert_eq!(usage.total_token_count, 15);
    }

    #[test]
    fn generate_content_response_empty() {
        let json = json!({});
        let resp: GenerateContentResponse = serde_json::from_value(json).unwrap();
        assert!(resp.candidates.is_empty());
        assert!(resp.usage_metadata.is_none());
    }

    // ---- UsageMetadata ----

    #[test]
    fn usage_metadata_default() {
        let usage = UsageMetadata::default();
        assert_eq!(usage.prompt_token_count, 0);
        assert_eq!(usage.candidates_token_count, 0);
        assert_eq!(usage.total_token_count, 0);
    }

    // ---- Embedding ----

    #[test]
    fn embed_content_response_serde() {
        let json = json!({"embedding": {"values": [0.1, 0.2, 0.3]}});
        let resp: EmbedContentResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.embedding.values.len(), 3);
    }

    #[test]
    fn batch_embed_response_serde() {
        let json = json!({"embeddings": [{"values": [0.1]}, {"values": [0.2]}]});
        let resp: BatchEmbedContentsResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.embeddings.len(), 2);
    }

    // ---- CountTokensResponse ----

    #[test]
    fn count_tokens_response_serde() {
        let json = json!({"totalTokens": 42});
        let resp: CountTokensResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.total_tokens, 42);
    }

    // ---- ModelInfo ----

    #[test]
    fn model_info_serde() {
        let json = json!({
            "name": "models/gemini-1.5-flash",
            "displayName": "Gemini 1.5 Flash",
            "description": "Fast model",
            "supportedGenerationMethods": ["generateContent", "countTokens"],
            "inputTokenLimit": 1000000,
            "outputTokenLimit": 8192
        });
        let info: ModelInfo = serde_json::from_value(json).unwrap();
        assert_eq!(info.name, "models/gemini-1.5-flash");
        assert_eq!(info.supported_generation_methods.len(), 2);
        assert_eq!(info.input_token_limit, Some(1_000_000));
    }

    #[test]
    fn model_info_minimal() {
        let json = json!({"name": "models/test"});
        let info: ModelInfo = serde_json::from_value(json).unwrap();
        assert_eq!(info.name, "models/test");
        assert!(info.display_name.is_none());
        assert!(info.supported_generation_methods.is_empty());
    }

    // ---- ListModelsResponse ----

    #[test]
    fn list_models_response_serde() {
        let json = json!({
            "models": [{"name": "models/gemini-1.5-flash"}],
            "nextPageToken": "abc"
        });
        let resp: ListModelsResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.models.len(), 1);
        assert_eq!(resp.next_page_token.as_deref(), Some("abc"));
    }

    // ---- ApiErrorResponse ----

    #[test]
    fn api_error_response_serde() {
        let json = json!({"error": {"message": "Not found", "status": "NOT_FOUND", "code": 404}});
        let resp: ApiErrorResponse = serde_json::from_value(json).unwrap();
        let detail = resp.error.unwrap();
        assert_eq!(detail.code, Some(404));
        assert_eq!(detail.status.as_deref(), Some("NOT_FOUND"));
    }

    // ---- UsageCounters ----

    #[test]
    fn usage_counters_default() {
        let counters = UsageCounters::default();
        assert_eq!(counters.input_tokens, 0);
        assert_eq!(counters.requests_total, 0);
    }
}
