use serde::{Deserialize, Serialize};

// ── Auth ──

/// Perplexity authentication: Bearer token.
#[derive(Clone, Deserialize)]
pub struct PerplexityAuth {
    /// API key, typically starts with `pplx-`.
    pub api_key: String,
}

impl PerplexityAuth {
    #[must_use]
    pub fn is_secretless(&self) -> bool {
        self.api_key.trim().is_empty()
    }
}

impl std::fmt::Debug for PerplexityAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PerplexityAuth")
            .field("api_key", &"[REDACTED]")
            .finish()
    }
}

// ── Chat Completion Request ──

/// A message in the chat conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

/// Request body for the Perplexity chat completions endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct ChatCompletionRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search_domain_filter: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_images: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_related_questions: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search_recency_filter: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_k: Option<u32>,
    /// Always false for non-streaming usage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presence_penalty: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frequency_penalty: Option<f64>,
}

// ── Chat Completion Response ──

/// Top-level response from the chat completions endpoint.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChatCompletionResponse {
    pub id: String,
    pub model: String,
    pub object: String,
    pub created: u64,
    pub choices: Vec<Choice>,
    #[serde(default)]
    pub usage: Option<Usage>,
    /// Citations returned by Perplexity search models.
    #[serde(default)]
    pub citations: Option<Vec<String>>,
}

/// A single completion choice.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Choice {
    pub index: u32,
    pub finish_reason: Option<String>,
    pub message: ChatMessage,
    pub delta: Option<ChatMessage>,
}

/// Token usage information.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Usage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

// ── Native Search API ──

/// Request body for the native Perplexity Search API.
#[derive(Debug, Clone, Serialize)]
pub struct SearchApiRequest {
    pub query: String,
    pub max_results: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search_domain_filter: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search_recency_filter: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search_language_filter: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search_after_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search_before_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens_per_page: Option<u32>,
}

/// Top-level response from the native Perplexity Search API.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SearchApiResponse {
    #[serde(default)]
    pub results: Vec<SearchApiResult>,
}

/// A single native search result.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SearchApiResult {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub snippet: Option<String>,
    #[serde(default)]
    pub date: Option<String>,
}

// ── API Error ──

/// Error response body from the Perplexity API.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiErrorResponse {
    pub error: Option<ApiErrorDetail>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiErrorDetail {
    pub message: String,
    #[serde(rename = "type")]
    pub error_type: Option<String>,
    pub code: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_api_key() {
        let auth = PerplexityAuth {
            api_key: "pplx-secret-key-12345".into(),
        };
        let debug = format!("{auth:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("pplx-secret"));
    }

    #[test]
    fn auth_secretless_detects_empty_key() {
        let empty = PerplexityAuth {
            api_key: "  ".into(),
        };
        assert!(empty.is_secretless());

        let present = PerplexityAuth {
            api_key: "pplx-abc".into(),
        };
        assert!(!present.is_secretless());
    }

    #[test]
    fn deserialize_chat_message() {
        let json = serde_json::json!({
            "role": "user",
            "content": "What is Rust?"
        });
        let msg: ChatMessage = serde_json::from_value(json).unwrap();
        assert_eq!(msg.role, "user");
        assert_eq!(msg.content, "What is Rust?");
    }

    #[test]
    fn serialize_chat_completion_request_omits_none_fields() {
        let req = ChatCompletionRequest {
            model: "sonar".into(),
            messages: vec![ChatMessage {
                role: "user".into(),
                content: "Hello".into(),
            }],
            max_tokens: None,
            temperature: Some(0.7),
            top_p: None,
            search_domain_filter: None,
            return_images: None,
            return_related_questions: None,
            search_recency_filter: None,
            top_k: None,
            stream: Some(false),
            presence_penalty: None,
            frequency_penalty: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["model"], "sonar");
        assert!(json.get("max_tokens").is_none());
        assert_eq!(json["temperature"], 0.7);
        assert_eq!(json["stream"], false);
    }

    #[test]
    fn deserialize_chat_completion_response() {
        let json = serde_json::json!({
            "id": "chatcmpl-abc123",
            "model": "sonar",
            "object": "chat.completion",
            "created": 1_700_000_000u64,
            "choices": [{
                "index": 0,
                "finish_reason": "stop",
                "message": { "role": "assistant", "content": "Rust is a systems programming language." },
                "delta": null
            }],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 50,
                "total_tokens": 60
            },
            "citations": ["https://www.rust-lang.org/"]
        });
        let resp: ChatCompletionResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.id, "chatcmpl-abc123");
        assert_eq!(resp.choices.len(), 1);
        assert_eq!(resp.choices[0].finish_reason.as_deref(), Some("stop"));
        assert_eq!(resp.usage.as_ref().unwrap().total_tokens, 60);
        assert_eq!(resp.citations.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn deserialize_chat_completion_response_no_citations() {
        let json = serde_json::json!({
            "id": "chatcmpl-xyz",
            "model": "sonar-pro",
            "object": "chat.completion",
            "created": 1_700_000_001u64,
            "choices": [{
                "index": 0,
                "finish_reason": "stop",
                "message": { "role": "assistant", "content": "No citations here." },
                "delta": null
            }]
        });
        let resp: ChatCompletionResponse = serde_json::from_value(json).unwrap();
        assert!(resp.citations.is_none());
        assert!(resp.usage.is_none());
    }

    #[test]
    fn deserialize_api_error_response() {
        let json = serde_json::json!({
            "error": {
                "message": "Invalid API Key",
                "type": "authentication_error",
                "code": 401
            }
        });
        let resp: ApiErrorResponse = serde_json::from_value(json).unwrap();
        let detail = resp.error.unwrap();
        assert_eq!(detail.message, "Invalid API Key");
        assert_eq!(detail.error_type.as_deref(), Some("authentication_error"));
    }

    #[test]
    fn serialize_search_api_request_omits_none_fields() {
        let req = SearchApiRequest {
            query: "rust async".into(),
            max_results: 5,
            country: None,
            search_domain_filter: Some(vec!["rust-lang.org".into()]),
            search_recency_filter: Some("week".into()),
            search_language_filter: None,
            search_after_date: None,
            search_before_date: None,
            max_tokens: Some(1000),
            max_tokens_per_page: None,
        };

        let json = serde_json::to_value(req).unwrap();
        assert_eq!(json["query"], "rust async");
        assert_eq!(json["max_results"], 5);
        assert_eq!(json["search_domain_filter"][0], "rust-lang.org");
        assert!(json.get("country").is_none());
        assert!(json.get("max_tokens_per_page").is_none());
    }

    #[test]
    fn deserialize_search_api_response_accepts_missing_fields() {
        let json = serde_json::json!({
            "results": [
                {
                    "title": "Rust",
                    "url": "https://www.rust-lang.org/",
                    "snippet": "Rust language",
                    "date": "2026-05-01"
                },
                {}
            ]
        });

        let resp: SearchApiResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.results.len(), 2);
        assert_eq!(
            resp.results[0].url.as_deref(),
            Some("https://www.rust-lang.org/")
        );
        assert!(resp.results[1].title.is_none());
    }

    #[test]
    fn usage_fields_parse_correctly() {
        let json = serde_json::json!({
            "prompt_tokens": 15,
            "completion_tokens": 100,
            "total_tokens": 115
        });
        let usage: Usage = serde_json::from_value(json).unwrap();
        assert_eq!(usage.prompt_tokens, 15);
        assert_eq!(usage.completion_tokens, 100);
        assert_eq!(usage.total_tokens, 115);
    }
}
