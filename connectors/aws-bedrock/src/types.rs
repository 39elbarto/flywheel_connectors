use serde::{Deserialize, Serialize};

use crate::error::{BedrockError, BedrockResult};
use crate::event_stream::EventStreamMessage;

const DEFAULT_MANTLE_ANTHROPIC_BETA: &str = "fine-grained-tool-streaming-2025-05-14";
const DEFAULT_MANTLE_MAX_TOKENS: u32 = 4_096;

#[derive(Clone, Deserialize)]
pub struct BedrockAuth {
    #[serde(default)]
    pub access_key_id: String,
    #[serde(default)]
    pub secret_access_key: String,
    #[serde(default)]
    pub session_token: Option<String>,
}

impl BedrockAuth {
    pub fn has_sigv4_credentials(&self) -> bool {
        !self.access_key_id.is_empty() && !self.secret_access_key.is_empty()
    }
}

impl std::fmt::Debug for BedrockAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BedrockAuth")
            .field("access_key_id", &"[REDACTED]")
            .field("secret_access_key", &"[REDACTED]")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConverseInput {
    pub model_id: String,
    pub messages: Vec<serde_json::Value>,
    #[serde(default)]
    pub system: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub inference_config: Option<serde_json::Value>,
    #[serde(default)]
    pub additional_model_request_fields: Option<serde_json::Value>,
    #[serde(default)]
    pub additional_model_response_field_paths: Option<Vec<String>>,
    #[serde(default)]
    pub guardrail_config: Option<serde_json::Value>,
    #[serde(default)]
    pub performance_config: Option<serde_json::Value>,
    #[serde(default)]
    pub prompt_variables: Option<serde_json::Value>,
    #[serde(default)]
    pub request_metadata: Option<serde_json::Value>,
    #[serde(default)]
    pub tool_config: Option<serde_json::Value>,
}

impl ConverseInput {
    pub fn request_body(&self) -> serde_json::Value {
        let mut body = serde_json::Map::new();
        body.insert(
            "messages".into(),
            serde_json::Value::Array(self.messages.clone()),
        );
        insert_optional(&mut body, "system", self.system.clone());
        insert_optional(&mut body, "inferenceConfig", self.inference_config.clone());
        insert_optional(
            &mut body,
            "additionalModelRequestFields",
            self.additional_model_request_fields.clone(),
        );
        insert_optional(
            &mut body,
            "additionalModelResponseFieldPaths",
            self.additional_model_response_field_paths.clone(),
        );
        insert_optional(&mut body, "guardrailConfig", self.guardrail_config.clone());
        insert_optional(
            &mut body,
            "performanceConfig",
            self.performance_config.clone(),
        );
        insert_optional(&mut body, "promptVariables", self.prompt_variables.clone());
        insert_optional(&mut body, "requestMetadata", self.request_metadata.clone());
        insert_optional(&mut body, "toolConfig", self.tool_config.clone());
        serde_json::Value::Object(body)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvokeModelFamily {
    AnthropicClaude,
    MantleAnthropicMessages,
    MetaLlama,
    AmazonTitan,
    CohereCommand,
    Mistral,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MantleReasoningLevel {
    Minimal,
    Low,
    Medium,
    High,
    Xhigh,
}

impl MantleReasoningLevel {
    const fn default_budget_tokens(self) -> u32 {
        match self {
            Self::Minimal => 1_024,
            Self::Low => 2_048,
            Self::Medium => 8_192,
            Self::High | Self::Xhigh => 16_384,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InvokeModelInput {
    pub model_id: String,
    #[serde(default)]
    pub body: Option<serde_json::Value>,
    #[serde(default)]
    pub model_family: Option<InvokeModelFamily>,
    #[serde(default)]
    pub prompt: Option<String>,
    #[serde(default)]
    pub messages: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub system: Option<serde_json::Value>,
    #[serde(default)]
    pub max_tokens: Option<u32>,
    #[serde(default)]
    pub temperature: Option<f64>,
    #[serde(default)]
    pub top_p: Option<f64>,
    #[serde(default)]
    pub accept: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub trace: Option<String>,
    #[serde(default)]
    pub guardrail_identifier: Option<String>,
    #[serde(default)]
    pub guardrail_version: Option<String>,
    #[serde(default)]
    pub performance_config_latency: Option<String>,
    #[serde(default)]
    pub service_tier: Option<String>,
    #[serde(default)]
    pub stream: Option<bool>,
    #[serde(default)]
    pub stop_sequences: Option<Vec<String>>,
    #[serde(default)]
    pub tools: Option<serde_json::Value>,
    #[serde(default)]
    pub tool_choice: Option<serde_json::Value>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
    #[serde(default)]
    pub thinking: Option<serde_json::Value>,
    #[serde(default)]
    pub reasoning_level: Option<MantleReasoningLevel>,
    #[serde(default)]
    pub thinking_budget_tokens: Option<u32>,
    #[serde(default)]
    pub model_max_tokens: Option<u32>,
    #[serde(default)]
    pub anthropic_beta: Option<Vec<String>>,
    #[serde(default)]
    pub extra_body: Option<serde_json::Value>,
}

impl InvokeModelInput {
    pub fn request_body(&self) -> BedrockResult<serde_json::Value> {
        if let Some(body) = &self.body {
            return Ok(body.clone());
        }
        let Some(family) = &self.model_family else {
            return Err(BedrockError::InvalidInput(
                "invoke_model requires either body or model_family".into(),
            ));
        };
        build_invoke_model_body(family, self)
    }

    pub fn is_mantle_anthropic_messages(&self) -> bool {
        matches!(
            self.model_family,
            Some(InvokeModelFamily::MantleAnthropicMessages)
        )
    }

    pub fn mantle_anthropic_body(&self, force_stream: bool) -> BedrockResult<serde_json::Value> {
        if let Some(body) = &self.body {
            if !force_stream {
                return Ok(body.clone());
            }
            let mut body = body.clone();
            let Some(object) = body.as_object_mut() else {
                return Err(BedrockError::InvalidInput(
                    "mantle_anthropic_messages streaming body must be a JSON object".into(),
                ));
            };
            object.insert("stream".into(), serde_json::json!(true));
            return Ok(body);
        }
        let messages = self.messages.clone().ok_or_else(|| {
            BedrockError::InvalidInput("mantle_anthropic_messages requires messages".into())
        })?;
        let mut body = serde_json::Map::new();
        body.insert("model".into(), serde_json::json!(self.model_id));
        body.insert("messages".into(), serde_json::Value::Array(messages));
        let mut max_tokens = self.max_tokens.unwrap_or(DEFAULT_MANTLE_MAX_TOKENS);
        if let Some(system) = &self.system {
            body.insert("system".into(), system.clone());
        }
        if model_allows_sampling(&self.model_id) {
            insert_optional(&mut body, "temperature", self.temperature);
            insert_optional(&mut body, "top_p", self.top_p);
        }
        insert_optional(&mut body, "stop_sequences", self.stop_sequences.clone());
        insert_optional(&mut body, "tools", self.tools.clone());
        insert_optional(&mut body, "tool_choice", self.tool_choice.clone());
        insert_optional(&mut body, "metadata", self.metadata.clone());
        if let Some(thinking) = &self.thinking {
            body.insert("thinking".into(), thinking.clone());
        } else if let Some(level) = self.reasoning_level {
            let thinking_budget = self
                .thinking_budget_tokens
                .unwrap_or_else(|| level.default_budget_tokens());
            let model_max = self.model_max_tokens.unwrap_or(u32::MAX);
            max_tokens = max_tokens.saturating_add(thinking_budget).min(model_max);
            let adjusted_budget = if max_tokens <= thinking_budget {
                max_tokens.saturating_sub(1_024)
            } else {
                thinking_budget
            };
            body.insert(
                "thinking".into(),
                serde_json::json!({
                    "type": "enabled",
                    "budget_tokens": adjusted_budget,
                }),
            );
        }
        body.insert("max_tokens".into(), serde_json::json!(max_tokens));
        body.insert(
            "stream".into(),
            serde_json::json!(force_stream || self.stream.unwrap_or(false)),
        );
        if let Some(extra) = &self.extra_body {
            let Some(extra) = extra.as_object() else {
                return Err(BedrockError::InvalidInput(
                    "extra_body must be a JSON object".into(),
                ));
            };
            for (key, value) in extra {
                body.insert(key.clone(), value.clone());
            }
        }
        Ok(serde_json::Value::Object(body))
    }

    pub fn mantle_beta_header(&self) -> String {
        let mut values = vec![DEFAULT_MANTLE_ANTHROPIC_BETA.to_string()];
        if let Some(configured) = &self.anthropic_beta {
            for value in configured {
                let trimmed = value.trim();
                if !trimmed.is_empty() && !values.iter().any(|existing| existing == trimmed) {
                    values.push(trimmed.to_string());
                }
            }
        }
        values.join(",")
    }

    pub fn accept(&self) -> &str {
        self.accept.as_deref().unwrap_or("application/json")
    }

    pub fn content_type(&self) -> &str {
        self.content_type.as_deref().unwrap_or("application/json")
    }
}

pub fn build_invoke_model_body(
    family: &InvokeModelFamily,
    input: &InvokeModelInput,
) -> BedrockResult<serde_json::Value> {
    match family {
        InvokeModelFamily::AnthropicClaude => {
            let messages = input.messages.clone().ok_or_else(|| {
                BedrockError::InvalidInput("anthropic_claude requires messages".into())
            })?;
            let mut body = serde_json::json!({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": input.max_tokens.unwrap_or(1024),
                "messages": messages,
            });
            if let Some(system) = &input.system {
                body["system"] = system.clone();
            }
            insert_generation_config(&mut body, input);
            Ok(body)
        }
        InvokeModelFamily::MantleAnthropicMessages => input.mantle_anthropic_body(false),
        InvokeModelFamily::MetaLlama => {
            let prompt = required_prompt(input, "meta_llama")?;
            let mut body = serde_json::json!({
                "prompt": prompt,
                "max_gen_len": input.max_tokens.unwrap_or(1024),
            });
            insert_generation_config(&mut body, input);
            Ok(body)
        }
        InvokeModelFamily::AmazonTitan => {
            let prompt = required_prompt(input, "amazon_titan")?;
            let mut config = serde_json::Map::new();
            if let Some(max_tokens) = input.max_tokens {
                config.insert("maxTokenCount".into(), serde_json::json!(max_tokens));
            }
            if let Some(temperature) = input.temperature {
                config.insert("temperature".into(), serde_json::json!(temperature));
            }
            if let Some(top_p) = input.top_p {
                config.insert("topP".into(), serde_json::json!(top_p));
            }
            Ok(serde_json::json!({
                "inputText": prompt,
                "textGenerationConfig": serde_json::Value::Object(config),
            }))
        }
        InvokeModelFamily::CohereCommand => {
            let prompt = required_prompt(input, "cohere_command")?;
            let mut body = serde_json::json!({
                "message": prompt,
            });
            insert_generation_config(&mut body, input);
            Ok(body)
        }
        InvokeModelFamily::Mistral => {
            let prompt = required_prompt(input, "mistral")?;
            let mut body = serde_json::json!({
                "prompt": prompt,
                "max_tokens": input.max_tokens.unwrap_or(1024),
            });
            insert_generation_config(&mut body, input);
            Ok(body)
        }
    }
}

fn model_allows_sampling(model_id: &str) -> bool {
    !model_id.contains("claude-opus-4-7")
}

fn required_prompt(input: &InvokeModelInput, family: &str) -> BedrockResult<String> {
    input
        .prompt
        .as_ref()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| BedrockError::InvalidInput(format!("{family} requires prompt")))
}

fn insert_generation_config(body: &mut serde_json::Value, input: &InvokeModelInput) {
    if let Some(temperature) = input.temperature {
        body["temperature"] = serde_json::json!(temperature);
    }
    if let Some(top_p) = input.top_p {
        body["top_p"] = serde_json::json!(top_p);
    }
}

fn insert_optional<T: Serialize>(
    body: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: Option<T>,
) {
    if let Some(value) = value {
        body.insert(
            key.into(),
            serde_json::to_value(value).expect("serializing request field should not fail"),
        );
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ListModelsInput {
    #[serde(default)]
    pub by_customization_type: Option<String>,
    #[serde(default)]
    pub by_inference_type: Option<String>,
    #[serde(default)]
    pub by_output_modality: Option<String>,
    #[serde(default)]
    pub by_provider: Option<String>,
    #[serde(default)]
    pub source: Option<ModelListSource>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ModelListSource {
    #[default]
    Native,
    Mantle,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FoundationModelsResponse {
    pub model_summaries: Vec<FoundationModelSummary>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FoundationModelSummary {
    pub model_arn: Option<String>,
    pub model_id: String,
    pub model_name: Option<String>,
    pub provider_name: Option<String>,
    #[serde(default)]
    pub input_modalities: Vec<String>,
    #[serde(default)]
    pub output_modalities: Vec<String>,
    #[serde(default)]
    pub response_streaming_supported: Option<bool>,
    #[serde(default)]
    pub customizations_supported: Vec<String>,
    #[serde(default)]
    pub inference_types_supported: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BedrockStreamEvent {
    pub event_type: Option<String>,
    pub headers: std::collections::BTreeMap<String, crate::event_stream::HeaderValue>,
    pub payload_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_json: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_utf8: Option<String>,
}

impl From<EventStreamMessage> for BedrockStreamEvent {
    fn from(message: EventStreamMessage) -> Self {
        let event_type = message.event_type().map(str::to_string);
        let payload_bytes = message.payload.len();
        let payload_json = message.payload_json();
        let payload_utf8 = if payload_json.is_none() {
            String::from_utf8(message.payload.clone()).ok()
        } else {
            None
        };
        Self {
            event_type,
            headers: message.headers,
            payload_bytes,
            payload_json,
            payload_utf8,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BedrockStreamResponse {
    pub events: Vec<BedrockStreamEvent>,
    pub chunk_count: usize,
    pub total_payload_bytes: usize,
}

impl BedrockStreamResponse {
    pub fn from_messages(messages: Vec<EventStreamMessage>) -> Self {
        let total_payload_bytes = messages.iter().map(|message| message.payload.len()).sum();
        let events: Vec<BedrockStreamEvent> = messages.into_iter().map(Into::into).collect();
        let chunk_count = events.len();
        Self {
            events,
            chunk_count,
            total_payload_bytes,
        }
    }

    pub fn from_events(events: Vec<BedrockStreamEvent>) -> Self {
        let total_payload_bytes = events.iter().map(|event| event.payload_bytes).sum();
        let chunk_count = events.len();
        Self {
            events,
            chunk_count,
            total_payload_bytes,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct HealthStatus {
    pub control_plane_reachable: bool,
    pub model_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ACCESS_KEY_ID: &str = "fcp-test-access-key";
    const TEST_SIGNING_MATERIAL: &str = "fcp-test-signing-material";
    const TEST_SESSION_MATERIAL: &str = "fcp-test-session-material";

    fn invoke_input_for_family(
        model_id: &str,
        model_family: InvokeModelFamily,
    ) -> InvokeModelInput {
        InvokeModelInput {
            model_id: model_id.into(),
            body: None,
            model_family: Some(model_family),
            prompt: Some("hello".into()),
            messages: None,
            system: None,
            max_tokens: Some(64),
            temperature: Some(0.5),
            top_p: Some(0.9),
            accept: None,
            content_type: None,
            trace: None,
            guardrail_identifier: None,
            guardrail_version: None,
            performance_config_latency: None,
            service_tier: None,
            stream: None,
            stop_sequences: None,
            tools: None,
            tool_choice: None,
            metadata: None,
            thinking: None,
            reasoning_level: None,
            thinking_budget_tokens: None,
            model_max_tokens: None,
            anthropic_beta: None,
            extra_body: None,
        }
    }

    #[test]
    fn auth_debug_redacts_secrets() {
        let auth = BedrockAuth {
            access_key_id: TEST_ACCESS_KEY_ID.into(),
            secret_access_key: TEST_SIGNING_MATERIAL.into(),
            session_token: Some(TEST_SESSION_MATERIAL.into()),
        };

        let debug = format!("{auth:?}");

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(TEST_ACCESS_KEY_ID));
        assert!(!debug.contains(TEST_SIGNING_MATERIAL));
        assert!(!debug.contains(TEST_SESSION_MATERIAL));
    }

    #[test]
    fn converse_body_uses_aws_camel_case_fields() {
        let input = ConverseInput {
            model_id: "anthropic.claude-3-sonnet-20240229-v1:0".into(),
            messages: vec![serde_json::json!({
                "role": "user",
                "content": [{"text": "hello"}],
            })],
            system: None,
            inference_config: Some(serde_json::json!({"maxTokens": 64})),
            additional_model_request_fields: Some(serde_json::json!({"top_k": 40})),
            additional_model_response_field_paths: Some(vec!["/stop_sequence".into()]),
            guardrail_config: None,
            performance_config: None,
            prompt_variables: None,
            request_metadata: None,
            tool_config: None,
        };

        let body = input.request_body();

        assert!(body.get("inferenceConfig").is_some());
        assert!(body.get("additionalModelRequestFields").is_some());
        assert_eq!(body["messages"][0]["role"], "user");
    }

    #[test]
    fn invoke_model_builds_claude_body() {
        let input = InvokeModelInput {
            model_id: "anthropic.claude-3-sonnet-20240229-v1:0".into(),
            body: None,
            model_family: Some(InvokeModelFamily::AnthropicClaude),
            prompt: None,
            messages: Some(vec![serde_json::json!({
                "role": "user",
                "content": [{"type": "text", "text": "hello"}],
            })]),
            system: Some(serde_json::json!("answer briefly")),
            max_tokens: Some(128),
            temperature: Some(0.2),
            top_p: None,
            accept: None,
            content_type: None,
            trace: None,
            guardrail_identifier: None,
            guardrail_version: None,
            performance_config_latency: None,
            service_tier: None,
            stream: None,
            stop_sequences: None,
            tools: None,
            tool_choice: None,
            metadata: None,
            thinking: None,
            reasoning_level: None,
            thinking_budget_tokens: None,
            model_max_tokens: None,
            anthropic_beta: None,
            extra_body: None,
        };

        let body = input.request_body().unwrap();

        assert_eq!(body["anthropic_version"], "bedrock-2023-05-31");
        assert_eq!(body["max_tokens"], 128);
        assert_eq!(body["system"], "answer briefly");
        assert_eq!(body["temperature"], 0.2);
    }

    #[test]
    fn invoke_model_builds_mantle_anthropic_body_with_default_beta_and_thinking_budget() {
        let input = InvokeModelInput {
            model_id: "anthropic.claude-sonnet-4-5".into(),
            body: None,
            model_family: Some(InvokeModelFamily::MantleAnthropicMessages),
            prompt: None,
            messages: Some(vec![serde_json::json!({
                "role": "user",
                "content": [{"type": "text", "text": "hello"}],
            })]),
            system: Some(serde_json::json!("answer briefly")),
            max_tokens: Some(2_048),
            temperature: Some(0.2),
            top_p: None,
            accept: None,
            content_type: None,
            trace: None,
            guardrail_identifier: None,
            guardrail_version: None,
            performance_config_latency: None,
            service_tier: None,
            stream: None,
            stop_sequences: Some(vec!["stop".into()]),
            tools: None,
            tool_choice: None,
            metadata: None,
            thinking: None,
            reasoning_level: Some(MantleReasoningLevel::Medium),
            thinking_budget_tokens: None,
            model_max_tokens: Some(32_000),
            anthropic_beta: Some(vec![
                DEFAULT_MANTLE_ANTHROPIC_BETA.into(),
                "context-management-2025-06-27".into(),
            ]),
            extra_body: None,
        };

        let body = input.mantle_anthropic_body(false).unwrap();

        assert_eq!(body["model"], "anthropic.claude-sonnet-4-5");
        assert_eq!(body["max_tokens"], 10_240);
        assert_eq!(body["thinking"]["budget_tokens"], 8_192);
        assert_eq!(body["temperature"], 0.2);
        assert_eq!(body["stream"], false);
        assert_eq!(
            input.mantle_beta_header(),
            "fine-grained-tool-streaming-2025-05-14,context-management-2025-06-27"
        );
    }

    #[test]
    fn invoke_model_builds_titan_body() {
        let input = invoke_input_for_family(
            "amazon.titan-text-express-v1",
            InvokeModelFamily::AmazonTitan,
        );

        let body = input.request_body().unwrap();

        assert_eq!(body["inputText"], "hello");
        assert_eq!(body["textGenerationConfig"]["maxTokenCount"], 64);
        assert_eq!(body["textGenerationConfig"]["topP"], 0.9);
    }

    #[test]
    fn invoke_model_builds_llama_body() {
        let input =
            invoke_input_for_family("meta.llama3-8b-instruct-v1:0", InvokeModelFamily::MetaLlama);

        let body = input.request_body().unwrap();

        assert_eq!(body["prompt"], "hello");
        assert_eq!(body["max_gen_len"], 64);
        assert_eq!(body["temperature"], 0.5);
        assert_eq!(body["top_p"], 0.9);
    }

    #[test]
    fn invoke_model_builds_cohere_command_body() {
        let input =
            invoke_input_for_family("cohere.command-r-v1:0", InvokeModelFamily::CohereCommand);

        let body = input.request_body().unwrap();

        assert_eq!(body["message"], "hello");
        assert_eq!(body["temperature"], 0.5);
        assert_eq!(body["top_p"], 0.9);
    }

    #[test]
    fn invoke_model_builds_mistral_body() {
        let input = invoke_input_for_family(
            "mistral.mistral-7b-instruct-v0:2",
            InvokeModelFamily::Mistral,
        );

        let body = input.request_body().unwrap();

        assert_eq!(body["prompt"], "hello");
        assert_eq!(body["max_tokens"], 64);
        assert_eq!(body["temperature"], 0.5);
        assert_eq!(body["top_p"], 0.9);
    }
}
