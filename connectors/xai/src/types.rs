use std::collections::{BTreeMap, BTreeSet};

use fcp_openai_compat::{
    ChatCompletionsRequest, ChatMessage, ProviderExtensions, ResponseFormat, ToolChoice,
    ToolDefinition,
};
use fcp_prelude::{FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use url::Url;

use crate::client::DEFAULT_MODEL;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChatInvokeInput {
    pub model: Option<String>,
    pub messages: Vec<ChatMessage>,
    pub temperature: Option<f32>,
    pub max_tokens: Option<u32>,
    pub top_p: Option<f32>,
    pub stop: Option<Vec<String>>,
    pub tools: Option<Vec<ToolDefinition>>,
    pub tool_choice: Option<ToolChoice>,
    pub response_format: Option<ResponseFormat>,
    pub seed: Option<i64>,
    pub user: Option<String>,
    pub n: Option<u32>,
    pub presence_penalty: Option<f32>,
    pub frequency_penalty: Option<f32>,
    pub logit_bias: Option<BTreeMap<String, f32>>,
    pub logprobs: Option<bool>,
    pub top_logprobs: Option<u32>,
    pub reasoning_effort: Option<String>,
    pub search_parameters: Option<Value>,
    #[serde(default)]
    pub provider_extensions: ProviderExtensions,
}

impl ChatInvokeInput {
    pub fn into_request(mut self, default_model: &str) -> FcpResult<ChatCompletionsRequest> {
        validate_xai_chat_input(&self)?;
        if let Some(reasoning_effort) = self.reasoning_effort {
            self.provider_extensions
                .insert("reasoning_effort".to_string(), json!(reasoning_effort));
        }
        if let Some(search_parameters) = self.search_parameters {
            self.provider_extensions
                .insert("search_parameters".to_string(), search_parameters);
        }

        Ok(ChatCompletionsRequest {
            model: self.model.unwrap_or_else(|| default_model.to_string()),
            messages: self.messages,
            temperature: self.temperature,
            max_tokens: self.max_tokens,
            top_p: self.top_p,
            stop: self.stop,
            stream: false,
            tools: self.tools,
            tool_choice: self.tool_choice,
            response_format: self.response_format,
            seed: self.seed,
            user: self.user,
            n: self.n,
            presence_penalty: self.presence_penalty,
            frequency_penalty: self.frequency_penalty,
            logit_bias: self.logit_bias,
            logprobs: self.logprobs,
            top_logprobs: self.top_logprobs,
            provider_extensions: self.provider_extensions,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebSearchOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_domains: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub excluded_domains: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_image_understanding: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponsesCreateInput {
    pub model: Option<String>,
    pub input: Value,
    pub instructions: Option<String>,
    pub include: Option<Vec<String>>,
    pub web_search: Option<WebSearchOptions>,
    pub tools: Option<Vec<Value>>,
    pub tool_choice: Option<Value>,
    pub max_output_tokens: Option<u32>,
    pub temperature: Option<f32>,
    pub top_p: Option<f32>,
    pub store: Option<bool>,
    pub previous_response_id: Option<String>,
    pub metadata: Option<Value>,
    #[serde(default)]
    pub provider_extensions: ProviderExtensions,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ResponsesCreateRequest {
    pub model: String,
    pub input: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_response_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub provider_extensions: ProviderExtensions,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseCitation {
    #[serde(rename = "type")]
    pub citation_type: String,
    pub url: String,
    pub host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_index: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_index: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ResponsesSummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    pub output_text: String,
    pub output_text_bytes: usize,
    pub citation_count: usize,
    pub citation_hosts: Vec<String>,
    pub citations: Vec<ResponseCitation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_side_tool_usage: Option<Value>,
}

pub fn chat_request_from_value(
    value: Value,
    default_model: &str,
) -> FcpResult<ChatCompletionsRequest> {
    let input: ChatInvokeInput =
        serde_json::from_value(value).map_err(|err| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid xAI chat input: {err}"),
        })?;
    input.into_request(if default_model.trim().is_empty() {
        DEFAULT_MODEL
    } else {
        default_model
    })
}

pub fn responses_request_from_value(
    value: Value,
    default_model: &str,
) -> FcpResult<ResponsesCreateRequest> {
    let input: ResponsesCreateInput =
        serde_json::from_value(value).map_err(|err| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid xAI responses input: {err}"),
        })?;
    input.into_request(if default_model.trim().is_empty() {
        DEFAULT_MODEL
    } else {
        default_model
    })
}

pub fn summarize_responses_value(raw: &Value) -> ResponsesSummary {
    let mut output_text_parts = Vec::new();
    let mut citations = Vec::new();

    if let Some(output) = raw.get("output").and_then(Value::as_array) {
        for item in output {
            collect_output_text_and_annotations(item, &mut output_text_parts, &mut citations);
        }
    }
    if output_text_parts.is_empty() {
        if let Some(text) = raw
            .get("output_text")
            .or_else(|| raw.pointer("/text/value"))
            .and_then(Value::as_str)
        {
            output_text_parts.push(text.to_string());
        }
    }
    collect_legacy_citation_urls(raw, &mut citations);

    let output_text = output_text_parts.join("\n");
    let citation_hosts = citations
        .iter()
        .map(|citation| citation.host.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    ResponsesSummary {
        id: raw
            .get("id")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        model: raw
            .get("model")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        status: raw
            .get("status")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        output_text_bytes: output_text.len(),
        output_text,
        citation_count: citations.len(),
        citation_hosts,
        citations,
        usage: raw.get("usage").cloned(),
        server_side_tool_usage: raw.get("server_side_tool_usage").cloned(),
    }
}

impl ResponsesCreateInput {
    fn into_request(self, default_model: &str) -> FcpResult<ResponsesCreateRequest> {
        validate_responses_input(&self)?;
        let mut tools = self.tools.unwrap_or_default();
        match self.web_search {
            Some(options) => {
                if tools.iter().any(is_web_search_tool) {
                    return Err(FcpError::InvalidRequest {
                        code: 1003,
                        message: "Provide web_search shorthand or a raw web_search tool, not both"
                            .into(),
                    });
                }
                tools.push(web_search_tool_value(&options)?);
            }
            None if !tools.iter().any(is_web_search_tool) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message:
                        "xai.responses.create requires a web_search tool or web_search options"
                            .into(),
                });
            }
            None => {}
        }

        Ok(ResponsesCreateRequest {
            model: self.model.unwrap_or_else(|| default_model.to_string()),
            input: self.input,
            instructions: self.instructions,
            include: self.include,
            tools,
            tool_choice: self.tool_choice,
            max_output_tokens: self.max_output_tokens,
            temperature: self.temperature,
            top_p: self.top_p,
            store: self.store,
            previous_response_id: self.previous_response_id,
            metadata: self.metadata,
            provider_extensions: self.provider_extensions,
        })
    }
}

fn validate_xai_chat_input(input: &ChatInvokeInput) -> FcpResult<()> {
    if input.messages.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "messages must be a non-empty array".into(),
        });
    }
    if input.n.is_some_and(|n| n == 0) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "n must be greater than 0 when supplied".into(),
        });
    }
    Ok(())
}

fn validate_responses_input(input: &ResponsesCreateInput) -> FcpResult<()> {
    if input.input.is_null() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "input is required for xai.responses.create".into(),
        });
    }
    if let Some(options) = &input.web_search {
        validate_web_search_options(options)?;
    }
    if let Some(include) = &input.include {
        for value in include {
            validate_header_safe_string("include", value)?;
        }
    }
    Ok(())
}

fn validate_web_search_options(options: &WebSearchOptions) -> FcpResult<()> {
    if options.allowed_domains.is_some() && options.excluded_domains.is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "allowed_domains cannot be combined with excluded_domains".into(),
        });
    }
    validate_domain_list("allowed_domains", options.allowed_domains.as_deref())?;
    validate_domain_list("excluded_domains", options.excluded_domains.as_deref())?;
    Ok(())
}

fn validate_domain_list(field: &str, domains: Option<&[String]>) -> FcpResult<()> {
    let Some(domains) = domains else {
        return Ok(());
    };
    if domains.is_empty() || domains.len() > 5 {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must contain between 1 and 5 domains"),
        });
    }
    for domain in domains {
        validate_header_safe_string(field, domain)?;
        if domain.contains('/') || domain.contains(':') || domain.trim().starts_with('.') {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("{field} entries must be domain names, not URLs"),
            });
        }
    }
    Ok(())
}

fn validate_header_safe_string(field: &str, value: &str) -> FcpResult<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} entries must not be empty"),
        });
    }
    if trimmed
        .bytes()
        .any(|byte| matches!(byte, b'\r' | b'\n' | 0))
    {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} entries contain invalid control characters"),
        });
    }
    Ok(())
}

fn web_search_tool_value(options: &WebSearchOptions) -> FcpResult<Value> {
    validate_web_search_options(options)?;
    let mut tool = Map::new();
    tool.insert("type".into(), json!("web_search"));
    if let Some(enable_image_understanding) = options.enable_image_understanding {
        tool.insert(
            "enable_image_understanding".into(),
            json!(enable_image_understanding),
        );
    }
    let mut filters = Map::new();
    if let Some(allowed_domains) = &options.allowed_domains {
        filters.insert("allowed_domains".into(), json!(allowed_domains));
    }
    if let Some(excluded_domains) = &options.excluded_domains {
        filters.insert("excluded_domains".into(), json!(excluded_domains));
    }
    if !filters.is_empty() {
        tool.insert("filters".into(), Value::Object(filters));
    }
    Ok(Value::Object(tool))
}

fn is_web_search_tool(value: &Value) -> bool {
    value
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|tool_type| tool_type == "web_search")
}

fn collect_output_text_and_annotations(
    value: &Value,
    output_text_parts: &mut Vec<String>,
    citations: &mut Vec<ResponseCitation>,
) {
    if value
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|kind| kind == "output_text")
    {
        if let Some(text) = value.get("text").and_then(Value::as_str) {
            output_text_parts.push(text.to_string());
        }
        if let Some(annotations) = value.get("annotations").and_then(Value::as_array) {
            for annotation in annotations {
                if let Some(citation) = citation_from_annotation(annotation) {
                    citations.push(citation);
                }
            }
        }
    }

    match value {
        Value::Array(values) => {
            for child in values {
                collect_output_text_and_annotations(child, output_text_parts, citations);
            }
        }
        Value::Object(map) => {
            for child in map.values() {
                collect_output_text_and_annotations(child, output_text_parts, citations);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn citation_from_annotation(value: &Value) -> Option<ResponseCitation> {
    let citation_type = value
        .get("type")
        .and_then(Value::as_str)
        .filter(|kind| *kind == "url_citation")?;
    let url = value.get("url").and_then(Value::as_str)?;
    let host = host_for_url(url)?;
    Some(ResponseCitation {
        citation_type: citation_type.to_string(),
        url: url.to_string(),
        host,
        title: value
            .get("title")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        start_index: value.get("start_index").and_then(Value::as_u64),
        end_index: value.get("end_index").and_then(Value::as_u64),
    })
}

fn collect_legacy_citation_urls(raw: &Value, citations: &mut Vec<ResponseCitation>) {
    let Some(values) = raw.get("citations").and_then(Value::as_array) else {
        return;
    };
    for value in values {
        let Some(url) = value.as_str() else {
            continue;
        };
        let Some(host) = host_for_url(url) else {
            continue;
        };
        citations.push(ResponseCitation {
            citation_type: "url_citation".into(),
            url: url.to_string(),
            host,
            title: None,
            start_index: None,
            end_index: None,
        });
    }
}

fn host_for_url(raw: &str) -> Option<String> {
    Url::parse(raw)
        .ok()
        .and_then(|url| url.host_str().map(ToString::to_string))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_openai_compat::ChatMessage;
    use serde_json::json;

    #[test]
    fn chat_request_does_not_enable_search_by_default() {
        let request = chat_request_from_value(
            json!({"messages": [{"role": "user", "content": "hello"}]}),
            DEFAULT_MODEL,
        )
        .expect("chat request should build");
        let value = serde_json::to_value(request).expect("request serializes");

        assert_eq!(value["model"], DEFAULT_MODEL);
        assert_eq!(value["stream"], false);
        assert!(value.get("search_parameters").is_none());
    }

    #[test]
    fn chat_request_preserves_explicit_legacy_search_parameters() {
        let request = chat_request_from_value(
            json!({
                "messages": [{"role": "user", "content": "fresh news"}],
                "search_parameters": {"mode": "auto", "return_citations": true}
            }),
            DEFAULT_MODEL,
        )
        .expect("chat request should build");
        let value = serde_json::to_value(request).expect("request serializes");

        assert_eq!(value["search_parameters"]["mode"], "auto");
        assert_eq!(value["search_parameters"]["return_citations"], true);
    }

    #[test]
    fn responses_web_search_shorthand_builds_current_tool_shape() {
        let request = responses_request_from_value(
            json!({
                "model": "grok-4.3",
                "input": [{"role": "user", "content": "What is xAI?"}],
                "include": ["no_inline_citations"],
                "web_search": {
                    "allowed_domains": ["x.ai"],
                    "enable_image_understanding": true
                }
            }),
            DEFAULT_MODEL,
        )
        .expect("responses request should build");
        let value = serde_json::to_value(request).expect("request serializes");

        assert_eq!(value["tools"][0]["type"], "web_search");
        assert_eq!(value["tools"][0]["filters"]["allowed_domains"][0], "x.ai");
        assert_eq!(value["tools"][0]["enable_image_understanding"], true);
        assert_eq!(value["include"][0], "no_inline_citations");
    }

    #[test]
    fn responses_web_search_rejects_ambiguous_domain_filters() {
        let error = responses_request_from_value(
            json!({
                "input": "hello",
                "web_search": {
                    "allowed_domains": ["x.ai"],
                    "excluded_domains": ["example.com"]
                }
            }),
            DEFAULT_MODEL,
        )
        .expect_err("ambiguous filters should be rejected");

        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn responses_requires_web_search_tool() {
        let error =
            responses_request_from_value(json!({"input": "hello", "tools": []}), DEFAULT_MODEL)
                .expect_err("plain responses should be rejected for this operation");

        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn citation_summary_extracts_annotations_and_hosts() {
        let raw = json!({
            "id": "resp_1",
            "model": "grok-4.3",
            "status": "completed",
            "output": [{
                "type": "message",
                "content": [{
                    "type": "output_text",
                    "text": "xAI ships Grok.[[1]](https://x.ai/news/grok-4-fast)",
                    "annotations": [{
                        "type": "url_citation",
                        "url": "https://x.ai/news/grok-4-fast",
                        "title": "1",
                        "start_index": 15,
                        "end_index": 55
                    }]
                }]
            }],
            "usage": {"input_tokens": 4, "output_tokens": 8}
        });

        let summary = summarize_responses_value(&raw);
        assert_eq!(summary.id.as_deref(), Some("resp_1"));
        assert_eq!(summary.citation_count, 1);
        assert_eq!(summary.citation_hosts, vec!["x.ai"]);
        assert_eq!(summary.citations[0].start_index, Some(15));
        assert!(summary.output_text.contains("[[1]]"));
    }

    #[test]
    fn multimodal_chat_message_still_uses_shared_oai_types() {
        let message = ChatMessage::user_text("inspect this");
        let request = ChatCompletionsRequest::new("grok-4.3", vec![message]);
        let value = serde_json::to_value(request).expect("request serializes");
        assert_eq!(value["messages"][0]["role"], "user");
    }
}
