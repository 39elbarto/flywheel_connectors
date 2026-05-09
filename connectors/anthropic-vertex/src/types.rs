use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::error::{VertexError, VertexResult};

pub const VERTEX_ANTHROPIC_VERSION: &str = "vertex-2023-10-16";
pub const DEFAULT_LOCATION: &str = "global";
pub const CLOUD_PLATFORM_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct VertexModelCatalogEntry {
    pub id: &'static str,
    pub display_name: &'static str,
    pub aliases: &'static [&'static str],
    pub endpoint_locations: &'static [&'static str],
    pub context_window_tokens: u32,
    pub supports_streaming: bool,
    pub supports_prompt_cache: bool,
    pub supports_thinking: bool,
}

const MODEL_CATALOG: &[VertexModelCatalogEntry] = &[
    VertexModelCatalogEntry {
        id: "claude-opus-4-7",
        display_name: "Claude Opus 4.7",
        aliases: &["opus-4.7", "opus-4-7", "claude-opus-4.7"],
        endpoint_locations: &["global", "us", "eu", "us-east5", "europe-west1"],
        context_window_tokens: 1_000_000,
        supports_streaming: true,
        supports_prompt_cache: true,
        supports_thinking: true,
    },
    VertexModelCatalogEntry {
        id: "claude-opus-4-6",
        display_name: "Claude Opus 4.6",
        aliases: &["opus-4.6", "opus-4-6", "claude-opus-4.6"],
        endpoint_locations: &["global", "us", "eu", "us-east5", "europe-west1"],
        context_window_tokens: 1_000_000,
        supports_streaming: true,
        supports_prompt_cache: true,
        supports_thinking: true,
    },
    VertexModelCatalogEntry {
        id: "claude-sonnet-4-6",
        display_name: "Claude Sonnet 4.6",
        aliases: &["sonnet-4.6", "sonnet-4-6", "claude-sonnet-4.6"],
        endpoint_locations: &["global", "us", "eu", "us-east5", "europe-west1"],
        context_window_tokens: 1_000_000,
        supports_streaming: true,
        supports_prompt_cache: true,
        supports_thinking: true,
    },
    VertexModelCatalogEntry {
        id: "claude-opus-4-5@20251101",
        display_name: "Claude Opus 4.5",
        aliases: &[
            "opus-4.5",
            "opus-4-5",
            "claude-opus-4.5",
            "claude-opus-4-5",
            "claude-opus-4-5-20251101",
        ],
        endpoint_locations: &["global", "us", "eu", "us-east5", "europe-west1"],
        context_window_tokens: 200_000,
        supports_streaming: true,
        supports_prompt_cache: true,
        supports_thinking: true,
    },
    VertexModelCatalogEntry {
        id: "claude-sonnet-4-5@20250929",
        display_name: "Claude Sonnet 4.5",
        aliases: &[
            "sonnet-4.5",
            "sonnet-4-5",
            "claude-sonnet-4.5",
            "claude-sonnet-4-5",
            "claude-sonnet-4-5-20250929",
        ],
        endpoint_locations: &["global", "us", "eu", "us-east5", "europe-west1"],
        context_window_tokens: 200_000,
        supports_streaming: true,
        supports_prompt_cache: true,
        supports_thinking: true,
    },
    VertexModelCatalogEntry {
        id: "claude-haiku-4-5@20251001",
        display_name: "Claude Haiku 4.5",
        aliases: &[
            "haiku-4.5",
            "haiku-4-5",
            "claude-haiku-4.5",
            "claude-haiku-4-5",
            "claude-haiku-4-5-20251001",
        ],
        endpoint_locations: &["global", "us", "eu", "us-east5", "europe-west1"],
        context_window_tokens: 200_000,
        supports_streaming: true,
        supports_prompt_cache: true,
        supports_thinking: false,
    },
    VertexModelCatalogEntry {
        id: "claude-sonnet-4@20250514",
        display_name: "Claude Sonnet 4",
        aliases: &["sonnet-4", "claude-sonnet-4", "claude-sonnet-4-20250514"],
        endpoint_locations: &["global", "us", "eu", "us-east5", "europe-west1"],
        context_window_tokens: 200_000,
        supports_streaming: true,
        supports_prompt_cache: true,
        supports_thinking: true,
    },
    VertexModelCatalogEntry {
        id: "claude-opus-4@20250514",
        display_name: "Claude Opus 4",
        aliases: &["opus-4", "claude-opus-4", "claude-opus-4-20250514"],
        endpoint_locations: &["global", "us", "eu", "us-east5", "europe-west1"],
        context_window_tokens: 200_000,
        supports_streaming: true,
        supports_prompt_cache: true,
        supports_thinking: true,
    },
    VertexModelCatalogEntry {
        id: "claude-3-7-sonnet@20250219",
        display_name: "Claude 3.7 Sonnet",
        aliases: &[
            "sonnet-3.7",
            "sonnet-3-7",
            "claude-3.7-sonnet",
            "claude-3-7-sonnet",
            "claude-3-7-sonnet-20250219",
        ],
        endpoint_locations: &["global", "us", "eu", "us-east5", "europe-west1"],
        context_window_tokens: 200_000,
        supports_streaming: true,
        supports_prompt_cache: true,
        supports_thinking: true,
    },
    VertexModelCatalogEntry {
        id: "claude-3-5-sonnet-v2@20241022",
        display_name: "Claude 3.5 Sonnet v2",
        aliases: &[
            "sonnet-3.5",
            "sonnet-3-5",
            "claude-3.5-sonnet",
            "claude-3-5-sonnet",
            "claude-3-5-sonnet-20241022",
        ],
        endpoint_locations: &["global", "us", "eu", "us-east5", "europe-west1"],
        context_window_tokens: 200_000,
        supports_streaming: true,
        supports_prompt_cache: true,
        supports_thinking: false,
    },
];

pub fn model_catalog() -> Vec<VertexModelCatalogEntry> {
    MODEL_CATALOG.to_vec()
}

pub fn normalize_model_id(input: &str) -> Option<&'static str> {
    let normalized = input.trim().to_ascii_lowercase().replace('_', "-");
    MODEL_CATALOG.iter().find_map(|entry| {
        if normalized == entry.id || entry.aliases.iter().any(|alias| normalized == *alias) {
            Some(entry.id)
        } else {
            None
        }
    })
}

pub fn catalog_entry(model_id: &str) -> Option<VertexModelCatalogEntry> {
    let normalized = normalize_model_id(model_id)?;
    MODEL_CATALOG
        .iter()
        .find(|entry| entry.id == normalized)
        .cloned()
}

pub fn validate_location(input: &str) -> VertexResult<String> {
    let location = input.trim();
    if location.is_empty() {
        return Err(VertexError::Config("location must not be empty".into()));
    }
    if !location
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(VertexError::Config(
            "location must contain only lowercase ASCII letters, digits, and '-'".into(),
        ));
    }
    if location.starts_with('-') || location.ends_with('-') || location.contains("..") {
        return Err(VertexError::Config(
            "location is not a valid Vertex location".into(),
        ));
    }
    Ok(location.to_string())
}

pub fn default_base_url_for_location(location: &str) -> String {
    match location {
        "global" => "https://aiplatform.googleapis.com".to_string(),
        "us" | "eu" => format!("https://aiplatform.{location}.rep.googleapis.com"),
        regional => format!("https://{regional}-aiplatform.googleapis.com"),
    }
}

pub fn validate_path_component(value: &str, field: &'static str) -> VertexResult<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(VertexError::InvalidInput(format!(
            "{field} must not be empty"
        )));
    }
    let lower = trimmed.to_ascii_lowercase();
    if trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains("..")
        || lower.contains("%2f")
        || lower.contains("%5c")
        || trimmed.contains('?')
        || trimmed.contains('#')
    {
        return Err(VertexError::InvalidInput(format!(
            "{field} contains URL path injection characters"
        )));
    }
    if !trimmed.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@')
    }) {
        return Err(VertexError::InvalidInput(format!(
            "{field} contains characters outside the Vertex path allow-list"
        )));
    }
    Ok(trimmed.to_string())
}

pub fn vertex_messages_path(project_id: &str, location: &str, model: &str, stream: bool) -> String {
    let suffix = if stream {
        "streamRawPredict"
    } else {
        "rawPredict"
    };
    format!(
        "/v1/projects/{project_id}/locations/{location}/publishers/anthropic/models/{model}:{suffix}"
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PreparedVertexRequest {
    pub model: String,
    pub body: Value,
    pub stream: bool,
}

pub fn prepare_vertex_request(
    input: &Value,
    force_stream: bool,
) -> VertexResult<PreparedVertexRequest> {
    let object = input.as_object().ok_or_else(|| {
        VertexError::InvalidInput("message input must be a JSON object".to_string())
    })?;

    let model = model_from_input(object)?;
    let model = normalize_model_id(&model)
        .ok_or_else(|| {
            VertexError::InvalidInput(format!("Unsupported Anthropic Vertex model: {model}"))
        })?
        .to_string();

    let mut body = if let Some(raw_body) = object.get("body") {
        raw_body.as_object().cloned().ok_or_else(|| {
            VertexError::InvalidInput("body must be a JSON object when provided".to_string())
        })?
    } else {
        object
            .iter()
            .filter(|(key, _)| !matches!(key.as_str(), "model" | "model_id"))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Map<String, Value>>()
    };

    body.remove("model");
    body.remove("model_id");
    validate_message_body(&body)?;

    match body.get("anthropic_version").and_then(Value::as_str) {
        Some(VERTEX_ANTHROPIC_VERSION) | None => {
            body.insert(
                "anthropic_version".to_string(),
                Value::String(VERTEX_ANTHROPIC_VERSION.to_string()),
            );
        }
        Some(other) => {
            return Err(VertexError::InvalidInput(format!(
                "anthropic_version must be {VERTEX_ANTHROPIC_VERSION} for Claude on Vertex, got {other}"
            )));
        }
    }

    body.insert("stream".to_string(), Value::Bool(force_stream));
    validate_vertex_payload_policy(&Value::Object(body.clone()))?;

    Ok(PreparedVertexRequest {
        model,
        body: Value::Object(body),
        stream: force_stream,
    })
}

fn model_from_input(object: &Map<String, Value>) -> VertexResult<String> {
    let raw = object
        .get("model")
        .or_else(|| object.get("model_id"))
        .or_else(|| {
            object
                .get("body")
                .and_then(Value::as_object)
                .and_then(|body| body.get("model"))
        })
        .or_else(|| {
            object
                .get("body")
                .and_then(Value::as_object)
                .and_then(|body| body.get("model_id"))
        })
        .and_then(Value::as_str)
        .ok_or_else(|| VertexError::InvalidInput("model or model_id is required".into()))?;
    Ok(raw.to_string())
}

fn validate_message_body(body: &Map<String, Value>) -> VertexResult<()> {
    if body
        .get("messages")
        .and_then(Value::as_array)
        .is_none_or(Vec::is_empty)
    {
        return Err(VertexError::InvalidInput(
            "messages must be a non-empty array".into(),
        ));
    }
    let max_tokens = body
        .get("max_tokens")
        .and_then(Value::as_u64)
        .ok_or_else(|| VertexError::InvalidInput("max_tokens must be a positive integer".into()))?;
    if max_tokens == 0 || max_tokens > u64::from(u32::MAX) {
        return Err(VertexError::InvalidInput(
            "max_tokens must fit in a positive u32".into(),
        ));
    }
    Ok(())
}

fn validate_vertex_payload_policy(value: &Value) -> VertexResult<()> {
    let Some(object) = value.as_object() else {
        return Ok(());
    };
    if object.contains_key("anthropic_beta") || object.contains_key("anthropic_betas") {
        return Err(VertexError::InvalidInput(
            "Claude on Vertex uses anthropic_version in the JSON body; Anthropic beta headers are not accepted by this connector".into(),
        ));
    }
    validate_cache_control_ttl(value)?;
    Ok(())
}

fn validate_cache_control_ttl(value: &Value) -> VertexResult<()> {
    match value {
        Value::Object(object) => {
            if let Some(cache_control) = object.get("cache_control").and_then(Value::as_object)
                && let Some(ttl) = cache_control.get("ttl").and_then(Value::as_str)
                && !matches!(ttl, "5m" | "1h")
            {
                return Err(VertexError::InvalidInput(
                    "cache_control.ttl must be either '5m' or '1h' for Claude on Vertex".into(),
                ));
            }
            for nested in object.values() {
                validate_cache_control_ttl(nested)?;
            }
        }
        Value::Array(values) => {
            for nested in values {
                validate_cache_control_ttl(nested)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VertexStreamEvent {
    pub event_type: Option<String>,
    pub payload_json: Option<Value>,
    pub payload_utf8: String,
    pub payload_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VertexStreamResponse {
    pub events: Vec<VertexStreamEvent>,
    pub event_count: usize,
    pub total_payload_bytes: usize,
}

pub fn parse_sse_events(input: &str) -> VertexStreamResponse {
    let mut events = Vec::new();
    for raw_event in input.split("\n\n") {
        let mut event_type = None;
        let mut data_lines = Vec::new();
        for line in raw_event.lines() {
            if let Some(rest) = line.strip_prefix("event:") {
                event_type = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("data:") {
                data_lines.push(rest.trim_start().to_string());
            }
        }
        if data_lines.is_empty() {
            continue;
        }
        let payload_utf8 = data_lines.join("\n");
        if payload_utf8 == "[DONE]" {
            continue;
        }
        let payload_bytes = payload_utf8.len();
        let payload_json = serde_json::from_str(&payload_utf8).ok();
        events.push(VertexStreamEvent {
            event_type,
            payload_json,
            payload_utf8,
            payload_bytes,
        });
    }
    let total_payload_bytes = events.iter().map(|event| event.payload_bytes).sum();
    let event_count = events.len();
    VertexStreamResponse {
        events,
        event_count,
        total_payload_bytes,
    }
}

pub fn auth_policy_report() -> Value {
    json!({
        "runtime_allowed": ["access_token", "credential_id", "oauth_refresh"],
        "provisioning_only": [
            "credentials_file",
            "default_credentials",
            "application_default_credentials",
            "metadata_server"
        ],
        "runtime_rationale": "ADC, metadata-server, and file discovery are host provisioning concerns under FCP secret-residency policy; runtime connectors accept ephemeral bearer material or credential_id handles only.",
        "required_scope": CLOUD_PLATFORM_SCOPE
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        VERTEX_ANTHROPIC_VERSION, default_base_url_for_location, normalize_model_id,
        parse_sse_events, prepare_vertex_request, validate_location,
    };

    #[test]
    fn normalizes_current_vertex_model_aliases() {
        assert_eq!(
            normalize_model_id("claude-sonnet-4-5-20250929"),
            Some("claude-sonnet-4-5@20250929")
        );
        assert_eq!(normalize_model_id("opus-4.7"), Some("claude-opus-4-7"));
        assert_eq!(normalize_model_id("unknown"), None);
    }

    #[test]
    fn endpoint_base_url_matches_vertex_location_shapes() {
        assert_eq!(
            default_base_url_for_location("global"),
            "https://aiplatform.googleapis.com"
        );
        assert_eq!(
            default_base_url_for_location("us"),
            "https://aiplatform.us.rep.googleapis.com"
        );
        assert_eq!(
            default_base_url_for_location("us-east5"),
            "https://us-east5-aiplatform.googleapis.com"
        );
    }

    #[test]
    fn location_validation_rejects_injection() {
        assert!(validate_location("us-east5").is_ok());
        assert!(validate_location("US-east5").is_err());
        assert!(validate_location("../us").is_err());
    }

    #[test]
    fn prepared_request_moves_model_to_url_and_sets_vertex_version() {
        let prepared = prepare_vertex_request(
            &json!({
                "model": "claude-sonnet-4-5-20250929",
                "messages": [{"role": "user", "content": "hi"}],
                "max_tokens": 8
            }),
            false,
        )
        .expect("valid request");
        assert_eq!(prepared.model, "claude-sonnet-4-5@20250929");
        assert_eq!(
            prepared.body["anthropic_version"].as_str(),
            Some(VERTEX_ANTHROPIC_VERSION)
        );
        assert!(prepared.body.get("model").is_none());
        assert_eq!(prepared.body["stream"].as_bool(), Some(false));
    }

    #[test]
    fn prepared_request_rejects_beta_header_shape() {
        let error = prepare_vertex_request(
            &json!({
                "model": "claude-sonnet-4-6",
                "messages": [{"role": "user", "content": "hi"}],
                "max_tokens": 8,
                "anthropic_beta": ["mcp-client-2025-04-04"]
            }),
            false,
        )
        .expect_err("beta headers are not allowed");
        assert!(error.to_string().contains("Anthropic beta headers"));
    }

    #[test]
    fn parses_sse_data_events() {
        let parsed = parse_sse_events(
            "event: message_start\ndata: {\"type\":\"message_start\"}\n\n\
             data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"hi\"}}\n\n\
             data: [DONE]\n\n",
        );
        assert_eq!(parsed.event_count, 2);
        assert_eq!(
            parsed.events[0].payload_json.as_ref().unwrap()["type"],
            "message_start"
        );
    }
}
