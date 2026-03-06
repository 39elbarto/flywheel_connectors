//! Anthropic API types.

use serde::{Deserialize, Serialize};

/// Available Claude models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Model {
    /// Claude Opus 4.5 - Most capable model
    #[serde(rename = "claude-opus-4-5-20251101")]
    ClaudeOpus4_5,
    /// Claude Sonnet 4 - Balanced performance
    #[serde(rename = "claude-sonnet-4-20250514")]
    ClaudeSonnet4,
    /// Claude 3.5 Haiku - Fast and efficient
    #[serde(rename = "claude-3-5-haiku-20241022")]
    Claude3_5Haiku,
    /// Claude 3.5 Sonnet - Previous generation
    #[serde(rename = "claude-3-5-sonnet-20241022")]
    Claude3_5Sonnet,
}

impl Model {
    /// Get the model string for API requests.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ClaudeOpus4_5 => "claude-opus-4-5-20251101",
            Self::ClaudeSonnet4 => "claude-sonnet-4-20250514",
            Self::Claude3_5Haiku => "claude-3-5-haiku-20241022",
            Self::Claude3_5Sonnet => "claude-3-5-sonnet-20241022",
        }
    }

    /// Get input price per million tokens.
    #[must_use]
    pub const fn input_price_per_million(&self) -> f64 {
        match self {
            Self::ClaudeOpus4_5 => 15.0,
            Self::ClaudeSonnet4 => 3.0,
            Self::Claude3_5Haiku => 0.25,
            Self::Claude3_5Sonnet => 3.0,
        }
    }

    /// Get output price per million tokens.
    #[must_use]
    pub const fn output_price_per_million(&self) -> f64 {
        match self {
            Self::ClaudeOpus4_5 => 75.0,
            Self::ClaudeSonnet4 => 15.0,
            Self::Claude3_5Haiku => 1.25,
            Self::Claude3_5Sonnet => 15.0,
        }
    }
}

impl Default for Model {
    fn default() -> Self {
        Self::ClaudeSonnet4
    }
}

/// A message in a conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Role of the message sender.
    pub role: Role,
    /// Content of the message.
    pub content: MessageContent,
}

/// Role in a conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// User message
    User,
    /// Assistant message
    Assistant,
}

/// Content of a message (can be text or multimodal).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MessageContent {
    /// Simple text content
    Text(String),
    /// Complex content with multiple blocks
    Blocks(Vec<ContentBlock>),
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

/// A content block in a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlock {
    /// Text content
    Text { text: String },
    /// Image content
    Image { source: ImageSource },
    /// Tool use request from assistant
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
    /// Tool result from user
    ToolResult {
        tool_use_id: String,
        content: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        is_error: Option<bool>,
    },
}

/// Image source for vision requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ImageSource {
    /// Base64-encoded image data
    Base64 { media_type: String, data: String },
    /// URL to an image
    Url { url: String },
}

/// Request to the Messages API.
#[derive(Debug, Clone, Serialize)]
pub struct MessagesRequest {
    /// Model to use
    pub model: String,
    /// Messages in the conversation
    pub messages: Vec<Message>,
    /// Maximum tokens to generate
    pub max_tokens: u32,
    /// System prompt
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
    /// Temperature for sampling
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    /// Whether to stream the response
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    /// Tools available to the model
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<Tool>>,
    /// How to choose which tool to use
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<ToolChoice>,
    /// Stop sequences
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_sequences: Option<Vec<String>>,
}

/// A tool definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tool {
    /// Tool name
    pub name: String,
    /// Tool description
    pub description: String,
    /// Input schema (JSON Schema)
    pub input_schema: serde_json::Value,
}

/// How to choose which tool to use.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ToolChoice {
    /// Let the model decide
    Auto,
    /// Force the model to use a tool
    Any,
    /// Force the model to use a specific tool
    Tool { name: String },
}

/// Response from the Messages API.
#[derive(Debug, Clone, Deserialize)]
pub struct MessagesResponse {
    /// Response ID
    pub id: String,
    /// Type of response (always "message")
    #[serde(rename = "type")]
    pub response_type: String,
    /// Role (always "assistant")
    pub role: Role,
    /// Content blocks
    pub content: Vec<ResponseContentBlock>,
    /// Model used
    pub model: String,
    /// Stop reason
    pub stop_reason: Option<StopReason>,
    /// Stop sequence that was hit (if any)
    pub stop_sequence: Option<String>,
    /// Usage statistics
    pub usage: Usage,
}

/// Content block in a response.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResponseContentBlock {
    /// Text content
    Text { text: String },
    /// Tool use request
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
}

impl ResponseContentBlock {
    /// Extract text content if this is a text block.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text { text } => Some(text),
            Self::ToolUse { .. } => None,
        }
    }
}

/// Reason the model stopped generating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// Hit end of turn
    EndTurn,
    /// Hit max tokens
    MaxTokens,
    /// Hit a stop sequence
    StopSequence,
    /// Model wants to use a tool
    ToolUse,
}

/// Token usage statistics.
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct Usage {
    /// Input tokens used
    pub input_tokens: u32,
    /// Output tokens used
    pub output_tokens: u32,
    /// Cache creation tokens (if using caching)
    #[serde(default)]
    pub cache_creation_input_tokens: u32,
    /// Cache read tokens (if using caching)
    #[serde(default)]
    pub cache_read_input_tokens: u32,
}

impl Usage {
    /// Calculate total tokens used.
    #[must_use]
    pub const fn total_tokens(&self) -> u32 {
        self.input_tokens + self.output_tokens
    }

    /// Calculate cost for this usage with a given model.
    #[must_use]
    pub fn calculate_cost(&self, model: Model) -> f64 {
        let base_input_price = model.input_price_per_million();
        let output_price = model.output_price_per_million();

        // Anthropic pricing for caching:
        // Cache writes are 25% more expensive than base input
        // Cache reads are 90% cheaper than base input (0.1x multiplier)
        let creation_price = base_input_price * 1.25;
        let read_price = base_input_price * 0.10;

        // input_tokens includes creation and read tokens, so we must subtract them
        // to get the uncached input count
        let uncached_input = self
            .input_tokens
            .saturating_sub(self.cache_creation_input_tokens)
            .saturating_sub(self.cache_read_input_tokens);

        let input_cost = (f64::from(uncached_input) / 1_000_000.0) * base_input_price
            + (f64::from(self.cache_creation_input_tokens) / 1_000_000.0) * creation_price
            + (f64::from(self.cache_read_input_tokens) / 1_000_000.0) * read_price;

        let output_cost = (f64::from(self.output_tokens) / 1_000_000.0) * output_price;

        input_cost + output_cost
    }
}

/// Streaming event from the Messages API.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StreamEvent {
    /// Start of message
    MessageStart { message: MessageStartData },
    /// Start of content block
    ContentBlockStart {
        index: u32,
        content_block: ContentBlockStartData,
    },
    /// Delta for content block
    ContentBlockDelta { index: u32, delta: ContentDelta },
    /// End of content block
    ContentBlockStop { index: u32 },
    /// Delta for message (usage updates)
    MessageDelta {
        delta: MessageDeltaData,
        usage: Usage,
    },
    /// End of message
    MessageStop,
    /// Ping event (keepalive)
    Ping,
    /// Error event
    Error { error: ApiError },
}

/// Data at message start.
#[derive(Debug, Clone, Deserialize)]
pub struct MessageStartData {
    /// Message ID
    pub id: String,
    /// Role
    pub role: Role,
    /// Model
    pub model: String,
    /// Initial usage
    pub usage: Usage,
}

/// Data at content block start.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlockStartData {
    /// Text block starting
    Text { text: String },
    /// Tool use starting (input starts as empty object)
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
}

/// Delta for content.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentDelta {
    /// Text delta
    TextDelta { text: String },
    /// Tool input delta (JSON string)
    InputJsonDelta { partial_json: String },
}

/// Delta data for message.
#[derive(Debug, Clone, Deserialize)]
pub struct MessageDeltaData {
    /// Stop reason
    pub stop_reason: Option<StopReason>,
    /// Stop sequence
    pub stop_sequence: Option<String>,
}

/// API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiError {
    /// Error type
    #[serde(rename = "type")]
    pub error_type: String,
    /// Error message
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---- Model ----

    #[test]
    fn model_as_str() {
        assert_eq!(Model::ClaudeOpus4_5.as_str(), "claude-opus-4-5-20251101");
        assert_eq!(Model::ClaudeSonnet4.as_str(), "claude-sonnet-4-20250514");
        assert_eq!(Model::Claude3_5Haiku.as_str(), "claude-3-5-haiku-20241022");
        assert_eq!(
            Model::Claude3_5Sonnet.as_str(),
            "claude-3-5-sonnet-20241022"
        );
    }

    #[test]
    fn model_default_is_sonnet4() {
        assert_eq!(Model::default(), Model::ClaudeSonnet4);
    }

    #[test]
    fn model_serde_roundtrip() {
        let model = Model::ClaudeOpus4_5;
        let json = serde_json::to_string(&model).unwrap();
        assert_eq!(json, "\"claude-opus-4-5-20251101\"");
        let back: Model = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Model::ClaudeOpus4_5);
    }

    #[test]
    fn model_pricing() {
        assert!(
            Model::ClaudeOpus4_5.input_price_per_million()
                > Model::ClaudeSonnet4.input_price_per_million()
        );
        assert!(
            Model::Claude3_5Haiku.input_price_per_million()
                < Model::ClaudeSonnet4.input_price_per_million()
        );
        assert!(Model::ClaudeOpus4_5.output_price_per_million() > 0.0);
    }

    // ---- Role ----

    #[test]
    fn role_serde() {
        let json = serde_json::to_string(&Role::User).unwrap();
        assert_eq!(json, "\"user\"");
        let back: Role = serde_json::from_str("\"assistant\"").unwrap();
        assert_eq!(back, Role::Assistant);
    }

    // ---- StopReason ----

    #[test]
    fn stop_reason_serde() {
        let json = serde_json::to_string(&StopReason::EndTurn).unwrap();
        assert_eq!(json, "\"end_turn\"");
        let back: StopReason = serde_json::from_str("\"tool_use\"").unwrap();
        assert_eq!(back, StopReason::ToolUse);
    }

    // ---- MessageContent ----

    #[test]
    fn message_content_from_str() {
        let content: MessageContent = "hello".into();
        match content {
            MessageContent::Text(s) => assert_eq!(s, "hello"),
            MessageContent::Blocks(_) => panic!("expected Text variant"),
        }
    }

    #[test]
    fn message_content_from_string() {
        let content: MessageContent = String::from("world").into();
        match content {
            MessageContent::Text(s) => assert_eq!(s, "world"),
            MessageContent::Blocks(_) => panic!("expected Text variant"),
        }
    }

    // ---- ContentBlock ----

    #[test]
    fn content_block_text_serde() {
        let block = ContentBlock::Text {
            text: "hello".to_string(),
        };
        let json = serde_json::to_string(&block).unwrap();
        assert!(json.contains("\"type\":\"text\""));
        let back: ContentBlock = serde_json::from_str(&json).unwrap();
        match back {
            ContentBlock::Text { text } => assert_eq!(text, "hello"),
            _ => panic!("expected Text"),
        }
    }

    #[test]
    fn content_block_tool_use_serde() {
        let block = ContentBlock::ToolUse {
            id: "t1".to_string(),
            name: "calc".to_string(),
            input: json!({"x": 1}),
        };
        let json = serde_json::to_string(&block).unwrap();
        assert!(json.contains("\"type\":\"tool_use\""));
        let back: ContentBlock = serde_json::from_str(&json).unwrap();
        match back {
            ContentBlock::ToolUse { id, name, .. } => {
                assert_eq!(id, "t1");
                assert_eq!(name, "calc");
            }
            _ => panic!("expected ToolUse"),
        }
    }

    #[test]
    fn content_block_tool_result_serde() {
        let block = ContentBlock::ToolResult {
            tool_use_id: "t1".to_string(),
            content: "42".to_string(),
            is_error: Some(false),
        };
        let json = serde_json::to_string(&block).unwrap();
        let back: ContentBlock = serde_json::from_str(&json).unwrap();
        match back {
            ContentBlock::ToolResult {
                tool_use_id,
                content,
                is_error,
            } => {
                assert_eq!(tool_use_id, "t1");
                assert_eq!(content, "42");
                assert_eq!(is_error, Some(false));
            }
            _ => panic!("expected ToolResult"),
        }
    }

    // ---- ResponseContentBlock ----

    #[test]
    fn response_content_block_as_text() {
        let block = ResponseContentBlock::Text {
            text: "hello".to_string(),
        };
        assert_eq!(block.as_text(), Some("hello"));

        let tool_block = ResponseContentBlock::ToolUse {
            id: "t1".to_string(),
            name: "calc".to_string(),
            input: json!({}),
        };
        assert_eq!(tool_block.as_text(), None);
    }

    // ---- ToolChoice ----

    #[test]
    fn tool_choice_serde() {
        let auto = ToolChoice::Auto;
        let json = serde_json::to_string(&auto).unwrap();
        assert!(json.contains("\"type\":\"auto\""));

        let specific = ToolChoice::Tool {
            name: "calc".to_string(),
        };
        let json = serde_json::to_string(&specific).unwrap();
        assert!(json.contains("\"calc\""));
    }

    // ---- Usage ----

    #[test]
    fn usage_total_tokens() {
        let usage = Usage {
            input_tokens: 100,
            output_tokens: 50,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
        };
        assert_eq!(usage.total_tokens(), 150);
    }

    #[test]
    fn usage_calculate_cost_no_cache() {
        let usage = Usage {
            input_tokens: 1_000_000,
            output_tokens: 1_000_000,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
        };
        let cost = usage.calculate_cost(Model::ClaudeSonnet4);
        // input: 1M * $3/M = $3, output: 1M * $15/M = $15
        assert!((cost - 18.0).abs() < 0.01);
    }

    #[test]
    fn usage_calculate_cost_with_cache() {
        let usage = Usage {
            input_tokens: 1000,
            output_tokens: 500,
            cache_creation_input_tokens: 200,
            cache_read_input_tokens: 300,
        };
        let cost = usage.calculate_cost(Model::ClaudeSonnet4);
        assert!(cost > 0.0);
    }

    #[test]
    fn usage_deserialize_with_defaults() {
        let json = r#"{"input_tokens": 10, "output_tokens": 5}"#;
        let usage: Usage = serde_json::from_str(json).unwrap();
        assert_eq!(usage.input_tokens, 10);
        assert_eq!(usage.output_tokens, 5);
        assert_eq!(usage.cache_creation_input_tokens, 0);
        assert_eq!(usage.cache_read_input_tokens, 0);
    }

    // ---- ImageSource ----

    #[test]
    fn image_source_base64_serde() {
        let src = ImageSource::Base64 {
            media_type: "image/png".to_string(),
            data: "abc123".to_string(),
        };
        let json = serde_json::to_string(&src).unwrap();
        assert!(json.contains("\"type\":\"base64\""));
    }

    #[test]
    fn image_source_url_serde() {
        let src = ImageSource::Url {
            url: "https://example.com/img.png".to_string(),
        };
        let json = serde_json::to_string(&src).unwrap();
        assert!(json.contains("\"type\":\"url\""));
    }

    // ---- ApiError ----

    #[test]
    fn api_error_deserialize() {
        let json = r#"{"type": "invalid_request_error", "message": "bad input"}"#;
        let err: ApiError = serde_json::from_str(json).unwrap();
        assert_eq!(err.error_type, "invalid_request_error");
        assert_eq!(err.message, "bad input");
    }

    // ---- MessagesResponse ----

    #[test]
    fn messages_response_deserialize() {
        let json = json!({
            "id": "msg_01",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "Hello!"}],
            "model": "claude-sonnet-4-20250514",
            "stop_reason": "end_turn",
            "stop_sequence": null,
            "usage": {"input_tokens": 10, "output_tokens": 5}
        });
        let resp: MessagesResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.id, "msg_01");
        assert_eq!(resp.role, Role::Assistant);
        assert_eq!(resp.content.len(), 1);
        assert_eq!(resp.stop_reason, Some(StopReason::EndTurn));
        assert_eq!(resp.usage.total_tokens(), 15);
    }

    // ---- Tool ----

    #[test]
    fn tool_serde_roundtrip() {
        let tool = Tool {
            name: "calculator".to_string(),
            description: "Does math".to_string(),
            input_schema: json!({"type": "object", "properties": {"x": {"type": "number"}}}),
        };
        let json = serde_json::to_string(&tool).unwrap();
        let back: Tool = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "calculator");
    }

    // ---- Model additional tests ----

    #[test]
    fn model_copy_and_use() {
        let original = Model::ClaudeOpus4_5;
        let copied = original;
        let _ = original;
        assert_eq!(copied.as_str(), "claude-opus-4-5-20251101");
    }

    #[test]
    fn model_debug() {
        let dbg = format!("{:?}", Model::Claude3_5Sonnet);
        assert!(dbg.contains("Claude3_5Sonnet"));
    }

    #[test]
    fn model_serde_all_variants() {
        for model in [
            Model::ClaudeOpus4_5,
            Model::ClaudeSonnet4,
            Model::Claude3_5Haiku,
            Model::Claude3_5Sonnet,
        ] {
            let json = serde_json::to_string(&model).unwrap();
            let back: Model = serde_json::from_str(&json).unwrap();
            assert_eq!(back, model);
        }
    }

    #[test]
    fn model_3_5_sonnet_pricing() {
        assert_eq!(Model::Claude3_5Sonnet.input_price_per_million(), 3.0);
        assert_eq!(Model::Claude3_5Sonnet.output_price_per_million(), 15.0);
    }

    // ---- Role additional tests ----

    #[test]
    fn role_copy_and_use() {
        let original = Role::User;
        let copied = original;
        let _ = original;
        assert_eq!(copied, Role::User);
    }

    #[test]
    fn role_debug() {
        assert!(format!("{:?}", Role::User).contains("User"));
        assert!(format!("{:?}", Role::Assistant).contains("Assistant"));
    }

    #[test]
    fn role_eq() {
        assert_eq!(Role::User, Role::User);
        assert_eq!(Role::Assistant, Role::Assistant);
        assert_ne!(Role::User, Role::Assistant);
    }

    // ---- StopReason additional tests ----

    #[test]
    fn stop_reason_all_variants_serde() {
        for (variant, expected) in [
            (StopReason::EndTurn, "\"end_turn\""),
            (StopReason::MaxTokens, "\"max_tokens\""),
            (StopReason::StopSequence, "\"stop_sequence\""),
            (StopReason::ToolUse, "\"tool_use\""),
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            assert_eq!(json, expected);
            let back: StopReason = serde_json::from_str(&json).unwrap();
            assert_eq!(back, variant);
        }
    }

    #[test]
    fn stop_reason_copy_and_use() {
        let original = StopReason::MaxTokens;
        let copied = original;
        let _ = original;
        assert_eq!(copied, StopReason::MaxTokens);
    }

    #[test]
    fn stop_reason_debug() {
        let dbg = format!("{:?}", StopReason::StopSequence);
        assert!(dbg.contains("StopSequence"));
    }

    // ---- MessageContent ----

    #[test]
    fn message_content_blocks_variant() {
        let blocks = vec![
            ContentBlock::Text {
                text: "hello".into(),
            },
            ContentBlock::Text {
                text: "world".into(),
            },
        ];
        let content = MessageContent::Blocks(blocks);
        let json = serde_json::to_string(&content).unwrap();
        assert!(json.contains("hello"));
        assert!(json.contains("world"));
    }

    #[test]
    fn message_content_text_serde_roundtrip() {
        let content = MessageContent::Text("test message".into());
        let json = serde_json::to_string(&content).unwrap();
        let back: MessageContent = serde_json::from_str(&json).unwrap();
        match back {
            MessageContent::Text(s) => assert_eq!(s, "test message"),
            MessageContent::Blocks(_) => panic!("expected Text"),
        }
    }

    #[test]
    fn message_content_clone_and_drop() {
        let original = MessageContent::Text("clone_test".into());
        let cloned = original.clone();
        drop(original);
        match cloned {
            MessageContent::Text(s) => assert_eq!(s, "clone_test"),
            MessageContent::Blocks(_) => panic!("expected Text"),
        }
    }

    // ---- ContentBlock additional ----

    #[test]
    fn content_block_image_base64_serde() {
        let block = ContentBlock::Image {
            source: ImageSource::Base64 {
                media_type: "image/png".into(),
                data: "abc123".into(),
            },
        };
        let json = serde_json::to_string(&block).unwrap();
        assert!(json.contains("\"type\":\"image\""));
        let back: ContentBlock = serde_json::from_str(&json).unwrap();
        match back {
            ContentBlock::Image { source } => match source {
                ImageSource::Base64 { media_type, data } => {
                    assert_eq!(media_type, "image/png");
                    assert_eq!(data, "abc123");
                }
                ImageSource::Url { .. } => panic!("expected Base64"),
            },
            other => panic!("expected Image, got {other:?}"),
        }
    }

    #[test]
    fn content_block_tool_result_no_error() {
        let block = ContentBlock::ToolResult {
            tool_use_id: "t1".into(),
            content: "result".into(),
            is_error: None,
        };
        let json = serde_json::to_string(&block).unwrap();
        assert!(!json.contains("is_error"));
    }

    #[test]
    fn content_block_clone_and_drop() {
        let original = ContentBlock::Text {
            text: "clone_me".into(),
        };
        let cloned = original.clone();
        drop(original);
        match cloned {
            ContentBlock::Text { text } => assert_eq!(text, "clone_me"),
            _ => panic!("expected Text"),
        }
    }

    // ---- Tool additional tests ----

    #[test]
    fn tool_clone_and_drop() {
        let original = Tool {
            name: "tool_a".into(),
            description: "desc".into(),
            input_schema: json!({}),
        };
        let cloned = original.clone();
        drop(original);
        assert_eq!(cloned.name, "tool_a");
        assert_eq!(cloned.description, "desc");
    }

    #[test]
    fn tool_debug() {
        let tool = Tool {
            name: "test_tool".into(),
            description: "desc".into(),
            input_schema: json!({}),
        };
        let dbg = format!("{tool:?}");
        assert!(dbg.contains("Tool"));
        assert!(dbg.contains("test_tool"));
    }

    // ---- ToolChoice additional tests ----

    #[test]
    fn tool_choice_any_serde() {
        let any = ToolChoice::Any;
        let json = serde_json::to_string(&any).unwrap();
        assert!(json.contains("\"type\":\"any\""));
        let back: ToolChoice = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, ToolChoice::Any));
    }

    #[test]
    fn tool_choice_tool_roundtrip() {
        let tc = ToolChoice::Tool {
            name: "my_tool".into(),
        };
        let json = serde_json::to_string(&tc).unwrap();
        let back: ToolChoice = serde_json::from_str(&json).unwrap();
        match back {
            ToolChoice::Tool { name } => assert_eq!(name, "my_tool"),
            _ => panic!("expected Tool variant"),
        }
    }

    #[test]
    fn tool_choice_clone_and_drop() {
        let original = ToolChoice::Auto;
        let cloned = original.clone();
        drop(original);
        assert!(matches!(cloned, ToolChoice::Auto));
    }

    // ---- Usage additional tests ----

    #[test]
    fn usage_total_tokens_large() {
        let usage = Usage {
            input_tokens: 100_000,
            output_tokens: 50_000,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
        };
        assert_eq!(usage.total_tokens(), 150_000);
    }

    #[test]
    fn usage_clone_and_drop() {
        let original = Usage {
            input_tokens: 10,
            output_tokens: 5,
            cache_creation_input_tokens: 2,
            cache_read_input_tokens: 3,
        };
        let cloned = original;
        assert_eq!(cloned.input_tokens, 10);
        assert_eq!(cloned.cache_creation_input_tokens, 2);
        assert_eq!(cloned.cache_read_input_tokens, 3);
    }

    #[test]
    fn usage_calculate_cost_opus() {
        let usage = Usage {
            input_tokens: 1_000_000,
            output_tokens: 1_000_000,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
        };
        let cost = usage.calculate_cost(Model::ClaudeOpus4_5);
        // 1M * $15/M + 1M * $75/M = $90
        assert!((cost - 90.0).abs() < 0.01);
    }

    #[test]
    fn usage_calculate_cost_haiku() {
        let usage = Usage {
            input_tokens: 1_000_000,
            output_tokens: 1_000_000,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
        };
        let cost = usage.calculate_cost(Model::Claude3_5Haiku);
        // 1M * $0.25/M + 1M * $1.25/M = $1.50
        assert!((cost - 1.50).abs() < 0.01);
    }

    // ---- MessagesRequest ----

    #[test]
    fn messages_request_serialize_skip_none() {
        let req = MessagesRequest {
            model: "claude-sonnet-4-20250514".into(),
            messages: vec![],
            max_tokens: 100,
            system: None,
            temperature: None,
            stream: None,
            tools: None,
            tool_choice: None,
            stop_sequences: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("system"));
        assert!(!json.contains("temperature"));
        assert!(!json.contains("stream"));
        assert!(!json.contains("tools"));
        assert!(!json.contains("tool_choice"));
        assert!(!json.contains("stop_sequences"));
    }

    #[test]
    fn messages_request_serialize_with_all_fields() {
        let req = MessagesRequest {
            model: "claude-sonnet-4-20250514".into(),
            messages: vec![Message {
                role: Role::User,
                content: "hi".into(),
            }],
            max_tokens: 1024,
            system: Some("system prompt".into()),
            temperature: Some(0.7),
            stream: Some(true),
            tools: Some(vec![Tool {
                name: "calc".into(),
                description: "Calculator".into(),
                input_schema: json!({}),
            }]),
            tool_choice: Some(ToolChoice::Auto),
            stop_sequences: Some(vec!["STOP".into()]),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("system prompt"));
        assert!(json.contains("0.7"));
        assert!(json.contains("calc"));
        assert!(json.contains("STOP"));
    }

    // ---- Message ----

    #[test]
    fn message_clone_and_drop() {
        let original = Message {
            role: Role::User,
            content: "test".into(),
        };
        let cloned = original.clone();
        drop(original);
        assert_eq!(cloned.role, Role::User);
    }

    #[test]
    fn message_debug() {
        let msg = Message {
            role: Role::Assistant,
            content: "response".into(),
        };
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("Message"));
        assert!(dbg.contains("Assistant"));
    }

    // ---- ResponseContentBlock ----

    #[test]
    fn response_content_block_tool_use_as_text_is_none() {
        let block = ResponseContentBlock::ToolUse {
            id: "t1".into(),
            name: "calc".into(),
            input: json!({"x": 42}),
        };
        assert!(block.as_text().is_none());
    }

    #[test]
    fn response_content_block_clone_and_drop() {
        let original = ResponseContentBlock::Text {
            text: "hello".into(),
        };
        let cloned = original.clone();
        drop(original);
        assert_eq!(cloned.as_text(), Some("hello"));
    }

    // ---- ApiError ----

    #[test]
    fn api_error_clone_and_drop() {
        let original = ApiError {
            error_type: "test_error".into(),
            message: "something".into(),
        };
        let cloned = original.clone();
        drop(original);
        assert_eq!(cloned.error_type, "test_error");
        assert_eq!(cloned.message, "something");
    }

    #[test]
    fn api_error_debug() {
        let err = ApiError {
            error_type: "debug_test".into(),
            message: "msg".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("ApiError"));
        assert!(dbg.contains("debug_test"));
    }

    // ---- StreamEvent ----

    #[test]
    fn stream_event_ping_serde() {
        let json = r#"{"type":"ping"}"#;
        let event: StreamEvent = serde_json::from_str(json).unwrap();
        assert!(matches!(event, StreamEvent::Ping));
    }

    #[test]
    fn stream_event_message_stop_serde() {
        let json = r#"{"type":"message_stop"}"#;
        let event: StreamEvent = serde_json::from_str(json).unwrap();
        assert!(matches!(event, StreamEvent::MessageStop));
    }

    #[test]
    fn stream_event_content_block_stop_serde() {
        let json = r#"{"type":"content_block_stop","index":0}"#;
        let event: StreamEvent = serde_json::from_str(json).unwrap();
        match event {
            StreamEvent::ContentBlockStop { index } => assert_eq!(index, 0),
            _ => panic!("expected ContentBlockStop"),
        }
    }

    #[test]
    fn stream_event_error_serde() {
        let json = r#"{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}"#;
        let event: StreamEvent = serde_json::from_str(json).unwrap();
        match event {
            StreamEvent::Error { error } => {
                assert_eq!(error.error_type, "overloaded_error");
                assert_eq!(error.message, "Overloaded");
            }
            _ => panic!("expected Error"),
        }
    }

    #[test]
    fn stream_event_clone_and_drop() {
        let original = StreamEvent::Ping;
        let cloned = original.clone();
        drop(original);
        assert!(matches!(cloned, StreamEvent::Ping));
    }

    // ---- ContentDelta ----

    #[test]
    fn content_delta_text_serde() {
        let json = r#"{"type":"text_delta","text":"hello"}"#;
        let delta: ContentDelta = serde_json::from_str(json).unwrap();
        match delta {
            ContentDelta::TextDelta { text } => assert_eq!(text, "hello"),
            ContentDelta::InputJsonDelta { .. } => panic!("expected TextDelta"),
        }
    }

    #[test]
    fn content_delta_input_json_serde() {
        let json = r#"{"type":"input_json_delta","partial_json":"{\"x\":"}"#;
        let delta: ContentDelta = serde_json::from_str(json).unwrap();
        match delta {
            ContentDelta::InputJsonDelta { partial_json } => {
                assert!(partial_json.contains("\"x\":"));
            }
            ContentDelta::TextDelta { .. } => panic!("expected InputJsonDelta"),
        }
    }

    // ---- ContentBlockStartData ----

    #[test]
    fn content_block_start_text_serde() {
        let json = r#"{"type":"text","text":""}"#;
        let data: ContentBlockStartData = serde_json::from_str(json).unwrap();
        match data {
            ContentBlockStartData::Text { text } => assert!(text.is_empty()),
            ContentBlockStartData::ToolUse { .. } => panic!("expected Text"),
        }
    }

    #[test]
    fn content_block_start_tool_use_serde() {
        let json = r#"{"type":"tool_use","id":"t1","name":"calc","input":{}}"#;
        let data: ContentBlockStartData = serde_json::from_str(json).unwrap();
        match data {
            ContentBlockStartData::ToolUse { id, name, .. } => {
                assert_eq!(id, "t1");
                assert_eq!(name, "calc");
            }
            ContentBlockStartData::Text { .. } => panic!("expected ToolUse"),
        }
    }

    // ---- MessageDeltaData ----

    #[test]
    fn message_delta_data_serde() {
        let json = r#"{"stop_reason":"end_turn","stop_sequence":null}"#;
        let data: MessageDeltaData = serde_json::from_str(json).unwrap();
        assert_eq!(data.stop_reason, Some(StopReason::EndTurn));
        assert!(data.stop_sequence.is_none());
    }

    #[test]
    fn message_delta_data_with_stop_sequence() {
        let json = r#"{"stop_reason":"stop_sequence","stop_sequence":"STOP"}"#;
        let data: MessageDeltaData = serde_json::from_str(json).unwrap();
        assert_eq!(data.stop_reason, Some(StopReason::StopSequence));
        assert_eq!(data.stop_sequence, Some("STOP".into()));
    }

    // ---- ImageSource additional ----

    #[test]
    fn image_source_clone_and_drop() {
        let original = ImageSource::Url {
            url: "https://example.com/img.png".into(),
        };
        let cloned = original.clone();
        drop(original);
        match cloned {
            ImageSource::Url { url } => assert_eq!(url, "https://example.com/img.png"),
            ImageSource::Base64 { .. } => panic!("expected Url"),
        }
    }

    // ---- MessagesResponse with tool_use ----

    #[test]
    fn messages_response_with_tool_use() {
        let json = json!({
            "id": "msg_02",
            "type": "message",
            "role": "assistant",
            "content": [
                {"type": "text", "text": "Let me calculate that."},
                {"type": "tool_use", "id": "t1", "name": "calc", "input": {"x": 42}}
            ],
            "model": "claude-sonnet-4-20250514",
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 20, "output_tokens": 15}
        });
        let resp: MessagesResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.content.len(), 2);
        assert_eq!(resp.content[0].as_text(), Some("Let me calculate that."));
        assert_eq!(resp.content[1].as_text(), None);
        assert_eq!(resp.stop_reason, Some(StopReason::ToolUse));
    }

    #[test]
    fn messages_response_clone_and_drop() {
        let json = json!({
            "id": "msg_03",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "Hi!"}],
            "model": "claude-sonnet-4-20250514",
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 5, "output_tokens": 2}
        });
        let original: MessagesResponse = serde_json::from_value(json).unwrap();
        let cloned = original.clone();
        drop(original);
        assert_eq!(cloned.id, "msg_03");
    }

    // ---- MessageStartData ----

    #[test]
    fn message_start_data_serde() {
        let json = json!({
            "id": "msg_start",
            "role": "assistant",
            "model": "claude-sonnet-4-20250514",
            "usage": {"input_tokens": 1, "output_tokens": 0}
        });
        let data: MessageStartData = serde_json::from_value(json).unwrap();
        assert_eq!(data.id, "msg_start");
        assert_eq!(data.role, Role::Assistant);
        assert_eq!(data.usage.input_tokens, 1);
    }
}
