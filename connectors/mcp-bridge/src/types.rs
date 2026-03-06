//! MCP protocol types for the bridge connector.

use serde::{Deserialize, Serialize};

/// An MCP tool definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpTool {
    /// The name of the tool.
    pub name: String,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// JSON Schema for the tool's input.
    #[serde(rename = "inputSchema", skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<serde_json::Value>,
}

/// An MCP resource definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpResource {
    /// The URI of the resource.
    pub uri: String,
    /// Human-readable name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// MIME type hint.
    #[serde(rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// Content returned by a resource read or tool call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceContent {
    /// The URI of the content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    /// MIME type.
    #[serde(rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Text content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Base64-encoded blob content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob: Option<String>,
}

/// Content item from a tool call result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolContent {
    /// Content type: "text", "image", or "resource".
    #[serde(rename = "type")]
    pub content_type: String,
    /// Text content (for type="text").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Extra fields.
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// An MCP prompt definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpPrompt {
    /// The name of the prompt.
    pub name: String,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Arguments the prompt accepts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Vec<PromptArgument>>,
}

/// An argument definition for an MCP prompt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptArgument {
    /// Argument name.
    pub name: String,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Whether the argument is required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

/// JSON-RPC 2.0 request envelope.
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: &'static str,
    pub id: u64,
    pub method: String,
    pub params: serde_json::Value,
}

/// JSON-RPC 2.0 response envelope.
#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcResponse {
    #[allow(dead_code)]
    pub jsonrpc: Option<String>,
    #[allow(dead_code)]
    pub id: Option<serde_json::Value>,
    pub result: Option<serde_json::Value>,
    pub error: Option<JsonRpcError>,
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// MCP API error response body (HTTP-level error).
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    pub message: Option<String>,
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn mcp_tool_roundtrip() {
        let t: McpTool = serde_json::from_value(json!({
            "name": "read_file",
            "description": "Read a file from disk",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"}
                },
                "required": ["path"]
            }
        }))
        .unwrap();
        assert_eq!(t.name, "read_file");
        assert_eq!(t.description, Some("Read a file from disk".into()));
        assert!(t.input_schema.is_some());
        let re = serde_json::to_value(&t).unwrap();
        assert_eq!(re["name"], "read_file");
    }

    #[test]
    fn mcp_tool_minimal() {
        let t: McpTool = serde_json::from_value(json!({"name": "ping"})).unwrap();
        assert_eq!(t.name, "ping");
        assert!(t.description.is_none());
        assert!(t.input_schema.is_none());
    }

    #[test]
    fn mcp_resource_roundtrip() {
        let r: McpResource = serde_json::from_value(json!({
            "uri": "file:///tmp/data.txt",
            "name": "data.txt",
            "description": "Test data file",
            "mimeType": "text/plain"
        }))
        .unwrap();
        assert_eq!(r.uri, "file:///tmp/data.txt");
        assert_eq!(r.name, Some("data.txt".into()));
        assert_eq!(r.mime_type, Some("text/plain".into()));
        let re = serde_json::to_value(&r).unwrap();
        assert_eq!(re["uri"], "file:///tmp/data.txt");
    }

    #[test]
    fn mcp_resource_minimal() {
        let r: McpResource = serde_json::from_value(json!({"uri": "res://x"})).unwrap();
        assert_eq!(r.uri, "res://x");
        assert!(r.name.is_none());
        assert!(r.description.is_none());
        assert!(r.mime_type.is_none());
    }

    #[test]
    fn resource_content_roundtrip() {
        let c: ResourceContent = serde_json::from_value(json!({
            "uri": "file:///tmp/data.txt",
            "mimeType": "text/plain",
            "text": "Hello, world!"
        }))
        .unwrap();
        assert_eq!(c.uri, Some("file:///tmp/data.txt".into()));
        assert_eq!(c.text, Some("Hello, world!".into()));
        assert!(c.blob.is_none());
    }

    #[test]
    fn resource_content_blob() {
        let c: ResourceContent = serde_json::from_value(json!({
            "mimeType": "image/png",
            "blob": "iVBORw0KGgo="
        }))
        .unwrap();
        assert_eq!(c.blob, Some("iVBORw0KGgo=".into()));
        assert!(c.text.is_none());
    }

    #[test]
    fn resource_content_empty() {
        let c: ResourceContent = serde_json::from_value(json!({})).unwrap();
        assert!(c.uri.is_none());
        assert!(c.text.is_none());
        assert!(c.blob.is_none());
    }

    #[test]
    fn tool_content_roundtrip() {
        let c: ToolContent = serde_json::from_value(json!({
            "type": "text",
            "text": "result data"
        }))
        .unwrap();
        assert_eq!(c.content_type, "text");
        assert_eq!(c.text, Some("result data".into()));
    }

    #[test]
    fn tool_content_image() {
        let c: ToolContent = serde_json::from_value(json!({
            "type": "image",
            "data": "base64data",
            "mimeType": "image/png"
        }))
        .unwrap();
        assert_eq!(c.content_type, "image");
        assert!(c.text.is_none());
    }

    #[test]
    fn mcp_prompt_roundtrip() {
        let p: McpPrompt = serde_json::from_value(json!({
            "name": "summarize",
            "description": "Summarize text",
            "arguments": [
                {"name": "text", "description": "Text to summarize", "required": true}
            ]
        }))
        .unwrap();
        assert_eq!(p.name, "summarize");
        assert_eq!(p.description, Some("Summarize text".into()));
        let args = p.arguments.unwrap();
        assert_eq!(args.len(), 1);
        assert_eq!(args[0].name, "text");
        assert_eq!(args[0].required, Some(true));
    }

    #[test]
    fn mcp_prompt_minimal() {
        let p: McpPrompt = serde_json::from_value(json!({"name": "greeting"})).unwrap();
        assert_eq!(p.name, "greeting");
        assert!(p.description.is_none());
        assert!(p.arguments.is_none());
    }

    #[test]
    fn prompt_argument_roundtrip() {
        let a: PromptArgument = serde_json::from_value(json!({
            "name": "language",
            "description": "Target language",
            "required": false
        }))
        .unwrap();
        assert_eq!(a.name, "language");
        assert_eq!(a.required, Some(false));
    }

    #[test]
    fn prompt_argument_minimal() {
        let a: PromptArgument = serde_json::from_value(json!({"name": "input"})).unwrap();
        assert_eq!(a.name, "input");
        assert!(a.description.is_none());
        assert!(a.required.is_none());
    }

    #[test]
    fn jsonrpc_request_serializes() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method: "tools/list".into(),
            params: json!({}),
        };
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["id"], 1);
        assert_eq!(v["method"], "tools/list");
    }

    #[test]
    fn jsonrpc_response_with_result() {
        let r: JsonRpcResponse = serde_json::from_value(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": []}
        }))
        .unwrap();
        assert!(r.result.is_some());
        assert!(r.error.is_none());
    }

    #[test]
    fn jsonrpc_response_with_error() {
        let r: JsonRpcResponse = serde_json::from_value(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32601,
                "message": "Method not found"
            }
        }))
        .unwrap();
        assert!(r.result.is_none());
        let err = r.error.unwrap();
        assert_eq!(err.code, -32601);
        assert_eq!(err.message, "Method not found");
    }

    #[test]
    fn jsonrpc_error_with_data() {
        let e: JsonRpcError = serde_json::from_value(json!({
            "code": -32600,
            "message": "Invalid Request",
            "data": {"detail": "missing method"}
        }))
        .unwrap();
        assert_eq!(e.code, -32600);
        assert!(e.data.is_some());
    }

    #[test]
    fn api_error_response_with_message() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "message": "Not found",
            "error": "404"
        }))
        .unwrap();
        assert_eq!(e.message, Some("Not found".into()));
        assert_eq!(e.error, Some("404".into()));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.message.is_none());
        assert!(e.error.is_none());
    }

    #[test]
    fn mcp_tool_serialize_skips_none() {
        let t = McpTool {
            name: "ping".into(),
            description: None,
            input_schema: None,
        };
        let v = serde_json::to_value(&t).unwrap();
        assert!(!v.as_object().unwrap().contains_key("description"));
        assert!(!v.as_object().unwrap().contains_key("inputSchema"));
    }

    #[test]
    fn mcp_resource_serialize_skips_none() {
        let r = McpResource {
            uri: "res://x".into(),
            name: None,
            description: None,
            mime_type: None,
        };
        let v = serde_json::to_value(&r).unwrap();
        assert!(!v.as_object().unwrap().contains_key("name"));
        assert!(!v.as_object().unwrap().contains_key("mimeType"));
    }

    #[test]
    fn mcp_prompt_with_empty_arguments() {
        let p: McpPrompt = serde_json::from_value(json!({
            "name": "test",
            "arguments": []
        }))
        .unwrap();
        assert!(p.arguments.unwrap().is_empty());
    }

    #[test]
    fn mcp_prompt_with_multiple_arguments() {
        let p: McpPrompt = serde_json::from_value(json!({
            "name": "translate",
            "arguments": [
                {"name": "text", "required": true},
                {"name": "target_language", "required": true},
                {"name": "tone", "required": false}
            ]
        }))
        .unwrap();
        assert_eq!(p.arguments.unwrap().len(), 3);
    }

    #[test]
    fn resource_content_serialize_skips_none() {
        let c = ResourceContent {
            uri: Some("res://x".into()),
            mime_type: None,
            text: Some("hello".into()),
            blob: None,
        };
        let v = serde_json::to_value(&c).unwrap();
        assert!(!v.as_object().unwrap().contains_key("mimeType"));
        assert!(!v.as_object().unwrap().contains_key("blob"));
        assert_eq!(v["text"], "hello");
    }

    #[test]
    fn mcp_tool_clone() {
        let t = McpTool {
            name: "read_file".into(),
            description: Some("Read a file".into()),
            input_schema: Some(json!({"type": "object"})),
        };
        let cloned = McpTool::clone(&t);
        assert_eq!(cloned.name, "read_file");
        assert_eq!(cloned.description, Some("Read a file".into()));
    }

    #[test]
    fn mcp_tool_debug() {
        let t = McpTool {
            name: "ping".into(),
            description: None,
            input_schema: None,
        };
        let dbg = format!("{t:?}");
        assert!(dbg.contains("ping"));
    }

    #[test]
    fn mcp_resource_clone() {
        let r = McpResource {
            uri: "res://x".into(),
            name: Some("data".into()),
            description: None,
            mime_type: Some("text/plain".into()),
        };
        let cloned = McpResource::clone(&r);
        assert_eq!(cloned.uri, "res://x");
        assert_eq!(cloned.name, Some("data".into()));
    }

    #[test]
    fn mcp_resource_debug() {
        let r = McpResource {
            uri: "res://test".into(),
            name: None,
            description: None,
            mime_type: None,
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("res://test"));
    }

    #[test]
    fn resource_content_clone() {
        let c = ResourceContent {
            uri: Some("res://x".into()),
            mime_type: None,
            text: Some("data".into()),
            blob: None,
        };
        let cloned = ResourceContent::clone(&c);
        assert_eq!(cloned.text, Some("data".into()));
    }

    #[test]
    fn tool_content_clone() {
        let c = ToolContent {
            content_type: "text".into(),
            text: Some("result".into()),
            extra: json!({}),
        };
        let cloned = ToolContent::clone(&c);
        assert_eq!(cloned.content_type, "text");
        assert_eq!(cloned.text, Some("result".into()));
    }

    #[test]
    fn mcp_prompt_clone() {
        let p = McpPrompt {
            name: "summarize".into(),
            description: Some("Summarize text".into()),
            arguments: Some(vec![PromptArgument {
                name: "text".into(),
                description: None,
                required: Some(true),
            }]),
        };
        let cloned = McpPrompt::clone(&p);
        assert_eq!(cloned.name, "summarize");
        assert_eq!(cloned.arguments.unwrap().len(), 1);
    }

    #[test]
    fn prompt_argument_clone() {
        let a = PromptArgument {
            name: "lang".into(),
            description: Some("Language".into()),
            required: Some(false),
        };
        let cloned = PromptArgument::clone(&a);
        assert_eq!(cloned.name, "lang");
        assert_eq!(cloned.required, Some(false));
    }

    #[test]
    fn jsonrpc_request_clone() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0",
            id: 42,
            method: "test".into(),
            params: json!({}),
        };
        let cloned = JsonRpcRequest::clone(&req);
        assert_eq!(cloned.id, 42);
        assert_eq!(cloned.method, "test");
    }

    #[test]
    fn jsonrpc_response_clone() {
        let r: JsonRpcResponse = serde_json::from_value(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"ok": true}
        }))
        .unwrap();
        let cloned = JsonRpcResponse::clone(&r);
        assert!(cloned.result.is_some());
        assert!(cloned.error.is_none());
    }

    #[test]
    fn jsonrpc_error_clone() {
        let e: JsonRpcError = serde_json::from_value(json!({
            "code": -32600,
            "message": "Invalid"
        }))
        .unwrap();
        let cloned = JsonRpcError::clone(&e);
        assert_eq!(cloned.code, -32600);
    }

    #[test]
    fn api_error_response_clone() {
        let e = ApiErrorResponse {
            message: Some("err".into()),
            error: Some("404".into()),
        };
        let cloned = ApiErrorResponse::clone(&e);
        assert_eq!(cloned.message, Some("err".into()));
        assert_eq!(cloned.error, Some("404".into()));
    }

    #[test]
    fn mcp_prompt_serialize_skips_none() {
        let p = McpPrompt {
            name: "test".into(),
            description: None,
            arguments: None,
        };
        let v = serde_json::to_value(&p).unwrap();
        assert!(!v.as_object().unwrap().contains_key("description"));
        assert!(!v.as_object().unwrap().contains_key("arguments"));
    }

    #[test]
    fn prompt_argument_serialize_skips_none() {
        let a = PromptArgument {
            name: "input".into(),
            description: None,
            required: None,
        };
        let v = serde_json::to_value(&a).unwrap();
        assert!(!v.as_object().unwrap().contains_key("description"));
        assert!(!v.as_object().unwrap().contains_key("required"));
    }

    #[test]
    fn jsonrpc_request_with_params() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0",
            id: 5,
            method: "tools/call".into(),
            params: json!({"name": "test", "arguments": {}}),
        };
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["params"]["name"], "test");
    }

    #[test]
    fn jsonrpc_response_null_result() {
        let r: JsonRpcResponse = serde_json::from_value(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": null
        }))
        .unwrap();
        // null result deserializes as None
        assert!(r.result.is_none());
    }

    #[test]
    fn tool_content_debug() {
        let c = ToolContent {
            content_type: "text".into(),
            text: Some("result".into()),
            extra: json!({}),
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("text"));
    }

    #[test]
    fn resource_content_debug() {
        let c = ResourceContent {
            uri: Some("res://x".into()),
            mime_type: None,
            text: None,
            blob: None,
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("res://x"));
    }
}
