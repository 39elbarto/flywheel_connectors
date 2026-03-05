//! Figma API types.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Figma API response envelope
// ---------------------------------------------------------------------------

/// Standard Figma API error response body.
#[derive(Debug, Clone, Deserialize)]
pub struct FigmaErrorResponse {
    #[serde(default)]
    pub status: Option<u16>,
    #[serde(default, alias = "err")]
    pub message: Option<String>,
}

// ---------------------------------------------------------------------------
// Teams & Projects
// ---------------------------------------------------------------------------

/// Response from `GET /v1/teams/:team_id/projects`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamProjectsResponse {
    pub name: String,
    pub projects: Vec<Project>,
}

/// A Figma project within a team.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: u64,
    pub name: String,
}

/// Response from `GET /v1/projects/:project_id/files`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectFilesResponse {
    pub name: String,
    pub files: Vec<ProjectFile>,
}

/// A file within a Figma project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectFile {
    pub key: String,
    pub name: String,
    #[serde(default)]
    pub thumbnail_url: Option<String>,
    pub last_modified: String,
}

// ---------------------------------------------------------------------------
// Files & Nodes
// ---------------------------------------------------------------------------

/// Response from `GET /v1/files/:file_key`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileResponse {
    pub name: String,
    pub document: serde_json::Value,
    pub last_modified: String,
    pub version: String,
    #[serde(default)]
    pub components: Option<serde_json::Value>,
    #[serde(default)]
    pub styles: Option<serde_json::Value>,
}

/// Response from `GET /v1/files/:file_key/nodes`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileNodesResponse {
    pub nodes: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Components & Styles
// ---------------------------------------------------------------------------

/// Response from `GET /v1/files/:file_key/components`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentsResponse {
    pub meta: serde_json::Value,
}

/// Response from `GET /v1/files/:file_key/styles`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StylesResponse {
    pub meta: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Design Tokens
// ---------------------------------------------------------------------------

/// A normalized design token extracted from Figma styles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesignToken {
    /// Normalized token name (kebab-case, e.g. "color-primary-500").
    pub name: String,
    /// Original Figma style name before normalization.
    pub original_name: String,
    /// Token category: "color", "typography", "effect", "grid".
    pub category: String,
    /// The Figma style type (FILL, TEXT, EFFECT, GRID).
    pub style_type: String,
    /// The resolved token value.
    pub value: TokenValue,
    /// Figma node ID for this style (e.g. "1:2").
    #[serde(default)]
    pub node_id: Option<String>,
    /// Description from Figma style metadata.
    #[serde(default)]
    pub description: Option<String>,
}

/// Resolved value for a design token.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum TokenValue {
    /// RGBA color value.
    #[serde(rename = "color")]
    Color {
        r: f64,
        g: f64,
        b: f64,
        a: f64,
        /// Hex representation (e.g. "#ff5500ff").
        hex: String,
    },
    /// Typography token with font properties.
    #[serde(rename = "typography")]
    Typography {
        font_family: String,
        font_size: f64,
        font_weight: f64,
        line_height: Option<f64>,
        letter_spacing: Option<f64>,
    },
    /// Effect token (shadows, blurs).
    #[serde(rename = "effect")]
    Effect {
        effect_type: String,
        #[serde(default)]
        radius: Option<f64>,
        #[serde(default)]
        color: Option<String>,
        #[serde(default)]
        offset_x: Option<f64>,
        #[serde(default)]
        offset_y: Option<f64>,
    },
    /// Grid layout token.
    #[serde(rename = "grid")]
    Grid {
        pattern: String,
        #[serde(default)]
        size: Option<f64>,
        #[serde(default)]
        gutter: Option<f64>,
        #[serde(default)]
        count: Option<f64>,
    },
    /// Raw fallback for unrecognized token types.
    #[serde(rename = "raw")]
    Raw { data: serde_json::Value },
}

// ---------------------------------------------------------------------------
// Image Export
// ---------------------------------------------------------------------------

/// Response from `GET /v1/images/:file_key`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportImagesResponse {
    pub images: serde_json::Value,
    #[serde(default)]
    pub err: Option<String>,
}

// ---------------------------------------------------------------------------
// Version History
// ---------------------------------------------------------------------------

/// Response from `GET /v1/files/:file_key/versions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionsResponse {
    pub versions: Vec<FileVersion>,
    #[serde(default)]
    pub pagination: Option<serde_json::Value>,
}

/// A single file version entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileVersion {
    pub id: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub user: Option<FigmaUser>,
    pub created_at: String,
}

// ---------------------------------------------------------------------------
// Comments
// ---------------------------------------------------------------------------

/// Response from `GET /v1/files/:file_key/comments`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommentsResponse {
    pub comments: Vec<Comment>,
}

/// A Figma comment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Comment {
    pub id: String,
    pub message: String,
    pub created_at: String,
    #[serde(default)]
    pub resolved_at: Option<String>,
    #[serde(default)]
    pub user: Option<FigmaUser>,
    #[serde(default)]
    pub client_meta: Option<serde_json::Value>,
    #[serde(default)]
    pub order_id: Option<String>,
    #[serde(default)]
    pub parent_id: Option<String>,
}

/// Figma user info (shared across multiple response types).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FigmaUser {
    #[serde(default)]
    pub handle: Option<String>,
    #[serde(default)]
    pub img_url: Option<String>,
    #[serde(default)]
    pub id: Option<String>,
}

/// Request body for `POST /v1/files/:file_key/comments`.
#[derive(Debug, Clone, Serialize)]
pub struct PostCommentRequest {
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_meta: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Webhooks
// ---------------------------------------------------------------------------

/// Response from `GET /v2/webhooks/:team_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhooksListResponse {
    pub webhooks: Vec<Webhook>,
}

/// A Figma webhook.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Webhook {
    pub id: String,
    pub team_id: String,
    pub event_type: String,
    pub endpoint: String,
    pub status: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub passcode: Option<String>,
}

/// Request body for POST /v2/webhooks.
#[derive(Debug, Clone, Serialize)]
pub struct CreateWebhookRequest {
    pub team_id: String,
    pub event_type: String,
    pub endpoint: String,
    pub passcode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ================================================================
    // FigmaErrorResponse
    // ================================================================

    #[test]
    fn error_response_with_alias() {
        let json = r#"{"status":404,"err":"Not found"}"#;
        let resp: FigmaErrorResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.status, Some(404));
        assert_eq!(resp.message.as_deref(), Some("Not found"));
    }

    #[test]
    fn error_response_with_message_field() {
        let json = r#"{"status":500,"message":"Internal error"}"#;
        let resp: FigmaErrorResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.status, Some(500));
        assert_eq!(resp.message.as_deref(), Some("Internal error"));
    }

    #[test]
    fn error_response_minimal() {
        let resp: FigmaErrorResponse = serde_json::from_str("{}").unwrap();
        assert!(resp.status.is_none());
        assert!(resp.message.is_none());
    }

    #[test]
    fn error_response_status_only() {
        let resp: FigmaErrorResponse = serde_json::from_str(r#"{"status":429}"#).unwrap();
        assert_eq!(resp.status, Some(429));
        assert!(resp.message.is_none());
    }

    #[test]
    fn error_response_message_only() {
        let resp: FigmaErrorResponse = serde_json::from_str(r#"{"err":"quota exceeded"}"#).unwrap();
        assert!(resp.status.is_none());
        assert_eq!(resp.message.as_deref(), Some("quota exceeded"));
    }

    #[test]
    fn error_response_clone() {
        let resp = FigmaErrorResponse {
            status: Some(404),
            message: Some("missing".into()),
        };
        let cloned = resp.clone();
        assert_eq!(cloned.status, resp.status);
        assert_eq!(cloned.message, resp.message);
    }

    #[test]
    fn error_response_debug() {
        let resp = FigmaErrorResponse {
            status: Some(500),
            message: Some("oops".into()),
        };
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("FigmaErrorResponse"));
        assert!(dbg.contains("500"));
        assert!(dbg.contains("oops"));
    }

    #[test]
    fn error_response_ignores_extra_fields() {
        let json = r#"{"status":400,"err":"bad","extra_field":"ignored"}"#;
        let resp: FigmaErrorResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.status, Some(400));
    }

    // ================================================================
    // TeamProjectsResponse / Project
    // ================================================================

    #[test]
    fn team_projects_response_roundtrip() {
        let resp = TeamProjectsResponse {
            name: "My Team".to_string(),
            projects: vec![Project {
                id: 1,
                name: "Project A".to_string(),
            }],
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: TeamProjectsResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "My Team");
        assert_eq!(back.projects.len(), 1);
        assert_eq!(back.projects[0].id, 1);
        assert_eq!(back.projects[0].name, "Project A");
    }

    #[test]
    fn team_projects_response_empty_projects() {
        let json = json!({"name": "Empty Team", "projects": []});
        let resp: TeamProjectsResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.name, "Empty Team");
        assert!(resp.projects.is_empty());
    }

    #[test]
    fn team_projects_response_multiple_projects() {
        let json = json!({
            "name": "Big Team",
            "projects": [
                {"id": 1, "name": "Alpha"},
                {"id": 2, "name": "Beta"},
                {"id": 999, "name": "Gamma"}
            ]
        });
        let resp: TeamProjectsResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.projects.len(), 3);
        assert_eq!(resp.projects[2].id, 999);
    }

    #[test]
    fn project_clone() {
        let p = Project {
            id: 42,
            name: "Cloned".into(),
        };
        let c = p.clone();
        assert_eq!(c.id, 42);
        assert_eq!(c.name, "Cloned");
        assert_eq!(p.id, 42);
    }

    #[test]
    fn project_debug() {
        let p = Project {
            id: 7,
            name: "Debug Test".into(),
        };
        let dbg = format!("{p:?}");
        assert!(dbg.contains("Project"));
        assert!(dbg.contains('7'));
    }

    // ================================================================
    // ProjectFilesResponse / ProjectFile
    // ================================================================

    #[test]
    fn project_files_response_roundtrip() {
        let resp = ProjectFilesResponse {
            name: "My Project".into(),
            files: vec![ProjectFile {
                key: "abc".into(),
                name: "Design".into(),
                thumbnail_url: Some("https://img.example.com/thumb.png".into()),
                last_modified: "2026-03-01T00:00:00Z".into(),
            }],
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: ProjectFilesResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "My Project");
        assert_eq!(back.files.len(), 1);
        assert_eq!(
            back.files[0].thumbnail_url.as_deref(),
            Some("https://img.example.com/thumb.png")
        );
    }

    #[test]
    fn project_file_missing_thumbnail() {
        let json = json!({
            "key": "abc123",
            "name": "Design System",
            "last_modified": "2026-03-01T00:00:00Z"
        });
        let file: ProjectFile = serde_json::from_value(json).unwrap();
        assert_eq!(file.key, "abc123");
        assert!(file.thumbnail_url.is_none());
    }

    #[test]
    fn project_file_with_thumbnail() {
        let json = json!({
            "key": "xyz",
            "name": "Icons",
            "thumbnail_url": "https://cdn.figma.com/thumb.png",
            "last_modified": "2026-03-05T12:00:00Z"
        });
        let file: ProjectFile = serde_json::from_value(json).unwrap();
        assert_eq!(
            file.thumbnail_url.as_deref(),
            Some("https://cdn.figma.com/thumb.png")
        );
    }

    #[test]
    fn project_file_clone() {
        let file = ProjectFile {
            key: "k".into(),
            name: "n".into(),
            thumbnail_url: None,
            last_modified: "now".into(),
        };
        let c = file.clone();
        assert_eq!(c.key, "k");
        assert!(c.thumbnail_url.is_none());
        assert_eq!(file.key, "k");
    }

    #[test]
    fn project_file_debug() {
        let file = ProjectFile {
            key: "dbg".into(),
            name: "test".into(),
            thumbnail_url: None,
            last_modified: "t".into(),
        };
        let dbg = format!("{file:?}");
        assert!(dbg.contains("ProjectFile"));
        assert!(dbg.contains("dbg"));
    }

    #[test]
    fn project_files_response_empty() {
        let json = json!({"name": "Empty", "files": []});
        let resp: ProjectFilesResponse = serde_json::from_value(json).unwrap();
        assert!(resp.files.is_empty());
    }

    // ================================================================
    // FileResponse (camelCase)
    // ================================================================

    #[test]
    fn file_response_camel_case() {
        let json = json!({
            "name": "My Design",
            "document": {"id": "0:0", "type": "DOCUMENT"},
            "lastModified": "2026-03-01",
            "version": "123"
        });
        let resp: FileResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.name, "My Design");
        assert_eq!(resp.version, "123");
        assert!(resp.components.is_none());
        assert!(resp.styles.is_none());
    }

    #[test]
    fn file_response_with_components_and_styles() {
        let json = json!({
            "name": "Full File",
            "document": {"id": "0:0"},
            "lastModified": "2026-03-05",
            "version": "456",
            "components": {"1:2": {"key": "comp1"}},
            "styles": {"3:4": {"key": "style1"}}
        });
        let resp: FileResponse = serde_json::from_value(json).unwrap();
        assert!(resp.components.is_some());
        assert!(resp.styles.is_some());
    }

    #[test]
    fn file_response_roundtrip() {
        let resp = FileResponse {
            name: "Test".into(),
            document: json!({"type": "DOCUMENT"}),
            last_modified: "2026-01-01".into(),
            version: "v1".into(),
            components: None,
            styles: Some(json!({})),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: FileResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "Test");
        assert!(back.components.is_none());
        assert!(back.styles.is_some());
    }

    #[test]
    fn file_response_clone() {
        let resp = FileResponse {
            name: "Clone".into(),
            document: json!({}),
            last_modified: "now".into(),
            version: "1".into(),
            components: None,
            styles: None,
        };
        let c = resp.clone();
        assert_eq!(c.name, "Clone");
        assert_eq!(resp.name, "Clone");
    }

    #[test]
    fn file_response_debug() {
        let resp = FileResponse {
            name: "Debug".into(),
            document: json!({}),
            last_modified: "t".into(),
            version: "v".into(),
            components: None,
            styles: None,
        };
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("FileResponse"));
    }

    // ================================================================
    // FileNodesResponse
    // ================================================================

    #[test]
    fn file_nodes_response_roundtrip() {
        let json = json!({"nodes": {"1:2": {"document": {"id": "1:2"}}}});
        let resp: FileNodesResponse = serde_json::from_value(json).unwrap();
        assert!(resp.nodes.is_object());
        let serialized = serde_json::to_string(&resp).unwrap();
        let back: FileNodesResponse = serde_json::from_str(&serialized).unwrap();
        assert!(back.nodes.is_object());
    }

    #[test]
    fn file_nodes_response_empty() {
        let json = json!({"nodes": {}});
        let resp: FileNodesResponse = serde_json::from_value(json).unwrap();
        assert!(resp.nodes.as_object().unwrap().is_empty());
    }

    #[test]
    fn file_nodes_response_clone_debug() {
        let resp = FileNodesResponse {
            nodes: json!({"a": 1}),
        };
        let c = resp.clone();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("FileNodesResponse"));
        assert_eq!(resp.nodes, json!({"a": 1}));
    }

    // ================================================================
    // ComponentsResponse
    // ================================================================

    #[test]
    fn components_response_roundtrip() {
        let resp = ComponentsResponse {
            meta: json!({"components": []}),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: ComponentsResponse = serde_json::from_str(&json).unwrap();
        assert!(back.meta.is_object());
    }

    #[test]
    fn components_response_clone_debug() {
        let resp = ComponentsResponse {
            meta: json!({"x": 1}),
        };
        let c = resp.clone();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("ComponentsResponse"));
        assert_eq!(c.meta, json!({"x": 1}));
        assert_eq!(resp.meta, json!({"x": 1}));
    }

    // ================================================================
    // StylesResponse
    // ================================================================

    #[test]
    fn styles_response_roundtrip() {
        let resp = StylesResponse {
            meta: json!({"styles": []}),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: StylesResponse = serde_json::from_str(&json).unwrap();
        assert!(back.meta.is_object());
    }

    #[test]
    fn styles_response_clone_debug() {
        let resp = StylesResponse {
            meta: json!({"y": 2}),
        };
        let c = resp.clone();
        assert_eq!(c.meta, json!({"y": 2}));
        let dbg = format!("{c:?}");
        assert!(dbg.contains("StylesResponse"));
        assert_eq!(resp.meta, json!({"y": 2}));
    }

    // ================================================================
    // DesignToken + TokenValue
    // ================================================================

    #[test]
    fn design_token_color_roundtrip() {
        let token = DesignToken {
            name: "color-primary-500".to_string(),
            original_name: "Primary/500".to_string(),
            category: "color".to_string(),
            style_type: "FILL".to_string(),
            value: TokenValue::Color {
                r: 1.0,
                g: 0.5,
                b: 0.0,
                a: 1.0,
                hex: "#ff8000ff".to_string(),
            },
            node_id: Some("1:2".to_string()),
            description: Some("Primary orange".to_string()),
        };
        let json = serde_json::to_string(&token).unwrap();
        let back: DesignToken = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "color-primary-500");
        assert_eq!(back.original_name, "Primary/500");
        assert_eq!(back.category, "color");
        assert_eq!(back.style_type, "FILL");
        assert_eq!(back.node_id.as_deref(), Some("1:2"));
        assert_eq!(back.description.as_deref(), Some("Primary orange"));
        match &back.value {
            TokenValue::Color { r, g, b, a, hex } => {
                assert_eq!(*r, 1.0);
                assert_eq!(*g, 0.5);
                assert_eq!(*b, 0.0);
                assert_eq!(*a, 1.0);
                assert_eq!(hex, "#ff8000ff");
            }
            _ => panic!("expected Color"),
        }
    }

    #[test]
    fn design_token_missing_optional_fields() {
        let token = DesignToken {
            name: "bare".to_string(),
            original_name: "Bare".to_string(),
            category: "color".to_string(),
            style_type: "FILL".to_string(),
            value: TokenValue::Color {
                r: 0.0,
                g: 0.0,
                b: 0.0,
                a: 1.0,
                hex: "#000000ff".into(),
            },
            node_id: None,
            description: None,
        };
        let json = serde_json::to_string(&token).unwrap();
        let back: DesignToken = serde_json::from_str(&json).unwrap();
        assert!(back.node_id.is_none());
        assert!(back.description.is_none());
    }

    #[test]
    fn design_token_from_json_missing_optional_node_id_and_description() {
        let json = json!({
            "name": "tok",
            "original_name": "Tok",
            "category": "color",
            "style_type": "FILL",
            "value": {
                "type": "color",
                "r": 1.0, "g": 0.0, "b": 0.0, "a": 1.0,
                "hex": "#ff0000ff"
            }
        });
        let token: DesignToken = serde_json::from_value(json).unwrap();
        assert!(token.node_id.is_none());
        assert!(token.description.is_none());
    }

    #[test]
    fn design_token_clone() {
        let token = DesignToken {
            name: "clone-test".into(),
            original_name: "Clone".into(),
            category: "color".into(),
            style_type: "FILL".into(),
            value: TokenValue::Raw {
                data: json!("hello"),
            },
            node_id: Some("n1".into()),
            description: Some("desc".into()),
        };
        let c = token.clone();
        assert_eq!(c.name, "clone-test");
        assert_eq!(c.node_id, Some("n1".into()));
        assert_eq!(token.name, "clone-test");
    }

    #[test]
    fn design_token_debug() {
        let token = DesignToken {
            name: "dbg".into(),
            original_name: "Dbg".into(),
            category: "effect".into(),
            style_type: "EFFECT".into(),
            value: TokenValue::Raw { data: json!(null) },
            node_id: None,
            description: None,
        };
        let dbg = format!("{token:?}");
        assert!(dbg.contains("DesignToken"));
        assert!(dbg.contains("dbg"));
    }

    #[test]
    fn design_token_typography_roundtrip() {
        let token = DesignToken {
            name: "text-body".to_string(),
            original_name: "Body".to_string(),
            category: "typography".to_string(),
            style_type: "TEXT".to_string(),
            value: TokenValue::Typography {
                font_family: "Inter".to_string(),
                font_size: 16.0,
                font_weight: 400.0,
                line_height: Some(24.0),
                letter_spacing: None,
            },
            node_id: None,
            description: None,
        };
        let json = serde_json::to_string(&token).unwrap();
        let back: DesignToken = serde_json::from_str(&json).unwrap();
        match &back.value {
            TokenValue::Typography {
                font_family,
                font_size,
                font_weight,
                line_height,
                letter_spacing,
            } => {
                assert_eq!(font_family, "Inter");
                assert_eq!(*font_size, 16.0);
                assert_eq!(*font_weight, 400.0);
                assert_eq!(*line_height, Some(24.0));
                assert!(letter_spacing.is_none());
            }
            _ => panic!("expected Typography"),
        }
    }

    #[test]
    fn typography_all_optional_fields_present() {
        let value = TokenValue::Typography {
            font_family: "Roboto".into(),
            font_size: 14.0,
            font_weight: 700.0,
            line_height: Some(20.0),
            letter_spacing: Some(0.5),
        };
        let json = serde_json::to_string(&value).unwrap();
        let back: TokenValue = serde_json::from_str(&json).unwrap();
        match back {
            TokenValue::Typography {
                line_height,
                letter_spacing,
                ..
            } => {
                assert_eq!(line_height, Some(20.0));
                assert_eq!(letter_spacing, Some(0.5));
            }
            _ => panic!("expected Typography"),
        }
    }

    #[test]
    fn typography_no_optional_fields() {
        let json = json!({
            "type": "typography",
            "font_family": "Arial",
            "font_size": 12.0,
            "font_weight": 400.0
        });
        let value: TokenValue = serde_json::from_value(json).unwrap();
        match value {
            TokenValue::Typography {
                line_height,
                letter_spacing,
                ..
            } => {
                assert!(line_height.is_none());
                assert!(letter_spacing.is_none());
            }
            _ => panic!("expected Typography"),
        }
    }

    #[test]
    fn design_token_effect_roundtrip() {
        let value = TokenValue::Effect {
            effect_type: "DROP_SHADOW".to_string(),
            radius: Some(4.0),
            color: Some("#00000040".to_string()),
            offset_x: Some(0.0),
            offset_y: Some(2.0),
        };
        let json = serde_json::to_string(&value).unwrap();
        let back: TokenValue = serde_json::from_str(&json).unwrap();
        match back {
            TokenValue::Effect {
                effect_type,
                radius,
                color,
                offset_x,
                offset_y,
            } => {
                assert_eq!(effect_type, "DROP_SHADOW");
                assert_eq!(radius, Some(4.0));
                assert_eq!(color.as_deref(), Some("#00000040"));
                assert_eq!(offset_x, Some(0.0));
                assert_eq!(offset_y, Some(2.0));
            }
            _ => panic!("expected Effect"),
        }
    }

    #[test]
    fn effect_all_optional_fields_missing() {
        let json = json!({
            "type": "effect",
            "effect_type": "BLUR"
        });
        let value: TokenValue = serde_json::from_value(json).unwrap();
        match value {
            TokenValue::Effect {
                effect_type,
                radius,
                color,
                offset_x,
                offset_y,
            } => {
                assert_eq!(effect_type, "BLUR");
                assert!(radius.is_none());
                assert!(color.is_none());
                assert!(offset_x.is_none());
                assert!(offset_y.is_none());
            }
            _ => panic!("expected Effect"),
        }
    }

    #[test]
    fn effect_partial_optional_fields() {
        let json = json!({
            "type": "effect",
            "effect_type": "INNER_SHADOW",
            "radius": 8.0,
            "color": "#ffffff80"
        });
        let value: TokenValue = serde_json::from_value(json).unwrap();
        match value {
            TokenValue::Effect {
                radius,
                color,
                offset_x,
                offset_y,
                ..
            } => {
                assert_eq!(radius, Some(8.0));
                assert_eq!(color.as_deref(), Some("#ffffff80"));
                assert!(offset_x.is_none());
                assert!(offset_y.is_none());
            }
            _ => panic!("expected Effect"),
        }
    }

    #[test]
    fn design_token_grid_roundtrip() {
        let value = TokenValue::Grid {
            pattern: "COLUMNS".to_string(),
            size: Some(8.0),
            gutter: Some(16.0),
            count: Some(12.0),
        };
        let json = serde_json::to_string(&value).unwrap();
        let back: TokenValue = serde_json::from_str(&json).unwrap();
        match back {
            TokenValue::Grid {
                pattern,
                size,
                gutter,
                count,
            } => {
                assert_eq!(pattern, "COLUMNS");
                assert_eq!(size, Some(8.0));
                assert_eq!(gutter, Some(16.0));
                assert_eq!(count, Some(12.0));
            }
            _ => panic!("expected Grid"),
        }
    }

    #[test]
    fn grid_all_optional_fields_missing() {
        let json = json!({
            "type": "grid",
            "pattern": "ROWS"
        });
        let value: TokenValue = serde_json::from_value(json).unwrap();
        match value {
            TokenValue::Grid {
                pattern,
                size,
                gutter,
                count,
            } => {
                assert_eq!(pattern, "ROWS");
                assert!(size.is_none());
                assert!(gutter.is_none());
                assert!(count.is_none());
            }
            _ => panic!("expected Grid"),
        }
    }

    #[test]
    fn grid_partial_optional_fields() {
        let json = json!({
            "type": "grid",
            "pattern": "GRID",
            "size": 4.0
        });
        let value: TokenValue = serde_json::from_value(json).unwrap();
        match value {
            TokenValue::Grid {
                size,
                gutter,
                count,
                ..
            } => {
                assert_eq!(size, Some(4.0));
                assert!(gutter.is_none());
                assert!(count.is_none());
            }
            _ => panic!("expected Grid"),
        }
    }

    #[test]
    fn design_token_raw_roundtrip() {
        let value = TokenValue::Raw {
            data: json!({"custom": true, "nested": {"deep": 42}}),
        };
        let json = serde_json::to_string(&value).unwrap();
        let back: TokenValue = serde_json::from_str(&json).unwrap();
        match back {
            TokenValue::Raw { data } => {
                assert_eq!(data["custom"], true);
                assert_eq!(data["nested"]["deep"], 42);
            }
            _ => panic!("expected Raw"),
        }
    }

    #[test]
    fn raw_with_null_data() {
        let value = TokenValue::Raw { data: json!(null) };
        let json = serde_json::to_string(&value).unwrap();
        let back: TokenValue = serde_json::from_str(&json).unwrap();
        match back {
            TokenValue::Raw { data } => assert!(data.is_null()),
            _ => panic!("expected Raw"),
        }
    }

    #[test]
    fn raw_with_array_data() {
        let value = TokenValue::Raw {
            data: json!([1, 2, 3]),
        };
        let json = serde_json::to_string(&value).unwrap();
        let back: TokenValue = serde_json::from_str(&json).unwrap();
        match back {
            TokenValue::Raw { data } => assert_eq!(data.as_array().unwrap().len(), 3),
            _ => panic!("expected Raw"),
        }
    }

    #[test]
    fn token_value_clone() {
        let v = TokenValue::Color {
            r: 1.0,
            g: 0.0,
            b: 0.0,
            a: 1.0,
            hex: "#ff0000ff".into(),
        };
        let c = v.clone();
        match c {
            TokenValue::Color { hex, .. } => assert_eq!(hex, "#ff0000ff"),
            _ => panic!("expected Color"),
        }
        assert!(matches!(v, TokenValue::Color { .. }));
    }

    #[test]
    fn token_value_debug() {
        let v = TokenValue::Grid {
            pattern: "COLUMNS".into(),
            size: None,
            gutter: None,
            count: None,
        };
        let dbg = format!("{v:?}");
        assert!(dbg.contains("Grid"));
        assert!(dbg.contains("COLUMNS"));
    }

    // Tagged enum: verify the "type" tag is in the JSON
    #[test]
    fn token_value_color_has_type_tag() {
        let v = TokenValue::Color {
            r: 0.0,
            g: 0.0,
            b: 0.0,
            a: 1.0,
            hex: "#000000ff".into(),
        };
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains(r#""type":"color""#));
    }

    #[test]
    fn token_value_typography_has_type_tag() {
        let v = TokenValue::Typography {
            font_family: "F".into(),
            font_size: 10.0,
            font_weight: 400.0,
            line_height: None,
            letter_spacing: None,
        };
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains(r#""type":"typography""#));
    }

    #[test]
    fn token_value_effect_has_type_tag() {
        let v = TokenValue::Effect {
            effect_type: "BLUR".into(),
            radius: None,
            color: None,
            offset_x: None,
            offset_y: None,
        };
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains(r#""type":"effect""#));
    }

    #[test]
    fn token_value_grid_has_type_tag() {
        let v = TokenValue::Grid {
            pattern: "ROWS".into(),
            size: None,
            gutter: None,
            count: None,
        };
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains(r#""type":"grid""#));
    }

    #[test]
    fn token_value_raw_has_type_tag() {
        let v = TokenValue::Raw { data: json!(1) };
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains(r#""type":"raw""#));
    }

    // ================================================================
    // ExportImagesResponse
    // ================================================================

    #[test]
    fn export_images_response_no_error() {
        let json = json!({
            "images": {"1:2": "https://example.com/img.png"},
            "err": null
        });
        let resp: ExportImagesResponse = serde_json::from_value(json).unwrap();
        assert!(resp.err.is_none());
        assert!(resp.images.is_object());
    }

    #[test]
    fn export_images_response_with_error() {
        let json = json!({
            "images": {},
            "err": "Node not found"
        });
        let resp: ExportImagesResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.err.as_deref(), Some("Node not found"));
    }

    #[test]
    fn export_images_response_missing_err_field() {
        let json = json!({"images": {}});
        let resp: ExportImagesResponse = serde_json::from_value(json).unwrap();
        assert!(resp.err.is_none());
    }

    #[test]
    fn export_images_response_roundtrip() {
        let resp = ExportImagesResponse {
            images: json!({"1:1": "https://img.example.com/a.svg"}),
            err: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: ExportImagesResponse = serde_json::from_str(&json).unwrap();
        assert!(back.err.is_none());
    }

    #[test]
    fn export_images_response_clone_debug() {
        let resp = ExportImagesResponse {
            images: json!({}),
            err: Some("error".into()),
        };
        let c = resp.clone();
        assert_eq!(c.err.as_deref(), Some("error"));
        let dbg = format!("{c:?}");
        assert!(dbg.contains("ExportImagesResponse"));
        assert!(resp.err.is_some());
    }

    // ================================================================
    // VersionsResponse / FileVersion
    // ================================================================

    #[test]
    fn versions_response_roundtrip() {
        let resp = VersionsResponse {
            versions: vec![FileVersion {
                id: "v1".into(),
                label: Some("Release".into()),
                description: Some("Final release".into()),
                user: None,
                created_at: "2026-03-01T00:00:00Z".into(),
            }],
            pagination: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: VersionsResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.versions.len(), 1);
        assert_eq!(back.versions[0].id, "v1");
        assert!(back.pagination.is_none());
    }

    #[test]
    fn versions_response_with_pagination() {
        let json = json!({
            "versions": [],
            "pagination": {"cursor": "abc", "has_more": true}
        });
        let resp: VersionsResponse = serde_json::from_value(json).unwrap();
        assert!(resp.versions.is_empty());
        assert!(resp.pagination.is_some());
    }

    #[test]
    fn versions_response_missing_pagination() {
        let json = json!({"versions": []});
        let resp: VersionsResponse = serde_json::from_value(json).unwrap();
        assert!(resp.pagination.is_none());
    }

    #[test]
    fn file_version_all_fields() {
        let json = json!({
            "id": "v1",
            "label": "Final",
            "description": "Ready for handoff",
            "user": {"handle": "alice", "img_url": null, "id": "u1"},
            "created_at": "2026-03-01T00:00:00Z"
        });
        let ver: FileVersion = serde_json::from_value(json).unwrap();
        assert_eq!(ver.id, "v1");
        assert_eq!(ver.label.as_deref(), Some("Final"));
        assert_eq!(ver.description.as_deref(), Some("Ready for handoff"));
        assert!(ver.user.is_some());
        assert_eq!(ver.created_at, "2026-03-01T00:00:00Z");
    }

    #[test]
    fn file_version_minimal() {
        let json = json!({
            "id": "v2",
            "created_at": "2026-03-05"
        });
        let ver: FileVersion = serde_json::from_value(json).unwrap();
        assert_eq!(ver.id, "v2");
        assert!(ver.label.is_none());
        assert!(ver.description.is_none());
        assert!(ver.user.is_none());
    }

    #[test]
    fn file_version_clone() {
        let ver = FileVersion {
            id: "v3".into(),
            label: None,
            description: None,
            user: Some(FigmaUser {
                handle: Some("bob".into()),
                img_url: None,
                id: Some("u2".into()),
            }),
            created_at: "now".into(),
        };
        let c = ver.clone();
        assert_eq!(c.id, "v3");
        assert!(c.user.is_some());
        assert_eq!(c.user.unwrap().handle.as_deref(), Some("bob"));
        assert_eq!(ver.id, "v3");
    }

    #[test]
    fn file_version_debug() {
        let ver = FileVersion {
            id: "vdbg".into(),
            label: None,
            description: None,
            user: None,
            created_at: "t".into(),
        };
        let dbg = format!("{ver:?}");
        assert!(dbg.contains("FileVersion"));
        assert!(dbg.contains("vdbg"));
    }

    // ================================================================
    // FigmaUser
    // ================================================================

    #[test]
    fn figma_user_all_fields() {
        let json = json!({"handle": "alice", "img_url": "https://img.com/a.png", "id": "u1"});
        let user: FigmaUser = serde_json::from_value(json).unwrap();
        assert_eq!(user.handle.as_deref(), Some("alice"));
        assert_eq!(user.img_url.as_deref(), Some("https://img.com/a.png"));
        assert_eq!(user.id.as_deref(), Some("u1"));
    }

    #[test]
    fn figma_user_all_fields_missing() {
        let json = json!({});
        let user: FigmaUser = serde_json::from_value(json).unwrap();
        assert!(user.handle.is_none());
        assert!(user.img_url.is_none());
        assert!(user.id.is_none());
    }

    #[test]
    fn figma_user_partial_fields() {
        let json = json!({"handle": "bob"});
        let user: FigmaUser = serde_json::from_value(json).unwrap();
        assert_eq!(user.handle.as_deref(), Some("bob"));
        assert!(user.img_url.is_none());
        assert!(user.id.is_none());
    }

    #[test]
    fn figma_user_roundtrip() {
        let user = FigmaUser {
            handle: Some("test".into()),
            img_url: Some("url".into()),
            id: Some("id1".into()),
        };
        let json = serde_json::to_string(&user).unwrap();
        let back: FigmaUser = serde_json::from_str(&json).unwrap();
        assert_eq!(back.handle, user.handle);
        assert_eq!(back.img_url, user.img_url);
        assert_eq!(back.id, user.id);
    }

    #[test]
    fn figma_user_clone() {
        let user = FigmaUser {
            handle: Some("clone".into()),
            img_url: None,
            id: None,
        };
        let c = user.clone();
        assert_eq!(c.handle.as_deref(), Some("clone"));
        assert_eq!(user.handle.as_deref(), Some("clone"));
    }

    #[test]
    fn figma_user_debug() {
        let user = FigmaUser {
            handle: None,
            img_url: None,
            id: None,
        };
        let dbg = format!("{user:?}");
        assert!(dbg.contains("FigmaUser"));
    }

    // ================================================================
    // Comment
    // ================================================================

    #[test]
    fn comment_minimal() {
        let json = json!({
            "id": "c1",
            "message": "Looks great!",
            "created_at": "2026-03-03T00:00:00Z"
        });
        let comment: Comment = serde_json::from_value(json).unwrap();
        assert_eq!(comment.id, "c1");
        assert_eq!(comment.message, "Looks great!");
        assert!(comment.resolved_at.is_none());
        assert!(comment.user.is_none());
        assert!(comment.client_meta.is_none());
        assert!(comment.order_id.is_none());
        assert!(comment.parent_id.is_none());
    }

    #[test]
    fn comment_all_fields() {
        let json = json!({
            "id": "c2",
            "message": "Resolved comment",
            "created_at": "2026-03-01T00:00:00Z",
            "resolved_at": "2026-03-02T00:00:00Z",
            "user": {"handle": "alice"},
            "client_meta": {"x": 100, "y": 200},
            "order_id": "o1",
            "parent_id": "c1"
        });
        let comment: Comment = serde_json::from_value(json).unwrap();
        assert_eq!(comment.resolved_at.as_deref(), Some("2026-03-02T00:00:00Z"));
        assert!(comment.user.is_some());
        assert!(comment.client_meta.is_some());
        assert_eq!(comment.order_id.as_deref(), Some("o1"));
        assert_eq!(comment.parent_id.as_deref(), Some("c1"));
    }

    #[test]
    fn comment_roundtrip() {
        let comment = Comment {
            id: "c3".into(),
            message: "Hello".into(),
            created_at: "2026-03-05".into(),
            resolved_at: None,
            user: Some(FigmaUser {
                handle: Some("u".into()),
                img_url: None,
                id: None,
            }),
            client_meta: Some(json!({"x": 0})),
            order_id: None,
            parent_id: Some("c1".into()),
        };
        let json = serde_json::to_string(&comment).unwrap();
        let back: Comment = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "c3");
        assert_eq!(back.parent_id.as_deref(), Some("c1"));
        assert!(back.user.is_some());
    }

    #[test]
    fn comment_clone() {
        let comment = Comment {
            id: "c4".into(),
            message: "clone me".into(),
            created_at: "t".into(),
            resolved_at: None,
            user: None,
            client_meta: None,
            order_id: None,
            parent_id: None,
        };
        let c = comment.clone();
        assert_eq!(c.id, "c4");
        assert_eq!(c.message, "clone me");
        assert_eq!(comment.id, "c4");
    }

    #[test]
    fn comment_debug() {
        let comment = Comment {
            id: "cdbg".into(),
            message: "msg".into(),
            created_at: "t".into(),
            resolved_at: None,
            user: None,
            client_meta: None,
            order_id: None,
            parent_id: None,
        };
        let dbg = format!("{comment:?}");
        assert!(dbg.contains("Comment"));
        assert!(dbg.contains("cdbg"));
    }

    // ================================================================
    // CommentsResponse
    // ================================================================

    #[test]
    fn comments_response_roundtrip() {
        let resp = CommentsResponse {
            comments: vec![Comment {
                id: "c1".into(),
                message: "hi".into(),
                created_at: "t".into(),
                resolved_at: None,
                user: None,
                client_meta: None,
                order_id: None,
                parent_id: None,
            }],
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: CommentsResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.comments.len(), 1);
    }

    #[test]
    fn comments_response_empty() {
        let json = json!({"comments": []});
        let resp: CommentsResponse = serde_json::from_value(json).unwrap();
        assert!(resp.comments.is_empty());
    }

    #[test]
    fn comments_response_clone_debug() {
        let resp = CommentsResponse { comments: vec![] };
        let c = resp.clone();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("CommentsResponse"));
        assert!(resp.comments.is_empty());
    }

    // ================================================================
    // PostCommentRequest (Serialize only, skip_serializing_if)
    // ================================================================

    #[test]
    fn post_comment_request_minimal() {
        let req = PostCommentRequest {
            message: "Hello".into(),
            comment_id: None,
            client_meta: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("message"));
        assert!(!json.contains("comment_id"));
        assert!(!json.contains("client_meta"));
    }

    #[test]
    fn post_comment_request_with_comment_id() {
        let req = PostCommentRequest {
            message: "Reply".into(),
            comment_id: Some("c1".into()),
            client_meta: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("comment_id"));
        assert!(json.contains("c1"));
        assert!(!json.contains("client_meta"));
    }

    #[test]
    fn post_comment_request_with_client_meta() {
        let req = PostCommentRequest {
            message: "Pinned".into(),
            comment_id: None,
            client_meta: Some(json!({"node_id": "1:2", "node_offset": {"x": 100, "y": 50}})),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("comment_id"));
        assert!(json.contains("client_meta"));
        assert!(json.contains("node_id"));
    }

    #[test]
    fn post_comment_request_all_fields() {
        let req = PostCommentRequest {
            message: "Full".into(),
            comment_id: Some("parent".into()),
            client_meta: Some(json!({"x": 0})),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("message"));
        assert!(json.contains("comment_id"));
        assert!(json.contains("client_meta"));
    }

    #[test]
    fn post_comment_request_clone() {
        let req = PostCommentRequest {
            message: "clone".into(),
            comment_id: None,
            client_meta: None,
        };
        let c = req.clone();
        assert_eq!(c.message, "clone");
        assert_eq!(req.message, "clone");
    }

    #[test]
    fn post_comment_request_debug() {
        let req = PostCommentRequest {
            message: "dbg".into(),
            comment_id: None,
            client_meta: None,
        };
        let dbg = format!("{req:?}");
        assert!(dbg.contains("PostCommentRequest"));
    }

    // ================================================================
    // Webhook
    // ================================================================

    #[test]
    fn webhook_roundtrip() {
        let webhook = Webhook {
            id: "w1".to_string(),
            team_id: "t1".to_string(),
            event_type: "FILE_UPDATE".to_string(),
            endpoint: "https://example.com/hook".to_string(),
            status: "ACTIVE".to_string(),
            description: Some("File updates".to_string()),
            client_id: None,
            passcode: Some("secret".to_string()),
        };
        let json = serde_json::to_string(&webhook).unwrap();
        let back: Webhook = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "w1");
        assert_eq!(back.event_type, "FILE_UPDATE");
        assert_eq!(back.status, "ACTIVE");
        assert_eq!(back.description.as_deref(), Some("File updates"));
        assert!(back.client_id.is_none());
        assert_eq!(back.passcode.as_deref(), Some("secret"));
    }

    #[test]
    fn webhook_all_optional_fields_present() {
        let json = json!({
            "id": "w2",
            "team_id": "t2",
            "event_type": "FILE_DELETE",
            "endpoint": "https://hook.example.com",
            "status": "PAUSED",
            "description": "desc",
            "client_id": "cl1",
            "passcode": "pass123"
        });
        let webhook: Webhook = serde_json::from_value(json).unwrap();
        assert_eq!(webhook.description.as_deref(), Some("desc"));
        assert_eq!(webhook.client_id.as_deref(), Some("cl1"));
        assert_eq!(webhook.passcode.as_deref(), Some("pass123"));
    }

    #[test]
    fn webhook_minimal_optional_fields() {
        let json = json!({
            "id": "w3",
            "team_id": "t3",
            "event_type": "LIBRARY_PUBLISH",
            "endpoint": "https://e.com",
            "status": "ACTIVE"
        });
        let webhook: Webhook = serde_json::from_value(json).unwrap();
        assert!(webhook.description.is_none());
        assert!(webhook.client_id.is_none());
        assert!(webhook.passcode.is_none());
    }

    #[test]
    fn webhook_clone() {
        let w = Webhook {
            id: "wc".into(),
            team_id: "tc".into(),
            event_type: "FILE_UPDATE".into(),
            endpoint: "https://e.com".into(),
            status: "ACTIVE".into(),
            description: None,
            client_id: None,
            passcode: None,
        };
        let c = w.clone();
        assert_eq!(c.id, "wc");
        assert_eq!(w.id, "wc");
    }

    #[test]
    fn webhook_debug() {
        let w = Webhook {
            id: "wdbg".into(),
            team_id: "tdbg".into(),
            event_type: "FILE_UPDATE".into(),
            endpoint: "https://e.com".into(),
            status: "ACTIVE".into(),
            description: None,
            client_id: None,
            passcode: None,
        };
        let dbg = format!("{w:?}");
        assert!(dbg.contains("Webhook"));
        assert!(dbg.contains("wdbg"));
    }

    // ================================================================
    // WebhooksListResponse
    // ================================================================

    #[test]
    fn webhooks_list_response_roundtrip() {
        let resp = WebhooksListResponse {
            webhooks: vec![Webhook {
                id: "w1".into(),
                team_id: "t1".into(),
                event_type: "FILE_UPDATE".into(),
                endpoint: "https://e.com".into(),
                status: "ACTIVE".into(),
                description: None,
                client_id: None,
                passcode: None,
            }],
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: WebhooksListResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.webhooks.len(), 1);
    }

    #[test]
    fn webhooks_list_response_empty() {
        let json = json!({"webhooks": []});
        let resp: WebhooksListResponse = serde_json::from_value(json).unwrap();
        assert!(resp.webhooks.is_empty());
    }

    #[test]
    fn webhooks_list_response_clone_debug() {
        let resp = WebhooksListResponse { webhooks: vec![] };
        let c = resp.clone();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("WebhooksListResponse"));
        assert!(c.webhooks.is_empty());
        assert!(resp.webhooks.is_empty());
    }

    // ================================================================
    // CreateWebhookRequest (Serialize only, skip_serializing_if)
    // ================================================================

    #[test]
    fn create_webhook_request_no_description() {
        let req = CreateWebhookRequest {
            team_id: "t1".to_string(),
            event_type: "FILE_UPDATE".to_string(),
            endpoint: "https://example.com/hook".to_string(),
            passcode: "secret".to_string(),
            description: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("description"));
        assert!(json.contains("team_id"));
        assert!(json.contains("event_type"));
        assert!(json.contains("endpoint"));
        assert!(json.contains("passcode"));
    }

    #[test]
    fn create_webhook_request_with_description() {
        let req = CreateWebhookRequest {
            team_id: "t1".into(),
            event_type: "FILE_UPDATE".into(),
            endpoint: "https://example.com/hook".into(),
            passcode: "secret".into(),
            description: Some("My webhook".into()),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("description"));
        assert!(json.contains("My webhook"));
    }

    #[test]
    fn create_webhook_request_clone() {
        let req = CreateWebhookRequest {
            team_id: "t".into(),
            event_type: "e".into(),
            endpoint: "u".into(),
            passcode: "p".into(),
            description: Some("d".into()),
        };
        let c = req.clone();
        assert_eq!(c.team_id, "t");
        assert_eq!(c.description.as_deref(), Some("d"));
        assert_eq!(req.team_id, "t");
    }

    #[test]
    fn create_webhook_request_debug() {
        let req = CreateWebhookRequest {
            team_id: "t".into(),
            event_type: "e".into(),
            endpoint: "u".into(),
            passcode: "p".into(),
            description: None,
        };
        let dbg = format!("{req:?}");
        assert!(dbg.contains("CreateWebhookRequest"));
    }

    // ================================================================
    // Edge cases: empty strings, unicode, special characters
    // ================================================================

    #[test]
    fn project_file_empty_string_fields() {
        let json = json!({
            "key": "",
            "name": "",
            "last_modified": ""
        });
        let file: ProjectFile = serde_json::from_value(json).unwrap();
        assert_eq!(file.key, "");
        assert_eq!(file.name, "");
    }

    #[test]
    fn comment_unicode_message() {
        let json = json!({
            "id": "cu",
            "message": "Great work! \u{1F44D} \u{2764}\u{FE0F}",
            "created_at": "2026-03-05"
        });
        let comment: Comment = serde_json::from_value(json).unwrap();
        assert!(comment.message.contains('\u{1F44D}'));
    }

    #[test]
    fn webhook_endpoint_with_query_params() {
        let json = json!({
            "id": "w",
            "team_id": "t",
            "event_type": "FILE_UPDATE",
            "endpoint": "https://example.com/hook?token=abc&source=figma",
            "status": "ACTIVE"
        });
        let webhook: Webhook = serde_json::from_value(json).unwrap();
        assert!(webhook.endpoint.contains("token=abc"));
    }

    #[test]
    fn design_token_color_zero_alpha() {
        let value = TokenValue::Color {
            r: 1.0,
            g: 1.0,
            b: 1.0,
            a: 0.0,
            hex: "#ffffff00".into(),
        };
        let json = serde_json::to_string(&value).unwrap();
        let back: TokenValue = serde_json::from_str(&json).unwrap();
        match back {
            TokenValue::Color { a, .. } => assert_eq!(a, 0.0),
            _ => panic!("expected Color"),
        }
    }

    #[test]
    fn design_token_typography_zero_font_size() {
        let value = TokenValue::Typography {
            font_family: "Mono".into(),
            font_size: 0.0,
            font_weight: 100.0,
            line_height: Some(0.0),
            letter_spacing: Some(-0.5),
        };
        let json = serde_json::to_string(&value).unwrap();
        let back: TokenValue = serde_json::from_str(&json).unwrap();
        match back {
            TokenValue::Typography {
                font_size,
                letter_spacing,
                ..
            } => {
                assert_eq!(font_size, 0.0);
                assert_eq!(letter_spacing, Some(-0.5));
            }
            _ => panic!("expected Typography"),
        }
    }

    // ================================================================
    // Deserialize from Value round-trips
    // ================================================================

    #[test]
    fn file_response_value_roundtrip() {
        let val = json!({
            "name": "RT",
            "document": {},
            "lastModified": "2026-01-01",
            "version": "1"
        });
        let resp: FileResponse = serde_json::from_value(val.clone()).unwrap();
        let serialized = serde_json::to_value(&resp).unwrap();
        assert_eq!(serialized["name"], "RT");
        assert_eq!(serialized["version"], "1");
        assert_eq!(val["name"], "RT");
    }

    #[test]
    fn comments_response_multiple_comments() {
        let json = json!({
            "comments": [
                {"id": "c1", "message": "first", "created_at": "t1"},
                {"id": "c2", "message": "second", "created_at": "t2"},
                {"id": "c3", "message": "third", "created_at": "t3"}
            ]
        });
        let resp: CommentsResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.comments.len(), 3);
        assert_eq!(resp.comments[0].id, "c1");
        assert_eq!(resp.comments[2].id, "c3");
    }

    #[test]
    fn versions_response_multiple_versions() {
        let json = json!({
            "versions": [
                {"id": "v1", "created_at": "t1"},
                {"id": "v2", "label": "Draft", "created_at": "t2"}
            ]
        });
        let resp: VersionsResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.versions.len(), 2);
        assert!(resp.versions[0].label.is_none());
        assert_eq!(resp.versions[1].label.as_deref(), Some("Draft"));
    }
}
