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

    // ---- FigmaErrorResponse ----

    #[test]
    fn error_response_with_alias() {
        let json = r#"{"status":404,"err":"Not found"}"#;
        let resp: FigmaErrorResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.status, Some(404));
        assert_eq!(resp.message.as_deref(), Some("Not found"));
    }

    #[test]
    fn error_response_minimal() {
        let json = "{}";
        let resp: FigmaErrorResponse = serde_json::from_str(json).unwrap();
        assert!(resp.status.is_none());
        assert!(resp.message.is_none());
    }

    // ---- TeamProjectsResponse ----

    #[test]
    fn team_projects_response_serde() {
        let resp = TeamProjectsResponse {
            name: "My Team".to_string(),
            projects: vec![Project {
                id: 1,
                name: "Project A".to_string(),
            }],
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: TeamProjectsResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.projects.len(), 1);
        assert_eq!(back.projects[0].id, 1);
    }

    // ---- ProjectFile ----

    #[test]
    fn project_file_serde() {
        let json = json!({
            "key": "abc123",
            "name": "Design System",
            "last_modified": "2026-03-01T00:00:00Z"
        });
        let file: ProjectFile = serde_json::from_value(json).unwrap();
        assert_eq!(file.key, "abc123");
        assert!(file.thumbnail_url.is_none());
    }

    // ---- FileResponse (camelCase) ----

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
    }

    // ---- DesignToken + TokenValue ----

    #[test]
    fn design_token_color_serde() {
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
        match &back.value {
            TokenValue::Color { hex, .. } => assert_eq!(hex, "#ff8000ff"),
            _ => panic!("expected Color"),
        }
    }

    #[test]
    fn design_token_typography_serde() {
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
            TokenValue::Typography { font_family, .. } => assert_eq!(font_family, "Inter"),
            _ => panic!("expected Typography"),
        }
    }

    #[test]
    fn design_token_effect_serde() {
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
            TokenValue::Effect { effect_type, .. } => assert_eq!(effect_type, "DROP_SHADOW"),
            _ => panic!("expected Effect"),
        }
    }

    #[test]
    fn design_token_grid_serde() {
        let value = TokenValue::Grid {
            pattern: "COLUMNS".to_string(),
            size: Some(8.0),
            gutter: Some(16.0),
            count: Some(12.0),
        };
        let json = serde_json::to_string(&value).unwrap();
        let back: TokenValue = serde_json::from_str(&json).unwrap();
        match back {
            TokenValue::Grid { pattern, .. } => assert_eq!(pattern, "COLUMNS"),
            _ => panic!("expected Grid"),
        }
    }

    #[test]
    fn design_token_raw_serde() {
        let value = TokenValue::Raw {
            data: json!({"custom": true}),
        };
        let json = serde_json::to_string(&value).unwrap();
        let back: TokenValue = serde_json::from_str(&json).unwrap();
        match back {
            TokenValue::Raw { data } => assert_eq!(data["custom"], true),
            _ => panic!("expected Raw"),
        }
    }

    // ---- FileVersion ----

    #[test]
    fn file_version_serde() {
        let json = json!({
            "id": "v1",
            "label": "Final",
            "description": "Ready for handoff",
            "user": {"handle": "alice", "img_url": null, "id": "u1"},
            "created_at": "2026-03-01T00:00:00Z"
        });
        let ver: FileVersion = serde_json::from_value(json).unwrap();
        assert_eq!(ver.label.as_deref(), Some("Final"));
        assert!(ver.user.is_some());
    }

    // ---- Comment ----

    #[test]
    fn comment_serde() {
        let json = json!({
            "id": "c1",
            "message": "Looks great!",
            "created_at": "2026-03-03T00:00:00Z"
        });
        let comment: Comment = serde_json::from_value(json).unwrap();
        assert_eq!(comment.message, "Looks great!");
        assert!(comment.resolved_at.is_none());
        assert!(comment.parent_id.is_none());
    }

    // ---- Webhook ----

    #[test]
    fn webhook_serde() {
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
        assert_eq!(back.event_type, "FILE_UPDATE");
        assert_eq!(back.status, "ACTIVE");
    }

    // ---- CreateWebhookRequest ----

    #[test]
    fn create_webhook_request_serialize() {
        let req = CreateWebhookRequest {
            team_id: "t1".to_string(),
            event_type: "FILE_UPDATE".to_string(),
            endpoint: "https://example.com/hook".to_string(),
            passcode: "secret".to_string(),
            description: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("description"));
    }

    // ---- ExportImagesResponse ----

    #[test]
    fn export_images_response_serde() {
        let json = json!({
            "images": {"1:2": "https://example.com/img.png"},
            "err": null
        });
        let resp: ExportImagesResponse = serde_json::from_value(json).unwrap();
        assert!(resp.err.is_none());
    }
}
