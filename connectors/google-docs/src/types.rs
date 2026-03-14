//! Google Docs API v1 data types.

use serde::{Deserialize, Serialize};

/// A Google Docs document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Document {
    pub document_id: String,
    pub title: String,
    #[serde(default)]
    pub revision_id: String,
    #[serde(default)]
    pub body: Option<DocumentBody>,
}

/// The body of a document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DocumentBody {
    #[serde(default)]
    pub content: Vec<StructuralElement>,
}

/// A structural element in a document body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StructuralElement {
    #[serde(default)]
    pub start_index: u32,
    #[serde(default)]
    pub end_index: u32,
    #[serde(default)]
    pub paragraph: Option<Paragraph>,
    #[serde(default)]
    pub table: Option<serde_json::Value>,
    #[serde(default)]
    pub section_break: Option<serde_json::Value>,
}

/// A paragraph element.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Paragraph {
    #[serde(default)]
    pub elements: Vec<ParagraphElement>,
    #[serde(default)]
    pub paragraph_style: Option<ParagraphStyle>,
}

/// An element within a paragraph.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ParagraphElement {
    #[serde(default)]
    pub start_index: u32,
    #[serde(default)]
    pub end_index: u32,
    #[serde(default)]
    pub text_run: Option<TextRun>,
}

/// A text run within a paragraph element.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TextRun {
    pub content: String,
    #[serde(default)]
    pub text_style: Option<TextStyle>,
}

/// Text styling properties.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TextStyle {
    #[serde(default)]
    pub bold: Option<bool>,
    #[serde(default)]
    pub italic: Option<bool>,
    #[serde(default)]
    pub underline: Option<bool>,
    #[serde(default)]
    pub font_size: Option<Dimension>,
    #[serde(default)]
    pub foreground_color: Option<OptionalColor>,
}

/// A dimension value (used for font sizes).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Dimension {
    pub magnitude: f64,
    pub unit: String,
}

/// An optional color wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OptionalColor {
    pub color: Option<Color>,
}

/// An RGB color.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Color {
    #[serde(default)]
    pub red: f32,
    #[serde(default)]
    pub green: f32,
    #[serde(default)]
    pub blue: f32,
}

/// Paragraph style.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ParagraphStyle {
    #[serde(default)]
    pub named_style_type: String,
}

/// A batch update request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchUpdateRequest {
    pub requests: Vec<Request>,
}

/// Response from batch update.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchUpdateResponse {
    pub document_id: String,
    #[serde(default)]
    pub replies: Vec<serde_json::Value>,
}

/// A single request within a batch update.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Request {
    /// Insert text at a location.
    InsertText {
        location: Location,
        text: String,
    },
    /// Delete content within a range.
    DeleteContentRange {
        range: Range,
    },
    /// Update text style within a range.
    UpdateTextStyle {
        range: Range,
        text_style: TextStyle,
        fields: String,
    },
}

/// A location in a document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Location {
    pub index: u32,
    #[serde(default)]
    pub segment_id: Option<String>,
}

/// A range in a document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Range {
    pub start_index: u32,
    pub end_index: u32,
    #[serde(default)]
    pub segment_id: Option<String>,
}

/// Google Docs API error response.
#[derive(Debug, Deserialize)]
pub(crate) struct ApiErrorResponse {
    pub error: ApiErrorDetail,
}

/// Error detail from the API.
#[derive(Debug, Deserialize)]
pub(crate) struct ApiErrorDetail {
    pub code: u16,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_serde() {
        let json = r#"{
            "documentId": "abc123",
            "title": "Test Doc",
            "revisionId": "rev1",
            "body": {
                "content": [{
                    "startIndex": 0,
                    "endIndex": 10,
                    "paragraph": {
                        "elements": [{
                            "startIndex": 0,
                            "endIndex": 10,
                            "textRun": {"content": "Hello world"}
                        }]
                    }
                }]
            }
        }"#;
        let doc: Document = serde_json::from_str(json).unwrap();
        assert_eq!(doc.document_id, "abc123");
        assert_eq!(doc.title, "Test Doc");
        let body = doc.body.unwrap();
        assert_eq!(body.content.len(), 1);
        let para = body.content[0].paragraph.as_ref().unwrap();
        assert_eq!(
            para.elements[0].text_run.as_ref().unwrap().content,
            "Hello world"
        );
    }

    #[test]
    fn document_minimal() {
        let json = r#"{"documentId": "x", "title": "Y"}"#;
        let doc: Document = serde_json::from_str(json).unwrap();
        assert_eq!(doc.document_id, "x");
        assert!(doc.body.is_none());
    }

    #[test]
    fn batch_update_response_serde() {
        let json = r#"{"documentId": "abc", "replies": [{}]}"#;
        let resp: BatchUpdateResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.document_id, "abc");
        assert_eq!(resp.replies.len(), 1);
    }

    #[test]
    fn api_error_response_serde() {
        let json = r#"{"error": {"code": 404, "message": "not found"}}"#;
        let er: ApiErrorResponse = serde_json::from_str(json).unwrap();
        assert_eq!(er.error.code, 404);
    }

    #[test]
    fn paragraph_style_debug() {
        let ps = ParagraphStyle {
            named_style_type: "HEADING_1".into(),
        };
        let dbg = format!("{ps:?}");
        assert!(dbg.contains("HEADING_1"));
    }

    #[test]
    fn text_run_content() {
        let tr = TextRun {
            content: "test content".into(),
            text_style: None,
        };
        assert_eq!(tr.content, "test content");
    }

    #[test]
    fn structural_element_with_table() {
        let json = r#"{
            "startIndex": 0,
            "endIndex": 5,
            "table": {"rows": 2, "columns": 3}
        }"#;
        let se: StructuralElement = serde_json::from_str(json).unwrap();
        assert!(se.table.is_some());
        assert!(se.paragraph.is_none());
    }

    #[test]
    fn batch_update_request_serde() {
        let req = BatchUpdateRequest {
            requests: vec![Request::InsertText {
                location: Location {
                    index: 1,
                    segment_id: None,
                },
                text: "hi".into(),
            }],
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("insertText"));
    }

    #[test]
    fn text_style_serde() {
        let json = r#"{
            "bold": true,
            "italic": false,
            "underline": true,
            "fontSize": {"magnitude": 12.0, "unit": "PT"},
            "foregroundColor": {"color": {"red": 1.0, "green": 0.0, "blue": 0.0}}
        }"#;
        let ts: TextStyle = serde_json::from_str(json).unwrap();
        assert_eq!(ts.bold, Some(true));
        assert_eq!(ts.italic, Some(false));
        assert_eq!(ts.underline, Some(true));
        let fs = ts.font_size.unwrap();
        assert!((fs.magnitude - 12.0).abs() < f64::EPSILON);
        let fg = ts.foreground_color.unwrap().color.unwrap();
        assert!((fg.red - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn text_style_default() {
        let ts = TextStyle::default();
        assert!(ts.bold.is_none());
        assert!(ts.italic.is_none());
        assert!(ts.underline.is_none());
        assert!(ts.font_size.is_none());
        assert!(ts.foreground_color.is_none());
    }

    #[test]
    fn color_serde() {
        let json = r#"{"red": 0.5, "green": 0.25, "blue": 0.75}"#;
        let c: Color = serde_json::from_str(json).unwrap();
        assert!((c.red - 0.5).abs() < f32::EPSILON);
        assert!((c.green - 0.25).abs() < f32::EPSILON);
        assert!((c.blue - 0.75).abs() < f32::EPSILON);
    }

    #[test]
    fn color_defaults() {
        let json = r"{}";
        let c: Color = serde_json::from_str(json).unwrap();
        assert!((c.red).abs() < f32::EPSILON);
        assert!((c.green).abs() < f32::EPSILON);
        assert!((c.blue).abs() < f32::EPSILON);
    }

    #[test]
    fn location_serde() {
        let loc = Location {
            index: 5,
            segment_id: Some("header".into()),
        };
        let json = serde_json::to_string(&loc).unwrap();
        assert!(json.contains("\"index\":5"));
        assert!(json.contains("header"));
    }

    #[test]
    fn range_serde() {
        let r = Range {
            start_index: 1,
            end_index: 10,
            segment_id: None,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("startIndex"));
        assert!(json.contains("endIndex"));
    }

    #[test]
    fn request_insert_text_serde() {
        let req = Request::InsertText {
            location: Location {
                index: 1,
                segment_id: None,
            },
            text: "Hello".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("insertText"));
        assert!(json.contains("Hello"));
    }

    #[test]
    fn request_delete_content_serde() {
        let req = Request::DeleteContentRange {
            range: Range {
                start_index: 1,
                end_index: 5,
                segment_id: None,
            },
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("deleteContentRange"));
    }

    #[test]
    fn request_update_text_style_serde() {
        let req = Request::UpdateTextStyle {
            range: Range {
                start_index: 1,
                end_index: 10,
                segment_id: None,
            },
            text_style: TextStyle {
                bold: Some(true),
                ..TextStyle::default()
            },
            fields: "bold".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("updateTextStyle"));
        assert!(json.contains("bold"));
    }

    #[test]
    fn text_run_with_style() {
        let json = r#"{
            "content": "styled text",
            "textStyle": {"bold": true, "italic": true}
        }"#;
        let tr: TextRun = serde_json::from_str(json).unwrap();
        assert_eq!(tr.content, "styled text");
        let style = tr.text_style.unwrap();
        assert_eq!(style.bold, Some(true));
        assert_eq!(style.italic, Some(true));
    }

    #[test]
    fn document_body_empty_content() {
        let body = DocumentBody { content: vec![] };
        assert!(body.content.is_empty());
    }

    #[test]
    fn dimension_serde() {
        let json = r#"{"magnitude": 14.0, "unit": "PT"}"#;
        let d: Dimension = serde_json::from_str(json).unwrap();
        assert!((d.magnitude - 14.0).abs() < f64::EPSILON);
        assert_eq!(d.unit, "PT");
    }
}
