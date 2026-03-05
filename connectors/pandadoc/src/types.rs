//! `PandaDoc` API types.

use serde::{Deserialize, Serialize};

/// A `PandaDoc` document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Document {
    pub id: String,
    pub name: Option<String>,
    pub status: Option<String>,
    pub date_created: Option<String>,
    pub date_modified: Option<String>,
    pub expiration_date: Option<String>,
    pub version: Option<String>,
}

/// List documents response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentList {
    pub results: Vec<serde_json::Value>,
}

/// Document creation response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentCreated {
    pub id: String,
    pub status: Option<String>,
    pub name: Option<String>,
    pub uuid: Option<String>,
}

/// Document send response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentSent {
    pub id: Option<String>,
    pub status: Option<String>,
}

/// A recipient for a document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recipient {
    pub email: String,
    pub role: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

/// A `PandaDoc` template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Template {
    pub id: String,
    pub name: Option<String>,
    pub date_created: Option<String>,
    pub date_modified: Option<String>,
    pub version: Option<String>,
}

/// List templates response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateList {
    pub results: Vec<serde_json::Value>,
}

/// `PandaDoc` API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    #[serde(rename = "type")]
    pub error_type: Option<String>,
    pub detail: Option<String>,
    pub status: Option<u16>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn document_roundtrip() {
        let d: Document = serde_json::from_value(json!({
            "id": "doc_abc123",
            "name": "Test NDA",
            "status": "document.draft",
            "date_created": "2026-03-01T00:00:00Z",
            "date_modified": "2026-03-01T12:00:00Z",
        }))
        .unwrap();
        assert_eq!(d.id, "doc_abc123");
        assert_eq!(d.name, Some("Test NDA".into()));
        assert_eq!(d.status, Some("document.draft".into()));
        let re = serde_json::to_value(&d).unwrap();
        assert_eq!(re["name"], "Test NDA");
    }

    #[test]
    fn document_minimal() {
        let d: Document = serde_json::from_value(json!({"id": "x"})).unwrap();
        assert_eq!(d.id, "x");
        assert!(d.name.is_none());
        assert!(d.status.is_none());
    }

    #[test]
    fn document_list_roundtrip() {
        let dl: DocumentList = serde_json::from_value(json!({
            "results": [
                {"id": "d1", "name": "Doc 1", "status": "document.draft"},
                {"id": "d2", "name": "Doc 2", "status": "document.sent"},
            ]
        }))
        .unwrap();
        assert_eq!(dl.results.len(), 2);
    }

    #[test]
    fn document_list_empty() {
        let dl: DocumentList = serde_json::from_value(json!({"results": []})).unwrap();
        assert!(dl.results.is_empty());
    }

    #[test]
    fn document_created_roundtrip() {
        let dc: DocumentCreated = serde_json::from_value(json!({
            "id": "new_doc_123",
            "status": "document.uploaded",
            "name": "My NDA",
            "uuid": "uuid-abc",
        }))
        .unwrap();
        assert_eq!(dc.id, "new_doc_123");
        assert_eq!(dc.status, Some("document.uploaded".into()));
    }

    #[test]
    fn document_created_minimal() {
        let dc: DocumentCreated = serde_json::from_value(json!({"id": "x"})).unwrap();
        assert_eq!(dc.id, "x");
        assert!(dc.status.is_none());
    }

    #[test]
    fn document_sent_roundtrip() {
        let ds: DocumentSent = serde_json::from_value(json!({
            "id": "doc_abc",
            "status": "document.sent",
        }))
        .unwrap();
        assert_eq!(ds.id, Some("doc_abc".into()));
        assert_eq!(ds.status, Some("document.sent".into()));
    }

    #[test]
    fn document_sent_empty() {
        let ds: DocumentSent = serde_json::from_value(json!({})).unwrap();
        assert!(ds.id.is_none());
        assert!(ds.status.is_none());
    }

    #[test]
    fn recipient_roundtrip() {
        let r: Recipient = serde_json::from_value(json!({
            "email": "bob@acme.com",
            "role": "signer",
            "first_name": "Bob",
            "last_name": "Smith",
        }))
        .unwrap();
        assert_eq!(r.email, "bob@acme.com");
        assert_eq!(r.role, Some("signer".into()));
        let re = serde_json::to_value(&r).unwrap();
        assert_eq!(re["first_name"], "Bob");
    }

    #[test]
    fn recipient_minimal() {
        let r: Recipient = serde_json::from_value(json!({"email": "a@b.com"})).unwrap();
        assert_eq!(r.email, "a@b.com");
        assert!(r.role.is_none());
    }

    #[test]
    fn template_roundtrip() {
        let t: Template = serde_json::from_value(json!({
            "id": "tpl_abc123",
            "name": "Standard NDA",
            "date_created": "2026-01-15T00:00:00Z",
        }))
        .unwrap();
        assert_eq!(t.id, "tpl_abc123");
        assert_eq!(t.name, Some("Standard NDA".into()));
    }

    #[test]
    fn template_minimal() {
        let t: Template = serde_json::from_value(json!({"id": "x"})).unwrap();
        assert_eq!(t.id, "x");
        assert!(t.name.is_none());
    }

    #[test]
    fn template_list_roundtrip() {
        let tl: TemplateList = serde_json::from_value(json!({
            "results": [
                {"id": "t1", "name": "NDA Template"},
                {"id": "t2", "name": "Invoice Template"},
            ]
        }))
        .unwrap();
        assert_eq!(tl.results.len(), 2);
    }

    #[test]
    fn template_list_empty() {
        let tl: TemplateList = serde_json::from_value(json!({"results": []})).unwrap();
        assert!(tl.results.is_empty());
    }

    #[test]
    fn api_error_response_with_detail() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "type": "request_error",
            "detail": "Document not found",
            "status": 404,
        }))
        .unwrap();
        assert_eq!(e.detail, Some("Document not found".into()));
        assert_eq!(e.status, Some(404));
        assert_eq!(e.error_type, Some("request_error".into()));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.detail.is_none());
        assert!(e.status.is_none());
        assert!(e.error_type.is_none());
    }
}
