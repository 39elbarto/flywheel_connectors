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

    // ── Clone trait tests ───────────────────────────────────────

    #[test]
    fn document_clone() {
        let d: Document = serde_json::from_value(json!({
            "id": "doc1", "name": "NDA", "status": "document.draft"
        }))
        .unwrap();
        let c = d.clone();
        assert_eq!(c.id, d.id);
        assert_eq!(c.name, d.name);
    }

    #[test]
    fn document_list_clone() {
        let dl: DocumentList = serde_json::from_value(json!({
            "results": [{"id": "d1"}]
        }))
        .unwrap();
        let c = dl.clone();
        assert_eq!(c.results.len(), 1);
        assert_eq!(dl.results.len(), 1);
    }

    #[test]
    fn document_created_clone() {
        let dc: DocumentCreated = serde_json::from_value(json!({
            "id": "doc1", "status": "document.uploaded"
        }))
        .unwrap();
        let c = dc.clone();
        assert_eq!(c.id, dc.id);
    }

    #[test]
    fn recipient_clone() {
        let r: Recipient = serde_json::from_value(json!({
            "email": "a@b.com", "role": "signer"
        }))
        .unwrap();
        let c = r.clone();
        assert_eq!(c.email, r.email);
        assert_eq!(c.role, r.role);
    }

    #[test]
    fn template_clone() {
        let t: Template = serde_json::from_value(json!({
            "id": "tpl1", "name": "NDA Template"
        }))
        .unwrap();
        let c = t.clone();
        assert_eq!(c.id, t.id);
        assert_eq!(c.name, t.name);
    }

    // ── Debug trait tests ───────────────────────────────────────

    #[test]
    fn document_debug() {
        let d: Document = serde_json::from_value(json!({"id": "x"})).unwrap();
        let dbg = format!("{d:?}");
        assert!(dbg.contains("Document"));
    }

    #[test]
    fn recipient_debug() {
        let r: Recipient = serde_json::from_value(json!({"email": "a@b.com"})).unwrap();
        let dbg = format!("{r:?}");
        assert!(dbg.contains("Recipient"));
    }

    #[test]
    fn template_debug() {
        let t: Template = serde_json::from_value(json!({"id": "x"})).unwrap();
        let dbg = format!("{t:?}");
        assert!(dbg.contains("Template"));
    }

    #[test]
    fn document_sent_debug() {
        let ds: DocumentSent = serde_json::from_value(json!({})).unwrap();
        let dbg = format!("{ds:?}");
        assert!(dbg.contains("DocumentSent"));
    }

    // ── Serialize roundtrip tests ───────────────────────────────

    #[test]
    fn document_serialize_roundtrip() {
        let d: Document = serde_json::from_value(json!({
            "id": "doc_rt", "name": "RT Test",
            "status": "document.sent",
            "date_created": "2026-01-01",
            "date_modified": "2026-02-01",
            "expiration_date": "2026-12-31",
            "version": "2"
        }))
        .unwrap();
        let serialized = serde_json::to_value(&d).unwrap();
        let back: Document = serde_json::from_value(serialized).unwrap();
        assert_eq!(back.id, "doc_rt");
        assert_eq!(back.version, Some("2".into()));
        assert_eq!(back.expiration_date, Some("2026-12-31".into()));
    }

    #[test]
    fn document_created_serialize_roundtrip() {
        let dc: DocumentCreated = serde_json::from_value(json!({
            "id": "dc_rt", "status": "document.uploaded",
            "name": "Test", "uuid": "u1"
        }))
        .unwrap();
        let serialized = serde_json::to_value(&dc).unwrap();
        let back: DocumentCreated = serde_json::from_value(serialized).unwrap();
        assert_eq!(back.uuid, Some("u1".into()));
    }

    #[test]
    fn document_sent_serialize_roundtrip() {
        let ds: DocumentSent = serde_json::from_value(json!({
            "id": "ds_rt", "status": "document.sent"
        }))
        .unwrap();
        let serialized = serde_json::to_value(&ds).unwrap();
        let back: DocumentSent = serde_json::from_value(serialized).unwrap();
        assert_eq!(back.id, Some("ds_rt".into()));
    }

    #[test]
    fn recipient_serialize_roundtrip() {
        let r: Recipient = serde_json::from_value(json!({
            "email": "test@example.com",
            "role": "approver",
            "first_name": "Test",
            "last_name": "User"
        }))
        .unwrap();
        let serialized = serde_json::to_value(&r).unwrap();
        let back: Recipient = serde_json::from_value(serialized).unwrap();
        assert_eq!(back.last_name, Some("User".into()));
    }

    #[test]
    fn template_serialize_roundtrip() {
        let t: Template = serde_json::from_value(json!({
            "id": "tpl_rt", "name": "Invoice Template",
            "date_created": "2026-01-01",
            "date_modified": "2026-03-01",
            "version": "3"
        }))
        .unwrap();
        let serialized = serde_json::to_value(&t).unwrap();
        let back: Template = serde_json::from_value(serialized).unwrap();
        assert_eq!(back.version, Some("3".into()));
        assert_eq!(back.date_modified, Some("2026-03-01".into()));
    }

    #[test]
    fn template_list_serialize_roundtrip() {
        let tl: TemplateList = serde_json::from_value(json!({
            "results": [{"id": "t1"}, {"id": "t2"}, {"id": "t3"}]
        }))
        .unwrap();
        let serialized = serde_json::to_value(&tl).unwrap();
        let back: TemplateList = serde_json::from_value(serialized).unwrap();
        assert_eq!(back.results.len(), 3);
    }

    // ── Edge cases ──────────────────────────────────────────────

    #[test]
    fn document_empty_string_id() {
        let d: Document = serde_json::from_value(json!({"id": ""})).unwrap();
        assert_eq!(d.id, "");
    }

    #[test]
    fn document_all_none_fields() {
        let d: Document = serde_json::from_value(json!({"id": "x"})).unwrap();
        assert!(d.name.is_none());
        assert!(d.status.is_none());
        assert!(d.date_created.is_none());
        assert!(d.date_modified.is_none());
        assert!(d.expiration_date.is_none());
        assert!(d.version.is_none());
    }

    #[test]
    fn document_list_many_results() {
        let results: Vec<serde_json::Value> =
            (0..50).map(|i| json!({"id": format!("doc_{i}")})).collect();
        let dl: DocumentList = serde_json::from_value(json!({"results": results})).unwrap();
        assert_eq!(dl.results.len(), 50);
    }

    #[test]
    fn recipient_empty_string_email() {
        let r: Recipient = serde_json::from_value(json!({"email": ""})).unwrap();
        assert_eq!(r.email, "");
    }

    #[test]
    fn api_error_response_type_rename() {
        // Verify the #[serde(rename = "type")] works
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "type": "validation_error"
        }))
        .unwrap();
        assert_eq!(e.error_type, Some("validation_error".into()));
    }

    #[test]
    fn api_error_response_debug() {
        let e: ApiErrorResponse = serde_json::from_value(json!({"detail": "err"})).unwrap();
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ApiErrorResponse"));
    }

    #[test]
    fn api_error_response_clone() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "detail": "test", "status": 400
        }))
        .unwrap();
        let c = e.clone();
        assert_eq!(c.detail, e.detail);
        assert_eq!(c.status, e.status);
    }
}
