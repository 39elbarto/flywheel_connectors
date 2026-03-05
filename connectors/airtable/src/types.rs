//! Airtable API types.

use serde::{Deserialize, Serialize};

// ── Base types ─────────────────────────────────────────────────────

/// An Airtable base (workspace/database).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Base {
    pub id: String,
    pub name: String,
    #[serde(default, rename = "permissionLevel")]
    pub permission_level: Option<String>,
}

/// Response for listing bases.
#[derive(Debug, Clone, Deserialize)]
pub struct ListBasesResponse {
    #[serde(default)]
    pub bases: Vec<Base>,
    #[serde(default)]
    pub offset: Option<String>,
}

// ── Schema types ───────────────────────────────────────────────────

/// A table in an Airtable base schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableSchema {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub fields: Vec<FieldSchema>,
    #[serde(default)]
    pub views: Vec<ViewSchema>,
    #[serde(default, rename = "primaryFieldId")]
    pub primary_field_id: Option<String>,
}

/// A field definition in a table schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldSchema {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub options: Option<serde_json::Value>,
}

/// A view in a table schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewSchema {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub view_type: String,
}

/// Response for getting base schema.
#[derive(Debug, Clone, Deserialize)]
pub struct BaseSchemaResponse {
    pub tables: Vec<TableSchema>,
}

// ── Record types ───────────────────────────────────────────────────

/// An Airtable record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    pub fields: serde_json::Value,
    #[serde(default, rename = "createdTime")]
    pub created_time: Option<String>,
}

/// Response for listing records.
#[derive(Debug, Clone, Deserialize)]
pub struct ListRecordsResponse {
    pub records: Vec<Record>,
    #[serde(default)]
    pub offset: Option<String>,
}

/// Response for creating multiple records.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateRecordsResponse {
    pub records: Vec<Record>,
}

/// Response for deleting a record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteRecordResponse {
    pub id: String,
    pub deleted: bool,
}

// ── Sort types ─────────────────────────────────────────────────────

/// Sort specification for listing records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SortSpec {
    pub field: String,
    #[serde(default = "default_sort_direction")]
    pub direction: String,
}

fn default_sort_direction() -> String {
    "asc".into()
}

// ── Attachment types ───────────────────────────────────────────────

/// Downloaded attachment data.
#[derive(Debug, Clone, Serialize)]
pub struct AttachmentDownload {
    pub data: String,
    pub content_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
}

// ── API Error response ─────────────────────────────────────────────

/// Airtable API error response body.
#[derive(Debug, Clone, Deserialize)]
pub struct AirtableApiError {
    #[serde(default)]
    pub error: Option<AirtableErrorDetail>,
}

/// Detail inside an Airtable error response.
#[derive(Debug, Clone, Deserialize)]
pub struct AirtableErrorDetail {
    #[serde(default, rename = "type")]
    pub error_type: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn base_serde() {
        let json = json!({"id": "app123", "name": "My Base", "permissionLevel": "create"});
        let base: Base = serde_json::from_value(json).unwrap();
        assert_eq!(base.id, "app123");
        assert_eq!(base.permission_level.as_deref(), Some("create"));
    }

    #[test]
    fn list_bases_response() {
        let json = json!({"bases": [{"id": "app1", "name": "B1"}], "offset": "abc"});
        let resp: ListBasesResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.bases.len(), 1);
        assert_eq!(resp.offset.as_deref(), Some("abc"));
    }

    #[test]
    fn table_schema_serde() {
        let json = json!({
            "id": "tbl1",
            "name": "Tasks",
            "fields": [{"id": "fld1", "name": "Name", "type": "singleLineText"}],
            "views": [{"id": "viw1", "name": "Grid", "type": "grid"}],
            "primaryFieldId": "fld1"
        });
        let schema: TableSchema = serde_json::from_value(json).unwrap();
        assert_eq!(schema.fields.len(), 1);
        assert_eq!(schema.fields[0].field_type, "singleLineText");
    }

    #[test]
    fn record_serde() {
        let json = json!({"id": "rec1", "fields": {"Name": "Task 1"}, "createdTime": "2026-03-01"});
        let rec: Record = serde_json::from_value(json).unwrap();
        assert_eq!(rec.id, "rec1");
        assert!(rec.created_time.is_some());
    }

    #[test]
    fn list_records_response() {
        let json = json!({"records": [], "offset": "next"});
        let resp: ListRecordsResponse = serde_json::from_value(json).unwrap();
        assert!(resp.records.is_empty());
        assert_eq!(resp.offset.as_deref(), Some("next"));
    }

    #[test]
    fn delete_record_response() {
        let resp = DeleteRecordResponse {
            id: "rec1".to_string(),
            deleted: true,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: DeleteRecordResponse = serde_json::from_str(&json).unwrap();
        assert!(back.deleted);
    }

    #[test]
    fn sort_spec_default_direction() {
        let json = r#"{"field":"Name"}"#;
        let sort: SortSpec = serde_json::from_str(json).unwrap();
        assert_eq!(sort.direction, "asc");
    }

    #[test]
    fn attachment_download_serialize() {
        let dl = AttachmentDownload {
            data: "base64data".to_string(),
            content_type: "image/png".to_string(),
            filename: None,
        };
        let json = serde_json::to_string(&dl).unwrap();
        assert!(!json.contains("filename"));
    }

    #[test]
    fn airtable_api_error() {
        let json = json!({"error": {"type": "INVALID_REQUEST", "message": "Bad field"}});
        let err: AirtableApiError = serde_json::from_value(json).unwrap();
        let detail = err.error.unwrap();
        assert_eq!(detail.error_type.as_deref(), Some("INVALID_REQUEST"));
    }

    // ── Additional edge case tests ──────────────────────────────

    #[test]
    fn base_missing_permission_level() {
        let json = json!({"id": "app1", "name": "Test"});
        let base: Base = serde_json::from_value(json).unwrap();
        assert!(base.permission_level.is_none());
    }

    #[test]
    fn base_clone_and_debug() {
        let base = Base {
            id: "app1".into(),
            name: "Test".into(),
            permission_level: Some("owner".into()),
        };
        let cloned = base.clone();
        assert_eq!(cloned.id, "app1");
        assert!(format!("{base:?}").contains("app1"));
    }

    #[test]
    fn base_roundtrip() {
        let base = Base {
            id: "app1".into(),
            name: "My Base".into(),
            permission_level: Some("editor".into()),
        };
        let json = serde_json::to_value(&base).unwrap();
        assert_eq!(json["permissionLevel"], "editor");
        let back: Base = serde_json::from_value(json).unwrap();
        assert_eq!(back.id, "app1");
    }

    #[test]
    fn list_bases_empty() {
        let json = json!({"bases": []});
        let resp: ListBasesResponse = serde_json::from_value(json).unwrap();
        assert!(resp.bases.is_empty());
        assert!(resp.offset.is_none());
    }

    #[test]
    fn table_schema_minimal() {
        let json = json!({"id": "tbl1", "name": "T1"});
        let schema: TableSchema = serde_json::from_value(json).unwrap();
        assert!(schema.fields.is_empty());
        assert!(schema.views.is_empty());
        assert!(schema.description.is_none());
        assert!(schema.primary_field_id.is_none());
    }

    #[test]
    fn table_schema_roundtrip() {
        let schema = TableSchema {
            id: "tbl1".into(),
            name: "Tasks".into(),
            description: Some("A task table".into()),
            fields: vec![FieldSchema {
                id: "fld1".into(),
                name: "Name".into(),
                field_type: "singleLineText".into(),
                description: None,
                options: None,
            }],
            views: vec![ViewSchema {
                id: "viw1".into(),
                name: "Grid".into(),
                view_type: "grid".into(),
            }],
            primary_field_id: Some("fld1".into()),
        };
        let json = serde_json::to_value(&schema).unwrap();
        let back: TableSchema = serde_json::from_value(json).unwrap();
        assert_eq!(back.fields.len(), 1);
        assert_eq!(back.views[0].view_type, "grid");
    }

    #[test]
    fn field_schema_with_options() {
        let json = json!({
            "id": "fld1",
            "name": "Status",
            "type": "singleSelect",
            "description": "Current status",
            "options": {"choices": [{"name": "Done"}, {"name": "Todo"}]}
        });
        let field: FieldSchema = serde_json::from_value(json).unwrap();
        assert_eq!(field.field_type, "singleSelect");
        assert!(field.options.is_some());
        assert!(field.description.is_some());
    }

    #[test]
    fn field_schema_clone_and_debug() {
        let field = FieldSchema {
            id: "fld1".into(),
            name: "Name".into(),
            field_type: "text".into(),
            description: None,
            options: None,
        };
        let cloned = field.clone();
        assert_eq!(cloned.name, "Name");
        assert!(format!("{field:?}").contains("fld1"));
    }

    #[test]
    fn view_schema_debug() {
        let view = ViewSchema {
            id: "viw1".into(),
            name: "Calendar".into(),
            view_type: "calendar".into(),
        };
        let dbg = format!("{view:?}");
        assert!(dbg.contains("calendar"));
    }

    #[test]
    fn base_schema_response_empty_tables() {
        let json = json!({"tables": []});
        let resp: BaseSchemaResponse = serde_json::from_value(json).unwrap();
        assert!(resp.tables.is_empty());
    }

    #[test]
    fn record_missing_created_time() {
        let json = json!({"id": "rec1", "fields": {}});
        let rec: Record = serde_json::from_value(json).unwrap();
        assert!(rec.created_time.is_none());
    }

    #[test]
    fn record_roundtrip() {
        let rec = Record {
            id: "rec1".into(),
            fields: json!({"Name": "Test", "Count": 42}),
            created_time: Some("2026-03-01T00:00:00Z".into()),
        };
        let json = serde_json::to_value(&rec).unwrap();
        assert_eq!(json["createdTime"], "2026-03-01T00:00:00Z");
        let back: Record = serde_json::from_value(json).unwrap();
        assert_eq!(back.fields["Count"], 42);
    }

    #[test]
    fn list_records_no_offset() {
        let json = json!({"records": [{"id": "rec1", "fields": {}}]});
        let resp: ListRecordsResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.records.len(), 1);
        assert!(resp.offset.is_none());
    }

    #[test]
    fn create_records_response() {
        let json = json!({"records": [{"id": "rec1", "fields": {"Name": "A"}}]});
        let resp: CreateRecordsResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.records.len(), 1);
    }

    #[test]
    fn delete_record_response_roundtrip() {
        let json = json!({"id": "rec1", "deleted": false});
        let resp: DeleteRecordResponse = serde_json::from_value(json).unwrap();
        assert!(!resp.deleted);
    }

    #[test]
    fn sort_spec_explicit_direction() {
        let json = json!({"field": "Name", "direction": "desc"});
        let sort: SortSpec = serde_json::from_value(json).unwrap();
        assert_eq!(sort.direction, "desc");
    }

    #[test]
    fn sort_spec_roundtrip() {
        let spec = SortSpec {
            field: "Status".into(),
            direction: "asc".into(),
        };
        let json = serde_json::to_value(&spec).unwrap();
        let back: SortSpec = serde_json::from_value(json).unwrap();
        assert_eq!(back.field, "Status");
    }

    #[test]
    fn attachment_download_with_filename() {
        let dl = AttachmentDownload {
            data: "base64data".to_string(),
            content_type: "application/pdf".to_string(),
            filename: Some("doc.pdf".into()),
        };
        let json = serde_json::to_string(&dl).unwrap();
        assert!(json.contains("doc.pdf"));
        assert!(json.contains("filename"));
    }

    #[test]
    fn airtable_api_error_no_error_field() {
        let json = json!({});
        let err: AirtableApiError = serde_json::from_value(json).unwrap();
        assert!(err.error.is_none());
    }

    #[test]
    fn airtable_error_detail_missing_fields() {
        let json = json!({});
        let detail: AirtableErrorDetail = serde_json::from_value(json).unwrap();
        assert!(detail.error_type.is_none());
        assert!(detail.message.is_none());
    }

    #[test]
    fn airtable_api_error_debug() {
        let err = AirtableApiError {
            error: Some(AirtableErrorDetail {
                error_type: Some("TEST".into()),
                message: Some("msg".into()),
            }),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("TEST"));
    }

    #[test]
    fn list_bases_response_clone() {
        let resp = ListBasesResponse {
            bases: vec![Base {
                id: "app1".into(),
                name: "B1".into(),
                permission_level: None,
            }],
            offset: Some("next".into()),
        };
        let cloned = resp.clone();
        assert_eq!(cloned.bases.len(), 1);
        assert_eq!(cloned.offset.as_deref(), Some("next"));
    }

    #[test]
    fn base_schema_response_clone() {
        let resp = BaseSchemaResponse {
            tables: vec![TableSchema {
                id: "tbl1".into(),
                name: "T".into(),
                description: None,
                fields: vec![],
                views: vec![],
                primary_field_id: None,
            }],
        };
        let cloned = resp.clone();
        assert_eq!(cloned.tables.len(), 1);
    }

    #[test]
    fn record_clone() {
        let rec = Record {
            id: "rec1".into(),
            fields: json!({}),
            created_time: None,
        };
        let cloned = rec.clone();
        assert_eq!(cloned.id, "rec1");
    }
}
