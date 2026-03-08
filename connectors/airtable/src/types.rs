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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRecordsResponse {
    pub records: Vec<Record>,
}

/// Response for upserting multiple records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertRecordsResponse {
    pub records: Vec<Record>,
    #[serde(default, rename = "createdRecords")]
    pub created_records: Vec<String>,
    #[serde(default, rename = "updatedRecords")]
    pub updated_records: Vec<String>,
}

/// Response for deleting a record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteRecordResponse {
    pub id: String,
    pub deleted: bool,
}

/// Response for deleting multiple records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteRecordsResponse {
    pub records: Vec<DeleteRecordResponse>,
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
    fn upsert_records_response() {
        let json = json!({
            "records": [{"id": "rec1", "fields": {"Name": "A"}}],
            "createdRecords": ["rec1"],
            "updatedRecords": []
        });
        let resp: UpsertRecordsResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.records.len(), 1);
        assert_eq!(resp.created_records, vec!["rec1"]);
        assert!(resp.updated_records.is_empty());
    }

    #[test]
    fn delete_record_response_roundtrip() {
        let json = json!({"id": "rec1", "deleted": false});
        let resp: DeleteRecordResponse = serde_json::from_value(json).unwrap();
        assert!(!resp.deleted);
    }

    #[test]
    fn delete_records_response_roundtrip() {
        let json = json!({"records": [{"id": "rec1", "deleted": true}]});
        let resp: DeleteRecordsResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.records.len(), 1);
        assert!(resp.records[0].deleted);
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
        assert_eq!(resp.bases.len(), 1);
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
        assert_eq!(resp.tables.len(), 1);
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
        assert_eq!(rec.id, "rec1");
    }

    // ── Additional type coverage ─────────────────────────────────

    #[test]
    fn base_serialize_no_permission_level() {
        let base = Base {
            id: "app1".into(),
            name: "Test".into(),
            permission_level: None,
        };
        let v = serde_json::to_value(&base).unwrap();
        // With #[serde(default)], None should serialize as null
        assert!(v.get("permissionLevel").is_some());
    }

    #[test]
    fn list_bases_response_debug() {
        let resp = ListBasesResponse {
            bases: vec![],
            offset: None,
        };
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("ListBasesResponse"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn table_schema_clone() {
        let schema = TableSchema {
            id: "tbl1".into(),
            name: "Tasks".into(),
            description: Some("desc".into()),
            fields: vec![],
            views: vec![],
            primary_field_id: Some("fld1".into()),
        };
        let cloned = schema.clone();
        assert_eq!(cloned.id, "tbl1");
        assert_eq!(cloned.description, Some("desc".into()));
        assert_eq!(cloned.primary_field_id, Some("fld1".into()));
    }

    #[test]
    fn field_schema_roundtrip() {
        let field = FieldSchema {
            id: "fld1".into(),
            name: "Status".into(),
            field_type: "singleSelect".into(),
            description: Some("Current status".into()),
            options: Some(json!({"choices": [{"name": "Done"}]})),
        };
        let v = serde_json::to_value(&field).unwrap();
        let back: FieldSchema = serde_json::from_value(v).unwrap();
        assert_eq!(back.field_type, "singleSelect");
        assert!(back.options.is_some());
    }

    #[test]
    fn field_schema_minimal_deser() {
        let json = json!({"id": "fld1", "name": "Name", "type": "singleLineText"});
        let field: FieldSchema = serde_json::from_value(json).unwrap();
        assert!(field.description.is_none());
        assert!(field.options.is_none());
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn view_schema_clone() {
        let view = ViewSchema {
            id: "viw1".into(),
            name: "Grid".into(),
            view_type: "grid".into(),
        };
        let cloned = view.clone();
        assert_eq!(cloned.id, "viw1");
        assert_eq!(cloned.view_type, "grid");
    }

    #[test]
    fn view_schema_roundtrip() {
        let view = ViewSchema {
            id: "viw1".into(),
            name: "Kanban".into(),
            view_type: "kanban".into(),
        };
        let v = serde_json::to_value(&view).unwrap();
        assert_eq!(v["type"], "kanban");
        let back: ViewSchema = serde_json::from_value(v).unwrap();
        assert_eq!(back.view_type, "kanban");
    }

    #[test]
    fn record_debug() {
        let rec = Record {
            id: "rec123".into(),
            fields: json!({"Name": "Test"}),
            created_time: Some("2026-01-01".into()),
        };
        let dbg = format!("{rec:?}");
        assert!(dbg.contains("rec123"));
    }

    #[test]
    fn record_empty_fields() {
        let rec = Record {
            id: "rec1".into(),
            fields: json!({}),
            created_time: None,
        };
        let v = serde_json::to_value(&rec).unwrap();
        assert!(v["fields"].as_object().unwrap().is_empty());
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn list_records_response_clone() {
        let resp = ListRecordsResponse {
            records: vec![Record {
                id: "rec1".into(),
                fields: json!({"x": 1}),
                created_time: None,
            }],
            offset: Some("off1".into()),
        };
        let cloned = resp.clone();
        assert_eq!(cloned.records.len(), 1);
        assert_eq!(cloned.offset, Some("off1".into()));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn create_records_response_clone() {
        let resp = CreateRecordsResponse { records: vec![] };
        let cloned = resp.clone();
        assert!(cloned.records.is_empty());
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn upsert_records_response_clone() {
        let resp = UpsertRecordsResponse {
            records: vec![],
            created_records: vec!["recA".into()],
            updated_records: vec!["recB".into()],
        };
        let cloned = resp.clone();
        assert_eq!(cloned.created_records, vec!["recA"]);
        assert_eq!(cloned.updated_records, vec!["recB"]);
    }

    #[test]
    fn create_records_response_debug() {
        let resp = CreateRecordsResponse {
            records: vec![Record {
                id: "rec1".into(),
                fields: json!({}),
                created_time: None,
            }],
        };
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("CreateRecordsResponse"));
    }

    #[test]
    fn upsert_records_response_debug() {
        let resp = UpsertRecordsResponse {
            records: vec![Record {
                id: "rec1".into(),
                fields: json!({}),
                created_time: None,
            }],
            created_records: vec!["rec1".into()],
            updated_records: vec![],
        };
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("UpsertRecordsResponse"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn delete_record_response_clone() {
        let resp = DeleteRecordResponse {
            id: "rec1".into(),
            deleted: true,
        };
        let cloned = resp.clone();
        assert_eq!(cloned.id, "rec1");
        assert!(cloned.deleted);
    }

    #[test]
    fn delete_record_response_debug() {
        let resp = DeleteRecordResponse {
            id: "rec1".into(),
            deleted: false,
        };
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("DeleteRecordResponse"));
        assert!(dbg.contains("rec1"));
    }

    #[test]
    fn delete_records_response_debug() {
        let resp = DeleteRecordsResponse {
            records: vec![DeleteRecordResponse {
                id: "rec1".into(),
                deleted: true,
            }],
        };
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("DeleteRecordsResponse"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn sort_spec_clone() {
        let spec = SortSpec {
            field: "Name".into(),
            direction: "desc".into(),
        };
        let cloned = spec.clone();
        assert_eq!(cloned.field, "Name");
        assert_eq!(cloned.direction, "desc");
    }

    #[test]
    fn sort_spec_debug() {
        let spec = SortSpec {
            field: "Status".into(),
            direction: "asc".into(),
        };
        let dbg = format!("{spec:?}");
        assert!(dbg.contains("SortSpec"));
        assert!(dbg.contains("Status"));
    }

    #[test]
    fn attachment_download_debug() {
        let dl = AttachmentDownload {
            data: "base64".into(),
            content_type: "text/plain".into(),
            filename: Some("file.txt".into()),
        };
        let dbg = format!("{dl:?}");
        assert!(dbg.contains("AttachmentDownload"));
        assert!(dbg.contains("file.txt"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn attachment_download_clone() {
        let dl = AttachmentDownload {
            data: "abc".into(),
            content_type: "image/png".into(),
            filename: None,
        };
        let cloned = dl.clone();
        assert_eq!(cloned.data, "abc");
        assert!(cloned.filename.is_none());
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn airtable_api_error_clone() {
        let err = AirtableApiError {
            error: Some(AirtableErrorDetail {
                error_type: Some("BAD".into()),
                message: Some("msg".into()),
            }),
        };
        let cloned = err.clone();
        let detail = cloned.error.unwrap();
        assert_eq!(detail.error_type, Some("BAD".into()));
        assert_eq!(detail.message, Some("msg".into()));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn airtable_error_detail_clone() {
        let detail = AirtableErrorDetail {
            error_type: Some("X".into()),
            message: None,
        };
        let cloned = detail.clone();
        assert_eq!(cloned.error_type, Some("X".into()));
        assert!(cloned.message.is_none());
    }

    #[test]
    fn base_schema_response_debug() {
        let resp = BaseSchemaResponse { tables: vec![] };
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("BaseSchemaResponse"));
    }

    #[test]
    fn list_records_response_debug() {
        let resp = ListRecordsResponse {
            records: vec![],
            offset: None,
        };
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("ListRecordsResponse"));
    }

    #[test]
    fn multiple_records_deser() {
        let json = json!({
            "records": [
                {"id": "rec1", "fields": {"A": 1}},
                {"id": "rec2", "fields": {"A": 2}},
                {"id": "rec3", "fields": {"A": 3}}
            ]
        });
        let resp: ListRecordsResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.records.len(), 3);
        assert_eq!(resp.records[2].id, "rec3");
    }

    #[test]
    fn sort_spec_serialize_uses_default_direction() {
        let spec = SortSpec {
            field: "Created".into(),
            direction: "asc".into(),
        };
        let v = serde_json::to_value(&spec).unwrap();
        assert_eq!(v["direction"], "asc");
    }

    #[test]
    fn table_schema_with_description() {
        let json = json!({
            "id": "tbl1",
            "name": "Projects",
            "description": "All team projects"
        });
        let schema: TableSchema = serde_json::from_value(json).unwrap();
        assert_eq!(schema.description, Some("All team projects".into()));
    }

    #[test]
    fn attachment_download_skip_serializing_filename_none() {
        let dl = AttachmentDownload {
            data: "d".into(),
            content_type: "c".into(),
            filename: None,
        };
        let serialized = serde_json::to_string(&dl).unwrap();
        assert!(!serialized.contains("filename"));
    }

    #[test]
    fn attachment_download_includes_filename_some() {
        let dl = AttachmentDownload {
            data: "d".into(),
            content_type: "c".into(),
            filename: Some("test.pdf".into()),
        };
        let serialized = serde_json::to_string(&dl).unwrap();
        assert!(serialized.contains("filename"));
        assert!(serialized.contains("test.pdf"));
    }

    #[test]
    fn base_with_all_permission_levels() {
        for level in ["create", "editor", "commenter", "read", "owner"] {
            let json = json!({"id": "app1", "name": "B", "permissionLevel": level});
            let base: Base = serde_json::from_value(json).unwrap();
            assert_eq!(base.permission_level.as_deref(), Some(level));
        }
    }

    #[test]
    fn base_missing_id_fails() {
        let json = json!({"name": "Test"});
        assert!(serde_json::from_value::<Base>(json).is_err());
    }

    #[test]
    fn base_missing_name_fails() {
        let json = json!({"id": "app1"});
        assert!(serde_json::from_value::<Base>(json).is_err());
    }

    #[test]
    fn record_missing_id_fails() {
        let json = json!({"fields": {}});
        assert!(serde_json::from_value::<Record>(json).is_err());
    }

    #[test]
    fn record_missing_fields_fails() {
        let json = json!({"id": "rec1"});
        assert!(serde_json::from_value::<Record>(json).is_err());
    }

    #[test]
    fn table_schema_missing_id_fails() {
        let json = json!({"name": "T"});
        assert!(serde_json::from_value::<TableSchema>(json).is_err());
    }

    #[test]
    fn field_schema_missing_type_fails() {
        let json = json!({"id": "f1", "name": "N"});
        assert!(serde_json::from_value::<FieldSchema>(json).is_err());
    }

    #[test]
    fn view_schema_missing_type_fails() {
        let json = json!({"id": "v1", "name": "V"});
        assert!(serde_json::from_value::<ViewSchema>(json).is_err());
    }

    #[test]
    fn delete_record_response_serialize_roundtrip() {
        let resp = DeleteRecordResponse {
            id: "recDEL".into(),
            deleted: true,
        };
        let json = serde_json::to_value(&resp).unwrap();
        let back: DeleteRecordResponse = serde_json::from_value(json).unwrap();
        assert_eq!(back.id, "recDEL");
        assert!(back.deleted);
    }

    #[test]
    fn upsert_records_response_serialize_roundtrip() {
        let resp = UpsertRecordsResponse {
            records: vec![Record {
                id: "recUPS".into(),
                fields: json!({"External ID": "ext-1"}),
                created_time: None,
            }],
            created_records: vec!["recUPS".into()],
            updated_records: vec!["recOLD".into()],
        };
        let json = serde_json::to_value(&resp).unwrap();
        let back: UpsertRecordsResponse = serde_json::from_value(json).unwrap();
        assert_eq!(back.created_records, vec!["recUPS"]);
        assert_eq!(back.updated_records, vec!["recOLD"]);
    }

    #[test]
    fn delete_records_response_serialize_roundtrip() {
        let resp = DeleteRecordsResponse {
            records: vec![DeleteRecordResponse {
                id: "recDEL".into(),
                deleted: true,
            }],
        };
        let json = serde_json::to_value(&resp).unwrap();
        let back: DeleteRecordsResponse = serde_json::from_value(json).unwrap();
        assert_eq!(back.records[0].id, "recDEL");
        assert!(back.records[0].deleted);
    }

    #[test]
    fn sort_spec_priority_desc_roundtrip() {
        let spec = SortSpec {
            field: "Priority".into(),
            direction: "desc".into(),
        };
        let json = serde_json::to_value(&spec).unwrap();
        let back: SortSpec = serde_json::from_value(json).unwrap();
        assert_eq!(back.field, "Priority");
        assert_eq!(back.direction, "desc");
    }

    #[test]
    fn record_with_complex_fields() {
        let json = json!({
            "id": "recCOMPLEX",
            "fields": {
                "Name": "Test",
                "Score": 99,
                "Tags": ["a", "b"],
                "Details": {"nested": true}
            }
        });
        let rec: Record = serde_json::from_value(json).unwrap();
        assert_eq!(rec.id, "recCOMPLEX");
        assert_eq!(rec.fields["Score"], 99);
        assert!(rec.fields["Tags"].is_array());
        assert!(rec.fields["Details"].is_object());
    }

    #[test]
    fn list_bases_response_with_offset() {
        let json = json!({
            "bases": [{"id": "app1", "name": "B1"}],
            "offset": "itr_offset_123"
        });
        let resp: ListBasesResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.bases.len(), 1);
        assert_eq!(resp.offset.as_deref(), Some("itr_offset_123"));
    }

    #[test]
    fn list_bases_response_empty() {
        let json = json!({"bases": []});
        let resp: ListBasesResponse = serde_json::from_value(json).unwrap();
        assert!(resp.bases.is_empty());
        assert!(resp.offset.is_none());
    }

    #[test]
    fn base_schema_response_with_tables() {
        let json = json!({
            "tables": [
                {"id": "tbl1", "name": "Tasks", "fields": [], "views": []},
                {"id": "tbl2", "name": "People", "fields": [], "views": []}
            ]
        });
        let resp: BaseSchemaResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.tables.len(), 2);
        assert_eq!(resp.tables[1].name, "People");
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn base_clone() {
        let base = Base {
            id: "app1".into(),
            name: "My Base".into(),
            permission_level: Some("owner".into()),
        };
        let cloned = base.clone();
        assert_eq!(cloned.id, "app1");
        assert_eq!(cloned.name, "My Base");
        assert_eq!(cloned.permission_level, Some("owner".into()));
    }

    #[test]
    fn base_debug() {
        let base = Base {
            id: "appDBG".into(),
            name: "Debug Base".into(),
            permission_level: None,
        };
        let dbg = format!("{base:?}");
        assert!(dbg.contains("Base"));
        assert!(dbg.contains("appDBG"));
    }
}
