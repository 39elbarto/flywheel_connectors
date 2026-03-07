//! `BigQuery` API types.

use serde::{Deserialize, Serialize};

/// A `BigQuery` dataset reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetReference {
    #[serde(rename = "datasetId")]
    pub dataset_id: String,
    #[serde(rename = "projectId")]
    pub project_id: Option<String>,
}

/// A `BigQuery` dataset entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetEntry {
    pub kind: Option<String>,
    pub id: Option<String>,
    #[serde(rename = "datasetReference")]
    pub dataset_reference: Option<DatasetReference>,
    #[serde(rename = "friendlyName")]
    pub friendly_name: Option<String>,
    pub location: Option<String>,
}

/// List datasets response from `BigQuery`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetsListResponse {
    pub kind: Option<String>,
    #[serde(default)]
    pub datasets: Vec<serde_json::Value>,
    #[serde(rename = "nextPageToken")]
    pub next_page_token: Option<String>,
}

/// A `BigQuery` table reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableReference {
    #[serde(rename = "projectId")]
    pub project_id: Option<String>,
    #[serde(rename = "datasetId")]
    pub dataset_id: Option<String>,
    #[serde(rename = "tableId")]
    pub table_id: String,
}

/// A `BigQuery` table entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableEntry {
    pub kind: Option<String>,
    pub id: Option<String>,
    #[serde(rename = "tableReference")]
    pub table_reference: Option<TableReference>,
    #[serde(rename = "type")]
    pub table_type: Option<String>,
    #[serde(rename = "creationTime")]
    pub creation_time: Option<String>,
    #[serde(rename = "expirationTime")]
    pub expiration_time: Option<String>,
}

/// List tables response from `BigQuery`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TablesListResponse {
    pub kind: Option<String>,
    #[serde(default)]
    pub tables: Vec<serde_json::Value>,
    #[serde(rename = "totalItems")]
    pub total_items: Option<i64>,
    #[serde(rename = "nextPageToken")]
    pub next_page_token: Option<String>,
}

/// A `BigQuery` job reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobReference {
    #[serde(rename = "projectId")]
    pub project_id: Option<String>,
    #[serde(rename = "jobId")]
    pub job_id: String,
    pub location: Option<String>,
}

/// A `BigQuery` job status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobStatus {
    pub state: Option<String>,
    #[serde(rename = "errorResult")]
    pub error_result: Option<serde_json::Value>,
}

/// A `BigQuery` job entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobEntry {
    pub kind: Option<String>,
    pub id: Option<String>,
    #[serde(rename = "jobReference")]
    pub job_reference: Option<JobReference>,
    pub status: Option<JobStatus>,
    #[serde(rename = "user_email")]
    pub user_email: Option<String>,
}

/// List jobs response from `BigQuery`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobsListResponse {
    pub kind: Option<String>,
    #[serde(default)]
    pub jobs: Vec<serde_json::Value>,
    #[serde(rename = "nextPageToken")]
    pub next_page_token: Option<String>,
}

/// A schema field in a `BigQuery` query result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaField {
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: String,
    pub mode: Option<String>,
}

/// A `BigQuery` query result schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableSchema {
    pub fields: Vec<SchemaField>,
}

/// Query response from `BigQuery`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResponse {
    pub kind: Option<String>,
    pub schema: Option<TableSchema>,
    #[serde(default)]
    pub rows: Vec<serde_json::Value>,
    #[serde(rename = "totalRows")]
    pub total_rows: Option<String>,
    #[serde(rename = "totalBytesProcessed")]
    pub total_bytes_processed: Option<String>,
    #[serde(rename = "jobComplete")]
    pub job_complete: Option<bool>,
    #[serde(rename = "jobReference")]
    pub job_reference: Option<JobReference>,
    #[serde(rename = "cacheHit")]
    pub cache_hit: Option<bool>,
}

/// `BigQuery` API error response body.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    pub error: Option<ApiErrorDetail>,
}

/// `BigQuery` API error detail.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorDetail {
    pub code: Option<i64>,
    pub message: Option<String>,
    pub status: Option<String>,
    #[serde(default)]
    pub errors: Vec<ApiErrorItem>,
}

/// Individual error item in a `BigQuery` API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorItem {
    pub domain: Option<String>,
    pub reason: Option<String>,
    pub message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -- DatasetReference --

    #[test]
    fn dataset_reference_roundtrip() {
        let r: DatasetReference = serde_json::from_value(json!({
            "datasetId": "analytics",
            "projectId": "my-project"
        }))
        .unwrap();
        assert_eq!(r.dataset_id, "analytics");
        assert_eq!(r.project_id, Some("my-project".into()));
        let re = serde_json::to_value(&r).unwrap();
        assert_eq!(re["datasetId"], "analytics");
    }

    #[test]
    fn dataset_reference_minimal() {
        let r: DatasetReference =
            serde_json::from_value(json!({"datasetId": "ds1"})).unwrap();
        assert_eq!(r.dataset_id, "ds1");
        assert!(r.project_id.is_none());
    }

    // -- DatasetEntry --

    #[test]
    fn dataset_entry_roundtrip() {
        let e: DatasetEntry = serde_json::from_value(json!({
            "kind": "bigquery#dataset",
            "id": "my-project:analytics",
            "datasetReference": {"datasetId": "analytics", "projectId": "my-project"},
            "friendlyName": "Analytics Dataset",
            "location": "US"
        }))
        .unwrap();
        assert_eq!(e.kind, Some("bigquery#dataset".into()));
        assert_eq!(e.friendly_name, Some("Analytics Dataset".into()));
        assert_eq!(e.location, Some("US".into()));
        assert!(e.dataset_reference.is_some());
    }

    #[test]
    fn dataset_entry_minimal() {
        let e: DatasetEntry = serde_json::from_value(json!({})).unwrap();
        assert!(e.kind.is_none());
        assert!(e.id.is_none());
        assert!(e.dataset_reference.is_none());
    }

    // -- DatasetsListResponse --

    #[test]
    fn datasets_list_response_roundtrip() {
        let r: DatasetsListResponse = serde_json::from_value(json!({
            "kind": "bigquery#datasetList",
            "datasets": [
                {"id": "proj:ds1", "datasetReference": {"datasetId": "ds1"}},
                {"id": "proj:ds2", "datasetReference": {"datasetId": "ds2"}}
            ],
            "nextPageToken": "abc123"
        }))
        .unwrap();
        assert_eq!(r.datasets.len(), 2);
        assert_eq!(r.next_page_token, Some("abc123".into()));
    }

    #[test]
    fn datasets_list_response_empty() {
        let r: DatasetsListResponse = serde_json::from_value(json!({
            "kind": "bigquery#datasetList"
        }))
        .unwrap();
        assert!(r.datasets.is_empty());
        assert!(r.next_page_token.is_none());
    }

    // -- TableReference --

    #[test]
    fn table_reference_roundtrip() {
        let r: TableReference = serde_json::from_value(json!({
            "projectId": "my-project",
            "datasetId": "analytics",
            "tableId": "events"
        }))
        .unwrap();
        assert_eq!(r.table_id, "events");
        assert_eq!(r.dataset_id, Some("analytics".into()));
        assert_eq!(r.project_id, Some("my-project".into()));
    }

    #[test]
    fn table_reference_minimal() {
        let r: TableReference =
            serde_json::from_value(json!({"tableId": "t1"})).unwrap();
        assert_eq!(r.table_id, "t1");
        assert!(r.project_id.is_none());
        assert!(r.dataset_id.is_none());
    }

    // -- TableEntry --

    #[test]
    fn table_entry_roundtrip() {
        let e: TableEntry = serde_json::from_value(json!({
            "kind": "bigquery#table",
            "id": "proj:ds.tbl",
            "tableReference": {"tableId": "tbl", "datasetId": "ds", "projectId": "proj"},
            "type": "TABLE",
            "creationTime": "1234567890000",
            "expirationTime": "9999999999000"
        }))
        .unwrap();
        assert_eq!(e.kind, Some("bigquery#table".into()));
        assert_eq!(e.table_type, Some("TABLE".into()));
        assert!(e.table_reference.is_some());
        assert_eq!(e.creation_time, Some("1234567890000".into()));
    }

    #[test]
    fn table_entry_minimal() {
        let e: TableEntry = serde_json::from_value(json!({})).unwrap();
        assert!(e.kind.is_none());
        assert!(e.table_type.is_none());
        assert!(e.table_reference.is_none());
    }

    // -- TablesListResponse --

    #[test]
    fn tables_list_response_roundtrip() {
        let r: TablesListResponse = serde_json::from_value(json!({
            "kind": "bigquery#tableList",
            "tables": [
                {"tableReference": {"tableId": "t1"}},
                {"tableReference": {"tableId": "t2"}}
            ],
            "totalItems": 2,
            "nextPageToken": "tok123"
        }))
        .unwrap();
        assert_eq!(r.tables.len(), 2);
        assert_eq!(r.total_items, Some(2));
        assert_eq!(r.next_page_token, Some("tok123".into()));
    }

    #[test]
    fn tables_list_response_empty() {
        let r: TablesListResponse = serde_json::from_value(json!({
            "kind": "bigquery#tableList"
        }))
        .unwrap();
        assert!(r.tables.is_empty());
        assert!(r.total_items.is_none());
    }

    // -- JobReference --

    #[test]
    fn job_reference_roundtrip() {
        let r: JobReference = serde_json::from_value(json!({
            "projectId": "my-project",
            "jobId": "job_abc123",
            "location": "US"
        }))
        .unwrap();
        assert_eq!(r.job_id, "job_abc123");
        assert_eq!(r.project_id, Some("my-project".into()));
        assert_eq!(r.location, Some("US".into()));
    }

    #[test]
    fn job_reference_minimal() {
        let r: JobReference =
            serde_json::from_value(json!({"jobId": "j1"})).unwrap();
        assert_eq!(r.job_id, "j1");
        assert!(r.project_id.is_none());
    }

    // -- JobStatus --

    #[test]
    fn job_status_roundtrip() {
        let s: JobStatus = serde_json::from_value(json!({
            "state": "DONE",
            "errorResult": null
        }))
        .unwrap();
        assert_eq!(s.state, Some("DONE".into()));
        assert!(s.error_result.is_none() || s.error_result == Some(serde_json::Value::Null));
    }

    #[test]
    fn job_status_with_error() {
        let s: JobStatus = serde_json::from_value(json!({
            "state": "DONE",
            "errorResult": {"reason": "invalidQuery", "message": "Syntax error"}
        }))
        .unwrap();
        assert_eq!(s.state, Some("DONE".into()));
        assert!(s.error_result.is_some());
    }

    #[test]
    fn job_status_minimal() {
        let s: JobStatus = serde_json::from_value(json!({})).unwrap();
        assert!(s.state.is_none());
    }

    // -- JobEntry --

    #[test]
    fn job_entry_roundtrip() {
        let e: JobEntry = serde_json::from_value(json!({
            "kind": "bigquery#job",
            "id": "proj:job_123",
            "jobReference": {"jobId": "job_123", "projectId": "proj"},
            "status": {"state": "DONE"},
            "user_email": "user@example.com"
        }))
        .unwrap();
        assert_eq!(e.kind, Some("bigquery#job".into()));
        assert_eq!(e.user_email, Some("user@example.com".into()));
        assert!(e.job_reference.is_some());
        assert!(e.status.is_some());
    }

    #[test]
    fn job_entry_minimal() {
        let e: JobEntry = serde_json::from_value(json!({})).unwrap();
        assert!(e.kind.is_none());
        assert!(e.job_reference.is_none());
        assert!(e.status.is_none());
    }

    // -- JobsListResponse --

    #[test]
    fn jobs_list_response_roundtrip() {
        let r: JobsListResponse = serde_json::from_value(json!({
            "kind": "bigquery#jobList",
            "jobs": [
                {"id": "proj:j1"},
                {"id": "proj:j2"}
            ],
            "nextPageToken": "next123"
        }))
        .unwrap();
        assert_eq!(r.jobs.len(), 2);
        assert_eq!(r.next_page_token, Some("next123".into()));
    }

    #[test]
    fn jobs_list_response_empty() {
        let r: JobsListResponse = serde_json::from_value(json!({
            "kind": "bigquery#jobList"
        }))
        .unwrap();
        assert!(r.jobs.is_empty());
    }

    // -- SchemaField --

    #[test]
    fn schema_field_roundtrip() {
        let f: SchemaField = serde_json::from_value(json!({
            "name": "user_id",
            "type": "STRING",
            "mode": "NULLABLE"
        }))
        .unwrap();
        assert_eq!(f.name, "user_id");
        assert_eq!(f.field_type, "STRING");
        assert_eq!(f.mode, Some("NULLABLE".into()));
    }

    #[test]
    fn schema_field_minimal() {
        let f: SchemaField = serde_json::from_value(json!({
            "name": "col",
            "type": "INTEGER"
        }))
        .unwrap();
        assert_eq!(f.name, "col");
        assert_eq!(f.field_type, "INTEGER");
        assert!(f.mode.is_none());
    }

    // -- TableSchema --

    #[test]
    fn table_schema_roundtrip() {
        let s: TableSchema = serde_json::from_value(json!({
            "fields": [
                {"name": "id", "type": "INTEGER"},
                {"name": "name", "type": "STRING", "mode": "REQUIRED"}
            ]
        }))
        .unwrap();
        assert_eq!(s.fields.len(), 2);
        assert_eq!(s.fields[0].name, "id");
        assert_eq!(s.fields[1].mode, Some("REQUIRED".into()));
    }

    #[test]
    fn table_schema_empty_fields() {
        let s: TableSchema = serde_json::from_value(json!({"fields": []})).unwrap();
        assert!(s.fields.is_empty());
    }

    // -- QueryResponse --

    #[test]
    fn query_response_roundtrip() {
        let r: QueryResponse = serde_json::from_value(json!({
            "kind": "bigquery#queryResponse",
            "schema": {
                "fields": [
                    {"name": "id", "type": "INTEGER"},
                    {"name": "name", "type": "STRING"}
                ]
            },
            "rows": [
                {"f": [{"v": "1"}, {"v": "Alice"}]},
                {"f": [{"v": "2"}, {"v": "Bob"}]}
            ],
            "totalRows": "2",
            "totalBytesProcessed": "1024",
            "jobComplete": true,
            "jobReference": {"jobId": "q_job_1", "projectId": "proj"},
            "cacheHit": false
        }))
        .unwrap();
        assert_eq!(r.rows.len(), 2);
        assert_eq!(r.total_rows, Some("2".into()));
        assert_eq!(r.total_bytes_processed, Some("1024".into()));
        assert_eq!(r.job_complete, Some(true));
        assert_eq!(r.cache_hit, Some(false));
        assert!(r.schema.is_some());
        assert!(r.job_reference.is_some());
    }

    #[test]
    fn query_response_minimal() {
        let r: QueryResponse = serde_json::from_value(json!({})).unwrap();
        assert!(r.rows.is_empty());
        assert!(r.schema.is_none());
        assert!(r.total_rows.is_none());
        assert!(r.job_complete.is_none());
    }

    #[test]
    fn query_response_incomplete_job() {
        let r: QueryResponse = serde_json::from_value(json!({
            "jobComplete": false,
            "jobReference": {"jobId": "pending_job"}
        }))
        .unwrap();
        assert_eq!(r.job_complete, Some(false));
        assert!(r.rows.is_empty());
    }

    // -- ApiErrorResponse --

    #[test]
    fn api_error_response_with_error() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error": {
                "code": 404,
                "message": "Not found: Dataset my-project:missing_ds",
                "status": "NOT_FOUND",
                "errors": [
                    {"domain": "global", "reason": "notFound", "message": "Not found"}
                ]
            }
        }))
        .unwrap();
        let detail = e.error.unwrap();
        assert_eq!(detail.code, Some(404));
        assert!(detail.message.as_ref().unwrap().contains("Not found"));
        assert_eq!(detail.status, Some("NOT_FOUND".into()));
        assert_eq!(detail.errors.len(), 1);
        assert_eq!(detail.errors[0].reason, Some("notFound".into()));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.error.is_none());
    }

    #[test]
    fn api_error_response_minimal_detail() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error": {"message": "Unauthorized"}
        }))
        .unwrap();
        let detail = e.error.unwrap();
        assert_eq!(detail.message, Some("Unauthorized".into()));
        assert!(detail.code.is_none());
        assert!(detail.errors.is_empty());
    }

    #[test]
    fn api_error_item_roundtrip() {
        let i: ApiErrorItem = serde_json::from_value(json!({
            "domain": "global",
            "reason": "forbidden",
            "message": "Access denied"
        }))
        .unwrap();
        assert_eq!(i.domain, Some("global".into()));
        assert_eq!(i.reason, Some("forbidden".into()));
        assert_eq!(i.message, Some("Access denied".into()));
    }

    #[test]
    fn api_error_item_minimal() {
        let i: ApiErrorItem = serde_json::from_value(json!({})).unwrap();
        assert!(i.domain.is_none());
        assert!(i.reason.is_none());
        assert!(i.message.is_none());
    }

    // -- Serialize round-trips for complex types --

    #[test]
    fn dataset_entry_serialize_deserialize() {
        let original = DatasetEntry {
            kind: Some("bigquery#dataset".into()),
            id: Some("proj:ds".into()),
            dataset_reference: Some(DatasetReference {
                dataset_id: "ds".into(),
                project_id: Some("proj".into()),
            }),
            friendly_name: Some("My Dataset".into()),
            location: Some("EU".into()),
        };
        let json = serde_json::to_value(&original).unwrap();
        assert_eq!(json["friendlyName"], "My Dataset");
        let back: DatasetEntry = serde_json::from_value(json).unwrap();
        assert_eq!(back.friendly_name, Some("My Dataset".into()));
    }

    #[test]
    fn table_entry_serialize_deserialize() {
        let original = TableEntry {
            kind: Some("bigquery#table".into()),
            id: Some("proj:ds.tbl".into()),
            table_reference: Some(TableReference {
                project_id: Some("proj".into()),
                dataset_id: Some("ds".into()),
                table_id: "tbl".into(),
            }),
            table_type: Some("TABLE".into()),
            creation_time: Some("1000000000000".into()),
            expiration_time: None,
        };
        let json = serde_json::to_value(&original).unwrap();
        assert_eq!(json["type"], "TABLE");
        let back: TableEntry = serde_json::from_value(json).unwrap();
        assert_eq!(back.table_type, Some("TABLE".into()));
    }

    #[test]
    fn job_entry_serialize_deserialize() {
        let original = JobEntry {
            kind: Some("bigquery#job".into()),
            id: Some("proj:job1".into()),
            job_reference: Some(JobReference {
                project_id: Some("proj".into()),
                job_id: "job1".into(),
                location: Some("US".into()),
            }),
            status: Some(JobStatus {
                state: Some("DONE".into()),
                error_result: None,
            }),
            user_email: Some("test@test.com".into()),
        };
        let json = serde_json::to_value(&original).unwrap();
        assert_eq!(json["user_email"], "test@test.com");
        let back: JobEntry = serde_json::from_value(json).unwrap();
        assert_eq!(back.user_email, Some("test@test.com".into()));
    }

    #[test]
    fn query_response_with_many_rows() {
        let rows: Vec<serde_json::Value> = (0..50)
            .map(|i| json!({"f": [{"v": format!("{i}")}, {"v": format!("name_{i}")}]}))
            .collect();
        let r: QueryResponse = serde_json::from_value(json!({
            "rows": rows,
            "totalRows": "50",
            "jobComplete": true
        }))
        .unwrap();
        assert_eq!(r.rows.len(), 50);
        assert_eq!(r.total_rows, Some("50".into()));
    }

    #[test]
    fn datasets_list_response_with_many_datasets() {
        let datasets: Vec<serde_json::Value> = (0..20)
            .map(|i| {
                json!({
                    "id": format!("proj:ds_{i}"),
                    "datasetReference": {"datasetId": format!("ds_{i}")}
                })
            })
            .collect();
        let r: DatasetsListResponse = serde_json::from_value(json!({
            "datasets": datasets,
            "kind": "bigquery#datasetList"
        }))
        .unwrap();
        assert_eq!(r.datasets.len(), 20);
    }

    #[test]
    fn table_schema_many_fields() {
        let fields: Vec<serde_json::Value> = (0..10)
            .map(|i| json!({"name": format!("col_{i}"), "type": "STRING"}))
            .collect();
        let s: TableSchema = serde_json::from_value(json!({"fields": fields})).unwrap();
        assert_eq!(s.fields.len(), 10);
    }

    #[test]
    fn schema_field_serialize_deserialize() {
        let original = SchemaField {
            name: "timestamp".into(),
            field_type: "TIMESTAMP".into(),
            mode: Some("REQUIRED".into()),
        };
        let json = serde_json::to_value(&original).unwrap();
        assert_eq!(json["type"], "TIMESTAMP");
        let back: SchemaField = serde_json::from_value(json).unwrap();
        assert_eq!(back.field_type, "TIMESTAMP");
    }

    #[test]
    fn dataset_reference_clone_and_debug() {
        let r = DatasetReference {
            dataset_id: "ds1".into(),
            project_id: Some("proj".into()),
        };
        let cloned = r.clone();
        assert_eq!(r.dataset_id, "ds1");
        assert_eq!(cloned.project_id.as_deref(), Some("proj"));
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("DatasetReference"));
    }

    #[test]
    fn table_reference_clone_and_debug() {
        let r = TableReference {
            project_id: Some("proj".into()),
            dataset_id: Some("ds".into()),
            table_id: "tbl".into(),
        };
        let cloned = r.clone();
        assert_eq!(r.table_id, "tbl");
        assert_eq!(cloned.dataset_id.as_deref(), Some("ds"));
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("TableReference"));
    }

    #[test]
    fn job_reference_clone_and_debug() {
        let r = JobReference {
            project_id: Some("proj".into()),
            job_id: "j1".into(),
            location: Some("US".into()),
        };
        let cloned = r.clone();
        assert_eq!(r.job_id, "j1");
        assert_eq!(cloned.location.as_deref(), Some("US"));
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("JobReference"));
    }

    #[test]
    fn api_error_response_clone_and_debug() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error": {"code": 403, "message": "forbidden"}
        }))
        .unwrap();
        let cloned = e.clone();
        assert!(cloned.error.is_some());
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("ApiErrorResponse"));
    }

    #[test]
    fn query_response_cache_hit_true() {
        let r: QueryResponse = serde_json::from_value(json!({
            "cacheHit": true,
            "jobComplete": true,
            "totalRows": "0"
        }))
        .unwrap();
        assert_eq!(r.cache_hit, Some(true));
    }

    #[test]
    fn dataset_entry_extra_fields_ignored() {
        let e: DatasetEntry = serde_json::from_value(json!({
            "kind": "bigquery#dataset",
            "unknown_extra": 42
        }))
        .unwrap();
        assert_eq!(e.kind, Some("bigquery#dataset".into()));
    }

    #[test]
    fn table_entry_type_rename() {
        let e: TableEntry = serde_json::from_value(json!({
            "type": "VIEW"
        }))
        .unwrap();
        assert_eq!(e.table_type.as_deref(), Some("VIEW"));
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["type"], "VIEW");
        assert!(v.get("table_type").is_none());
    }

    #[test]
    fn job_status_clone_and_debug() {
        let s = JobStatus {
            state: Some("RUNNING".into()),
            error_result: None,
        };
        let cloned = s.clone();
        assert_eq!(s.state.as_deref(), Some("RUNNING"));
        assert!(cloned.error_result.is_none());
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("JobStatus"));
    }
}
