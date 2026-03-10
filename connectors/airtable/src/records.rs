//! Record CRUD operations with batching, pagination, and safety controls.
//!
//! Provides typed request/response structures for Airtable record operations,
//! including validation that enforces Airtable's batch size limits (max 10
//! records per API call) and required field constraints.

use serde::{Deserialize, Serialize};

/// Maximum number of records Airtable allows in a single batch request.
pub const MAX_BATCH_SIZE: usize = 10;

/// Maximum page size Airtable allows for list requests.
pub const MAX_PAGE_SIZE: usize = 100;

/// Default page size for list requests.
pub const DEFAULT_PAGE_SIZE: usize = 100;

// ── Record ──────────────────────────────────────────────────────────

/// An Airtable record suitable for CRUD operations.
///
/// Unlike [`crate::types::Record`] (which always has an `id`), this type
/// makes `id` optional so it can represent records being created.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Record {
    /// Record ID (absent for new records being created).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Field name → value mapping.
    pub fields: serde_json::Value,

    /// ISO-8601 timestamp set by Airtable on creation.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "createdTime"
    )]
    pub created_time: Option<String>,
}

// ── RecordPage ──────────────────────────────────────────────────────

/// A page of records returned by the list API.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecordPage {
    /// Records in this page.
    pub records: Vec<Record>,

    /// Pagination cursor. Pass this as `offset` to fetch the next page.
    /// `None` indicates no more pages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<String>,
}

// ── Sort ────────────────────────────────────────────────────────────

/// Sort direction for record listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SortDirection {
    /// Ascending (A→Z, 0→9).
    #[serde(rename = "asc")]
    Asc,
    /// Descending (Z→A, 9→0).
    #[serde(rename = "desc")]
    Desc,
}

impl std::fmt::Display for SortDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Asc => f.write_str("asc"),
            Self::Desc => f.write_str("desc"),
        }
    }
}

/// A single sort criterion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SortField {
    /// Field name to sort by.
    pub field: String,
    /// Sort direction.
    pub direction: SortDirection,
}

// ── ListRecordsParams ───────────────────────────────────────────────

/// Parameters for listing records with pagination, filtering, and sorting.
#[derive(Debug, Clone)]
pub struct ListRecordsParams {
    /// Table ID or name.
    pub table_id: String,
    /// Optional view ID or name to restrict records.
    pub view: Option<String>,
    /// Number of records per page (1..=100, default 100).
    pub page_size: usize,
    /// Pagination cursor from a previous response.
    pub offset: Option<String>,
    /// Only return these fields.
    pub fields: Option<Vec<String>>,
    /// Airtable formula to filter records.
    pub filter_by_formula: Option<String>,
    /// Sort specifications.
    pub sort: Vec<SortField>,
    /// Maximum total records to return (across all pages).
    pub max_records: Option<usize>,
}

impl ListRecordsParams {
    /// Create new list parameters with defaults.
    #[must_use]
    pub fn new(table_id: &str) -> Self {
        Self {
            table_id: table_id.to_string(),
            view: None,
            page_size: DEFAULT_PAGE_SIZE,
            offset: None,
            fields: None,
            filter_by_formula: None,
            sort: Vec::new(),
            max_records: None,
        }
    }

    /// Set the page size, capping at [`MAX_PAGE_SIZE`] (100).
    #[must_use]
    pub fn with_page_size(mut self, size: usize) -> Self {
        self.page_size = size.min(MAX_PAGE_SIZE);
        self
    }

    /// Set the filter formula.
    #[must_use]
    pub fn with_filter(mut self, formula: &str) -> Self {
        self.filter_by_formula = Some(formula.to_string());
        self
    }

    /// Add a sort criterion.
    #[must_use]
    pub fn with_sort(mut self, field: &str, direction: SortDirection) -> Self {
        self.sort.push(SortField {
            field: field.to_string(),
            direction,
        });
        self
    }

    /// Set the fields to return.
    #[must_use]
    pub fn with_fields(mut self, fields: Vec<String>) -> Self {
        self.fields = Some(fields);
        self
    }

    /// Set the view.
    #[must_use]
    pub fn with_view(mut self, view: &str) -> Self {
        self.view = Some(view.to_string());
        self
    }

    /// Set the pagination offset.
    #[must_use]
    pub fn with_offset(mut self, offset: &str) -> Self {
        self.offset = Some(offset.to_string());
        self
    }

    /// Set the maximum total number of records.
    #[must_use]
    pub const fn with_max_records(mut self, max: usize) -> Self {
        self.max_records = Some(max);
        self
    }

    /// Serialize parameters to URL query pairs.
    #[must_use]
    pub fn to_query_params(&self) -> Vec<(String, String)> {
        let mut params = Vec::new();

        params.push(("pageSize".to_string(), self.page_size.to_string()));

        if let Some(ref view) = self.view {
            params.push(("view".to_string(), view.clone()));
        }

        if let Some(ref offset) = self.offset {
            params.push(("offset".to_string(), offset.clone()));
        }

        if let Some(ref formula) = self.filter_by_formula {
            params.push(("filterByFormula".to_string(), formula.clone()));
        }

        if let Some(ref fields) = self.fields {
            for f in fields {
                params.push(("fields[]".to_string(), f.clone()));
            }
        }

        for (i, sort) in self.sort.iter().enumerate() {
            params.push((format!("sort[{i}][field]"), sort.field.clone()));
            params.push((format!("sort[{i}][direction]"), sort.direction.to_string()));
        }

        if let Some(max) = self.max_records {
            params.push(("maxRecords".to_string(), max.to_string()));
        }

        params
    }
}

// ── Create / Update / Delete requests ───────────────────────────────

/// Request to create records in a table.
#[derive(Debug, Clone)]
pub struct CreateRecordsRequest {
    /// Target table.
    pub table_id: String,
    /// Records to create (max 10).
    pub records: Vec<Record>,
    /// If true, Airtable will try to convert string values to their
    /// proper column types automatically.
    pub typecast: bool,
}

/// Request to update records in a table.
#[derive(Debug, Clone)]
pub struct UpdateRecordsRequest {
    /// Target table.
    pub table_id: String,
    /// Records to update (max 10). Each must have an `id`.
    pub records: Vec<Record>,
    /// If true, enable typecast.
    pub typecast: bool,
    /// If true, use PUT (replace all fields). If false, use PATCH (merge).
    pub destructive: bool,
}

/// Request to delete records from a table.
#[derive(Debug, Clone)]
pub struct DeleteRecordsRequest {
    /// Target table.
    pub table_id: String,
    /// IDs of records to delete (max 10).
    pub record_ids: Vec<String>,
}

// ── BatchResult ─────────────────────────────────────────────────────

/// Outcome of a batch operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchResult {
    /// Number of records successfully created.
    pub created: usize,
    /// Number of records successfully updated.
    pub updated: usize,
    /// Number of records successfully deleted.
    pub deleted: usize,
    /// Errors encountered during the batch.
    pub errors: Vec<BatchError>,
}

impl BatchResult {
    /// Create an empty result with all counters at zero.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            created: 0,
            updated: 0,
            deleted: 0,
            errors: Vec::new(),
        }
    }

    /// Returns `true` if no errors occurred.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.errors.is_empty()
    }
}

/// A single error from a batch operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchError {
    /// The record ID this error relates to, if known.
    pub record_id: Option<String>,
    /// Human-readable error message.
    pub message: String,
    /// Airtable error type code (e.g. `"INVALID_VALUE_FOR_COLUMN"`).
    pub error_type: String,
}

// ── RecordValidator ─────────────────────────────────────────────────

/// Validates records before sending them to the Airtable API.
pub struct RecordValidator;

impl RecordValidator {
    /// Validate records for a create operation.
    ///
    /// # Errors
    ///
    /// Returns a list of validation error messages if:
    /// - There are more than [`MAX_BATCH_SIZE`] records
    /// - Any record has null or non-object fields
    /// - The records slice is empty
    pub fn validate_create(records: &[Record]) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if records.is_empty() {
            errors.push("At least one record is required".to_string());
        }

        if records.len() > MAX_BATCH_SIZE {
            errors.push(format!(
                "Batch size {} exceeds maximum of {MAX_BATCH_SIZE}",
                records.len()
            ));
        }

        for (i, rec) in records.iter().enumerate() {
            if rec.fields.is_null() || !rec.fields.is_object() {
                errors.push(format!("Record {i}: fields must be a JSON object"));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Validate records for an update operation.
    ///
    /// # Errors
    ///
    /// Returns a list of validation error messages if:
    /// - There are more than [`MAX_BATCH_SIZE`] records
    /// - Any record is missing an `id`
    /// - Any record has null or non-object fields
    /// - The records slice is empty
    pub fn validate_update(records: &[Record]) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if records.is_empty() {
            errors.push("At least one record is required".to_string());
        }

        if records.len() > MAX_BATCH_SIZE {
            errors.push(format!(
                "Batch size {} exceeds maximum of {MAX_BATCH_SIZE}",
                records.len()
            ));
        }

        for (i, rec) in records.iter().enumerate() {
            if rec.id.is_none() || rec.id.as_deref() == Some("") {
                errors.push(format!("Record {i}: id is required for updates"));
            }
            if rec.fields.is_null() || !rec.fields.is_object() {
                errors.push(format!("Record {i}: fields must be a JSON object"));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Validate record IDs for a delete operation.
    ///
    /// # Errors
    ///
    /// Returns a list of validation error messages if:
    /// - There are more than [`MAX_BATCH_SIZE`] IDs
    /// - Any ID is empty
    /// - The IDs slice is empty
    pub fn validate_delete(record_ids: &[String]) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if record_ids.is_empty() {
            errors.push("At least one record ID is required".to_string());
        }

        if record_ids.len() > MAX_BATCH_SIZE {
            errors.push(format!(
                "Batch size {} exceeds maximum of {MAX_BATCH_SIZE}",
                record_ids.len()
            ));
        }

        for (i, id) in record_ids.iter().enumerate() {
            if id.is_empty() {
                errors.push(format!("Record ID at index {i} is empty"));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

// ── RecordValidation trait ──────────────────────────────────────────

/// Trait for types that can self-validate before being sent to the API.
pub trait RecordValidation {
    /// Validate field types, check batch sizes, and verify required fields.
    ///
    /// # Errors
    ///
    /// Returns validation error messages.
    fn validate(&self) -> Result<(), Vec<String>>;
}

impl RecordValidation for CreateRecordsRequest {
    fn validate(&self) -> Result<(), Vec<String>> {
        RecordValidator::validate_create(&self.records)
    }
}

impl RecordValidation for UpdateRecordsRequest {
    fn validate(&self) -> Result<(), Vec<String>> {
        RecordValidator::validate_update(&self.records)
    }
}

impl RecordValidation for DeleteRecordsRequest {
    fn validate(&self) -> Result<(), Vec<String>> {
        RecordValidator::validate_delete(&self.record_ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── Record serde ────────────────────────────────────────────

    #[test]
    fn record_with_id_roundtrip() {
        let rec = Record {
            id: Some("rec123".into()),
            fields: json!({"Name": "Task 1", "Status": "Done"}),
            created_time: Some("2026-03-01T00:00:00.000Z".into()),
        };
        let json = serde_json::to_value(&rec).unwrap();
        assert_eq!(json["id"], "rec123");
        assert_eq!(json["createdTime"], "2026-03-01T00:00:00.000Z");
        let back: Record = serde_json::from_value(json).unwrap();
        assert_eq!(back.id, Some("rec123".into()));
        assert_eq!(back.fields["Name"], "Task 1");
    }

    #[test]
    fn record_without_id_roundtrip() {
        let rec = Record {
            id: None,
            fields: json!({"Name": "New Task"}),
            created_time: None,
        };
        let json = serde_json::to_value(&rec).unwrap();
        // id should be omitted (skip_serializing_if)
        assert!(json.get("id").is_none());
        assert!(json.get("createdTime").is_none());
        let back: Record = serde_json::from_value(json).unwrap();
        assert!(back.id.is_none());
        assert!(back.created_time.is_none());
    }

    #[test]
    fn record_with_id_no_created_time() {
        let rec = Record {
            id: Some("recABC".into()),
            fields: json!({"Count": 42}),
            created_time: None,
        };
        let json = serde_json::to_value(&rec).unwrap();
        assert_eq!(json["id"], "recABC");
        assert!(json.get("createdTime").is_none());
    }

    #[test]
    fn record_without_id_with_created_time() {
        // Unusual but valid: server might return created_time without us setting id
        let json = json!({"fields": {"X": 1}, "createdTime": "2026-01-01"});
        let rec: Record = serde_json::from_value(json).unwrap();
        assert!(rec.id.is_none());
        assert_eq!(rec.created_time.as_deref(), Some("2026-01-01"));
    }

    #[test]
    fn record_empty_fields_object() {
        let rec = Record {
            id: Some("rec1".into()),
            fields: json!({}),
            created_time: None,
        };
        let v = serde_json::to_value(&rec).unwrap();
        assert!(v["fields"].as_object().unwrap().is_empty());
    }

    #[test]
    fn record_complex_field_values() {
        let rec = Record {
            id: Some("recCOMPLEX".into()),
            fields: json!({
                "Name": "Test",
                "Score": 99.5,
                "Tags": ["a", "b", "c"],
                "Metadata": {"nested": true, "depth": 2},
                "Empty": null
            }),
            created_time: None,
        };
        let json = serde_json::to_value(&rec).unwrap();
        let back: Record = serde_json::from_value(json).unwrap();
        assert!(back.fields["Tags"].is_array());
        assert!(back.fields["Metadata"].is_object());
        assert!(back.fields["Empty"].is_null());
    }

    #[test]
    fn record_equality() {
        let a = Record {
            id: Some("rec1".into()),
            fields: json!({"X": 1}),
            created_time: None,
        };
        let b = Record {
            id: Some("rec1".into()),
            fields: json!({"X": 1}),
            created_time: None,
        };
        assert_eq!(a, b);
    }

    #[test]
    fn record_inequality_different_id() {
        let a = Record {
            id: Some("rec1".into()),
            fields: json!({}),
            created_time: None,
        };
        let b = Record {
            id: Some("rec2".into()),
            fields: json!({}),
            created_time: None,
        };
        assert_ne!(a, b);
    }

    #[test]
    fn record_clone() {
        let rec = Record {
            id: Some("rec1".into()),
            fields: json!({"A": 1}),
            created_time: Some("2026-01-01".into()),
        };
        let cloned = rec.clone();
        assert_eq!(rec, cloned);
    }

    #[test]
    fn record_debug_format() {
        let rec = Record {
            id: Some("recDBG".into()),
            fields: json!({}),
            created_time: None,
        };
        let dbg = format!("{rec:?}");
        assert!(dbg.contains("recDBG"));
        assert!(dbg.contains("Record"));
    }

    #[test]
    fn record_deser_from_airtable_response() {
        // Simulates an actual Airtable API response shape
        let json = json!({
            "id": "recXYZ789",
            "fields": {
                "Name": "Project Alpha",
                "Status": "In Progress",
                "Priority": 1
            },
            "createdTime": "2026-03-09T12:00:00.000Z"
        });
        let rec: Record = serde_json::from_value(json).unwrap();
        assert_eq!(rec.id, Some("recXYZ789".into()));
        assert_eq!(rec.fields["Status"], "In Progress");
        assert_eq!(rec.fields["Priority"], 1);
    }

    // ── RecordPage ──────────────────────────────────────────────

    #[test]
    fn record_page_with_offset() {
        let page = RecordPage {
            records: vec![Record {
                id: Some("rec1".into()),
                fields: json!({"A": 1}),
                created_time: None,
            }],
            offset: Some("itr_cursor_abc".into()),
        };
        let json = serde_json::to_value(&page).unwrap();
        assert_eq!(json["offset"], "itr_cursor_abc");
        let back: RecordPage = serde_json::from_value(json).unwrap();
        assert_eq!(back.records.len(), 1);
        assert_eq!(back.offset.as_deref(), Some("itr_cursor_abc"));
    }

    #[test]
    fn record_page_without_offset() {
        let page = RecordPage {
            records: vec![],
            offset: None,
        };
        let json = serde_json::to_value(&page).unwrap();
        assert!(json.get("offset").is_none());
        let back: RecordPage = serde_json::from_value(json).unwrap();
        assert!(back.records.is_empty());
        assert!(back.offset.is_none());
    }

    #[test]
    fn record_page_empty() {
        let page = RecordPage {
            records: vec![],
            offset: None,
        };
        assert!(page.records.is_empty());
        assert!(page.offset.is_none());
    }

    #[test]
    fn record_page_multiple_records() {
        let page = RecordPage {
            records: vec![
                Record {
                    id: Some("rec1".into()),
                    fields: json!({"A": 1}),
                    created_time: None,
                },
                Record {
                    id: Some("rec2".into()),
                    fields: json!({"A": 2}),
                    created_time: None,
                },
                Record {
                    id: Some("rec3".into()),
                    fields: json!({"A": 3}),
                    created_time: None,
                },
            ],
            offset: Some("next_page".into()),
        };
        assert_eq!(page.records.len(), 3);
        assert_eq!(page.records[2].id.as_deref(), Some("rec3"));
    }

    #[test]
    fn record_page_roundtrip() {
        let page = RecordPage {
            records: vec![Record {
                id: Some("recRT".into()),
                fields: json!({"Val": true}),
                created_time: Some("2026-01-01".into()),
            }],
            offset: Some("off123".into()),
        };
        let json = serde_json::to_value(&page).unwrap();
        let back: RecordPage = serde_json::from_value(json).unwrap();
        assert_eq!(page, back);
    }

    #[test]
    fn record_page_debug() {
        let page = RecordPage {
            records: vec![],
            offset: None,
        };
        let dbg = format!("{page:?}");
        assert!(dbg.contains("RecordPage"));
    }

    #[test]
    fn record_page_clone() {
        let page = RecordPage {
            records: vec![Record {
                id: Some("rec1".into()),
                fields: json!({}),
                created_time: None,
            }],
            offset: Some("off".into()),
        };
        let cloned = page.clone();
        assert_eq!(page, cloned);
    }

    // ── SortDirection ───────────────────────────────────────────

    #[test]
    fn sort_direction_asc_serde() {
        let json = serde_json::to_value(SortDirection::Asc).unwrap();
        assert_eq!(json, "asc");
        let back: SortDirection = serde_json::from_value(json).unwrap();
        assert_eq!(back, SortDirection::Asc);
    }

    #[test]
    fn sort_direction_desc_serde() {
        let json = serde_json::to_value(SortDirection::Desc).unwrap();
        assert_eq!(json, "desc");
        let back: SortDirection = serde_json::from_value(json).unwrap();
        assert_eq!(back, SortDirection::Desc);
    }

    #[test]
    fn sort_direction_display_asc() {
        assert_eq!(SortDirection::Asc.to_string(), "asc");
    }

    #[test]
    fn sort_direction_display_desc() {
        assert_eq!(SortDirection::Desc.to_string(), "desc");
    }

    #[test]
    fn sort_direction_copy() {
        let d = SortDirection::Asc;
        let copy = d;
        assert_eq!(d, copy);
    }

    #[test]
    fn sort_direction_debug() {
        assert!(format!("{:?}", SortDirection::Asc).contains("Asc"));
        assert!(format!("{:?}", SortDirection::Desc).contains("Desc"));
    }

    #[test]
    fn sort_direction_invalid_deser_fails() {
        let result = serde_json::from_value::<SortDirection>(json!("invalid"));
        assert!(result.is_err());
    }

    // ── SortField ───────────────────────────────────────────────

    #[test]
    fn sort_field_roundtrip() {
        let sf = SortField {
            field: "Priority".into(),
            direction: SortDirection::Desc,
        };
        let json = serde_json::to_value(&sf).unwrap();
        assert_eq!(json["field"], "Priority");
        assert_eq!(json["direction"], "desc");
        let back: SortField = serde_json::from_value(json).unwrap();
        assert_eq!(back, sf);
    }

    #[test]
    fn sort_field_clone() {
        let sf = SortField {
            field: "Name".into(),
            direction: SortDirection::Asc,
        };
        let cloned = sf.clone();
        assert_eq!(sf, cloned);
    }

    #[test]
    fn sort_field_debug() {
        let sf = SortField {
            field: "Status".into(),
            direction: SortDirection::Desc,
        };
        let dbg = format!("{sf:?}");
        assert!(dbg.contains("SortField"));
        assert!(dbg.contains("Status"));
    }

    // ── ListRecordsParams builder ───────────────────────────────

    #[test]
    fn list_params_new_defaults() {
        let params = ListRecordsParams::new("tblTasks");
        assert_eq!(params.table_id, "tblTasks");
        assert_eq!(params.page_size, DEFAULT_PAGE_SIZE);
        assert!(params.view.is_none());
        assert!(params.offset.is_none());
        assert!(params.fields.is_none());
        assert!(params.filter_by_formula.is_none());
        assert!(params.sort.is_empty());
        assert!(params.max_records.is_none());
    }

    #[test]
    fn list_params_with_page_size() {
        let params = ListRecordsParams::new("tbl1").with_page_size(50);
        assert_eq!(params.page_size, 50);
    }

    #[test]
    fn list_params_page_size_capped_at_100() {
        let params = ListRecordsParams::new("tbl1").with_page_size(200);
        assert_eq!(params.page_size, MAX_PAGE_SIZE);
    }

    #[test]
    fn list_params_page_size_zero() {
        let params = ListRecordsParams::new("tbl1").with_page_size(0);
        assert_eq!(params.page_size, 0);
    }

    #[test]
    fn list_params_page_size_exactly_100() {
        let params = ListRecordsParams::new("tbl1").with_page_size(100);
        assert_eq!(params.page_size, 100);
    }

    #[test]
    fn list_params_with_filter() {
        let params = ListRecordsParams::new("tbl1").with_filter("{Status} = 'Done'");
        assert_eq!(
            params.filter_by_formula.as_deref(),
            Some("{Status} = 'Done'")
        );
    }

    #[test]
    fn list_params_with_sort_single() {
        let params = ListRecordsParams::new("tbl1").with_sort("Name", SortDirection::Asc);
        assert_eq!(params.sort.len(), 1);
        assert_eq!(params.sort[0].field, "Name");
        assert_eq!(params.sort[0].direction, SortDirection::Asc);
    }

    #[test]
    fn list_params_with_sort_multiple() {
        let params = ListRecordsParams::new("tbl1")
            .with_sort("Priority", SortDirection::Desc)
            .with_sort("Name", SortDirection::Asc);
        assert_eq!(params.sort.len(), 2);
        assert_eq!(params.sort[0].field, "Priority");
        assert_eq!(params.sort[1].field, "Name");
    }

    #[test]
    fn list_params_with_fields() {
        let params =
            ListRecordsParams::new("tbl1").with_fields(vec!["Name".into(), "Status".into()]);
        assert_eq!(
            params.fields.as_deref(),
            Some(&["Name".into(), "Status".into()][..])
        );
    }

    #[test]
    fn list_params_with_view() {
        let params = ListRecordsParams::new("tbl1").with_view("viwGrid1");
        assert_eq!(params.view.as_deref(), Some("viwGrid1"));
    }

    #[test]
    fn list_params_with_offset() {
        let params = ListRecordsParams::new("tbl1").with_offset("itr_next");
        assert_eq!(params.offset.as_deref(), Some("itr_next"));
    }

    #[test]
    fn list_params_with_max_records() {
        let params = ListRecordsParams::new("tbl1").with_max_records(500);
        assert_eq!(params.max_records, Some(500));
    }

    #[test]
    fn list_params_full_builder_chain() {
        let params = ListRecordsParams::new("tblProjects")
            .with_page_size(25)
            .with_view("viwKanban")
            .with_filter("{Status} != 'Archived'")
            .with_sort("Priority", SortDirection::Desc)
            .with_sort("Name", SortDirection::Asc)
            .with_fields(vec!["Name".into(), "Priority".into(), "Status".into()])
            .with_max_records(1000)
            .with_offset("cursor_abc");

        assert_eq!(params.table_id, "tblProjects");
        assert_eq!(params.page_size, 25);
        assert_eq!(params.view.as_deref(), Some("viwKanban"));
        assert_eq!(
            params.filter_by_formula.as_deref(),
            Some("{Status} != 'Archived'")
        );
        assert_eq!(params.sort.len(), 2);
        assert_eq!(params.fields.as_ref().unwrap().len(), 3);
        assert_eq!(params.max_records, Some(1000));
        assert_eq!(params.offset.as_deref(), Some("cursor_abc"));
    }

    #[test]
    fn list_params_debug() {
        let params = ListRecordsParams::new("tbl1");
        let dbg = format!("{params:?}");
        assert!(dbg.contains("ListRecordsParams"));
        assert!(dbg.contains("tbl1"));
    }

    #[test]
    fn list_params_clone() {
        let params = ListRecordsParams::new("tbl1")
            .with_page_size(50)
            .with_filter("x");
        let cloned = params.clone();
        assert_eq!(cloned.table_id, "tbl1");
        assert_eq!(cloned.page_size, 50);
        assert_eq!(params.table_id, "tbl1");
    }

    // ── Query param serialization ───────────────────────────────

    #[test]
    fn query_params_defaults() {
        let params = ListRecordsParams::new("tbl1");
        let qp = params.to_query_params();
        assert_eq!(qp.len(), 1);
        assert_eq!(qp[0], ("pageSize".to_string(), "100".to_string()));
    }

    #[test]
    fn query_params_with_page_size() {
        let params = ListRecordsParams::new("tbl1").with_page_size(42);
        let qp = params.to_query_params();
        assert!(qp.contains(&("pageSize".to_string(), "42".to_string())));
    }

    #[test]
    fn query_params_with_view() {
        let params = ListRecordsParams::new("tbl1").with_view("viwGrid");
        let qp = params.to_query_params();
        assert!(qp.contains(&("view".to_string(), "viwGrid".to_string())));
    }

    #[test]
    fn query_params_with_offset() {
        let params = ListRecordsParams::new("tbl1").with_offset("off123");
        let qp = params.to_query_params();
        assert!(qp.contains(&("offset".to_string(), "off123".to_string())));
    }

    #[test]
    fn query_params_with_filter() {
        let params = ListRecordsParams::new("tbl1").with_filter("{Done} = TRUE()");
        let qp = params.to_query_params();
        assert!(qp.contains(&("filterByFormula".to_string(), "{Done} = TRUE()".to_string())));
    }

    #[test]
    fn query_params_with_fields() {
        let params =
            ListRecordsParams::new("tbl1").with_fields(vec!["Name".into(), "Email".into()]);
        let qp = params.to_query_params();
        assert!(qp.contains(&("fields[]".to_string(), "Name".to_string())));
        assert!(qp.contains(&("fields[]".to_string(), "Email".to_string())));
    }

    #[test]
    fn query_params_with_sort_single() {
        let params = ListRecordsParams::new("tbl1").with_sort("Name", SortDirection::Asc);
        let qp = params.to_query_params();
        assert!(qp.contains(&("sort[0][field]".to_string(), "Name".to_string())));
        assert!(qp.contains(&("sort[0][direction]".to_string(), "asc".to_string())));
    }

    #[test]
    fn query_params_with_sort_multiple() {
        let params = ListRecordsParams::new("tbl1")
            .with_sort("Priority", SortDirection::Desc)
            .with_sort("Created", SortDirection::Asc);
        let qp = params.to_query_params();
        assert!(qp.contains(&("sort[0][field]".to_string(), "Priority".to_string())));
        assert!(qp.contains(&("sort[0][direction]".to_string(), "desc".to_string())));
        assert!(qp.contains(&("sort[1][field]".to_string(), "Created".to_string())));
        assert!(qp.contains(&("sort[1][direction]".to_string(), "asc".to_string())));
    }

    #[test]
    fn query_params_with_max_records() {
        let params = ListRecordsParams::new("tbl1").with_max_records(250);
        let qp = params.to_query_params();
        assert!(qp.contains(&("maxRecords".to_string(), "250".to_string())));
    }

    #[test]
    fn query_params_full_combination() {
        let params = ListRecordsParams::new("tbl1")
            .with_page_size(10)
            .with_view("viwKanban")
            .with_offset("cursor_x")
            .with_filter("{Active} = 1")
            .with_fields(vec!["Name".into()])
            .with_sort("Name", SortDirection::Asc)
            .with_max_records(50);
        let qp = params.to_query_params();

        // Expected: pageSize, view, offset, filterByFormula, fields[], sort[0][field],
        //           sort[0][direction], maxRecords = 8 params
        assert_eq!(qp.len(), 8);
    }

    #[test]
    fn query_params_empty_fields_list() {
        let params = ListRecordsParams::new("tbl1").with_fields(vec![]);
        let qp = params.to_query_params();
        // Should just have pageSize, no fields[] entries
        assert_eq!(qp.len(), 1);
    }

    // ── CreateRecordsRequest ────────────────────────────────────

    #[test]
    fn create_request_default_typecast() {
        let req = CreateRecordsRequest {
            table_id: "tbl1".into(),
            records: vec![Record {
                id: None,
                fields: json!({"Name": "Test"}),
                created_time: None,
            }],
            typecast: false,
        };
        assert!(!req.typecast);
        assert_eq!(req.table_id, "tbl1");
    }

    #[test]
    fn create_request_debug() {
        let req = CreateRecordsRequest {
            table_id: "tblDBG".into(),
            records: vec![],
            typecast: true,
        };
        let dbg = format!("{req:?}");
        assert!(dbg.contains("CreateRecordsRequest"));
        assert!(dbg.contains("tblDBG"));
    }

    #[test]
    fn create_request_clone() {
        let req = CreateRecordsRequest {
            table_id: "tbl1".into(),
            records: vec![Record {
                id: None,
                fields: json!({"X": 1}),
                created_time: None,
            }],
            typecast: true,
        };
        let cloned = req.clone();
        assert_eq!(cloned.table_id, "tbl1");
        assert!(cloned.typecast);
        assert_eq!(req.records.len(), 1);
    }

    // ── UpdateRecordsRequest ────────────────────────────────────

    #[test]
    fn update_request_patch_mode() {
        let req = UpdateRecordsRequest {
            table_id: "tbl1".into(),
            records: vec![Record {
                id: Some("rec1".into()),
                fields: json!({"Status": "Done"}),
                created_time: None,
            }],
            typecast: false,
            destructive: false,
        };
        assert!(!req.destructive);
    }

    #[test]
    fn update_request_put_mode() {
        let req = UpdateRecordsRequest {
            table_id: "tbl1".into(),
            records: vec![Record {
                id: Some("rec1".into()),
                fields: json!({"Status": "Done"}),
                created_time: None,
            }],
            typecast: false,
            destructive: true,
        };
        assert!(req.destructive);
    }

    #[test]
    fn update_request_debug() {
        let req = UpdateRecordsRequest {
            table_id: "tblUPD".into(),
            records: vec![],
            typecast: false,
            destructive: false,
        };
        let dbg = format!("{req:?}");
        assert!(dbg.contains("UpdateRecordsRequest"));
    }

    #[test]
    fn update_request_clone() {
        let req = UpdateRecordsRequest {
            table_id: "tbl1".into(),
            records: vec![],
            typecast: true,
            destructive: true,
        };
        let cloned = req.clone();
        assert_eq!(cloned.table_id, "tbl1");
        assert!(cloned.typecast);
        assert!(cloned.destructive);
        assert_eq!(req.table_id, "tbl1");
    }

    // ── DeleteRecordsRequest ────────────────────────────────────

    #[test]
    fn delete_request_basic() {
        let req = DeleteRecordsRequest {
            table_id: "tbl1".into(),
            record_ids: vec!["rec1".into(), "rec2".into()],
        };
        assert_eq!(req.record_ids.len(), 2);
    }

    #[test]
    fn delete_request_debug() {
        let req = DeleteRecordsRequest {
            table_id: "tblDEL".into(),
            record_ids: vec![],
        };
        let dbg = format!("{req:?}");
        assert!(dbg.contains("DeleteRecordsRequest"));
    }

    #[test]
    fn delete_request_clone() {
        let req = DeleteRecordsRequest {
            table_id: "tbl1".into(),
            record_ids: vec!["rec1".into()],
        };
        let cloned = req.clone();
        assert_eq!(cloned.record_ids.len(), 1);
        assert_eq!(req.record_ids.len(), 1);
    }

    // ── BatchResult ─────────────────────────────────────────────

    #[test]
    fn batch_result_empty() {
        let r = BatchResult::empty();
        assert_eq!(r.created, 0);
        assert_eq!(r.updated, 0);
        assert_eq!(r.deleted, 0);
        assert!(r.errors.is_empty());
        assert!(r.is_success());
    }

    #[test]
    fn batch_result_with_created() {
        let r = BatchResult {
            created: 5,
            updated: 0,
            deleted: 0,
            errors: vec![],
        };
        assert!(r.is_success());
        assert_eq!(r.created, 5);
    }

    #[test]
    fn batch_result_with_errors_not_success() {
        let r = BatchResult {
            created: 3,
            updated: 0,
            deleted: 0,
            errors: vec![BatchError {
                record_id: Some("rec1".into()),
                message: "Invalid value".into(),
                error_type: "INVALID_VALUE_FOR_COLUMN".into(),
            }],
        };
        assert!(!r.is_success());
    }

    #[test]
    fn batch_result_debug() {
        let r = BatchResult::empty();
        let dbg = format!("{r:?}");
        assert!(dbg.contains("BatchResult"));
    }

    #[test]
    fn batch_result_clone() {
        let r = BatchResult {
            created: 2,
            updated: 3,
            deleted: 1,
            errors: vec![],
        };
        let cloned = r.clone();
        assert_eq!(r, cloned);
    }

    #[test]
    fn batch_result_equality() {
        let a = BatchResult::empty();
        let b = BatchResult::empty();
        assert_eq!(a, b);
    }

    #[test]
    fn batch_result_mixed_counts() {
        let r = BatchResult {
            created: 2,
            updated: 5,
            deleted: 3,
            errors: vec![],
        };
        assert!(r.is_success());
        assert_eq!(r.created, 2);
        assert_eq!(r.updated, 5);
        assert_eq!(r.deleted, 3);
    }

    #[test]
    fn batch_result_multiple_errors() {
        let r = BatchResult {
            created: 0,
            updated: 0,
            deleted: 0,
            errors: vec![
                BatchError {
                    record_id: Some("rec1".into()),
                    message: "Error 1".into(),
                    error_type: "TYPE_A".into(),
                },
                BatchError {
                    record_id: None,
                    message: "Error 2".into(),
                    error_type: "TYPE_B".into(),
                },
            ],
        };
        assert!(!r.is_success());
        assert_eq!(r.errors.len(), 2);
    }

    // ── BatchError ──────────────────────────────────────────────

    #[test]
    fn batch_error_with_record_id() {
        let e = BatchError {
            record_id: Some("rec123".into()),
            message: "Field X is required".into(),
            error_type: "REQUIRED_FIELD_MISSING".into(),
        };
        assert_eq!(e.record_id.as_deref(), Some("rec123"));
    }

    #[test]
    fn batch_error_without_record_id() {
        let e = BatchError {
            record_id: None,
            message: "General error".into(),
            error_type: "UNKNOWN".into(),
        };
        assert!(e.record_id.is_none());
    }

    #[test]
    fn batch_error_debug() {
        let e = BatchError {
            record_id: Some("recDBG".into()),
            message: "test".into(),
            error_type: "TEST".into(),
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("BatchError"));
        assert!(dbg.contains("recDBG"));
    }

    #[test]
    fn batch_error_clone() {
        let e = BatchError {
            record_id: Some("rec1".into()),
            message: "err".into(),
            error_type: "TYPE".into(),
        };
        let cloned = e.clone();
        assert_eq!(e, cloned);
    }

    #[test]
    fn batch_error_equality() {
        let a = BatchError {
            record_id: None,
            message: "x".into(),
            error_type: "T".into(),
        };
        let b = BatchError {
            record_id: None,
            message: "x".into(),
            error_type: "T".into(),
        };
        assert_eq!(a, b);
    }

    // ── Create validation ───────────────────────────────────────

    #[test]
    fn validate_create_valid_single() {
        let records = vec![Record {
            id: None,
            fields: json!({"Name": "Test"}),
            created_time: None,
        }];
        assert!(RecordValidator::validate_create(&records).is_ok());
    }

    #[test]
    fn validate_create_valid_max_batch() {
        let records: Vec<Record> = (0..MAX_BATCH_SIZE)
            .map(|i| Record {
                id: None,
                fields: json!({"Idx": i}),
                created_time: None,
            })
            .collect();
        assert!(RecordValidator::validate_create(&records).is_ok());
    }

    #[test]
    fn validate_create_too_many() {
        let records: Vec<Record> = (0..=MAX_BATCH_SIZE)
            .map(|i| Record {
                id: None,
                fields: json!({"Idx": i}),
                created_time: None,
            })
            .collect();
        let err = RecordValidator::validate_create(&records).unwrap_err();
        assert!(err.iter().any(|e| e.contains("exceeds maximum")));
    }

    #[test]
    fn validate_create_empty_records() {
        let err = RecordValidator::validate_create(&[]).unwrap_err();
        assert!(err.iter().any(|e| e.contains("At least one record")));
    }

    #[test]
    fn validate_create_null_fields() {
        let records = vec![Record {
            id: None,
            fields: serde_json::Value::Null,
            created_time: None,
        }];
        let err = RecordValidator::validate_create(&records).unwrap_err();
        assert!(err.iter().any(|e| e.contains("must be a JSON object")));
    }

    #[test]
    fn validate_create_array_fields() {
        let records = vec![Record {
            id: None,
            fields: json!([1, 2, 3]),
            created_time: None,
        }];
        let err = RecordValidator::validate_create(&records).unwrap_err();
        assert!(err.iter().any(|e| e.contains("must be a JSON object")));
    }

    #[test]
    fn validate_create_string_fields() {
        let records = vec![Record {
            id: None,
            fields: json!("not an object"),
            created_time: None,
        }];
        let err = RecordValidator::validate_create(&records).unwrap_err();
        assert!(err.iter().any(|e| e.contains("must be a JSON object")));
    }

    #[test]
    fn validate_create_number_fields() {
        let records = vec![Record {
            id: None,
            fields: json!(42),
            created_time: None,
        }];
        let err = RecordValidator::validate_create(&records).unwrap_err();
        assert!(err.iter().any(|e| e.contains("must be a JSON object")));
    }

    #[test]
    fn validate_create_multiple_errors() {
        // Too many records + one with null fields
        let mut records: Vec<Record> = (0..=MAX_BATCH_SIZE)
            .map(|i| Record {
                id: None,
                fields: json!({"Idx": i}),
                created_time: None,
            })
            .collect();
        records[0].fields = serde_json::Value::Null;
        let err = RecordValidator::validate_create(&records).unwrap_err();
        assert!(err.len() >= 2);
    }

    #[test]
    fn validate_create_with_id_still_valid() {
        // Having an id is fine for creates (server will ignore or error separately)
        let records = vec![Record {
            id: Some("rec1".into()),
            fields: json!({"Name": "Test"}),
            created_time: None,
        }];
        assert!(RecordValidator::validate_create(&records).is_ok());
    }

    #[test]
    fn validate_create_empty_fields_object_valid() {
        let records = vec![Record {
            id: None,
            fields: json!({}),
            created_time: None,
        }];
        assert!(RecordValidator::validate_create(&records).is_ok());
    }

    // ── Update validation ───────────────────────────────────────

    #[test]
    fn validate_update_valid_single() {
        let records = vec![Record {
            id: Some("rec1".into()),
            fields: json!({"Status": "Done"}),
            created_time: None,
        }];
        assert!(RecordValidator::validate_update(&records).is_ok());
    }

    #[test]
    fn validate_update_valid_max_batch() {
        let records: Vec<Record> = (0..MAX_BATCH_SIZE)
            .map(|i| Record {
                id: Some(format!("rec{i}")),
                fields: json!({"Idx": i}),
                created_time: None,
            })
            .collect();
        assert!(RecordValidator::validate_update(&records).is_ok());
    }

    #[test]
    fn validate_update_too_many() {
        let records: Vec<Record> = (0..=MAX_BATCH_SIZE)
            .map(|i| Record {
                id: Some(format!("rec{i}")),
                fields: json!({"Idx": i}),
                created_time: None,
            })
            .collect();
        let err = RecordValidator::validate_update(&records).unwrap_err();
        assert!(err.iter().any(|e| e.contains("exceeds maximum")));
    }

    #[test]
    fn validate_update_missing_id() {
        let records = vec![Record {
            id: None,
            fields: json!({"Status": "Done"}),
            created_time: None,
        }];
        let err = RecordValidator::validate_update(&records).unwrap_err();
        assert!(err.iter().any(|e| e.contains("id is required")));
    }

    #[test]
    fn validate_update_empty_id() {
        let records = vec![Record {
            id: Some(String::new()),
            fields: json!({"Status": "Done"}),
            created_time: None,
        }];
        let err = RecordValidator::validate_update(&records).unwrap_err();
        assert!(err.iter().any(|e| e.contains("id is required")));
    }

    #[test]
    fn validate_update_null_fields() {
        let records = vec![Record {
            id: Some("rec1".into()),
            fields: serde_json::Value::Null,
            created_time: None,
        }];
        let err = RecordValidator::validate_update(&records).unwrap_err();
        assert!(err.iter().any(|e| e.contains("must be a JSON object")));
    }

    #[test]
    fn validate_update_empty_records() {
        let err = RecordValidator::validate_update(&[]).unwrap_err();
        assert!(err.iter().any(|e| e.contains("At least one record")));
    }

    #[test]
    fn validate_update_multiple_errors_missing_id_and_fields() {
        let records = vec![
            Record {
                id: None,
                fields: serde_json::Value::Null,
                created_time: None,
            },
            Record {
                id: Some("rec2".into()),
                fields: json!({"OK": true}),
                created_time: None,
            },
        ];
        let err = RecordValidator::validate_update(&records).unwrap_err();
        // Record 0 should have both id and fields errors
        assert!(err.len() >= 2);
    }

    // ── Delete validation ───────────────────────────────────────

    #[test]
    fn validate_delete_valid_single() {
        let ids = vec!["rec1".to_string()];
        assert!(RecordValidator::validate_delete(&ids).is_ok());
    }

    #[test]
    fn validate_delete_valid_max_batch() {
        let ids: Vec<String> = (0..MAX_BATCH_SIZE).map(|i| format!("rec{i}")).collect();
        assert!(RecordValidator::validate_delete(&ids).is_ok());
    }

    #[test]
    fn validate_delete_too_many() {
        let ids: Vec<String> = (0..=MAX_BATCH_SIZE).map(|i| format!("rec{i}")).collect();
        let err = RecordValidator::validate_delete(&ids).unwrap_err();
        assert!(err.iter().any(|e| e.contains("exceeds maximum")));
    }

    #[test]
    fn validate_delete_empty_list() {
        let err = RecordValidator::validate_delete(&[]).unwrap_err();
        assert!(err.iter().any(|e| e.contains("At least one record ID")));
    }

    #[test]
    fn validate_delete_empty_id() {
        let ids = vec![String::new()];
        let err = RecordValidator::validate_delete(&ids).unwrap_err();
        assert!(err.iter().any(|e| e.contains("empty")));
    }

    #[test]
    fn validate_delete_some_empty_ids() {
        let ids = vec!["rec1".to_string(), String::new(), "rec3".to_string()];
        let err = RecordValidator::validate_delete(&ids).unwrap_err();
        assert!(err.iter().any(|e| e.contains("index 1")));
    }

    #[test]
    fn validate_delete_multiple_errors() {
        let mut ids: Vec<String> = (0..=MAX_BATCH_SIZE).map(|i| format!("rec{i}")).collect();
        ids[3] = String::new();
        let err = RecordValidator::validate_delete(&ids).unwrap_err();
        // Should have both batch-size and empty-id errors
        assert!(err.len() >= 2);
    }

    // ── Boundary tests (exactly at limit) ───────────────────────

    #[test]
    fn validate_create_exactly_10() {
        let records: Vec<Record> = (0..10)
            .map(|i| Record {
                id: None,
                fields: json!({"N": i}),
                created_time: None,
            })
            .collect();
        assert!(RecordValidator::validate_create(&records).is_ok());
    }

    #[test]
    fn validate_create_11_fails() {
        let records: Vec<Record> = (0..11)
            .map(|i| Record {
                id: None,
                fields: json!({"N": i}),
                created_time: None,
            })
            .collect();
        assert!(RecordValidator::validate_create(&records).is_err());
    }

    #[test]
    fn validate_update_exactly_10() {
        let records: Vec<Record> = (0..10)
            .map(|i| Record {
                id: Some(format!("rec{i}")),
                fields: json!({"N": i}),
                created_time: None,
            })
            .collect();
        assert!(RecordValidator::validate_update(&records).is_ok());
    }

    #[test]
    fn validate_update_11_fails() {
        let records: Vec<Record> = (0..11)
            .map(|i| Record {
                id: Some(format!("rec{i}")),
                fields: json!({"N": i}),
                created_time: None,
            })
            .collect();
        assert!(RecordValidator::validate_update(&records).is_err());
    }

    #[test]
    fn validate_delete_exactly_10() {
        let ids: Vec<String> = (0..10).map(|i| format!("rec{i}")).collect();
        assert!(RecordValidator::validate_delete(&ids).is_ok());
    }

    #[test]
    fn validate_delete_11_fails() {
        let ids: Vec<String> = (0..11).map(|i| format!("rec{i}")).collect();
        assert!(RecordValidator::validate_delete(&ids).is_err());
    }

    // ── RecordValidation trait ──────────────────────────────────

    #[test]
    fn trait_validate_create_request_valid() {
        let req = CreateRecordsRequest {
            table_id: "tbl1".into(),
            records: vec![Record {
                id: None,
                fields: json!({"X": 1}),
                created_time: None,
            }],
            typecast: false,
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn trait_validate_create_request_invalid() {
        let req = CreateRecordsRequest {
            table_id: "tbl1".into(),
            records: vec![],
            typecast: false,
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn trait_validate_update_request_valid() {
        let req = UpdateRecordsRequest {
            table_id: "tbl1".into(),
            records: vec![Record {
                id: Some("rec1".into()),
                fields: json!({"X": 1}),
                created_time: None,
            }],
            typecast: false,
            destructive: false,
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn trait_validate_update_request_invalid() {
        let req = UpdateRecordsRequest {
            table_id: "tbl1".into(),
            records: vec![Record {
                id: None,
                fields: json!({"X": 1}),
                created_time: None,
            }],
            typecast: false,
            destructive: false,
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn trait_validate_delete_request_valid() {
        let req = DeleteRecordsRequest {
            table_id: "tbl1".into(),
            record_ids: vec!["rec1".into()],
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn trait_validate_delete_request_invalid() {
        let req = DeleteRecordsRequest {
            table_id: "tbl1".into(),
            record_ids: vec![],
        };
        assert!(req.validate().is_err());
    }

    // ── Null field values in records ────────────────────────────

    #[test]
    fn record_with_null_field_value() {
        let rec = Record {
            id: Some("rec1".into()),
            fields: json!({"Name": null, "Status": "Active"}),
            created_time: None,
        };
        let json = serde_json::to_value(&rec).unwrap();
        let back: Record = serde_json::from_value(json).unwrap();
        assert!(back.fields["Name"].is_null());
        assert_eq!(back.fields["Status"], "Active");
    }

    #[test]
    fn record_with_all_null_field_values() {
        let rec = Record {
            id: Some("rec1".into()),
            fields: json!({"A": null, "B": null}),
            created_time: None,
        };
        // This is a valid object, even with all null values
        assert!(RecordValidator::validate_create(&[rec]).is_ok());
    }

    // ── Constants ───────────────────────────────────────────────

    #[test]
    fn max_batch_size_is_10() {
        assert_eq!(MAX_BATCH_SIZE, 10);
    }

    #[test]
    fn max_page_size_is_100() {
        assert_eq!(MAX_PAGE_SIZE, 100);
    }

    #[test]
    fn default_page_size_is_100() {
        assert_eq!(DEFAULT_PAGE_SIZE, 100);
    }

    #[test]
    fn default_page_size_equals_max() {
        assert_eq!(DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE);
    }

    // ── Edge cases ──────────────────────────────────────────────

    #[test]
    fn record_with_unicode_field_names() {
        let rec = Record {
            id: None,
            fields: json!({"Nombre": "Prueba", "Descripcion": "Una tarea"}),
            created_time: None,
        };
        let json = serde_json::to_value(&rec).unwrap();
        let back: Record = serde_json::from_value(json).unwrap();
        assert_eq!(back.fields["Nombre"], "Prueba");
    }

    #[test]
    fn record_with_very_long_field_value() {
        let long_val = "x".repeat(10_000);
        let rec = Record {
            id: None,
            fields: json!({"LongField": long_val}),
            created_time: None,
        };
        assert!(RecordValidator::validate_create(&[rec]).is_ok());
    }

    #[test]
    fn list_params_filter_with_special_chars() {
        let params =
            ListRecordsParams::new("tbl1").with_filter("AND({Name} = 'O\\'Brien', {Age} > 21)");
        let qp = params.to_query_params();
        let filter = qp
            .iter()
            .find(|(k, _)| k == "filterByFormula")
            .map(|(_, v)| v.as_str());
        assert!(filter.unwrap().contains("O\\'Brien"));
    }

    #[test]
    fn sort_field_with_space_in_name() {
        let params = ListRecordsParams::new("tbl1").with_sort("First Name", SortDirection::Asc);
        let qp = params.to_query_params();
        assert!(qp.contains(&("sort[0][field]".to_string(), "First Name".to_string())));
    }

    #[test]
    fn list_params_page_size_one() {
        let params = ListRecordsParams::new("tbl1").with_page_size(1);
        assert_eq!(params.page_size, 1);
    }

    #[test]
    fn list_params_max_records_one() {
        let params = ListRecordsParams::new("tbl1").with_max_records(1);
        assert_eq!(params.max_records, Some(1));
    }

    #[test]
    fn record_page_deser_from_api_response() {
        let json = json!({
            "records": [
                {"id": "rec1", "fields": {"Name": "A"}, "createdTime": "2026-01-01"},
                {"id": "rec2", "fields": {"Name": "B"}}
            ],
            "offset": "itr_next_123"
        });
        let page: RecordPage = serde_json::from_value(json).unwrap();
        assert_eq!(page.records.len(), 2);
        assert_eq!(page.records[0].id, Some("rec1".into()));
        assert_eq!(page.records[1].created_time, None);
        assert_eq!(page.offset.as_deref(), Some("itr_next_123"));
    }

    #[test]
    fn record_page_last_page_no_offset() {
        let json = json!({
            "records": [
                {"id": "rec1", "fields": {"Name": "Last"}}
            ]
        });
        let page: RecordPage = serde_json::from_value(json).unwrap();
        assert_eq!(page.records.len(), 1);
        assert!(page.offset.is_none());
    }

    #[test]
    fn create_request_with_typecast() {
        let req = CreateRecordsRequest {
            table_id: "tbl1".into(),
            records: vec![Record {
                id: None,
                fields: json!({"Date": "March 9, 2026"}),
                created_time: None,
            }],
            typecast: true,
        };
        assert!(req.typecast);
        assert!(req.validate().is_ok());
    }

    #[test]
    fn validate_update_mixed_valid_and_invalid() {
        let records = vec![
            Record {
                id: Some("rec1".into()),
                fields: json!({"OK": true}),
                created_time: None,
            },
            Record {
                id: None,
                fields: json!({"Also OK fields": true}),
                created_time: None,
            },
        ];
        let err = RecordValidator::validate_update(&records).unwrap_err();
        assert!(err.iter().any(|e| e.contains("Record 1")));
    }

    #[test]
    fn validate_delete_with_duplicate_ids() {
        // Duplicates are not a validation concern at this level
        let ids = vec!["rec1".to_string(), "rec1".to_string()];
        assert!(RecordValidator::validate_delete(&ids).is_ok());
    }

    #[test]
    fn batch_result_only_deletes() {
        let r = BatchResult {
            created: 0,
            updated: 0,
            deleted: 10,
            errors: vec![],
        };
        assert!(r.is_success());
        assert_eq!(r.deleted, 10);
    }

    #[test]
    fn batch_result_only_updates() {
        let r = BatchResult {
            created: 0,
            updated: 7,
            deleted: 0,
            errors: vec![],
        };
        assert!(r.is_success());
        assert_eq!(r.updated, 7);
    }

    #[test]
    fn batch_error_inequality() {
        let a = BatchError {
            record_id: Some("rec1".into()),
            message: "err".into(),
            error_type: "T".into(),
        };
        let b = BatchError {
            record_id: Some("rec2".into()),
            message: "err".into(),
            error_type: "T".into(),
        };
        assert_ne!(a, b);
    }

    #[test]
    fn query_params_no_fields_key_when_none() {
        let params = ListRecordsParams::new("tbl1");
        let qp = params.to_query_params();
        assert!(!qp.iter().any(|(k, _)| k == "fields[]"));
    }

    #[test]
    fn query_params_no_sort_when_empty() {
        let params = ListRecordsParams::new("tbl1");
        let qp = params.to_query_params();
        assert!(!qp.iter().any(|(k, _)| k.starts_with("sort")));
    }

    #[test]
    fn query_params_no_filter_when_none() {
        let params = ListRecordsParams::new("tbl1");
        let qp = params.to_query_params();
        assert!(!qp.iter().any(|(k, _)| k == "filterByFormula"));
    }

    #[test]
    fn query_params_no_max_records_when_none() {
        let params = ListRecordsParams::new("tbl1");
        let qp = params.to_query_params();
        assert!(!qp.iter().any(|(k, _)| k == "maxRecords"));
    }

    #[test]
    fn query_params_no_view_when_none() {
        let params = ListRecordsParams::new("tbl1");
        let qp = params.to_query_params();
        assert!(!qp.iter().any(|(k, _)| k == "view"));
    }

    #[test]
    fn query_params_no_offset_when_none() {
        let params = ListRecordsParams::new("tbl1");
        let qp = params.to_query_params();
        assert!(!qp.iter().any(|(k, _)| k == "offset"));
    }

    #[test]
    fn record_boolean_field_value() {
        let rec = Record {
            id: None,
            fields: json!({"Active": true, "Archived": false}),
            created_time: None,
        };
        let json = serde_json::to_value(&rec).unwrap();
        let back: Record = serde_json::from_value(json).unwrap();
        assert_eq!(back.fields["Active"], true);
        assert_eq!(back.fields["Archived"], false);
    }

    #[test]
    fn record_numeric_field_values() {
        let rec = Record {
            id: None,
            fields: json!({"Int": 42, "Float": 1.23, "Negative": -5}),
            created_time: None,
        };
        let json = serde_json::to_value(&rec).unwrap();
        let back: Record = serde_json::from_value(json).unwrap();
        assert_eq!(back.fields["Int"], 42);
        assert_eq!(back.fields["Negative"], -5);
    }

    #[test]
    fn record_nested_array_field() {
        let rec = Record {
            id: None,
            fields: json!({"Attachments": [
                {"url": "https://example.com/a.png", "filename": "a.png"},
                {"url": "https://example.com/b.pdf", "filename": "b.pdf"}
            ]}),
            created_time: None,
        };
        assert!(RecordValidator::validate_create(&[rec]).is_ok());
    }

    #[test]
    fn sort_direction_eq() {
        assert_eq!(SortDirection::Asc, SortDirection::Asc);
        assert_eq!(SortDirection::Desc, SortDirection::Desc);
        assert_ne!(SortDirection::Asc, SortDirection::Desc);
    }
}
