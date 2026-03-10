//! Excel Online Spreadsheets — Microsoft Graph workbook/range/table operations.
//!
//! Provides typed wrappers for reading workbook metadata, reading/writing cell
//! ranges and tables. Every operation family is capability-gated through
//! [`ExcelPolicy`]; writes emit [`ExcelAuditEvent`] receipts and fail closed
//! when denied.

use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// Visibility
// ---------------------------------------------------------------------------

/// Worksheet visibility state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Visibility {
    Visible,
    Hidden,
    VeryHidden,
}

impl fmt::Display for Visibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Visible => f.write_str("visible"),
            Self::Hidden => f.write_str("hidden"),
            Self::VeryHidden => f.write_str("veryHidden"),
        }
    }
}

// ---------------------------------------------------------------------------
// CellValue
// ---------------------------------------------------------------------------

/// A single cell value in a spreadsheet.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum CellValue {
    Text(String),
    Number(f64),
    Boolean(bool),
    Empty,
    Error(String),
    Formula(String),
}

impl CellValue {
    /// Try to extract a text representation.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(s) | Self::Formula(s) | Self::Error(s) => Some(s),
            _ => None,
        }
    }

    /// Try to extract a numeric value.
    #[must_use]
    pub fn as_number(&self) -> Option<f64> {
        match self {
            Self::Number(n) => Some(*n),
            _ => None,
        }
    }

    /// Returns `true` when the cell is [`CellValue::Empty`].
    #[must_use]
    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Empty)
    }
}

// ---------------------------------------------------------------------------
// Workbook
// ---------------------------------------------------------------------------

/// Metadata for an Excel workbook hosted in OneDrive/SharePoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workbook {
    pub id: String,
    pub name: String,
    #[serde(rename = "webUrl")]
    pub web_url: Option<String>,
    #[serde(rename = "driveItemId")]
    pub drive_item_id: Option<String>,
    #[serde(rename = "worksheetCount")]
    pub worksheet_count: Option<u32>,
}

// ---------------------------------------------------------------------------
// Worksheet
// ---------------------------------------------------------------------------

/// A single worksheet inside a workbook.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Worksheet {
    pub id: String,
    pub name: String,
    pub position: u32,
    pub visibility: Visibility,
}

// ---------------------------------------------------------------------------
// CellRange
// ---------------------------------------------------------------------------

/// A rectangular range of cells including their values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellRange {
    pub address: String,
    #[serde(rename = "rowCount")]
    pub row_count: u32,
    #[serde(rename = "columnCount")]
    pub column_count: u32,
    pub values: Vec<Vec<CellValue>>,
}

impl CellRange {
    /// Validate that `address` looks like a valid A1-style reference (e.g.
    /// `A1`, `A1:B10`, `Sheet1!A1:C5`).
    pub fn validate_address(&self) -> Result<(), ExcelValidationError> {
        RangeAddress::parse(&self.address).map(|_| ())
    }

    /// Validate that the declared dimensions match the values grid.
    pub fn validate_size(&self) -> Result<(), ExcelValidationError> {
        let actual_rows = self.values.len() as u32;
        if actual_rows != self.row_count {
            return Err(ExcelValidationError::RangeTooLarge {
                requested: u64::from(self.row_count) * u64::from(self.column_count),
                max: u64::from(actual_rows) * u64::from(self.column_count),
            });
        }
        for row in &self.values {
            if row.len() as u32 != self.column_count {
                return Err(ExcelValidationError::RangeTooLarge {
                    requested: u64::from(self.row_count) * u64::from(self.column_count),
                    max: u64::from(self.row_count) * u64::from(row.len() as u32),
                });
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RangeAddress
// ---------------------------------------------------------------------------

/// Parsed representation of an A1 range reference such as `Sheet1!A1:B10` or
/// `A1:C5` or just `A1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeAddress {
    pub sheet_name: Option<String>,
    pub start_cell: String,
    pub end_cell: Option<String>,
}

impl RangeAddress {
    /// Parse a range string. Accepted forms:
    /// - `A1`
    /// - `A1:B10`
    /// - `Sheet1!A1:B10`
    /// - `'Sheet 1'!A1:B10`
    pub fn parse(input: &str) -> Result<Self, ExcelValidationError> {
        if input.is_empty() {
            return Err(ExcelValidationError::InvalidRangeAddress(
                "empty address".into(),
            ));
        }

        let (sheet_name, cell_part) = if let Some(idx) = input.find('!') {
            let raw_sheet = &input[..idx];
            let sheet = raw_sheet.trim_matches('\'');
            if sheet.is_empty() {
                return Err(ExcelValidationError::InvalidRangeAddress(
                    "empty sheet name".into(),
                ));
            }
            (Some(sheet.to_string()), &input[idx + 1..])
        } else {
            (None, input)
        };

        if cell_part.is_empty() {
            return Err(ExcelValidationError::InvalidRangeAddress(
                "no cell reference after sheet name".into(),
            ));
        }

        let (start_cell, end_cell) = if let Some(colon_idx) = cell_part.find(':') {
            let start = &cell_part[..colon_idx];
            let end = &cell_part[colon_idx + 1..];
            if start.is_empty() || end.is_empty() {
                return Err(ExcelValidationError::InvalidRangeAddress(
                    "incomplete range".into(),
                ));
            }
            (start.to_string(), Some(end.to_string()))
        } else {
            (cell_part.to_string(), None)
        };

        // Validate cell references (must start with letter, contain digits).
        Self::validate_cell_ref(&start_cell)?;
        if let Some(ref end) = end_cell {
            Self::validate_cell_ref(end)?;
        }

        Ok(Self {
            sheet_name,
            start_cell,
            end_cell,
        })
    }

    fn validate_cell_ref(cell: &str) -> Result<(), ExcelValidationError> {
        if cell.is_empty() {
            return Err(ExcelValidationError::InvalidRangeAddress(
                "empty cell reference".into(),
            ));
        }
        let chars: Vec<char> = cell.chars().collect();
        if !chars[0].is_ascii_alphabetic() {
            return Err(ExcelValidationError::InvalidRangeAddress(format!(
                "cell reference must start with a letter: {cell}"
            )));
        }
        let has_digit = chars.iter().any(|c| c.is_ascii_digit());
        if !has_digit {
            return Err(ExcelValidationError::InvalidRangeAddress(format!(
                "cell reference must contain a row number: {cell}"
            )));
        }
        // All chars must be alphanumeric.
        if !chars.iter().all(|c| c.is_ascii_alphanumeric()) {
            return Err(ExcelValidationError::InvalidRangeAddress(format!(
                "cell reference contains invalid characters: {cell}"
            )));
        }
        Ok(())
    }
}

impl fmt::Display for RangeAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref sheet) = self.sheet_name {
            if sheet.contains(' ') {
                write!(f, "'{sheet}'!")?;
            } else {
                write!(f, "{sheet}!")?;
            }
        }
        write!(f, "{}", self.start_cell)?;
        if let Some(ref end) = self.end_cell {
            write!(f, ":{end}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Table / TableColumn / TableRow
// ---------------------------------------------------------------------------

/// An Excel table (ListObject).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Table {
    pub id: String,
    pub name: String,
    #[serde(rename = "showHeaders")]
    pub show_headers: bool,
    #[serde(rename = "rowCount")]
    pub row_count: u32,
    #[serde(rename = "columnCount")]
    pub column_count: u32,
    pub columns: Vec<TableColumn>,
}

/// A single column inside an Excel table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableColumn {
    pub id: String,
    pub name: String,
    pub index: u32,
}

/// A single row in an Excel table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableRow {
    pub index: u32,
    pub values: Vec<CellValue>,
}

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

/// Request to read a cell range from a workbook.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadRangeRequest {
    pub workbook_id: String,
    pub range_address: RangeAddress,
}

impl ReadRangeRequest {
    /// Validate the request fields.
    pub fn validate(&self) -> Result<(), ExcelValidationError> {
        if self.workbook_id.is_empty() {
            return Err(ExcelValidationError::WorkbookNotFound(
                "workbook_id is empty".into(),
            ));
        }
        // Range address was already parsed, so it should be structurally valid.
        // Re-validate by round-tripping.
        let addr_str = self.range_address.to_string();
        RangeAddress::parse(&addr_str)?;
        Ok(())
    }
}

/// Request to write values into a cell range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteRangeRequest {
    pub workbook_id: String,
    pub range_address: RangeAddress,
    pub values: Vec<Vec<CellValue>>,
}

impl WriteRangeRequest {
    /// Validate the request, enforcing size bounds (max 10 000 cells).
    pub fn validate(&self) -> Result<(), ExcelValidationError> {
        if self.workbook_id.is_empty() {
            return Err(ExcelValidationError::WorkbookNotFound(
                "workbook_id is empty".into(),
            ));
        }
        if self.values.is_empty() {
            return Err(ExcelValidationError::EmptyValues);
        }
        let rows = self.values.len() as u64;
        let cols = self.values.first().map_or(0, |r| r.len() as u64);
        let total = rows * cols;
        if total > ExcelValidator::DEFAULT_MAX_RANGE_CELLS {
            return Err(ExcelValidationError::RangeTooLarge {
                requested: total,
                max: ExcelValidator::DEFAULT_MAX_RANGE_CELLS,
            });
        }
        let addr_str = self.range_address.to_string();
        RangeAddress::parse(&addr_str)?;
        Ok(())
    }
}

/// Request to append rows to a named table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendRowsRequest {
    pub workbook_id: String,
    pub table_name: String,
    pub rows: Vec<Vec<CellValue>>,
}

impl AppendRowsRequest {
    /// Validate the request, enforcing max 1 000 rows per append.
    pub fn validate(&self) -> Result<(), ExcelValidationError> {
        if self.workbook_id.is_empty() {
            return Err(ExcelValidationError::WorkbookNotFound(
                "workbook_id is empty".into(),
            ));
        }
        if self.table_name.is_empty() {
            return Err(ExcelValidationError::EmptyValues);
        }
        if self.rows.is_empty() {
            return Err(ExcelValidationError::EmptyValues);
        }
        let count = self.rows.len() as u64;
        if count > ExcelValidator::DEFAULT_MAX_APPEND_ROWS {
            return Err(ExcelValidationError::TooManyRows {
                requested: count,
                max: ExcelValidator::DEFAULT_MAX_APPEND_ROWS,
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// Capability-gate policy for Excel operations. Default deny — each family
/// must be explicitly enabled.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct ExcelPolicy {
    pub allow_read: bool,
    pub allow_write_ranges: bool,
    pub allow_write_tables: bool,
    pub allow_formulas: bool,
    pub require_approval_for_write: bool,
    pub max_cells_per_request: u32,
    pub max_rows_per_append: u32,
}

impl Default for ExcelPolicy {
    /// Default deny — nothing is permitted.
    fn default() -> Self {
        Self {
            allow_read: false,
            allow_write_ranges: false,
            allow_write_tables: false,
            allow_formulas: false,
            require_approval_for_write: true,
            max_cells_per_request: 10_000,
            max_rows_per_append: 1_000,
        }
    }
}

impl ExcelPolicy {
    /// Create a permissive policy (all operations allowed, no approval).
    #[must_use]
    pub fn new_permissive() -> Self {
        Self {
            allow_read: true,
            allow_write_ranges: true,
            allow_write_tables: true,
            allow_formulas: true,
            require_approval_for_write: false,
            max_cells_per_request: 10_000,
            max_rows_per_append: 1_000,
        }
    }

    /// Create a read-only policy.
    #[must_use]
    pub fn new_readonly() -> Self {
        Self {
            allow_read: true,
            allow_write_ranges: false,
            allow_write_tables: false,
            allow_formulas: false,
            require_approval_for_write: true,
            max_cells_per_request: 10_000,
            max_rows_per_append: 1_000,
        }
    }

    /// Check whether reads are allowed.
    pub fn check_read(&self) -> Result<(), ExcelValidationError> {
        if self.allow_read {
            Ok(())
        } else {
            Err(ExcelValidationError::WriteDenied(
                "read operations are not permitted".into(),
            ))
        }
    }

    /// Check whether writes (range or table) are allowed.
    pub fn check_write(&self, is_table: bool) -> Result<(), ExcelValidationError> {
        if is_table {
            if !self.allow_write_tables {
                return Err(ExcelValidationError::WriteDenied(
                    "table write operations are not permitted".into(),
                ));
            }
        } else if !self.allow_write_ranges {
            return Err(ExcelValidationError::WriteDenied(
                "range write operations are not permitted".into(),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Validator
// ---------------------------------------------------------------------------

/// Structural validator for Excel requests enforcing size bounds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExcelValidator {
    pub max_range_cells: u64,
    pub max_append_rows: u64,
    pub max_workbook_name: usize,
}

impl ExcelValidator {
    /// Default max cells per range request.
    pub const DEFAULT_MAX_RANGE_CELLS: u64 = 10_000;
    /// Default max rows per append request.
    pub const DEFAULT_MAX_APPEND_ROWS: u64 = 1_000;
    /// Default max workbook name length.
    pub const DEFAULT_MAX_WORKBOOK_NAME: usize = 256;
}

impl Default for ExcelValidator {
    fn default() -> Self {
        Self {
            max_range_cells: Self::DEFAULT_MAX_RANGE_CELLS,
            max_append_rows: Self::DEFAULT_MAX_APPEND_ROWS,
            max_workbook_name: Self::DEFAULT_MAX_WORKBOOK_NAME,
        }
    }
}

impl ExcelValidator {
    /// Validate a read-range request.
    pub fn validate_range_request(
        &self,
        req: &ReadRangeRequest,
    ) -> Result<(), ExcelValidationError> {
        req.validate()
    }

    /// Validate a write-range request against this validator's bounds.
    pub fn validate_write_request(
        &self,
        req: &WriteRangeRequest,
    ) -> Result<(), ExcelValidationError> {
        if req.workbook_id.is_empty() {
            return Err(ExcelValidationError::WorkbookNotFound(
                "workbook_id is empty".into(),
            ));
        }
        if req.values.is_empty() {
            return Err(ExcelValidationError::EmptyValues);
        }
        let rows = req.values.len() as u64;
        let cols = req.values.first().map_or(0, |r| r.len() as u64);
        let total = rows * cols;
        if total > self.max_range_cells {
            return Err(ExcelValidationError::RangeTooLarge {
                requested: total,
                max: self.max_range_cells,
            });
        }
        Ok(())
    }

    /// Validate an append-rows request against this validator's bounds.
    pub fn validate_append(&self, req: &AppendRowsRequest) -> Result<(), ExcelValidationError> {
        if req.workbook_id.is_empty() {
            return Err(ExcelValidationError::WorkbookNotFound(
                "workbook_id is empty".into(),
            ));
        }
        if req.rows.is_empty() || req.table_name.is_empty() {
            return Err(ExcelValidationError::EmptyValues);
        }
        let count = req.rows.len() as u64;
        if count > self.max_append_rows {
            return Err(ExcelValidationError::TooManyRows {
                requested: count,
                max: self.max_append_rows,
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Validation errors
// ---------------------------------------------------------------------------

/// Validation errors for Excel operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum ExcelValidationError {
    #[error("Invalid range address: {0}")]
    InvalidRangeAddress(String),

    #[error("Range too large: requested {requested} cells, max {max}")]
    RangeTooLarge { requested: u64, max: u64 },

    #[error("Too many rows: requested {requested}, max {max}")]
    TooManyRows { requested: u64, max: u64 },

    #[error("Values payload must not be empty")]
    EmptyValues,

    #[error("Workbook not found: {0}")]
    WorkbookNotFound(String),

    #[error("Write denied: {0}")]
    WriteDenied(String),
}

// ---------------------------------------------------------------------------
// Audit events
// ---------------------------------------------------------------------------

/// Audit receipt emitted for every successful write operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExcelAuditEvent {
    pub timestamp: String,
    pub action: String,
    pub workbook_id: String,
    pub range: Option<String>,
    pub cell_count: u64,
    pub row_count: u64,
}

impl ExcelAuditEvent {
    /// Create an audit event for a range write.
    #[must_use]
    pub fn range_write(workbook_id: &str, range: &str, cell_count: u64, timestamp: &str) -> Self {
        Self {
            timestamp: timestamp.to_string(),
            action: "write_range".to_string(),
            workbook_id: workbook_id.to_string(),
            range: Some(range.to_string()),
            cell_count,
            row_count: 0,
        }
    }

    /// Create an audit event for a table append.
    #[must_use]
    pub fn table_append(
        workbook_id: &str,
        table_name: &str,
        row_count: u64,
        timestamp: &str,
    ) -> Self {
        Self {
            timestamp: timestamp.to_string(),
            action: "append_rows".to_string(),
            workbook_id: workbook_id.to_string(),
            range: Some(table_name.to_string()),
            cell_count: 0,
            row_count,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Visibility ====================

    #[test]
    fn visibility_display_visible() {
        assert_eq!(Visibility::Visible.to_string(), "visible");
    }

    #[test]
    fn visibility_display_hidden() {
        assert_eq!(Visibility::Hidden.to_string(), "hidden");
    }

    #[test]
    fn visibility_display_very_hidden() {
        assert_eq!(Visibility::VeryHidden.to_string(), "veryHidden");
    }

    #[test]
    fn visibility_serde_roundtrip() {
        for v in [
            Visibility::Visible,
            Visibility::Hidden,
            Visibility::VeryHidden,
        ] {
            let json = serde_json::to_value(v).unwrap();
            let back: Visibility = serde_json::from_value(json).unwrap();
            assert_eq!(back, v);
        }
    }

    #[test]
    fn visibility_clone_eq() {
        let v = Visibility::Hidden;
        let c = v;
        assert_eq!(v, c);
    }

    #[test]
    fn visibility_debug() {
        let dbg = format!("{:?}", Visibility::VeryHidden);
        assert!(dbg.contains("VeryHidden"), "got: {dbg}");
    }

    #[test]
    fn visibility_deserialize_camelcase() {
        let v: Visibility = serde_json::from_str("\"veryHidden\"").unwrap();
        assert_eq!(v, Visibility::VeryHidden);
    }

    // ==================== CellValue ====================

    #[test]
    fn cell_value_text_as_text() {
        let cv = CellValue::Text("hello".into());
        assert_eq!(cv.as_text(), Some("hello"));
        assert_eq!(cv.as_number(), None);
        assert!(!cv.is_empty());
    }

    #[test]
    fn cell_value_number_as_number() {
        let cv = CellValue::Number(1.23);
        assert_eq!(cv.as_number(), Some(1.23));
        assert_eq!(cv.as_text(), None);
        assert!(!cv.is_empty());
    }

    #[test]
    fn cell_value_boolean_accessors() {
        let cv = CellValue::Boolean(true);
        assert_eq!(cv.as_text(), None);
        assert_eq!(cv.as_number(), None);
        assert!(!cv.is_empty());
    }

    #[test]
    fn cell_value_empty_is_empty() {
        let cv = CellValue::Empty;
        assert!(cv.is_empty());
        assert_eq!(cv.as_text(), None);
        assert_eq!(cv.as_number(), None);
    }

    #[test]
    fn cell_value_error_as_text() {
        let cv = CellValue::Error("#REF!".into());
        assert_eq!(cv.as_text(), Some("#REF!"));
        assert!(!cv.is_empty());
    }

    #[test]
    fn cell_value_formula_as_text() {
        let cv = CellValue::Formula("=SUM(A1:A10)".into());
        assert_eq!(cv.as_text(), Some("=SUM(A1:A10)"));
        assert_eq!(cv.as_number(), None);
    }

    #[test]
    fn cell_value_serde_roundtrip_text() {
        let cv = CellValue::Text("test".into());
        let json = serde_json::to_value(&cv).unwrap();
        let back: CellValue = serde_json::from_value(json).unwrap();
        assert_eq!(back, cv);
    }

    #[test]
    fn cell_value_serde_roundtrip_number() {
        let cv = CellValue::Number(42.5);
        let json = serde_json::to_value(&cv).unwrap();
        let back: CellValue = serde_json::from_value(json).unwrap();
        assert_eq!(back, cv);
    }

    #[test]
    fn cell_value_serde_roundtrip_boolean() {
        let cv = CellValue::Boolean(false);
        let json = serde_json::to_value(&cv).unwrap();
        let back: CellValue = serde_json::from_value(json).unwrap();
        assert_eq!(back, cv);
    }

    #[test]
    fn cell_value_serde_roundtrip_empty() {
        let cv = CellValue::Empty;
        let json = serde_json::to_value(&cv).unwrap();
        let back: CellValue = serde_json::from_value(json).unwrap();
        assert_eq!(back, cv);
    }

    #[test]
    fn cell_value_serde_roundtrip_error() {
        let cv = CellValue::Error("#DIV/0!".into());
        let json = serde_json::to_value(&cv).unwrap();
        let back: CellValue = serde_json::from_value(json).unwrap();
        assert_eq!(back, cv);
    }

    #[test]
    fn cell_value_serde_roundtrip_formula() {
        let cv = CellValue::Formula("=A1+B1".into());
        let json = serde_json::to_value(&cv).unwrap();
        let back: CellValue = serde_json::from_value(json).unwrap();
        assert_eq!(back, cv);
    }

    #[test]
    fn cell_value_clone() {
        let cv = CellValue::Text("clone me".into());
        let cloned = cv.clone();
        assert_eq!(cloned, cv);
    }

    #[test]
    fn cell_value_debug() {
        let cv = CellValue::Number(7.5);
        let dbg = format!("{cv:?}");
        assert!(dbg.contains("Number"), "got: {dbg}");
        assert!(dbg.contains("7.5"), "got: {dbg}");
    }

    #[test]
    fn cell_value_ne() {
        assert_ne!(CellValue::Text("a".into()), CellValue::Text("b".into()));
        assert_ne!(CellValue::Number(1.0), CellValue::Number(2.0));
        assert_ne!(CellValue::Empty, CellValue::Boolean(false));
    }

    // ==================== Workbook ====================

    #[test]
    fn workbook_serde_roundtrip() {
        let wb = Workbook {
            id: "wb-1".into(),
            name: "Budget.xlsx".into(),
            web_url: Some("https://example.com/wb".into()),
            drive_item_id: Some("drv-1".into()),
            worksheet_count: Some(3),
        };
        let json = serde_json::to_value(&wb).unwrap();
        assert_eq!(json["id"], "wb-1");
        assert_eq!(json["name"], "Budget.xlsx");
        assert_eq!(json["webUrl"], "https://example.com/wb");
        assert_eq!(json["driveItemId"], "drv-1");
        assert_eq!(json["worksheetCount"], 3);
        let back: Workbook = serde_json::from_value(json).unwrap();
        assert_eq!(back.id, "wb-1");
    }

    #[test]
    fn workbook_optional_fields_none() {
        let wb = Workbook {
            id: "wb-2".into(),
            name: "Simple.xlsx".into(),
            web_url: None,
            drive_item_id: None,
            worksheet_count: None,
        };
        let json = serde_json::to_value(&wb).unwrap();
        assert!(json.get("webUrl").is_none() || json["webUrl"].is_null());
    }

    #[test]
    fn workbook_clone() {
        let wb = Workbook {
            id: "wb-c".into(),
            name: "Clone.xlsx".into(),
            web_url: None,
            drive_item_id: None,
            worksheet_count: Some(1),
        };
        let cloned = wb.clone();
        assert_eq!(cloned.id, wb.id);
        assert_eq!(cloned.worksheet_count, wb.worksheet_count);
    }

    #[test]
    fn workbook_debug() {
        let wb = Workbook {
            id: "wb-d".into(),
            name: "Debug.xlsx".into(),
            web_url: None,
            drive_item_id: None,
            worksheet_count: None,
        };
        let dbg = format!("{wb:?}");
        assert!(dbg.contains("Workbook"), "got: {dbg}");
    }

    // ==================== Worksheet ====================

    #[test]
    fn worksheet_serde_roundtrip() {
        let ws = Worksheet {
            id: "ws-1".into(),
            name: "Sheet1".into(),
            position: 0,
            visibility: Visibility::Visible,
        };
        let json = serde_json::to_value(&ws).unwrap();
        assert_eq!(json["name"], "Sheet1");
        assert_eq!(json["position"], 0);
        let back: Worksheet = serde_json::from_value(json).unwrap();
        assert_eq!(back.visibility, Visibility::Visible);
    }

    #[test]
    fn worksheet_hidden() {
        let ws = Worksheet {
            id: "ws-h".into(),
            name: "Hidden Sheet".into(),
            position: 2,
            visibility: Visibility::Hidden,
        };
        assert_eq!(ws.visibility, Visibility::Hidden);
    }

    #[test]
    fn worksheet_clone() {
        let ws = Worksheet {
            id: "ws-c".into(),
            name: "Cloned".into(),
            position: 5,
            visibility: Visibility::VeryHidden,
        };
        let cloned = ws.clone();
        assert_eq!(cloned.id, ws.id);
        assert_eq!(cloned.position, ws.position);
    }

    #[test]
    fn worksheet_debug() {
        let ws = Worksheet {
            id: "ws-d".into(),
            name: "Debug".into(),
            position: 0,
            visibility: Visibility::Visible,
        };
        let dbg = format!("{ws:?}");
        assert!(dbg.contains("Worksheet"), "got: {dbg}");
    }

    // ==================== CellRange ====================

    #[test]
    fn cell_range_validate_address_valid() {
        let cr = CellRange {
            address: "A1:B10".into(),
            row_count: 1,
            column_count: 1,
            values: vec![vec![CellValue::Empty]],
        };
        assert!(cr.validate_address().is_ok());
    }

    #[test]
    fn cell_range_validate_address_invalid() {
        let cr = CellRange {
            address: String::new(),
            row_count: 0,
            column_count: 0,
            values: vec![],
        };
        assert!(cr.validate_address().is_err());
    }

    #[test]
    fn cell_range_validate_size_matching() {
        let cr = CellRange {
            address: "A1:B2".into(),
            row_count: 2,
            column_count: 2,
            values: vec![
                vec![CellValue::Number(1.0), CellValue::Number(2.0)],
                vec![CellValue::Number(1.23), CellValue::Number(4.0)],
            ],
        };
        assert!(cr.validate_size().is_ok());
    }

    #[test]
    fn cell_range_validate_size_row_mismatch() {
        let cr = CellRange {
            address: "A1:B3".into(),
            row_count: 3,
            column_count: 2,
            values: vec![
                vec![CellValue::Empty, CellValue::Empty],
                vec![CellValue::Empty, CellValue::Empty],
            ],
        };
        assert!(cr.validate_size().is_err());
    }

    #[test]
    fn cell_range_validate_size_col_mismatch() {
        let cr = CellRange {
            address: "A1:C2".into(),
            row_count: 2,
            column_count: 3,
            values: vec![
                vec![CellValue::Empty, CellValue::Empty],
                vec![CellValue::Empty, CellValue::Empty],
            ],
        };
        assert!(cr.validate_size().is_err());
    }

    #[test]
    fn cell_range_serde_roundtrip() {
        let cr = CellRange {
            address: "Sheet1!A1:B2".into(),
            row_count: 2,
            column_count: 2,
            values: vec![
                vec![CellValue::Text("a".into()), CellValue::Number(1.0)],
                vec![CellValue::Boolean(true), CellValue::Empty],
            ],
        };
        let json = serde_json::to_value(&cr).unwrap();
        let back: CellRange = serde_json::from_value(json).unwrap();
        assert_eq!(back.address, "Sheet1!A1:B2");
        assert_eq!(back.row_count, 2);
        assert_eq!(back.column_count, 2);
        assert_eq!(back.values.len(), 2);
    }

    #[test]
    fn cell_range_clone() {
        let cr = CellRange {
            address: "A1".into(),
            row_count: 1,
            column_count: 1,
            values: vec![vec![CellValue::Text("x".into())]],
        };
        let cloned = cr.clone();
        assert_eq!(cloned.address, cr.address);
    }

    #[test]
    fn cell_range_debug() {
        let cr = CellRange {
            address: "D5".into(),
            row_count: 1,
            column_count: 1,
            values: vec![vec![CellValue::Empty]],
        };
        let dbg = format!("{cr:?}");
        assert!(dbg.contains("CellRange"), "got: {dbg}");
    }

    // ==================== RangeAddress ====================

    #[test]
    fn range_address_parse_single_cell() {
        let addr = RangeAddress::parse("A1").unwrap();
        assert!(addr.sheet_name.is_none());
        assert_eq!(addr.start_cell, "A1");
        assert!(addr.end_cell.is_none());
    }

    #[test]
    fn range_address_parse_range() {
        let addr = RangeAddress::parse("A1:B10").unwrap();
        assert!(addr.sheet_name.is_none());
        assert_eq!(addr.start_cell, "A1");
        assert_eq!(addr.end_cell.as_deref(), Some("B10"));
    }

    #[test]
    fn range_address_parse_with_sheet() {
        let addr = RangeAddress::parse("Sheet1!A1:C5").unwrap();
        assert_eq!(addr.sheet_name.as_deref(), Some("Sheet1"));
        assert_eq!(addr.start_cell, "A1");
        assert_eq!(addr.end_cell.as_deref(), Some("C5"));
    }

    #[test]
    fn range_address_parse_quoted_sheet() {
        let addr = RangeAddress::parse("'Sheet 1'!A1:B10").unwrap();
        assert_eq!(addr.sheet_name.as_deref(), Some("Sheet 1"));
        assert_eq!(addr.start_cell, "A1");
        assert_eq!(addr.end_cell.as_deref(), Some("B10"));
    }

    #[test]
    fn range_address_parse_empty_fails() {
        assert!(RangeAddress::parse("").is_err());
    }

    #[test]
    fn range_address_parse_no_cell_after_sheet_fails() {
        assert!(RangeAddress::parse("Sheet1!").is_err());
    }

    #[test]
    fn range_address_parse_empty_sheet_fails() {
        assert!(RangeAddress::parse("'!'A1").is_err());
    }

    #[test]
    fn range_address_parse_incomplete_range_fails() {
        assert!(RangeAddress::parse("A1:").is_err());
        assert!(RangeAddress::parse(":B5").is_err());
    }

    #[test]
    fn range_address_parse_no_digits_fails() {
        assert!(RangeAddress::parse("AB").is_err());
    }

    #[test]
    fn range_address_parse_starts_with_digit_fails() {
        assert!(RangeAddress::parse("1A").is_err());
    }

    #[test]
    fn range_address_display_single_cell() {
        let addr = RangeAddress {
            sheet_name: None,
            start_cell: "A1".into(),
            end_cell: None,
        };
        assert_eq!(addr.to_string(), "A1");
    }

    #[test]
    fn range_address_display_range() {
        let addr = RangeAddress {
            sheet_name: None,
            start_cell: "A1".into(),
            end_cell: Some("B10".into()),
        };
        assert_eq!(addr.to_string(), "A1:B10");
    }

    #[test]
    fn range_address_display_with_sheet() {
        let addr = RangeAddress {
            sheet_name: Some("Sheet1".into()),
            start_cell: "A1".into(),
            end_cell: Some("C5".into()),
        };
        assert_eq!(addr.to_string(), "Sheet1!A1:C5");
    }

    #[test]
    fn range_address_display_quoted_sheet_with_space() {
        let addr = RangeAddress {
            sheet_name: Some("My Sheet".into()),
            start_cell: "D1".into(),
            end_cell: Some("F20".into()),
        };
        assert_eq!(addr.to_string(), "'My Sheet'!D1:F20");
    }

    #[test]
    fn range_address_serde_roundtrip() {
        let addr = RangeAddress {
            sheet_name: Some("Data".into()),
            start_cell: "B2".into(),
            end_cell: Some("Z100".into()),
        };
        let json = serde_json::to_value(&addr).unwrap();
        let back: RangeAddress = serde_json::from_value(json).unwrap();
        assert_eq!(back, addr);
    }

    #[test]
    fn range_address_parse_roundtrip() {
        let inputs = ["A1", "A1:B10", "Sheet1!A1:C5", "'Sheet 1'!D1:F20"];
        for input in inputs {
            let parsed = RangeAddress::parse(input).unwrap();
            let display = parsed.to_string();
            let reparsed = RangeAddress::parse(&display).unwrap();
            assert_eq!(parsed, reparsed, "roundtrip failed for: {input}");
        }
    }

    #[test]
    fn range_address_clone() {
        let addr = RangeAddress::parse("Z99:AA100").unwrap();
        let cloned = addr.clone();
        assert_eq!(cloned, addr);
    }

    #[test]
    fn range_address_debug() {
        let addr = RangeAddress::parse("A1").unwrap();
        let dbg = format!("{addr:?}");
        assert!(dbg.contains("RangeAddress"), "got: {dbg}");
    }

    #[test]
    fn range_address_special_characters_in_ref_fails() {
        assert!(RangeAddress::parse("A$1").is_err());
    }

    #[test]
    fn range_address_multichar_column() {
        let addr = RangeAddress::parse("AA1:ZZ999").unwrap();
        assert_eq!(addr.start_cell, "AA1");
        assert_eq!(addr.end_cell.as_deref(), Some("ZZ999"));
    }

    // ==================== Table ====================

    #[test]
    fn table_serde_roundtrip() {
        let tbl = Table {
            id: "tbl-1".into(),
            name: "SalesData".into(),
            show_headers: true,
            row_count: 100,
            column_count: 5,
            columns: vec![
                TableColumn {
                    id: "col-1".into(),
                    name: "Product".into(),
                    index: 0,
                },
                TableColumn {
                    id: "col-2".into(),
                    name: "Revenue".into(),
                    index: 1,
                },
            ],
        };
        let json = serde_json::to_value(&tbl).unwrap();
        assert_eq!(json["name"], "SalesData");
        assert_eq!(json["showHeaders"], true);
        assert_eq!(json["rowCount"], 100);
        let back: Table = serde_json::from_value(json).unwrap();
        assert_eq!(back.columns.len(), 2);
    }

    #[test]
    fn table_no_headers() {
        let tbl = Table {
            id: "tbl-nh".into(),
            name: "NoHeaders".into(),
            show_headers: false,
            row_count: 10,
            column_count: 2,
            columns: vec![],
        };
        assert!(!tbl.show_headers);
    }

    #[test]
    fn table_clone() {
        let tbl = Table {
            id: "tbl-c".into(),
            name: "Clone".into(),
            show_headers: true,
            row_count: 5,
            column_count: 3,
            columns: vec![],
        };
        let cloned = tbl.clone();
        assert_eq!(cloned.id, tbl.id);
        assert_eq!(cloned.row_count, tbl.row_count);
    }

    #[test]
    fn table_debug() {
        let tbl = Table {
            id: "tbl-d".into(),
            name: "Debug".into(),
            show_headers: true,
            row_count: 0,
            column_count: 0,
            columns: vec![],
        };
        let dbg = format!("{tbl:?}");
        assert!(dbg.contains("Table"), "got: {dbg}");
    }

    // ==================== TableColumn ====================

    #[test]
    fn table_column_serde_roundtrip() {
        let col = TableColumn {
            id: "tc-1".into(),
            name: "Amount".into(),
            index: 3,
        };
        let json = serde_json::to_value(&col).unwrap();
        assert_eq!(json["index"], 3);
        let back: TableColumn = serde_json::from_value(json).unwrap();
        assert_eq!(back.name, "Amount");
    }

    #[test]
    fn table_column_clone() {
        let col = TableColumn {
            id: "tc-c".into(),
            name: "Col".into(),
            index: 0,
        };
        let cloned = col.clone();
        assert_eq!(cloned.id, col.id);
    }

    #[test]
    fn table_column_debug() {
        let col = TableColumn {
            id: "tc-d".into(),
            name: "Dbg".into(),
            index: 7,
        };
        let dbg = format!("{col:?}");
        assert!(dbg.contains("TableColumn"), "got: {dbg}");
    }

    // ==================== TableRow ====================

    #[test]
    fn table_row_serde_roundtrip() {
        let row = TableRow {
            index: 0,
            values: vec![CellValue::Text("Alice".into()), CellValue::Number(1_000.0)],
        };
        let json = serde_json::to_value(&row).unwrap();
        assert_eq!(json["index"], 0);
        let back: TableRow = serde_json::from_value(json).unwrap();
        assert_eq!(back.values.len(), 2);
    }

    #[test]
    fn table_row_empty_values() {
        let row = TableRow {
            index: 5,
            values: vec![],
        };
        assert!(row.values.is_empty());
    }

    #[test]
    fn table_row_clone() {
        let row = TableRow {
            index: 3,
            values: vec![CellValue::Boolean(true)],
        };
        let cloned = row.clone();
        assert_eq!(cloned.index, row.index);
        assert_eq!(cloned.values, row.values);
    }

    #[test]
    fn table_row_debug() {
        let row = TableRow {
            index: 0,
            values: vec![CellValue::Empty],
        };
        let dbg = format!("{row:?}");
        assert!(dbg.contains("TableRow"), "got: {dbg}");
    }

    // ==================== ReadRangeRequest ====================

    #[test]
    fn read_range_request_valid() {
        let req = ReadRangeRequest {
            workbook_id: "wb-1".into(),
            range_address: RangeAddress::parse("A1:B10").unwrap(),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn read_range_request_empty_workbook_id() {
        let req = ReadRangeRequest {
            workbook_id: String::new(),
            range_address: RangeAddress::parse("A1").unwrap(),
        };
        let err = req.validate().unwrap_err();
        assert!(matches!(err, ExcelValidationError::WorkbookNotFound(_)));
    }

    #[test]
    fn read_range_request_serde() {
        let req = ReadRangeRequest {
            workbook_id: "wb-s".into(),
            range_address: RangeAddress::parse("Sheet1!C3:D4").unwrap(),
        };
        let json = serde_json::to_value(&req).unwrap();
        let back: ReadRangeRequest = serde_json::from_value(json).unwrap();
        assert_eq!(back.workbook_id, "wb-s");
    }

    #[test]
    fn read_range_request_clone() {
        let req = ReadRangeRequest {
            workbook_id: "wb-c".into(),
            range_address: RangeAddress::parse("A1").unwrap(),
        };
        let cloned = req.clone();
        assert_eq!(cloned.workbook_id, req.workbook_id);
    }

    #[test]
    fn read_range_request_debug() {
        let req = ReadRangeRequest {
            workbook_id: "wb-d".into(),
            range_address: RangeAddress::parse("A1").unwrap(),
        };
        let dbg = format!("{req:?}");
        assert!(dbg.contains("ReadRangeRequest"), "got: {dbg}");
    }

    // ==================== WriteRangeRequest ====================

    #[test]
    fn write_range_request_valid() {
        let req = WriteRangeRequest {
            workbook_id: "wb-1".into(),
            range_address: RangeAddress::parse("A1:B2").unwrap(),
            values: vec![
                vec![CellValue::Number(1.0), CellValue::Number(2.0)],
                vec![CellValue::Number(1.23), CellValue::Number(4.0)],
            ],
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn write_range_request_empty_workbook() {
        let req = WriteRangeRequest {
            workbook_id: String::new(),
            range_address: RangeAddress::parse("A1").unwrap(),
            values: vec![vec![CellValue::Empty]],
        };
        let err = req.validate().unwrap_err();
        assert!(matches!(err, ExcelValidationError::WorkbookNotFound(_)));
    }

    #[test]
    fn write_range_request_empty_values() {
        let req = WriteRangeRequest {
            workbook_id: "wb-1".into(),
            range_address: RangeAddress::parse("A1").unwrap(),
            values: vec![],
        };
        let err = req.validate().unwrap_err();
        assert!(matches!(err, ExcelValidationError::EmptyValues));
    }

    #[test]
    fn write_range_request_too_many_cells() {
        // 101 rows x 100 cols = 10100 > 10000
        let row: Vec<CellValue> = (0..100).map(|_| CellValue::Empty).collect();
        let values: Vec<Vec<CellValue>> = (0..101).map(|_| row.clone()).collect();
        let req = WriteRangeRequest {
            workbook_id: "wb-1".into(),
            range_address: RangeAddress::parse("A1:CV101").unwrap(),
            values,
        };
        let err = req.validate().unwrap_err();
        assert!(matches!(err, ExcelValidationError::RangeTooLarge { .. }));
    }

    #[test]
    fn write_range_request_exactly_max_cells() {
        // 100 rows x 100 cols = 10000 (exactly at limit)
        let row: Vec<CellValue> = (0..100).map(|_| CellValue::Empty).collect();
        let values: Vec<Vec<CellValue>> = (0..100).map(|_| row.clone()).collect();
        let req = WriteRangeRequest {
            workbook_id: "wb-1".into(),
            range_address: RangeAddress::parse("A1:CV100").unwrap(),
            values,
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn write_range_request_serde() {
        let req = WriteRangeRequest {
            workbook_id: "wb-s".into(),
            range_address: RangeAddress::parse("A1").unwrap(),
            values: vec![vec![CellValue::Text("hi".into())]],
        };
        let json = serde_json::to_value(&req).unwrap();
        let back: WriteRangeRequest = serde_json::from_value(json).unwrap();
        assert_eq!(back.workbook_id, "wb-s");
    }

    #[test]
    fn write_range_request_clone() {
        let req = WriteRangeRequest {
            workbook_id: "wb-c".into(),
            range_address: RangeAddress::parse("A1").unwrap(),
            values: vec![vec![CellValue::Empty]],
        };
        let cloned = req.clone();
        assert_eq!(cloned.workbook_id, req.workbook_id);
    }

    #[test]
    fn write_range_request_debug() {
        let req = WriteRangeRequest {
            workbook_id: "wb-d".into(),
            range_address: RangeAddress::parse("A1").unwrap(),
            values: vec![vec![CellValue::Empty]],
        };
        let dbg = format!("{req:?}");
        assert!(dbg.contains("WriteRangeRequest"), "got: {dbg}");
    }

    // ==================== AppendRowsRequest ====================

    #[test]
    fn append_rows_request_valid() {
        let req = AppendRowsRequest {
            workbook_id: "wb-1".into(),
            table_name: "Table1".into(),
            rows: vec![vec![CellValue::Text("a".into()), CellValue::Number(1.0)]],
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn append_rows_request_empty_workbook() {
        let req = AppendRowsRequest {
            workbook_id: String::new(),
            table_name: "Table1".into(),
            rows: vec![vec![CellValue::Empty]],
        };
        let err = req.validate().unwrap_err();
        assert!(matches!(err, ExcelValidationError::WorkbookNotFound(_)));
    }

    #[test]
    fn append_rows_request_empty_table_name() {
        let req = AppendRowsRequest {
            workbook_id: "wb-1".into(),
            table_name: String::new(),
            rows: vec![vec![CellValue::Empty]],
        };
        let err = req.validate().unwrap_err();
        assert!(matches!(err, ExcelValidationError::EmptyValues));
    }

    #[test]
    fn append_rows_request_empty_rows() {
        let req = AppendRowsRequest {
            workbook_id: "wb-1".into(),
            table_name: "Table1".into(),
            rows: vec![],
        };
        let err = req.validate().unwrap_err();
        assert!(matches!(err, ExcelValidationError::EmptyValues));
    }

    #[test]
    fn append_rows_request_too_many_rows() {
        let rows: Vec<Vec<CellValue>> = (0..1001).map(|_| vec![CellValue::Empty]).collect();
        let req = AppendRowsRequest {
            workbook_id: "wb-1".into(),
            table_name: "Table1".into(),
            rows,
        };
        let err = req.validate().unwrap_err();
        assert!(matches!(err, ExcelValidationError::TooManyRows { .. }));
    }

    #[test]
    fn append_rows_request_exactly_max() {
        let rows: Vec<Vec<CellValue>> = (0..1000).map(|_| vec![CellValue::Empty]).collect();
        let req = AppendRowsRequest {
            workbook_id: "wb-1".into(),
            table_name: "Table1".into(),
            rows,
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn append_rows_request_serde() {
        let req = AppendRowsRequest {
            workbook_id: "wb-s".into(),
            table_name: "T1".into(),
            rows: vec![vec![CellValue::Boolean(false)]],
        };
        let json = serde_json::to_value(&req).unwrap();
        let back: AppendRowsRequest = serde_json::from_value(json).unwrap();
        assert_eq!(back.table_name, "T1");
    }

    #[test]
    fn append_rows_request_clone() {
        let req = AppendRowsRequest {
            workbook_id: "wb-c".into(),
            table_name: "T1".into(),
            rows: vec![vec![CellValue::Empty]],
        };
        let cloned = req.clone();
        assert_eq!(cloned.workbook_id, req.workbook_id);
    }

    #[test]
    fn append_rows_request_debug() {
        let req = AppendRowsRequest {
            workbook_id: "wb-d".into(),
            table_name: "T1".into(),
            rows: vec![],
        };
        let dbg = format!("{req:?}");
        assert!(dbg.contains("AppendRowsRequest"), "got: {dbg}");
    }

    // ==================== ExcelPolicy ====================

    #[test]
    fn policy_default_denies_all() {
        let p = ExcelPolicy::default();
        assert!(!p.allow_read);
        assert!(!p.allow_write_ranges);
        assert!(!p.allow_write_tables);
        assert!(!p.allow_formulas);
        assert!(p.require_approval_for_write);
    }

    #[test]
    fn policy_permissive_allows_all() {
        let p = ExcelPolicy::new_permissive();
        assert!(p.allow_read);
        assert!(p.allow_write_ranges);
        assert!(p.allow_write_tables);
        assert!(p.allow_formulas);
        assert!(!p.require_approval_for_write);
    }

    #[test]
    fn policy_readonly_allows_read_only() {
        let p = ExcelPolicy::new_readonly();
        assert!(p.allow_read);
        assert!(!p.allow_write_ranges);
        assert!(!p.allow_write_tables);
        assert!(!p.allow_formulas);
    }

    #[test]
    fn policy_check_read_allowed() {
        let p = ExcelPolicy::new_readonly();
        assert!(p.check_read().is_ok());
    }

    #[test]
    fn policy_check_read_denied() {
        let p = ExcelPolicy::default();
        let err = p.check_read().unwrap_err();
        assert!(matches!(err, ExcelValidationError::WriteDenied(_)));
    }

    #[test]
    fn policy_check_write_range_allowed() {
        let p = ExcelPolicy::new_permissive();
        assert!(p.check_write(false).is_ok());
    }

    #[test]
    fn policy_check_write_range_denied() {
        let p = ExcelPolicy::new_readonly();
        let err = p.check_write(false).unwrap_err();
        assert!(matches!(err, ExcelValidationError::WriteDenied(_)));
    }

    #[test]
    fn policy_check_write_table_allowed() {
        let p = ExcelPolicy::new_permissive();
        assert!(p.check_write(true).is_ok());
    }

    #[test]
    fn policy_check_write_table_denied() {
        let p = ExcelPolicy::new_readonly();
        let err = p.check_write(true).unwrap_err();
        assert!(matches!(err, ExcelValidationError::WriteDenied(_)));
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = ExcelPolicy::new_permissive();
        let json = serde_json::to_value(&p).unwrap();
        let back: ExcelPolicy = serde_json::from_value(json).unwrap();
        assert_eq!(back.allow_read, p.allow_read);
        assert_eq!(back.max_cells_per_request, p.max_cells_per_request);
    }

    #[test]
    fn policy_clone() {
        let p = ExcelPolicy::new_readonly();
        let cloned = p.clone();
        assert_eq!(cloned.allow_read, p.allow_read);
        assert_eq!(cloned.allow_write_ranges, p.allow_write_ranges);
    }

    #[test]
    fn policy_debug() {
        let p = ExcelPolicy::default();
        let dbg = format!("{p:?}");
        assert!(dbg.contains("ExcelPolicy"), "got: {dbg}");
    }

    #[test]
    fn policy_max_cells_value() {
        let p = ExcelPolicy::default();
        assert_eq!(p.max_cells_per_request, 10_000);
        assert_eq!(p.max_rows_per_append, 1_000);
    }

    #[test]
    fn policy_custom_limits() {
        let p = ExcelPolicy {
            allow_read: true,
            allow_write_ranges: true,
            allow_write_tables: false,
            allow_formulas: false,
            require_approval_for_write: true,
            max_cells_per_request: 500,
            max_rows_per_append: 50,
        };
        assert_eq!(p.max_cells_per_request, 500);
        assert_eq!(p.max_rows_per_append, 50);
        assert!(p.check_write(false).is_ok());
        assert!(p.check_write(true).is_err());
    }

    // ==================== ExcelValidator ====================

    #[test]
    fn validator_default_constants() {
        let v = ExcelValidator::default();
        assert_eq!(v.max_range_cells, 10_000);
        assert_eq!(v.max_append_rows, 1_000);
        assert_eq!(v.max_workbook_name, 256);
    }

    #[test]
    fn validator_validate_range_request_ok() {
        let v = ExcelValidator::default();
        let req = ReadRangeRequest {
            workbook_id: "wb-1".into(),
            range_address: RangeAddress::parse("A1:B10").unwrap(),
        };
        assert!(v.validate_range_request(&req).is_ok());
    }

    #[test]
    fn validator_validate_range_request_empty_wb() {
        let v = ExcelValidator::default();
        let req = ReadRangeRequest {
            workbook_id: String::new(),
            range_address: RangeAddress::parse("A1").unwrap(),
        };
        assert!(v.validate_range_request(&req).is_err());
    }

    #[test]
    fn validator_validate_write_request_ok() {
        let v = ExcelValidator::default();
        let req = WriteRangeRequest {
            workbook_id: "wb-1".into(),
            range_address: RangeAddress::parse("A1").unwrap(),
            values: vec![vec![CellValue::Text("x".into())]],
        };
        assert!(v.validate_write_request(&req).is_ok());
    }

    #[test]
    fn validator_validate_write_request_too_large() {
        let v = ExcelValidator {
            max_range_cells: 5,
            ..ExcelValidator::default()
        };
        let req = WriteRangeRequest {
            workbook_id: "wb-1".into(),
            range_address: RangeAddress::parse("A1:C3").unwrap(),
            values: vec![
                vec![CellValue::Empty, CellValue::Empty, CellValue::Empty],
                vec![CellValue::Empty, CellValue::Empty, CellValue::Empty],
            ],
        };
        let err = v.validate_write_request(&req).unwrap_err();
        assert!(matches!(err, ExcelValidationError::RangeTooLarge { .. }));
    }

    #[test]
    fn validator_validate_write_empty_values() {
        let v = ExcelValidator::default();
        let req = WriteRangeRequest {
            workbook_id: "wb-1".into(),
            range_address: RangeAddress::parse("A1").unwrap(),
            values: vec![],
        };
        let err = v.validate_write_request(&req).unwrap_err();
        assert!(matches!(err, ExcelValidationError::EmptyValues));
    }

    #[test]
    fn validator_validate_write_empty_workbook() {
        let v = ExcelValidator::default();
        let req = WriteRangeRequest {
            workbook_id: String::new(),
            range_address: RangeAddress::parse("A1").unwrap(),
            values: vec![vec![CellValue::Empty]],
        };
        let err = v.validate_write_request(&req).unwrap_err();
        assert!(matches!(err, ExcelValidationError::WorkbookNotFound(_)));
    }

    #[test]
    fn validator_validate_append_ok() {
        let v = ExcelValidator::default();
        let req = AppendRowsRequest {
            workbook_id: "wb-1".into(),
            table_name: "T1".into(),
            rows: vec![vec![CellValue::Text("val".into())]],
        };
        assert!(v.validate_append(&req).is_ok());
    }

    #[test]
    fn validator_validate_append_too_many() {
        let v = ExcelValidator {
            max_append_rows: 3,
            ..ExcelValidator::default()
        };
        let rows: Vec<Vec<CellValue>> = (0..4).map(|_| vec![CellValue::Empty]).collect();
        let req = AppendRowsRequest {
            workbook_id: "wb-1".into(),
            table_name: "T1".into(),
            rows,
        };
        let err = v.validate_append(&req).unwrap_err();
        assert!(matches!(err, ExcelValidationError::TooManyRows { .. }));
    }

    #[test]
    fn validator_validate_append_empty_rows() {
        let v = ExcelValidator::default();
        let req = AppendRowsRequest {
            workbook_id: "wb-1".into(),
            table_name: "T1".into(),
            rows: vec![],
        };
        let err = v.validate_append(&req).unwrap_err();
        assert!(matches!(err, ExcelValidationError::EmptyValues));
    }

    #[test]
    fn validator_validate_append_empty_table_name() {
        let v = ExcelValidator::default();
        let req = AppendRowsRequest {
            workbook_id: "wb-1".into(),
            table_name: String::new(),
            rows: vec![vec![CellValue::Empty]],
        };
        let err = v.validate_append(&req).unwrap_err();
        assert!(matches!(err, ExcelValidationError::EmptyValues));
    }

    #[test]
    fn validator_validate_append_empty_workbook() {
        let v = ExcelValidator::default();
        let req = AppendRowsRequest {
            workbook_id: String::new(),
            table_name: "T1".into(),
            rows: vec![vec![CellValue::Empty]],
        };
        let err = v.validate_append(&req).unwrap_err();
        assert!(matches!(err, ExcelValidationError::WorkbookNotFound(_)));
    }

    #[test]
    fn validator_serde_roundtrip() {
        let v = ExcelValidator {
            max_range_cells: 500,
            max_append_rows: 100,
            max_workbook_name: 128,
        };
        let json = serde_json::to_value(&v).unwrap();
        let back: ExcelValidator = serde_json::from_value(json).unwrap();
        assert_eq!(back.max_range_cells, 500);
        assert_eq!(back.max_append_rows, 100);
        assert_eq!(back.max_workbook_name, 128);
    }

    #[test]
    fn validator_clone() {
        let v = ExcelValidator::default();
        let cloned = v.clone();
        assert_eq!(cloned.max_range_cells, v.max_range_cells);
    }

    #[test]
    fn validator_debug() {
        let v = ExcelValidator::default();
        let dbg = format!("{v:?}");
        assert!(dbg.contains("ExcelValidator"), "got: {dbg}");
    }

    // ==================== ExcelValidationError ====================

    #[test]
    fn validation_error_display_invalid_range() {
        let err = ExcelValidationError::InvalidRangeAddress("bad".into());
        assert_eq!(err.to_string(), "Invalid range address: bad");
    }

    #[test]
    fn validation_error_display_range_too_large() {
        let err = ExcelValidationError::RangeTooLarge {
            requested: 20_000,
            max: 10_000,
        };
        let display = err.to_string();
        assert!(display.contains("20000"), "got: {display}");
        assert!(display.contains("10000"), "got: {display}");
    }

    #[test]
    fn validation_error_display_too_many_rows() {
        let err = ExcelValidationError::TooManyRows {
            requested: 2000,
            max: 1000,
        };
        let display = err.to_string();
        assert!(display.contains("2000"), "got: {display}");
        assert!(display.contains("1000"), "got: {display}");
    }

    #[test]
    fn validation_error_display_empty_values() {
        let err = ExcelValidationError::EmptyValues;
        assert_eq!(err.to_string(), "Values payload must not be empty");
    }

    #[test]
    fn validation_error_display_workbook_not_found() {
        let err = ExcelValidationError::WorkbookNotFound("wb-missing".into());
        assert_eq!(err.to_string(), "Workbook not found: wb-missing");
    }

    #[test]
    fn validation_error_display_write_denied() {
        let err = ExcelValidationError::WriteDenied("no permission".into());
        assert_eq!(err.to_string(), "Write denied: no permission");
    }

    #[test]
    fn validation_error_serde_roundtrip() {
        let errors = vec![
            ExcelValidationError::InvalidRangeAddress("x".into()),
            ExcelValidationError::RangeTooLarge {
                requested: 1,
                max: 2,
            },
            ExcelValidationError::TooManyRows {
                requested: 3,
                max: 4,
            },
            ExcelValidationError::EmptyValues,
            ExcelValidationError::WorkbookNotFound("wb".into()),
            ExcelValidationError::WriteDenied("no".into()),
        ];
        for err in errors {
            let json = serde_json::to_value(&err).unwrap();
            let back: ExcelValidationError = serde_json::from_value(json).unwrap();
            assert_eq!(back, err);
        }
    }

    #[test]
    fn validation_error_clone() {
        let err = ExcelValidationError::InvalidRangeAddress("test".into());
        let cloned = err.clone();
        assert_eq!(cloned, err);
    }

    #[test]
    fn validation_error_debug() {
        let err = ExcelValidationError::EmptyValues;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("EmptyValues"), "got: {dbg}");
    }

    // ==================== ExcelAuditEvent ====================

    #[test]
    fn audit_event_range_write() {
        let evt = ExcelAuditEvent::range_write("wb-1", "A1:B10", 20, "2026-03-09T12:00:00Z");
        assert_eq!(evt.action, "write_range");
        assert_eq!(evt.workbook_id, "wb-1");
        assert_eq!(evt.range.as_deref(), Some("A1:B10"));
        assert_eq!(evt.cell_count, 20);
        assert_eq!(evt.row_count, 0);
        assert_eq!(evt.timestamp, "2026-03-09T12:00:00Z");
    }

    #[test]
    fn audit_event_table_append() {
        let evt = ExcelAuditEvent::table_append("wb-2", "Sales", 50, "2026-03-09T13:00:00Z");
        assert_eq!(evt.action, "append_rows");
        assert_eq!(evt.workbook_id, "wb-2");
        assert_eq!(evt.range.as_deref(), Some("Sales"));
        assert_eq!(evt.cell_count, 0);
        assert_eq!(evt.row_count, 50);
    }

    #[test]
    fn audit_event_serde_roundtrip() {
        let evt = ExcelAuditEvent::range_write("wb-1", "A1", 1, "2026-01-01T00:00:00Z");
        let json = serde_json::to_value(&evt).unwrap();
        let back: ExcelAuditEvent = serde_json::from_value(json).unwrap();
        assert_eq!(back.action, "write_range");
        assert_eq!(back.cell_count, 1);
    }

    #[test]
    fn audit_event_clone() {
        let evt = ExcelAuditEvent::table_append("wb-c", "T1", 10, "now");
        let cloned = evt.clone();
        assert_eq!(cloned.action, evt.action);
        assert_eq!(cloned.row_count, evt.row_count);
    }

    #[test]
    fn audit_event_debug() {
        let evt = ExcelAuditEvent::range_write("wb-d", "A1", 1, "now");
        let dbg = format!("{evt:?}");
        assert!(dbg.contains("ExcelAuditEvent"), "got: {dbg}");
    }

    #[test]
    fn audit_event_no_range() {
        let evt = ExcelAuditEvent {
            timestamp: "2026-03-09T00:00:00Z".into(),
            action: "custom".into(),
            workbook_id: "wb-nr".into(),
            range: None,
            cell_count: 0,
            row_count: 0,
        };
        assert!(evt.range.is_none());
        let json = serde_json::to_value(&evt).unwrap();
        assert!(json.get("range").is_none() || json["range"].is_null());
    }

    // ==================== Integration / cross-cutting ====================

    #[test]
    fn end_to_end_read_flow() {
        let policy = ExcelPolicy::new_readonly();
        let validator = ExcelValidator::default();

        // Build a valid read request
        let req = ReadRangeRequest {
            workbook_id: "wb-e2e".into(),
            range_address: RangeAddress::parse("Sheet1!A1:C3").unwrap(),
        };

        // Policy check
        assert!(policy.check_read().is_ok());
        // Validation
        assert!(validator.validate_range_request(&req).is_ok());
    }

    #[test]
    fn end_to_end_write_flow() {
        let policy = ExcelPolicy::new_permissive();
        let validator = ExcelValidator::default();

        let req = WriteRangeRequest {
            workbook_id: "wb-e2e".into(),
            range_address: RangeAddress::parse("A1:B2").unwrap(),
            values: vec![
                vec![
                    CellValue::Text("Name".into()),
                    CellValue::Text("Score".into()),
                ],
                vec![CellValue::Text("Alice".into()), CellValue::Number(95.5)],
            ],
        };

        // Policy check
        assert!(policy.check_write(false).is_ok());
        // Validation
        assert!(validator.validate_write_request(&req).is_ok());

        // Emit audit
        let evt = ExcelAuditEvent::range_write("wb-e2e", "A1:B2", 4, "2026-03-09T00:00:00Z");
        assert_eq!(evt.cell_count, 4);
    }

    #[test]
    fn end_to_end_append_flow() {
        let policy = ExcelPolicy::new_permissive();
        let validator = ExcelValidator::default();

        let req = AppendRowsRequest {
            workbook_id: "wb-e2e".into(),
            table_name: "SalesData".into(),
            rows: vec![
                vec![CellValue::Text("Widget".into()), CellValue::Number(100.0)],
                vec![CellValue::Text("Gadget".into()), CellValue::Number(200.0)],
            ],
        };

        // Policy check
        assert!(policy.check_write(true).is_ok());
        // Validation
        assert!(validator.validate_append(&req).is_ok());

        // Audit
        let evt = ExcelAuditEvent::table_append("wb-e2e", "SalesData", 2, "now");
        assert_eq!(evt.row_count, 2);
    }

    #[test]
    fn write_denied_by_readonly_policy() {
        let policy = ExcelPolicy::new_readonly();
        let err = policy.check_write(false).unwrap_err();
        assert!(matches!(err, ExcelValidationError::WriteDenied(_)));
        let err2 = policy.check_write(true).unwrap_err();
        assert!(matches!(err2, ExcelValidationError::WriteDenied(_)));
    }

    #[test]
    fn write_denied_by_default_policy() {
        let policy = ExcelPolicy::default();
        assert!(policy.check_read().is_err());
        assert!(policy.check_write(false).is_err());
        assert!(policy.check_write(true).is_err());
    }

    #[test]
    fn validator_custom_bounds_reject_small_write() {
        let v = ExcelValidator {
            max_range_cells: 2,
            max_append_rows: 1,
            max_workbook_name: 10,
        };

        let write_req = WriteRangeRequest {
            workbook_id: "wb".into(),
            range_address: RangeAddress::parse("A1:B2").unwrap(),
            values: vec![
                vec![CellValue::Empty, CellValue::Empty],
                vec![CellValue::Empty, CellValue::Empty],
            ],
        };
        assert!(matches!(
            v.validate_write_request(&write_req).unwrap_err(),
            ExcelValidationError::RangeTooLarge {
                requested: 4,
                max: 2
            }
        ));

        let append_req = AppendRowsRequest {
            workbook_id: "wb".into(),
            table_name: "T".into(),
            rows: vec![vec![CellValue::Empty], vec![CellValue::Empty]],
        };
        assert!(matches!(
            v.validate_append(&append_req).unwrap_err(),
            ExcelValidationError::TooManyRows {
                requested: 2,
                max: 1
            }
        ));
    }

    #[test]
    fn workbook_with_zero_worksheets() {
        let wb = Workbook {
            id: "wb-zero".into(),
            name: "Empty.xlsx".into(),
            web_url: None,
            drive_item_id: None,
            worksheet_count: Some(0),
        };
        assert_eq!(wb.worksheet_count, Some(0));
    }

    #[test]
    fn worksheet_very_hidden_visibility() {
        let ws = Worksheet {
            id: "ws-vh".into(),
            name: "Config".into(),
            position: 99,
            visibility: Visibility::VeryHidden,
        };
        assert_eq!(ws.visibility.to_string(), "veryHidden");
    }

    #[test]
    fn cell_range_with_mixed_values() {
        let cr = CellRange {
            address: "A1:D1".into(),
            row_count: 1,
            column_count: 4,
            values: vec![vec![
                CellValue::Text("hello".into()),
                CellValue::Number(42.0),
                CellValue::Boolean(true),
                CellValue::Empty,
            ]],
        };
        assert!(cr.validate_size().is_ok());
        assert_eq!(cr.values[0][0].as_text(), Some("hello"));
        assert_eq!(cr.values[0][1].as_number(), Some(42.0));
        assert!(cr.values[0][3].is_empty());
    }

    #[test]
    fn table_with_columns() {
        let tbl = Table {
            id: "tbl-cols".into(),
            name: "Inventory".into(),
            show_headers: true,
            row_count: 500,
            column_count: 4,
            columns: vec![
                TableColumn {
                    id: "c1".into(),
                    name: "Item".into(),
                    index: 0,
                },
                TableColumn {
                    id: "c2".into(),
                    name: "Qty".into(),
                    index: 1,
                },
                TableColumn {
                    id: "c3".into(),
                    name: "Price".into(),
                    index: 2,
                },
                TableColumn {
                    id: "c4".into(),
                    name: "Total".into(),
                    index: 3,
                },
            ],
        };
        assert_eq!(tbl.columns.len(), 4);
        assert_eq!(tbl.columns[2].name, "Price");
        assert_eq!(tbl.columns[3].index, 3);
    }

    #[test]
    fn range_address_sheet_name_with_numbers() {
        let addr = RangeAddress::parse("Sheet2!A1:Z100").unwrap();
        assert_eq!(addr.sheet_name.as_deref(), Some("Sheet2"));
    }

    #[test]
    fn range_address_large_columns() {
        let addr = RangeAddress::parse("XFD1:XFD1048576").unwrap();
        assert_eq!(addr.start_cell, "XFD1");
        assert_eq!(addr.end_cell.as_deref(), Some("XFD1048576"));
    }

    #[test]
    fn validation_error_eq_empty_values() {
        let err1 = ExcelValidationError::EmptyValues;
        let err2 = ExcelValidationError::EmptyValues;
        assert_eq!(err1, err2);
    }

    #[test]
    fn validation_error_eq_range_too_large() {
        let err1 = ExcelValidationError::RangeTooLarge {
            requested: 1,
            max: 2,
        };
        let err2 = ExcelValidationError::RangeTooLarge {
            requested: 1,
            max: 2,
        };
        assert_eq!(err1, err2);
    }

    #[test]
    fn validation_error_ne_different_values() {
        let err1 = ExcelValidationError::RangeTooLarge {
            requested: 1,
            max: 2,
        };
        let err2 = ExcelValidationError::RangeTooLarge {
            requested: 3,
            max: 4,
        };
        assert_ne!(err1, err2);
    }

    #[test]
    fn cell_value_number_negative() {
        let cv = CellValue::Number(-1.23);
        assert_eq!(cv.as_number(), Some(-1.23));
    }

    #[test]
    fn cell_value_number_zero() {
        let cv = CellValue::Number(0.0);
        assert_eq!(cv.as_number(), Some(0.0));
        assert!(!cv.is_empty());
    }

    #[test]
    fn cell_value_text_empty_string() {
        let cv = CellValue::Text(String::new());
        assert_eq!(cv.as_text(), Some(""));
        assert!(!cv.is_empty());
    }

    #[test]
    fn write_range_single_cell() {
        let req = WriteRangeRequest {
            workbook_id: "wb-sc".into(),
            range_address: RangeAddress::parse("A1").unwrap(),
            values: vec![vec![CellValue::Number(42.0)]],
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn audit_event_fields_populated() {
        let evt = ExcelAuditEvent {
            timestamp: "2026-03-09T15:30:00Z".into(),
            action: "write_range".into(),
            workbook_id: "wb-fields".into(),
            range: Some("A1:Z100".into()),
            cell_count: 2600,
            row_count: 100,
        };
        assert_eq!(evt.timestamp, "2026-03-09T15:30:00Z");
        assert_eq!(evt.action, "write_range");
        assert_eq!(evt.workbook_id, "wb-fields");
        assert_eq!(evt.range.as_deref(), Some("A1:Z100"));
        assert_eq!(evt.cell_count, 2600);
        assert_eq!(evt.row_count, 100);
    }
}
