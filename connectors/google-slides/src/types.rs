//! Bounded Google Slides API v1 request and response types.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchUpdateResponse {
    pub presentation_id: String,
    #[serde(default)]
    pub replies: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_control: Option<WriteControl>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WriteControl {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_revision_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Request {
    CreateSlide(CreateSlideRequest),
    CreateShape(CreateShapeRequest),
    CreateTable(CreateTableRequest),
    InsertText(InsertTextRequest),
    DeleteText(DeleteTextRequest),
    UpdateTextStyle(UpdateTextStyleRequest),
    UpdateParagraphStyle(UpdateParagraphStyleRequest),
    CreateImage(CreateImageRequest),
    CreateSheetsChart(CreateSheetsChartRequest),
    RefreshSheetsChart(RefreshSheetsChartRequest),
    DeleteObject(DeleteObjectRequest),
    ReplaceAllText(ReplaceAllTextRequest),
    UpdateSlidesPosition(UpdateSlidesPositionRequest),
    DuplicateObject(DuplicateObjectRequest),
    ReplaceImage(ReplaceImageRequest),
    UpdatePageElementTransform(UpdatePageElementTransformRequest),
    UpdateShapeProperties(UpdateShapePropertiesRequest),
    UpdatePageProperties(UpdatePagePropertiesRequest),
    UpdateTableCellProperties(UpdateTableCellPropertiesRequest),
}

impl Request {
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::CreateSlide(_) => "createSlide",
            Self::CreateShape(_) => "createShape",
            Self::CreateTable(_) => "createTable",
            Self::InsertText(_) => "insertText",
            Self::DeleteText(_) => "deleteText",
            Self::UpdateTextStyle(_) => "updateTextStyle",
            Self::UpdateParagraphStyle(_) => "updateParagraphStyle",
            Self::CreateImage(_) => "createImage",
            Self::CreateSheetsChart(_) => "createSheetsChart",
            Self::RefreshSheetsChart(_) => "refreshSheetsChart",
            Self::DeleteObject(_) => "deleteObject",
            Self::ReplaceAllText(_) => "replaceAllText",
            Self::UpdateSlidesPosition(_) => "updateSlidesPosition",
            Self::DuplicateObject(_) => "duplicateObject",
            Self::ReplaceImage(_) => "replaceImage",
            Self::UpdatePageElementTransform(_) => "updatePageElementTransform",
            Self::UpdateShapeProperties(_) => "updateShapeProperties",
            Self::UpdatePageProperties(_) => "updatePageProperties",
            Self::UpdateTableCellProperties(_) => "updateTableCellProperties",
        }
    }

    #[must_use]
    pub const fn is_destructive(&self) -> bool {
        matches!(
            self,
            Self::DeleteText(_)
                | Self::DeleteObject(_)
                | Self::ReplaceAllText(_)
                | Self::UpdateSlidesPosition(_)
                | Self::ReplaceImage(_)
                | Self::RefreshSheetsChart(_)
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateSlideRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub insertion_index: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slide_layout_reference: Option<LayoutReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LayoutReference {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predefined_layout: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layout_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateShapeRequest {
    pub object_id: String,
    pub shape_type: String,
    pub element_properties: PageElementProperties,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateTableRequest {
    pub object_id: String,
    pub rows: u32,
    pub columns: u32,
    pub element_properties: PageElementProperties,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PageElementProperties {
    pub page_object_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<Size>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transform: Option<AffineTransform>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Size {
    pub width: Dimension,
    pub height: Dimension,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Dimension {
    pub magnitude: f64,
    pub unit: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AffineTransform {
    pub scale_x: f64,
    pub scale_y: f64,
    pub shear_x: f64,
    pub shear_y: f64,
    pub translate_x: f64,
    pub translate_y: f64,
    pub unit: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InsertTextRequest {
    pub object_id: String,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub insertion_index: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell_location: Option<TableCellLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeleteTextRequest {
    pub object_id: String,
    pub text_range: TextRange,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell_location: Option<TableCellLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TextRange {
    #[serde(rename = "type")]
    pub range_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_index: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_index: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TableCellLocation {
    pub row_index: u32,
    pub column_index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateTextStyleRequest {
    pub object_id: String,
    pub text_range: TextRange,
    pub style: TextStyle,
    pub fields: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell_location: Option<TableCellLocation>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TextStyle {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bold: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub italic: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub underline: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub font_family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub font_size: Option<Dimension>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub foreground_color: Option<OptionalColor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OptionalColor {
    pub opaque_color: OpaqueColor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpaqueColor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rgb_color: Option<RgbColor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub theme_color: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RgbColor {
    #[serde(default)]
    pub red: f32,
    #[serde(default)]
    pub green: f32,
    #[serde(default)]
    pub blue: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateParagraphStyleRequest {
    pub object_id: String,
    pub text_range: TextRange,
    pub style: ParagraphStyle,
    pub fields: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell_location: Option<TableCellLocation>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParagraphStyle {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alignment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_spacing: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateImageRequest {
    pub object_id: String,
    pub url: String,
    pub element_properties: PageElementProperties,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateSheetsChartRequest {
    pub object_id: String,
    pub spreadsheet_id: String,
    pub chart_id: u32,
    pub linking_mode: String,
    pub element_properties: PageElementProperties,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RefreshSheetsChartRequest {
    pub object_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeleteObjectRequest {
    pub object_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReplaceAllTextRequest {
    pub contains_text: SubstringMatchCriteria,
    pub replace_text: String,
    #[serde(default)]
    pub page_object_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubstringMatchCriteria {
    pub text: String,
    #[serde(default)]
    pub match_case: bool,
    #[serde(default)]
    pub search_by_regex: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateSlidesPositionRequest {
    pub slide_object_ids: Vec<String>,
    pub insertion_index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DuplicateObjectRequest {
    pub object_id: String,
    #[serde(default)]
    pub object_ids: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReplaceImageRequest {
    pub image_object_id: String,
    pub url: String,
    pub image_replace_method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdatePageElementTransformRequest {
    pub object_id: String,
    pub transform: AffineTransform,
    pub apply_mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateShapePropertiesRequest {
    pub object_id: String,
    pub shape_properties: ShapeProperties,
    pub fields: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShapeProperties {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_alignment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autofit: Option<Autofit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Autofit {
    pub autofit_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdatePagePropertiesRequest {
    pub object_id: String,
    pub page_properties: PageProperties,
    pub fields: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PageProperties {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_background_fill: Option<PageBackgroundFill>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PageBackgroundFill {
    pub solid_fill: SolidFill,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SolidFill {
    pub color: OpaqueColor,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpha: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateTableCellPropertiesRequest {
    pub object_id: String,
    pub table_range: TableRange,
    pub table_cell_properties: TableCellProperties,
    pub fields: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TableRange {
    pub location: TableCellLocation,
    pub row_span: u32,
    pub column_span: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TableCellProperties {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_alignment: Option<String>,
}
