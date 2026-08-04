//! Typed Google Apps Script API request and response models.

use serde::{Deserialize, Serialize};

/// Google Apps Script source file types accepted by `projects.updateContent`.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FileType {
    ServerJs,
    Html,
    Json,
}

/// One complete source file in an Apps Script project.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScriptFile {
    pub name: String,
    #[serde(rename = "type")]
    pub file_type: FileType,
    pub source: String,
}

/// Apps Script project metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Project {
    pub script_id: String,
    pub title: String,
    #[serde(default)]
    pub parent_id: Option<String>,
    #[serde(default)]
    pub create_time: Option<String>,
    #[serde(default)]
    pub update_time: Option<String>,
}

/// Project source returned by Google.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Content {
    pub script_id: String,
    #[serde(default)]
    pub files: Vec<ScriptFile>,
}

/// Immutable Apps Script version metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Version {
    pub script_id: String,
    pub version_number: i32,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub create_time: Option<String>,
}

/// Deployment entry point.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryPoint {
    pub entry_point_type: String,
}

/// Mutable deployment configuration accepted by create/update methods.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeploymentConfig {
    pub script_id: String,
    pub version_number: i32,
    pub manifest_file_name: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// Apps Script deployment metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Deployment {
    pub deployment_id: String,
    pub deployment_config: DeploymentConfig,
    #[serde(default)]
    pub entry_points: Vec<EntryPoint>,
    #[serde(default)]
    pub update_time: Option<String>,
}

/// One Apps Script process-history record. Names and IDs stay in the response,
/// never in telemetry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Process {
    #[serde(default)]
    pub project_name: Option<String>,
    #[serde(default)]
    pub function_name: Option<String>,
    #[serde(default)]
    pub process_type: Option<String>,
    #[serde(default)]
    pub process_status: Option<String>,
    #[serde(default)]
    pub start_time: Option<String>,
    #[serde(default)]
    pub duration: Option<String>,
}

/// Generic bounded list page used by versions, deployments, and processes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListPage<T> {
    #[serde(default)]
    pub items: Vec<T>,
    #[serde(default)]
    pub next_page_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionsPage {
    #[serde(default)]
    pub versions: Vec<Version>,
    #[serde(default)]
    pub next_page_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentsPage {
    #[serde(default)]
    pub deployments: Vec<Deployment>,
    #[serde(default)]
    pub next_page_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessesPage {
    #[serde(default)]
    pub processes: Vec<Process>,
    #[serde(default)]
    pub next_page_token: Option<String>,
}

/// Allowlisted Apps Script process-history filters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessFilter {
    #[serde(default)]
    pub function_name: Option<String>,
    #[serde(default)]
    pub deployment_id: Option<String>,
    #[serde(default)]
    pub start_time: Option<String>,
    #[serde(default)]
    pub end_time: Option<String>,
    #[serde(default)]
    pub types: Vec<String>,
    #[serde(default)]
    pub statuses: Vec<String>,
    #[serde(default)]
    pub user_access_levels: Vec<String>,
}

/// Metrics payload varies by metric and is returned only through a bounded
/// response envelope.
pub type Metrics = serde_json::Value;

/// Compact source inventory entry exposed by preflight/readback.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct FileInventoryEntry {
    pub name: String,
    pub file_type: FileType,
    pub sha256: String,
    pub bytes: usize,
}

/// Typed confirmation input for complete source replacement.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceReplacement {
    pub script_id: String,
    pub files: Vec<ScriptFile>,
    pub expected_current_inventory_sha256: String,
    #[serde(default)]
    pub expected_removed_files: Vec<String>,
    pub confirm_replace_all_files: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_file_rejects_unknown_fields() {
        let value = serde_json::json!({
            "name": "Code",
            "type": "SERVER_JS",
            "source": "function f() {}",
            "extra": true
        });
        assert!(serde_json::from_value::<ScriptFile>(value).is_err());
    }

    #[test]
    fn file_type_matches_provider_wire_names() {
        assert_eq!(
            serde_json::to_string(&FileType::ServerJs).unwrap(),
            "\"SERVER_JS\""
        );
        assert_eq!(serde_json::to_string(&FileType::Html).unwrap(), "\"HTML\"");
        assert_eq!(serde_json::to_string(&FileType::Json).unwrap(), "\"JSON\"");
    }
}
