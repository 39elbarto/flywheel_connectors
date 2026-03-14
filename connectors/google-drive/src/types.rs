//! Google Drive API v3 types.

use serde::{Deserialize, Serialize};

// ── File ───────────────────────────────────────────────────────

/// A Drive file or folder resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DriveFile {
    pub id: String,
    pub name: String,
    pub mime_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parents: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub web_view_link: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub web_content_link: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail_link: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trashed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shared: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owners: Option<Vec<DriveUser>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Vec<DrivePermission>>,
}

/// A Drive user (owner, modifier, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DriveUser {
    pub display_name: Option<String>,
    pub email_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub photo_link: Option<String>,
}

/// A Drive permission entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DrivePermission {
    pub id: String,
    pub role: String,
    #[serde(rename = "type")]
    pub permission_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

// ── File list response ─────────────────────────────────────────

/// Response from files.list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileListResponse {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,
    #[serde(default)]
    pub files: Vec<DriveFile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub incomplete_search: Option<bool>,
}

// ── About ──────────────────────────────────────────────────────

/// Drive storage quota information.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageQuota {
    pub limit: Option<String>,
    pub usage: Option<String>,
    pub usage_in_drive: Option<String>,
    pub usage_in_drive_trash: Option<String>,
}

/// Drive about response (user info + quota).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AboutResponse {
    pub kind: String,
    pub user: Option<DriveUser>,
    pub storage_quota: Option<StorageQuota>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn drive_file_serde_roundtrip() {
        let file = DriveFile {
            id: "file-1".into(),
            name: "test.txt".into(),
            mime_type: "text/plain".into(),
            kind: Some("drive#file".into()),
            description: None,
            size: Some("1024".into()),
            created_time: Some("2026-01-01T00:00:00Z".into()),
            modified_time: None,
            parents: Some(vec!["root".into()]),
            web_view_link: None,
            web_content_link: None,
            thumbnail_link: None,
            trashed: Some(false),
            shared: None,
            owners: None,
            permissions: None,
        };
        let json_str = serde_json::to_string(&file).unwrap();
        let parsed: DriveFile = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed.id, "file-1");
        assert_eq!(parsed.name, "test.txt");
    }

    #[test]
    fn drive_file_from_api_response() {
        let json = json!({
            "id": "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2wtIs",
            "name": "Project Plan.docx",
            "mimeType": "application/vnd.google-apps.document",
            "size": "0",
            "createdTime": "2026-01-15T10:30:00.000Z",
            "modifiedTime": "2026-03-10T14:20:00.000Z",
            "parents": ["0AJ6gSXK9k4z_Uk9PVA"],
            "webViewLink": "https://docs.google.com/document/d/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2wtIs/edit",
            "trashed": false,
            "shared": true
        });
        let file: DriveFile = serde_json::from_value(json).unwrap();
        assert_eq!(file.name, "Project Plan.docx");
        assert!(file.shared.unwrap());
    }

    #[test]
    fn file_list_response_serde() {
        let json = json!({
            "kind": "drive#fileList",
            "nextPageToken": "token123",
            "files": [
                {
                    "id": "f1",
                    "name": "file1.txt",
                    "mimeType": "text/plain"
                }
            ]
        });
        let resp: FileListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.files.len(), 1);
        assert_eq!(resp.next_page_token.as_deref(), Some("token123"));
    }

    #[test]
    fn file_list_response_empty() {
        let json = json!({ "kind": "drive#fileList", "files": [] });
        let resp: FileListResponse = serde_json::from_value(json).unwrap();
        assert!(resp.files.is_empty());
        assert!(resp.next_page_token.is_none());
    }

    #[test]
    fn about_response_serde() {
        let json = json!({
            "kind": "drive#about",
            "user": {
                "displayName": "Test User",
                "emailAddress": "test@example.com"
            },
            "storageQuota": {
                "limit": "16106127360",
                "usage": "1073741824",
                "usageInDrive": "536870912",
                "usageInDriveTrash": "0"
            }
        });
        let about: AboutResponse = serde_json::from_value(json).unwrap();
        assert_eq!(about.user.unwrap().display_name.unwrap(), "Test User");
        assert!(about.storage_quota.is_some());
    }

    #[test]
    fn permission_serde() {
        let json = json!({
            "id": "perm-1",
            "role": "writer",
            "type": "user",
            "emailAddress": "user@example.com"
        });
        let perm: DrivePermission = serde_json::from_value(json).unwrap();
        assert_eq!(perm.role, "writer");
        assert_eq!(perm.permission_type, "user");
    }
}
