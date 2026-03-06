//! `Box` API types.

use serde::{Deserialize, Serialize};

/// A `Box` file object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoxFile {
    pub id: String,
    #[serde(rename = "type")]
    pub file_type: Option<String>,
    pub name: Option<String>,
    pub size: Option<i64>,
    pub created_at: Option<String>,
    pub modified_at: Option<String>,
    pub description: Option<String>,
    pub sha1: Option<String>,
    pub parent: Option<MiniFolder>,
    pub owned_by: Option<MiniUser>,
    pub shared_link: Option<serde_json::Value>,
}

/// A `Box` folder object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoxFolder {
    pub id: String,
    #[serde(rename = "type")]
    pub folder_type: Option<String>,
    pub name: Option<String>,
    pub created_at: Option<String>,
    pub modified_at: Option<String>,
    pub description: Option<String>,
    pub size: Option<i64>,
    pub parent: Option<MiniFolder>,
    pub owned_by: Option<MiniUser>,
    pub item_collection: Option<ItemCollection>,
}

/// Mini folder reference (used as parent).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiniFolder {
    pub id: String,
    #[serde(rename = "type")]
    pub folder_type: Option<String>,
    pub name: Option<String>,
    pub sequence_id: Option<String>,
    pub etag: Option<String>,
}

/// Mini user reference (used as owner/assignee).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiniUser {
    pub id: String,
    #[serde(rename = "type")]
    pub user_type: Option<String>,
    pub name: Option<String>,
    pub login: Option<String>,
}

/// Item collection (folder items response).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemCollection {
    pub total_count: Option<i64>,
    pub entries: Vec<serde_json::Value>,
    pub offset: Option<i64>,
    pub limit: Option<i64>,
}

/// Folder items response (top-level).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderItems {
    pub total_count: Option<i64>,
    pub entries: Vec<serde_json::Value>,
    pub offset: Option<i64>,
    pub limit: Option<i64>,
    pub order: Option<Vec<OrderEntry>>,
}

/// Order entry in folder listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderEntry {
    pub by: Option<String>,
    pub direction: Option<String>,
}

/// Upload response from Box.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadResponse {
    pub total_count: Option<i64>,
    pub entries: Vec<serde_json::Value>,
}

/// Collaboration (sharing) object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collaboration {
    pub id: String,
    #[serde(rename = "type")]
    pub collab_type: Option<String>,
    pub role: Option<String>,
    pub status: Option<String>,
    pub created_at: Option<String>,
    pub modified_at: Option<String>,
    pub accessible_by: Option<MiniUser>,
    pub item: Option<serde_json::Value>,
}

/// Collaborations list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollaborationList {
    pub total_count: Option<i64>,
    pub entries: Vec<serde_json::Value>,
}

/// `Box` API error response.
/// Format: `{"type": "error", "status": 409, "message": "...", "code": "item_name_in_use"}`
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    #[serde(rename = "type")]
    pub error_type: Option<String>,
    pub status: Option<u16>,
    pub message: Option<String>,
    pub code: Option<String>,
    pub request_id: Option<String>,
    pub context_info: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn box_file_roundtrip() {
        let f: BoxFile = serde_json::from_value(json!({
            "id": "12345",
            "type": "file",
            "name": "report.pdf",
            "size": 1024,
            "created_at": "2026-01-01T00:00:00-08:00",
            "modified_at": "2026-02-01T00:00:00-08:00",
            "sha1": "abc123def456",
        }))
        .unwrap();
        assert_eq!(f.id, "12345");
        assert_eq!(f.file_type, Some("file".into()));
        assert_eq!(f.name, Some("report.pdf".into()));
        assert_eq!(f.size, Some(1024));
        let re = serde_json::to_value(&f).unwrap();
        assert_eq!(re["name"], "report.pdf");
    }

    #[test]
    fn box_file_minimal() {
        let f: BoxFile = serde_json::from_value(json!({"id": "x"})).unwrap();
        assert_eq!(f.id, "x");
        assert!(f.name.is_none());
        assert!(f.size.is_none());
        assert!(f.parent.is_none());
    }

    #[test]
    fn box_file_with_parent() {
        let f: BoxFile = serde_json::from_value(json!({
            "id": "123",
            "parent": {"id": "0", "type": "folder", "name": "All Files"}
        }))
        .unwrap();
        assert_eq!(f.parent.as_ref().unwrap().id, "0");
        assert_eq!(f.parent.as_ref().unwrap().name, Some("All Files".into()));
    }

    #[test]
    fn box_file_with_owner() {
        let f: BoxFile = serde_json::from_value(json!({
            "id": "123",
            "owned_by": {"id": "u1", "type": "user", "name": "Admin", "login": "admin@example.com"}
        }))
        .unwrap();
        let owner = f.owned_by.unwrap();
        assert_eq!(owner.id, "u1");
        assert_eq!(owner.login, Some("admin@example.com".into()));
    }

    #[test]
    fn box_folder_roundtrip() {
        let f: BoxFolder = serde_json::from_value(json!({
            "id": "0",
            "type": "folder",
            "name": "All Files",
            "size": 4096,
        }))
        .unwrap();
        assert_eq!(f.id, "0");
        assert_eq!(f.name, Some("All Files".into()));
        let re = serde_json::to_value(&f).unwrap();
        assert_eq!(re["id"], "0");
    }

    #[test]
    fn box_folder_minimal() {
        let f: BoxFolder = serde_json::from_value(json!({"id": "0"})).unwrap();
        assert_eq!(f.id, "0");
        assert!(f.name.is_none());
        assert!(f.item_collection.is_none());
    }

    #[test]
    fn box_folder_with_items() {
        let f: BoxFolder = serde_json::from_value(json!({
            "id": "0",
            "item_collection": {
                "total_count": 2,
                "entries": [
                    {"id": "f1", "type": "file", "name": "doc.pdf"},
                    {"id": "f2", "type": "folder", "name": "Subfolder"}
                ],
                "offset": 0,
                "limit": 100
            }
        }))
        .unwrap();
        let ic = f.item_collection.unwrap();
        assert_eq!(ic.total_count, Some(2));
        assert_eq!(ic.entries.len(), 2);
    }

    #[test]
    fn mini_folder_roundtrip() {
        let mf: MiniFolder = serde_json::from_value(json!({
            "id": "0",
            "type": "folder",
            "name": "All Files",
            "sequence_id": "1",
            "etag": "1"
        }))
        .unwrap();
        assert_eq!(mf.id, "0");
        assert_eq!(mf.sequence_id, Some("1".into()));
    }

    #[test]
    fn mini_user_roundtrip() {
        let mu: MiniUser = serde_json::from_value(json!({
            "id": "u1",
            "type": "user",
            "name": "Alice",
            "login": "alice@example.com"
        }))
        .unwrap();
        assert_eq!(mu.id, "u1");
        assert_eq!(mu.login, Some("alice@example.com".into()));
    }

    #[test]
    fn item_collection_roundtrip() {
        let ic: ItemCollection = serde_json::from_value(json!({
            "total_count": 5,
            "entries": [{"id": "1"}, {"id": "2"}],
            "offset": 0,
            "limit": 100
        }))
        .unwrap();
        assert_eq!(ic.total_count, Some(5));
        assert_eq!(ic.entries.len(), 2);
    }

    #[test]
    fn item_collection_empty() {
        let ic: ItemCollection = serde_json::from_value(json!({
            "entries": []
        }))
        .unwrap();
        assert_eq!(ic.total_count, None);
        assert!(ic.entries.is_empty());
    }

    #[test]
    fn folder_items_roundtrip() {
        let fi: FolderItems = serde_json::from_value(json!({
            "total_count": 10,
            "entries": [{"id": "f1", "type": "file"}],
            "offset": 0,
            "limit": 100,
            "order": [{"by": "name", "direction": "ASC"}]
        }))
        .unwrap();
        assert_eq!(fi.total_count, Some(10));
        assert_eq!(fi.entries.len(), 1);
        assert_eq!(fi.order.as_ref().unwrap()[0].by, Some("name".into()));
    }

    #[test]
    fn folder_items_minimal() {
        let fi: FolderItems = serde_json::from_value(json!({
            "entries": []
        }))
        .unwrap();
        assert!(fi.entries.is_empty());
        assert!(fi.order.is_none());
    }

    #[test]
    fn order_entry_roundtrip() {
        let o: OrderEntry = serde_json::from_value(json!({
            "by": "date",
            "direction": "DESC"
        }))
        .unwrap();
        assert_eq!(o.by, Some("date".into()));
        assert_eq!(o.direction, Some("DESC".into()));
    }

    #[test]
    fn upload_response_roundtrip() {
        let ur: UploadResponse = serde_json::from_value(json!({
            "total_count": 1,
            "entries": [{"id": "new123", "type": "file", "name": "report.pdf"}]
        }))
        .unwrap();
        assert_eq!(ur.total_count, Some(1));
        assert_eq!(ur.entries.len(), 1);
    }

    #[test]
    fn upload_response_empty() {
        let ur: UploadResponse = serde_json::from_value(json!({
            "entries": []
        }))
        .unwrap();
        assert!(ur.entries.is_empty());
    }

    #[test]
    fn collaboration_roundtrip() {
        let c: Collaboration = serde_json::from_value(json!({
            "id": "collab1",
            "type": "collaboration",
            "role": "editor",
            "status": "accepted",
            "created_at": "2026-01-15T10:00:00-08:00",
            "accessible_by": {"id": "u2", "type": "user", "name": "Bob"},
        }))
        .unwrap();
        assert_eq!(c.id, "collab1");
        assert_eq!(c.role, Some("editor".into()));
        assert_eq!(c.status, Some("accepted".into()));
        let ab = c.accessible_by.unwrap();
        assert_eq!(ab.name, Some("Bob".into()));
    }

    #[test]
    fn collaboration_minimal() {
        let c: Collaboration = serde_json::from_value(json!({"id": "c1"})).unwrap();
        assert_eq!(c.id, "c1");
        assert!(c.role.is_none());
        assert!(c.accessible_by.is_none());
    }

    #[test]
    fn collaboration_list_roundtrip() {
        let cl: CollaborationList = serde_json::from_value(json!({
            "total_count": 3,
            "entries": [
                {"id": "c1", "role": "editor"},
                {"id": "c2", "role": "viewer"},
                {"id": "c3", "role": "owner"},
            ]
        }))
        .unwrap();
        assert_eq!(cl.total_count, Some(3));
        assert_eq!(cl.entries.len(), 3);
    }

    #[test]
    fn collaboration_list_empty() {
        let cl: CollaborationList = serde_json::from_value(json!({
            "total_count": 0,
            "entries": []
        }))
        .unwrap();
        assert_eq!(cl.total_count, Some(0));
        assert!(cl.entries.is_empty());
    }

    #[test]
    fn api_error_response_with_message() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "type": "error",
            "status": 409,
            "message": "Item with the same name already exists",
            "code": "item_name_in_use",
            "request_id": "req-123",
        }))
        .unwrap();
        assert_eq!(
            e.message,
            Some("Item with the same name already exists".into())
        );
        assert_eq!(e.code, Some("item_name_in_use".into()));
        assert_eq!(e.status, Some(409));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.message.is_none());
        assert!(e.code.is_none());
        assert!(e.status.is_none());
    }

    #[test]
    fn api_error_response_not_found() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "type": "error",
            "status": 404,
            "message": "Not Found",
            "code": "not_found"
        }))
        .unwrap();
        assert_eq!(e.error_type, Some("error".into()));
        assert_eq!(e.status, Some(404));
    }

    #[test]
    fn api_error_response_with_context_info() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "type": "error",
            "status": 409,
            "message": "Conflict",
            "context_info": {"conflicts": [{"id": "123"}]}
        }))
        .unwrap();
        assert!(e.context_info.is_some());
    }

    #[test]
    fn box_file_serialize_preserves_type_rename() {
        let f = BoxFile {
            id: "1".into(),
            file_type: Some("file".into()),
            name: Some("test.txt".into()),
            size: None,
            created_at: None,
            modified_at: None,
            description: None,
            sha1: None,
            parent: None,
            owned_by: None,
            shared_link: None,
        };
        let v = serde_json::to_value(&f).unwrap();
        assert_eq!(v["type"], "file");
        assert!(v.get("file_type").is_none());
    }

    #[test]
    fn collaboration_serialize_preserves_type_rename() {
        let c = Collaboration {
            id: "c1".into(),
            collab_type: Some("collaboration".into()),
            role: Some("editor".into()),
            status: None,
            created_at: None,
            modified_at: None,
            accessible_by: None,
            item: None,
        };
        let v = serde_json::to_value(&c).unwrap();
        assert_eq!(v["type"], "collaboration");
        assert!(v.get("collab_type").is_none());
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn box_file_clone() {
        let f = BoxFile {
            id: "1".into(),
            file_type: Some("file".into()),
            name: Some("test.txt".into()),
            size: Some(512),
            created_at: None,
            modified_at: None,
            description: Some("desc".into()),
            sha1: None,
            parent: None,
            owned_by: None,
            shared_link: None,
        };
        let f2 = f.clone();
        assert_eq!(f2.id, "1");
        assert_eq!(f2.name, Some("test.txt".into()));
        assert_eq!(f2.size, Some(512));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn box_folder_clone() {
        let f = BoxFolder {
            id: "0".into(),
            folder_type: Some("folder".into()),
            name: Some("Root".into()),
            created_at: None,
            modified_at: None,
            description: None,
            size: None,
            parent: None,
            owned_by: None,
            item_collection: None,
        };
        let f2 = f.clone();
        assert_eq!(f2.id, "0");
        assert_eq!(f2.name, Some("Root".into()));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn mini_folder_clone() {
        let mf = MiniFolder {
            id: "0".into(),
            folder_type: Some("folder".into()),
            name: Some("All Files".into()),
            sequence_id: None,
            etag: None,
        };
        let mf2 = mf.clone();
        assert_eq!(mf2.id, "0");
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn mini_user_clone() {
        let mu = MiniUser {
            id: "u1".into(),
            user_type: Some("user".into()),
            name: Some("Alice".into()),
            login: Some("alice@test.com".into()),
        };
        let mu2 = mu.clone();
        assert_eq!(mu2.id, "u1");
        assert_eq!(mu2.login, Some("alice@test.com".into()));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn collaboration_clone() {
        let c = Collaboration {
            id: "c1".into(),
            collab_type: Some("collaboration".into()),
            role: Some("editor".into()),
            status: Some("accepted".into()),
            created_at: None,
            modified_at: None,
            accessible_by: None,
            item: None,
        };
        let c2 = c.clone();
        assert_eq!(c2.id, "c1");
        assert_eq!(c2.role, Some("editor".into()));
    }

    #[test]
    fn box_file_debug_format() {
        let f: BoxFile = serde_json::from_value(json!({"id": "f1"})).unwrap();
        let dbg = format!("{f:?}");
        assert!(dbg.contains("BoxFile"));
        assert!(dbg.contains("f1"));
    }

    #[test]
    fn box_folder_debug_format() {
        let f: BoxFolder = serde_json::from_value(json!({"id": "d1"})).unwrap();
        let dbg = format!("{f:?}");
        assert!(dbg.contains("BoxFolder"));
    }

    #[test]
    fn collaboration_debug_format() {
        let c: Collaboration = serde_json::from_value(json!({"id": "c1"})).unwrap();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("Collaboration"));
    }

    #[test]
    fn box_file_zero_size() {
        let f: BoxFile = serde_json::from_value(json!({
            "id": "f1",
            "size": 0,
        }))
        .unwrap();
        assert_eq!(f.size, Some(0));
    }

    #[test]
    fn box_file_with_shared_link() {
        let f: BoxFile = serde_json::from_value(json!({
            "id": "f1",
            "shared_link": {"url": "https://box.com/s/abc", "access": "open"}
        }))
        .unwrap();
        assert!(f.shared_link.is_some());
        assert_eq!(f.shared_link.unwrap()["access"], "open");
    }

    #[test]
    fn box_file_with_description() {
        let f: BoxFile = serde_json::from_value(json!({
            "id": "f1",
            "description": "A test file"
        }))
        .unwrap();
        assert_eq!(f.description, Some("A test file".into()));
    }

    #[test]
    fn box_folder_serialize_preserves_type_rename() {
        let f = BoxFolder {
            id: "0".into(),
            folder_type: Some("folder".into()),
            name: None,
            created_at: None,
            modified_at: None,
            description: None,
            size: None,
            parent: None,
            owned_by: None,
            item_collection: None,
        };
        let v = serde_json::to_value(&f).unwrap();
        assert_eq!(v["type"], "folder");
        assert!(v.get("folder_type").is_none());
    }

    #[test]
    fn mini_user_serialize_preserves_type_rename() {
        let mu = MiniUser {
            id: "u1".into(),
            user_type: Some("user".into()),
            name: Some("Test".into()),
            login: None,
        };
        let v = serde_json::to_value(&mu).unwrap();
        assert_eq!(v["type"], "user");
        assert!(v.get("user_type").is_none());
    }

    #[test]
    fn order_entry_minimal() {
        let o: OrderEntry = serde_json::from_value(json!({})).unwrap();
        assert!(o.by.is_none());
        assert!(o.direction.is_none());
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn order_entry_clone() {
        let o = OrderEntry {
            by: Some("name".into()),
            direction: Some("ASC".into()),
        };
        let o2 = o.clone();
        assert_eq!(o2.by, Some("name".into()));
    }

    #[test]
    fn api_error_response_with_request_id() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "type": "error",
            "status": 500,
            "message": "Internal server error",
            "request_id": "req_xyz"
        }))
        .unwrap();
        assert_eq!(e.request_id, Some("req_xyz".into()));
        assert_eq!(e.status, Some(500));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn api_error_response_clone() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "type": "error",
            "status": 409,
            "message": "Conflict",
            "code": "item_name_in_use"
        }))
        .unwrap();
        let e2 = e.clone();
        assert_eq!(e2.code, Some("item_name_in_use".into()));
        assert_eq!(e2.status, Some(409));
    }

    #[test]
    fn box_file_extra_fields_ignored() {
        let f: BoxFile = serde_json::from_value(json!({
            "id": "f1",
            "unknown_field": "should be ignored"
        }))
        .unwrap();
        assert_eq!(f.id, "f1");
    }

    #[test]
    fn collaboration_with_item() {
        let c: Collaboration = serde_json::from_value(json!({
            "id": "c1",
            "item": {"type": "file", "id": "f1", "name": "doc.pdf"}
        }))
        .unwrap();
        assert!(c.item.is_some());
        assert_eq!(c.item.unwrap()["id"], "f1");
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn collaboration_list_clone() {
        let cl = CollaborationList {
            total_count: Some(2),
            entries: vec![json!({"id": "c1"}), json!({"id": "c2"})],
        };
        let cl2 = cl.clone();
        assert_eq!(cl2.total_count, Some(2));
        assert_eq!(cl2.entries.len(), 2);
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn upload_response_clone() {
        let ur = UploadResponse {
            total_count: Some(1),
            entries: vec![json!({"id": "f1"})],
        };
        let ur2 = ur.clone();
        assert_eq!(ur2.total_count, Some(1));
        assert_eq!(ur2.entries.len(), 1);
    }

    #[test]
    fn mini_folder_minimal() {
        let mf: MiniFolder = serde_json::from_value(json!({"id": "0"})).unwrap();
        assert_eq!(mf.id, "0");
        assert!(mf.folder_type.is_none());
        assert!(mf.name.is_none());
        assert!(mf.sequence_id.is_none());
        assert!(mf.etag.is_none());
    }

    #[test]
    fn mini_user_minimal() {
        let mu: MiniUser = serde_json::from_value(json!({"id": "u1"})).unwrap();
        assert_eq!(mu.id, "u1");
        assert!(mu.user_type.is_none());
        assert!(mu.name.is_none());
        assert!(mu.login.is_none());
    }

    #[test]
    fn folder_items_with_multiple_orders() {
        let fi: FolderItems = serde_json::from_value(json!({
            "entries": [],
            "order": [
                {"by": "name", "direction": "ASC"},
                {"by": "date", "direction": "DESC"}
            ]
        }))
        .unwrap();
        assert_eq!(fi.order.as_ref().unwrap().len(), 2);
        assert_eq!(fi.order.as_ref().unwrap()[1].direction, Some("DESC".into()));
    }
}
