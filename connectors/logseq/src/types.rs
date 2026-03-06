//! `Logseq` API types.

use serde::{Deserialize, Serialize};

/// A `Logseq` page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page {
    pub name: String,
    pub uuid: String,
    #[serde(rename = "original-name", skip_serializing_if = "Option::is_none")]
    pub original_name: Option<String>,
    #[serde(rename = "created-at", skip_serializing_if = "Option::is_none")]
    pub created_at: Option<i64>,
    #[serde(rename = "updated-at", skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<serde_json::Value>,
}

/// A `Logseq` block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub uuid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub left: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub children: Option<Vec<serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<serde_json::Value>,
}

/// List of pages returned from the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageList {
    pub pages: Vec<serde_json::Value>,
}

/// List of blocks returned from the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockList {
    pub blocks: Vec<serde_json::Value>,
}

/// Block creation response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockCreateResponse {
    pub uuid: String,
}

/// Insert block request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsertBlockRequest {
    pub page: String,
    pub content: String,
}

/// `Logseq` API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn page_roundtrip() {
        let p: Page = serde_json::from_value(json!({
            "name": "daily notes",
            "uuid": "abc-123-def",
            "original-name": "Daily Notes",
            "created-at": 1_709_251_200_000i64,
            "updated-at": 1_709_337_600_000i64,
        }))
        .unwrap();
        assert_eq!(p.name, "daily notes");
        assert_eq!(p.uuid, "abc-123-def");
        assert_eq!(p.original_name, Some("Daily Notes".into()));
        assert_eq!(p.created_at, Some(1_709_251_200_000));
        let re = serde_json::to_value(&p).unwrap();
        assert_eq!(re["name"], "daily notes");
    }

    #[test]
    fn page_minimal() {
        let p: Page = serde_json::from_value(json!({
            "name": "test",
            "uuid": "x"
        }))
        .unwrap();
        assert_eq!(p.name, "test");
        assert!(p.created_at.is_none());
        assert!(p.original_name.is_none());
        assert!(p.properties.is_none());
    }

    #[test]
    fn page_with_properties() {
        let p: Page = serde_json::from_value(json!({
            "name": "tagged",
            "uuid": "p1",
            "properties": {"tags": ["research", "ai"]}
        }))
        .unwrap();
        assert!(p.properties.is_some());
    }

    #[test]
    fn page_serialization_preserves_rename() {
        let p = Page {
            name: "test".into(),
            uuid: "u1".into(),
            original_name: Some("Test".into()),
            created_at: Some(1000),
            updated_at: Some(2000),
            properties: None,
        };
        let v = serde_json::to_value(&p).unwrap();
        assert!(v.get("original-name").is_some());
        assert!(v.get("created-at").is_some());
        assert!(v.get("updated-at").is_some());
        assert!(v.get("original_name").is_none());
    }

    #[test]
    fn page_skip_serializing_none_fields() {
        let p = Page {
            name: "t".into(),
            uuid: "u".into(),
            original_name: None,
            created_at: None,
            updated_at: None,
            properties: None,
        };
        let v = serde_json::to_string(&p).unwrap();
        assert!(!v.contains("original-name"));
        assert!(!v.contains("created-at"));
        assert!(!v.contains("properties"));
    }

    #[test]
    fn block_roundtrip() {
        let b: Block = serde_json::from_value(json!({
            "uuid": "blk1",
            "content": "Hello world",
            "children": [{"uuid": "blk2", "content": "child"}],
        }))
        .unwrap();
        assert_eq!(b.uuid, "blk1");
        assert_eq!(b.content, Some("Hello world".into()));
        assert_eq!(b.children.unwrap().len(), 1);
    }

    #[test]
    fn block_minimal() {
        let b: Block = serde_json::from_value(json!({"uuid": "b"})).unwrap();
        assert_eq!(b.uuid, "b");
        assert!(b.content.is_none());
        assert!(b.children.is_none());
        assert!(b.left.is_none());
        assert!(b.parent.is_none());
    }

    #[test]
    fn block_with_parent_and_left() {
        let b: Block = serde_json::from_value(json!({
            "uuid": "b1",
            "content": "text",
            "parent": {"id": 100},
            "left": {"id": 99},
        }))
        .unwrap();
        assert!(b.parent.is_some());
        assert!(b.left.is_some());
    }

    #[test]
    fn block_with_properties() {
        let b: Block = serde_json::from_value(json!({
            "uuid": "b1",
            "properties": {"priority": "A"}
        }))
        .unwrap();
        assert!(b.properties.is_some());
    }

    #[test]
    fn block_skip_serializing_none_fields() {
        let b = Block {
            uuid: "b".into(),
            content: None,
            left: None,
            parent: None,
            children: None,
            properties: None,
        };
        let v = serde_json::to_string(&b).unwrap();
        assert!(!v.contains("content"));
        assert!(!v.contains("left"));
        assert!(!v.contains("parent"));
        assert!(!v.contains("children"));
        assert!(!v.contains("properties"));
    }

    #[test]
    fn page_list_roundtrip() {
        let pl: PageList = serde_json::from_value(json!({
            "pages": [
                {"name": "page 1", "uuid": "p1"},
                {"name": "page 2", "uuid": "p2"}
            ]
        }))
        .unwrap();
        assert_eq!(pl.pages.len(), 2);
    }

    #[test]
    fn page_list_empty() {
        let pl: PageList = serde_json::from_value(json!({"pages": []})).unwrap();
        assert!(pl.pages.is_empty());
    }

    #[test]
    fn block_list_roundtrip() {
        let bl: BlockList = serde_json::from_value(json!({
            "blocks": [
                {"uuid": "b1", "content": "block 1"},
                {"uuid": "b2", "content": "block 2"}
            ]
        }))
        .unwrap();
        assert_eq!(bl.blocks.len(), 2);
    }

    #[test]
    fn block_list_empty() {
        let bl: BlockList = serde_json::from_value(json!({"blocks": []})).unwrap();
        assert!(bl.blocks.is_empty());
    }

    #[test]
    fn block_create_response_roundtrip() {
        let r: BlockCreateResponse = serde_json::from_value(json!({"uuid": "new123"})).unwrap();
        assert_eq!(r.uuid, "new123");
        let re = serde_json::to_value(&r).unwrap();
        assert_eq!(re["uuid"], "new123");
    }

    #[test]
    fn insert_block_request_roundtrip() {
        let req = InsertBlockRequest {
            page: "Project Notes".into(),
            content: "TODO: Review architecture".into(),
        };
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["page"], "Project Notes");
        assert_eq!(v["content"], "TODO: Review architecture");
    }

    #[test]
    fn insert_block_request_deserialize() {
        let req: InsertBlockRequest = serde_json::from_value(json!({
            "page": "Daily",
            "content": "- item"
        }))
        .unwrap();
        assert_eq!(req.page, "Daily");
        assert_eq!(req.content, "- item");
    }

    #[test]
    fn api_error_response_with_error() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error": "Page not found"
        }))
        .unwrap();
        assert_eq!(e.error, Some("Page not found".into()));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.error.is_none());
    }

    #[test]
    fn api_error_response_null_error() {
        let e: ApiErrorResponse = serde_json::from_value(json!({"error": null})).unwrap();
        assert!(e.error.is_none());
    }

    #[test]
    fn page_list_serialization() {
        let pl = PageList {
            pages: vec![json!({"name": "p1", "uuid": "u1"})],
        };
        let v = serde_json::to_value(&pl).unwrap();
        assert_eq!(v["pages"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn block_list_serialization() {
        let bl = BlockList {
            blocks: vec![json!({"uuid": "b1", "content": "hello"})],
        };
        let v = serde_json::to_value(&bl).unwrap();
        assert_eq!(v["blocks"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn page_debug_format() {
        let p = Page {
            name: "test".into(),
            uuid: "u1".into(),
            original_name: None,
            created_at: None,
            updated_at: None,
            properties: None,
        };
        let dbg = format!("{p:?}");
        assert!(dbg.contains("Page"));
        assert!(dbg.contains("test"));
    }

    #[test]
    fn block_debug_format() {
        let b = Block {
            uuid: "b1".into(),
            content: Some("hello".into()),
            left: None,
            parent: None,
            children: None,
            properties: None,
        };
        let dbg = format!("{b:?}");
        assert!(dbg.contains("Block"));
        assert!(dbg.contains("hello"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn page_clone() {
        let p = Page {
            name: "test".into(),
            uuid: "u1".into(),
            original_name: Some("Test".into()),
            created_at: Some(1000),
            updated_at: Some(2000),
            properties: None,
        };
        let p2 = p.clone();
        assert_eq!(p2.name, "test");
        assert_eq!(p2.original_name, Some("Test".into()));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn block_clone() {
        let b = Block {
            uuid: "b1".into(),
            content: Some("text".into()),
            left: None,
            parent: None,
            children: Some(vec![json!({"uuid": "c1"})]),
            properties: None,
        };
        let b2 = b.clone();
        assert_eq!(b2.uuid, "b1");
        assert_eq!(b2.children.unwrap().len(), 1);
    }

    #[test]
    fn page_with_null_properties() {
        let p: Page = serde_json::from_value(json!({
            "name": "test",
            "uuid": "u1",
            "properties": null
        }))
        .unwrap();
        assert!(p.properties.is_none());
    }

    #[test]
    fn block_with_empty_children() {
        let b: Block = serde_json::from_value(json!({
            "uuid": "b1",
            "children": []
        }))
        .unwrap();
        assert!(b.children.unwrap().is_empty());
    }

    #[test]
    fn page_list_clone() {
        let pl = PageList {
            pages: vec![json!({"name": "p1"})],
        };
        #[allow(clippy::redundant_clone)]
        let pl2 = pl.clone();
        assert_eq!(pl2.pages.len(), 1);
    }

    #[test]
    fn block_list_clone() {
        let bl = BlockList {
            blocks: vec![json!({"uuid": "b1"})],
        };
        #[allow(clippy::redundant_clone)]
        let bl2 = bl.clone();
        assert_eq!(bl2.blocks.len(), 1);
    }

    #[test]
    fn insert_block_request_clone() {
        let req = InsertBlockRequest {
            page: "p1".into(),
            content: "hello".into(),
        };
        #[allow(clippy::redundant_clone)]
        let req2 = req.clone();
        assert_eq!(req2.page, "p1");
    }

    #[test]
    fn block_create_response_clone() {
        let r = BlockCreateResponse {
            uuid: "new1".into(),
        };
        #[allow(clippy::redundant_clone)]
        let r2 = r.clone();
        assert_eq!(r2.uuid, "new1");
    }

    #[test]
    fn api_error_response_clone() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error": "something"
        }))
        .unwrap();
        #[allow(clippy::redundant_clone)]
        let e2 = e.clone();
        assert_eq!(e2.error, Some("something".into()));
    }

    #[test]
    fn page_with_all_fields_roundtrip() {
        let p = Page {
            name: "my page".into(),
            uuid: "uuid-1".into(),
            original_name: Some("My Page".into()),
            created_at: Some(1_000_000),
            updated_at: Some(2_000_000),
            properties: Some(json!({"tag": "value"})),
        };
        let v = serde_json::to_value(&p).unwrap();
        let p2: Page = serde_json::from_value(v).unwrap();
        assert_eq!(p2.name, "my page");
        assert_eq!(p2.properties.unwrap()["tag"], "value");
    }
}
